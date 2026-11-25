//! 백업 어댑터.
//!
//! Postgres 의 도구만으로 백업과 복구를 한다. 기반 백업(`pg_basebackup`), WAL 보관(`archive_command` 가 보관 폴더에 복사한다),
//! 시점 복구(`restore_command` + `recovery_target_time`, **옆에 따로 세운 클러스터에만**), database 하나 옮기기(`pg_dump` · `pg_restore`).
//! 백업을 두는 곳과 도구는 갈아 끼우는 자리([`Store`])이고 구현은 이 기계의 폴더에 두는 [`LocalStore`] 하나다.
//!
//! 「되살릴 수 있는가」, 「훈련이 통과했는가」, 「무엇을 지울까」는 core 의 `backup` 이 판정한다. 여기서는 시각과 이름을 읽어 넘기고 실행만 한다.
//! 결과와 오류에는 이름과 숫자만 싣는다. Postgres 와 도구가 찍은 글은 행의 값이 섞일 수 있어 싣지 않는다.
//!
//! Postgres 는 root 로 돌지 않는다. 레이어가 root 로 돌면 Postgres 의 도구와 그 파일은 `postgres` 사용자로 다룬다(`runuser`).

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod cluster;
mod database;
mod records;
mod store;

pub use cluster::Cluster;
pub use database::{
    DatabaseName, Load, databases, dump_database, fingerprint, load_database, roles,
};
pub use records::{RECORDS, pack, unpack};
pub use store::{LocalStore, Store};

/// 백업과 복구가 깨진 까닭. 무엇을 하다 깨졌는지만 적는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Postgres 의 도구를 찾지 못했다.
    NoTools,
    /// 파일을 다루다 깨졌다.
    Io { doing: &'static str },
    /// 도구가 실패로 끝났다. 도구의 출력은 싣지 않는다.
    Tool { doing: &'static str },
    /// Postgres 가 거절했다. SQLSTATE 만 싣는다.
    Pg {
        doing: &'static str,
        code: Option<String>,
    },
    /// WAL 을 넘겼는데 정한 시간 안에 보관 폴더에 닿지 않았다. `archive_command` 를 본다.
    ArchiveStalled,
    /// 옆의 클러스터가 서지 못했다.
    Recovery(orbital_core::backup::RecoveryFailure),
    /// 이름이 database 의 이름으로 쓸 수 없는 글자를 담았다.
    BadName,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use orbital_core::backup::RecoveryFailure;
        match self {
            Self::NoTools => write!(
                f,
                "PostgreSQL 의 도구(pg_basebackup · pg_ctl · pg_dump)를 찾지 못했습니다. /usr/lib/postgresql/<버전>/bin 에 설치해 주세요"
            ),
            Self::Io { doing } => write!(f, "{doing} 하다가 파일을 다루지 못했습니다"),
            Self::Tool { doing } => write!(f, "{doing} 하다가 도구가 실패했습니다"),
            Self::Pg {
                doing,
                code: Some(code),
            } => write!(f, "{doing} 하다가 DB 가 거절했습니다(SQLSTATE {code})"),
            Self::Pg { doing, code: None } => {
                write!(f, "{doing} 하다가 DB 와의 연결이 끊겼습니다")
            }
            Self::ArchiveStalled => write!(
                f,
                "WAL 을 넘겼는데 보관 폴더에 닿지 않았습니다. 운영 클러스터의 `archive_mode` 와 `archive_command` 를 확인해 주세요"
            ),
            Self::Recovery(RecoveryFailure::TargetNotReached) => write!(
                f,
                "옆의 클러스터가 보관한 WAL 을 끝까지 돌렸는데 그 시점에 닿지 못했습니다. WAL 이 빠졌거나 그 시점이 보관된 것보다 뒤입니다"
            ),
            Self::Recovery(RecoveryFailure::WalMissing) => {
                write!(f, "옆의 클러스터가 이어질 WAL 조각을 읽지 못했습니다")
            }
            Self::Recovery(RecoveryFailure::DidNotStart) => {
                write!(f, "옆의 클러스터가 뜨지 않았습니다")
            }
            Self::BadName => write!(f, "database 의 이름은 소문자 · 숫자 · 밑줄만 씁니다"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn pg(doing: &'static str) -> impl FnOnce(postgres::Error) -> Error {
    move |source| Error::Pg {
        doing,
        code: source.code().map(|code| code.code().to_owned()),
    }
}

pub(crate) fn io(doing: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |_| Error::Io { doing }
}

/// Postgres 의 도구와 그 파일을 다루는 것. 레이어가 root 로 돌면 `postgres` 사용자로 부른다.
#[derive(Debug, Clone)]
pub struct Tools {
    bin: PathBuf,
    as_postgres: bool,
}

/// 명령을 부를 때 넘기는 경로. 레이어의 환경(DB 의 관리 주소, service key)은 넘기지 않는다.
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

impl Tools {
    /// 이 기계에서 가장 높은 버전의 도구를 찾는다(`/usr/lib/postgresql/<버전>/bin`). 운영 클러스터와 같은 버전이어야 한다.
    pub fn find() -> Result<Self, Error> {
        let mut found: Vec<(u32, PathBuf)> = fs::read_dir("/usr/lib/postgresql")
            .map_err(|_| Error::NoTools)?
            .flatten()
            .filter_map(|entry| {
                let version = entry.file_name().to_str()?.parse::<u32>().ok()?;
                let bin = entry.path().join("bin");
                bin.join("pg_basebackup")
                    .is_file()
                    .then_some((version, bin))
            })
            .collect();
        found.sort();
        let (_, bin) = found.pop().ok_or(Error::NoTools)?;
        Ok(Self::at(bin))
    }

    /// 정한 폴더의 도구를 쓴다.
    pub fn at(bin: PathBuf) -> Self {
        // 이 프로세스의 주인이 root 인가. `/proc/self` 의 주인이 이 프로세스의 주인이다
        let as_postgres = fs::metadata("/proc/self").is_ok_and(|meta| meta.uid() == 0);
        Self { bin, as_postgres }
    }

    /// 명령 하나. Postgres 의 사용자로, 환경을 비우고 부른다.
    fn command(&self, program: &Path) -> Command {
        let mut command = if self.as_postgres {
            let mut command = Command::new("runuser");
            command.args(["-u", "postgres", "--"]).arg(program);
            command
        } else {
            Command::new(program)
        };
        command
            .env_clear()
            .env("PATH", PATH)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// Postgres 의 도구(`pg_ctl` 같은).
    pub(crate) fn tool(&self, name: &str) -> Command {
        self.command(&self.bin.join(name))
    }

    /// Postgres 의 도구를 주인만 읽는 파일을 만들게(`umask 077`) 부른다. 덤프와 기반 백업처럼 운영의 행이 담기는 것에 쓴다.
    pub(crate) fn tool_private(&self, name: &str) -> Command {
        let mut command = self.system("sh");
        command
            .arg("-c")
            .arg("umask 077 && exec \"$0\" \"$@\"")
            .arg(self.bin.join(name));
        command
    }

    /// 이 기계의 명령(`mkdir` 같은)을 Postgres 의 사용자로.
    pub(crate) fn system(&self, name: &str) -> Command {
        self.command(Path::new(name))
    }

    /// 명령을 돌리고 끝나기를 기다린다. 출력은 싣지 않는다.
    pub(crate) fn run(mut command: Command, doing: &'static str) -> Result<(), Error> {
        match command.status() {
            Ok(status) if status.success() => Ok(()),
            _ => Err(Error::Tool { doing }),
        }
    }

    /// Postgres 의 사용자만 들어가는 폴더를 만든다.
    pub fn private_folder(&self, path: &Path) -> Result<(), Error> {
        let mut command = self.system("mkdir");
        command.args(["-p", "-m", "0700"]).arg(path);
        Self::run(command, "폴더를 만들")?;
        // 이미 있던 폴더도 좁힌다
        let mut command = self.system("chmod");
        command.arg("0700").arg(path);
        Self::run(command, "폴더의 권한을 좁히")
    }

    /// Postgres 의 사용자로 파일에 글을 적는다(`append` 면 뒤에 붙인다). 설정 파일은 Postgres 가 읽고 고친다.
    pub(crate) fn write(&self, path: &Path, text: &str, append: bool) -> Result<(), Error> {
        let mut command = self.system("sh");
        command
            .arg("-c")
            .arg(if append {
                "cat >> \"$1\""
            } else {
                "cat > \"$1\""
            })
            .arg("sh")
            .arg(path)
            .stdin(Stdio::piped());
        let mut child = command.spawn().map_err(io("설정을 적"))?;
        child
            .stdin
            .take()
            .ok_or(Error::Io {
                doing: "설정을 적"
            })?
            .write_all(text.as_bytes())
            .map_err(io("설정을 적"))?;
        match child.wait() {
            Ok(status) if status.success() => Ok(()),
            _ => Err(Error::Io {
                doing: "설정을 적"
            }),
        }
    }

    /// 폴더를 통째로 지운다. 없으면 할 일이 없다. 레이어가 만든 파일과 Postgres 가 만든 파일이 섞여 있어 먼저 레이어로 지우고,
    /// 남으면 Postgres 의 사용자로 지운다.
    pub fn remove(&self, path: &Path) -> Result<(), Error> {
        if !path.exists() || fs::remove_dir_all(path).is_ok() {
            return Ok(());
        }
        let mut command = self.system("rm");
        command.arg("-rf").arg(path);
        Self::run(command, "폴더를 지우")
    }
}

/// 유닉스 밀리초를 Postgres 가 읽는 시각(UTC)으로 적는다. `2026-11-25 16:00:56.994+00`.
pub fn timestamp(millis: u64) -> String {
    let seconds = millis / 1000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // 날짜는 1970-01-01 에서 센 날 수로 그레고리력의 연 · 월 · 일을 구한다(Howard Hinnant 의 civil_from_days)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:03}+00",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60,
        millis % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 유닉스_밀리초를_utc_의_시각으로_적는다() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00.000+00");
        assert_eq!(timestamp(951_782_400_123), "2000-02-29 00:00:00.123+00");
        assert_eq!(timestamp(1_795_622_456_994), "2026-11-25 16:00:56.994+00");
    }
}
