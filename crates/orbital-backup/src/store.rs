//! 백업을 두는 곳. 갈아 끼우는 자리([`Store`])와, 이 기계의 폴더에 두는 구현([`LocalStore`]).
//!
//! 폴더의 모양:
//!
//! ```text
//! <root>/wal/                  archive_command 가 WAL 조각을 복사해 두는 곳
//! <root>/seal.json             마지막으로 보관을 확인한 표시(core 의 `Seal`)
//! <root>/base/<id>/data/       pg_basebackup 이 뜬 클러스터(plain, WAL 포함)
//! <root>/base/<id>/records.tar 레이어의 기록(`RECORDS`)
//! <root>/base/<id>/backup.json 기반 백업의 시각과 시작 조각. 다 뜬 뒤에 적으므로 이것이 없는 폴더는 덜 뜬 것이다
//! <root>/restore/<n>/          시점 복구로 옆에 세운 클러스터. 내리면 지운다
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use orbital_core::backup::{Archive, BaseBackup, Pruning, Seal};
use postgres::{Client, Config, NoTls};
use serde::{Deserialize, Serialize};

use crate::{Cluster, Error, Tools, io, pg, records, timestamp};

/// 백업을 두는 곳과 도구. 지금은 이 기계의 폴더(`LocalStore`) 하나다. 다른 기계나 저장소에 두려면 이것을 갈아 끼운다.
pub trait Store: Send + Sync {
    /// 운영 클러스터의 기반 백업을 하나 뜨고, 레이어의 기록(`home`)을 함께 묶는다.
    fn base_backup(&self, admin_url: &str, home: &Path) -> Result<BaseBackup, Error>;
    /// 다 뜬 기반 백업.
    fn backups(&self) -> Result<Vec<BaseBackup>, Error>;
    /// 보관한 WAL 의 모습.
    fn archive(&self) -> Result<Archive, Error>;
    /// commit 하나를 적고 WAL 을 넘겨, 그것이 보관된 것을 확인한다. 이 시각까지 쓴 것은 되살릴 수 있다.
    fn seal(&self, admin_url: &str) -> Result<Seal, Error>;
    /// 기반 백업과 보관한 WAL 로 그 시점(유닉스 밀리초)의 클러스터를 옆에 세운다. 운영 클러스터는 건드리지 않는다.
    fn recover(&self, backup: &BaseBackup, at: u64) -> Result<Cluster, Error>;
    /// 기반 백업에 묶은 레이어의 기록을 `into` 에 푼다.
    fn records(&self, backup: &BaseBackup, into: &Path) -> Result<(), Error>;
    /// 지울 것으로 판정된 기반 백업과 WAL 을 지운다.
    fn prune(&self, pruning: &Pruning) -> Result<(), Error>;
    /// 이 프로세스가 옆에 세운 클러스터가 몇 개 남아 있는가. 훈련과 되살리기는 끝나면 이것이 0 이어야 한다.
    /// 함께 도는 다른 프로세스(관리 서버와 `orbitald drill`)가 세운 것은 세지 않는다.
    fn restores_left(&self) -> usize;
}

/// 기반 백업 하나의 기록. core 의 모양에 클러스터를 세운 관리 역할의 이름을 더한다(옆의 클러스터에 그 역할로 붙는다).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    backup: BaseBackup,
    superuser: String,
}

/// 이 기계의 폴더에 두는 백업.
#[derive(Debug, Clone)]
pub struct LocalStore {
    tools: Tools,
    root: PathBuf,
}

static RESTORES: AtomicU64 = AtomicU64::new(0);

/// WAL 을 넘긴 뒤 보관 폴더에 닿기를 기다리는 시간.
const SEAL_WAIT: Duration = Duration::from_secs(60);

fn now_millis(client: &mut Client) -> Result<u64, Error> {
    let millis: i64 = client
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .map_err(pg("DB 의 시각을 읽"))?
        .get(0);
    Ok(u64::try_from(millis).unwrap_or(0))
}

fn connect(admin_url: &str) -> Result<Client, Error> {
    let config: Config = admin_url.parse().map_err(|_| Error::Io {
        doing: "DB 의 관리 주소를 읽",
    })?;
    config.connect(NoTls).map_err(pg("운영 클러스터에 붙"))
}

/// `backup_label` 에서 시작하는 WAL 조각의 이름을 읽는다. `START WAL LOCATION: 0/9000028 (file 000000010000000000000009)`.
fn start_wal(label: &str) -> Option<String> {
    let line = label
        .lines()
        .find(|line| line.starts_with("START WAL LOCATION:"))?;
    let name = line.split("(file ").nth(1)?.trim_end_matches(')').trim();
    (name.len() == 24).then(|| name.to_owned())
}

impl LocalStore {
    /// `root` 에 백업을 둔다. 폴더가 없으면 만든다(Postgres 의 사용자만 들어간다).
    pub fn open(tools: Tools, root: PathBuf) -> Result<Self, Error> {
        // 폴더의 이름은 따옴표로 감싸 `archive_command` · `restore_command` 에 들어간다. 따옴표와 줄바꿈을 받지 않는다
        if root
            .to_str()
            .is_none_or(|text| text.contains(['\'', '"', '\n', '\\']))
        {
            return Err(Error::Io {
                doing: "백업의 폴더 이름에 따옴표나 줄바꿈이 없는지 보",
            });
        }
        tools.private_folder(&root)?;
        for folder in ["wal", "base", "restore"] {
            tools.private_folder(&root.join(folder))?;
        }
        let store = Self { tools, root };
        // 앞에서 깨진 채로 남은 옆의 클러스터를 걷는다
        store.sweep_restores();
        Ok(store)
    }

    /// 운영 클러스터의 `archive_command` 에 적을 명령. 이미 있는 조각은 덮어쓰지 않는다.
    pub fn archive_command(&self) -> String {
        let wal = self.root.join("wal");
        format!("test ! -f '{0}/%f' && cp %p '{0}/%f'", wal.display())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn tools(&self) -> &Tools {
        &self.tools
    }

    /// 세운 프로세스가 이미 끝난 옆의 클러스터를 걷는다. 폴더의 이름(`<시점>-<프로세스>-<차례>`)에 세운 프로세스가 적혀 있어,
    /// 함께 도는 다른 프로세스(관리 서버와 `orbitald drill`)의 것은 건드리지 않는다.
    fn sweep_restores(&self) {
        let Ok(entries) = fs::read_dir(self.root.join("restore")) else {
            return;
        };
        for entry in entries.flatten() {
            let owner = entry
                .file_name()
                .to_str()
                .and_then(|name| name.split('-').nth(1).map(str::to_owned));
            if owner.is_some_and(|pid| Path::new("/proc").join(pid).exists()) {
                continue;
            }
            let data = entry.path().join("data");
            if data.is_dir() {
                let mut command = self.tools.tool("pg_ctl");
                command
                    .arg("-D")
                    .arg(&data)
                    .args(["-m", "immediate", "-w", "stop"]);
                let _ = Tools::run(command, "남은 클러스터를 멈추");
            }
            let _ = self.tools.remove(&entry.path());
        }
    }

    fn meta(&self, id: &str) -> Result<Meta, Error> {
        let text = fs::read(self.root.join("base").join(id).join("backup.json"))
            .map_err(io("기반 백업의 기록을 읽"))?;
        serde_json::from_slice(&text).map_err(|_| Error::Io {
            doing: "기반 백업의 기록을 읽",
        })
    }
}

impl Store for LocalStore {
    fn base_backup(&self, admin_url: &str, home: &Path) -> Result<BaseBackup, Error> {
        let mut client = connect(admin_url)?;
        let started_at = now_millis(&mut client)?;
        let segment_bytes: i64 = client
            .query_one(
                "SELECT setting::bigint FROM pg_settings WHERE name = 'wal_segment_size'",
                &[],
            )
            .map_err(pg("WAL 조각의 크기를 읽"))?
            .get(0);
        // 클러스터를 세운 관리 역할(oid 10). 옆에 되살린 클러스터에는 이 역할로 붙는다
        let superuser: String = client
            .query_one("SELECT rolname::text FROM pg_roles WHERE oid = 10", &[])
            .map_err(pg("관리 역할을 읽"))?
            .get(0);
        let id = started_at.to_string();
        let folder = self.root.join("base").join(&id);
        self.tools.private_folder(&folder)?;
        // 관리 주소는 명령줄에 싣지 않고 환경 변수로 건넨다
        let mut command = self.tools.tool_private("pg_basebackup");
        command.arg("-D").arg(folder.join("data")).args([
            "-Fp",
            "-X",
            "stream",
            "-c",
            "fast",
            "--no-password",
        ]);
        crate::database::Endpoint::parse(admin_url)?.apply(&mut command);
        if let Err(error) = Tools::run(command, "기반 백업을 뜨") {
            let _ = self.tools.remove(&folder);
            return Err(error);
        }
        let finished_at = now_millis(&mut client)?;
        let label = {
            let mut command = self.tools.system("cat");
            command
                .arg(folder.join("data").join("backup_label"))
                .stdout(std::process::Stdio::piped());
            command
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                .unwrap_or_default()
        };
        let Some(start_wal) = start_wal(&label) else {
            let _ = self.tools.remove(&folder);
            return Err(Error::Io {
                doing: "기반 백업의 시작 조각을 읽",
            });
        };
        if let Err(error) = records::pack(home, &folder.join("records.tar")) {
            let _ = self.tools.remove(&folder);
            return Err(error);
        }
        let backup = BaseBackup {
            id,
            started_at,
            finished_at,
            start_wal,
            segment_bytes: u64::try_from(segment_bytes).unwrap_or(0),
        };
        let meta = Meta {
            backup: backup.clone(),
            superuser,
        };
        let text = serde_json::to_vec_pretty(&meta).map_err(|_| Error::Io {
            doing: "기반 백업의 기록을 적",
        })?;
        fs::write(folder.join("backup.json"), text).map_err(io("기반 백업의 기록을 적"))?;
        Ok(backup)
    }

    fn backups(&self) -> Result<Vec<BaseBackup>, Error> {
        let mut found = Vec::new();
        for entry in fs::read_dir(self.root.join("base"))
            .map_err(io("기반 백업의 목록을 읽"))?
            .flatten()
        {
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // 다 뜨지 않은 폴더(기록이 없는 것)는 기반 백업이 아니다
            if let Ok(meta) = self.meta(&id) {
                found.push(meta.backup);
            }
        }
        found.sort_by_key(|backup| backup.finished_at);
        Ok(found)
    }

    fn archive(&self) -> Result<Archive, Error> {
        let mut files: Vec<String> = fs::read_dir(self.root.join("wal"))
            .map_err(io("보관한 WAL 의 목록을 읽"))?
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .collect();
        files.sort();
        let sealed = fs::read(self.root.join("seal.json"))
            .ok()
            .and_then(|text| serde_json::from_slice::<Seal>(&text).ok());
        Ok(Archive { files, sealed })
    }

    fn seal(&self, admin_url: &str) -> Result<Seal, Error> {
        let mut client = connect(admin_url)?;
        // 트랜잭션 번호를 받으면 commit 이 WAL 에 적힌다. 그 commit 의 시각은 여기서 읽은 시각보다 뒤다
        let at: i64 = client
            .query_one(
                "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint, pg_current_xact_id()::text",
                &[],
            )
            .map_err(pg("보관할 commit 을 적"))?
            .get(0);
        let wal: String = client
            .query_one("SELECT pg_walfile_name(pg_switch_wal())", &[])
            .map_err(pg("WAL 을 넘기"))?
            .get(0);
        let deadline = Instant::now() + SEAL_WAIT;
        while !self.root.join("wal").join(&wal).is_file() {
            if Instant::now() >= deadline {
                return Err(Error::ArchiveStalled);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let seal = Seal {
            at: u64::try_from(at).unwrap_or(0),
            wal,
        };
        let text = serde_json::to_vec(&seal).map_err(|_| Error::Io {
            doing: "보관의 표시를 적",
        })?;
        let beside = self.root.join("seal.json.writing");
        fs::write(&beside, text).map_err(io("보관의 표시를 적"))?;
        fs::rename(&beside, self.root.join("seal.json")).map_err(io("보관의 표시를 적"))?;
        Ok(seal)
    }

    fn recover(&self, backup: &BaseBackup, at: u64) -> Result<Cluster, Error> {
        let meta = self.meta(&backup.id)?;
        let side = self.root.join("restore").join(format!(
            "{at}-{}-{}",
            std::process::id(),
            RESTORES.fetch_add(1, Ordering::Relaxed)
        ));
        self.tools.private_folder(&side)?;
        let mut command = self.tools.system("cp");
        command
            .arg("-a")
            .arg(self.root.join("base").join(&backup.id).join("data"))
            .arg(side.join("data"));
        if let Err(error) = Tools::run(command, "기반 백업을 옆에 펼치") {
            let _ = self.tools.remove(&side);
            return Err(error);
        }
        let restore_command = format!("cp '{}/%f' %p", self.root.join("wal").display());
        Cluster::recover(
            &self.tools,
            &side,
            &restore_command,
            &timestamp(at),
            &meta.superuser,
        )
    }

    fn records(&self, backup: &BaseBackup, into: &Path) -> Result<(), Error> {
        records::unpack(
            &self.root.join("base").join(&backup.id).join("records.tar"),
            into,
        )
    }

    fn restores_left(&self) -> usize {
        let mine = format!("-{}-", std::process::id());
        fs::read_dir(self.root.join("restore")).map_or(0, |entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().contains(&mine))
                .count()
        })
    }

    fn prune(&self, pruning: &Pruning) -> Result<(), Error> {
        for id in &pruning.backups {
            // 식별자는 이 폴더가 지은 숫자다. 폴더 밖을 가리키지 못하게 다시 본다
            if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            self.tools.remove(&self.root.join("base").join(id))?;
        }
        let Some(before) = &pruning.wal_before else {
            return Ok(());
        };
        let timeline = before.get(..8).unwrap_or_default();
        for entry in fs::read_dir(self.root.join("wal"))
            .map_err(io("보관한 WAL 의 목록을 읽"))?
            .flatten()
        {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // 조각(`…`)과 그 조각의 백업 표시(`….backup`)만 본다. 타임라인의 기록(`.history`)은 남긴다
            let segment = name.get(..24).unwrap_or_default();
            let ours = segment.len() == 24
                && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
                && segment.starts_with(timeline)
                && !name.ends_with(".history");
            if ours && segment < before.as_str() {
                fs::remove_file(entry.path()).map_err(io("지난 WAL 을 지우"))?;
            }
        }
        Ok(())
    }
}
