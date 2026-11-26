//! 실행기. 빌드 명령을 돌리고 서버를 띄운다.
//!
//! 실행기는 갈아 끼우는 자리다([`Runner`]). 레이어의 나머지는 서버가 어디서 어떻게 도는지 모른다.
//! 직접 띄운 microVM, 빌린 함수, 빌린 컨테이너를 같은 자리에 넣고 견주려는 것이다(기획안 11절의 0번).
//!
//! 여기에는 개발용 실행기([`LocalRunner`]) 하나가 있다. 이 기계의 프로세스로 돌리고 **격리하지 않는다.** 운영에 쓰지 않는다.
//! 다만 환경은 비운다. 레이어의 환경 변수(DB 의 관리 주소 같은 것)가 앱에 새지 않고, 앱은 레이어가 건넨 것만 본다.
//! 빌드에는 레이어의 운영자가 정한 것(레지스트리의 주소, 프록시, CA 묶음 같은 것)을 더 건넨다([`build_env`]). 서버에는 건네지 않는다.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// 돌릴 일 하나.
#[derive(Debug, Clone, Copy)]
pub struct Job<'a> {
    /// 코드를 꺼내 둔 폴더. 여기서 명령을 돌린다.
    pub folder: &'a Path,
    /// 선언의 빌드 명령이나 실행 명령.
    pub command: &'a str,
    /// 앱에 건네는 것. 이것 말고는 아무 환경 변수도 보이지 않는다.
    pub env: &'a [(String, String)],
    /// 출력을 이어 적을 파일.
    pub log: &'a Path,
    /// 도구가 캐시와 설정을 쓰는 홈(`HOME`). 빌드는 인스턴스마다의 자리를 받아 인스턴스 사이에 캐시를 나누지 않는다.
    /// 없으면 꺼내 둔 폴더 안의 `.orbital-home` 이다.
    pub home: Option<&'a Path>,
}

/// 빌드의 환경을 정하는 운영자의 목록(`ORBITAL_BUILD_ENV`)을 읽는다. 쉼표로 가른 이름마다 `lookup` 의 값을 가져온다.
///
/// 값이 없는 이름은 건너뛴다. 레이어의 설정(`ORBITAL_`)과 DB 의 접속(`PG`), 레이어가 정하는 `PATH` · `HOME` 은 받지 않는다.
/// 빌드는 에이전트가 쓴 코드를 돌리므로, 여기에 적은 값은 그 코드가 모두 읽는다고 본다.
pub fn build_env(
    names: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    for name in names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let shaped = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit());
        if !shaped {
            return Err(format!(
                "`{name}` 은 환경 변수의 이름이 아닙니다. 영문 · 숫자 · `_` 로 적어 주세요"
            ));
        }
        let upper = name.to_ascii_uppercase();
        if upper.starts_with("ORBITAL_") || upper.starts_with("PG") {
            return Err(format!(
                "`{name}` 은 레이어의 설정이나 DB 의 접속이라 빌드에 넘기지 않습니다. 목록에서 빼 주세요"
            ));
        }
        if upper == "PATH" || upper == "HOME" {
            return Err(format!("`{name}` 은 레이어가 정합니다. 목록에서 빼 주세요"));
        }
        if let Some(value) = lookup(name) {
            env.push((name.to_owned(), value));
        }
    }
    Ok(env)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// 명령을 시작하지 못했다.
    Spawn,
    /// 명령이 실패로 끝났다.
    Failed { code: Option<i32> },
    /// 정한 시간 안에 끝나지 않아 멈췄다.
    TimedOut,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn => write!(f, "명령을 시작하지 못했습니다"),
            Self::Failed { code: Some(code) } => write!(
                f,
                "명령이 실패로 끝났습니다(종료 코드 {code}). 로그를 확인해 주세요"
            ),
            Self::Failed { code: None } => {
                write!(f, "명령이 신호를 받고 끝났습니다. 로그를 확인해 주세요")
            }
            Self::TimedOut => write!(f, "명령이 정한 시간 안에 끝나지 않아 멈췄습니다"),
        }
    }
}

impl std::error::Error for RunError {}

/// 떠 있는 서버 하나. 사라지면 서버도 내려간다.
pub trait Running: Send {
    fn alive(&mut self) -> bool;
    fn stop(&mut self);
}

pub trait Runner: Send + Sync {
    /// 빌드 명령을 끝까지 돌린다.
    fn build(&self, job: &Job<'_>) -> Result<(), RunError>;
    /// 서버를 띄운다. 요청을 받을 준비가 됐는지는 부르는 쪽이 포트로 확인한다.
    fn start(&self, job: &Job<'_>) -> Result<Box<dyn Running>, RunError>;
    /// 끝나는 명령(적합성 테스트)을 `limit` 안에 끝까지 돌린다. 넘으면 낳은 프로세스까지 멈추고 [`RunError::TimedOut`] 이다.
    /// 빌드와 같은 자리에서 같은 격리로 돈다.
    fn check(&self, job: &Job<'_>, limit: Duration) -> Result<(), RunError>;
}

/// 개발용 실행기. 이 기계의 프로세스로 돌린다. 격리하지 않는다.
#[derive(Debug, Clone)]
pub struct LocalRunner {
    pub build_timeout: Duration,
    /// 빌드에만 더 건네는 것. 운영자가 정한다([`build_env`]). 서버와 적합성 테스트에는 건네지 않는다.
    pub build_env: Vec<(String, String)>,
}

impl Default for LocalRunner {
    fn default() -> Self {
        Self {
            build_timeout: Duration::from_secs(600),
            build_env: Vec::new(),
        }
    }
}

impl LocalRunner {
    fn spawn(job: &Job<'_>, extra: &[(String, String)]) -> Result<Child, RunError> {
        if let Some(parent) = job.log.parent() {
            fs::create_dir_all(parent).map_err(|_| RunError::Spawn)?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(job.log)
            .map_err(|_| RunError::Spawn)?;
        let errors = log.try_clone().map_err(|_| RunError::Spawn)?;
        // 도구가 캐시와 설정을 쓰는 자리. 이 기계의 홈을 쓰지 않는다
        let home = job
            .home
            .map_or_else(|| job.folder.join(".orbital-home"), Path::to_path_buf);
        fs::create_dir_all(&home).map_err(|_| RunError::Spawn)?;
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(job.command)
            .current_dir(job.folder)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .envs(
                extra
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .envs(
                job.env
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(errors)
            // 명령이 낳은 프로세스까지 한 묶음으로 멈추려고 묶음을 따로 만든다
            .process_group(0);
        command.spawn().map_err(|_| RunError::Spawn)
    }
}

/// 프로세스 묶음에 신호를 보낸다. 묶음의 번호는 맨 처음 프로세스의 번호와 같다.
fn signal(child: &Child, name: &str) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg("--")
        .arg(format!("-{}", child.id()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// 묶음에 아직 도는 프로세스가 있는가. 죽었지만 거두어지지 않은 것(좀비)은 세지 않는다.
/// 좀비는 포트도 파일도 쥐고 있지 않고, 거두는 것은 이 프로세스가 아니라 기다려도 소용이 없다.
fn group_running(child: &Child) -> bool {
    let group = child.id().to_string();
    let Ok(output) = Command::new("ps")
        .args(["-A", "-o", "pgid=,stat="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some(group.as_str())
            && fields.next().is_some_and(|state| !state.starts_with('Z'))
    })
}

/// 묶음에 도는 프로세스가 없어질 때까지 기다린다. 신호는 보낸 뒤에 닿으므로, 멈췄다고 답하기 전에 실제로 사라졌는지 본다.
/// 그러지 않으면 낳은 프로세스가 잠깐 더 살아 포트를 쥐고 있다.
fn wait_for_group(child: &Child, limit: Duration) {
    let started = Instant::now();
    while group_running(child) && started.elapsed() < limit {
        sleep(Duration::from_millis(10));
    }
}

fn wait_until(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if started.elapsed() >= limit {
            return None;
        }
        sleep(Duration::from_millis(20));
    }
}

fn stop(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        signal(child, "TERM");
        if wait_until(child, Duration::from_secs(3)).is_none() {
            signal(child, "KILL");
            let _ = child.wait();
        }
    }
    // 맨 처음 프로세스가 끝났어도 낳은 프로세스가 남아 있을 수 있다
    signal(child, "KILL");
    wait_for_group(child, Duration::from_secs(2));
}

struct LocalProcess(Child);

impl Running for LocalProcess {
    fn alive(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }

    fn stop(&mut self) {
        stop(&mut self.0);
    }
}

impl Drop for LocalProcess {
    fn drop(&mut self) {
        stop(&mut self.0);
    }
}

impl LocalRunner {
    fn finish(job: &Job<'_>, extra: &[(String, String)], limit: Duration) -> Result<(), RunError> {
        let mut child = Self::spawn(job, extra)?;
        match wait_until(&mut child, limit) {
            Some(status) if status.success() => Ok(()),
            Some(status) => Err(RunError::Failed {
                code: status.code(),
            }),
            None => {
                stop(&mut child);
                Err(RunError::TimedOut)
            }
        }
    }
}

impl Runner for LocalRunner {
    fn build(&self, job: &Job<'_>) -> Result<(), RunError> {
        Self::finish(job, &self.build_env, self.build_timeout)
    }

    fn check(&self, job: &Job<'_>, limit: Duration) -> Result<(), RunError> {
        Self::finish(job, &[], limit)
    }

    fn start(&self, job: &Job<'_>) -> Result<Box<dyn Running>, RunError> {
        Ok(Box::new(LocalProcess(Self::spawn(job, &[])?)))
    }
}

/// 방금 내준 포트와 그때. 받은 쪽이 듣기 시작하기 전에 같은 포트를 다른 쪽에 내주지 않으려고 잠깐 기억한다.
static HANDED: Mutex<Vec<(u16, Instant)>> = Mutex::new(Vec::new());
/// 내준 포트를 기억하는 시간. 앱이 뜨는 데 걸리는 시간(깨우는 한도)보다 넉넉하다.
const HANDED_FOR: Duration = Duration::from_secs(60);

/// 방금 다른 쪽에 내준 포트인가. 받은 쪽이 아직 듣지 않아 비어 보여도 쓰지 않는다.
///
/// 정한 포트나 운영체제가 준 포트에서 바로 듣는 쪽(router · proxy)이 듣기 전에 묻는다. 잡았다 놓은 포트는 받은 프로세스가
/// 듣기 전까지 비어 있어, 묻지 않으면 그 사이에 같은 포트를 잡는다.
pub fn handed(port: u16) -> bool {
    let mut handed = HANDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    handed.retain(|(_, at)| now.duration_since(*at) < HANDED_FOR);
    handed.iter().any(|(taken, _)| *taken == port)
}

/// 포트를 내준 것으로 적는다. 이미 적힌 포트면 `false` 다.
fn hand(port: u16) -> bool {
    if handed(port) {
        return false;
    }
    HANDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((port, Instant::now()));
    true
}

/// 이 기계에서 비어 있는 포트 하나. 잡았다 놓은 것이라 곧바로 쓴다. 방금 내준 포트는 다시 내주지 않는다.
pub fn free_port() -> Option<u16> {
    for _ in 0..64 {
        let port = TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        if hand(port) {
            return Some(port);
        }
    }
    None
}

/// 포트가 연결을 받을 때까지 기다린다. 받으면 `true` 다.
pub fn wait_for_port(port: u16, limit: Duration) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let started = Instant::now();
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
            return true;
        }
        if started.elapsed() >= limit {
            return false;
        }
        sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "orbital-run-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn log(&self) -> PathBuf {
            self.0.join("logs/out.log")
        }

        fn job<'a>(
            &'a self,
            command: &'a str,
            env: &'a [(String, String)],
            log: &'a Path,
        ) -> Job<'a> {
            Job {
                folder: &self.0,
                command,
                env,
                log,
                home: None,
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn runner() -> LocalRunner {
        LocalRunner {
            build_timeout: Duration::from_secs(20),
            build_env: Vec::new(),
        }
    }

    #[test]
    fn 빌드_명령이_성공하면_통과하고_출력은_로그에_남는다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        runner()
            .build(&scratch.job("echo built > out.txt && echo 빌드했다", &[], &log))
            .unwrap();
        assert_eq!(
            fs::read_to_string(scratch.0.join("out.txt")).unwrap(),
            "built\n"
        );
        assert!(fs::read_to_string(&log).unwrap().contains("빌드했다"));
    }

    #[test]
    fn 빌드_명령이_실패하면_종료_코드와_함께_실패한다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let result = runner().build(&scratch.job("echo 깨졌다 >&2; exit 3", &[], &log));
        assert_eq!(result, Err(RunError::Failed { code: Some(3) }));
        assert!(fs::read_to_string(&log).unwrap().contains("깨졌다"));
    }

    #[test]
    fn 정한_시간_안에_끝나지_않는_빌드는_멈춘다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let quick = LocalRunner {
            build_timeout: Duration::from_millis(300),
            build_env: Vec::new(),
        };
        let started = Instant::now();
        assert_eq!(
            quick.build(&scratch.job("sleep 30", &[], &log)),
            Err(RunError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn 앱은_레이어가_건넨_환경만_본다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        // 이 테스트 프로세스의 환경에는 CARGO 로 시작하는 변수가 여럿 있다. 앱에는 보이지 않아야 한다
        assert!(std::env::vars().any(|(key, _)| key.starts_with("CARGO")));
        let env = [("PORT".to_owned(), "4000".to_owned())];
        runner()
            .build(&scratch.job("env > env.txt", &env, &log))
            .unwrap();
        let seen = fs::read_to_string(scratch.0.join("env.txt")).unwrap();
        assert!(seen.contains("PORT=4000"));
        assert!(!seen.contains("CARGO"), "{seen}");
        assert!(!seen.contains("ORBITAL_PG"));
        // 홈은 꺼내 둔 폴더 안이다
        assert!(seen.contains(&format!(
            "HOME={}",
            scratch.0.join(".orbital-home").display()
        )));
    }

    /// 운영자의 환경을 흉내 낸 것. 목록에 적은 이름과 적지 않은 이름이 섞여 있다.
    fn operator(name: &str) -> Option<String> {
        match name {
            "HTTPS_PROXY" => Some("http://proxy.example.invalid:3128".to_owned()),
            "NODE_EXTRA_CA_CERTS" => Some("/etc/orbital/ca.crt".to_owned()),
            "SECRET_TOKEN" => Some("나가면_안_되는_값".to_owned()),
            _ => None,
        }
    }

    fn builder() -> LocalRunner {
        LocalRunner {
            build_env: build_env(
                "HTTPS_PROXY, NODE_EXTRA_CA_CERTS,NPM_CONFIG_REGISTRY",
                operator,
            )
            .unwrap(),
            ..runner()
        }
    }

    #[test]
    fn 방금_내준_포트는_비어_보여도_다시_내주지_않는다() {
        let port = free_port().unwrap();
        // 받은 쪽이 아직 듣지 않아 포트는 비어 보인다. 그래도 장부가 내준 것으로 안다.
        // 비어 있는지는 재지 않는다: 같은 바이너리의 다른 테스트가 나가는 연결(`wait_for_port`)에 운영체제가 이 포트를 잠깐 줄 수 있어
        // 「지금 비어 있다」는 이 기계 전체에서는 참이라고 장담할 수 없다(그것이 이 장부가 있는 까닭이다)
        assert!(handed(port));
        let others: Vec<u16> = (0..200).map(|_| free_port().unwrap()).collect();
        assert!(!others.contains(&port));
        let mut unique = others.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), others.len(), "같은 포트를 두 번 내줬습니다");
    }

    #[test]
    fn 빌드에_건넬_환경은_운영자가_적은_이름만_넘긴다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        builder()
            .build(&scratch.job("env > env.txt", &[], &log))
            .unwrap();
        let seen = fs::read_to_string(scratch.0.join("env.txt")).unwrap();
        assert!(
            seen.contains("HTTPS_PROXY=http://proxy.example.invalid:3128"),
            "{seen}"
        );
        assert!(
            seen.contains("NODE_EXTRA_CA_CERTS=/etc/orbital/ca.crt"),
            "{seen}"
        );
        // 목록에 없는 이름은 운영자의 환경에 있어도 넘기지 않고, 목록에 있어도 값이 없으면 빈 값으로 만들지 않는다
        assert!(!seen.contains("SECRET_TOKEN"), "{seen}");
        assert!(!seen.contains("NPM_CONFIG_REGISTRY"), "{seen}");
    }

    #[test]
    fn 서버를_띄울_때는_빌드의_환경을_넘기지_않는다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let port = free_port().unwrap();
        let env = [("PORT".to_owned(), port.to_string())];
        let command = "env > env.txt && node -e \"require('http').createServer((q, s) => s.end('ok')).listen(process.env.PORT, '127.0.0.1')\"";
        let mut server = builder().start(&scratch.job(command, &env, &log)).unwrap();
        assert!(wait_for_port(port, Duration::from_secs(10)));
        server.stop();
        let seen = fs::read_to_string(scratch.0.join("env.txt")).unwrap();
        assert!(seen.contains(&format!("PORT={port}")), "{seen}");
        assert!(!seen.contains("HTTPS_PROXY"), "{seen}");
        assert!(!seen.contains("NODE_EXTRA_CA_CERTS"), "{seen}");
    }

    #[test]
    fn 적합성_테스트에도_빌드의_환경을_넘기지_않는다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        builder()
            .check(
                &scratch.job("env > env.txt", &[], &log),
                Duration::from_secs(20),
            )
            .unwrap();
        let seen = fs::read_to_string(scratch.0.join("env.txt")).unwrap();
        assert!(!seen.contains("HTTPS_PROXY"), "{seen}");
    }

    #[test]
    fn 레이어의_설정과_db_의_접속은_빌드의_환경_목록에_적지_못한다() {
        for names in [
            "ORBITAL_PG",
            "HTTPS_PROXY,orbital_seal_key",
            "PGPASSWORD",
            "PGHOST",
            "PATH",
            "HOME",
        ] {
            let refused = build_env(names, |_| Some("값".to_owned()));
            assert!(refused.is_err(), "{names}");
            assert!(!refused.unwrap_err().contains("값"), "{names}");
        }
        assert!(build_env("HTTPS PROXY", |_| None).is_err());
        assert_eq!(build_env("", |_| Some("값".to_owned())), Ok(Vec::new()));
    }

    #[test]
    fn 홈을_받은_명령은_그_자리를_홈으로_쓰고_받지_않은_명령은_꺼내_둔_폴더_안을_쓴다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let cache = scratch.0.join("caches/k3f9x2ab");
        let mut job = scratch.job("echo \"$HOME\" > home.txt", &[], &log);
        job.home = Some(&cache);
        runner().build(&job).unwrap();
        assert_eq!(
            fs::read_to_string(scratch.0.join("home.txt"))
                .unwrap()
                .trim(),
            cache.display().to_string()
        );
        assert!(cache.is_dir());
        runner()
            .build(&scratch.job("echo \"$HOME\" > home.txt", &[], &log))
            .unwrap();
        assert_eq!(
            fs::read_to_string(scratch.0.join("home.txt"))
                .unwrap()
                .trim(),
            scratch.0.join(".orbital-home").display().to_string()
        );
    }

    #[test]
    fn 띄운_서버는_포트로_요청을_받고_멈추면_내려간다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let port = free_port().unwrap();
        let env = [("PORT".to_owned(), port.to_string())];
        let command = "node -e \"require('http').createServer((q, s) => s.end('ok')).listen(process.env.PORT, '127.0.0.1')\"";
        let mut server = runner().start(&scratch.job(command, &env, &log)).unwrap();
        assert!(wait_for_port(port, Duration::from_secs(10)));
        assert!(server.alive());
        server.stop();
        assert!(!server.alive());
        assert!(!wait_for_port(port, Duration::from_millis(300)));
    }

    #[test]
    fn 명령이_낳은_프로세스도_함께_멈춘다() {
        let scratch = Scratch::new();
        let log = scratch.log();
        let port = free_port().unwrap();
        let env = [("PORT".to_owned(), port.to_string())];
        // sh 가 node 를 뒤에 띄우고 기다린다. sh 만 멈추면 node 가 남는다
        let command = "node -e \"require('http').createServer((q, s) => s.end('ok')).listen(process.env.PORT, '127.0.0.1')\" & wait";
        let server = runner().start(&scratch.job(command, &env, &log)).unwrap();
        assert!(wait_for_port(port, Duration::from_secs(10)));
        drop(server);
        assert!(!wait_for_port(port, Duration::from_millis(300)));
    }

    #[test]
    fn 열리지_않는_포트는_기다리다_아니라고_답한다() {
        // 포트를 잡아 두되 듣지는 않는다(bind 만 하고 listen 하지 않는다). 잡아 둔 동안은 다른 프로세스가 그 포트를 열지 못하고,
        // 듣지 않으니 연결은 거절된다. 빈 포트를 받았다 놓으면 그 사이에 다른 프로세스가 열 수 있어 겨루게 된다
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        let port = socket.local_addr().unwrap().as_socket().unwrap().port();
        assert!(!wait_for_port(port, Duration::from_millis(200)));
        drop(socket);
    }
}
