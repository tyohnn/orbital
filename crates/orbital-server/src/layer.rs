//! 레이어의 동작. 인스턴스를 세우고, 코드를 받고, 그 commit 에서 직접 빌드해 프리뷰를 세우고, 승인받은 release 를 운영에 올린다.
//!
//! 판정은 core 가 한다(토큰의 범위, 권한 검사, 승격의 규칙, 어느 기계가 할 일인지). 여기서는 부품을 순서대로 부르고, 중간에 깨지면 앞의 모습으로 돌린다.
//!
//! 기록은 control database 에 있고([`crate::records`]), 기록의 정합성은 DB 의 트랜잭션이 지킨다. 프로세스 안의 자물쇠(`inner`)는
//! 이 관리 서버의 메모리(떠 있는 프리뷰와 운영, router)만 지킨다. 인스턴스는 그것을 세운 관리 서버의 기계에 놓이고, 그 인스턴스의
//! 코드 저장소 · 빌드 · 프로세스에 닿는 일은 놓인 기계만 한다(core 의 `placement`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_core::access::Access;
use orbital_core::auth::query_value;
use orbital_core::check::{judge as judge_access, unguarded};
use orbital_core::cron::Cron;
use orbital_core::describe::{changes, schedule_changes};
use orbital_core::git::Service as GitService;
use orbital_core::google::{IdTokenRefusal, callback_url, judge_id_token, judge_state};
use orbital_core::host::{BaseDomain, HostTarget, Scheme, origin as host_origin};
use orbital_core::manifest::{ServiceKind, ValidManifest};
use orbital_core::name::{Ident, InstanceId, SecretName};
use orbital_core::oauth::registrable_redirect;
use orbital_core::placement::{Errand, judge as judge_place};
use orbital_core::plan::Names;
use orbital_core::release::{
    Aftermath, Approval, Approver, BuiltBy, Change, Conformed, FactoryKey, Migrations,
    PromoteDenied, Rehearsed, Release, ReleaseId, after_promotion, blockers, missing_keys,
    promote as judge_promotion,
};
use orbital_core::scope::{
    Action, Capability, DenyReason, OrganizationId, Request, Token, Verdict, judge,
};
use orbital_core::secrets::{
    Entry, EntryRefusal, Place, RequestProblem, Stage as SecretStage, ValueProblem,
    entry_expires_at, judge_request, judge_value, missing_secrets, newly_received,
};
use orbital_pg::Admin;
use orbital_pg::auth::AuthStore;
use orbital_pg::rehearsal::RestorePoint;
use orbital_proxy::{Route, serve};
use orbital_router::{
    AppServer, Called, Config as RouterConfig, Connect, DocumentFetcher, GoogleDoor, Hosts,
    HttpsFetcher, Outbox, Resend, Router, SESSION_COOKIE, Stage as RouterStage, Starter,
    Target as RouterTarget, WakeFailure, serve_hosts, serve_slot, start_on_free_port,
};
use orbital_run::{Job, Runner, Running, wait_for_port};
use orbital_source::assemble::{AssembleError, Assembled, assemble};
use orbital_source::{Commit, Error as SourceError, SourceStore, receive_scaffold};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::backup::BackupOptions;
use crate::login::{Endpoints, FactoryGoogleDoor, FactoryMailer, exchange, sha256_hex};
use crate::records::{
    CONTROL_DATABASE, DEFAULT_MACHINE, MachineHold, REFRESH_CHANNEL, RecordError, Records,
};
use crate::registry::{
    InstanceRecord, ProductionRecord, ReleaseRecord, ScheduleRecord, ScheduleRun,
};
use crate::seal::SealKey;
use crate::settings::{Settings, SettingsError};
use crate::token;
use crate::vault::{RedeemError, SecretValue, Vault, VaultError};

mod rollout;
use orbital_core::rollout::Event as RolloutEvent;
use rollout::refusal_text;
pub use rollout::{
    AgentRollout, ApplyReport, ConformanceReport, InstanceProgress, NewRollout, RolloutReport,
};

/// 일이 안 됐을 때 부른 쪽에 돌려주는 것. 에이전트가 읽고 고칠 수 있게 적는다.
#[derive(Debug)]
pub enum Failure {
    /// 없거나, 있어도 이 토큰의 범위 밖이다. 둘을 구분하지 않는다.
    NotFound,
    Unauthorized,
    Forbidden(String),
    /// 코드에 고칠 것이 있다.
    Problems(Vec<String>),
    BuildFailed {
        service: String,
        log: String,
    },
    StartFailed {
        service: String,
        log: String,
    },
    MigrationFailed(String),
    /// 요청이 틀렸다(위조했거나 만료된 Google 의 `state` 같은). 아무것도 하지 않았다.
    Invalid(String),
    /// 승격의 규칙이 막았다.
    Denied(PromoteDenied),
    Conflict(String),
    /// 한 번 쓰는 것을 이미 썼거나 만료됐다(입력 표).
    Gone(String),
    /// 요청의 `Content-Type` 을 받지 않는다(git 의 길).
    UnsupportedMediaType(String),
    /// 인스턴스(또는 앱)가 다른 기계에 놓여 있어 이 관리 서버는 하지 않는다. 놓인 기계의 이름을 싣는다.
    Misplaced {
        machine: String,
    },
    Internal(String),
}

impl From<RecordError> for Failure {
    fn from(error: RecordError) -> Self {
        Self::Internal(error.0)
    }
}

type Outcome<T> = Result<T, Failure>;

fn internal(error: impl std::fmt::Display) -> Failure {
    Failure::Internal(error.to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// 운영체제에서 난수를 읽는다. 열쇠와 식별자를 짓는 데 쓴다.
fn random(length: usize) -> Outcome<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| internal("난수를 읽지 못했습니다"))?;
    Ok(bytes)
}

/// 뜻이 없는 식별자를 짓는다. `lead` 는 첫 글자다.
fn fresh_id(lead: char) -> Outcome<InstanceId> {
    let text: String = std::iter::once(lead)
        .chain(
            random(10)?
                .into_iter()
                .map(|byte| char::from_digit(u32::from(byte) % 36, 36).unwrap_or('0')),
        )
        .collect();
    InstanceId::parse(&text).map_err(internal)
}

/// 글에서 레이어의 폴더 경로를 `<레이어>` 로 가린다.
fn masked(text: &str, home: &Path) -> String {
    let mut text = text.to_owned();
    let mut homes = vec![home.display().to_string()];
    if let Ok(real) = fs::canonicalize(home) {
        homes.push(real.display().to_string());
    }
    // 긴 것부터 바꿔 한쪽이 다른 쪽의 머리일 때도 남김없이 가린다
    homes.sort_by_key(|path| std::cmp::Reverse(path.len()));
    for path in homes.iter().filter(|path| path.len() > 1) {
        text = text.replace(path.as_str(), "<레이어>");
    }
    text
}

/// 로그의 끝 `count` 줄. 레이어의 폴더 경로(빌드의 홈 · 빌드 폴더가 그 아래에 있다)는 `<레이어>` 로 가린다.
/// 에이전트에게 가는 글이라 이 기계의 배치를 싣지 않는다. 격리하는 실행기로 바꾸면 경로도 바뀐다.
fn tail(log: &Path, home: &Path, count: usize) -> String {
    let text = masked(&fs::read_to_string(log).unwrap_or_default(), home);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(count)..].join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Preview,
    Production,
}

impl Stage {
    /// 금고의 칸. 프리뷰는 프리뷰의 칸만, 운영은 운영의 칸만 읽는다.
    fn vault(self) -> SecretStage {
        match self {
            Self::Preview => SecretStage::Preview,
            Self::Production => SecretStage::Production,
        }
    }

    fn of(stage: SecretStage) -> Self {
        match stage {
            SecretStage::Preview => Self::Preview,
            SecretStage::Production => Self::Production,
        }
    }
}

struct LiveService {
    name: String,
    kind: ServiceKind,
    /// 밖에 알리는 주소. router 의 주소 + 서비스의 `path` 다.
    url: String,
    /// 서버 서비스의 프로세스를 재우고 깨우는 것. 정적 서비스에는 없다.
    server: Option<Arc<AppServer>>,
    proxy: Option<JoinHandle<std::io::Result<()>>>,
}

/// 떠 있는 router. 내리면 요청을 받지 않는다.
enum Front {
    /// 인스턴스마다 포트 하나를 듣는다. 내리면 듣기를 멈추고 붙어 있던 연결도 함께 내린다.
    /// 자리(`slot`)의 router 만 바꿔 넣으면 듣기를 멈추지 않고 다음 요청부터 새 router 가 답한다.
    Port {
        task: JoinHandle<std::io::Result<()>>,
        slot: Arc<RwLock<Router>>,
    },
    /// 레이어의 주소 하나에서 하위 도메인으로 가른다. 내리면 그 하위 도메인을 표에서 걷는다.
    Host {
        hosts: Arc<Hosts>,
        target: HostTarget,
        router: Router,
    },
}

impl Drop for Front {
    fn drop(&mut self) {
        match self {
            Self::Port { task, .. } => task.abort(),
            Self::Host {
                hosts,
                target,
                router,
            } => hosts.remove(target, router),
        }
    }
}

/// 띄운 서비스들과 그 앞의 router.
struct Launched {
    services: Vec<LiveService>,
    router: Front,
    /// 그 router. 레이어가 일정을 부를 때 쓴다.
    handle: Router,
    /// router 의 바깥 주소.
    origin: String,
    /// 포트마다 주소를 내는 레이어에서 router 가 듣는 포트. 하위 도메인을 쓰면 없다.
    port: Option<u16>,
}

/// 서버 서비스를 어떻게 세우나.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// 지금 띄워 실제로 뜨는지 본다(프리뷰와 승격).
    Awake,
    /// 자는 채로 세워 첫 요청에 깨운다(관리 서버가 다시 떴을 때).
    Asleep,
    /// 아직 빌드하는 중이다. 서비스로 가는 요청에 503 과 `Retry-After` 로 답한다. 레이어의 길(`/_orbital/`)은 연다.
    Building,
}

/// 하위 도메인을 쓰는 레이어의 자리. 주소 하나를 듣고 `Host` 로 인스턴스를 가른다.
struct Hosted {
    hosts: Arc<Hosts>,
    address: SocketAddr,
    base: BaseDomain,
    scheme: Scheme,
    _task: JoinHandle<std::io::Result<()>>,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        self._task.abort();
    }
}

/// 서버 서비스의 프로세스를 띄우는 것. router 가 자는 서비스를 깨울 때도 부른다.
struct ServiceStarter {
    runner: Arc<dyn Runner>,
    folder: PathBuf,
    command: String,
    env: Vec<(String, String)>,
    /// 밖에서 넣는 비밀. 띄울 때마다 금고에서 읽어, 값을 바꾼 뒤 깬 프로세스는 새 값을 받는다.
    external: External,
    log: PathBuf,
    wake_timeout: Duration,
}

/// 서버 서비스에 건넬 밖에서 넣는 비밀의 자리. 프리뷰는 프리뷰의 칸만, 운영은 운영의 칸만 읽는다.
struct External {
    vault: Arc<Vault>,
    organization: String,
    instance: InstanceId,
    stage: SecretStage,
    names: Vec<SecretName>,
}

impl Starter for ServiceStarter {
    fn start(&self, port: u16) -> Result<Box<dyn Running>, WakeFailure> {
        let mut env = vec![("PORT".to_owned(), port.to_string())];
        env.extend(self.env.iter().cloned());
        let external = &self.external;
        // 금고를 읽지 못하면 띄우지 않는다. 비밀 없이 뜬 앱은 겉으로는 멀쩡해 보이고 속에서 틀린다
        let secrets = external
            .vault
            .values(
                &external.organization,
                &external.instance,
                external.stage,
                &external.names,
            )
            .map_err(|_| {
                eprintln!(
                    "orbitald: 비밀의 금고를 읽지 못해 {} 의 서비스를 띄우지 않았습니다",
                    external.instance.as_str()
                );
                WakeFailure::Refused
            })?;
        env.extend(
            secrets
                .into_iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.expose().to_owned())),
        );
        let mut process = self
            .runner
            .start(&Job {
                folder: &self.folder,
                command: &self.command,
                env: &env,
                log: &self.log,
                home: None,
            })
            .map_err(|_| WakeFailure::Refused)?;
        // 포트가 열리기를 기다린다. 그 전에 프로세스가 끝나면 더 기다리지 않는다
        let deadline = Instant::now() + self.wake_timeout;
        loop {
            if wait_for_port(port, Duration::from_millis(100)) {
                if process.alive() {
                    return Ok(process);
                }
                return Err(WakeFailure::Exited);
            }
            if !process.alive() {
                process.stop();
                return Err(WakeFailure::Exited);
            }
            if Instant::now() >= deadline {
                process.stop();
                return Err(WakeFailure::TimedOut);
            }
        }
    }
}

/// 띄울 자리. 프리뷰와 운영이 이름 · 비밀 · 서명의 열쇠를 따로 갖는다.
struct Stand<'a> {
    names: &'a Names,
    generated: &'a BTreeMap<String, String>,
    identity_key: &'a [u8],
    stage: Stage,
    /// 인스턴스가 속한 팩토리. 운영의 메일과 Google 로그인이 이 팩토리의 키를 쓴다.
    organization: &'a str,
    /// 인스턴스가 속한 앱의 이름. 메일의 글에 쓴다.
    app: &'a str,
    /// 포트마다 주소를 내는 레이어에서 먼저 잡아 볼 포트. 운영은 앞에 듣던 포트를 다시 잡아 주소가 바뀌지 않게 한다.
    port: Option<u16>,
}

impl Drop for LiveService {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.close();
        }
        if let Some(proxy) = self.proxy.take() {
            proxy.abort();
        }
    }
}

/// 떠 있는 것 하나(프리뷰이거나 운영). 서비스가 먼저 내려가고 router 가 뒤에 내려간다.
struct Live {
    release: String,
    /// router 의 바깥 주소. Google 의 콜백이 한 번 쓰는 표를 들고 이리로 보낸다.
    origin: String,
    names: Names,
    manifest: ValidManifest,
    /// 프리뷰의 씨앗 사용자. 운영에는 없다.
    seed_users: Vec<String>,
    services: Vec<LiveService>,
    /// 일정을 부를 때 쓰는 router.
    router: Router,
    /// 빌드가 끝나기를 기다리며 503 으로 답하는 중인가(관리 서버가 빌드 폴더 없이 다시 떴을 때).
    building: bool,
    _router: Front,
}

/// 운영에 올리려는 release 하나와 그것이 설 자리.
struct Target<'a> {
    instance: &'a InstanceId,
    assembled: &'a Assembled,
    folder: &'a Path,
    names: &'a Names,
    generated: &'a BTreeMap<String, String>,
    identity_key: &'a [u8],
    organization: &'a str,
    app: &'a str,
    /// 앞의 운영이 듣던 포트.
    port: Option<u16>,
}

/// 승격이 깨지기 앞의 운영.
struct Prior<'a> {
    instance: &'a InstanceId,
    record: &'a InstanceRecord,
    names: &'a Names,
}

/// 띄운 서비스와, 돌린 마이그레이션의 이름.
type Raised = (Launched, Vec<String>);
/// 깨진 까닭과, 마이그레이션이 돌았는지.
type Fallen = (Failure, bool);

/// 이 관리 서버의 메모리. 떠 있는 프리뷰와 운영, 관리 연결. 기록은 여기에 없다(control database 에 있다).
struct Inner {
    admin: Admin,
    live: BTreeMap<(String, Stage), Live>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceReport {
    pub name: String,
    pub kind: ServiceKind,
    /// 서비스에 닿는 주소. 인스턴스의 router 의 주소 + 서비스의 `path` 다. 서비스의 직접 포트는 알리지 않는다.
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewReport {
    pub release: String,
    pub commit: String,
    pub services: Vec<ServiceReport>,
    /// 권한 검사가 찾은 어긋남. 비어 있어야 승격을 요청할 수 있다.
    pub findings: Vec<String>,
    /// 운영과 견준 권한의 변화. 승인 카드에 설 문장이다.
    pub changes: Vec<String>,
    /// 승격을 막는 것.
    pub blockers: Vec<String>,
    /// 실패는 아니지만 알아 둘 것. 로그인을 레이어에 맡겼는데 행 단위 규칙을 꺼서 역할 제한이 걸리지 않는 표.
    pub notices: Vec<String>,
    /// 밖에서 넣는 비밀 가운데 프리뷰의 값이 없어 환경 변수 없이 선 것의 이름. 사람에게 입력을 요청한다.
    pub missing_secrets: Vec<String>,
    /// 위쪽이 정한 적합성 테스트의 결과. 위쪽이 선언하지 않았으면 `null` 이다.
    pub conformance: Option<ConformanceReport>,
}

/// 프리뷰의 로그. 서비스마다 빌드(`build-<서비스>`)와 서버(`preview-<서비스>`)의 끝이다.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewLogs {
    pub release: String,
    pub logs: Vec<LogReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogReport {
    pub name: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RehearsalReport {
    pub release: String,
    pub needed: bool,
    pub passed: bool,
    pub millis: u64,
    pub failed_at: Option<String>,
    pub sqlstate: Option<String>,
    /// 표마다의 행 수(앞, 뒤). 행의 내용은 없다.
    pub tables: Vec<(String, Option<i64>, Option<i64>)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionReport {
    pub release: String,
    pub services: Vec<ServiceReport>,
    pub migrations: Vec<String>,
    /// 선언의 일정마다 다음 때와 마지막 실행(숫자와 갈래만).
    pub schedules: Vec<ScheduleReport>,
}

/// 운영의 일정 하나. 레이어가 그 때에 부른다(UTC).
#[derive(Debug, Clone, Serialize)]
pub struct ScheduleReport {
    pub service: String,
    pub path: String,
    pub cron: String,
    /// 일정이 도는 업무 역할. 없으면 신원 없이 부른다.
    pub role: Option<String>,
    /// 다음에 부를 때(유닉스 초).
    pub next_at: Option<u64>,
    /// 마지막으로 부른 것. 한 번도 부르지 않았으면 `null` 이다.
    pub last_run: Option<ScheduleRun>,
}

/// 사람의 승인을 기다리는 승격 요청. 팩토리의 승인 화면이 이것을 세운다.
#[derive(Debug, Clone, Serialize)]
pub struct PendingPromotion {
    pub release: String,
    pub commit: String,
    /// 지금의 운영과 견준 권한의 변화.
    pub changes: Vec<String>,
    /// 운영에 아직 돌지 않은 마이그레이션의 이름.
    pub migrations: Vec<String>,
    /// 이번 변경으로 앱이 새로 받게 되는 밖에서 넣는 비밀의 이름. 지금의 운영과 견준다.
    pub new_secrets: Vec<String>,
    /// 이 release 가 담은 업데이트의 열린 rollout. 없으면 `null` 이다.
    pub rollout: Option<String>,
}

/// 비밀 하나의 모습. 값은 싣지 않는다(지문도 길이도 없다).
#[derive(Debug, Clone, Serialize)]
pub struct SecretReport {
    pub name: String,
    /// 이 인스턴스의 release(프리뷰로 세운 것과 운영의 것) 가운데 밖에서 넣는다고 선언한 것이 있는가.
    pub declared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<RequestedReport>,
    pub preview: SlotReport,
    pub production: SlotReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestedReport {
    pub reason: String,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlotReport {
    pub set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_at: Option<u64>,
}

/// 사람이 값을 넣을 입력 표. 10분 안에 한 번 쓴다. 주소(`url`)는 고정이고 표를 싣지 않는다.
/// 브라우저는 그 주소로 `Authorization: Bearer <표>` 를 실어 보낸다(경로에 실으면 레이어 앞의 프록시가 남기는 접근 기록에 남는다).
#[derive(Debug, Clone, Serialize)]
pub struct EntryTicket {
    pub url: String,
    pub ticket: String,
    pub expires_at: u64,
}

/// git 과 주고받은 답. 올리기의 결과는 짧아 한 번에, 받기의 pack 은 흘려 보낸다.
pub enum Exchanged {
    Bytes(Vec<u8>),
    Stream(orbital_source::PackStream),
}

/// 지금 시각(유닉스 초)을 주는 것. 테스트가 갈아 끼운다.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct Options {
    /// 레이어가 저장소 · 빌드 · 기록을 두는 폴더.
    pub home: PathBuf,
    /// DB 의 관리 주소.
    pub pg_url: String,
    /// (service key, 조직). 팩토리의 서버가 쓴다.
    pub service_keys: Vec<(String, String)>,
    pub runner: Box<dyn Runner>,
    /// 팩토리의 키를 봉인하는 열쇠. 기록 밖에서 온다(`ORBITAL_SEAL_KEY`). 없으면 팩토리가 설정을 넣지 못한다.
    pub seal_key: Option<SealKey>,
    /// 열쇠를 돌려 바꿀 때의 옛 열쇠(`ORBITAL_SEAL_KEY_PREVIOUS`). 주면 뜰 때 옛 열쇠로만 풀리는 줄을 새 열쇠로 다시 봉인한다.
    /// 다시 봉인을 마친 뒤에는 빼고 띄운다.
    pub previous_seal_key: Option<SealKey>,
    /// 레이어의 바깥 주소(`ORBITAL_PUBLIC_URL`). Google 의 콜백이 이 아래(`/v1/auth/google/callback`)에 선다.
    pub public_url: String,
    /// 개발용 메일함(`ORBITAL_DEV_MAIL=outbox`). 명시해 켰을 때만, 팩토리의 메일 키가 없어도 운영에 오르고 메일이 `ORBITAL_HOME/outbox.jsonl` 에 쌓인다.
    pub dev_mailbox: bool,
    /// Resend 와 Google 의 주소. 테스트가 가짜 서버로 갈아 끼운다.
    pub endpoints: Endpoints,
    /// 마지막 요청이 끝난 뒤 이만큼 요청이 없으면 서버 서비스의 프로세스를 내린다(`ORBITAL_SLEEP_AFTER`, 기본 5분).
    pub sleep_after: Duration,
    /// 서버 서비스를 띄우고 포트가 열리기를 기다리는 시간. 넘으면 띄우지 못한 것이다(기본 30초).
    pub wake_timeout: Duration,
    /// 서버 서비스마다 깨우기를 기다리는 요청의 상한(기본 128, `ORBITAL_WAKE_QUEUE`). 넘친 요청은 기다리지 않고 503 과 `Retry-After` 로 답한다.
    pub wake_queue: usize,
    /// 인스턴스마다의 하위 도메인. 없으면 인스턴스마다 포트 하나를 낸다(개발과 지금의 테스트).
    pub hosting: Option<Hosting>,
    /// 비밀의 입력 표와 요청이 읽는 시계. 테스트가 갈아 끼워 표의 만료를 잰다.
    pub clock: Clock,
    /// 적합성 테스트의 제한 시간(기본 120초). 넘으면 멈추고 실패로 적는다.
    pub conformance_timeout: Duration,
    /// 백업과 복구 훈련(`ORBITAL_BACKUP_DIR`). 없으면 백업하지 않고, 인스턴스를 되살리는 길은 409 로 답한다.
    pub backup: Option<BackupOptions>,
    /// 토큰을 내고 판정하는 시계. 테스트가 갈아 끼워 진행 중인 요청의 만료를 잰다.
    pub token_clock: Clock,
    /// 요청 본문의 상한(기본 64MiB). 묶음과 git 으로 올리는 것이 모두 이 안이어야 한다. 넘으면 413 으로 답하고 읽지 않는다.
    pub upload_limit: usize,
    /// 일정으로 부른 요청에 앱이 답하기를 기다리는 시간(기본 10분, `ORBITAL_SCHEDULE_TIMEOUT`). 넘으면 `timed_out` 으로 적는다.
    pub schedule_timeout: Duration,
    /// 레이어의 기록을 두는 database 의 이름(`ORBITAL_CONTROL_DB`, 기본 `orbital_control`). 관리 연결의 클러스터 안에 둔다.
    /// 같은 이름을 보는 관리 서버들은 같은 기록을 본다. 테스트는 레이어마다 다른 이름을 쓴다.
    pub control_database: Ident,
    /// 이 관리 서버의 기계(`ORBITAL_MACHINE`, 기본 `local`). 이 서버가 세운 인스턴스가 이 기계에 놓인다.
    pub machine: Ident,
    /// 작업의 토큰과 Google 의 `state` 에 서명하는 열쇠(`ORBITAL_TOKEN_KEY`, hex). 관리 서버가 여럿이면 모두 같은 열쇠를 줘야 한쪽이 낸 토큰을
    /// 다른 쪽이 받는다. 주지 않으면 `ORBITAL_HOME/token.key` 를 쓴다(없으면 만든다). 기록(control database)에는 두지 않는다.
    pub token_key: Option<Vec<u8>>,
}

/// 하위 도메인으로 인스턴스를 가르는 레이어의 설정.
pub struct Hosting {
    /// 모든 인스턴스의 요청을 받는 주소(`ORBITAL_ROUTER_LISTEN`).
    pub listen: String,
    /// 기준 도메인(`ORBITAL_BASE_DOMAIN`). `<인스턴스>.<기준 도메인>` 이 운영, `<인스턴스>-preview.<기준 도메인>` 이 프리뷰다.
    pub base: BaseDomain,
    /// 바깥의 스킴(`ORBITAL_PUBLIC_SCHEME`). TLS 는 레이어 앞에서 끝난다고 본다.
    pub scheme: Scheme,
}

impl Options {
    /// 기본값의 설정. 봉인의 열쇠와 개발용 메일함은 없고, 바깥 주소는 `http://127.0.0.1:7400` 이며, 실제 Resend 와 Google 을 부른다.
    pub fn new(
        home: PathBuf,
        pg_url: String,
        service_keys: Vec<(String, String)>,
        runner: Box<dyn Runner>,
    ) -> Self {
        Self {
            home,
            pg_url,
            service_keys,
            runner,
            seal_key: None,
            previous_seal_key: None,
            public_url: "http://127.0.0.1:7400".to_owned(),
            dev_mailbox: false,
            endpoints: Endpoints::default(),
            sleep_after: Duration::from_secs(5 * 60),
            wake_timeout: Duration::from_secs(30),
            wake_queue: 128,
            hosting: None,
            clock: Arc::new(now),
            conformance_timeout: Duration::from_secs(120),
            backup: None,
            token_clock: Arc::new(now),
            upload_limit: 64 * 1024 * 1024,
            schedule_timeout: Duration::from_secs(10 * 60),
            control_database: Ident::parse(CONTROL_DATABASE).expect("기본 이름은 맞는 이름이다"),
            machine: Ident::parse(DEFAULT_MACHINE).expect("기본 이름은 맞는 이름이다"),
            token_key: None,
        }
    }
}

/// 레이어. 속은 [`LayerCore`] 하나를 나눠 쥐는 손잡이다. 뒤에서 도는 일(다시 뜰 때의 빌드, 일정)이 같은 레이어를 쥔다.
pub struct Layer(Arc<LayerCore>);

impl std::ops::Deref for Layer {
    type Target = LayerCore;

    fn deref(&self) -> &LayerCore {
        &self.0
    }
}

/// 레이어의 속. 밖에서는 필드를 보지 못한다.
pub struct LayerCore {
    home: PathBuf,
    /// DB 의 관리 주소. router 가 인증 역할로 붙을 때 사용자와 database 만 바꿔 쓴다.
    pg_url: String,
    /// 레이어의 기록(control database).
    records: Arc<Records>,
    /// 이 기계의 이름을 쥔 것. 레이어가 살아 있는 동안 같은 이름의 관리 서버가 뜨지 못한다.
    _machine_hold: MachineHold,
    /// 팩토리의 설정(메일 · Google 의 키). 봉인한 글로만 기록에 있다.
    settings: Arc<Settings>,
    /// 밖에서 넣는 비밀의 금고. 봉인한 글로만 기록에 있다.
    vault: Arc<Vault>,
    clock: Clock,
    token_clock: Clock,
    upload_limit: usize,
    schedule_timeout: Duration,
    /// 개발용 메일함. 명시해 켰을 때만 있다.
    outbox: Option<Arc<Outbox>>,
    public_url: String,
    endpoints: Endpoints,
    /// Client ID Metadata Documents 를 받아 오는 것. 갈아 끼운다(테스트는 가짜를 쓴다).
    documents: Mutex<Arc<dyn DocumentFetcher>>,
    upstream: String,
    sources: SourceStore,
    runner: Arc<dyn Runner>,
    sleep_after: Duration,
    wake_timeout: Duration,
    wake_queue: usize,
    conformance_timeout: Duration,
    /// 하위 도메인을 쓸 때만 있다.
    hosted: Option<Hosted>,
    runtime: Runtime,
    token_key: Vec<u8>,
    service_keys: Vec<([u8; 32], String)>,
    /// 백업을 켠 레이어에만 있다.
    backup: Option<Backup>,
    /// 지금 되살리거나 무르는 인스턴스. 같은 인스턴스의 되살리기를 겹치지 않게 한다.
    restoring: Mutex<BTreeSet<String>>,
    /// 뜰 때 옛 열쇠로 다시 봉인한 결과. 옛 열쇠를 주지 않았으면 없다.
    resealed: Option<crate::seal::Resealed>,
    /// 뜰 때 평문이던 운영의 신원 열쇠 · 레이어가 만든 비밀을 봉인한 칸의 수.
    sealed_plaintext: usize,
    /// 인스턴스마다의 빌드 자물쇠. 빌드는 레이어의 자물쇠(`inner`) 밖에서 돌고, 같은 인스턴스의 빌드와 빌드 폴더 걷기만 한 줄로 세운다.
    building: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    inner: Mutex<Inner>,
}

/// 백업을 두는 곳과 그 설정.
struct Backup {
    store: Box<dyn orbital_backup::Store>,
    keep_for: Duration,
    require_drill: bool,
}

/// 사용자 목록의 한 줄. 팩토리의 관리 화면이 세운다.
#[derive(Debug, Clone, Serialize)]
pub struct UserReport {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    pub disabled: bool,
    /// 마지막으로 들어온 때(유닉스 초). 한 번도 들어오지 않았으면 `null` 이다.
    pub last_signed_in_at: Option<u64>,
}

/// 업무 역할의 이름을 읽는다. 이름의 모양이 틀리면 고칠 것으로 돌려준다.
fn role_names(roles: &[String]) -> Outcome<Vec<Ident>> {
    roles
        .iter()
        .map(|role| {
            Ident::parse(role)
                .map_err(|error| Failure::Problems(vec![format!("업무 역할 `{role}`: {error}")]))
        })
        .collect()
}

/// 사용자 저장소의 거절을 HTTP 의 답으로 옮긴다. 없는 사용자는 없는 것으로, 선언에 없는 역할은 고칠 것으로.
fn auth_failure(error: orbital_pg::auth::AuthError) -> Failure {
    use orbital_pg::auth::AuthError;
    match error {
        AuthError::UndeclaredRoles { .. } => Failure::Problems(vec![error.to_string()]),
        AuthError::NoSuchUser => Failure::NotFound,
        other => internal(other),
    }
}

/// 같은 기계 이름으로 뜬 앞의 관리 서버가 내려가기를 기다려 주는 시간. 넘으면 뜨지 않는다.
const MACHINE_WAIT: Duration = Duration::from_secs(5);

/// 개발용 메일함의 파일. `ORBITAL_HOME` 아래에 둔다.
pub const OUTBOX: &str = "outbox.jsonl";

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn blocker_text(blocker: &orbital_core::release::Blocker) -> String {
    use orbital_core::release::Blocker;
    match blocker {
        Blocker::NotBuiltByLayer => "레이어가 빌드한 것이 아닙니다".to_owned(),
        Blocker::AccessCheckFailed { findings } => {
            format!("권한 검사에서 어긋남이 {findings}개 나왔습니다")
        }
        Blocker::RehearsalNotRun => {
            "마이그레이션의 리허설을 아직 돌리지 않았습니다. 이 release 로 리허설을 돌려 주세요"
                .to_owned()
        }
        Blocker::RehearsalFailed => "마이그레이션의 리허설이 실패했습니다".to_owned(),
        Blocker::KeyMissing { key } => key_text(*key),
        Blocker::SecretMissing { secret } => secret_text(secret),
        Blocker::ConformanceFailed { outcome } => conformance_text(*outcome),
    }
}

/// 적합성 테스트를 통과하지 못해 막힌 까닭. 테스트는 위쪽의 것이라 고쳐도 소용없고, 포크의 코드를 고쳐야 함을 밝힌다.
pub fn conformance_text(outcome: Conformed) -> String {
    let how = match outcome {
        Conformed::Failed => "실패했습니다",
        Conformed::TimedOut => "제한 시간 안에 끝나지 않았습니다",
        Conformed::NotRun => {
            "돌지 못했습니다(위쪽의 테스트 폴더를 꺼내지 못했거나 명령을 시작하지 못했습니다)"
        }
        Conformed::NotDeclared | Conformed::Passed => "통과했습니다",
    };
    format!(
        "팩토리가 정한 적합성 테스트가 {how}. 테스트는 위쪽(앱)의 것으로 돌아서 포크에서 테스트를 고치거나 지워도 바뀌지 않습니다. 프리뷰의 `conformance.output` 을 보고 앱의 코드를 고친 뒤 프리뷰를 다시 세워 주세요"
    )
}

/// 밖에서 넣는 비밀의 운영 값이 없어 막힌 까닭. 에이전트가 고칠 수 없는 일임을 밝힌다.
pub fn secret_text(secret: &SecretName) -> String {
    format!(
        "비밀 `{secret}` 의 운영 값이 없습니다. 에이전트가 고칠 수 없는 일입니다. 에이전트는 값을 묻거나 코드에 적지 말고 사람에게 이 이름의 입력을 요청하고, 사람이 입력 카드에서 운영의 값을 넣어야 운영에 오릅니다",
        secret = secret.as_str()
    )
}

/// 팩토리의 키가 없어 막힌 까닭. 에이전트가 고칠 수 없는 일임을 밝힌다.
pub fn key_text(key: FactoryKey) -> String {
    match key {
        FactoryKey::Mail => "팩토리가 메일 발송 키를 넣지 않았습니다. 에이전트가 고칠 수 없는 일입니다. 팩토리의 관리자가 설정(`PUT /v1/settings/auth`)에 Resend 키와 보내는 주소를 넣어야 이메일 링크 로그인이 운영에 오릅니다".to_owned(),
        FactoryKey::Google => "팩토리가 Google 로그인 키를 넣지 않았습니다. 에이전트가 고칠 수 없는 일입니다. 팩토리의 관리자가 설정(`PUT /v1/settings/auth`)에 Google 클라이언트의 ID 와 비밀을 넣어야 Google 로그인이 운영에 오릅니다".to_owned(),
    }
}

impl Layer {
    /// metadata 문서를 받아 오는 것을 갈아 끼운다. 테스트가 실제 네트워크에 나가지 않으려고 쓴다.
    #[must_use]
    pub fn with_document_fetcher(self, documents: Arc<dyn DocumentFetcher>) -> Self {
        *self
            .documents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = documents;
        self
    }

    pub fn open(options: Options) -> Result<Self, String> {
        fs::create_dir_all(&options.home)
            .map_err(|_| "레이어의 폴더를 만들지 못했습니다".to_owned())?;
        let config: postgres::Config = options
            .pg_url
            .parse()
            .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
        let host = match config.get_hosts().first() {
            Some(postgres::config::Host::Tcp(host)) => host.clone(),
            _ => return Err("DB 의 주소는 TCP 주소여야 합니다".to_owned()),
        };
        let upstream = format!(
            "{host}:{}",
            config.get_ports().first().copied().unwrap_or(5432)
        );
        let admin = Admin::connect(&options.pg_url).map_err(|error| error.to_string())?;

        let token_key = match options.token_key.clone() {
            Some(key) if key.len() >= 32 => key,
            Some(_) => {
                return Err(
                    "`ORBITAL_TOKEN_KEY` 는 32바이트 이상이어야 합니다. `openssl rand -hex 32` 로 만들어 주세요".to_owned(),
                );
            }
            None => {
                let key_file = options.home.join("token.key");
                match fs::read(&key_file) {
                    Ok(key) if key.len() >= 32 => key,
                    _ => {
                        let key = random(32).map_err(|_| "난수를 읽지 못했습니다".to_owned())?;
                        fs::write(&key_file, &key)
                            .map_err(|_| "토큰의 열쇠를 적지 못했습니다".to_owned())?;
                        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))
                            .map_err(|_| "토큰의 열쇠를 적지 못했습니다".to_owned())?;
                        key
                    }
                }
            }
        };

        if options.previous_seal_key.is_some() && options.seal_key.is_none() {
            return Err(
                "`ORBITAL_SEAL_KEY_PREVIOUS` 는 새 열쇠 `ORBITAL_SEAL_KEY` 와 함께 줘야 합니다. 새 열쇠를 적어 주세요"
                    .to_owned(),
            );
        }
        // 기록은 control database 에 있다. 처음 뜨면 세우고 마이그레이션을 적용한 뒤, 옛 기록 파일이 있으면 한 번 옮긴다
        let records = Arc::new(Records::open(
            &options.pg_url,
            &options.control_database,
            &options.machine,
            options.seal_key.clone(),
            (options.clock)(),
        )?);
        // 이 기계의 이름으로 뜬 관리 서버는 하나뿐이어야 한다. 막 내려가는 앞의 서버는 잠깐 기다려 준다
        let machine_hold = records
            .hold_machine(MACHINE_WAIT)
            .map_err(|error| error.0)?
            .ok_or_else(|| {
                format!(
                    "기계 `{}` 의 이름으로 뜬 관리 서버가 이미 있습니다. 같은 이름의 관리 서버가 둘이면 같은 운영을 둘이 되살립니다. 앞의 관리 서버를 내린 뒤에 띄우거나, 다른 기계라면 `ORBITAL_MACHINE` 으로 다른 이름을 주세요",
                    options.machine.as_str()
                )
            })?;
        if let Some(count) = records.import(&options.home, (options.clock)())? {
            eprintln!(
                "orbitald: 옛 기록 파일을 control database 로 옮겼습니다(인스턴스 {count}개). 옮긴 파일은 `*.imported` 로 이름을 바꿨습니다"
            );
        }
        let vault = Vault::new(Arc::clone(&records), options.seal_key.clone());
        let settings = Settings::new(Arc::clone(&records), options.seal_key.clone());
        // 운영의 신원 열쇠와 레이어가 만든 비밀: 평문이던 줄은 봉인하고, 옛 열쇠를 함께 줬으면 새 열쇠로 다시 봉인한다
        let production = records
            .seal_production(options.previous_seal_key.as_ref())
            .map_err(|error| error.0)?;
        let resealed = match &options.previous_seal_key {
            None => None,
            Some(previous) => {
                let (settings_changed, mut unopened) = settings.reseal(previous)?;
                let (vault_changed, more) = vault.reseal(previous)?;
                unopened.extend(more);
                unopened.extend(production.unopened.iter().cloned());
                Some(crate::seal::Resealed {
                    settings: settings_changed,
                    vault: vault_changed,
                    production: production.resealed,
                    unopened,
                })
            }
        };
        let runtime =
            Runtime::new().map_err(|_| "proxy 의 런타임을 띄우지 못했습니다".to_owned())?;
        let hosted = match options.hosting {
            None => None,
            Some(hosting) => {
                let listener = runtime
                    .block_on(TcpListener::bind(&hosting.listen))
                    .map_err(|_| format!("`{}` 에서 듣지 못했습니다", hosting.listen))?;
                let address = listener
                    .local_addr()
                    .map_err(|_| "router 의 주소를 읽지 못했습니다".to_owned())?;
                let hosts = Hosts::new(hosting.base.clone());
                let task = runtime.spawn(serve_hosts(listener, Arc::clone(&hosts)));
                Some(Hosted {
                    hosts,
                    address,
                    base: hosting.base,
                    scheme: hosting.scheme,
                    _task: task,
                })
            }
        };
        let backup = match options.backup {
            None => None,
            Some(backup) => {
                let tools = orbital_backup::Tools::find().map_err(|error| error.to_string())?;
                let store = orbital_backup::LocalStore::open(tools, backup.root)
                    .map_err(|error| format!("백업의 폴더를 열지 못했습니다. {error}"))?;
                // 운영 클러스터가 WAL 을 보관하지 않으면 시점 복구가 되지 않는다. 적을 명령을 알린다
                let archiving = postgres::Client::connect(&options.pg_url, postgres::NoTls)
                    .and_then(|mut client| client.query_one("SHOW archive_mode", &[]))
                    .map(|row| row.get::<_, String>(0) != "off")
                    .unwrap_or(false);
                if !archiving {
                    return Err(format!(
                        "운영 클러스터가 WAL 을 보관하지 않습니다. postgresql.conf 에 `archive_mode = on` 과 `archive_command = '{}'` 를 적고 클러스터를 다시 띄워 주세요",
                        store.archive_command().replace('\'', "''")
                    ));
                }
                Some(Backup {
                    store: Box::new(store),
                    keep_for: backup.keep_for,
                    require_drill: backup.require_drill,
                })
            }
        };
        let layer = Self(Arc::new(LayerCore {
            backup,
            sources: SourceStore::new(options.home.join("sources")),
            records,
            _machine_hold: machine_hold,
            settings: Arc::new(settings),
            vault: Arc::new(vault),
            sealed_plaintext: production.sealed,
            clock: options.clock,
            token_clock: options.token_clock,
            upload_limit: options.upload_limit,
            schedule_timeout: options.schedule_timeout,
            outbox: options
                .dev_mailbox
                .then(|| Arc::new(Outbox::new(options.home.join(OUTBOX)))),
            public_url: options.public_url.trim_end_matches('/').to_owned(),
            endpoints: options.endpoints,
            documents: Mutex::new(Arc::new(HttpsFetcher)),
            pg_url: options.pg_url,
            upstream,
            runner: Arc::from(options.runner),
            sleep_after: options.sleep_after,
            wake_timeout: options.wake_timeout,
            wake_queue: options.wake_queue,
            conformance_timeout: options.conformance_timeout,
            hosted,
            runtime,
            token_key,
            service_keys: options
                .service_keys
                .iter()
                .map(|(key, organization)| (digest(key), organization.clone()))
                .collect(),
            building: Mutex::new(BTreeMap::new()),
            resealed,
            restoring: Mutex::new(BTreeSet::new()),
            inner: Mutex::new(Inner {
                admin,
                live: BTreeMap::new(),
            }),
            home: options.home,
        }));
        layer.restore();
        layer.listen_for_refresh();
        Ok(layer)
    }

    /// 열쇠를 나중에 준 레이어가 뜰 때 평문이던 운영의 신원 열쇠 · 레이어가 만든 비밀을 봉인한 칸의 수.
    pub fn sealed_plaintext(&self) -> usize {
        self.sealed_plaintext
    }

    /// 레이어의 기록. 테스트와 `orbitald drill` 이 읽는다.
    pub fn records(&self) -> &Records {
        &self.records
    }

    /// 이 관리 서버의 기계.
    pub fn machine(&self) -> &str {
        self.records.machine()
    }

    /// 알림을 듣는 연결. 붙지 못하면 `None` 이다.
    fn listening(&self) -> Option<postgres::Client> {
        let mut client = self.records.connect().ok()?;
        client
            .batch_execute(&format!("LISTEN {REFRESH_CHANNEL}"))
            .ok()?;
        Some(client)
    }

    /// 다른 기계의 관리 서버가 「이 인스턴스의 서비스를 재워 달라」고 알리는 것을 듣는다. 놓인 기계에서 비밀의 값이 바뀌면
    /// 다음 요청이 새 값으로 깬다. 레이어가 내려가면 듣기를 멈춘다.
    ///
    /// 듣던 연결이 끊기면(DB 가 다시 떴다) 다시 붙는다. 끊긴 사이의 알림은 받지 못했으므로, 다시 붙으면 이 기계에 떠 있는
    /// 서버 서비스를 모두 재운다. 다음 요청이 지금의 값으로 깬다.
    fn listen_for_refresh(&self) {
        let mut client = self.listening();
        if client.is_none() {
            eprintln!(
                "orbitald: 다른 관리 서버의 알림을 듣지 못합니다. 다시 붙을 때까지 다른 기계에서 바꾼 비밀은 서비스가 다시 깰 때 실립니다"
            );
        }
        let weak = Arc::downgrade(&self.0);
        std::thread::spawn(move || {
            loop {
                let Some(mut heard) = client.take().filter(|client| !client.is_closed()) else {
                    std::thread::sleep(Duration::from_millis(500));
                    let Some(core) = weak.upgrade() else {
                        return;
                    };
                    let layer = Layer(core);
                    client = layer.listening();
                    if client.is_some() {
                        layer.sleep_all();
                    }
                    continue;
                };
                let received: Vec<String> = {
                    let mut notifications = heard.notifications();
                    let mut found = Vec::new();
                    let mut waiting = notifications.timeout_iter(Duration::from_millis(500));
                    while let Ok(Some(notification)) =
                        postgres::fallible_iterator::FallibleIterator::next(&mut waiting)
                    {
                        found.push(notification.payload().to_owned());
                    }
                    found
                };
                // 레이어를 쥐는 것은 알림이 왔을 때만이다. 쥔 채로 기다리면 레이어가 내려가지 못한다
                if weak.strong_count() == 0 {
                    return;
                }
                client = Some(heard);
                if received.is_empty() {
                    continue;
                }
                let Some(core) = weak.upgrade() else {
                    return;
                };
                let layer = Layer(core);
                for payload in received {
                    let mut parts = payload.split(' ');
                    let (Some(machine), Some(instance), Some(stage)) =
                        (parts.next(), parts.next(), parts.next())
                    else {
                        continue;
                    };
                    if machine != layer.machine() {
                        continue;
                    }
                    let (Ok(instance), Some(stage)) =
                        (InstanceId::parse(instance), SecretStage::parse(stage))
                    else {
                        continue;
                    };
                    layer.sleep_services(&instance, Stage::of(stage));
                }
            }
        });
    }

    /// 뜰 때 옛 열쇠(`ORBITAL_SEAL_KEY_PREVIOUS`)로 다시 봉인한 결과. 바꾼 줄의 수와 풀리지 않는 줄의 이름만 있다.
    pub fn resealed(&self) -> Option<&crate::seal::Resealed> {
        self.resealed.as_ref()
    }

    /// 하위 도메인을 쓰는 레이어가 모든 인스턴스의 요청을 받는 주소. 포트마다 주소를 내는 레이어에는 없다.
    pub fn router_address(&self) -> Option<SocketAddr> {
        self.hosted.as_ref().map(|hosted| hosted.address)
    }

    /// 관리 서버가 다시 떴을 때 기록에서 운영 중인 인스턴스의 router 를 「자는」 상태로 다시 세운다. 첫 요청에 깬다.
    ///
    /// 기록(control database)의 운영 release · 서명의 열쇠 · 레이어가 만든 비밀 · 듣던 포트와, 레이어가 빌드한 폴더를 믿는다.
    /// 빌드한 폴더가 없으면 router 만 먼저 세워 서비스로 가는 요청에 503 과 `Retry-After` 로 답하게 하고, 그 commit 에서의 빌드는
    /// 레이어의 자물쇠 밖(뒤의 스레드)에서 한다. 빌드가 끝나면 같은 주소에서 선다. 다른 인스턴스와 API 는 그 빌드를 기다리지 않는다.
    /// 프리뷰는 되살리지 않는다(다시 세우면 된다). 되살리지 못한 인스턴스는 건너뛰고 식별자와 갈래만 알린다.
    fn restore(&self) {
        let mut inner = self.lock();
        // 이 기계에 놓인 인스턴스만 되살린다. 다른 기계의 운영은 그 기계의 관리 서버가 되살린다
        let mine: Vec<(String, InstanceRecord)> = match self.records.instances() {
            Ok(all) => all
                .into_iter()
                .filter(|(_, record)| record.machine == self.machine())
                .collect(),
            Err(_) => {
                eprintln!("orbitald: 레이어의 기록을 읽지 못해 운영을 되살리지 않았습니다");
                Vec::new()
            }
        };
        // 프리뷰는 되살리지 않는다. 앞의 관리 서버가 세워 둔 프리뷰의 database 는 운영을 다 세운 뒤에 뒤에서 걷는다.
        // database 하나를 지우는 데 0.5초쯤 걸려, 먼저 걷으면 프리뷰의 수만큼 운영이 늦게 선다
        let stale: Vec<(String, String)> = mine
            .iter()
            .filter_map(|(id, record)| Some((id.clone(), record.preview.clone()?)))
            .collect();
        let mut building = Vec::new();
        for (id, record) in mine {
            if record.production.is_none() {
                continue;
            }
            let Ok(instance) = InstanceId::parse(&id) else {
                continue;
            };
            match self.revive(&instance, &record) {
                Ok((live, port)) => {
                    if live.building {
                        building.push(instance);
                    }
                    // 앞의 포트를 잡지 못해 새 포트를 잡았으면 기록을 고친다. 옛 기록에 없던 주소와 선언도 이때 채운다
                    let (origin, manifest) = (live.origin.clone(), live.manifest.get().clone());
                    let noted = self.records.update_instance(&id, |record| {
                        if let Some(production) = record.production.as_mut() {
                            production.port = port;
                            production.origin = Some(origin);
                            production.manifest = Some(manifest);
                        }
                        Ok::<(), Failure>(())
                    });
                    if noted.is_err() {
                        eprintln!("orbitald: 레이어의 기록을 적지 못했습니다");
                    }
                    inner.live.insert((id, Stage::Production), live);
                }
                Err(failure) => {
                    eprintln!(
                        "orbitald: 운영 {id} 를 되살리지 못했습니다({})",
                        failure_kind(&failure)
                    );
                }
            }
        }
        drop(inner);
        if !stale.is_empty() {
            let weak = Arc::downgrade(&self.0);
            std::thread::spawn(move || {
                for (id, preview) in stale {
                    // 레이어가 내려갔으면 멈춘다. 기록에 이름이 남아 있어 다음에 뜰 때 걷는다
                    let Some(core) = weak.upgrade() else {
                        return;
                    };
                    Layer(core).sweep_preview(&id, &preview);
                }
            });
        }
        if !building.is_empty() {
            // 뒤의 스레드는 레이어를 약하게 쥔다. 레이어가 내려가면 남은 빌드를 하지 않는다
            let weak = Arc::downgrade(&self.0);
            std::thread::spawn(move || {
                for instance in building {
                    let Some(core) = weak.upgrade() else {
                        return;
                    };
                    Layer(core).finish_revive(&instance);
                }
            });
        }
    }

    /// 앞의 관리 서버가 세워 둔 프리뷰의 database 하나를 걷고 기록에서 그 이름을 지운다. 그사이 새 프리뷰를 세웠으면
    /// 기록의 이름은 새것이므로 건드리지 않는다(프리뷰의 이름은 세울 때마다 새로 지어 겹치지 않는다).
    fn sweep_preview(&self, id: &str, preview: &str) {
        let mut inner = self.lock();
        let destroyed = InstanceId::parse(preview)
            .map_err(internal)
            .and_then(|preview| inner.admin.destroy(&Names::new(preview)).map_err(internal));
        let noted = destroyed.and_then(|()| {
            self.records
                .update_instance(id, |record| {
                    if record.preview.as_deref() == Some(preview) {
                        record.preview = None;
                    }
                    Ok::<(), Failure>(())
                })
                .map(|_| ())
        });
        if noted.is_err() {
            eprintln!("orbitald: {id} 의 앞 프리뷰 database 를 걷지 못했습니다");
        }
    }

    /// 기록의 운영을 다시 세운다. 빌드 폴더가 있으면 자는 채로, 없으면 빌드를 기다리며 503 으로 답하는 채로 선다.
    /// 세운 것과, 포트마다 주소를 내는 레이어에서 router 가 듣는 포트를 돌려준다.
    fn revive(
        &self,
        instance: &InstanceId,
        record: &InstanceRecord,
    ) -> Outcome<(Live, Option<u16>)> {
        let production = record
            .production
            .as_ref()
            .ok_or_else(|| internal("운영의 기록이 없습니다"))?;
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
        // 운영의 비밀이 금고에서 풀리지 않으면(열쇠가 바뀌었거나 줄이 빠졌으면) 값 없이 세우지 않는다
        let missing = self.missing_secrets(&record.organization, instance, &assembled.manifest);
        if !missing.is_empty() {
            return Err(Failure::Denied(PromoteDenied::Blocked {
                blockers: missing
                    .into_iter()
                    .map(|secret| orbital_core::release::Blocker::SecretMissing { secret })
                    .collect(),
            }));
        }
        let folder = self.builds_folder(instance).join(&assembled.release.0);
        let built = folder.join(BUILT_MARKER).is_file();
        let names = Names::new(instance.clone());
        let identity_key = identity_key_of(production)?;
        let stand = Stand {
            names: &names,
            generated: &production.generated,
            identity_key: &identity_key,
            stage: Stage::Production,
            organization: &record.organization,
            app: &record.app,
            port: production.port,
        };
        let mode = if built { Mode::Asleep } else { Mode::Building };
        let launched = self.launch(instance, &assembled, &folder, &stand, mode, None)?;
        let port = launched.port;
        Ok((
            Live {
                release: production.release.clone(),
                origin: launched.origin,
                names,
                manifest: assembled.manifest.clone(),
                seed_users: Vec::new(),
                services: launched.services,
                router: launched.handle,
                building: !built,
                _router: launched.router,
            },
            port,
        ))
    }

    /// 빌드를 기다리던 운영을 레이어의 자물쇠 밖에서 빌드하고, 끝나면 같은 자리(포트 · 하위 도메인)에 자는 채로 세운다.
    /// 그동안 운영이 바뀌었으면(승격 · 되살리기 · 지우기) 아무것도 하지 않는다. 빌드가 실패하면 503 으로 답하던 것을 걷는다.
    fn finish_revive(&self, instance: &InstanceId) {
        let key = (instance.as_str().to_owned(), Stage::Production);
        let Ok(Some(record)) = self.records.instance(instance.as_str()) else {
            return;
        };
        let Some(production) = record.production.clone() else {
            return;
        };
        let still_waiting = |inner: &Inner| {
            inner
                .live
                .get(&key)
                .is_some_and(|live| live.building && live.release == production.release)
        };
        let built = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))
            .and_then(|commit| self.assembled(instance, &commit))
            .and_then(|assembled| {
                let folder = self.build(instance, &assembled)?;
                Ok((assembled, folder))
            });
        let mut inner = self.lock();
        if !still_waiting(&inner) {
            return;
        }
        let (assembled, folder) = match built {
            Ok(built) => built,
            Err(failure) => {
                eprintln!(
                    "orbitald: 운영 {} 를 되살리지 못했습니다({})",
                    instance.as_str(),
                    failure_kind(&failure)
                );
                inner.live.remove(&key);
                return;
            }
        };
        let Some(old) = inner.live.remove(&key) else {
            return;
        };
        let Live {
            origin, _router, ..
        } = old;
        let names = Names::new(instance.clone());
        let Some(identity_key) = token::unhex(&production.identity_key) else {
            return;
        };
        let stand = Stand {
            names: &names,
            generated: &production.generated,
            identity_key: &identity_key,
            stage: Stage::Production,
            organization: &record.organization,
            app: &record.app,
            port: production.port,
        };
        match self.launch(
            instance,
            &assembled,
            &folder,
            &stand,
            Mode::Asleep,
            Some((_router, origin)),
        ) {
            Ok(launched) => {
                inner.live.insert(
                    key,
                    Live {
                        release: production.release.clone(),
                        origin: launched.origin,
                        names,
                        manifest: assembled.manifest.clone(),
                        seed_users: Vec::new(),
                        services: launched.services,
                        router: launched.handle,
                        building: false,
                        _router: launched.router,
                    },
                );
            }
            Err(failure) => eprintln!(
                "orbitald: 운영 {} 를 되살리지 못했습니다({})",
                instance.as_str(),
                failure_kind(&failure)
            ),
        }
    }
}

/// 운영의 신원 열쇠. 기록의 봉인이 이 레이어의 열쇠로 풀리지 않았으면(열쇠를 옛 열쇠 없이 바꿨다) 까닭을 알린다.
fn identity_key_of(production: &ProductionRecord) -> Outcome<Vec<u8>> {
    if production.identity_key.starts_with("seal1.") {
        return Err(Failure::Conflict(
            "운영의 신원 열쇠가 이 레이어의 봉인 열쇠로 풀리지 않습니다. 레이어의 운영자가 봉인의 열쇠를 바꿨다면 옛 열쇠를 `ORBITAL_SEAL_KEY_PREVIOUS` 로 함께 주고 다시 띄워야 합니다".to_owned(),
        ));
    }
    token::unhex(&production.identity_key).ok_or_else(|| internal("서명의 열쇠를 읽지 못했습니다"))
}

/// 되살리지 못한 까닭의 갈래. 기록에는 이것만 남긴다.
fn failure_kind(failure: &Failure) -> &'static str {
    match failure {
        Failure::BuildFailed { .. } => "build_failed",
        Failure::StartFailed { .. } => "start_failed",
        Failure::Denied(_) => "secret_missing",
        _ => "internal",
    }
}

/// 작업의 토큰이 살 수 있는 가장 긴 때(초). 거둔 작업은 그만큼 장부에 둔다.
const TOKEN_LONGEST: u64 = 12 * 60 * 60;

/// 저장소에서 한 번 도는 빌드(`[build]`)가 실패했을 때 `BuildFailed` 의 서비스 자리에 적는 이름.
pub const REPOSITORY_BUILD: &str = "[build]";

/// 빌드가 끝났다는 표시. 빌드 폴더 안에 둔다.
const BUILT_MARKER: &str = ".orbital-built";

// ---- 누구인가 ----

impl Layer {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // 다른 일이 하다가 깨졌어도 기록은 control database 에 있으므로 메모리를 이어 쓴다
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// service key 의 조직. 팩토리의 서버만 갖는 열쇠다.
    pub fn organization(&self, key: &str) -> Outcome<String> {
        let given = digest(key);
        self.service_keys
            .iter()
            .find(|(known, _)| known == &given)
            .map(|(_, organization)| organization.clone())
            .ok_or(Failure::Unauthorized)
    }

    /// 토큰이 이 인스턴스에서 이 일을 해도 되는지 본다. 판정은 core 가 한다.
    /// 거둔 작업의 토큰은 서명이 맞고 만료 전이어도 만료된 것과 같이 401 이다(진행 중인 git 의 다음 왕복도).
    pub fn authorize(&self, bearer: &str, instance: &InstanceId, action: Action) -> Outcome<()> {
        let token = token::verify(&self.token_key, bearer).ok_or(Failure::Unauthorized)?;
        // 닫은 작업은 요청마다 control database 에서 본다. 다른 관리 서버가 닫았어도 다음 요청부터 받지 않는다
        if self
            .records
            .revoked(token.instance.as_str(), &token::session_of(bearer))?
        {
            return Err(Failure::Unauthorized);
        }
        let organization = OrganizationId(self.record_of(instance)?.organization);
        let request = Request {
            organization,
            instance: instance.clone(),
            action,
            at: (self.token_clock)(),
        };
        match judge(&token, &request) {
            Verdict::Allow => Ok(()),
            Verdict::Deny(DenyReason::NotFound) => Err(Failure::NotFound),
            Verdict::Deny(DenyReason::Expired) => Err(Failure::Unauthorized),
            Verdict::Deny(DenyReason::ServiceKeyOnly) => {
                Err(Failure::Forbidden("토큰으로는 할 수 없는 일입니다. 운영을 바꾸는 일은 팩토리의 서버가 사람의 승인을 받아 합니다".to_owned()))
            }
            Verdict::Deny(DenyReason::NotGranted) => Err(Failure::Forbidden("이 토큰에는 그 능력이 없습니다".to_owned())),
        }
    }

    /// 인스턴스가 길에 없는 일(rollout 을 만들거나 다시 여는 일)을 토큰이 두드렸을 때, 토큰이 발급받은 인스턴스로 판정한다.
    pub fn authorize_own(&self, bearer: &str, action: Action) -> Outcome<()> {
        let token = token::verify(&self.token_key, bearer).ok_or(Failure::Unauthorized)?;
        self.authorize(bearer, &token.instance, action)
    }

    /// 인스턴스의 기록. 없으면 404 다.
    fn record_of(&self, instance: &InstanceId) -> Outcome<InstanceRecord> {
        self.records
            .instance(instance.as_str())?
            .ok_or(Failure::NotFound)
    }

    /// 그 팩토리의 인스턴스의 기록. 다른 팩토리의 것은 없는 것과 같다.
    fn owned(&self, organization: &str, instance: &InstanceId) -> Outcome<InstanceRecord> {
        // 기록을 읽지 못한 것은 「없다」가 아니다. 그대로 알린다
        let record = self.record_of(instance)?;
        if record.organization != organization {
            return Err(Failure::NotFound);
        }
        Ok(record)
    }

    /// 이 기계가 이 인스턴스의 그 일을 해도 되는가. 판정은 core 의 `placement` 가 한다.
    fn placed(&self, record: &InstanceRecord, errand: Errand) -> Outcome<()> {
        judge_place(errand, &record.machine, self.machine()).map_err(|misplaced| {
            Failure::Misplaced {
                machine: misplaced.machine,
            }
        })
    }

    /// 인스턴스가 있고 이 기계가 그 일을 해도 되는지 본다. 기록을 돌려준다.
    fn here(&self, instance: &InstanceId, errand: Errand) -> Outcome<InstanceRecord> {
        let record = self.record_of(instance)?;
        self.placed(&record, errand)?;
        Ok(record)
    }

    /// 인스턴스의 줄을 잠그고 고친다. 없으면 404 다.
    fn update<T>(
        &self,
        instance: &InstanceId,
        change: impl FnOnce(&mut InstanceRecord) -> Outcome<T>,
    ) -> Outcome<T> {
        self.records
            .update_instance(instance.as_str(), change)?
            .ok_or(Failure::NotFound)
    }
}

// ---- 팩토리의 서버가 하는 일(service key) ----

impl Layer {
    fn app_path(&self, organization: &str, app: &Ident) -> Outcome<PathBuf> {
        let organization = Ident::parse(organization)
            .map_err(|_| internal("조직의 이름을 폴더 이름으로 쓸 수 없습니다"))?;
        Ok(self
            .home
            .join("apps")
            .join(organization.as_str())
            .join(format!("{app}.git")))
    }

    /// 스캐폴드를 올린다. 묶음에 든 버전(태그와 브랜치)을 모두 받는다.
    pub fn put_app(&self, organization: &str, app: &str, bundle: &[u8]) -> Outcome<()> {
        let app = Ident::parse(app)
            .map_err(|error| Failure::Problems(vec![format!("앱의 이름 `{app}`: {error}")]))?;
        let _guard = self.lock();
        // 앱의 코드 저장소는 처음 받은 기계에 있다. 다른 기계에 있는 앱은 그 기계가 받는다
        let machine = self
            .records
            .claim_app(organization, app.as_str(), (self.clock)())?;
        if machine != self.machine() {
            return Err(Failure::Misplaced { machine });
        }
        receive_scaffold(&self.app_path(organization, &app)?, bundle).map_err(|error| match error {
            SourceError::BadBundle => Failure::Problems(vec![error.to_string()]),
            other => internal(other),
        })
    }

    /// 앱의 코드 저장소가 이 기계에 있는지 본다. 다른 기계에 있으면 그 기계의 이름으로 답한다.
    fn app_here(&self, organization: &str, app: &Ident) -> Outcome<()> {
        match self.records.app_machine(organization, app.as_str())? {
            Some(machine) if machine != self.machine() => Err(Failure::Misplaced { machine }),
            _ => Ok(()),
        }
    }

    /// 고객 하나의 인스턴스를 스캐폴드의 한 버전에서 세운다. 코드 저장소만 생기고, DB 와 서버는 첫 승격 때 선다.
    pub fn create_instance(
        &self,
        organization: &str,
        app: &str,
        version: &str,
    ) -> Outcome<InstanceId> {
        let app = Ident::parse(app).map_err(|_| Failure::NotFound)?;
        self.app_here(organization, &app)?;
        let scaffold = self.app_path(organization, &app)?;
        if !scaffold.join("HEAD").is_file() {
            return Err(Failure::NotFound);
        }
        // 복구 훈련이 통과한 뒤에만 새 고객의 데이터를 받는다
        self.require_fresh_drill()?;
        let _inner = self.lock();
        let instance = fresh_id('i')?;
        self.sources
            .create(&instance, &scaffold, version)
            .map_err(|error| match error {
                SourceError::NoSuchVersion => Failure::Problems(vec![format!(
                    "스캐폴드 `{app}` 에 `{version}` 버전이 없습니다"
                )]),
                other => internal(other),
            })?;
        // 인스턴스는 세운 관리 서버의 기계에 놓인다. 코드 저장소가 이 기계에 생겼다
        let written = self.records.insert_instance(
            instance.as_str(),
            &InstanceRecord {
                organization: organization.to_owned(),
                app: app.to_string(),
                machine: self.machine().to_owned(),
                ..InstanceRecord::default()
            },
        );
        if let Err(error) = written {
            let _ = self.sources.destroy(&instance);
            return Err(error.into());
        }
        Ok(instance)
    }

    /// 에이전트의 작업 한 번에 쓸 토큰을 낸다. 누가 이 인스턴스를 고칠 수 있는지는 팩토리가 이미 판정했다.
    /// (토큰, 만료되는 때, 작업의 식별자). 작업의 식별자로 만료 전에 거둔다([`Layer::close_session`]).
    pub fn open_session(
        &self,
        organization: &str,
        instance: &InstanceId,
        can: BTreeSet<Capability>,
        ttl_seconds: u64,
    ) -> Outcome<(String, u64, String)> {
        self.owned(organization, instance)?;
        let expires_at = (self.token_clock)() + ttl_seconds.clamp(60, TOKEN_LONGEST);
        let token = Token {
            organization: OrganizationId(organization.to_owned()),
            instance: instance.clone(),
            can,
            expires_at,
        };
        let signed = token::sign(&self.token_key, &token, &token::hex(&random(16)?));
        let session = token::session_of(&signed);
        Ok((signed, expires_at, session))
    }

    /// 작업을 닫는다. 그 토큰으로 도는 다음 요청부터 받지 않는다. 장부에는 토큰이 살 수 있는 가장 긴 때까지 기억한다.
    /// 모르는 식별자여도 같은 답이다(토큰을 모르면 지을 수 없다). 다른 팩토리의 인스턴스는 없는 것과 같다.
    pub fn close_session(
        &self,
        organization: &str,
        instance: &InstanceId,
        session: &str,
    ) -> Outcome<()> {
        let shaped = session.len() == 32
            && session
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !shaped {
            return Err(Failure::NotFound);
        }
        self.owned(organization, instance)?;
        let now = (self.token_clock)();
        self.records
            .revoke(instance.as_str(), session, now + TOKEN_LONGEST, now)
            .map_err(Failure::from)
    }
}

// ---- 에이전트가 하는 일(토큰) ----

impl Layer {
    pub fn source_bundle(&self, instance: &InstanceId) -> Outcome<Vec<u8>> {
        self.here(instance, Errand::SourceBundle)?;
        let _guard = self.lock();
        self.sources.bundle(instance).map_err(internal)
    }

    /// 묶음으로 올린 것을 받는다. git 으로 올린 것(`git_exchange`)과 같은 규칙으로 판정한다.
    pub fn push(&self, instance: &InstanceId, bundle: &[u8]) -> Outcome<Commit> {
        self.here(instance, Errand::Push)?;
        let inner = self.lock();
        let commit = self
            .sources
            .receive(instance, bundle)
            .map_err(|error| match error {
                SourceError::BadBundle | SourceError::NotFastForward | SourceError::Refused(_) => {
                    Failure::Problems(vec![error.to_string()])
                }
                other => internal(other),
            })?;
        self.received(instance, &commit)?;
        drop(inner);
        Ok(commit)
    }

    /// 올린 commit 을 받은 뒤의 일. 묶음과 git 의 두 길이 함께 부른다.
    fn received(&self, instance: &InstanceId, commit: &Commit) -> Outcome<()> {
        // 에이전트가 업데이트를 합쳐(충돌을 풀어) 올렸으면 적용된 것이다
        self.track(
            instance,
            commit,
            &[RolloutEvent::Applied {
                instance: instance.clone(),
            }],
        )
    }

    /// 요청 본문의 상한.
    pub fn upload_limit(&self) -> usize {
        self.upload_limit
    }

    /// git 의 광고. 받기는 `main` 과 열린 rollout 의 `update` 만 보이고, 올리기는 `main` 하나만 알린다.
    pub fn git_advertise(&self, instance: &InstanceId, service: GitService) -> Outcome<Vec<u8>> {
        self.here(instance, Errand::Git)?;
        self.sources
            .advertise(instance, service)
            .map_err(|error| match error {
                SourceError::NoSuchInstance => Failure::NotFound,
                other => internal(other),
            })
    }

    /// git 과 객체를 주고받는다. 올리기는 묶음과 같은 자리를 지나고, 받으면 묶음으로 올린 것과 같은 뒤의 일을 한다.
    /// `request` 는 이미 풀린(gzip 이 아닌) 본문이다.
    pub fn git_exchange(
        &self,
        instance: &InstanceId,
        service: GitService,
        request: &[u8],
    ) -> Outcome<Exchanged> {
        self.here(instance, Errand::Git)?;
        let source_failure = |error: SourceError| match error {
            SourceError::NoSuchInstance => Failure::NotFound,
            SourceError::BadBundle => Failure::Problems(vec![error.to_string()]),
            other => internal(other),
        };
        match service {
            // 받기는 읽기만 한다. ref 는 한 번에 옮겨 가므로 잠그지 않는다
            GitService::UploadPack => self
                .sources
                .upload_pack(instance, request.to_vec())
                .map(Exchanged::Stream)
                .map_err(source_failure),
            GitService::ReceivePack => {
                let _inner = self.lock();
                let received = self
                    .sources
                    .receive_pack(instance, request)
                    .map_err(source_failure)?;
                if let Some(commit) = &received.commit {
                    self.received(instance, commit)?;
                }
                Ok(Exchanged::Bytes(received.report))
            }
        }
    }

    /// 떠 있는 프리뷰의 빌드와 서버의 로그(끝의 200줄씩). 프리뷰의 앱은 에이전트가 쓴 코드이고 씨앗 데이터만 갖는다.
    pub fn preview_logs(&self, instance: &InstanceId) -> Outcome<PreviewLogs> {
        self.here(instance, Errand::Preview)?;
        let (release, manifest) = {
            let inner = self.lock();
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Preview))
                .ok_or_else(|| {
                    Failure::Conflict(
                        "떠 있는 프리뷰가 없습니다. 프리뷰를 먼저 세워 주세요".to_owned(),
                    )
                })?;
            (live.release.clone(), live.manifest.clone())
        };
        let id = ReleaseId(release.clone());
        let mut logs = Vec::new();
        if manifest.get().build.is_some() {
            let name = "build".to_owned();
            let text = tail(&self.log(instance, &id, &name), &self.home, 200);
            logs.push(LogReport { name, text });
        }
        for service in &manifest.get().services {
            let mut names = vec![format!("build-{}", service.name)];
            if service.kind == ServiceKind::Server {
                names.push(format!("preview-{}", service.name));
            }
            for name in names {
                let text = tail(&self.log(instance, &id, &name), &self.home, 200);
                logs.push(LogReport { name, text });
            }
        }
        Ok(PreviewLogs { release, logs })
    }

    fn assembled(&self, instance: &InstanceId, commit: &Commit) -> Outcome<Assembled> {
        assemble(&self.sources, instance, commit).map_err(|error| match error {
            AssembleError::Problems(problems) => Failure::Problems(problems),
            AssembleError::Source(SourceError::NoSuchCommit) => Failure::Problems(vec![
                "그 commit 은 레이어에 올라와 있지 않습니다. `main` 에 commit 해 먼저 올려 주세요"
                    .to_owned(),
            ]),
            AssembleError::Source(other) => internal(other),
        })
    }

    fn log(&self, instance: &InstanceId, release: &ReleaseId, name: &str) -> PathBuf {
        self.home
            .join("logs")
            .join(instance.as_str())
            .join(&release.0)
            .join(format!("{name}.log"))
    }

    /// 인스턴스의 빌드 폴더들이 사는 곳. release 마다 그 아래에 폴더 하나다.
    fn builds_folder(&self, instance: &InstanceId) -> PathBuf {
        self.home.join("builds").join(instance.as_str())
    }

    /// 인스턴스의 빌드가 홈으로 쓰는 곳. 도구의 캐시가 여기에 쌓이고 다른 인스턴스와 나누지 않는다.
    fn cache_folder(&self, instance: &InstanceId) -> PathBuf {
        self.home.join("caches").join(instance.as_str())
    }

    /// 인스턴스의 빌드 자물쇠.
    fn build_gate(&self, instance: &InstanceId) -> Arc<Mutex<()>> {
        let mut gates = self
            .building
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(gates.entry(instance.as_str().to_owned()).or_default())
    }

    /// 떠 있지 않은 release 의 빌드 폴더를 걷는다. 프리뷰와 운영에 떠 있는 것과 기록의 운영 release 만 남긴다.
    /// 빌드 폴더마다 의존성(`node_modules`)이 들어 수백 MB 가 되므로, 남겨 두면 commit 마다 쌓인다.
    /// 걷은 release 가 다시 필요하면(되돌리기 · 관리 서버의 재시작) [`Self::build`] 가 그 commit 에서 다시 빌드한다.
    fn prune_builds(&self, inner: &Inner, instance: &InstanceId) {
        let mut keep: Vec<&str> = [Stage::Preview, Stage::Production]
            .iter()
            .filter_map(|stage| inner.live.get(&(instance.as_str().to_owned(), *stage)))
            .map(|live| live.release.as_str())
            .collect();
        let recorded = self
            .records
            .instance(instance.as_str())
            .ok()
            .flatten()
            .and_then(|record| record.production)
            .map(|production| production.release);
        if let Some(release) = &recorded {
            keep.push(release);
        }
        // 같은 인스턴스의 빌드가 돌고 있으면 그 폴더를 걷지 않게 이번에는 건너뛴다. 다음 프리뷰나 승격이 걷는다
        let gate = self.build_gate(instance);
        let Ok(_building) = gate.try_lock() else {
            return;
        };
        let Ok(entries) = fs::read_dir(self.builds_folder(instance)) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            if !keep.iter().any(|release| entry.file_name() == **release) {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    /// release 를 그 commit 에서 직접 빌드한다. 이미 빌드했으면 그것을 쓴다.
    fn build(&self, instance: &InstanceId, assembled: &Assembled) -> Outcome<PathBuf> {
        let gate = self.build_gate(instance);
        let _building = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let folder = self.builds_folder(instance).join(&assembled.release.0);
        let marker = folder.join(BUILT_MARKER);
        if marker.is_file() {
            return Ok(folder);
        }
        let _ = fs::remove_dir_all(&folder);
        self.sources
            .export(instance, &assembled.commit, &folder)
            .map_err(internal)?;
        let cache = self.cache_folder(instance);
        // 저장소에서 한 번 도는 빌드(`[build]`)가 서비스의 빌드보다 먼저 돈다. 같은 실행기 · 같은 환경 · 같은 폴더다
        if let Some(repository) = &assembled.manifest.get().build {
            let log = self.log(instance, &assembled.release, "build");
            let job = Job {
                folder: &folder,
                command: &repository.command,
                env: &[],
                log: &log,
                home: Some(&cache),
            };
            self.runner.build(&job).map_err(|_| Failure::BuildFailed {
                service: REPOSITORY_BUILD.to_owned(),
                log: tail(&log, &self.home, 40),
            })?;
        }
        for service in &assembled.manifest.get().services {
            let log = self.log(
                instance,
                &assembled.release,
                &format!("build-{}", service.name),
            );
            // 도구의 캐시(npm 의 `~/.npm` 같은 것)는 인스턴스마다 따로 둔다. 다른 인스턴스의 빌드가 건드리지 못하게 나누지 않는다
            let job = Job {
                folder: &folder,
                command: &service.build,
                env: &[],
                log: &log,
                home: Some(&cache),
            };
            self.runner.build(&job).map_err(|_| Failure::BuildFailed {
                service: service.name.to_string(),
                log: tail(&log, &self.home, 40),
            })?;
        }
        fs::write(&marker, assembled.commit.as_str())
            .map_err(|_| internal("빌드의 표시를 적지 못했습니다"))?;
        Ok(folder)
    }

    /// 빌드한 것을 띄운다. 서버 서비스마다 proxy 를 하나 세우고, 앱에는 그 주소와 레이어가 만든 비밀만 건넨다.
    /// 서비스들 앞에 router 를 세운다. 밖에서는 router 의 주소로만 닿는다.
    ///
    /// `mode` 가 서버 서비스를 지금 띄울지([`Mode::Awake`]), 자는 채로 세울지, 빌드가 끝날 때까지 503 으로 답할지를 정한다.
    /// 어느 쪽이든 요청이 없으면 정한 시간 뒤에 잔다. `reuse` 를 주면 그 자리(포트)에서 듣기를 멈추지 않고 router 만 바꿔 넣는다.
    fn launch(
        &self,
        instance: &InstanceId,
        assembled: &Assembled,
        folder: &Path,
        stand: &Stand<'_>,
        mode: Mode,
        reuse: Option<(Front, String)>,
    ) -> Outcome<Launched> {
        let (names, generated, stage) = (stand.names, stand.generated, stand.stage);
        // 하위 도메인을 쓰면 레이어의 주소 하나가 받고, 아니면 인스턴스마다 포트 하나를 듣는다
        let (listener, origin, host, reused) = match (&self.hosted, reuse) {
            // 앞의 것(빌드를 기다리던 router)은 새 router 를 하위 도메인의 표에 넣은 뒤에 내려간다. 그 사이에 404 가 없다
            (Some(hosted), old) => {
                let target = match stage {
                    Stage::Preview => HostTarget::Preview(instance.clone()),
                    Stage::Production => HostTarget::Production(instance.clone()),
                };
                let origin = host_origin(hosted.scheme, &hosted.base, &target);
                (None, origin, Some(target), old.map(|(front, _)| front))
            }
            (None, Some((front, origin))) => (None, origin, None, Some(front)),
            (None, None) => {
                let listener = self.listen(stand.port)?;
                let origin = format!(
                    "http://127.0.0.1:{}",
                    listener.local_addr().map_err(internal)?.port()
                );
                (Some(listener), origin, None, None)
            }
        };
        let port = self
            .hosted
            .is_none()
            .then(|| origin.rsplit(':').next().and_then(|port| port.parse().ok()))
            .flatten();
        let url = |path: &str| format!("{origin}{}", path.trim_end_matches('/'));
        let mut services = Vec::new();
        let mut targets = BTreeMap::new();
        for service in &assembled.manifest.get().services {
            if mode == Mode::Building {
                targets.insert(service.name.to_string(), RouterTarget::Pending);
                services.push(LiveService {
                    name: service.name.to_string(),
                    kind: service.kind,
                    url: url(&service.path),
                    server: None,
                    proxy: None,
                });
                continue;
            }
            if service.kind == ServiceKind::Static {
                let output = folder.join(service.output.as_deref().unwrap_or_default());
                if !output.is_dir() {
                    return Err(Failure::StartFailed {
                        service: service.name.to_string(),
                        log: "빌드 결과의 폴더(`output`)가 없습니다. 빌드 명령이 그 폴더를 만드는지 확인해 주세요".to_owned(),
                    });
                }
                targets.insert(
                    service.name.to_string(),
                    RouterTarget::Static { folder: output },
                );
                services.push(LiveService {
                    name: service.name.to_string(),
                    kind: service.kind,
                    url: url(&service.path),
                    server: None,
                    proxy: None,
                });
                continue;
            }

            // 포트(`PORT`)는 띄울 때마다 새로 받는다. 자고 깨면 바뀐다
            // 듣는 주소. 프레임워크마다 읽는 이름이 달라 둘 다 건넨다(`next start` 는 `HOSTNAME` 을 읽는다)
            let mut env = vec![
                ("HOST".to_owned(), "127.0.0.1".to_owned()),
                ("HOSTNAME".to_owned(), "127.0.0.1".to_owned()),
                // 프리뷰에서 메일을 보내지 않는 것처럼, 앱이 어디에 섰는지에 따라 달리 굴 일이 있다
                (
                    "ORBITAL_STAGE".to_owned(),
                    match stage {
                        Stage::Preview => "preview",
                        Stage::Production => "production",
                    }
                    .to_owned(),
                ),
            ];
            let mut proxy = None;
            if !service.roles.is_empty() {
                let listener = self.unclaimed_listener()?;
                let proxy_port = listener.local_addr().map_err(internal)?.port();
                let route = Route::for_service(names, &assembled.manifest, &service.name);
                proxy = Some(
                    self.runtime
                        .spawn(serve(listener, self.upstream.clone(), route)),
                );
                // 비밀번호는 없다. 앱은 사용자 자리에 업무 역할의 이름을 적어 이 주소로 붙는다
                for (key, value) in [
                    ("ORBITAL_DB_HOST", "127.0.0.1".to_owned()),
                    ("ORBITAL_DB_PORT", proxy_port.to_string()),
                    ("PGHOST", "127.0.0.1".to_owned()),
                    ("PGPORT", proxy_port.to_string()),
                    ("PGDATABASE", "app".to_owned()),
                ] {
                    env.push((key.to_owned(), value));
                }
            }
            env.extend(
                generated
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );

            let label = if stage == Stage::Preview {
                "preview"
            } else {
                "production"
            };
            let log = self.log(
                instance,
                &assembled.release,
                &format!("{label}-{}", service.name),
            );
            let starter = Arc::new(ServiceStarter {
                runner: Arc::clone(&self.runner),
                folder: folder.to_path_buf(),
                command: service.start.clone().unwrap_or_default(),
                env,
                external: External {
                    vault: Arc::clone(&self.vault),
                    organization: stand.organization.to_owned(),
                    instance: instance.clone(),
                    stage: stage.vault(),
                    names: assembled.manifest.get().secrets.external.clone(),
                },
                log: log.clone(),
                wake_timeout: self.wake_timeout,
            });
            let server = AppServer::new(
                service.name.as_str(),
                Arc::clone(&starter) as Arc<dyn Starter>,
                self.sleep_after,
                self.wake_timeout,
                self.wake_queue,
                self.runtime.handle().clone(),
            );
            let live = LiveService {
                name: service.name.to_string(),
                kind: service.kind,
                url: url(&service.path),
                server: Some(Arc::clone(&server)),
                proxy,
            };
            if mode == Mode::Awake {
                // 깨울 때와 같은 길로 띄운다. 받은 포트를 다른 프로세스가 먼저 잡아 앱이 끝나면 포트를 바꿔 한 번 더 띄운다
                let (process, port) =
                    start_on_free_port(starter.as_ref()).map_err(|_| Failure::StartFailed {
                        service: service.name.to_string(),
                        log: tail(&log, &self.home, 40),
                    })?;
                server.adopt(process, port);
            }
            targets.insert(service.name.to_string(), RouterTarget::Server(server));
            services.push(live);
        }

        let label = if stage == Stage::Preview {
            "preview"
        } else {
            "production"
        };
        let log = self.log(instance, &assembled.release, &format!("{label}-router"));
        if let Some(parent) = log.parent() {
            fs::create_dir_all(parent).map_err(|_| internal("기록의 폴더를 만들지 못했습니다"))?;
        }
        let auth: Option<Connect> = assembled.manifest.get().auth.as_ref().map(|_| {
            let (url, names, manifest) = (
                self.pg_url.clone(),
                names.clone(),
                assembled.manifest.clone(),
            );
            Arc::new(move || AuthStore::connect(&url, &names, &manifest)) as Connect
        });
        // 메일과 Google 은 팩토리의 키로 한다. 프리뷰의 router 는 메일을 보내지 않고 Google 의 문이 없다
        let mailer = Arc::new(FactoryMailer {
            settings: Arc::clone(&self.settings),
            organization: stand.organization.to_owned(),
            app: stand.app.to_owned(),
            resend: Resend::new(&self.endpoints.resend),
            outbox: self.outbox.clone(),
        });
        let declares_google = assembled
            .manifest
            .get()
            .auth
            .as_ref()
            .is_some_and(|auth| auth.uses(orbital_core::manifest::Auth::GOOGLE));
        let google = (stage == Stage::Production && declares_google).then(|| {
            Arc::new(FactoryGoogleDoor {
                settings: Arc::clone(&self.settings),
                organization: stand.organization.to_owned(),
                instance: instance.as_str().to_owned(),
                state_key: self.token_key.clone(),
                callback: callback_url(&self.public_url),
                authorize_endpoint: self.endpoints.google_authorize.clone(),
            }) as Arc<dyn GoogleDoor>
        });
        let config = RouterConfig {
            origin: origin.clone(),
            manifest: assembled.manifest.clone(),
            names: names.clone(),
            identity_key: stand.identity_key.to_vec(),
            targets,
            auth,
            mailer,
            google,
            stage: match stage {
                Stage::Preview => RouterStage::Preview,
                Stage::Production => RouterStage::Production,
            },
            seed_users: Self::seed_ids(assembled, stage),
            log: Some(log),
            documents: Arc::clone(
                &self
                    .documents
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
        };
        let handle = Router::new(config);
        let router = match (listener, host, &self.hosted, reused) {
            (Some(listener), _, _, _) => {
                let slot = Arc::new(RwLock::new(handle.clone()));
                Front::Port {
                    task: self.runtime.spawn(serve_slot(listener, Arc::clone(&slot))),
                    slot,
                }
            }
            (None, Some(target), Some(hosted), _) => {
                hosted.hosts.insert(target.clone(), &handle);
                Front::Host {
                    hosts: Arc::clone(&hosted.hosts),
                    target,
                    router: handle.clone(),
                }
            }
            (None, None, None, Some(front @ Front::Port { .. })) => {
                if let Front::Port { slot, .. } = &front {
                    *slot
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = handle.clone();
                }
                front
            }
            _ => return Err(internal("router 를 세울 자리가 없습니다")),
        };
        Ok(Launched {
            services,
            router,
            handle,
            origin,
            port,
        })
    }

    /// router 가 들을 포트를 잡는다. `preferred` 를 먼저 잡아 보고(앞의 router 가 막 내려가는 중이면 잠깐 되풀이한다),
    /// 잡지 못하면 빈 포트를 잡는다.
    fn listen(&self, preferred: Option<u16>) -> Outcome<TcpListener> {
        // 방금 앱에 내준 포트(아직 듣지 않아 비어 보인다)는 잡지 않는다
        if let Some(port) = preferred.filter(|port| !orbital_run::handed(*port)) {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if let Ok(listener) = self
                    .runtime
                    .block_on(TcpListener::bind(("127.0.0.1", port)))
                {
                    return Ok(listener);
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        self.unclaimed_listener()
    }

    /// 운영체제가 준 빈 포트에서 듣는다. 방금 앱에 내준 포트가 오면 놓고 다시 받는다.
    fn unclaimed_listener(&self) -> Outcome<TcpListener> {
        for _ in 0..64 {
            let listener = self
                .runtime
                .block_on(TcpListener::bind("127.0.0.1:0"))
                .map_err(internal)?;
            let port = listener.local_addr().map_err(internal)?.port();
            if !orbital_run::handed(port) {
                return Ok(listener);
            }
        }
        Err(internal("빈 포트를 찾지 못했습니다"))
    }

    /// 씨앗 사용자의 식별자. 프리뷰에만 있다.
    fn seed_ids(assembled: &Assembled, stage: Stage) -> Vec<String> {
        if stage == Stage::Preview {
            assembled
                .seed_users
                .iter()
                .map(|user| user.id.to_string())
                .collect()
        } else {
            Vec::new()
        }
    }

    fn secrets(assembled: &Assembled) -> Outcome<BTreeMap<String, String>> {
        let mut generated = BTreeMap::new();
        for name in &assembled.manifest.get().secrets.generated {
            generated.insert(name.as_str().to_owned(), token::hex(&random(32)?));
        }
        Ok(generated)
    }

    fn report(services: &[LiveService]) -> Vec<ServiceReport> {
        services
            .iter()
            .map(|service| ServiceReport {
                name: service.name.clone(),
                kind: service.kind,
                url: Some(service.url.clone()),
            })
            .collect()
    }

    /// 운영에 올라 있는 release 가 밖에서 넣는다고 선언한 비밀. 운영이 없으면 비어 있다.
    fn production_external(
        &self,
        instance: &InstanceId,
        record: &InstanceRecord,
    ) -> Outcome<Vec<SecretName>> {
        let Some(production) = &record.production else {
            return Ok(Vec::new());
        };
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        Ok(self
            .assembled(instance, &commit)?
            .manifest
            .get()
            .secrets
            .external
            .clone())
    }

    /// 운영에 오른 release 의 재료. 운영이 아직 없으면 `None` 이다.
    fn production_assembled(
        &self,
        instance: &InstanceId,
        record: &InstanceRecord,
    ) -> Outcome<Option<Assembled>> {
        let Some(production) = &record.production else {
            return Ok(None);
        };
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        self.assembled(instance, &commit).map(Some)
    }

    /// 운영과 견준 변화의 문장. 승인 카드에 선다. 일정이 도는 업무 역할의 변화를 먼저, 권한 표의 변화를 그 뒤에 적는다.
    fn change_sentences(
        &self,
        instance: &InstanceId,
        record: &InstanceRecord,
        assembled: &Assembled,
    ) -> Outcome<Vec<String>> {
        let production = self.production_assembled(instance, record)?;
        let (access, schedules) = match &production {
            Some(production) => (
                production.access.clone(),
                production.manifest.get().schedules.clone(),
            ),
            None => (Access::default(), Vec::new()),
        };
        let mut sentences = schedule_changes(&schedules, &assembled.manifest.get().schedules);
        sentences.extend(
            changes(&access, &assembled.access)
                .into_iter()
                .map(|change| change.sentence),
        );
        Ok(sentences)
    }

    /// commit 하나의 프리뷰를 세운다. 그 commit 에서 직접 빌드하고, 씨앗 데이터만 든 DB 를 새로 만들어 역할과 권한을 세우고, 권한 검사를 돌린다.
    pub fn preview(&self, instance: &InstanceId, commit: Option<Commit>) -> Outcome<PreviewReport> {
        self.here(instance, Errand::Preview)?;
        let commit = match commit {
            Some(commit) => commit,
            None => self.sources.head(instance).map_err(internal)?,
        };
        let assembled = self.assembled(instance, &commit)?;
        // 빌드(npm ci 와 프레임워크의 빌드)는 분 단위로 걸린다. 레이어의 자물쇠를 쥐지 않고 돌려 다른 인스턴스의 일을 막지 않는다
        let folder = self.build(instance, &assembled)?;

        let mut inner = self.lock();
        // 빌드하는 동안 인스턴스가 지워졌거나 운영이 바뀌었을 수 있다. 기록은 자물쇠를 쥔 뒤에 다시 읽는다
        let record = self.record_of(instance)?;

        // 앞의 프리뷰를 걷는다. 인스턴스마다 프리뷰는 하나다
        if let Some(old) = inner
            .live
            .remove(&(instance.as_str().to_owned(), Stage::Preview))
        {
            let names = old.names.clone();
            drop(old);
            inner.admin.destroy(&names).map_err(internal)?;
        }
        self.drop_recorded_preview(&mut inner, instance)?;

        let names = Names::new(fresh_id('p')?);
        // 세우기 전에 적어 둔다. 도중에 관리 서버가 내려가도 다시 뜰 때 이 database 를 걷는다
        self.note_preview(instance, Some(&names))?;
        let identity_key = random(32)?;
        let prepared =
            self.prepare_preview_database(&mut inner.admin, &names, &assembled, &identity_key);
        let findings = match prepared {
            Ok(findings) => findings,
            Err(failure) => {
                let _ = inner.admin.destroy(&names);
                return Err(failure);
            }
        };
        let generated = Self::secrets(&assembled)?;
        let stand = Stand {
            names: &names,
            generated: &generated,
            identity_key: &identity_key,
            stage: Stage::Preview,
            organization: &record.organization,
            app: &record.app,
            port: None,
        };
        let launched = match self.launch(instance, &assembled, &folder, &stand, Mode::Awake, None) {
            Ok(launched) => launched,
            Err(failure) => {
                let _ = inner.admin.destroy(&names);
                return Err(failure);
            }
        };

        // 위쪽이 정한 적합성 테스트를 이 프리뷰에 대해 돌린다
        let conformance = self.conform(instance, &assembled, &launched.origin);
        let conformed = conformance
            .as_ref()
            .map_or(Conformed::NotDeclared, |report| report.outcome);

        // 운영에 아직 돌지 않은 마이그레이션이 있으면 리허설이 필요하다
        let rehearsal = match &record.production {
            None => Rehearsed::NotNeeded,
            Some(_) => {
                let all: Vec<&str> = assembled
                    .migrations
                    .iter()
                    .map(|script| script.name.as_str())
                    .collect();
                let pending = inner
                    .admin
                    .pending(&Names::new(instance.clone()), &all)
                    .map_err(internal)?;
                match record.releases.get(&assembled.release.0) {
                    _ if pending.is_empty() => Rehearsed::NotNeeded,
                    Some(known) if known.rehearsal != Rehearsed::NotNeeded => known.rehearsal,
                    _ => Rehearsed::NotRun,
                }
            }
        };
        let report = PreviewReport {
            release: assembled.release.0.clone(),
            commit: commit.to_string(),
            services: Self::report(&launched.services),
            findings: findings.iter().map(ToString::to_string).collect(),
            changes: self.change_sentences(instance, &record, &assembled)?,
            blockers: blockers(&Release {
                id: assembled.release.clone(),
                built_by: BuiltBy::Layer,
                access_findings: findings.len(),
                rehearsal,
                missing_keys: self.missing_keys(&record.organization, &assembled.manifest),
                missing_secrets: self.missing_secrets(
                    &record.organization,
                    instance,
                    &assembled.manifest,
                ),
                conformance: conformed,
            })
            .iter()
            .map(blocker_text)
            .collect(),
            notices: unguarded(&assembled.manifest, &assembled.access)
                .iter()
                .map(|table| {
                    format!(
                        "표 `{table}` 은 행 단위 규칙을 꺼서 역할 제한이 걸리지 않습니다. 권한 표대로 그 역할의 연결이면 신원 없이도 읽힙니다"
                    )
                })
                .collect(),
            missing_secrets: missing_secrets(
                &assembled.manifest,
                &self
                    .vault
                    .filled(&record.organization, instance, SecretStage::Preview),
            )
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
            conformance,
        };

        let release = ReleaseRecord {
            commit: commit.to_string(),
            access_findings: findings.len(),
            rehearsal,
            external: assembled
                .manifest
                .get()
                .secrets
                .external
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
            conformance: conformed,
        };
        self.update(instance, |stored| {
            stored.releases.insert(assembled.release.0.clone(), release);
            Ok(())
        })?;
        // 업데이트를 담은 commit 이면 그 rollout 에 적용 · 프리뷰 · 검사의 결과를 넘긴다
        self.track(
            instance,
            &commit,
            &[
                RolloutEvent::Applied {
                    instance: instance.clone(),
                },
                RolloutEvent::Previewed {
                    instance: instance.clone(),
                },
                RolloutEvent::Checked {
                    instance: instance.clone(),
                    access_passed: findings.is_empty(),
                    conformance_passed: conformed.clears(),
                },
            ],
        )?;
        inner.live.insert(
            (instance.as_str().to_owned(), Stage::Preview),
            Live {
                release: assembled.release.0.clone(),
                origin: launched.origin,
                names,
                seed_users: Self::seed_ids(&assembled, Stage::Preview),
                manifest: assembled.manifest.clone(),
                services: launched.services,
                router: launched.handle,
                building: false,
                _router: launched.router,
            },
        );
        self.prune_builds(&inner, instance);
        Ok(report)
    }

    /// 프리뷰의 database 를 기록에 적거나 지운다.
    fn note_preview(&self, instance: &InstanceId, names: Option<&Names>) -> Outcome<()> {
        self.records.update_instance(instance.as_str(), |record| {
            record.preview = names.map(|names| names.instance().as_str().to_owned());
            Ok::<(), Failure>(())
        })?;
        Ok(())
    }

    fn prepare_preview_database(
        &self,
        admin: &mut Admin,
        names: &Names,
        assembled: &Assembled,
        identity_key: &[u8],
    ) -> Outcome<Vec<orbital_core::check::Finding>> {
        admin
            .provision(names, &assembled.manifest)
            .map_err(internal)?;
        admin
            .install_identity(names, identity_key)
            .map_err(internal)?;
        // 앱의 마이그레이션이 사용자를 외래 키로 가리킬 수 있게 마이그레이션 앞에 둔다
        admin
            .install_auth(names, &assembled.manifest)
            .map_err(internal)?;
        let scripts: Vec<(&str, &str)> = assembled
            .migrations
            .iter()
            .map(|script| (script.name.as_str(), script.sql.as_str()))
            .collect();
        admin.migrate_named(names, &scripts).map_err(|error| {
            Failure::MigrationFailed(format!(
                "빈 DB 에 마이그레이션을 돌리다가 실패했습니다. {error}"
            ))
        })?;
        // 씨앗 데이터의 SQL 이 씨앗 사용자를 가리킬 수 있게 그 앞에 넣는다. 프리뷰에만 들어간다
        admin
            .seed_users(names, &assembled.seed_users, now())
            .map_err(|error| {
                Failure::MigrationFailed(format!("씨앗 사용자를 넣다가 실패했습니다. {error}"))
            })?;
        let seed: Vec<&str> = assembled
            .seed
            .iter()
            .map(|script| script.sql.as_str())
            .collect();
        admin.migrate(names, &seed).map_err(|error| {
            Failure::MigrationFailed(format!("씨앗 데이터를 넣다가 실패했습니다. {error}"))
        })?;
        admin
            .grant(names, &assembled.manifest, &assembled.access)
            .map_err(internal)?;
        let snapshot = admin.snapshot(names).map_err(internal)?;
        Ok(judge_access(
            names,
            &assembled.manifest,
            &assembled.access,
            &snapshot,
        ))
    }

    /// 프리뷰에서 씨앗 사용자로 요청해 볼 수 있게 그 사용자의 세션을 만들고, 요청에 그대로 붙일 `Cookie` 머리말의 값을 돌려준다.
    ///
    /// 프리뷰의 DB 에만 있는 세션이라 운영에서는 읽히지 않는다. 씨앗 사용자(`db/seed/users.toml`)만 된다.
    pub fn preview_session(&self, instance: &InstanceId, user: &str) -> Outcome<String> {
        self.here(instance, Errand::Preview)?;
        let (names, manifest) = {
            let inner = self.lock();
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Preview))
                .ok_or_else(|| {
                    Failure::Conflict(
                        "떠 있는 프리뷰가 없습니다. 프리뷰를 먼저 세워 주세요".to_owned(),
                    )
                })?;
            if live.manifest.get().auth.is_none() {
                return Err(Failure::Problems(vec![
                    "이 앱은 로그인을 레이어에 맡기지 않아 사용자가 없습니다. `orbital.toml` 에 `[auth]` 를 적어 주세요".to_owned(),
                ]));
            }
            if !live.seed_users.iter().any(|seed| seed == user) {
                return Err(Failure::Problems(vec![format!(
                    "씨앗 사용자 `{user}` 가 없습니다. `db/seed/users.toml` 에 적힌 식별자로 들어가 주세요"
                )]));
            }
            (live.names.clone(), live.manifest.clone())
        };
        let mut store = AuthStore::connect(&self.pg_url, &names, &manifest).map_err(internal)?;
        let (session, _) = store.start_session(user, now()).map_err(internal)?;
        Ok(format!("{SESSION_COOKIE}={}", session.to_text()))
    }

    /// 프리뷰를 걷는다.
    pub fn stop_preview(&self, instance: &InstanceId) -> Outcome<()> {
        self.here(instance, Errand::Preview)?;
        let mut inner = self.lock();
        if let Some(old) = inner
            .live
            .remove(&(instance.as_str().to_owned(), Stage::Preview))
        {
            let names = old.names.clone();
            drop(old);
            inner.admin.destroy(&names).map_err(internal)?;
        }
        self.drop_recorded_preview(&mut inner, instance)?;
        self.note_preview(instance, None)
    }

    /// 기록에 이름으로만 남은 프리뷰의 database 를 걷는다. 다시 뜬 뒤 뒤에서 걷기 전의 것이거나, 앞에서 걷다 만 것이다.
    /// 기록의 이름을 덮거나 지우기 전에 부른다. 이름을 잃으면 그 database 를 걷을 길이 없어 클러스터에 남는다.
    fn drop_recorded_preview(&self, inner: &mut Inner, instance: &InstanceId) -> Outcome<()> {
        let recorded = self
            .record_of(instance)?
            .preview
            .and_then(|preview| InstanceId::parse(&preview).ok());
        if let Some(preview) = recorded {
            inner
                .admin
                .destroy(&Names::new(preview))
                .map_err(internal)?;
        }
        Ok(())
    }

    /// 운영 DB 의 사본에 아직 돌지 않은 마이그레이션을 미리 돌려 본다. 숫자만 돌아온다.
    pub fn rehearse(&self, instance: &InstanceId, release: &str) -> Outcome<RehearsalReport> {
        self.here(instance, Errand::Rehearse)?;
        let mut inner = self.lock();
        let record = self.record_of(instance)?;
        let known = record.releases.get(release).ok_or_else(|| {
            Failure::Conflict(
                "그 release 의 프리뷰가 없습니다. 프리뷰를 먼저 세워 주세요".to_owned(),
            )
        })?;
        let commit = Commit::parse(&known.commit)
            .ok_or_else(|| internal("release 의 commit 을 읽지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
        let names = Names::new(instance.clone());
        let mut report = RehearsalReport {
            release: release.to_owned(),
            needed: false,
            passed: true,
            millis: 0,
            failed_at: None,
            sqlstate: None,
            tables: Vec::new(),
        };
        let mut outcome = Rehearsed::NotNeeded;
        if record.production.is_some() {
            let all: Vec<&str> = assembled
                .migrations
                .iter()
                .map(|script| script.name.as_str())
                .collect();
            let pending = inner.admin.pending(&names, &all).map_err(internal)?;
            let scripts: Vec<&orbital_source::assemble::Script> = assembled
                .migrations
                .iter()
                .filter(|script| pending.contains(&script.name))
                .collect();
            if !scripts.is_empty() {
                let sql: Vec<&str> = scripts.iter().map(|script| script.sql.as_str()).collect();
                // 복제는 원본에 다른 연결이 없어야 한다. 잠깐 문을 닫는다
                inner.admin.quiesce(&names).map_err(internal)?;
                let rehearsed = inner.admin.rehearse(&names, &sql);
                inner.admin.resume(&names).map_err(internal)?;
                let rehearsed = rehearsed.map_err(internal)?;
                outcome = if rehearsed.passed {
                    Rehearsed::Passed
                } else {
                    Rehearsed::Failed
                };
                report.needed = true;
                report.passed = rehearsed.passed;
                report.millis = rehearsed.millis;
                report.failed_at = rehearsed
                    .failed_at
                    .and_then(|at| scripts.get(at))
                    .map(|script| script.name.clone());
                report.sqlstate = rehearsed.sqlstate;
                report.tables = rehearsed
                    .tables
                    .into_iter()
                    .map(|count| (count.table, count.before, count.after))
                    .collect();
            }
        }
        self.update(instance, |stored| {
            if let Some(stored) = stored.releases.get_mut(release) {
                stored.rehearsal = outcome;
            }
            Ok(())
        })?;
        Ok(report)
    }

    /// 승격을 요청한다. 막는 것이 있으면 요청하지 못한다. 올리는 것은 사람의 승인을 받은 팩토리의 서버다.
    pub fn request_promotion(&self, instance: &InstanceId, release: &str) -> Outcome<()> {
        let record = self.here(instance, Errand::PromotionRequest)?;
        let known = record.releases.get(release).ok_or_else(|| {
            Failure::Conflict(
                "그 release 의 프리뷰가 없습니다. 프리뷰를 먼저 세워 주세요".to_owned(),
            )
        })?;
        let commit = Commit::parse(&known.commit)
            .ok_or_else(|| internal("release 의 commit 을 읽지 못했습니다"))?;
        let (access_findings, rehearsal, conformance) =
            (known.access_findings, known.rehearsal, known.conformance);
        let organization = record.organization.clone();
        let manifest = self.assembled(instance, &commit)?.manifest;
        let found = blockers(&Release {
            id: ReleaseId(release.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings,
            rehearsal,
            missing_keys: self.missing_keys(&organization, &manifest),
            missing_secrets: self.missing_secrets(&organization, instance, &manifest),
            conformance,
        });
        if !found.is_empty() {
            return Err(Failure::Denied(PromoteDenied::Blocked { blockers: found }));
        }
        self.update(instance, |record| {
            record.promotion_requested = Some(release.to_owned());
            Ok(())
        })
    }
}

// ---- 운영에 올리기(service key) ----

impl Layer {
    /// 사람이 승인한 release 를 운영에 올린다. 올리기 직전의 DB 를 되돌릴 지점으로 떠 두고, 중간에 깨지면 거기로 돌아간다.
    pub fn promote(
        &self,
        organization: &str,
        instance: &InstanceId,
        release: &str,
        change: Change,
        approved_by: Approver,
    ) -> Outcome<PromotionReport> {
        // 빌드 폴더가 없으면(걷었거나 기계를 옮겼다) 레이어의 자물쇠 밖에서 먼저 빌드한다. 판정은 자물쇠를 쥔 뒤에 한다
        let commit = {
            let record = self.owned(organization, instance)?;
            self.placed(&record, Errand::Promote)?;
            record
                .releases
                .get(release)
                .and_then(|known| Commit::parse(&known.commit))
        };
        if let Some(commit) = commit {
            let assembled = self.assembled(instance, &commit)?;
            self.build(instance, &assembled)?;
        }
        let mut inner = self.lock();
        let record = self.owned(organization, instance)?;
        // 운영을 내리기 전에 신원 열쇠가 풀리는지 본다. 풀리지 않으면 운영을 건드리지 않는다
        if let Some(production) = &record.production {
            identity_key_of(production)?;
        }
        let known = record.releases.get(release).ok_or(Failure::NotFound)?;
        let commit = Commit::parse(&known.commit)
            .ok_or_else(|| internal("release 의 commit 을 읽지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
        let facts = Release {
            id: ReleaseId(release.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings: known.access_findings,
            rehearsal: known.rehearsal,
            // 팩토리의 키는 올리는 때의 것을 본다. 앞에서 넣었다가 지웠으면 막힌다
            missing_keys: self.missing_keys(organization, &assembled.manifest),
            // 밖에서 넣는 비밀도 올리는 때의 운영 칸을 본다
            missing_secrets: self.missing_secrets(organization, instance, &assembled.manifest),
            // 적합성 테스트는 프리뷰에서 돈 결과를 본다
            conformance: known.conformance,
        };
        // 승인은 호출에 적힌 release 하나에 묶인다. 승인한 뒤 commit 이 더해졌으면 식별자가 달라 여기서 찾지 못하거나 리허설이 다시 필요하다
        let approval = Approval {
            release: ReleaseId(release.to_owned()),
            by: approved_by,
        };
        judge_promotion(&facts, change, Some(&approval)).map_err(Failure::Denied)?;
        // 업데이트를 담은 release 면 그 rollout 의 관문(멈춤 · 물결 · 통과 · change)을 지나야 한다
        let governing = self.governing(instance, &commit)?;
        if let Some(id) = &governing
            && let Some(record) = self.records.rollout(id)?
        {
            record
                .rollout
                .may_promote(instance, change)
                .map_err(|refusal| Failure::Conflict(refusal_text(&refusal)))?;
        }

        let folder = self.build(instance, &assembled)?;
        let names = Names::new(instance.clone());
        let key = (instance.as_str().to_owned(), Stage::Production);

        // 선언에서 뺀 역할은 이 승격에서 걷는다. 그 역할이 아직 무엇의 주인이면 운영을 건드리기 전에 멈춘다
        if record.production.is_some() {
            let owners = inner
                .admin
                .stale_owners(&names, &assembled.manifest)
                .map_err(internal)?;
            if let Some(role) = owners.into_iter().next() {
                return Err(Failure::Conflict(
                    orbital_pg::Error::RoleOwnsObjects { role }.to_string(),
                ));
            }
        }

        // 운영의 서버를 내린다. 그래야 DB 에 붙은 연결이 없어 되돌릴 지점을 뜰 수 있다
        inner.live.remove(&key);

        let (identity_key, generated, point) = match &record.production {
            None => {
                inner
                    .admin
                    .provision(&names, &assembled.manifest)
                    .map_err(internal)?;
                let identity_key = random(32)?;
                inner
                    .admin
                    .install_identity(&names, &identity_key)
                    .map_err(internal)?;
                (identity_key, Self::secrets(&assembled)?, None)
            }
            Some(production) => {
                // 선언에 서비스나 역할이 더해졌으면 그 로그인을 세운다
                inner
                    .admin
                    .provision(&names, &assembled.manifest)
                    .map_err(internal)?;
                inner.admin.quiesce(&names).map_err(internal)?;
                let marked = inner.admin.mark(&names);
                inner.admin.resume(&names).map_err(internal)?;
                let identity_key = identity_key_of(production)?;
                // 검증 함수를 레이어의 지금 모양(v2 · granted)으로 맞춘다. 열쇠는 그대로다
                inner
                    .admin
                    .install_identity(&names, &identity_key)
                    .map_err(internal)?;
                let mut generated = production.generated.clone();
                for (name, value) in Self::secrets(&assembled)? {
                    generated.entry(name).or_insert(value);
                }
                (identity_key, generated, Some(marked.map_err(internal)?))
            }
        };

        let scripts: Vec<(&str, &str)> = assembled
            .migrations
            .iter()
            .map(|script| (script.name.as_str(), script.sql.as_str()))
            .collect();
        let target = Target {
            instance,
            assembled: &assembled,
            folder: &folder,
            names: &names,
            generated: &generated,
            identity_key: &identity_key,
            organization: &record.organization,
            app: &record.app,
            port: record
                .production
                .as_ref()
                .and_then(|production| production.port),
        };
        let outcome = self.promote_onto(&mut inner, &target, &scripts);
        let (launched, ran) = match outcome {
            Ok(done) => done,
            Err((failure, migrated)) => {
                // 새 release 가 서지 못했다. 어디로 돌아갈지는 core 가 정한다
                let kind = if migrated {
                    Migrations::Destructive
                } else {
                    Migrations::None
                };
                let prior = Prior {
                    instance,
                    record: &record,
                    names: &names,
                };
                let failure = self.back_out(&mut inner, &prior, point.as_ref(), kind, failure);
                // 업데이트를 담은 release 가 서지 못하고 되돌려졌다. 그 인스턴스는 실패로 적히고 rollout 이 멈춘다
                if let Some(id) = &governing {
                    let _ = self.record(
                        id,
                        &[RolloutEvent::RolledBack {
                            instance: instance.clone(),
                        }],
                    );
                }
                return Err(failure);
            }
        };

        // 앞의 승격이 남긴 되돌릴 지점은 지운다. 지점은 하나만 둔다
        if let Some(old) = record
            .production
            .as_ref()
            .and_then(|production| production.restore_point.clone())
        {
            let _ = inner.admin.forget(RestorePoint::named(old));
        }
        let report = PromotionReport {
            release: release.to_owned(),
            services: Self::report(&launched.services),
            migrations: ran,
            schedules: Self::schedule_report(&assembled.manifest, &BTreeMap::new(), (self.clock)()),
        };
        let production = ProductionRecord {
            release: release.to_owned(),
            previous: record
                .production
                .as_ref()
                .map(|production| production.release.clone()),
            restore_point: point.as_ref().map(|point| point.database().to_owned()),
            // 되살리기를 무를 수 있는지는 되돌릴 지점이 그대로인지로 본다. 이 승격으로 지점이 바뀌었으니 까닭을 알리려고 남긴다
            restored: record
                .production
                .as_ref()
                .and_then(|production| production.restored.clone()),
            identity_key: token::hex(&identity_key),
            generated,
            port: launched.port,
            origin: Some(launched.origin.clone()),
            manifest: Some(assembled.manifest.get().clone()),
        };
        self.update(instance, |stored| {
            stored.production = Some(production);
            stored.promotion_requested = None;
            Ok(())
        })?;
        if let Some(id) = &governing {
            self.record(
                id,
                &[RolloutEvent::Promoted {
                    instance: instance.clone(),
                    change,
                }],
            )?;
        }
        inner.live.insert(
            key,
            Live {
                release: release.to_owned(),
                origin: launched.origin,
                names,
                manifest: assembled.manifest.clone(),
                seed_users: Vec::new(),
                services: launched.services,
                router: launched.handle,
                building: false,
                _router: launched.router,
            },
        );
        self.prune_builds(&inner, instance);
        Ok(report)
    }

    /// 마이그레이션을 돌리고, 권한을 세워 검사하고, 서버를 띄운다. 실패하면 마이그레이션이 돌았는지를 함께 돌려준다.
    fn promote_onto(
        &self,
        inner: &mut Inner,
        target: &Target<'_>,
        scripts: &[(&str, &str)],
    ) -> Result<Raised, Fallen> {
        let (names, assembled) = (target.names, target.assembled);
        // 앱의 마이그레이션이 사용자를 외래 키로 가리킬 수 있게 마이그레이션 앞에 둔다. 다시 불러도 되고, 뷰의 권한을 선언에 맞춘다
        inner
            .admin
            .install_auth(names, &assembled.manifest)
            .map_err(|error| (internal(error), false))?;
        let ran = inner.admin.migrate_named(names, scripts).map_err(|error| {
            (
                Failure::MigrationFailed(format!(
                    "운영 DB 에 마이그레이션을 돌리다가 실패했습니다. {error}"
                )),
                true,
            )
        })?;
        let migrated = !ran.is_empty();
        inner
            .admin
            .grant(names, &assembled.manifest, &assembled.access)
            .map_err(|error| (internal(error), migrated))?;
        // 선언에서 뺀 묶음과 로그인을 걷는다. 권한 검사는 남은 역할을 어긋남으로 본다
        inner
            .admin
            .retire(names, &assembled.manifest)
            .map_err(|error| (Failure::Conflict(error.to_string()), migrated))?;
        let snapshot = inner
            .admin
            .snapshot(names)
            .map_err(|error| (internal(error), migrated))?;
        let findings = judge_access(names, &assembled.manifest, &assembled.access, &snapshot);
        if !findings.is_empty() {
            let text: Vec<String> = findings.iter().map(ToString::to_string).collect();
            return Err((
                Failure::Conflict(format!(
                    "운영 DB 의 권한이 권한 표와 다릅니다: {}",
                    text.join(" / ")
                )),
                migrated,
            ));
        }
        let stand = Stand {
            names,
            generated: target.generated,
            identity_key: target.identity_key,
            stage: Stage::Production,
            organization: target.organization,
            app: target.app,
            port: target.port,
        };
        let launched = self
            .launch(
                target.instance,
                assembled,
                target.folder,
                &stand,
                Mode::Awake,
                None,
            )
            .map_err(|failure| (failure, migrated))?;
        Ok((launched, ran))
    }

    /// 승격이 깨졌을 때 앞의 모습으로 돌린다. 데이터를 잃는 되돌리기는 기계가 정하지 않는다.
    fn back_out(
        &self,
        inner: &mut Inner,
        prior: &Prior<'_>,
        point: Option<&RestorePoint>,
        kind: Migrations,
        failure: Failure,
    ) -> Failure {
        let Some(production) = &prior.record.production else {
            // 첫 승격이었다. 돌아갈 운영이 없으니 세우던 것을 걷는다
            let _ = inner.admin.destroy(prior.names);
            return failure;
        };
        match after_promotion(false, kind) {
            Aftermath::Keep => failure,
            Aftermath::RollBackCode => match self.relaunch(inner, prior, production) {
                Ok(()) => failure,
                Err(blocked) => blocked,
            },
            Aftermath::AskHuman => {
                // 마이그레이션이 돈 직후이고 아직 아무도 쓰지 않았다. 되돌릴 지점으로 돌려도 잃는 데이터가 없다
                let manifest = prior
                    .record
                    .releases
                    .get(&production.release)
                    .and_then(|release| Commit::parse(&release.commit))
                    .and_then(|commit| self.assembled(prior.instance, &commit).ok())
                    .map(|assembled| assembled.manifest);
                if let (Some(point), Some(manifest)) = (point, manifest)
                    && inner.admin.restore(prior.names, &manifest, point).is_ok()
                {
                    return match self.relaunch(inner, prior, production) {
                        Ok(()) => failure,
                        Err(blocked) => blocked,
                    };
                }
                Failure::Conflict(
                    "새 release 가 서지 못했고 운영 DB 를 앞의 모습으로 돌리지도 못했습니다. 운영이 내려가 있습니다. 사람이 확인해야 합니다".to_owned(),
                )
            }
        }
    }

    /// 앞의 release 의 서버를 다시 띄운다. 승격과 같은 판정을 지나서, 그 release 가 쓰는 비밀의 운영 값이 빠졌으면
    /// 값 없이 띄우지 않고 까닭을 돌려준다.
    fn relaunch(
        &self,
        inner: &mut Inner,
        prior: &Prior<'_>,
        production: &ProductionRecord,
    ) -> Result<(), Failure> {
        let previous = prior
            .record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .and_then(|commit| self.assembled(prior.instance, &commit).ok());
        let Some(assembled) = previous else {
            return Ok(());
        };
        let missing = self.missing_secrets(
            &prior.record.organization,
            prior.instance,
            &assembled.manifest,
        );
        if !missing.is_empty() {
            let names: Vec<String> = missing
                .iter()
                .map(|name| format!("`{}`", name.as_str()))
                .collect();
            return Err(Failure::Conflict(format!(
                "새 release 가 서지 못했고, 앞의 release 가 쓰는 비밀 {} 의 운영 값이 없어 앞의 release 로 되돌리지도 못했습니다. 운영이 내려가 있습니다. 사람이 입력 카드에서 운영의 값을 넣은 뒤 다시 올려 주세요",
                names.join(", ")
            )));
        }
        let Ok(folder) = self.build(prior.instance, &assembled) else {
            return Ok(());
        };
        // 앞의 선언의 역할을 다시 세우고(새 release 가 걷었을 수 있다) 권한을 앞의 권한 표로 되돌린다.
        // 새 release 의 권한이나 역할이 남아 있으면 안 된다
        let _ = inner.admin.provision(prior.names, &assembled.manifest);
        let _ = inner
            .admin
            .grant(prior.names, &assembled.manifest, &assembled.access);
        let _ = inner.admin.retire(prior.names, &assembled.manifest);
        let identity_key = token::unhex(&production.identity_key).unwrap_or_default();
        let stand = Stand {
            names: prior.names,
            generated: &production.generated,
            identity_key: &identity_key,
            stage: Stage::Production,
            organization: &prior.record.organization,
            app: &prior.record.app,
            port: production.port,
        };
        if let Ok(launched) = self.launch(
            prior.instance,
            &assembled,
            &folder,
            &stand,
            Mode::Awake,
            None,
        ) {
            inner.live.insert(
                (prior.instance.as_str().to_owned(), Stage::Production),
                Live {
                    release: production.release.clone(),
                    origin: launched.origin,
                    names: prior.names.clone(),
                    manifest: assembled.manifest.clone(),
                    seed_users: Vec::new(),
                    services: launched.services,
                    router: launched.handle,
                    building: false,
                    _router: launched.router,
                },
            );
        }
        Ok(())
    }

    /// 사람의 승인을 기다리는 승격 요청. 없으면 `None` 이다. 권한의 변화는 읽는 때의 운영과 견준다.
    pub fn promotion_request(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<Option<PendingPromotion>> {
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::PromotionRequest)?;
        let mut inner = self.lock();
        let Some(release) = record.promotion_requested.clone() else {
            return Ok(None);
        };
        let commit = record
            .releases
            .get(&release)
            .and_then(|known| Commit::parse(&known.commit))
            .ok_or_else(|| internal("요청된 release 의 commit 을 읽지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
        let all: Vec<&str> = assembled
            .migrations
            .iter()
            .map(|script| script.name.as_str())
            .collect();
        let migrations = match &record.production {
            None => all.iter().map(|name| (*name).to_owned()).collect(),
            Some(_) => inner
                .admin
                .pending(&Names::new(instance.clone()), &all)
                .map_err(internal)?,
        };
        let received = self.production_external(instance, &record)?;
        let rollout = self.governing(instance, &commit)?;
        Ok(Some(PendingPromotion {
            rollout,
            release,
            commit: commit.to_string(),
            changes: self.change_sentences(instance, &record, &assembled)?,
            migrations,
            new_secrets: newly_received(&received, &assembled.manifest.get().secrets.external)
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
        }))
    }

    /// 운영에 올라 있는 것의 주소. 팩토리의 서버가 본다.
    pub fn production(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<Option<PromotionReport>> {
        let record = self.owned(organization, instance)?;
        let schedules = self.records.schedules(instance.as_str())?;
        let now = (self.clock)();
        // 이 기계에 놓인 것은 떠 있는 것을 답한다
        if record.machine == self.machine() {
            return Ok(self
                .lock()
                .live
                .get(&(instance.as_str().to_owned(), Stage::Production))
                .map(|live| PromotionReport {
                    release: live.release.clone(),
                    services: Self::report(&live.services),
                    migrations: Vec::new(),
                    schedules: Self::schedule_report(&live.manifest, &schedules, now),
                }));
        }
        // 다른 기계에 놓인 것은 기록의 운영(주소와 선언)으로 답한다
        let Some(production) = record.production else {
            return Ok(None);
        };
        let (Some(origin), Some(manifest)) = (
            production.origin,
            production
                .manifest
                .and_then(|manifest| manifest.check().ok()),
        ) else {
            return Ok(None);
        };
        let services = manifest
            .get()
            .services
            .iter()
            .map(|service| ServiceReport {
                name: service.name.to_string(),
                kind: service.kind,
                url: Some(format!("{origin}{}", service.path.trim_end_matches('/'))),
            })
            .collect();
        Ok(Some(PromotionReport {
            release: production.release,
            services,
            migrations: Vec::new(),
            schedules: Self::schedule_report(&manifest, &schedules, now),
        }))
    }

    fn schedule_report(
        manifest: &ValidManifest,
        records: &BTreeMap<String, ScheduleRecord>,
        now: u64,
    ) -> Vec<ScheduleReport> {
        manifest
            .get()
            .schedules
            .iter()
            .map(|schedule| {
                let record = records.get(&schedule.key());
                ScheduleReport {
                    service: schedule.service.to_string(),
                    path: schedule.path.clone(),
                    cron: schedule.cron.clone(),
                    role: schedule.role.as_ref().map(ToString::to_string),
                    next_at: record.map(|record| record.next_at).or_else(|| {
                        Cron::parse(&schedule.cron)
                            .ok()
                            .and_then(|cron| cron.next_after(now))
                    }),
                    last_run: record.and_then(|record| record.last_run.clone()),
                }
            })
            .collect()
    }

    /// 운영의 사용자 저장소(인증 역할로 붙은 연결). 운영이 서 있고 `[auth]` 를 선언했을 때만 있다.
    pub fn production_auth(&self, organization: &str, instance: &InstanceId) -> Outcome<AuthStore> {
        let manifest = self.production_manifest(organization, instance)?;
        if manifest.get().auth.is_none() {
            return Err(Failure::Problems(vec![
                "이 앱은 로그인을 레이어에 맡기지 않아 사용자가 없습니다. `orbital.toml` 에 `[auth]` 를 적어 주세요".to_owned(),
            ]));
        }
        AuthStore::connect(&self.pg_url, &Names::new(instance.clone()), &manifest).map_err(internal)
    }

    /// 운영의 선언. 이 기계에 떠 있으면 그것을, 아니면 기록의 것을 쓴다. 인스턴스의 DB 에만 닿는 일(사용자 · 초대)이 어느 기계에서나 되게 한다.
    fn production_manifest(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<ValidManifest> {
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::Users)?;
        let none = || {
            Failure::Conflict(
                "운영에 오른 것이 없습니다. 운영에 먼저 올린 뒤에 사용자를 초대해 주세요"
                    .to_owned(),
            )
        };
        if record.machine == self.machine() {
            return self
                .lock()
                .live
                .get(&(instance.as_str().to_owned(), Stage::Production))
                .map(|live| live.manifest.clone())
                .ok_or_else(none);
        }
        record
            .production
            .and_then(|production| production.manifest)
            .and_then(|manifest| manifest.check().ok())
            .ok_or_else(none)
    }

    /// 운영에 사용자를 초대한다. 팩토리의 서버(service key)만 부른다. 선언에 없는 업무 역할이면 고칠 것으로 돌려준다.
    pub fn invite(
        &self,
        organization: &str,
        instance: &InstanceId,
        email: &str,
        roles: &[String],
    ) -> Outcome<()> {
        let mut store = self.production_auth(organization, instance)?;
        let roles = role_names(roles)?;
        store.invite(email, &roles, now()).map_err(auth_failure)
    }

    /// MCP 의 클라이언트를 미리 등록한다(팩토리의 service key 만). redirect 는 `https` 이거나 `localhost` 여야 한다.
    pub fn register_oauth_client(
        &self,
        organization: &str,
        instance: &InstanceId,
        name: &str,
        redirect_uris: &[String],
    ) -> Outcome<String> {
        let mut store = self.production_auth(organization, instance)?;
        let declared =
            orbital_core::oauth::mcp(&self.production_manifest(organization, instance)?).is_some();
        if !declared {
            return Err(Failure::Problems(vec![
                "이 앱은 MCP 의 인가를 선언하지 않았습니다. `orbital.toml` 에 `[auth.mcp]` 를 적어 주세요".to_owned(),
            ]));
        }
        if redirect_uris.is_empty() {
            return Err(Failure::Problems(vec![
                "redirect_uris 를 하나 이상 적어 주세요".to_owned(),
            ]));
        }
        let problems: Vec<String> = redirect_uris
            .iter()
            .filter(|uri| registrable_redirect(uri).is_err())
            .map(|uri| format!("redirect `{uri}` 는 https 이거나 localhost 의 http 여야 하고 조각을 쓸 수 없습니다. 주소를 고쳐 주세요"))
            .collect();
        if !problems.is_empty() {
            return Err(Failure::Problems(problems));
        }
        if name.trim().is_empty() {
            return Err(Failure::Problems(vec![
                "클라이언트의 이름(name)을 적어 주세요".to_owned(),
            ]));
        }
        store
            .register_client("registered", name, redirect_uris, None, now())
            .map_err(auth_failure)
    }

    /// 운영의 사용자 목록. 막힌 사용자도 함께 돌려준다. 토큰이나 세션은 싣지 않는다.
    pub fn users(&self, organization: &str, instance: &InstanceId) -> Outcome<Vec<UserReport>> {
        let mut store = self.production_auth(organization, instance)?;
        Ok(store
            .users()
            .map_err(auth_failure)?
            .into_iter()
            .map(|user| UserReport {
                id: user.id,
                email: user.email,
                name: user.name,
                roles: user.roles,
                disabled: user.disabled,
                last_signed_in_at: user.last_signed_in_at,
            })
            .collect())
    }

    /// 운영의 사용자 한 사람의 업무 역할을 통째로 바꾼다. 다음 요청부터 신원에 실린다.
    pub fn set_roles(
        &self,
        organization: &str,
        instance: &InstanceId,
        user: &str,
        roles: &[String],
    ) -> Outcome<()> {
        let mut store = self.production_auth(organization, instance)?;
        let roles = role_names(roles)?;
        store.set_roles(user, &roles).map_err(auth_failure)
    }

    /// 운영의 사용자를 뺀다. 막고 그 사용자의 세션을 모두 거둔다.
    pub fn remove_user(
        &self,
        organization: &str,
        instance: &InstanceId,
        user: &str,
    ) -> Outcome<()> {
        let mut store = self.production_auth(organization, instance)?;
        store.remove(user, now()).map_err(auth_failure)
    }

    /// 인스턴스를 걷는다. 떠 있는 것을 내리고 DB 와 코드 저장소를 지운다. 되돌릴 수 없다.
    pub fn destroy_instance(&self, organization: &str, instance: &InstanceId) -> Outcome<()> {
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::Destroy)?;
        let mut inner = self.lock();
        for stage in [Stage::Preview, Stage::Production] {
            if let Some(live) = inner.live.remove(&(instance.as_str().to_owned(), stage)) {
                let names = live.names.clone();
                drop(live);
                inner.admin.destroy(&names).map_err(internal)?;
            }
        }
        // 떠 있지 않은 프리뷰의 database 도 걷는다. 다시 뜬 뒤 아직 걷지 못한 앞의 프리뷰가 기록에 이름으로 남아 있다
        self.drop_recorded_preview(&mut inner, instance)?;
        inner
            .admin
            .destroy(&Names::new(instance.clone()))
            .map_err(internal)?;
        self.sources.destroy(instance).map_err(internal)?;
        // 빌드 폴더(node_modules 가 든다) · 빌드의 캐시 · 기록도 걷는다. 남겨 두면 지운 인스턴스의 것이 디스크에 쌓인다
        for folder in [
            self.builds_folder(instance),
            self.cache_folder(instance),
            self.home.join("logs").join(instance.as_str()),
            self.home.join("conformance").join(instance.as_str()),
        ] {
            if folder.exists() {
                fs::remove_dir_all(&folder)
                    .map_err(|_| internal("인스턴스의 빌드 폴더를 걷지 못했습니다"))?;
            }
        }
        // 기록의 줄을 지운다. 그 인스턴스의 일정 · 금고의 값 · 요청 · 입력 표 · 닫은 작업도 함께 지워진다
        drop(inner);
        self.records
            .remove_instance(instance.as_str())
            .map_err(Failure::from)
    }
}

// ---- 팩토리의 설정과 Google 의 콜백 ----

impl Layer {
    /// 선언의 로그인 방법이 쓰는데 그 팩토리가 넣지 않은 키. 판정은 core 가 한다.
    fn missing_keys(&self, organization: &str, manifest: &ValidManifest) -> Vec<FactoryKey> {
        missing_keys(
            manifest,
            &self.settings.keys(organization, self.outbox.is_some()),
        )
    }

    /// 팩토리의 로그인 설정. 비밀은 싣지 않는다.
    pub fn auth_settings(&self, organization: &str) -> serde_json::Value {
        self.settings
            .view(organization, &callback_url(&self.public_url))
    }

    /// 팩토리의 로그인 설정을 바꾼다. 봉인의 열쇠가 없는 레이어에서는 409 로 까닭을 알린다.
    pub fn put_auth_settings(&self, organization: &str, body: &[u8]) -> Outcome<()> {
        self.settings
            .update(organization, body)
            .map_err(|error| match error {
                SettingsError::Problems(problems) => Failure::Problems(problems),
                SettingsError::NoSealKey => Failure::Conflict(
                    "레이어에 봉인의 열쇠가 없어 키를 넣지 못합니다. 레이어의 운영자가 `ORBITAL_SEAL_KEY` 를 넣고 다시 띄워야 합니다".to_owned(),
                ),
                SettingsError::Internal(message) => Failure::Internal(message),
            })
    }

    /// Google 이 돌려보낸 콜백. `state` 를 확인하고, 그 인스턴스의 팩토리 키로 `code` 를 바꾸고, `id_token` 을 확인한 뒤
    /// 그 인스턴스에 한 번 쓰는 표를 적고, 인스턴스의 router 로 보낼 주소를 돌려준다.
    ///
    /// 위조했거나 만료된 `state` 는 아무것도 하지 않고 거절한다(Google 을 부르지도, 표를 적지도 않는다).
    /// `state` 가 맞으면 그 뒤의 실패는 앱의 로그인 화면(`login_path?error=<코드>`)으로 보낸다.
    pub fn google_callback(&self, query: &str) -> Outcome<String> {
        let bad_state = || {
            Failure::Invalid(
                "state 가 틀렸거나 만료되었습니다. 앱의 로그인 화면에서 Google 로 다시 들어와 주세요"
                    .to_owned(),
            )
        };
        let state = query_value(query, "state")
            .and_then(|text| token::verify_state(&self.token_key, &text))
            .ok_or_else(bad_state)?;
        judge_state(&state, now()).map_err(|_| bad_state())?;
        let browser_hash = token::unhex(&state.browser_hash)
            .filter(|hash| hash.len() == 32)
            .ok_or_else(bad_state)?;
        let instance = InstanceId::parse(&state.instance).map_err(|_| bad_state())?;
        // 어느 관리 서버가 콜백을 받아도 된다. 운영의 주소와 선언은 이 기계에 떠 있으면 그것을, 아니면 기록의 것을 쓴다
        let record = self.record_of(&instance)?;
        let (origin, manifest) = if record.machine == self.machine() {
            let inner = self.lock();
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Production))
                .ok_or(Failure::NotFound)?;
            (live.origin.clone(), live.manifest.clone())
        } else {
            let production = record.production.clone().ok_or(Failure::NotFound)?;
            (
                production.origin.ok_or(Failure::NotFound)?,
                production
                    .manifest
                    .and_then(|manifest| manifest.check().ok())
                    .ok_or(Failure::NotFound)?,
            )
        };
        let organization = record.organization.clone();
        let names = Names::new(instance.clone());
        let Some(auth) = manifest
            .get()
            .auth
            .as_ref()
            .filter(|auth| auth.uses(orbital_core::manifest::Auth::GOOGLE))
        else {
            return Err(Failure::NotFound);
        };
        let to_login = |code: &str| format!("{origin}{}?error={code}", auth.login_path);
        if query_value(query, "error").is_some() {
            return Ok(to_login("denied"));
        }
        let Some(code) = query_value(query, "code") else {
            return Ok(to_login("invalid"));
        };
        let Some(client) = self.settings.google(&organization) else {
            return Ok(to_login("unavailable"));
        };
        let Ok(token) = exchange(
            &self.endpoints.google_token,
            &client,
            &code,
            &callback_url(&self.public_url),
        ) else {
            return Ok(to_login("unavailable"));
        };
        let computed = token.nonce.as_deref().map(sha256_hex);
        let account = match judge_id_token(
            &token,
            &client.client_id,
            &state.nonce_hash,
            computed.as_deref(),
            now(),
        ) {
            Ok(account) => account,
            Err(IdTokenRefusal::EmailNotVerified) => return Ok(to_login("unverified")),
            Err(_) => return Ok(to_login("invalid")),
        };
        let mut store = AuthStore::connect(&self.pg_url, &names, &manifest).map_err(internal)?;
        let ticket = store
            .issue_google_ticket(
                &account.email,
                &account.subject,
                &state.next,
                &browser_hash,
                now(),
            )
            .map_err(internal)?;
        Ok(format!(
            "{origin}/_orbital/auth/google/finish?ticket={}",
            ticket.to_text()
        ))
    }
}

// ---- 밖에서 넣는 비밀 ----

/// 봉인의 열쇠가 없는 레이어에서 값을 넣으려 했을 때의 까닭.
const NO_SEAL_KEY: &str = "레이어에 봉인의 열쇠가 없어 비밀의 값을 넣지 못합니다. 레이어의 운영자가 `ORBITAL_SEAL_KEY` 를 넣고 다시 띄워야 합니다";

/// 금고의 거절을 HTTP 의 답으로 옮긴다.
fn vault_failure(error: VaultError) -> Failure {
    match error {
        VaultError::NoSealKey => Failure::Conflict(NO_SEAL_KEY.to_owned()),
        VaultError::Internal(message) => Failure::Internal(message),
    }
}

/// 비밀의 이름을 읽는다. 틀린 이름은 되풀이하지 않는다. 이름 자리에 값을 잘못 넣었을 수 있다.
fn secret_name(name: &str) -> Outcome<SecretName> {
    SecretName::parse(name).map_err(|error| {
        Failure::Problems(vec![format!(
            "비밀의 이름이 틀렸습니다({error}). `orbital.toml` 의 `[secrets] external` 에 적은 이름(대문자 · 숫자 · 밑줄)을 써 주세요"
        )])
    })
}

fn undeclared(name: &SecretName) -> String {
    format!(
        "비밀 `{}` 은 이 인스턴스의 어느 release 도 밖에서 넣는다고 선언하지 않았습니다. `orbital.toml` 의 `[secrets] external` 에 적고 프리뷰를 세운 뒤 요청해 주세요",
        name.as_str()
    )
}

/// 값을 받지 않는 까닭. 값은 되풀이하지 않는다.
fn value_failure(problems: &[ValueProblem]) -> Failure {
    Failure::Problems(
        problems
            .iter()
            .map(|problem| match problem {
                ValueProblem::Empty => "값이 비었습니다. 값을 붙여 넣어 주세요".to_owned(),
                ValueProblem::TooLarge { max } => {
                    format!("값이 {max}바이트보다 큽니다. 비밀의 값만 넣어 주세요")
                }
                ValueProblem::Nul => {
                    "값에 NUL 글자가 들었습니다. 환경 변수에 실을 수 없으니 값을 다시 복사해 넣어 주세요"
                        .to_owned()
                }
            })
            .collect(),
    )
}

impl Layer {
    /// 선언이 밖에서 넣는다고 적었는데 운영의 칸에 풀리는 값이 없는 비밀. 판정은 core 가 한다.
    fn missing_secrets(
        &self,
        organization: &str,
        instance: &InstanceId,
        manifest: &ValidManifest,
    ) -> Vec<SecretName> {
        missing_secrets(
            manifest,
            &self
                .vault
                .filled(organization, instance, SecretStage::Production),
        )
    }

    /// 인스턴스가 속한 팩토리. 토큰의 길이 범위를 판정받은 뒤에 쓴다.
    pub fn instance_organization(&self, instance: &InstanceId) -> Outcome<String> {
        Ok(self.record_of(instance)?.organization)
    }

    /// 그 인스턴스의 release(프리뷰로 세운 것과 운영의 것)가 밖에서 넣는다고 선언한 이름. 다른 팩토리의 것은 없는 것으로 답한다.
    fn declared_secrets(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<BTreeSet<SecretName>> {
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::Secrets)?;
        Ok(record
            .releases
            .values()
            .flat_map(|release| release.external.iter())
            .filter_map(|name| SecretName::parse(name).ok())
            .collect())
    }

    /// 이름마다 선언됐는지 · 요청됐는지 · 단계마다 채워졌는지. 값은 어떤 열쇠로도 돌려주지 않는다.
    pub fn list_secrets(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<Vec<SecretReport>> {
        let declared = self.declared_secrets(organization, instance)?;
        let status = self.vault.status(organization, instance);
        let requests = self.vault.requests(instance);
        let mut names: BTreeSet<String> = declared
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        names.extend(status.keys().map(|name| name.as_str().to_owned()));
        names.extend(requests.keys().cloned());
        let slot = |at: Option<u64>| SlotReport {
            set: at.is_some(),
            set_at: at,
        };
        Ok(names
            .into_iter()
            .map(|name| {
                let parsed = SecretName::parse(&name).ok();
                let filled = parsed
                    .as_ref()
                    .and_then(|parsed| status.get(parsed).cloned())
                    .unwrap_or_default();
                SecretReport {
                    declared: parsed.is_some_and(|parsed| declared.contains(&parsed)),
                    requested: requests.get(&name).map(|requested| RequestedReport {
                        reason: requested.reason.clone(),
                        at: requested.at,
                    }),
                    preview: slot(filled.preview),
                    production: slot(filled.production),
                    name,
                }
            })
            .collect())
    }

    /// 사람에게 비밀의 입력을 요청한다. 에이전트의 토큰(`secrets:request`)이나 service key 로 부른다.
    pub fn request_secret(
        &self,
        organization: &str,
        instance: &InstanceId,
        name: &str,
        reason: &str,
    ) -> Outcome<()> {
        let name = secret_name(name)?;
        let declared = self.declared_secrets(organization, instance)?;
        let problems = judge_request(&declared, &name, reason);
        if !problems.is_empty() {
            return Err(Failure::Problems(
                problems
                    .iter()
                    .map(|problem| match problem {
                        RequestProblem::Undeclared => undeclared(&name),
                        RequestProblem::ReasonEmpty => {
                            "까닭(reason)을 적어 주세요. 사람이 카드에서 무엇에 쓰는 값인지 읽습니다"
                                .to_owned()
                        }
                        RequestProblem::ReasonTooLong { max } => {
                            format!("까닭(reason)은 {max}자 안으로 줄여 주세요")
                        }
                    })
                    .collect(),
            ));
        }
        self.vault
            .request(instance, &name, reason.trim(), (self.clock)())
            .map_err(vault_failure)
    }

    /// 값을 넣는다(service key 만). 그 단계에 떠 있는 서비스는 재워, 다음 요청이 새 값으로 깨게 한다.
    pub fn put_secret(
        &self,
        organization: &str,
        instance: &InstanceId,
        name: &str,
        stage: SecretStage,
        value: &SecretValue,
    ) -> Outcome<()> {
        let name = secret_name(name)?;
        if !self
            .declared_secrets(organization, instance)?
            .contains(&name)
        {
            return Err(Failure::Problems(vec![undeclared(&name)]));
        }
        let problems = judge_value(value.expose());
        if !problems.is_empty() {
            return Err(value_failure(&problems));
        }
        let place = Place {
            instance: instance.clone(),
            name,
            stage,
        };
        self.vault
            .put(organization, &place, value, (self.clock)())
            .map_err(vault_failure)?;
        self.refresh(&place);
        Ok(())
    }

    /// 값을 지운다(service key 만). 지금 운영의 release 가 쓰는 비밀의 운영 값은 지우지 못한다.
    pub fn remove_secret(
        &self,
        organization: &str,
        instance: &InstanceId,
        name: &str,
        stage: SecretStage,
    ) -> Outcome<bool> {
        let name = secret_name(name)?;
        let record = self.owned(organization, instance)?;
        // 지금 운영의 선언은 기록에 있다. 다른 기계에 놓인 인스턴스여도 코드 저장소 없이 판정한다
        let in_use = match record
            .production
            .as_ref()
            .and_then(|production| production.manifest.as_ref())
        {
            Some(manifest) => manifest.secrets.external.contains(&name),
            None => self.production_external(instance, &record)?.contains(&name),
        };
        if stage == SecretStage::Production && in_use {
            return Err(Failure::Conflict(format!(
                "지금 운영의 release 가 쓰는 비밀 `{}` 의 운영 값은 지우지 못합니다. 값을 바꾸려면 새 값을 넣어 주세요. 지우려면 먼저 `[secrets] external` 에서 뺀 release 를 운영에 올려 주세요",
                name.as_str()
            )));
        }
        let place = Place {
            instance: instance.clone(),
            name,
            stage,
        };
        let removed = self.vault.remove(&place).map_err(vault_failure)?;
        if removed {
            self.refresh(&place);
        }
        Ok(removed)
    }

    /// 사람이 값을 넣을 입력 표를 낸다(service key 만). 표는 인스턴스 · 이름 · 단계 하나에 묶이고 10분 안에 한 번 쓴다.
    /// 레이어는 표의 sha256 만 적는다. 사람의 브라우저가 돌려받은 주소로 레이어에 바로 값을 보낸다.
    pub fn open_entry(
        &self,
        organization: &str,
        instance: &InstanceId,
        name: &str,
        stage: SecretStage,
    ) -> Outcome<EntryTicket> {
        let name = secret_name(name)?;
        if !self
            .declared_secrets(organization, instance)?
            .contains(&name)
        {
            return Err(Failure::Problems(vec![undeclared(&name)]));
        }
        // 넣지 못할 값을 받을 표는 내지 않는다
        if !self.vault.can_seal() {
            return Err(Failure::Conflict(NO_SEAL_KEY.to_owned()));
        }
        let ticket = token::hex(&random(32)?);
        let now = (self.clock)();
        let expires_at = entry_expires_at(now);
        self.vault
            .issue(
                organization,
                &sha256_hex(&ticket),
                Entry {
                    place: Place {
                        instance: instance.clone(),
                        name,
                        stage,
                    },
                    expires_at,
                    used: false,
                },
                now,
            )
            .map_err(vault_failure)?;
        Ok(EntryTicket {
            url: format!("{}/v1/secret-entries", self.public_url),
            ticket,
            expires_at,
        })
    }

    /// 입력 표로 값을 넣는다. 쿠키도 키도 보지 않고 표만 본다. 본문이 적은 이름과 단계는 표의 것과 같아야 한다.
    pub fn redeem_entry(
        &self,
        ticket: &str,
        name: Option<&str>,
        stage: Option<SecretStage>,
        value: &SecretValue,
    ) -> Outcome<Place> {
        if ticket.len() != 64 || !ticket.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Failure::NotFound);
        }
        let name = name.map(secret_name).transpose()?;
        let place = self
            .vault
            .redeem(&sha256_hex(ticket), (name, stage), value, (self.clock)())
            .map_err(|error| match error {
                RedeemError::Unknown => Failure::NotFound,
                RedeemError::Refused(EntryRefusal::Used) => Failure::Gone(
                    "이미 쓴 입력 표입니다. 카드에서 표를 새로 받아 주세요".to_owned(),
                ),
                RedeemError::Refused(EntryRefusal::Expired) => Failure::Gone(
                    "입력 표가 만료되었습니다(10분). 카드에서 표를 새로 받아 주세요".to_owned(),
                ),
                RedeemError::Refused(EntryRefusal::OtherPlace) => Failure::Invalid(
                    "입력 표는 묶인 이름과 단계에만 값을 넣습니다. 본문에는 `value` 만 적어 주세요"
                        .to_owned(),
                ),
                RedeemError::Value(problems) => value_failure(&problems),
                RedeemError::Vault(error) => vault_failure(error),
            })?;
        self.refresh(&place);
        Ok(place)
    }

    /// 그 단계에 떠 있는 앱이 이 비밀을 선언했으면 서버 서비스를 재운다. 다음 요청이 새 값으로 깬다.
    /// 인스턴스가 다른 기계에 놓여 있으면 그 기계에 control database 로 알린다(`NOTIFY`). 그 기계가 받아 재운다.
    fn refresh(&self, place: &Place) {
        let machine = self
            .records
            .instance(place.instance.as_str())
            .ok()
            .flatten()
            .map(|record| record.machine);
        match machine {
            Some(machine) if machine != self.machine() => {
                if self
                    .records
                    .notify_refresh(&machine, place.instance.as_str(), place.stage.as_str())
                    .is_err()
                {
                    eprintln!(
                        "orbitald: 다른 기계에 놓인 {} 에 비밀이 바뀐 것을 알리지 못했습니다",
                        place.instance.as_str()
                    );
                }
            }
            _ => self.sleep_secret(place),
        }
    }

    fn sleep_secret(&self, place: &Place) {
        let declared = self
            .lock()
            .live
            .get(&(place.instance.as_str().to_owned(), Stage::of(place.stage)))
            .is_some_and(|live| live.manifest.get().secrets.external.contains(&place.name));
        if declared {
            self.sleep_services(&place.instance, Stage::of(place.stage));
        }
    }

    /// 이 기계에 떠 있는 서버 서비스를 모두 재운다. 알림을 놓쳤을 수 있을 때 쓴다.
    fn sleep_all(&self) {
        let inner = self.lock();
        for live in inner.live.values() {
            for service in &live.services {
                if let Some(server) = &service.server {
                    server.refresh();
                }
            }
        }
    }

    /// 그 단계에 떠 있는 서버 서비스를 재운다. 다음 요청이 새 환경으로 깬다.
    fn sleep_services(&self, instance: &InstanceId, stage: Stage) {
        let inner = self.lock();
        let Some(live) = inner.live.get(&(instance.as_str().to_owned(), stage)) else {
            return;
        };
        for service in &live.services {
            if let Some(server) = &service.server {
                server.refresh();
            }
        }
    }
}

// ---- 백업과 복구 훈련 ----

/// 인스턴스 하나를 되살린 결과. 이름과 숫자만 싣는다.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub instance: String,
    /// 되살린 시점(유닉스 초).
    pub at: u64,
    /// 되살리는 데 걸린 시간.
    pub millis: u64,
    /// 되살린 database 의 표의 수.
    pub tables: usize,
    /// 되살리기 직전의 운영 DB 를 떠 둔 되돌릴 지점(database 의 이름).
    pub restore_point: String,
}

/// 되살리기를 무른 결과. 이름과 숫자만 싣는다.
#[derive(Debug, Clone, Serialize)]
pub struct UndoReport {
    pub instance: String,
    /// 무르는 데 걸린 시간.
    pub millis: u64,
    /// 돌아간 database 의 표의 수.
    pub tables: usize,
}

/// 인스턴스 하나를 되살리는 일이 쥔 자리. 떨어지면 돌려준다.
struct Restoring<'a> {
    layer: &'a LayerCore,
    instance: String,
}

impl Drop for Restoring<'_> {
    fn drop(&mut self) {
        self.layer
            .restoring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.instance);
    }
}

/// 팩토리가 보는 훈련의 모습. 통과했는지와 숫자만.
#[derive(Debug, Clone, Serialize)]
pub struct BackupStatus {
    /// 마지막으로 통과한 훈련이 여드레 안인가. 아니면 새 고객의 데이터를 받지 않는 것이 규칙이다.
    pub fresh: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_passed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_drill: Option<DrillSummary>,
}

/// 마지막 훈련의 숫자.
#[derive(Debug, Clone, Serialize)]
pub struct DrillSummary {
    pub passed: bool,
    pub at: u64,
    pub recovery_millis: u64,
    pub drill_millis: u64,
    pub exposure_seconds: Option<u64>,
    pub instances: usize,
    pub checks: usize,
    pub failed_checks: usize,
}

fn backup_off() -> Failure {
    Failure::Conflict(
        "이 레이어는 백업을 켜지 않았습니다. 레이어의 운영자가 관리 서버에 `ORBITAL_BACKUP_DIR` 을 적어야 합니다".to_owned(),
    )
}

/// 그 시점으로 되살리지 못하는 까닭. 무엇을 고치면 되는지를 함께 적는다.
pub fn restore_refusal_text(refusal: &orbital_core::backup::RestoreRefusal) -> String {
    use orbital_core::backup::RestoreRefusal;
    match refusal {
        RestoreRefusal::NoBackup => "기반 백업이 아직 없습니다. 레이어가 첫 기반 백업을 뜬 뒤의 시점으로만 되살릴 수 있습니다".to_owned(),
        RestoreRefusal::BeforeOldestBackup { oldest } => format!(
            "가장 오랜 기반 백업(유닉스 초 {})보다 앞선 시점으로는 되살리지 못합니다. 그 뒤의 시점을 적어 주세요",
            oldest.div_ceil(1000)
        ),
        RestoreRefusal::BeyondArchive { .. } => {
            "보관한 WAL 이 그 시점에 닿지 않습니다. 지금보다 앞선 시점을 적어 주세요".to_owned()
        }
        RestoreRefusal::MissingWal { segment } => format!(
            "기반 백업에서 그 시점까지 이어지는 WAL 조각 `{segment}` 이 보관 폴더에 없어 되살리지 못합니다. 레이어의 운영자가 백업을 확인해야 합니다"
        ),
    }
}

/// 훈련이 낡아 새 인스턴스를 받지 않는 까닭. 에이전트가 고칠 수 없는 일임을 밝힌다.
fn stale_text(freshness: orbital_core::backup::Freshness) -> String {
    use orbital_core::backup::Freshness;
    let why = match freshness {
        Freshness::Overdue { .. } => "마지막으로 통과한 복구 훈련이 여드레를 넘겼습니다",
        Freshness::NeverPassed | Freshness::Fresh => "복구 훈련이 한 번도 통과하지 않았습니다",
    };
    format!(
        "{why}. 훈련이 통과한 뒤에만 새 고객의 데이터를 받으므로 새 인스턴스를 세우지 않습니다. 에이전트가 고칠 수 없는 일입니다. 레이어의 운영자가 `orbitald drill` 로 훈련을 통과시켜야 합니다. 이미 선 인스턴스의 프리뷰와 승격은 그대로 됩니다"
    )
}

impl Layer {
    fn backup_on(&self) -> Outcome<&Backup> {
        self.backup.as_ref().ok_or_else(backup_off)
    }

    /// 마지막으로 통과한 훈련으로 본 지금의 모습.
    fn freshness(&self) -> orbital_core::backup::Freshness {
        let history = crate::backup::history(&self.records);
        orbital_core::backup::freshness(orbital_core::backup::last_passed(&history), (self.clock)())
    }

    /// 훈련을 켠 레이어에서 훈련이 낡았으면 새 인스턴스를 받지 않는다.
    fn require_fresh_drill(&self) -> Outcome<()> {
        if self
            .backup
            .as_ref()
            .is_some_and(|backup| backup.require_drill)
        {
            let freshness = self.freshness();
            if !freshness.is_fresh() {
                return Err(Failure::Conflict(stale_text(freshness)));
            }
        }
        Ok(())
    }

    /// 기반 백업과 훈련의 차례를 잡는다. 여러 관리 서버 가운데 하나만 돌린다. 다른 관리 서버가 돌리는 중이면 409 다.
    fn backup_turn(&self) -> Outcome<crate::records::Exclusive> {
        self.records.take_backup_turn()?.ok_or_else(|| {
            Failure::Conflict(
                "다른 관리 서버가 기반 백업이나 복구 훈련을 돌리는 중입니다. 끝난 뒤에 다시 불러 주세요"
                    .to_owned(),
            )
        })
    }

    /// 기반 백업을 하나 뜨고 보관 기간이 지난 것을 지운다. 백업을 켜지 않은 레이어에서는 409 다.
    /// 기록은 클러스터 안(control database)에 있어 기반 백업에 함께 든다. 코드 저장소의 묶음이 같은 때의 것이 되게 이 기계의 일은 멈춘다.
    pub fn base_backup(&self) -> Outcome<orbital_core::backup::BaseBackup> {
        let backup = self.backup_on()?;
        let _turn = self.backup_turn()?;
        self.base_backup_now(backup)
    }

    fn base_backup_now(&self, backup: &Backup) -> Outcome<orbital_core::backup::BaseBackup> {
        let _guard = self.lock();
        crate::backup::take_base_backup(
            backup.store.as_ref(),
            &self.home,
            &self.pg_url,
            backup.keep_for,
        )
        .map_err(internal)
    }

    /// 복구 훈련을 한 번 돌리고 기록에 쌓는다. 훈련은 운영 클러스터를 덮어쓰지 않고, 도는 동안 다른 일을 막지 않는다.
    /// 여러 관리 서버 가운데 하나만 돌린다. 다른 관리 서버가 돌리는 중이면 409 다.
    pub fn drill(&self) -> Outcome<orbital_core::backup::DrillRecord> {
        let backup = self.backup_on()?;
        let _turn = self.backup_turn()?;
        self.drill_now(backup)
    }

    fn drill_now(&self, backup: &Backup) -> Outcome<orbital_core::backup::DrillRecord> {
        let record = crate::backup::drill(
            backup.store.as_ref(),
            &self.records,
            &self.home,
            (self.clock)(),
        );
        crate::backup::append(&self.records, &record).map_err(Failure::Internal)?;
        Ok(record)
    }

    /// 팩토리가 보는 훈련의 모습. 훈련은 레이어 하나의 일이라 어느 팩토리에게나 같다.
    pub fn backup_status(&self, _organization: &str) -> Outcome<BackupStatus> {
        let history = crate::backup::history(&self.records);
        let last_passed_at = orbital_core::backup::last_passed(&history);
        let fresh = orbital_core::backup::freshness(last_passed_at, (self.clock)()).is_fresh();
        let last_drill = history
            .iter()
            .max_by_key(|record| record.at)
            .map(|record| DrillSummary {
                passed: record.passed,
                at: record.at,
                recovery_millis: record.recovery_millis,
                drill_millis: record.drill_millis,
                exposure_seconds: record.exposure_seconds,
                instances: record.instances,
                checks: record.checks.len(),
                failed_checks: record
                    .checks
                    .iter()
                    .filter(|checked| !checked.passed)
                    .count(),
            });
        Ok(BackupStatus {
            fresh,
            last_passed_at,
            last_drill,
        })
    }

    /// 정한 주기가 됐으면 기반 백업을 뜨고 복구 훈련을 돌린다. 관리 서버가 1분마다 부른다.
    /// 훈련이 실패했으면 주기를 기다리지 않고 한 시간 뒤에 다시 돌린다.
    /// 운영의 인스턴스 가운데 때가 된 일정을 부른다. `orbitald` 가 1분마다 부르고, 테스트는 시계를 갈아 끼워 때를 만든다.
    ///
    /// 처음 보는 일정은 지난 때를 부르지 않고 다음 때를 적는다. 레이어가 내려가 있어 여러 때를 놓쳤으면 몰아서 부르지 않고 한 번만 부른다.
    /// 부르기 **전에** 다음 때를 기록에 적어, 부르는 도중에 레이어가 내려가도 같은 때를 두 번 부르지 않는다. 실패해도 다시 부르지 않는다.
    /// 프리뷰와 빌드를 기다리는 운영은 부르지 않는다. 부르는 일은 따로 된 스레드에서 돌고, 그 스레드들을 돌려준다(테스트가 기다린다).
    pub fn call_schedules(&self) -> Vec<std::thread::JoinHandle<()>> {
        let now = (self.clock)();
        // 이 기계에 떠 있는 운영만 본다. 다른 기계에 놓인 인스턴스의 일정은 그 기계가 부른다
        let lives: Vec<(String, Vec<orbital_core::manifest::Schedule>, Router)> = self
            .lock()
            .live
            .iter()
            .filter(|((_, stage), live)| *stage == Stage::Production && !live.building)
            .map(|((id, _), live)| {
                (
                    id.clone(),
                    live.manifest.get().schedules.clone(),
                    live.router.clone(),
                )
            })
            .collect();
        let mut due = Vec::new();
        for (id, schedules, router) in lives {
            let parsed: Vec<(&orbital_core::manifest::Schedule, Cron)> = schedules
                .iter()
                .filter_map(|schedule| Some((schedule, Cron::parse(&schedule.cron).ok()?)))
                .collect();
            // 선언에서 빠진 일정은 걷고, 처음 보는 일정은 지난 때를 부르지 않고 다음 때를 적는다
            let wanted: Vec<(String, u64)> = parsed
                .iter()
                .filter_map(|(schedule, cron)| Some((schedule.key(), cron.next_after(now)?)))
                .collect();
            if self.records.sync_schedules(&id, &wanted).is_err() {
                eprintln!("orbitald: 일정의 기록을 적지 못했습니다. 이번 때는 부르지 않습니다");
                continue;
            }
            let Ok(records) = self.records.schedules(&id) else {
                continue;
            };
            for (schedule, cron) in parsed {
                let key = schedule.key();
                let Some(entry) = records.get(&key) else {
                    continue;
                };
                if now < entry.next_at {
                    continue;
                }
                // 놓친 때 가운데 마지막 것에 맞춘다
                let mut due_at = entry.next_at;
                while let Some(later) = cron.next_after(due_at)
                    && later <= now
                {
                    due_at = later;
                }
                let run = ScheduleRun {
                    due_at,
                    started_at: now,
                    outcome: "running".to_owned(),
                    status: None,
                    millis: None,
                };
                // 부르기 전에 다음 때를 적는다. 그 줄의 다음 때가 그대로일 때만 잡혀, 같은 때를 두 번 부르지 않는다
                let next_at = cron.next_after(now).unwrap_or(u64::MAX);
                match self
                    .records
                    .claim_schedule(&id, &key, entry.next_at, next_at, &run)
                {
                    Ok(true) => due.push((
                        id.clone(),
                        key,
                        (schedule.service.to_string(), schedule.role.clone()),
                        schedule.path.clone(),
                        router.clone(),
                        run,
                    )),
                    Ok(false) => {}
                    Err(_) => {
                        eprintln!(
                            "orbitald: 일정의 기록을 적지 못했습니다. 이번 때는 부르지 않습니다"
                        );
                    }
                }
            }
        }
        due.into_iter()
            .map(|(id, key, (service, role), path, router, mut run)| {
                let runtime = self.runtime.handle().clone();
                let limit = self.schedule_timeout;
                let weak = Arc::downgrade(&self.0);
                std::thread::spawn(move || {
                    let started = Instant::now();
                    let called = runtime.block_on(router.call_schedule(
                        &service,
                        &path,
                        &key,
                        role.as_ref(),
                        limit,
                    ));
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let (outcome, status) = match called {
                        Called::Answered(status) if (200..300).contains(&status) => {
                            ("ok", Some(status))
                        }
                        Called::Answered(status) => ("failed", Some(status)),
                        Called::Unreachable => ("unreachable", None),
                        Called::TimedOut => ("timed_out", None),
                    };
                    let Some(core) = weak.upgrade() else {
                        return;
                    };
                    run.outcome = outcome.to_owned();
                    run.status = status;
                    run.millis = Some(millis);
                    if core.records.finish_schedule(&id, &key, &run).is_err() {
                        eprintln!("orbitald: 일정의 결과를 적지 못했습니다");
                    }
                })
            })
            .collect()
    }

    pub fn tend(&self, backup_every: Duration, drill_every: Duration) {
        let Some(backup) = &self.backup else {
            return;
        };
        // 여러 관리 서버 가운데 차례를 잡은 하나만 돈다. 때가 됐는지는 차례를 잡은 뒤에 봐서, 앞의 서버가 막 뜬 백업을 다시 뜨지 않는다
        let Ok(Some(_turn)) = self.records.take_backup_turn() else {
            return;
        };
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let latest = backup
            .store
            .backups()
            .ok()
            .and_then(|backups| backups.iter().map(|backup| backup.finished_at).max());
        let every = u64::try_from(backup_every.as_millis()).unwrap_or(u64::MAX);
        if latest.is_none_or(|at| now_millis >= at.saturating_add(every))
            && self.base_backup_now(backup).is_err()
        {
            eprintln!("orbitald: 기반 백업을 뜨지 못했습니다");
        }
        let history = crate::backup::history(&self.records);
        let now = (self.clock)();
        let due = match history.iter().max_by_key(|record| record.at) {
            None => true,
            Some(last) if last.passed => now >= last.at.saturating_add(drill_every.as_secs()),
            Some(last) => now >= last.at.saturating_add(60 * 60),
        };
        if due {
            match self.drill_now(backup) {
                Ok(record) if record.passed => eprintln!(
                    "orbitald: 복구 훈련이 통과했습니다(복구 {}ms)",
                    record.recovery_millis
                ),
                Ok(_) => eprintln!(
                    "orbitald: 복구 훈련이 실패했습니다. control database 의 `orbital.drill` 표의 마지막 줄을 봐 주세요"
                ),
                Err(_) => eprintln!("orbitald: 복구 훈련을 돌리지 못했습니다"),
            }
        }
    }

    /// 같은 인스턴스를 되살리는 일의 자리를 잡는다. 이미 누가 되살리거나 무르는 중이면 409 다. 떨어지면 자리를 돌려준다.
    fn begin_restore(&self, instance: &InstanceId) -> Outcome<Restoring<'_>> {
        let mut restoring = self
            .restoring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !restoring.insert(instance.as_str().to_owned()) {
            return Err(Failure::Conflict(
                "이 인스턴스는 지금 되살리는 중입니다. 끝난 뒤에 다시 불러 주세요".to_owned(),
            ));
        }
        Ok(Restoring {
            layer: self,
            instance: instance.as_str().to_owned(),
        })
    }

    /// 마지막 되살리기를 무른다. 그때 남긴 되돌릴 지점(되살리기 직전의 운영 DB)으로 돌아간다. 팩토리의 서버(service key)만 부른다.
    ///
    /// 되돌릴 지점은 하나라서 무른 뒤에는 다시 무르지 못한다. 되살린 뒤 승격이 있었으면 지점이 그 승격의 것으로 바뀌어 무르지 못한다.
    pub fn undo_restore(&self, organization: &str, instance: &InstanceId) -> Outcome<UndoReport> {
        let started = Instant::now();
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::Restore)?;
        let _restoring = self.begin_restore(instance)?;
        let mut inner = self.lock();
        let production = record.production.clone().ok_or_else(|| {
            Failure::Conflict("운영에 오른 것이 없어 무를 되살리기가 없습니다".to_owned())
        })?;
        let Some(restored) = production.restored.clone() else {
            return Err(Failure::Conflict(
                "무를 되살리기가 없습니다. 되살린 뒤 한 번만, 그 사이 승격이 없을 때 무를 수 있습니다".to_owned(),
            ));
        };
        match &production.restore_point {
            Some(point) if *point == restored => {}
            Some(_) => {
                return Err(Failure::Conflict(
                    "되살린 뒤 승격이 있어 되돌릴 지점이 그 승격의 것으로 바뀌었습니다. 되살리기를 무르지 못합니다. 필요하면 원하는 시점으로 다시 되살려 주세요".to_owned(),
                ));
            }
            None => {
                return Err(Failure::Conflict(
                    "이미 물렀습니다. 되돌릴 지점은 하나라 다시 무르지 못합니다".to_owned(),
                ));
            }
        }
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
        let names = Names::new(instance.clone());
        let key = (instance.as_str().to_owned(), Stage::Production);
        let sleep = |inner: &Inner| {
            if let Some(live) = inner.live.get(&key) {
                for service in &live.services {
                    if let Some(server) = &service.server {
                        server.refresh();
                    }
                }
            }
        };
        sleep(&inner);
        inner
            .admin
            .restore(&names, &assembled.manifest, &RestorePoint::named(restored))
            .map_err(internal)?;
        let tables = inner
            .admin
            .tables(&names, &assembled.manifest)
            .map_err(internal)?
            .len();
        self.update(instance, |stored| {
            if let Some(production) = stored.production.as_mut() {
                production.restore_point = None;
                production.restored = None;
            }
            Ok(())
        })?;
        sleep(&inner);
        Ok(UndoReport {
            instance: instance.as_str().to_owned(),
            millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            tables,
        })
    }

    /// 운영 중인 인스턴스 하나의 DB 를 지난 시점(유닉스 초)으로 되살린다. 팩토리의 서버(service key)만 부른다.
    ///
    /// 옆에 그 시점의 클러스터를 되살린 뒤 이 인스턴스의 database 만 운영 클러스터로 옮겨 바꿔 넣는다. 순서는 이렇다.
    /// 옆 이름에 레이어의 계획으로 다시 세우고 권한 검사를 지난다(앱의 정의는 관리 권한으로 돌지 않는다) → 서버를 재운다 →
    /// 지금의 운영 DB 를 되돌릴 지점으로 남긴다 → 이름을 바꿔 넣는다 → 다음 요청이 되살린 DB 에 닿는다.
    /// 다른 인스턴스의 database 와 역할은 건드리지 않는다. 코드(release)와 금고는 그대로다.
    pub fn restore_instance(
        &self,
        organization: &str,
        instance: &InstanceId,
        at: u64,
    ) -> Outcome<RestoreReport> {
        use orbital_backup::DatabaseName;

        let started = Instant::now();
        // 같은 인스턴스를 되살리거나 무르는 일은 한 번에 하나만 한다. 다른 인스턴스의 일은 기다리지 않는다
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::Restore)?;
        let _restoring = self.begin_restore(instance)?;
        let backup = self.backup_on()?;
        let production = record.production.clone().ok_or_else(|| {
            Failure::Conflict("운영에 오른 것이 없어 되살릴 DB 가 없습니다".to_owned())
        })?;
        let at_millis = at
            .checked_mul(1000)
            .ok_or_else(|| Failure::Problems(vec!["`at` 은 유닉스 초로 적어 주세요".to_owned()]))?;
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;

        // 그 시점의 클러스터를 옆에 세운다. 운영 클러스터는 덮어쓰지 않는다
        let store = backup.store.as_ref();
        store.seal(&self.pg_url).map_err(internal)?;
        let backups = store.backups().map_err(internal)?;
        let archive = store.archive().map_err(internal)?;
        let chosen = orbital_core::backup::judge_restore(&backups, &archive, at_millis)
            .map_err(|refusal| Failure::Conflict(restore_refusal_text(&refusal)))?
            .clone();
        let side = store
            .recover(&chosen, at_millis)
            .map_err(|error| Failure::Conflict(error.to_string()))?;
        let names = Names::new(instance.clone());
        let present = side
            .connect("postgres")
            .and_then(|mut client| orbital_backup::databases(&mut client))
            .map_err(internal)?;
        if !present.contains(&names.database()) {
            return Err(Failure::Conflict(
                "그 시점에는 이 인스턴스의 DB 가 아직 없었습니다. 운영에 처음 오른 뒤의 시점을 적어 주세요".to_owned(),
            ));
        }
        let source = DatabaseName::parse(&names.database()).map_err(internal)?;
        let suffix: String = random(5)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let staged = names
            .staged(&format!("rs_{suffix}"))
            .ok_or_else(|| internal("옆 이름을 짓지 못했습니다"))?;
        let identity_key = identity_key_of(&production)?;
        let manifest = &assembled.manifest;

        // 그 시점의 database 를 운영 클러스터의 옆 이름에 다시 세운다. 레이어의 것은 레이어의 계획으로 세우고, 앱의 정의는
        // 마이그레이션 역할로, 로그인의 행은 인증 역할로 넣는다. 권한을 권한 표대로 세워 권한 검사를 지나야 바꿔 넣는다.
        // 이동안 운영은 그대로 돌고, 레이어의 자물쇠는 쥐지 않는다(관리 연결을 따로 연다)
        let plan = crate::backup::Rebuild {
            names: &staged,
            manifest,
            access: &assembled.access,
            identity_key: &identity_key,
            pg_url: &self.pg_url,
        };
        let mut admin = Admin::connect(&self.pg_url).map_err(internal)?;
        let rebuilt = crate::backup::rebuild(&mut admin, &side, &source, &plan);
        drop(side);
        rebuilt.map_err(Failure::Conflict)?;

        // 여기서부터 짧게 레이어의 자물쇠를 쥔다. 그사이 운영이 바뀌었으면(승격 · 지우기) 바꿔 넣지 않는다
        let mut inner = self.lock();
        let unchanged = self
            .owned(organization, instance)
            .ok()
            .and_then(|stored| stored.production)
            .is_some_and(|now| {
                now.release == production.release && now.restore_point == production.restore_point
            });
        if !unchanged {
            let _ = inner.admin.forget(RestorePoint::named(staged.database()));
            return Err(Failure::Conflict(
                "되살리는 동안 운영이 바뀌었습니다(승격이나 지우기). 바꿔 넣지 않았습니다. 필요하면 다시 되살려 주세요".to_owned(),
            ));
        }

        // 서버를 재우고, 지금의 운영 DB 를 되돌릴 지점으로 남긴 뒤 바꿔 넣는다
        let key = (instance.as_str().to_owned(), Stage::Production);
        let sleep = |inner: &Inner| {
            if let Some(live) = inner.live.get(&key) {
                for service in &live.services {
                    if let Some(server) = &service.server {
                        server.refresh();
                    }
                }
            }
        };
        let forget_staged = |inner: &mut Inner| {
            let _ = inner.admin.forget(RestorePoint::named(staged.database()));
        };
        sleep(&inner);
        if let Err(error) = inner.admin.quiesce(&names) {
            forget_staged(&mut inner);
            return Err(internal(error));
        }
        let marked = inner.admin.mark(&names);
        let resumed = inner.admin.resume(&names);
        let point = match (marked, resumed) {
            (Ok(point), Ok(())) => point,
            (marked, resumed) => {
                forget_staged(&mut inner);
                return Err(internal(
                    marked
                        .err()
                        .or(resumed.err())
                        .map_or_else(String::new, |error| error.to_string()),
                ));
            }
        };
        if let Err(error) =
            inner
                .admin
                .restore(&names, manifest, &RestorePoint::named(staged.database()))
        {
            forget_staged(&mut inner);
            let _ = inner.admin.forget(point);
            return Err(internal(error));
        }
        let tables = inner
            .admin
            .tables(&names, manifest)
            .map_err(internal)?
            .len();

        // 되돌릴 지점은 하나만 둔다. 앞의 승격이 남긴 것은 지운다
        if let Some(old) = production.restore_point.clone() {
            let _ = inner.admin.forget(RestorePoint::named(old));
        }
        self.update(instance, |stored| {
            if let Some(production) = stored.production.as_mut() {
                production.restore_point = Some(point.database().to_owned());
                production.restored = Some(point.database().to_owned());
            }
            Ok(())
        })?;
        // 앞의 DB 에 붙어 있던 프로세스를 다시 재운다. 다음 요청이 되살린 DB 로 깬다
        sleep(&inner);
        Ok(RestoreReport {
            instance: instance.as_str().to_owned(),
            at,
            millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            tables,
            restore_point: point.database().to_owned(),
        })
    }
}
