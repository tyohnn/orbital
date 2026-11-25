//! 레이어의 동작. 인스턴스를 세우고, 코드를 받고, 그 commit 에서 직접 빌드해 프리뷰를 세우고, 승인받은 release 를 운영에 올린다.
//!
//! 판정은 core 가 한다(토큰의 범위, 권한 검사, 승격의 규칙). 여기서는 부품을 순서대로 부르고, 중간에 깨지면 앞의 모습으로 돌린다.
//! 서버가 하나일 때의 모양이라 일을 하나씩 차례로 한다(자물쇠 하나).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_core::access::Access;
use orbital_core::auth::query_value;
use orbital_core::check::{judge as judge_access, unguarded};
use orbital_core::describe::changes;
use orbital_core::git::Service as GitService;
use orbital_core::google::{IdTokenRefusal, callback_url, judge_id_token, judge_state};
use orbital_core::host::{BaseDomain, HostTarget, Scheme, origin as host_origin};
use orbital_core::manifest::{ServiceKind, ValidManifest};
use orbital_core::name::{Ident, InstanceId, SecretName};
use orbital_core::oauth::registrable_redirect;
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
    AppServer, Config as RouterConfig, Connect, DocumentFetcher, GoogleDoor, Hosts, HttpsFetcher,
    Outbox, Resend, Router, SESSION_COOKIE, Stage as RouterStage, Starter, Target as RouterTarget,
    WakeFailure, serve as serve_router, serve_hosts,
};
use orbital_run::{Job, Runner, Running, free_port, wait_for_port};
use orbital_source::assemble::{AssembleError, Assembled, assemble};
use orbital_source::{Commit, Error as SourceError, SourceStore, receive_scaffold};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::backup::BackupOptions;
use crate::login::{Endpoints, FactoryGoogleDoor, FactoryMailer, exchange, sha256_hex};
use crate::registry::{InstanceRecord, ProductionRecord, Registry, ReleaseRecord};
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
    Internal(String),
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
    Port(JoinHandle<std::io::Result<()>>),
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
            Self::Port(task) => task.abort(),
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
    /// router 의 바깥 주소.
    origin: String,
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
        env.extend(
            external
                .vault
                .values(
                    &external.organization,
                    &external.instance,
                    external.stage,
                    &external.names,
                )
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

struct Inner {
    admin: Admin,
    registry: Registry,
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

/// 사람이 값을 넣을 입력 표. 주소에 표가 실려 있다. 10분 안에 한 번 쓴다.
#[derive(Debug, Clone, Serialize)]
pub struct EntryTicket {
    pub url: String,
    pub expires_at: u64,
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
            public_url: "http://127.0.0.1:7400".to_owned(),
            dev_mailbox: false,
            endpoints: Endpoints::default(),
            sleep_after: Duration::from_secs(5 * 60),
            wake_timeout: Duration::from_secs(30),
            hosting: None,
            clock: Arc::new(now),
            conformance_timeout: Duration::from_secs(120),
            backup: None,
            token_clock: Arc::new(now),
            upload_limit: 64 * 1024 * 1024,
        }
    }
}

pub struct Layer {
    home: PathBuf,
    /// DB 의 관리 주소. router 가 인증 역할로 붙을 때 사용자와 database 만 바꿔 쓴다.
    pg_url: String,
    /// 팩토리의 설정(메일 · Google 의 키). 봉인한 글로만 파일에 있다.
    settings: Arc<Settings>,
    /// 밖에서 넣는 비밀의 금고. 봉인한 글로만 파일에 있다.
    vault: Arc<Vault>,
    clock: Clock,
    token_clock: Clock,
    upload_limit: usize,
    /// 개발용 메일함. 명시해 켰을 때만 있다.
    outbox: Option<Arc<Outbox>>,
    public_url: String,
    endpoints: Endpoints,
    /// Client ID Metadata Documents 를 받아 오는 것. 갈아 끼운다(테스트는 가짜를 쓴다).
    documents: Arc<dyn DocumentFetcher>,
    upstream: String,
    sources: SourceStore,
    runner: Arc<dyn Runner>,
    sleep_after: Duration,
    wake_timeout: Duration,
    conformance_timeout: Duration,
    /// 하위 도메인을 쓸 때만 있다.
    hosted: Option<Hosted>,
    runtime: Runtime,
    token_key: Vec<u8>,
    service_keys: Vec<([u8; 32], String)>,
    /// 백업을 켠 레이어에만 있다.
    backup: Option<Backup>,
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

/// 개발용 메일함의 파일. `ORBITAL_HOME` 아래에 둔다.
pub const OUTBOX: &str = "outbox.jsonl";
/// 팩토리의 설정 파일. `ORBITAL_HOME` 아래에 둔다.
pub const SETTINGS: &str = "settings.json";
/// 밖에서 넣는 비밀의 금고. `ORBITAL_HOME` 아래에 둔다.
pub const VAULT: &str = "vault.json";

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
    pub fn with_document_fetcher(mut self, documents: Arc<dyn DocumentFetcher>) -> Self {
        self.documents = documents;
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

        let key_file = options.home.join("token.key");
        let token_key = match fs::read(&key_file) {
            Ok(key) if key.len() >= 32 => key,
            _ => {
                let key = random(32).map_err(|_| "난수를 읽지 못했습니다".to_owned())?;
                fs::write(&key_file, &key)
                    .map_err(|_| "토큰의 열쇠를 적지 못했습니다".to_owned())?;
                fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))
                    .map_err(|_| "토큰의 열쇠를 적지 못했습니다".to_owned())?;
                key
            }
        };

        let vault = Vault::open(options.home.join(VAULT), options.seal_key.clone())?;
        let settings = Settings::open(options.home.join(SETTINGS), options.seal_key)?;
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
        let layer = Self {
            backup,
            sources: SourceStore::new(options.home.join("sources")),
            settings: Arc::new(settings),
            vault: Arc::new(vault),
            clock: options.clock,
            token_clock: options.token_clock,
            upload_limit: options.upload_limit,
            outbox: options
                .dev_mailbox
                .then(|| Arc::new(Outbox::new(options.home.join(OUTBOX)))),
            public_url: options.public_url.trim_end_matches('/').to_owned(),
            endpoints: options.endpoints,
            documents: Arc::new(HttpsFetcher),
            pg_url: options.pg_url,
            upstream,
            runner: Arc::from(options.runner),
            sleep_after: options.sleep_after,
            wake_timeout: options.wake_timeout,
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
            inner: Mutex::new(Inner {
                admin,
                registry: Registry::open(options.home.join("registry.json"))?,
                live: BTreeMap::new(),
            }),
            home: options.home,
        };
        layer.restore();
        Ok(layer)
    }

    /// 하위 도메인을 쓰는 레이어가 모든 인스턴스의 요청을 받는 주소. 포트마다 주소를 내는 레이어에는 없다.
    pub fn router_address(&self) -> Option<SocketAddr> {
        self.hosted.as_ref().map(|hosted| hosted.address)
    }

    /// 관리 서버가 다시 떴을 때 기록에서 운영 중인 인스턴스의 router 를 「자는」 상태로 다시 세운다. 첫 요청에 깬다.
    ///
    /// 기록(`registry.json`)의 운영 release · 서명의 열쇠 · 레이어가 만든 비밀과, 레이어가 빌드한 폴더를 믿는다.
    /// 빌드한 폴더가 없으면 그 commit 에서 다시 빌드한다. 프리뷰는 되살리지 않는다(다시 세우면 된다).
    /// 되살리지 못한 인스턴스는 건너뛰고 식별자와 갈래만 알린다.
    fn restore(&self) {
        let mut inner = self.lock();
        let records: Vec<(String, InstanceRecord)> = inner
            .registry
            .state
            .instances
            .iter()
            .filter(|(_, record)| record.production.is_some())
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect();
        // 프리뷰는 되살리지 않는다. 앞의 관리 서버가 세워 둔 프리뷰의 database 를 걷는다
        let previews: Vec<(String, String)> = inner
            .registry
            .state
            .instances
            .iter()
            .filter_map(|(id, record)| record.preview.clone().map(|preview| (id.clone(), preview)))
            .collect();
        for (id, preview) in previews {
            let destroyed = InstanceId::parse(&preview)
                .map_err(internal)
                .and_then(|preview| inner.admin.destroy(&Names::new(preview)).map_err(internal));
            match destroyed {
                Ok(()) => {
                    if let Some(record) = inner.registry.state.instances.get_mut(&id) {
                        record.preview = None;
                    }
                }
                Err(_) => eprintln!("orbitald: {id} 의 앞 프리뷰 database 를 걷지 못했습니다"),
            }
        }
        if inner.registry.save().is_err() {
            eprintln!("orbitald: 레이어의 기록을 적지 못했습니다");
        }
        for (id, record) in records {
            let Ok(instance) = InstanceId::parse(&id) else {
                continue;
            };
            match self.revive(&instance, &record) {
                Ok(live) => {
                    inner.live.insert((id, Stage::Production), live);
                }
                Err(failure) => {
                    let kind = match failure {
                        Failure::BuildFailed { .. } => "build_failed",
                        Failure::StartFailed { .. } => "start_failed",
                        Failure::Denied(_) => "secret_missing",
                        _ => "internal",
                    };
                    eprintln!("orbitald: 운영 {id} 를 되살리지 못했습니다({kind})");
                }
            }
        }
    }

    fn revive(&self, instance: &InstanceId, record: &InstanceRecord) -> Outcome<Live> {
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
        let folder = self.build(instance, &assembled)?;
        let names = Names::new(instance.clone());
        let identity_key = token::unhex(&production.identity_key)
            .ok_or_else(|| internal("서명의 열쇠를 읽지 못했습니다"))?;
        let stand = Stand {
            names: &names,
            generated: &production.generated,
            identity_key: &identity_key,
            stage: Stage::Production,
            organization: &record.organization,
            app: &record.app,
        };
        let launched = self.launch(instance, &assembled, &folder, &stand, false)?;
        Ok(Live {
            release: production.release.clone(),
            origin: launched.origin,
            names,
            manifest: assembled.manifest.clone(),
            seed_users: Vec::new(),
            services: launched.services,
            _router: launched.router,
        })
    }
}

// ---- 누구인가 ----

impl Layer {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // 다른 일이 하다가 깨졌어도 기록은 파일에서 다시 읽은 것과 같으므로 이어 쓴다
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
    pub fn authorize(&self, bearer: &str, instance: &InstanceId, action: Action) -> Outcome<()> {
        let token = token::verify(&self.token_key, bearer).ok_or(Failure::Unauthorized)?;
        let organization = {
            let inner = self.lock();
            let record = inner
                .registry
                .state
                .instances
                .get(instance.as_str())
                .ok_or(Failure::NotFound)?;
            OrganizationId(record.organization.clone())
        };
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

    fn owned<'a>(
        inner: &'a mut Inner,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<&'a mut InstanceRecord> {
        inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .filter(|record| record.organization == organization)
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
        receive_scaffold(&self.app_path(organization, &app)?, bundle).map_err(|error| match error {
            SourceError::BadBundle => Failure::Problems(vec![error.to_string()]),
            other => internal(other),
        })
    }

    /// 고객 하나의 인스턴스를 스캐폴드의 한 버전에서 세운다. 코드 저장소만 생기고, DB 와 서버는 첫 승격 때 선다.
    pub fn create_instance(
        &self,
        organization: &str,
        app: &str,
        version: &str,
    ) -> Outcome<InstanceId> {
        let app = Ident::parse(app).map_err(|_| Failure::NotFound)?;
        let scaffold = self.app_path(organization, &app)?;
        if !scaffold.join("HEAD").is_file() {
            return Err(Failure::NotFound);
        }
        // 복구 훈련이 통과한 뒤에만 새 고객의 데이터를 받는다
        self.require_fresh_drill()?;
        let mut inner = self.lock();
        let instance = fresh_id('i')?;
        self.sources
            .create(&instance, &scaffold, version)
            .map_err(|error| match error {
                SourceError::NoSuchVersion => Failure::Problems(vec![format!(
                    "스캐폴드 `{app}` 에 `{version}` 버전이 없습니다"
                )]),
                other => internal(other),
            })?;
        inner.registry.state.instances.insert(
            instance.as_str().to_owned(),
            InstanceRecord {
                organization: organization.to_owned(),
                app: app.to_string(),
                ..InstanceRecord::default()
            },
        );
        inner.registry.save().map_err(Failure::Internal)?;
        Ok(instance)
    }

    /// 에이전트의 작업 한 번에 쓸 토큰을 낸다. 누가 이 인스턴스를 고칠 수 있는지는 팩토리가 이미 판정했다.
    pub fn open_session(
        &self,
        organization: &str,
        instance: &InstanceId,
        can: BTreeSet<Capability>,
        ttl_seconds: u64,
    ) -> Outcome<(String, u64)> {
        /// 토큰은 몇 시간 안에 만료된다.
        const LONGEST: u64 = 12 * 60 * 60;
        let mut inner = self.lock();
        Self::owned(&mut inner, organization, instance)?;
        let expires_at = (self.token_clock)() + ttl_seconds.clamp(60, LONGEST);
        let token = Token {
            organization: OrganizationId(organization.to_owned()),
            instance: instance.clone(),
            can,
            expires_at,
        };
        Ok((token::sign(&self.token_key, &token), expires_at))
    }
}

// ---- 에이전트가 하는 일(토큰) ----

impl Layer {
    pub fn source_bundle(&self, instance: &InstanceId) -> Outcome<Vec<u8>> {
        let _guard = self.lock();
        self.sources.bundle(instance).map_err(internal)
    }

    /// 묶음으로 올린 것을 받는다. git 으로 올린 것(`git_exchange`)과 같은 규칙으로 판정한다.
    pub fn push(&self, instance: &InstanceId, bundle: &[u8]) -> Outcome<Commit> {
        let mut inner = self.lock();
        let commit = self
            .sources
            .receive(instance, bundle)
            .map_err(|error| match error {
                SourceError::BadBundle | SourceError::NotFastForward | SourceError::Refused(_) => {
                    Failure::Problems(vec![error.to_string()])
                }
                other => internal(other),
            })?;
        self.received(&mut inner, instance, &commit)?;
        Ok(commit)
    }

    /// 올린 commit 을 받은 뒤의 일. 묶음과 git 의 두 길이 함께 부른다.
    fn received(&self, inner: &mut Inner, instance: &InstanceId, commit: &Commit) -> Outcome<()> {
        // 에이전트가 업데이트를 합쳐(충돌을 풀어) 올렸으면 적용된 것이다
        self.track(
            inner,
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
    ) -> Outcome<Vec<u8>> {
        let source_failure = |error: SourceError| match error {
            SourceError::NoSuchInstance => Failure::NotFound,
            SourceError::BadBundle => Failure::Problems(vec![error.to_string()]),
            other => internal(other),
        };
        match service {
            // 받기는 읽기만 한다. ref 는 한 번에 옮겨 가므로 잠그지 않는다
            GitService::UploadPack => self
                .sources
                .upload_pack(instance, request)
                .map_err(source_failure),
            GitService::ReceivePack => {
                let mut inner = self.lock();
                let received = self
                    .sources
                    .receive_pack(instance, request)
                    .map_err(source_failure)?;
                if let Some(commit) = &received.commit {
                    self.received(&mut inner, instance, commit)?;
                }
                Ok(received.report)
            }
        }
    }

    /// 떠 있는 프리뷰의 빌드와 서버의 로그(끝의 200줄씩). 프리뷰의 앱은 에이전트가 쓴 코드이고 씨앗 데이터만 갖는다.
    pub fn preview_logs(&self, instance: &InstanceId) -> Outcome<PreviewLogs> {
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
        if let Some(production) = inner
            .registry
            .state
            .instances
            .get(instance.as_str())
            .and_then(|record| record.production.as_ref())
        {
            keep.push(&production.release);
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
        let marker = folder.join(".orbital-built");
        if marker.is_file() {
            return Ok(folder);
        }
        let _ = fs::remove_dir_all(&folder);
        self.sources
            .export(instance, &assembled.commit, &folder)
            .map_err(internal)?;
        let cache = self.cache_folder(instance);
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
    /// `wake` 면 서버 서비스를 지금 띄워 실제로 뜨는지 확인한다(프리뷰와 승격). 아니면 자는 채로 세워 첫 요청에 깨운다
    /// (관리 서버가 다시 떴을 때). 어느 쪽이든 요청이 없으면 정한 시간 뒤에 잔다.
    fn launch(
        &self,
        instance: &InstanceId,
        assembled: &Assembled,
        folder: &Path,
        stand: &Stand<'_>,
        wake: bool,
    ) -> Outcome<Launched> {
        let (names, generated, stage) = (stand.names, stand.generated, stand.stage);
        // 하위 도메인을 쓰면 레이어의 주소 하나가 받고, 아니면 인스턴스마다 포트 하나를 듣는다
        let (listener, origin, host) = match &self.hosted {
            Some(hosted) => {
                let target = match stage {
                    Stage::Preview => HostTarget::Preview(instance.clone()),
                    Stage::Production => HostTarget::Production(instance.clone()),
                };
                let origin = host_origin(hosted.scheme, &hosted.base, &target);
                (None, origin, Some(target))
            }
            None => {
                let listener = self
                    .runtime
                    .block_on(TcpListener::bind("127.0.0.1:0"))
                    .map_err(internal)?;
                let origin = format!(
                    "http://127.0.0.1:{}",
                    listener.local_addr().map_err(internal)?.port()
                );
                (Some(listener), origin, None)
            }
        };
        let url = |path: &str| format!("{origin}{}", path.trim_end_matches('/'));
        let mut services = Vec::new();
        let mut targets = BTreeMap::new();
        for service in &assembled.manifest.get().services {
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
            let mut env = vec![
                ("HOST".to_owned(), "127.0.0.1".to_owned()),
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
                let listener = self
                    .runtime
                    .block_on(TcpListener::bind("127.0.0.1:0"))
                    .map_err(internal)?;
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
                self.runtime.handle().clone(),
            );
            let live = LiveService {
                name: service.name.to_string(),
                kind: service.kind,
                url: url(&service.path),
                server: Some(Arc::clone(&server)),
                proxy,
            };
            if wake {
                let port = free_port().ok_or_else(|| internal("빈 포트를 찾지 못했습니다"))?;
                let process = starter.start(port).map_err(|_| Failure::StartFailed {
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
            documents: Arc::clone(&self.documents),
        };
        let router = match (listener, host, &self.hosted) {
            (Some(listener), _, _) => {
                Front::Port(self.runtime.spawn(serve_router(listener, config)))
            }
            (None, Some(target), Some(hosted)) => {
                let router = Router::new(config);
                hosted.hosts.insert(target.clone(), &router);
                Front::Host {
                    hosts: Arc::clone(&hosted.hosts),
                    target,
                    router,
                }
            }
            _ => return Err(internal("router 를 세울 자리가 없습니다")),
        };
        Ok(Launched {
            services,
            router,
            origin,
        })
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

    /// 운영에 올라 있는 release 의 권한 표. 운영이 없으면 빈 표다.
    fn production_access(&self, instance: &InstanceId, record: &InstanceRecord) -> Outcome<Access> {
        let Some(production) = &record.production else {
            return Ok(Access::default());
        };
        let commit = record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .ok_or_else(|| internal("운영의 release 를 찾지 못했습니다"))?;
        Ok(self.assembled(instance, &commit)?.access)
    }

    /// commit 하나의 프리뷰를 세운다. 그 commit 에서 직접 빌드하고, 씨앗 데이터만 든 DB 를 새로 만들어 역할과 권한을 세우고, 권한 검사를 돌린다.
    pub fn preview(&self, instance: &InstanceId, commit: Option<Commit>) -> Outcome<PreviewReport> {
        if !self
            .lock()
            .registry
            .state
            .instances
            .contains_key(instance.as_str())
        {
            return Err(Failure::NotFound);
        }
        let commit = match commit {
            Some(commit) => commit,
            None => self.sources.head(instance).map_err(internal)?,
        };
        let assembled = self.assembled(instance, &commit)?;
        // 빌드(npm ci 와 프레임워크의 빌드)는 분 단위로 걸린다. 레이어의 자물쇠를 쥐지 않고 돌려 다른 인스턴스의 일을 막지 않는다
        let folder = self.build(instance, &assembled)?;

        let mut inner = self.lock();
        // 빌드하는 동안 인스턴스가 지워졌거나 운영이 바뀌었을 수 있다. 기록은 자물쇠를 쥔 뒤에 다시 읽는다
        let record = inner
            .registry
            .state
            .instances
            .get(instance.as_str())
            .cloned()
            .ok_or(Failure::NotFound)?;

        // 앞의 프리뷰를 걷는다. 인스턴스마다 프리뷰는 하나다
        if let Some(old) = inner
            .live
            .remove(&(instance.as_str().to_owned(), Stage::Preview))
        {
            let names = old.names.clone();
            drop(old);
            inner.admin.destroy(&names).map_err(internal)?;
        }

        let names = Names::new(fresh_id('p')?);
        // 세우기 전에 적어 둔다. 도중에 관리 서버가 내려가도 다시 뜰 때 이 database 를 걷는다
        Self::note_preview(&mut inner, instance, Some(&names))?;
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
        };
        let launched = match self.launch(instance, &assembled, &folder, &stand, true) {
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
        let before = self.production_access(instance, &record)?;
        let report = PreviewReport {
            release: assembled.release.0.clone(),
            commit: commit.to_string(),
            services: Self::report(&launched.services),
            findings: findings.iter().map(ToString::to_string).collect(),
            changes: changes(&before, &assembled.access)
                .into_iter()
                .map(|change| change.sentence)
                .collect(),
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

        let stored = inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .ok_or(Failure::NotFound)?;
        stored.releases.insert(
            assembled.release.0.clone(),
            ReleaseRecord {
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
            },
        );
        inner.registry.save().map_err(Failure::Internal)?;
        // 업데이트를 담은 commit 이면 그 rollout 에 적용 · 프리뷰 · 검사의 결과를 넘긴다
        self.track(
            &mut inner,
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
                _router: launched.router,
            },
        );
        self.prune_builds(&inner, instance);
        Ok(report)
    }

    /// 프리뷰의 database 를 기록에 적거나 지운다.
    fn note_preview(
        inner: &mut Inner,
        instance: &InstanceId,
        names: Option<&Names>,
    ) -> Outcome<()> {
        if let Some(record) = inner.registry.state.instances.get_mut(instance.as_str()) {
            record.preview = names.map(|names| names.instance().as_str().to_owned());
            inner.registry.save().map_err(Failure::Internal)?;
        }
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
        let mut inner = self.lock();
        if let Some(old) = inner
            .live
            .remove(&(instance.as_str().to_owned(), Stage::Preview))
        {
            let names = old.names.clone();
            drop(old);
            inner.admin.destroy(&names).map_err(internal)?;
        }
        Self::note_preview(&mut inner, instance, None)
    }

    /// 운영 DB 의 사본에 아직 돌지 않은 마이그레이션을 미리 돌려 본다. 숫자만 돌아온다.
    pub fn rehearse(&self, instance: &InstanceId, release: &str) -> Outcome<RehearsalReport> {
        let mut inner = self.lock();
        let record = inner
            .registry
            .state
            .instances
            .get(instance.as_str())
            .cloned()
            .ok_or(Failure::NotFound)?;
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
        if let Some(stored) = inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .and_then(|stored| stored.releases.get_mut(release))
        {
            stored.rehearsal = outcome;
        }
        inner.registry.save().map_err(Failure::Internal)?;
        Ok(report)
    }

    /// 승격을 요청한다. 막는 것이 있으면 요청하지 못한다. 올리는 것은 사람의 승인을 받은 팩토리의 서버다.
    pub fn request_promotion(&self, instance: &InstanceId, release: &str) -> Outcome<()> {
        let mut inner = self.lock();
        let record = inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .ok_or(Failure::NotFound)?;
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
        let record = inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .ok_or(Failure::NotFound)?;
        record.promotion_requested = Some(release.to_owned());
        inner.registry.save().map_err(Failure::Internal)
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
        let mut inner = self.lock();
        let record = Self::owned(&mut inner, organization, instance)?.clone();
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
        let governing = self.governing(&inner, instance, &commit);
        if let Some(id) = &governing
            && let Some(record) = inner.registry.state.rollouts.get(id)
        {
            record
                .rollout
                .may_promote(instance, change)
                .map_err(|refusal| Failure::Conflict(refusal_text(&refusal)))?;
        }

        let folder = self.build(instance, &assembled)?;
        let names = Names::new(instance.clone());
        let key = (instance.as_str().to_owned(), Stage::Production);

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
                let identity_key = token::unhex(&production.identity_key)
                    .ok_or_else(|| internal("서명의 열쇠를 읽지 못했습니다"))?;
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
                    let _ = Self::record(
                        &mut inner,
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
        };
        let stored = inner
            .registry
            .state
            .instances
            .get_mut(instance.as_str())
            .ok_or(Failure::NotFound)?;
        stored.production = Some(ProductionRecord {
            release: release.to_owned(),
            previous: record
                .production
                .as_ref()
                .map(|production| production.release.clone()),
            restore_point: point.as_ref().map(|point| point.database().to_owned()),
            identity_key: token::hex(&identity_key),
            generated,
        });
        stored.promotion_requested = None;
        inner.registry.save().map_err(Failure::Internal)?;
        if let Some(id) = &governing {
            Self::record(
                &mut inner,
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
        };
        let launched = self
            .launch(target.instance, assembled, target.folder, &stand, true)
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
        // 권한을 앞의 권한 표로 되돌린다. 새 release 의 권한이 남아 있으면 안 된다
        let _ = inner
            .admin
            .grant(prior.names, &assembled.manifest, &assembled.access);
        let identity_key = token::unhex(&production.identity_key).unwrap_or_default();
        let stand = Stand {
            names: prior.names,
            generated: &production.generated,
            identity_key: &identity_key,
            stage: Stage::Production,
            organization: &prior.record.organization,
            app: &prior.record.app,
        };
        if let Ok(launched) = self.launch(prior.instance, &assembled, &folder, &stand, true) {
            inner.live.insert(
                (prior.instance.as_str().to_owned(), Stage::Production),
                Live {
                    release: production.release.clone(),
                    origin: launched.origin,
                    names: prior.names.clone(),
                    manifest: assembled.manifest.clone(),
                    seed_users: Vec::new(),
                    services: launched.services,
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
        let mut inner = self.lock();
        let record = Self::owned(&mut inner, organization, instance)?.clone();
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
        let before = self.production_access(instance, &record)?;
        let received = self.production_external(instance, &record)?;
        let rollout = self.governing(&inner, instance, &commit);
        Ok(Some(PendingPromotion {
            rollout,
            release,
            commit: commit.to_string(),
            changes: changes(&before, &assembled.access)
                .into_iter()
                .map(|change| change.sentence)
                .collect(),
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
        let mut inner = self.lock();
        Self::owned(&mut inner, organization, instance)?;
        Ok(inner
            .live
            .get(&(instance.as_str().to_owned(), Stage::Production))
            .map(|live| PromotionReport {
                release: live.release.clone(),
                services: Self::report(&live.services),
                migrations: Vec::new(),
            }))
    }

    /// 운영의 사용자 저장소(인증 역할로 붙은 연결). 운영이 서 있고 `[auth]` 를 선언했을 때만 있다.
    pub fn production_auth(&self, organization: &str, instance: &InstanceId) -> Outcome<AuthStore> {
        let (names, manifest) = {
            let mut inner = self.lock();
            Self::owned(&mut inner, organization, instance)?;
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Production))
                .ok_or_else(|| {
                    Failure::Conflict(
                        "운영에 오른 것이 없습니다. 운영에 먼저 올린 뒤에 사용자를 초대해 주세요"
                            .to_owned(),
                    )
                })?;
            if live.manifest.get().auth.is_none() {
                return Err(Failure::Problems(vec![
                    "이 앱은 로그인을 레이어에 맡기지 않아 사용자가 없습니다. `orbital.toml` 에 `[auth]` 를 적어 주세요".to_owned(),
                ]));
            }
            (live.names.clone(), live.manifest.clone())
        };
        AuthStore::connect(&self.pg_url, &names, &manifest).map_err(internal)
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
        let declared = self
            .lock()
            .live
            .get(&(instance.as_str().to_owned(), Stage::Production))
            .is_some_and(|live| orbital_core::oauth::mcp(&live.manifest).is_some());
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
        let mut inner = self.lock();
        Self::owned(&mut inner, organization, instance)?;
        for stage in [Stage::Preview, Stage::Production] {
            if let Some(live) = inner.live.remove(&(instance.as_str().to_owned(), stage)) {
                let names = live.names.clone();
                drop(live);
                inner.admin.destroy(&names).map_err(internal)?;
            }
        }
        inner
            .admin
            .destroy(&Names::new(instance.clone()))
            .map_err(internal)?;
        self.sources.destroy(instance).map_err(internal)?;
        self.vault.forget(instance).map_err(vault_failure)?;
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
        inner.registry.state.instances.remove(instance.as_str());
        inner.registry.save().map_err(Failure::Internal)
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
        let (organization, origin, names, manifest) = {
            let inner = self.lock();
            let record = inner
                .registry
                .state
                .instances
                .get(instance.as_str())
                .ok_or(Failure::NotFound)?;
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Production))
                .ok_or(Failure::NotFound)?;
            (
                record.organization.clone(),
                live.origin.clone(),
                live.names.clone(),
                live.manifest.clone(),
            )
        };
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
        self.lock()
            .registry
            .state
            .instances
            .get(instance.as_str())
            .map(|record| record.organization.clone())
            .ok_or(Failure::NotFound)
    }

    /// 그 인스턴스의 release(프리뷰로 세운 것과 운영의 것)가 밖에서 넣는다고 선언한 이름. 다른 팩토리의 것은 없는 것으로 답한다.
    fn declared_secrets(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<BTreeSet<SecretName>> {
        let mut inner = self.lock();
        let record = Self::owned(&mut inner, organization, instance)?;
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
        let record = {
            let mut inner = self.lock();
            Self::owned(&mut inner, organization, instance)?.clone()
        };
        if stage == SecretStage::Production
            && self.production_external(instance, &record)?.contains(&name)
        {
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
            url: format!("{}/v1/secret-entries/{ticket}", self.public_url),
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
    fn refresh(&self, place: &Place) {
        let inner = self.lock();
        let Some(live) = inner
            .live
            .get(&(place.instance.as_str().to_owned(), Stage::of(place.stage)))
        else {
            return;
        };
        if !live.manifest.get().secrets.external.contains(&place.name) {
            return;
        }
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
        let history = crate::backup::history(&self.home);
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

    /// 기반 백업을 하나 뜨고 보관 기간이 지난 것을 지운다. 백업을 켜지 않은 레이어에서는 409 다.
    /// 뜨는 동안 다른 일을 멈춰 레이어의 기록과 DB 가 같은 때의 것이 되게 한다.
    pub fn base_backup(&self) -> Outcome<orbital_core::backup::BaseBackup> {
        let backup = self.backup_on()?;
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
    pub fn drill(&self) -> Outcome<orbital_core::backup::DrillRecord> {
        let backup = self.backup_on()?;
        let record = crate::backup::drill(
            backup.store.as_ref(),
            &self.home,
            &self.pg_url,
            (self.clock)(),
        );
        crate::backup::append(&self.home, &record).map_err(Failure::Internal)?;
        Ok(record)
    }

    /// 팩토리가 보는 훈련의 모습. 훈련은 레이어 하나의 일이라 어느 팩토리에게나 같다.
    pub fn backup_status(&self, _organization: &str) -> Outcome<BackupStatus> {
        let history = crate::backup::history(&self.home);
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
    pub fn tend(&self, backup_every: Duration, drill_every: Duration) {
        let Some(backup) = &self.backup else {
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
            && self.base_backup().is_err()
        {
            eprintln!("orbitald: 기반 백업을 뜨지 못했습니다");
        }
        let history = crate::backup::history(&self.home);
        let now = (self.clock)();
        let due = match history.iter().max_by_key(|record| record.at) {
            None => true,
            Some(last) if last.passed => now >= last.at.saturating_add(drill_every.as_secs()),
            Some(last) => now >= last.at.saturating_add(60 * 60),
        };
        if due {
            match self.drill() {
                Ok(record) if record.passed => eprintln!(
                    "orbitald: 복구 훈련이 통과했습니다(복구 {}ms)",
                    record.recovery_millis
                ),
                Ok(_) => eprintln!(
                    "orbitald: 복구 훈련이 실패했습니다. drills.jsonl 의 마지막 줄을 봐 주세요"
                ),
                Err(_) => eprintln!("orbitald: 복구 훈련을 돌리지 못했습니다"),
            }
        }
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
        let mut inner = self.lock();
        let record = Self::owned(&mut inner, organization, instance)?.clone();
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
        let identity_key = token::unhex(&production.identity_key)
            .ok_or_else(|| internal("서명의 열쇠를 읽지 못했습니다"))?;
        let manifest = &assembled.manifest;

        // 그 시점의 database 를 운영 클러스터의 옆 이름에 다시 세운다. 레이어의 것은 레이어의 계획으로 세우고, 앱의 정의는
        // 마이그레이션 역할로, 로그인의 행은 인증 역할로 넣는다. 권한을 권한 표대로 세워 권한 검사를 지나야 바꿔 넣는다.
        // 이동안 운영은 그대로 돈다
        let plan = crate::backup::Rebuild {
            names: &staged,
            manifest,
            access: &assembled.access,
            identity_key: &identity_key,
            pg_url: &self.pg_url,
        };
        let rebuilt = crate::backup::rebuild(&mut inner.admin, &side, &source, &plan);
        drop(side);
        rebuilt.map_err(Failure::Conflict)?;

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
        let stored = Self::owned(&mut inner, organization, instance)?;
        if let Some(production) = stored.production.as_mut() {
            production.restore_point = Some(point.database().to_owned());
        }
        inner.registry.save().map_err(Failure::Internal)?;
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
