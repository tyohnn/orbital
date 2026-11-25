//! 레이어의 동작. 인스턴스를 세우고, 코드를 받고, 그 commit 에서 직접 빌드해 미리보기를 세우고, 승인받은 release 를 운영에 올린다.
//!
//! 판정은 core 가 한다(토큰의 범위, 권한 검사, 승격의 규칙). 여기서는 부품을 순서대로 부르고, 중간에 깨지면 앞의 모습으로 돌린다.
//! 서버가 하나일 때의 모양이라 일을 하나씩 차례로 한다(자물쇠 하나).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orbital_core::access::Access;
use orbital_core::auth::query_value;
use orbital_core::check::{judge as judge_access, unguarded};
use orbital_core::describe::changes;
use orbital_core::google::{IdTokenRefusal, callback_url, judge_id_token, judge_state};
use orbital_core::manifest::{ServiceKind, ValidManifest};
use orbital_core::name::{Ident, InstanceId};
use orbital_core::oauth::registrable_redirect;
use orbital_core::plan::Names;
use orbital_core::release::{
    Aftermath, Approval, Approver, BuiltBy, Change, FactoryKey, Migrations, PromoteDenied,
    Rehearsed, Release, ReleaseId, after_promotion, blockers, missing_keys,
    promote as judge_promotion,
};
use orbital_core::scope::{
    Action, Capability, DenyReason, OrganizationId, Request, Token, Verdict, judge,
};
use orbital_pg::Admin;
use orbital_pg::auth::AuthStore;
use orbital_pg::rehearsal::RestorePoint;
use orbital_proxy::{Route, serve};
use orbital_router::{
    Config as RouterConfig, Connect, DocumentFetcher, GoogleDoor, HttpsFetcher, Outbox, Resend,
    SESSION_COOKIE, Stage as RouterStage, Target as RouterTarget, serve as serve_router,
};
use orbital_run::{Job, Runner, Running, free_port, wait_for_port};
use orbital_source::assemble::{AssembleError, Assembled, assemble};
use orbital_source::{Commit, Error as SourceError, SourceStore, receive_scaffold};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::login::{Endpoints, FactoryGoogleDoor, FactoryMailer, exchange, sha256_hex};
use crate::registry::{InstanceRecord, ProductionRecord, Registry, ReleaseRecord};
use crate::seal::SealKey;
use crate::settings::{Settings, SettingsError};
use crate::token;

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

fn tail(log: &Path) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Preview,
    Production,
}

struct LiveService {
    name: String,
    kind: ServiceKind,
    /// 밖에 알리는 주소. router 의 주소 + 서비스의 `path` 다.
    url: String,
    process: Option<Box<dyn Running>>,
    proxy: Option<JoinHandle<std::io::Result<()>>>,
}

/// 떠 있는 router. 내리면 듣기를 멈추고 붙어 있던 연결도 함께 내린다.
struct RouterTask(JoinHandle<std::io::Result<()>>);

impl Drop for RouterTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 띄운 서비스들과 그 앞의 router.
struct Launched {
    services: Vec<LiveService>,
    router: RouterTask,
    /// router 의 바깥 주소.
    origin: String,
}

/// 띄울 자리. 미리보기와 운영이 이름 · 비밀 · 서명의 열쇠를 따로 갖는다.
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
        if let Some(mut process) = self.process.take() {
            process.stop();
        }
        if let Some(proxy) = self.proxy.take() {
            proxy.abort();
        }
    }
}

/// 떠 있는 것 하나(미리보기이거나 운영). 서비스가 먼저 내려가고 router 가 뒤에 내려간다.
struct Live {
    release: String,
    /// router 의 바깥 주소. Google 의 콜백이 한 번 쓰는 표를 들고 이리로 보낸다.
    origin: String,
    names: Names,
    manifest: ValidManifest,
    /// 미리보기의 씨앗 사용자. 운영에는 없다.
    seed_users: Vec<String>,
    services: Vec<LiveService>,
    _router: RouterTask,
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
}

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
        }
    }
}

pub struct Layer {
    home: PathBuf,
    /// DB 의 관리 주소. router 가 인증 역할로 붙을 때 사용자와 database 만 바꿔 쓴다.
    pg_url: String,
    /// 팩토리의 설정(메일 · Google 의 키). 봉인한 글로만 파일에 있다.
    settings: Arc<Settings>,
    /// 개발용 메일함. 명시해 켰을 때만 있다.
    outbox: Option<Arc<Outbox>>,
    public_url: String,
    endpoints: Endpoints,
    /// Client ID Metadata Documents 를 받아 오는 것. 갈아 끼운다(테스트는 가짜를 쓴다).
    documents: Arc<dyn DocumentFetcher>,
    upstream: String,
    sources: SourceStore,
    runner: Box<dyn Runner>,
    runtime: Runtime,
    token_key: Vec<u8>,
    service_keys: Vec<([u8; 32], String)>,
    inner: Mutex<Inner>,
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
            "마이그레이션의 예행연습을 아직 돌리지 않았습니다. `orbital rehearse` 로 돌려 주세요"
                .to_owned()
        }
        Blocker::RehearsalFailed => "마이그레이션의 예행연습이 실패했습니다".to_owned(),
        Blocker::KeyMissing { key } => key_text(*key),
    }
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

        let settings = Settings::open(options.home.join(SETTINGS), options.seal_key)?;
        Ok(Self {
            sources: SourceStore::new(options.home.join("sources")),
            settings: Arc::new(settings),
            outbox: options
                .dev_mailbox
                .then(|| Arc::new(Outbox::new(options.home.join(OUTBOX)))),
            public_url: options.public_url.trim_end_matches('/').to_owned(),
            endpoints: options.endpoints,
            documents: Arc::new(HttpsFetcher),
            pg_url: options.pg_url,
            upstream,
            runner: options.runner,
            runtime: Runtime::new()
                .map_err(|_| "proxy 의 런타임을 띄우지 못했습니다".to_owned())?,
            token_key,
            service_keys: options
                .service_keys
                .iter()
                .map(|(key, organization)| (digest(key), organization.clone()))
                .collect(),
            inner: Mutex::new(Inner {
                admin,
                registry: Registry::open(options.home.join("registry.json"))?,
                live: BTreeMap::new(),
            }),
            home: options.home,
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
            at: now(),
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
        let expires_at = now() + ttl_seconds.clamp(60, LONGEST);
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

    pub fn push(&self, instance: &InstanceId, bundle: &[u8]) -> Outcome<Commit> {
        let _guard = self.lock();
        self.sources
            .receive(instance, bundle)
            .map_err(|error| match error {
                SourceError::BadBundle | SourceError::NotFastForward => {
                    Failure::Problems(vec![error.to_string()])
                }
                other => internal(other),
            })
    }

    fn assembled(&self, instance: &InstanceId, commit: &Commit) -> Outcome<Assembled> {
        assemble(&self.sources, instance, commit).map_err(|error| match error {
            AssembleError::Problems(problems) => Failure::Problems(problems),
            AssembleError::Source(SourceError::NoSuchCommit) => Failure::Problems(vec![
                "그 commit 은 레이어에 올라와 있지 않습니다. `orbital push` 로 먼저 올려 주세요"
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

    /// release 를 그 commit 에서 직접 빌드한다. 이미 빌드했으면 그것을 쓴다.
    fn build(&self, instance: &InstanceId, assembled: &Assembled) -> Outcome<PathBuf> {
        let folder = self
            .home
            .join("builds")
            .join(instance.as_str())
            .join(&assembled.release.0);
        let marker = folder.join(".orbital-built");
        if marker.is_file() {
            return Ok(folder);
        }
        let _ = fs::remove_dir_all(&folder);
        self.sources
            .export(instance, &assembled.commit, &folder)
            .map_err(internal)?;
        for service in &assembled.manifest.get().services {
            let log = self.log(
                instance,
                &assembled.release,
                &format!("build-{}", service.name),
            );
            let job = Job {
                folder: &folder,
                command: &service.build,
                env: &[],
                log: &log,
            };
            self.runner.build(&job).map_err(|_| Failure::BuildFailed {
                service: service.name.to_string(),
                log: tail(&log),
            })?;
        }
        fs::write(&marker, assembled.commit.as_str())
            .map_err(|_| internal("빌드의 표시를 적지 못했습니다"))?;
        Ok(folder)
    }

    /// 빌드한 것을 띄운다. 서버 서비스마다 proxy 를 하나 세우고, 앱에는 그 주소와 레이어가 만든 비밀만 건넨다.
    /// 서비스들 앞에 router 를 세운다. 밖에서는 router 의 주소로만 닿는다.
    fn launch(
        &self,
        instance: &InstanceId,
        assembled: &Assembled,
        folder: &Path,
        stand: &Stand<'_>,
    ) -> Outcome<Launched> {
        let (names, generated, stage) = (stand.names, stand.generated, stand.stage);
        let listener = self
            .runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .map_err(internal)?;
        let origin = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().map_err(internal)?.port()
        );
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
                    process: None,
                    proxy: None,
                });
                continue;
            }

            let port = free_port().ok_or_else(|| internal("빈 포트를 찾지 못했습니다"))?;
            let mut env = vec![
                ("PORT".to_owned(), port.to_string()),
                ("HOST".to_owned(), "127.0.0.1".to_owned()),
                // 미리보기에서 메일을 보내지 않는 것처럼, 앱이 어디에 섰는지에 따라 달리 굴 일이 있다
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
            let command = service.start.as_deref().unwrap_or_default();
            let failed = |log: &Path| Failure::StartFailed {
                service: service.name.to_string(),
                log: tail(log),
            };
            let mut live = LiveService {
                name: service.name.to_string(),
                kind: service.kind,
                url: url(&service.path),
                process: None,
                proxy,
            };
            let mut process = self
                .runner
                .start(&Job {
                    folder,
                    command,
                    env: &env,
                    log: &log,
                })
                .map_err(|_| failed(&log))?;
            // 포트가 열리기를 기다린다. 그 전에 프로세스가 끝나면 더 기다리지 않는다
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let up = loop {
                if wait_for_port(port, Duration::from_millis(100)) {
                    break process.alive();
                }
                if !process.alive() || std::time::Instant::now() >= deadline {
                    break false;
                }
            };
            live.process = Some(process);
            if !up {
                return Err(failed(&log));
            }
            targets.insert(service.name.to_string(), RouterTarget::Server { port });
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
        // 메일과 Google 은 팩토리의 키로 한다. 미리보기의 router 는 메일을 보내지 않고 Google 의 문이 없다
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
        let router = RouterTask(self.runtime.spawn(serve_router(listener, config)));
        Ok(Launched {
            services,
            router,
            origin,
        })
    }

    /// 씨앗 사용자의 식별자. 미리보기에만 있다.
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

    /// commit 하나의 미리보기를 세운다. 그 commit 에서 직접 빌드하고, 씨앗 데이터만 든 DB 를 새로 만들어 역할과 권한을 세우고, 권한 검사를 돌린다.
    pub fn preview(&self, instance: &InstanceId, commit: Option<Commit>) -> Outcome<PreviewReport> {
        let mut inner = self.lock();
        let record = inner
            .registry
            .state
            .instances
            .get(instance.as_str())
            .cloned()
            .ok_or(Failure::NotFound)?;
        let commit = match commit {
            Some(commit) => commit,
            None => self.sources.head(instance).map_err(internal)?,
        };
        let assembled = self.assembled(instance, &commit)?;
        let folder = self.build(instance, &assembled)?;

        // 앞의 미리보기를 걷는다. 인스턴스마다 미리보기는 하나다
        if let Some(old) = inner
            .live
            .remove(&(instance.as_str().to_owned(), Stage::Preview))
        {
            let names = old.names.clone();
            drop(old);
            inner.admin.destroy(&names).map_err(internal)?;
        }

        let names = Names::new(fresh_id('p')?);
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
        let launched = match self.launch(instance, &assembled, &folder, &stand) {
            Ok(launched) => launched,
            Err(failure) => {
                let _ = inner.admin.destroy(&names);
                return Err(failure);
            }
        };

        // 운영에 아직 돌지 않은 마이그레이션이 있으면 예행연습이 필요하다
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
            },
        );
        inner.registry.save().map_err(Failure::Internal)?;
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
        Ok(report)
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
        // 씨앗 데이터의 SQL 이 씨앗 사용자를 가리킬 수 있게 그 앞에 넣는다. 미리보기에만 들어간다
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

    /// 미리보기에서 씨앗 사용자로 요청해 볼 수 있게 그 사용자의 세션을 만들고, 요청에 그대로 붙일 `Cookie` 머리말의 값을 돌려준다.
    ///
    /// 미리보기의 DB 에만 있는 세션이라 운영에서는 읽히지 않는다. 씨앗 사용자(`db/seed/users.toml`)만 된다.
    pub fn preview_session(&self, instance: &InstanceId, user: &str) -> Outcome<String> {
        let (names, manifest) = {
            let inner = self.lock();
            let live = inner
                .live
                .get(&(instance.as_str().to_owned(), Stage::Preview))
                .ok_or_else(|| {
                    Failure::Conflict(
                        "떠 있는 미리보기가 없습니다. `orbital preview` 로 먼저 세워 주세요"
                            .to_owned(),
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

    /// 미리보기를 걷는다.
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
        Ok(())
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
                "그 release 의 미리보기가 없습니다. `orbital preview` 로 먼저 세워 주세요"
                    .to_owned(),
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
                "그 release 의 미리보기가 없습니다. `orbital preview` 로 먼저 세워 주세요"
                    .to_owned(),
            )
        })?;
        let commit = Commit::parse(&known.commit)
            .ok_or_else(|| internal("release 의 commit 을 읽지 못했습니다"))?;
        let (access_findings, rehearsal) = (known.access_findings, known.rehearsal);
        let organization = record.organization.clone();
        let manifest = self.assembled(instance, &commit)?.manifest;
        let found = blockers(&Release {
            id: ReleaseId(release.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings,
            rehearsal,
            missing_keys: self.missing_keys(&organization, &manifest),
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
        };
        // 승인은 호출에 적힌 release 하나에 묶인다. 승인한 뒤 commit 이 더해졌으면 식별자가 달라 여기서 찾지 못하거나 예행연습이 다시 필요하다
        let approval = Approval {
            release: ReleaseId(release.to_owned()),
            by: approved_by,
        };
        judge_promotion(&facts, change, Some(&approval)).map_err(Failure::Denied)?;

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
                return Err(self.back_out(&mut inner, &prior, point.as_ref(), kind, failure));
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
            .launch(target.instance, assembled, target.folder, &stand)
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
            Aftermath::RollBackCode => {
                self.relaunch(inner, prior, production);
                failure
            }
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
                    self.relaunch(inner, prior, production);
                    return failure;
                }
                Failure::Conflict(
                    "새 release 가 서지 못했고 운영 DB 를 앞의 모습으로 돌리지도 못했습니다. 운영이 내려가 있습니다. 사람이 확인해야 합니다".to_owned(),
                )
            }
        }
    }

    /// 앞의 release 의 서버를 다시 띄운다.
    fn relaunch(&self, inner: &mut Inner, prior: &Prior<'_>, production: &ProductionRecord) {
        let previous = prior
            .record
            .releases
            .get(&production.release)
            .and_then(|release| Commit::parse(&release.commit))
            .and_then(|commit| self.assembled(prior.instance, &commit).ok());
        let Some(assembled) = previous else {
            return;
        };
        let Ok(folder) = self.build(prior.instance, &assembled) else {
            return;
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
        if let Ok(launched) = self.launch(prior.instance, &assembled, &folder, &stand) {
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
        Ok(Some(PendingPromotion {
            release,
            commit: commit.to_string(),
            changes: changes(&before, &assembled.access)
                .into_iter()
                .map(|change| change.sentence)
                .collect(),
            migrations,
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
