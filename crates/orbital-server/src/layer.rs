//! 레이어의 동작. 인스턴스를 세우고, 코드를 받고, 그 commit 에서 직접 빌드해 미리보기를 세우고, 승인받은 release 를 운영에 올린다.
//!
//! 판정은 core 가 한다(토큰의 범위, 권한 검사, 승격의 규칙). 여기서는 부품을 순서대로 부르고, 중간에 깨지면 앞의 모습으로 돌린다.
//! 서버가 하나일 때의 모양이라 일을 하나씩 차례로 한다(자물쇠 하나).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orbital_core::access::Access;
use orbital_core::check::judge as judge_access;
use orbital_core::describe::changes;
use orbital_core::manifest::ServiceKind;
use orbital_core::name::{Ident, InstanceId};
use orbital_core::plan::Names;
use orbital_core::release::{
    Aftermath, Approval, Approver, BuiltBy, Change, Migrations, PromoteDenied, Rehearsed, Release,
    ReleaseId, after_promotion, blockers, promote as judge_promotion,
};
use orbital_core::scope::{
    Action, Capability, DenyReason, OrganizationId, Request, Token, Verdict, judge,
};
use orbital_pg::Admin;
use orbital_pg::identity::{Claims, sign as sign_identity};
use orbital_pg::rehearsal::RestorePoint;
use orbital_proxy::{Route, serve};
use orbital_run::{Job, Runner, Running, free_port, wait_for_port};
use orbital_source::assemble::{AssembleError, Assembled, assemble};
use orbital_source::{Commit, Error as SourceError, SourceStore, receive_scaffold};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::registry::{InstanceRecord, ProductionRecord, Registry, ReleaseRecord};
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
    port: Option<u16>,
    process: Option<Box<dyn Running>>,
    proxy: Option<JoinHandle<std::io::Result<()>>>,
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

/// 떠 있는 것 하나(미리보기이거나 운영).
struct Live {
    release: String,
    names: Names,
    identity_key: Vec<u8>,
    services: Vec<LiveService>,
}

/// 운영에 올리려는 release 하나와 그것이 설 자리.
struct Target<'a> {
    instance: &'a InstanceId,
    assembled: &'a Assembled,
    folder: &'a Path,
    names: &'a Names,
    generated: &'a BTreeMap<String, String>,
}

/// 승격이 깨지기 앞의 운영.
struct Prior<'a> {
    instance: &'a InstanceId,
    record: &'a InstanceRecord,
    names: &'a Names,
}

/// 띄운 서비스와, 돌린 마이그레이션의 이름.
type Raised = (Vec<LiveService>, Vec<String>);
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
    /// 서버 서비스가 요청을 받는 주소.
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

pub struct Options {
    /// 레이어가 저장소 · 빌드 · 기록을 두는 폴더.
    pub home: PathBuf,
    /// DB 의 관리 주소.
    pub pg_url: String,
    /// (service key, 조직). 팩토리의 서버가 쓴다.
    pub service_keys: Vec<(String, String)>,
    pub runner: Box<dyn Runner>,
}

pub struct Layer {
    home: PathBuf,
    upstream: String,
    sources: SourceStore,
    runner: Box<dyn Runner>,
    runtime: Runtime,
    token_key: Vec<u8>,
    service_keys: Vec<([u8; 32], String)>,
    inner: Mutex<Inner>,
}

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
    }
}

impl Layer {
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

        Ok(Self {
            sources: SourceStore::new(options.home.join("sources")),
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
    fn launch(
        &self,
        instance: &InstanceId,
        assembled: &Assembled,
        folder: &Path,
        names: &Names,
        generated: &BTreeMap<String, String>,
        stage: Stage,
    ) -> Outcome<Vec<LiveService>> {
        let mut services = Vec::new();
        for service in &assembled.manifest.get().services {
            if service.kind == ServiceKind::Static {
                let output = folder.join(service.output.as_deref().unwrap_or_default());
                if !output.is_dir() {
                    return Err(Failure::StartFailed {
                        service: service.name.to_string(),
                        log: "빌드 결과의 폴더(`output`)가 없습니다. 빌드 명령이 그 폴더를 만드는지 확인해 주세요".to_owned(),
                    });
                }
                services.push(LiveService {
                    name: service.name.to_string(),
                    kind: service.kind,
                    port: None,
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
                port: Some(port),
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
            services.push(live);
        }
        Ok(services)
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
                url: service.port.map(|port| format!("http://127.0.0.1:{port}")),
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
        let services = match self.launch(
            instance,
            &assembled,
            &folder,
            &names,
            &Self::secrets(&assembled)?,
            Stage::Preview,
        ) {
            Ok(services) => services,
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
            services: Self::report(&services),
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
            })
            .iter()
            .map(blocker_text)
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
                names,
                identity_key,
                services,
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

    /// 미리보기에서 씨앗 데이터의 사람으로 요청해 볼 수 있게 신원에 서명해 준다. 미리보기의 열쇠라 운영에서는 읽히지 않는다.
    pub fn preview_identity(&self, instance: &InstanceId, subject: &str) -> Outcome<String> {
        let inner = self.lock();
        let live = inner
            .live
            .get(&(instance.as_str().to_owned(), Stage::Preview))
            .ok_or_else(|| {
                Failure::Conflict(
                    "떠 있는 미리보기가 없습니다. `orbital preview` 로 먼저 세워 주세요".to_owned(),
                )
            })?;
        Ok(sign_identity(
            &live.identity_key,
            &live.names,
            &Claims {
                subject: subject.to_owned(),
                expires_at: now() + 3600,
            },
        ))
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
        let found = blockers(&Release {
            id: ReleaseId(release.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings: known.access_findings,
            rehearsal: known.rehearsal,
        });
        if !found.is_empty() {
            return Err(Failure::Denied(PromoteDenied::Blocked { blockers: found }));
        }
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
        let facts = Release {
            id: ReleaseId(release.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings: known.access_findings,
            rehearsal: known.rehearsal,
        };
        // 승인은 호출에 적힌 release 하나에 묶인다. 승인한 뒤 commit 이 더해졌으면 식별자가 달라 여기서 찾지 못하거나 예행연습이 다시 필요하다
        let approval = Approval {
            release: ReleaseId(release.to_owned()),
            by: approved_by,
        };
        judge_promotion(&facts, change, Some(&approval)).map_err(Failure::Denied)?;

        let commit = Commit::parse(&known.commit)
            .ok_or_else(|| internal("release 의 commit 을 읽지 못했습니다"))?;
        let assembled = self.assembled(instance, &commit)?;
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
        };
        let outcome = self.promote_onto(&mut inner, &target, &scripts);
        let (services, ran) = match outcome {
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
            services: Self::report(&services),
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
                names,
                identity_key,
                services,
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
        let services = self
            .launch(
                target.instance,
                assembled,
                target.folder,
                names,
                target.generated,
                Stage::Production,
            )
            .map_err(|failure| (failure, migrated))?;
        Ok((services, ran))
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
        if let Ok(services) = self.launch(
            prior.instance,
            &assembled,
            &folder,
            prior.names,
            &production.generated,
            Stage::Production,
        ) {
            let identity_key = token::unhex(&production.identity_key).unwrap_or_default();
            inner.live.insert(
                (prior.instance.as_str().to_owned(), Stage::Production),
                Live {
                    release: production.release.clone(),
                    names: prior.names.clone(),
                    identity_key,
                    services,
                },
            );
        }
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

    /// 운영에서 로그인한 사람의 신원에 서명한다. 로그인을 확인한 router 가 부를 자리이고, 지금은 팩토리의 서버가 부른다.
    pub fn production_identity(
        &self,
        organization: &str,
        instance: &InstanceId,
        subject: &str,
    ) -> Outcome<String> {
        let mut inner = self.lock();
        Self::owned(&mut inner, organization, instance)?;
        let live = inner
            .live
            .get(&(instance.as_str().to_owned(), Stage::Production))
            .ok_or(Failure::NotFound)?;
        Ok(sign_identity(
            &live.identity_key,
            &live.names,
            &Claims {
                subject: subject.to_owned(),
                expires_at: now() + 3600,
            },
        ))
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
