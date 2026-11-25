//! 선언 파일(`orbital.toml`)의 모양과 검증.
//!
//! 앱은 필요한 것의 이름만 적는다. 값(비밀번호 · 키 · 주소)은 적지 않고 레이어가 만들어 잇는다.
//! 읽어 들인 [`Manifest`] 는 아직 믿을 수 없고, [`Manifest::check`] 를 지난 [`ValidManifest`] 만 계획과 검사에 쓴다.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::name::{Ident, SecretName};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default, rename = "service")]
    pub services: Vec<Service>,
    #[serde(default, rename = "schedule")]
    pub schedules: Vec<Schedule>,
    #[serde(default)]
    pub database: Database,
    #[serde(default)]
    pub secrets: Secrets,
    /// 레이어가 운영하는 로그인(Orbital Auth). 없으면 레이어는 로그인에 관여하지 않는다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// 요청을 받는 서버. 쉬면 재운다.
    Server,
    /// 빌드한 파일을 router 가 바로 내준다. 서버가 없고 DB 에 닿지 않는다.
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: Ident,
    pub kind: ServiceKind,
    pub build: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// 이 경로로 온 요청을 받는다. `/` 로 시작한다.
    pub path: String,
    /// 이 서비스가 쓸 수 있는 업무 역할. 여기에 없는 역할로는 DB 에 들어가지 못한다.
    #[serde(default)]
    pub roles: Vec<Ident>,
    /// 로그인한 사람만 들어오는가. 기본은 누구나 들어오고, 로그인했다면 신원이 함께 넘어간다.
    #[serde(default, skip_serializing_if = "ServiceAuth::is_optional")]
    pub auth: ServiceAuth,
}

/// 서비스가 로그인을 요구하는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAuth {
    /// 로그인한 사람만 들어온다. 아니면 `[auth].login_path` 로 보낸다.
    Required,
    /// 누구나 들어온다.
    #[default]
    Optional,
}

impl ServiceAuth {
    pub fn is_optional(&self) -> bool {
        *self == Self::Optional
    }
}

/// 레이어가 운영하는 로그인의 선언. 화면은 앱이 그리고, 레이어는 뒤쪽(사용자 · 초대 · 링크 · 세션)만 맡는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// 로그인 방법. 지금은 `email_link` 만 받는다. 모르는 값은 [`Manifest::check`] 가 고칠 것으로 돌려준다.
    pub methods: Vec<String>,
    /// 앱의 로그인 화면. 어느 서비스의 `path` 아래여야 한다.
    pub login_path: String,
    #[serde(default)]
    pub signup: Signup,
    /// 초대 없이 들어온 사람이 처음 갖는 업무 역할. `signup = "open"` 일 때만 적는다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_roles: Vec<Ident>,
    /// 다른 사용자의 이름과 이메일(`orbital.users`)을 읽는 업무 역할.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory: Vec<Ident>,
    /// MCP 의 주소와 그 인가(OAuth 2.1). 없으면 인가 서버의 주소가 없다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<Mcp>,
}

/// MCP 의 주소. router 가 자원 서버의 자리를, Orbital Auth 가 인가 서버의 자리를 맡는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mcp {
    /// MCP 주소가 있는 서버 서비스.
    pub service: Ident,
    /// MCP 요청의 경로. 그 서비스의 `path` 아래여야 한다.
    pub path: String,
    /// 앱의 동의 화면. 어느 서비스의 `path` 아래여야 한다.
    pub consent_path: String,
    /// 동적 등록(RFC 7591)을 받는가. 기본은 받는다.
    #[serde(default = "yes")]
    pub dynamic_registration: bool,
}

fn yes() -> bool {
    true
}

impl Auth {
    /// 레이어가 아는 로그인 방법.
    pub const METHODS: [&'static str; 1] = ["email_link"];
}

/// 누가 들어올 수 있는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signup {
    /// 초대받은 이메일만.
    #[default]
    Invite,
    /// 누구나. 처음 들어오면 `default_roles` 를 갖는다.
    Open,
}

/// 레이어가 쓰는 경로의 머리. 서비스와 로그인 화면은 이 아래에 둘 수 없다.
pub const LAYER_PATH: &str = "/_orbital";
/// 인가 서버와 자원 서버의 메타데이터가 서는 경로의 머리. 서비스와 화면의 경로로 적지 못한다.
pub const WELL_KNOWN_PATH: &str = "/.well-known";

impl Service {
    /// 서비스 이름의 길이. 서비스마다의 로그인 이름이 Postgres 의 63바이트 한도 안에 들어야 한다.
    pub const NAME_MAX: usize = 16;
}

/// 서버가 자는 동안에도 레이어가 정한 시각에 깨워 부르는 일.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub service: Ident,
    pub cron: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    #[serde(default)]
    pub schemas: Vec<Ident>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrations: Option<String>,
    /// 업무 역할. 권한은 권한 표가 정한다.
    #[serde(default)]
    pub roles: Vec<Ident>,
    /// 미리보기 DB 에 넣을 가짜 데이터.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    /// 레이어가 만든다. 아무도 보지 못한다.
    #[serde(default)]
    pub generated: Vec<SecretName>,
    /// 사람이 입력 화면에서 한 번 넣는다. 에이전트는 이름만 본다.
    #[serde(default)]
    pub external: Vec<SecretName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ManifestProblem {
    NoService,
    DuplicateService { service: Ident },
    ServiceNameTooLong { service: Ident },
    ServerNeedsStart { service: Ident },
    StaticNeedsOutput { service: Ident },
    StaticHasRoles { service: Ident },
    PathNotAbsolute { service: Ident },
    DuplicatePath { path: String },
    UndeclaredRole { service: Ident, role: Ident },
    DuplicateRole { role: Ident },
    DuplicateSchema { schema: Ident },
    RolesWithoutSchema,
    ScheduleUnknownService { service: Ident },
    ScheduleNotServer { service: Ident },
    SchedulePathOutsideService { service: Ident, path: String },
    ScheduleBadCron { cron: String },
    DuplicateSecret { secret: SecretName },
    AuthRequiredWithoutAuth { service: Ident },
    AuthNoMethod,
    AuthUnknownMethod { method: String },
    LoginPathOutsideServices { path: String },
    LayerPath { path: String },
    DirectoryUndeclaredRole { role: Ident },
    DefaultRoleUndeclared { role: Ident },
    OpenSignupWithoutDefaultRoles,
    DefaultRolesWithoutOpenSignup,
    McpUnknownService { service: Ident },
    McpNotServer { service: Ident },
    McpPathOutsideService { path: String },
    ConsentPathOutsideServices { path: String },
}

impl fmt::Display for ManifestProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoService => write!(
                f,
                "서비스가 하나도 없습니다. `[[service]]` 를 하나 이상 적어 주세요"
            ),
            Self::DuplicateService { service } => {
                write!(f, "서비스 `{service}` 가 두 번 적혀 있습니다")
            }
            Self::ServiceNameTooLong { service } => {
                write!(
                    f,
                    "서비스 이름 `{service}` 이 깁니다. {}자까지입니다",
                    Service::NAME_MAX
                )
            }
            Self::ServerNeedsStart { service } => {
                write!(
                    f,
                    "서버 서비스 `{service}` 에 실행 명령(`start`)이 없습니다"
                )
            }
            Self::StaticNeedsOutput { service } => {
                write!(
                    f,
                    "정적 서비스 `{service}` 에 빌드 결과의 폴더(`output`)가 없습니다"
                )
            }
            Self::StaticHasRoles { service } => {
                write!(
                    f,
                    "정적 서비스 `{service}` 는 DB 에 닿지 않으므로 `roles` 를 적을 수 없습니다"
                )
            }
            Self::PathNotAbsolute { service } => {
                write!(f, "서비스 `{service}` 의 경로는 `/` 로 시작해야 합니다")
            }
            Self::DuplicatePath { path } => write!(f, "경로 `{path}` 를 두 서비스가 함께 받습니다"),
            Self::UndeclaredRole { service, role } => write!(
                f,
                "서비스 `{service}` 가 쓰는 역할 `{role}` 이 `[database].roles` 에 없습니다"
            ),
            Self::DuplicateRole { role } => write!(f, "역할 `{role}` 이 두 번 적혀 있습니다"),
            Self::DuplicateSchema { schema } => {
                write!(f, "스키마 `{schema}` 가 두 번 적혀 있습니다")
            }
            Self::RolesWithoutSchema => write!(
                f,
                "역할을 선언했지만 스키마가 없습니다. `[database].schemas` 를 적어 주세요"
            ),
            Self::ScheduleUnknownService { service } => {
                write!(f, "일정이 가리키는 서비스 `{service}` 가 없습니다")
            }
            Self::ScheduleNotServer { service } => {
                write!(
                    f,
                    "일정은 서버 서비스만 부를 수 있습니다. `{service}` 는 정적 서비스입니다"
                )
            }
            Self::SchedulePathOutsideService { service, path } => {
                write!(
                    f,
                    "일정의 경로 `{path}` 가 서비스 `{service}` 의 경로 아래가 아닙니다"
                )
            }
            Self::ScheduleBadCron { cron } => {
                write!(f, "일정 `{cron}` 은 다섯 칸의 cron 식이어야 합니다")
            }
            Self::DuplicateSecret { secret } => write!(
                f,
                "비밀 `{secret}` 이 두 번 적혀 있습니다",
                secret = secret.as_str()
            ),
            Self::AuthRequiredWithoutAuth { service } => write!(
                f,
                "서비스 `{service}` 가 로그인을 요구하지만 `[auth]` 가 없습니다. `[auth]` 를 적거나 `auth = \"optional\"` 로 바꿔 주세요"
            ),
            Self::AuthNoMethod => write!(
                f,
                "`[auth].methods` 가 비어 있습니다. `methods = [\"email_link\"]` 처럼 하나 이상 적어 주세요"
            ),
            Self::AuthUnknownMethod { method } => write!(
                f,
                "로그인 방법 `{method}` 은 모르는 값입니다. 받는 값은 {} 입니다",
                Auth::METHODS.join(", ")
            ),
            Self::LoginPathOutsideServices { path } => write!(
                f,
                "로그인 화면 `{path}` 가 어느 서비스의 경로 아래도 아닙니다. 로그인 화면을 그리는 서비스의 `path` 아래로 적어 주세요"
            ),
            Self::LayerPath { path } => write!(
                f,
                "경로 `{path}` 는 `{LAYER_PATH}` 나 `{WELL_KNOWN_PATH}` 로 시작합니다. 레이어가 쓰는 경로이니 다른 경로로 바꿔 주세요"
            ),
            Self::McpUnknownService { service } => write!(
                f,
                "`[auth.mcp].service` 의 서비스 `{service}` 가 없습니다. MCP 주소가 있는 서버 서비스의 이름을 적어 주세요"
            ),
            Self::McpNotServer { service } => write!(
                f,
                "`[auth.mcp].service` 의 `{service}` 는 정적 서비스입니다. MCP 주소는 서버 서비스에 둬야 합니다"
            ),
            Self::McpPathOutsideService { path } => write!(
                f,
                "`[auth.mcp].path` 의 `{path}` 가 그 서비스의 `path` 아래가 아닙니다. 서비스의 경로 아래로 적어 주세요"
            ),
            Self::ConsentPathOutsideServices { path } => write!(
                f,
                "`[auth.mcp].consent_path` 의 `{path}` 가 어느 서비스의 경로 아래도 아닙니다. 동의 화면을 그리는 서비스의 `path` 아래로 적어 주세요"
            ),
            Self::DirectoryUndeclaredRole { role } => write!(
                f,
                "`[auth].directory` 의 역할 `{role}` 이 `[database].roles` 에 없습니다. 선언한 업무 역할만 적어 주세요"
            ),
            Self::DefaultRoleUndeclared { role } => write!(
                f,
                "`[auth].default_roles` 의 역할 `{role}` 이 `[database].roles` 에 없습니다. 선언한 업무 역할만 적어 주세요"
            ),
            Self::OpenSignupWithoutDefaultRoles => write!(
                f,
                "`signup = \"open\"` 이면 처음 들어온 사람이 가질 역할이 있어야 합니다. `[auth].default_roles` 를 적어 주세요"
            ),
            Self::DefaultRolesWithoutOpenSignup => write!(
                f,
                "`[auth].default_roles` 는 `signup = \"open\"` 일 때만 씁니다. 초대받은 사람은 초대의 역할을 갖습니다. `default_roles` 를 지우거나 `signup = \"open\"` 으로 바꿔 주세요"
            ),
        }
    }
}

/// 검증을 지난 선언. 계획과 검사는 이 타입만 받는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ValidManifest(Manifest);

impl ValidManifest {
    pub fn get(&self) -> &Manifest {
        &self.0
    }

    /// 서비스가 그 역할로 DB 에 들어갈 수 있는가.
    pub fn service_may_use(&self, service: &Ident, role: &Ident) -> bool {
        self.0
            .services
            .iter()
            .any(|candidate| &candidate.name == service && candidate.roles.contains(role))
    }
}

impl Manifest {
    /// 선언이 서로 맞는지 본다. 문제를 하나만이 아니라 모두 돌려준다. 에이전트가 한 번에 고치게 하려는 것이다.
    pub fn check(self) -> Result<ValidManifest, Vec<ManifestProblem>> {
        let mut problems = Vec::new();

        if self.services.is_empty() {
            problems.push(ManifestProblem::NoService);
        }

        let mut schemas = BTreeSet::new();
        for schema in &self.database.schemas {
            if !schemas.insert(schema) {
                problems.push(ManifestProblem::DuplicateSchema {
                    schema: schema.clone(),
                });
            }
        }

        let mut roles = BTreeSet::new();
        for role in &self.database.roles {
            if !roles.insert(role) {
                problems.push(ManifestProblem::DuplicateRole { role: role.clone() });
            }
        }
        if !roles.is_empty() && schemas.is_empty() {
            problems.push(ManifestProblem::RolesWithoutSchema);
        }

        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for service in &self.services {
            if !names.insert(&service.name) {
                problems.push(ManifestProblem::DuplicateService {
                    service: service.name.clone(),
                });
            }
            if service.name.as_str().len() > Service::NAME_MAX {
                problems.push(ManifestProblem::ServiceNameTooLong {
                    service: service.name.clone(),
                });
            }
            if is_layer_path(&service.path) {
                problems.push(ManifestProblem::LayerPath {
                    path: service.path.clone(),
                });
            }
            if service.auth == ServiceAuth::Required && self.auth.is_none() {
                problems.push(ManifestProblem::AuthRequiredWithoutAuth {
                    service: service.name.clone(),
                });
            }
            if !service.path.starts_with('/') {
                problems.push(ManifestProblem::PathNotAbsolute {
                    service: service.name.clone(),
                });
            } else if !paths.insert(trim_path(&service.path)) {
                problems.push(ManifestProblem::DuplicatePath {
                    path: service.path.clone(),
                });
            }
            match service.kind {
                ServiceKind::Server => {
                    if service.start.as_deref().is_none_or(str::is_empty) {
                        problems.push(ManifestProblem::ServerNeedsStart {
                            service: service.name.clone(),
                        });
                    }
                }
                ServiceKind::Static => {
                    if service.output.as_deref().is_none_or(str::is_empty) {
                        problems.push(ManifestProblem::StaticNeedsOutput {
                            service: service.name.clone(),
                        });
                    }
                    if !service.roles.is_empty() {
                        problems.push(ManifestProblem::StaticHasRoles {
                            service: service.name.clone(),
                        });
                    }
                }
            }
            for role in &service.roles {
                if !roles.contains(role) {
                    problems.push(ManifestProblem::UndeclaredRole {
                        service: service.name.clone(),
                        role: role.clone(),
                    });
                }
            }
        }

        for schedule in &self.schedules {
            match self
                .services
                .iter()
                .find(|service| service.name == schedule.service)
            {
                None => problems.push(ManifestProblem::ScheduleUnknownService {
                    service: schedule.service.clone(),
                }),
                Some(service) if service.kind != ServiceKind::Server => {
                    problems.push(ManifestProblem::ScheduleNotServer {
                        service: schedule.service.clone(),
                    });
                }
                Some(service) => {
                    if !under(&schedule.path, &service.path) {
                        problems.push(ManifestProblem::SchedulePathOutsideService {
                            service: schedule.service.clone(),
                            path: schedule.path.clone(),
                        });
                    }
                }
            }
            if schedule.cron.split_whitespace().count() != 5 {
                problems.push(ManifestProblem::ScheduleBadCron {
                    cron: schedule.cron.clone(),
                });
            }
        }

        let mut secrets = BTreeSet::new();
        for secret in self.secrets.generated.iter().chain(&self.secrets.external) {
            if !secrets.insert(secret) {
                problems.push(ManifestProblem::DuplicateSecret {
                    secret: secret.clone(),
                });
            }
        }

        if let Some(auth) = &self.auth {
            if auth.methods.is_empty() {
                problems.push(ManifestProblem::AuthNoMethod);
            }
            for method in &auth.methods {
                if !Auth::METHODS.contains(&method.as_str()) {
                    problems.push(ManifestProblem::AuthUnknownMethod {
                        method: method.clone(),
                    });
                }
            }
            if is_layer_path(&auth.login_path) {
                problems.push(ManifestProblem::LayerPath {
                    path: auth.login_path.clone(),
                });
            } else if !self
                .services
                .iter()
                .any(|service| under(&auth.login_path, &service.path))
            {
                problems.push(ManifestProblem::LoginPathOutsideServices {
                    path: auth.login_path.clone(),
                });
            }
            for role in &auth.directory {
                if !roles.contains(role) {
                    problems.push(ManifestProblem::DirectoryUndeclaredRole { role: role.clone() });
                }
            }
            for role in &auth.default_roles {
                if !roles.contains(role) {
                    problems.push(ManifestProblem::DefaultRoleUndeclared { role: role.clone() });
                }
            }
            match auth.signup {
                Signup::Open if auth.default_roles.is_empty() => {
                    problems.push(ManifestProblem::OpenSignupWithoutDefaultRoles);
                }
                Signup::Invite if !auth.default_roles.is_empty() => {
                    problems.push(ManifestProblem::DefaultRolesWithoutOpenSignup);
                }
                _ => {}
            }
            if let Some(mcp) = &auth.mcp {
                match self
                    .services
                    .iter()
                    .find(|service| service.name == mcp.service)
                {
                    None => problems.push(ManifestProblem::McpUnknownService {
                        service: mcp.service.clone(),
                    }),
                    Some(service) if service.kind != ServiceKind::Server => {
                        problems.push(ManifestProblem::McpNotServer {
                            service: mcp.service.clone(),
                        });
                    }
                    Some(service) => {
                        if is_layer_path(&mcp.path) {
                            problems.push(ManifestProblem::LayerPath {
                                path: mcp.path.clone(),
                            });
                        } else if !under(&mcp.path, &service.path) {
                            problems.push(ManifestProblem::McpPathOutsideService {
                                path: mcp.path.clone(),
                            });
                        }
                    }
                }
                if is_layer_path(&mcp.consent_path) {
                    problems.push(ManifestProblem::LayerPath {
                        path: mcp.consent_path.clone(),
                    });
                } else if !self
                    .services
                    .iter()
                    .any(|service| under(&mcp.consent_path, &service.path))
                {
                    problems.push(ManifestProblem::ConsentPathOutsideServices {
                        path: mcp.consent_path.clone(),
                    });
                }
            }
        }

        if problems.is_empty() {
            Ok(ValidManifest(self))
        } else {
            Err(problems)
        }
    }
}

/// 레이어가 쓰는 경로인가. 조각의 경계를 따지지 않고 글자로 본다(`/_orbitalx` 도 받지 않는다). 넓게 막는 편이 안전하다.
fn is_layer_path(path: &str) -> bool {
    path.starts_with(LAYER_PATH) || path.starts_with(WELL_KNOWN_PATH)
}

pub(crate) fn trim_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

/// `path` 가 `base` 와 같거나 그 아래인가. 조각의 경계로 본다(`/api` 는 `/apiary` 의 위가 아니다).
pub(crate) fn under(path: &str, base: &str) -> bool {
    let base = trim_path(base);
    if base == "/" {
        return path.starts_with('/');
    }
    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NestJS + Vite 스캐폴드의 선언. 기획안 5절의 예와 같다.
    pub(crate) const NEST_VITE: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build -w api"
start = "npm run start -w api"
path = "/api"
roles = ["employee", "manager", "payroll_admin"]

[[service]]
name = "web"
kind = "static"
build = "npm run build -w web"
output = "web/dist"
path = "/"

[[schedule]]
service = "api"
cron = "0 9 25 * *"
path = "/api/jobs/payroll"

[database]
schemas = ["hr", "payroll", "audit"]
migrations = "db/migrations"
roles = ["employee", "manager", "payroll_admin"]
seed = "db/seed"

[secrets]
generated = ["SESSION_KEY"]
external = ["BANK_API_KEY"]
"#;

    fn parse(text: &str) -> Manifest {
        toml::from_str(text).expect("선언 파일을 읽지 못했습니다")
    }

    fn problems(text: &str) -> Vec<ManifestProblem> {
        parse(text).check().expect_err("문제가 있어야 합니다")
    }

    fn ident(text: &str) -> Ident {
        Ident::parse(text).unwrap()
    }

    #[test]
    fn 서버_하나와_정적_하나를_적은_선언을_받는다() {
        let manifest = parse(NEST_VITE).check().expect("받아야 합니다");
        assert_eq!(manifest.get().services.len(), 2);
    }

    #[test]
    fn next_풀스택은_서버_서비스_하나만_적는다() {
        let text = r#"
[[service]]
name = "web"
kind = "server"
build = "npm run build"
start = "npm run start"
path = "/"
"#;
        assert!(parse(text).check().is_ok());
    }

    #[test]
    fn 서비스가_없는_선언은_받지_않는다() {
        assert_eq!(problems(""), vec![ManifestProblem::NoService]);
    }

    #[test]
    fn 모르는_칸이_있으면_읽지_않는다() {
        let text = NEST_VITE.replace("seed = \"db/seed\"", "password = \"hunter2\"");
        assert!(toml::from_str::<Manifest>(&text).is_err());
    }

    #[test]
    fn 서버_서비스에는_실행_명령이_있어야_한다() {
        let text = NEST_VITE.replace("start = \"npm run start -w api\"\n", "");
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::ServerNeedsStart {
                service: ident("api")
            }]
        );
    }

    #[test]
    fn 정적_서비스에는_빌드_결과의_폴더가_있어야_한다() {
        let text = NEST_VITE.replace("output = \"web/dist\"\n", "");
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::StaticNeedsOutput {
                service: ident("web")
            }]
        );
    }

    #[test]
    fn 정적_서비스는_업무_역할을_갖지_못한다() {
        let text = NEST_VITE.replace(
            "output = \"web/dist\"",
            "output = \"web/dist\"\nroles = [\"employee\"]",
        );
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::StaticHasRoles {
                service: ident("web")
            }]
        );
    }

    #[test]
    fn 서비스가_쓰는_역할은_database_에_선언되어_있어야_한다() {
        let text = NEST_VITE.replacen(
            "roles = [\"employee\", \"manager\", \"payroll_admin\"]",
            "roles = [\"employee\", \"auditor\"]",
            1,
        );
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::UndeclaredRole {
                service: ident("api"),
                role: ident("auditor")
            }]
        );
    }

    #[test]
    fn 서비스에_적지_않은_역할로는_그_서비스가_db_에_들어가지_못한다() {
        let text = NEST_VITE.replacen(
            "roles = [\"employee\", \"manager\", \"payroll_admin\"]",
            "roles = [\"employee\"]",
            1,
        );
        let manifest = parse(&text).check().unwrap();
        assert!(manifest.service_may_use(&ident("api"), &ident("employee")));
        assert!(!manifest.service_may_use(&ident("api"), &ident("payroll_admin")));
        assert!(!manifest.service_may_use(&ident("web"), &ident("employee")));
    }

    #[test]
    fn 같은_이름의_서비스와_같은_경로는_받지_않는다() {
        let text = NEST_VITE
            .replace("name = \"web\"", "name = \"api\"")
            .replace("path = \"/\"", "path = \"/api/\"");
        let found = problems(&text);
        assert!(found.contains(&ManifestProblem::DuplicateService {
            service: ident("api")
        }));
        assert!(found.contains(&ManifestProblem::DuplicatePath {
            path: "/api/".to_owned()
        }));
    }

    #[test]
    fn 서비스_이름은_16자까지_받고_17자는_받지_않는다() {
        let ok = NEST_VITE.replace("name = \"web\"", &format!("name = \"{}\"", "w".repeat(16)));
        assert!(parse(&ok).check().is_ok());
        let long = "w".repeat(17);
        let bad = NEST_VITE.replace("name = \"web\"", &format!("name = \"{long}\""));
        assert_eq!(
            problems(&bad),
            vec![ManifestProblem::ServiceNameTooLong {
                service: ident(&long)
            }]
        );
    }

    #[test]
    fn 일정은_서버_서비스의_경로_아래만_부른다() {
        let outside = NEST_VITE.replace("path = \"/api/jobs/payroll\"", "path = \"/apiary/jobs\"");
        assert_eq!(
            problems(&outside),
            vec![ManifestProblem::SchedulePathOutsideService {
                service: ident("api"),
                path: "/apiary/jobs".to_owned()
            }]
        );
        let to_static = NEST_VITE.replace("service = \"api\"", "service = \"web\"");
        assert_eq!(
            problems(&to_static),
            vec![ManifestProblem::ScheduleNotServer {
                service: ident("web")
            }]
        );
        let unknown = NEST_VITE.replace("service = \"api\"", "service = \"worker\"");
        assert_eq!(
            problems(&unknown),
            vec![ManifestProblem::ScheduleUnknownService {
                service: ident("worker")
            }]
        );
    }

    #[test]
    fn 일정은_다섯_칸의_cron_식이어야_한다() {
        let text = NEST_VITE.replace("cron = \"0 9 25 * *\"", "cron = \"every month\"");
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::ScheduleBadCron {
                cron: "every month".to_owned()
            }]
        );
    }

    #[test]
    fn 같은_비밀을_만드는_것과_넣는_것에_함께_적지_못한다() {
        let text = NEST_VITE.replace(
            "external = [\"BANK_API_KEY\"]",
            "external = [\"SESSION_KEY\"]",
        );
        assert_eq!(
            problems(&text),
            vec![ManifestProblem::DuplicateSecret {
                secret: SecretName::parse("SESSION_KEY").unwrap()
            }]
        );
    }

    #[test]
    fn 선언에는_값을_적을_자리가_없다() {
        // 비밀은 이름의 목록이다. 표(`KEY = "값"`)로 적으면 읽지 않는다.
        let text = NEST_VITE.replace(
            "external = [\"BANK_API_KEY\"]",
            "external = { BANK_API_KEY = \"sk-live-123\" }",
        );
        assert!(toml::from_str::<Manifest>(&text).is_err());
    }

    /// 로그인을 레이어에 맡긴 선언. web 이 로그인 화면을 그린다.
    pub(crate) const WITH_AUTH: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build -w api"
start = "npm run start -w api"
path = "/api"
roles = ["member", "manager"]
auth = "required"

[[service]]
name = "web"
kind = "static"
build = "npm run build -w web"
output = "web/dist"
path = "/"

[database]
schemas = ["app"]
roles = ["member", "manager"]

[auth]
methods = ["email_link"]
login_path = "/login"
directory = ["manager"]
"#;

    #[test]
    fn 로그인을_레이어에_맡긴_선언을_받는다() {
        let manifest = parse(WITH_AUTH).check().expect("받아야 합니다");
        let auth = manifest.get().auth.as_ref().unwrap();
        assert_eq!(auth.signup, Signup::Invite);
        assert_eq!(manifest.get().services[0].auth, ServiceAuth::Required);
        assert_eq!(manifest.get().services[1].auth, ServiceAuth::Optional);
    }

    #[test]
    fn auth_를_적지_않은_선언의_json_모양은_그대로다() {
        let manifest = parse(NEST_VITE).check().unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("auth"), "{json}");
    }

    #[test]
    fn 로그인이_필요한_서비스가_있는데_auth_가_없으면_고칠_것으로_돌려준다() {
        let text = WITH_AUTH.split("[auth]").next().unwrap();
        assert_eq!(
            problems(text),
            vec![ManifestProblem::AuthRequiredWithoutAuth {
                service: ident("api")
            }]
        );
        // 로그인을 요구하지 않으면 [auth] 가 없어도 된다
        assert!(
            parse(&text.replace("auth = \"required\"\n", ""))
                .check()
                .is_ok()
        );
    }

    #[test]
    fn login_path_가_어느_서비스의_path_아래도_아니면_고칠_것으로_돌려준다() {
        // web 을 /app 으로 옮기면 /login 은 어느 서비스의 아래도 아니다
        let moved = WITH_AUTH.replace("path = \"/\"\n", "path = \"/app\"\n");
        assert_eq!(
            problems(&moved),
            vec![ManifestProblem::LoginPathOutsideServices {
                path: "/login".to_owned()
            }]
        );
        // 조각의 경계로 본다. /apix 는 /api 의 아래가 아니다
        let edge = moved.replace("login_path = \"/login\"", "login_path = \"/apix/login\"");
        assert_eq!(
            problems(&edge),
            vec![ManifestProblem::LoginPathOutsideServices {
                path: "/apix/login".to_owned()
            }]
        );
        let inside = moved.replace("login_path = \"/login\"", "login_path = \"/app/login\"");
        assert!(parse(&inside).check().is_ok());
        let exact = moved.replace("login_path = \"/login\"", "login_path = \"/app\"");
        assert!(parse(&exact).check().is_ok());
    }

    #[test]
    fn directory_와_default_roles_에_선언에_없는_업무_역할을_적으면_고칠_것으로_돌려준다() {
        let text = WITH_AUTH
            .replace("directory = [\"manager\"]", "directory = [\"auditor\"]")
            .replace(
                "login_path = \"/login\"",
                "login_path = \"/login\"\nsignup = \"open\"\ndefault_roles = [\"guest\", \"member\"]",
            );
        assert_eq!(
            problems(&text),
            vec![
                ManifestProblem::DirectoryUndeclaredRole {
                    role: ident("auditor")
                },
                ManifestProblem::DefaultRoleUndeclared {
                    role: ident("guest")
                },
            ]
        );
    }

    #[test]
    fn 로그인_방법은_비어_있지_않고_아는_값이어야_한다() {
        let empty = WITH_AUTH.replace("methods = [\"email_link\"]", "methods = []");
        assert_eq!(problems(&empty), vec![ManifestProblem::AuthNoMethod]);
        let unknown = WITH_AUTH.replace(
            "methods = [\"email_link\"]",
            "methods = [\"email_link\", \"password\"]",
        );
        assert_eq!(
            problems(&unknown),
            vec![ManifestProblem::AuthUnknownMethod {
                method: "password".to_owned()
            }]
        );
    }

    #[test]
    fn 누구나_가입하면_기본_역할이_있어야_하고_초대로만_들어오면_기본_역할을_적지_못한다() {
        let open = WITH_AUTH.replace(
            "login_path = \"/login\"",
            "login_path = \"/login\"\nsignup = \"open\"",
        );
        assert_eq!(
            problems(&open),
            vec![ManifestProblem::OpenSignupWithoutDefaultRoles]
        );
        let fixed = open.replace(
            "signup = \"open\"",
            "signup = \"open\"\ndefault_roles = [\"member\"]",
        );
        assert!(parse(&fixed).check().is_ok());
        let invite = WITH_AUTH.replace(
            "login_path = \"/login\"",
            "login_path = \"/login\"\ndefault_roles = [\"member\"]",
        );
        assert_eq!(
            problems(&invite),
            vec![ManifestProblem::DefaultRolesWithoutOpenSignup]
        );
        let bad = WITH_AUTH.replace(
            "login_path = \"/login\"",
            "login_path = \"/login\"\nsignup = \"anyone\"",
        );
        assert!(toml::from_str::<Manifest>(&bad).is_err());
    }

    #[test]
    fn orbital_auth_와_orbital_은_선언에_적지_못한다() {
        // 스키마 · 역할 이름으로 orbital_auth 를 적으면 읽지 않는다
        let schema = WITH_AUTH.replace("schemas = [\"app\"]", "schemas = [\"orbital_auth\"]");
        assert!(toml::from_str::<Manifest>(&schema).is_err());
        let role = WITH_AUTH.replace(
            "roles = [\"member\", \"manager\"]\n\n[auth]",
            "roles = [\"member\", \"manager\", \"orbital_auth\"]\n\n[auth]",
        );
        assert!(toml::from_str::<Manifest>(&role).is_err());
        // 서비스의 경로와 로그인 화면은 /_orbital 로 시작하지 못한다
        let service = WITH_AUTH.replace("path = \"/api\"", "path = \"/_orbital/api\"");
        assert_eq!(
            problems(&service),
            vec![ManifestProblem::LayerPath {
                path: "/_orbital/api".to_owned()
            }]
        );
        for path in ["/_orbital", "/_orbital/login", "/_orbitalx"] {
            let login = WITH_AUTH.replace(
                "login_path = \"/login\"",
                &format!("login_path = \"{path}\""),
            );
            assert_eq!(
                problems(&login),
                vec![ManifestProblem::LayerPath {
                    path: path.to_owned()
                }],
                "{path}"
            );
        }
        // 비슷하지만 다른 경로는 받는다
        let near = WITH_AUTH.replace("login_path = \"/login\"", "login_path = \"/orbital/login\"");
        assert!(parse(&near).check().is_ok());
    }

    #[test]
    fn mcp_의_선언은_auth_가_있어야_하고_경로는_그_서비스의_path_아래여야_한다() {
        let with_mcp = format!(
            "{WITH_AUTH}\n[auth.mcp]\nservice = \"api\"\npath = \"/api/mcp\"\nconsent_path = \"/oauth/consent\"\n"
        );
        let manifest = parse(&with_mcp).check().expect("받아야 합니다");
        let mcp = manifest.get().auth.as_ref().unwrap().mcp.as_ref().unwrap();
        assert!(mcp.dynamic_registration, "동적 등록은 기본으로 켜져 있다");
        // [auth] 없이 [auth.mcp] 만 적으면 로그인의 선언이 모자라 읽지 않는다
        let alone = format!(
            "{}\n[auth.mcp]\nservice = \"api\"\npath = \"/api/mcp\"\nconsent_path = \"/oauth/consent\"\n",
            WITH_AUTH
                .split("[auth]")
                .next()
                .unwrap()
                .replace("auth = \"required\"\n", "")
        );
        assert!(toml::from_str::<Manifest>(&alone).is_err());
        // 경로는 그 서비스의 path 아래여야 한다. 조각의 경계로 본다
        for (path, problem) in [
            (
                "/mcp",
                ManifestProblem::McpPathOutsideService {
                    path: "/mcp".to_owned(),
                },
            ),
            (
                "/apix/mcp",
                ManifestProblem::McpPathOutsideService {
                    path: "/apix/mcp".to_owned(),
                },
            ),
            (
                "/_orbital/mcp",
                ManifestProblem::LayerPath {
                    path: "/_orbital/mcp".to_owned(),
                },
            ),
            (
                "/.well-known/mcp",
                ManifestProblem::LayerPath {
                    path: "/.well-known/mcp".to_owned(),
                },
            ),
        ] {
            let text = with_mcp.replace("path = \"/api/mcp\"", &format!("path = \"{path}\""));
            assert_eq!(problems(&text), vec![problem], "{path}");
        }
        // 정적 서비스나 없는 서비스에는 두지 못한다
        let static_service = with_mcp.replace(
            "service = \"api\"\npath = \"/api/mcp\"",
            "service = \"web\"\npath = \"/mcp\"",
        );
        assert_eq!(
            problems(&static_service),
            vec![ManifestProblem::McpNotServer {
                service: ident("web")
            }]
        );
        let missing = with_mcp.replace("service = \"api\"\npath", "service = \"worker\"\npath");
        assert_eq!(
            problems(&missing),
            vec![ManifestProblem::McpUnknownService {
                service: ident("worker")
            }]
        );
        // 동의 화면은 어느 서비스의 path 아래여야 하고 레이어의 경로로 적지 못한다
        let consent = with_mcp.replace(
            "consent_path = \"/oauth/consent\"",
            "consent_path = \"/.well-known/consent\"",
        );
        assert_eq!(
            problems(&consent),
            vec![ManifestProblem::LayerPath {
                path: "/.well-known/consent".to_owned()
            }]
        );
        // 서비스의 경로도 /.well-known 으로 시작하지 못한다
        let service = WITH_AUTH.replace("path = \"/api\"", "path = \"/.well-known/api\"");
        assert_eq!(
            problems(&service),
            vec![ManifestProblem::LayerPath {
                path: "/.well-known/api".to_owned()
            }]
        );
    }

    #[test]
    fn 문제는_하나만이_아니라_모두_돌려준다() {
        let text = NEST_VITE
            .replace("start = \"npm run start -w api\"\n", "")
            .replace("output = \"web/dist\"\n", "")
            .replace("cron = \"0 9 25 * *\"", "cron = \"daily\"");
        assert_eq!(problems(&text).len(), 3);
    }
}
