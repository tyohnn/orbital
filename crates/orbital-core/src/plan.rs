//! 역할 계획. 선언과 권한 표에서, DB 에 세울 역할과 권한을 단계의 목록으로 만든다.
//!
//! 역할은 세 갈래다.
//! - 소유자: 모든 표의 주인. 로그인하지 못한다.
//! - 마이그레이션: 레이어가 배포하는 동안만 들어간다. 소유자가 되어 스키마를 바꾼다.
//! - 업무 역할: 권한 표의 권한을 갖는 묶음(로그인하지 못함)과, 서비스마다 그 묶음에 딸린 로그인.
//!
//! 로그인은 (서비스, 업무 역할)마다 따로다. 자기 묶음의 권한만 물려받고, 다른 역할로 바꿔 타지 못한다(`SET FALSE`).
//! 그래서 SQL 주입 한 번으로 직원의 요청이 급여 관리자가 되지 않는다. 비밀번호는 어디에도 없다. 역할에 비밀번호를 주지 않고,
//! DB 는 proxy 만 닿는 자리에서만 연결을 받는다.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::access::{Access, Privilege, Reach, Rls};
use crate::manifest::ValidManifest;
use crate::name::{Ident, InstanceId, TableRef};

/// 인스턴스 하나가 클러스터에서 갖는 이름들. 클러스터의 역할과 database 는 모든 인스턴스가 함께 보므로 식별자를 머리에 단다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    instance: InstanceId,
}

impl Names {
    pub fn new(instance: InstanceId) -> Self {
        Self { instance }
    }

    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// 이 인스턴스의 모든 이름이 갖는 머리말.
    pub fn prefix(&self) -> String {
        format!("i_{}", self.instance.as_str())
    }

    pub fn database(&self) -> String {
        self.prefix()
    }

    pub fn owner(&self) -> String {
        format!("{}_owner", self.prefix())
    }

    pub fn migrator(&self) -> String {
        format!("{}_migrator", self.prefix())
    }

    /// 업무 역할의 권한 묶음. 로그인하지 못한다.
    pub fn group(&self, role: &Ident) -> String {
        format!("{}_r_{role}", self.prefix())
    }

    /// 서비스가 업무 역할로 들어갈 때의 로그인.
    pub fn login(&self, service: &Ident, role: &Ident) -> String {
        format!("{}_s_{service}_{role}", self.prefix())
    }

    /// Orbital Auth 의 역할. 레이어의 로그인 뒤쪽이 이 역할로 `orbital_auth` 의 표를 읽고 쓴다. 앱의 스키마에는 닿지 못한다.
    pub fn auth(&self) -> String {
        format!("{}_auth", self.prefix())
    }

    /// 이 이름이 이 인스턴스의 것인가. 머리말 뒤가 `_` 로 이어져야 한다(`i_abc` 는 `i_abcd_owner` 의 주인이 아니다).
    pub fn owns(&self, name: &str) -> bool {
        name.strip_prefix(&self.prefix())
            .is_some_and(|rest| rest.starts_with('_'))
    }
}

/// 단계가 실행되는 자리.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    /// 클러스터 전체(역할 · database). 관리 연결에서 실행한다.
    Cluster,
    /// 인스턴스의 database 안.
    Database,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    CreateRole {
        name: String,
        login: bool,
    },
    GrantMembership {
        group: String,
        member: String,
        inherit: bool,
        set: bool,
    },
    CreateDatabase {
        name: String,
    },
    RevokeDatabaseFromPublic {
        database: String,
    },
    GrantConnect {
        database: String,
        role: String,
    },
    RevokePublicSchemaFromPublic,
    CreateSchema {
        schema: Ident,
        owner: String,
    },
    RevokeSchemaUsage {
        schema: Ident,
        role: String,
    },
    GrantSchemaUsage {
        schema: Ident,
        role: String,
    },
    RevokeSequences {
        schema: Ident,
        role: String,
    },
    GrantSequences {
        schema: Ident,
        role: String,
    },
    RevokeTable {
        table: TableRef,
        role: String,
    },
    GrantTable {
        table: TableRef,
        role: String,
        privileges: Vec<Privilege>,
    },
    /// 표에 역할 제한 정책을 (다시) 둔다. 신원에 없는 업무 역할의 연결에서는 어떤 행도 읽고 쓰지 못한다.
    SetRolePolicy {
        table: TableRef,
    },
    /// 표의 역할 제한 정책을 걷는다. 없으면 아무것도 하지 않는다.
    DropRolePolicy {
        table: TableRef,
    },
}

/// 역할 제한 정책의 이름. 앱의 마이그레이션은 이 이름을 쓰지 못한다(권한 검사가 잡는다).
pub const ROLE_POLICY: &str = "orbital_role";
/// 역할 제한 정책의 조건. 지금 연결의 업무 역할이 서명된 신원에 있는가.
/// `SELECT` 로 감싸 문장마다 한 번만 검증한다(행마다 서명을 확인하지 않는다).
pub const ROLE_POLICY_EXPR: &str = "(SELECT orbital.granted() AS granted)";

/// 이 표에 역할 제한 정책을 두는가. `[auth]` 를 선언했고 권한 표에서 행 단위 규칙을 켠 표만이다.
///
/// 행 단위 규칙을 끈 표(`rls = "off: 까닭"`)에는 정책이 걸리지 않는다. 그런 표는 [`crate::check::unguarded`] 가 따로 알린다.
/// `[auth]` 가 없는 인스턴스에는 사용자도 신원도 없으므로 정책을 두지 않는다. 두면 어떤 표도 아무에게도 읽히지 않는다.
pub fn role_guarded(manifest: &ValidManifest, access: &Access, table: &TableRef) -> bool {
    manifest.get().auth.is_some()
        && access
            .tables
            .get(table)
            .is_some_and(|declared| declared.rls == Rls::On)
}

fn quote(name: &str) -> String {
    // 이름은 모두 검증된 글자(소문자 · 숫자 · 밑줄)로만 지어진다. 따옴표는 예약어와 겹치는 이름을 위한 것이다.
    format!("\"{name}\"")
}

fn quote_table(table: &TableRef) -> String {
    format!(
        "{}.{}",
        quote(table.schema.as_str()),
        quote(table.table.as_str())
    )
}

impl Step {
    pub fn place(&self) -> Place {
        match self {
            Self::CreateRole { .. }
            | Self::GrantMembership { .. }
            | Self::CreateDatabase { .. }
            | Self::RevokeDatabaseFromPublic { .. }
            | Self::GrantConnect { .. } => Place::Cluster,
            _ => Place::Database,
        }
    }

    pub fn sql(&self) -> String {
        match self {
            Self::CreateRole { name, login } => format!(
                "CREATE ROLE {} {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
                quote(name),
                if *login { "LOGIN" } else { "NOLOGIN" }
            ),
            Self::GrantMembership {
                group,
                member,
                inherit,
                set,
            } => format!(
                "GRANT {} TO {} WITH INHERIT {}, SET {}",
                quote(group),
                quote(member),
                if *inherit { "TRUE" } else { "FALSE" },
                if *set { "TRUE" } else { "FALSE" }
            ),
            Self::CreateDatabase { name } => format!("CREATE DATABASE {}", quote(name)),
            Self::RevokeDatabaseFromPublic { database } => {
                format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", quote(database))
            }
            Self::GrantConnect { database, role } => {
                format!(
                    "GRANT CONNECT ON DATABASE {} TO {}",
                    quote(database),
                    quote(role)
                )
            }
            Self::RevokePublicSchemaFromPublic => {
                "REVOKE ALL ON SCHEMA public FROM PUBLIC".to_owned()
            }
            Self::CreateSchema { schema, owner } => {
                format!(
                    "CREATE SCHEMA {} AUTHORIZATION {}",
                    quote(schema.as_str()),
                    quote(owner)
                )
            }
            Self::RevokeSchemaUsage { schema, role } => {
                format!(
                    "REVOKE ALL ON SCHEMA {} FROM {}",
                    quote(schema.as_str()),
                    quote(role)
                )
            }
            Self::GrantSchemaUsage { schema, role } => {
                format!(
                    "GRANT USAGE ON SCHEMA {} TO {}",
                    quote(schema.as_str()),
                    quote(role)
                )
            }
            Self::RevokeSequences { schema, role } => {
                format!(
                    "REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}",
                    quote(schema.as_str()),
                    quote(role)
                )
            }
            Self::GrantSequences { schema, role } => {
                format!(
                    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}",
                    quote(schema.as_str()),
                    quote(role)
                )
            }
            Self::RevokeTable { table, role } => {
                format!(
                    "REVOKE ALL ON TABLE {} FROM {}",
                    quote_table(table),
                    quote(role)
                )
            }
            Self::GrantTable {
                table,
                role,
                privileges,
            } => format!(
                "GRANT {} ON TABLE {} TO {}",
                privileges
                    .iter()
                    .map(Privilege::sql)
                    .collect::<Vec<_>>()
                    .join(", "),
                quote_table(table),
                quote(role)
            ),
            Self::SetRolePolicy { table } => {
                let table = quote_table(table);
                format!(
                    "DROP POLICY IF EXISTS {ROLE_POLICY} ON {table}; \
                     CREATE POLICY {ROLE_POLICY} ON {table} AS RESTRICTIVE FOR ALL TO PUBLIC \
                     USING ({ROLE_POLICY_EXPR}) WITH CHECK ({ROLE_POLICY_EXPR})"
                )
            }
            Self::DropRolePolicy { table } => {
                format!(
                    "DROP POLICY IF EXISTS {ROLE_POLICY} ON {}",
                    quote_table(table)
                )
            }
        }
    }
}

/// 서비스가 업무 역할로 들어갈 때 쓰는 로그인 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub service: Ident,
    pub role: Ident,
    pub name: String,
}

/// 선언이 요구하는 로그인의 목록. proxy 가 이 표로 서비스와 역할을 로그인에 잇는다.
pub fn logins(names: &Names, manifest: &ValidManifest) -> Vec<Login> {
    let mut logins = Vec::new();
    for service in &manifest.get().services {
        for role in &service.roles {
            logins.push(Login {
                service: service.name.clone(),
                role: role.clone(),
                name: names.login(&service.name, role),
            });
        }
    }
    logins
}

/// 인스턴스의 database 에 접속하는 역할. 마이그레이션 역할, 인증 역할(`[auth]` 를 선언했을 때), 서비스의 로그인이다.
pub fn connectors(names: &Names, manifest: &ValidManifest) -> Vec<String> {
    let mut roles = vec![names.migrator()];
    if manifest.get().auth.is_some() {
        roles.push(names.auth());
    }
    roles.extend(logins(names, manifest).into_iter().map(|login| login.name));
    roles
}

/// 인스턴스를 처음 세울 때의 단계. 역할, database, 스키마까지다. 표의 권한은 마이그레이션 뒤에 [`grants`] 가 세운다.
///
/// database 의 주인은 레이어의 관리 역할이다. 인스턴스의 소유자는 선언한 스키마만 갖고, 새 스키마를 만들지 못한다.
pub fn provision(names: &Names, manifest: &ValidManifest) -> Vec<Step> {
    let database = &manifest.get().database;
    let mut steps = vec![
        Step::CreateRole {
            name: names.owner(),
            login: false,
        },
        Step::CreateRole {
            name: names.migrator(),
            login: true,
        },
        Step::GrantMembership {
            group: names.owner(),
            member: names.migrator(),
            inherit: true,
            set: true,
        },
    ];
    if manifest.get().auth.is_some() {
        // 어느 묶음에도 딸리지 않는다. 권한은 `orbital_auth` 를 둘 때 그 표에만 준다
        steps.push(Step::CreateRole {
            name: names.auth(),
            login: true,
        });
    }
    for role in &database.roles {
        steps.push(Step::CreateRole {
            name: names.group(role),
            login: false,
        });
    }
    let logins = logins(names, manifest);
    for login in &logins {
        steps.push(Step::CreateRole {
            name: login.name.clone(),
            login: true,
        });
        steps.push(Step::GrantMembership {
            group: names.group(&login.role),
            member: login.name.clone(),
            inherit: true,
            set: false,
        });
    }
    steps.push(Step::CreateDatabase {
        name: names.database(),
    });
    steps.push(Step::RevokeDatabaseFromPublic {
        database: names.database(),
    });
    for role in connectors(names, manifest) {
        steps.push(Step::GrantConnect {
            database: names.database(),
            role,
        });
    }
    steps.push(Step::RevokePublicSchemaFromPublic);
    for schema in &database.schemas {
        steps.push(Step::CreateSchema {
            schema: schema.clone(),
            owner: names.owner(),
        });
    }
    steps
}

/// 마이그레이션이 끝난 뒤, 권한 표대로 권한을 다시 세우는 단계.
///
/// 먼저 모두 걷고 표에 적힌 것만 준다. 그래서 앞 배포에서 준 권한이 표에서 빠지면 함께 사라진다.
/// `tables` 는 선언한 스키마에 실제로 있는 표다. 권한 표에 없는 표에는 아무 권한도 주지 않는다.
pub fn grants(
    names: &Names,
    manifest: &ValidManifest,
    access: &Access,
    tables: &[TableRef],
) -> Vec<Step> {
    let database = &manifest.get().database;
    let mut steps = Vec::new();

    for schema in &database.schemas {
        for role in &database.roles {
            steps.push(Step::RevokeSchemaUsage {
                schema: schema.clone(),
                role: names.group(role),
            });
            steps.push(Step::RevokeSequences {
                schema: schema.clone(),
                role: names.group(role),
            });
        }
    }
    let declared: BTreeSet<&Ident> = database.schemas.iter().collect();
    let actual: BTreeSet<&TableRef> = tables
        .iter()
        .filter(|table| declared.contains(&table.schema))
        .collect();
    for table in &actual {
        for role in &database.roles {
            steps.push(Step::RevokeTable {
                table: (*table).clone(),
                role: names.group(role),
            });
        }
    }

    for schema in &database.schemas {
        for role in &database.roles {
            let reach = actual
                .iter()
                .filter(|table| &table.schema == schema)
                .map(|table| access.grant(table, role))
                .fold((false, false), |(any, write), grant| {
                    (
                        any || grant.read != Reach::None || grant.write != Reach::None,
                        write || grant.write != Reach::None,
                    )
                });
            if reach.0 {
                steps.push(Step::GrantSchemaUsage {
                    schema: schema.clone(),
                    role: names.group(role),
                });
            }
            if reach.1 {
                steps.push(Step::GrantSequences {
                    schema: schema.clone(),
                    role: names.group(role),
                });
            }
        }
    }
    for table in &actual {
        for role in &database.roles {
            let privileges = access.grant(table, role).privileges();
            if !privileges.is_empty() {
                steps.push(Step::GrantTable {
                    table: (*table).clone(),
                    role: names.group(role),
                    privileges,
                });
            }
        }
    }

    // 역할 제한 정책은 권한을 다 준 뒤에 맞춘다. 둘 표에는 다시 두고, 그 밖의 표에서는 걷는다
    // (앞에서 auth 를 선언했다가 뺐거나 행 단위 규칙을 껐으면 남은 정책이 없어야 한다)
    let (guarded, open): (Vec<&TableRef>, Vec<&TableRef>) = actual
        .iter()
        .copied()
        .partition(|table| role_guarded(manifest, access, table));
    steps.extend(open.into_iter().map(|table| Step::DropRolePolicy {
        table: table.clone(),
    }));
    steps.extend(guarded.into_iter().map(|table| Step::SetRolePolicy {
        table: table.clone(),
    }));
    steps
}

/// 클러스터에 남아 있지만 선언에는 없는 이 인스턴스의 역할. 서비스나 역할을 선언에서 빼면 생긴다.
pub fn stale_roles(names: &Names, manifest: &ValidManifest, existing: &[String]) -> Vec<String> {
    let mut wanted: BTreeSet<String> = [names.owner()].into();
    wanted.extend(connectors(names, manifest));
    wanted.extend(
        manifest
            .get()
            .database
            .roles
            .iter()
            .map(|role| names.group(role)),
    );
    existing
        .iter()
        .filter(|name| names.owns(name) && !wanted.contains(*name))
        .cloned()
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::access::tests::{ACCESS, access, ident, manifest, table};

    pub(crate) fn names() -> Names {
        Names::new(InstanceId::parse("k3f9x2ab").unwrap())
    }

    #[test]
    fn 이름은_인스턴스의_식별자를_머리에_단다() {
        let names = names();
        assert_eq!(names.database(), "i_k3f9x2ab");
        assert_eq!(names.owner(), "i_k3f9x2ab_owner");
        assert_eq!(names.group(&ident("employee")), "i_k3f9x2ab_r_employee");
        assert_eq!(
            names.login(&ident("api"), &ident("employee")),
            "i_k3f9x2ab_s_api_employee"
        );
    }

    #[test]
    fn 가장_긴_이름도_postgres_의_63바이트_안에_든다() {
        let names = Names::new(InstanceId::parse(&"a".repeat(InstanceId::MAX)).unwrap());
        let service = ident(&"s".repeat(crate::manifest::Service::NAME_MAX));
        let role = ident(&"r".repeat(Ident::MAX));
        assert!(names.login(&service, &role).len() <= 63);
    }

    #[test]
    fn 머리말이_같은_글자로_시작해도_다른_인스턴스의_이름은_제_것이_아니다() {
        let names = names();
        assert!(names.owns("i_k3f9x2ab_owner"));
        assert!(!names.owns("i_k3f9x2abcd_owner"));
        assert!(!names.owns("i_k3f9x2ab"));
        assert!(!names.owns("postgres"));
    }

    #[test]
    fn 소유자와_업무_역할의_묶음은_로그인하지_못한다() {
        let steps = provision(&names(), &manifest());
        for name in [
            "i_k3f9x2ab_owner",
            "i_k3f9x2ab_r_employee",
            "i_k3f9x2ab_r_payroll_admin",
        ] {
            assert!(
                steps.contains(&Step::CreateRole {
                    name: name.to_owned(),
                    login: false
                }),
                "{name}"
            );
        }
        assert!(steps.contains(&Step::CreateRole {
            name: "i_k3f9x2ab_s_api_employee".to_owned(),
            login: true
        }));
    }

    #[test]
    fn 로그인은_자기_묶음의_권한만_물려받고_역할을_바꿔_타지_못한다() {
        let steps = provision(&names(), &manifest());
        assert!(steps.contains(&Step::GrantMembership {
            group: "i_k3f9x2ab_r_employee".to_owned(),
            member: "i_k3f9x2ab_s_api_employee".to_owned(),
            inherit: true,
            set: false,
        }));
        let switchable: Vec<_> = steps
            .iter()
            .filter(|step| matches!(step, Step::GrantMembership { set: true, .. }))
            .collect();
        assert_eq!(
            switchable,
            vec![&Step::GrantMembership {
                group: "i_k3f9x2ab_owner".to_owned(),
                member: "i_k3f9x2ab_migrator".to_owned(),
                inherit: true,
                set: true,
            }]
        );
    }

    #[test]
    fn database_는_만들자마자_모두에게서_권한을_걷고_제_로그인에게만_접속을_준다() {
        let steps = provision(&names(), &manifest());
        let create = steps
            .iter()
            .position(|step| matches!(step, Step::CreateDatabase { .. }))
            .unwrap();
        assert_eq!(
            steps[create + 1],
            Step::RevokeDatabaseFromPublic {
                database: "i_k3f9x2ab".to_owned()
            }
        );
        let connect: Vec<_> = steps
            .iter()
            .filter_map(|step| match step {
                Step::GrantConnect { role, .. } => Some(role.as_str()),
                _ => None,
            })
            .collect();
        assert!(connect.iter().all(|role| names().owns(role)));
        assert!(!connect.contains(&"i_k3f9x2ab_owner"));
        assert!(!connect.contains(&"i_k3f9x2ab_r_employee"));
    }

    #[test]
    fn 권한은_먼저_모두_걷고_권한_표에_적힌_것만_준다() {
        let access = access(ACCESS).unwrap();
        let tables = [table("payroll", "payslip"), table("hr", "department")];
        let steps = grants(&names(), &manifest(), &access, &tables);
        let first_grant = steps
            .iter()
            .position(|step| {
                matches!(
                    step,
                    Step::GrantTable { .. } | Step::GrantSchemaUsage { .. }
                )
            })
            .unwrap();
        assert!(steps[..first_grant].iter().all(|step| {
            matches!(
                step,
                Step::RevokeTable { .. }
                    | Step::RevokeSchemaUsage { .. }
                    | Step::RevokeSequences { .. }
            )
        }));
        assert!(steps.contains(&Step::GrantTable {
            table: table("payroll", "payslip"),
            role: "i_k3f9x2ab_r_employee".to_owned(),
            privileges: vec![Privilege::Select],
        }));
        assert!(!steps.iter().any(|step| matches!(
            step,
            Step::GrantTable { table: target, role, .. } if target == &table("payroll", "payslip") && role == "i_k3f9x2ab_r_manager"
        )));
    }

    #[test]
    fn 한_스키마의_어떤_표도_못_보는_역할에게는_스키마도_열지_않는다() {
        let access = access(ACCESS).unwrap();
        let tables = [table("payroll", "payslip"), table("hr", "department")];
        let steps = grants(&names(), &manifest(), &access, &tables);
        assert!(!steps.contains(&Step::GrantSchemaUsage {
            schema: ident("payroll"),
            role: "i_k3f9x2ab_r_manager".to_owned()
        }));
        assert!(steps.contains(&Step::GrantSchemaUsage {
            schema: ident("hr"),
            role: "i_k3f9x2ab_r_manager".to_owned()
        }));
    }

    #[test]
    fn 권한_표에_없는_표에는_아무_권한도_주지_않는다() {
        let access = access(ACCESS).unwrap();
        let tables = [table("payroll", "payslip"), table("payroll", "bonus")];
        let steps = grants(&names(), &manifest(), &access, &tables);
        assert!(!steps.iter().any(|step| matches!(step, Step::GrantTable { table: target, .. } if target == &table("payroll", "bonus"))));
        assert!(steps.contains(&Step::RevokeTable {
            table: table("payroll", "bonus"),
            role: "i_k3f9x2ab_r_payroll_admin".to_owned()
        }));
    }

    #[test]
    fn 선언하지_않은_스키마의_표는_건드리지_않는다() {
        let access = access(ACCESS).unwrap();
        let steps = grants(&names(), &manifest(), &access, &[table("audit", "log")]);
        assert!(
            !steps
                .iter()
                .any(|step| matches!(step, Step::RevokeTable { .. } | Step::GrantTable { .. }))
        );
    }

    #[test]
    fn 선언에서_뺀_서비스와_역할의_로그인은_남은_역할로_잡힌다() {
        let existing = [
            "i_k3f9x2ab_owner".to_owned(),
            "i_k3f9x2ab_s_api_employee".to_owned(),
            "i_k3f9x2ab_s_worker_employee".to_owned(),
            "i_k3f9x2ab_r_auditor".to_owned(),
            "i_zzzzzzzz_owner".to_owned(),
            "postgres".to_owned(),
        ];
        assert_eq!(
            stale_roles(&names(), &manifest(), &existing),
            vec![
                "i_k3f9x2ab_s_worker_employee".to_owned(),
                "i_k3f9x2ab_r_auditor".to_owned()
            ]
        );
    }

    pub(crate) fn with_auth() -> ValidManifest {
        let text = format!(
            "{}\n[auth]\nmethods = [\"email_link\"]\nlogin_path = \"/login\"\ndirectory = [\"manager\"]\n",
            crate::access::tests::MANIFEST
        );
        toml::from_str::<crate::manifest::Manifest>(&text)
            .unwrap()
            .check()
            .unwrap()
    }

    #[test]
    fn 인증_역할의_이름은_인스턴스의_머리말에_auth_를_단다() {
        assert_eq!(names().auth(), "i_k3f9x2ab_auth");
        assert!(names().owns(&names().auth()));
    }

    #[test]
    fn auth_를_선언하면_인증_역할이_로그인으로_서고_database_에만_접속하고_어느_묶음에도_딸리지_않는다()
     {
        let steps = provision(&names(), &with_auth());
        assert!(steps.contains(&Step::CreateRole {
            name: "i_k3f9x2ab_auth".to_owned(),
            login: true
        }));
        assert!(steps.contains(&Step::GrantConnect {
            database: "i_k3f9x2ab".to_owned(),
            role: "i_k3f9x2ab_auth".to_owned()
        }));
        assert!(!steps.iter().any(|step| matches!(
            step,
            Step::GrantMembership { group, member, .. } if group == "i_k3f9x2ab_auth" || member == "i_k3f9x2ab_auth"
        )));
    }

    #[test]
    fn auth_를_선언하지_않은_선언의_계획에는_인증_역할이_없다() {
        let steps = provision(&names(), &manifest());
        let with = provision(&names(), &with_auth());
        assert!(!format!("{steps:?}").contains("_auth"));
        // auth 를 더해도 그 밖의 단계는 같다
        let rest: Vec<_> = with
            .into_iter()
            .filter(|step| !format!("{step:?}").contains("i_k3f9x2ab_auth"))
            .collect();
        assert_eq!(rest, steps);
    }

    #[test]
    fn 인증_역할은_auth_를_선언했을_때만_남은_역할이_아니다() {
        let existing = ["i_k3f9x2ab_auth".to_owned()];
        assert_eq!(
            stale_roles(&names(), &with_auth(), &existing),
            Vec::<String>::new()
        );
        assert_eq!(
            stale_roles(&names(), &manifest(), &existing),
            vec!["i_k3f9x2ab_auth".to_owned()]
        );
    }

    #[test]
    fn auth_를_선언하면_행_단위_규칙을_켠_표마다_역할_제한_정책을_세우고_나머지에서는_걷는다() {
        let access = crate::access::Access::parse(
            &toml::from_str::<crate::access::RawAccess>(ACCESS).unwrap(),
            &with_auth(),
        )
        .unwrap();
        let tables = [
            table("payroll", "payslip"),
            table("hr", "department"),
            table("payroll", "bonus"),
        ];
        let steps = grants(&names(), &with_auth(), &access, &tables);
        let policies: Vec<&Step> = steps
            .iter()
            .filter(|step| {
                matches!(
                    step,
                    Step::SetRolePolicy { .. } | Step::DropRolePolicy { .. }
                )
            })
            .collect();
        assert_eq!(
            policies,
            vec![
                &Step::DropRolePolicy {
                    table: table("hr", "department")
                },
                &Step::DropRolePolicy {
                    table: table("payroll", "bonus")
                },
                &Step::SetRolePolicy {
                    table: table("payroll", "payslip")
                },
            ]
        );
        // 정책은 권한을 다 준 뒤에 세운다
        let last_grant = steps
            .iter()
            .rposition(|step| {
                matches!(
                    step,
                    Step::GrantTable { .. }
                        | Step::GrantSchemaUsage { .. }
                        | Step::GrantSequences { .. }
                )
            })
            .unwrap();
        let first_policy = steps
            .iter()
            .position(|step| {
                matches!(
                    step,
                    Step::SetRolePolicy { .. } | Step::DropRolePolicy { .. }
                )
            })
            .unwrap();
        assert!(last_grant < first_policy);
    }

    #[test]
    fn auth_를_선언하지_않으면_역할_제한_정책을_세우지_않는다() {
        let access = access(ACCESS).unwrap();
        let tables = [table("payroll", "payslip"), table("hr", "department")];
        let steps = grants(&names(), &manifest(), &access, &tables);
        assert!(
            !steps
                .iter()
                .any(|step| matches!(step, Step::SetRolePolicy { .. }))
        );
        // 앞에서 auth 를 선언했다가 뺐으면 남은 정책을 걷는다
        assert!(steps.contains(&Step::DropRolePolicy {
            table: table("payroll", "payslip")
        }));
    }

    #[test]
    fn 역할_제한_정책은_제한하는_정책이고_모든_명령과_모든_역할에_걸린다() {
        assert_eq!(
            Step::SetRolePolicy {
                table: table("payroll", "payslip")
            }
            .sql(),
            "DROP POLICY IF EXISTS orbital_role ON \"payroll\".\"payslip\"; \
             CREATE POLICY orbital_role ON \"payroll\".\"payslip\" AS RESTRICTIVE FOR ALL TO PUBLIC \
             USING ((SELECT orbital.granted() AS granted)) WITH CHECK ((SELECT orbital.granted() AS granted))"
        );
        assert_eq!(
            Step::DropRolePolicy {
                table: table("payroll", "payslip")
            }
            .sql(),
            "DROP POLICY IF EXISTS orbital_role ON \"payroll\".\"payslip\""
        );
        assert_eq!(
            Step::DropRolePolicy {
                table: table("payroll", "payslip")
            }
            .place(),
            Place::Database
        );
    }

    #[test]
    fn 단계의_sql_은_이름을_따옴표로_감싼다() {
        let step = Step::GrantTable {
            table: table("payroll", "payslip"),
            role: "i_k3f9x2ab_r_employee".to_owned(),
            privileges: vec![Privilege::Select, Privilege::Insert],
        };
        assert_eq!(
            step.sql(),
            "GRANT SELECT, INSERT ON TABLE \"payroll\".\"payslip\" TO \"i_k3f9x2ab_r_employee\""
        );
        assert_eq!(step.place(), Place::Database);
        assert_eq!(
            Step::CreateDatabase {
                name: "i_k3f9x2ab".to_owned()
            }
            .place(),
            Place::Cluster
        );
    }
}
