//! 권한 검사. 실제 DB 의 모습이 선언과 권한 표에 정확히 맞는지 본다.
//!
//! 승격의 관문이다. 하나라도 어긋나면 승격을 요청할 수 없다. 권한이 모자라도 실패이고 남아도 실패다.
//! 실제 DB 를 읽는 일은 `orbital-pg` 가 하고, 여기서는 읽어 온 [`Snapshot`] 을 판정만 한다.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::access::{Access, Privilege, Rls};
use crate::manifest::ValidManifest;
use crate::name::{Ident, TableRef};
use crate::plan::{Names, logins};

/// 실제 DB 에서 읽어 온 모습.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// database 에 있는 스키마(Postgres 의 것은 뺀다).
    pub schemas: Vec<String>,
    /// 모든 스키마의 표.
    pub tables: Vec<TableState>,
    /// 이 인스턴스의 머리말을 가진 역할.
    pub roles: Vec<RoleState>,
    /// 이 인스턴스의 역할이 낀 멤버십.
    pub memberships: Vec<Membership>,
    /// 누구나(PUBLIC) 이 database 에 접속할 수 있는가.
    pub public_can_connect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableState {
    pub schema: String,
    pub table: String,
    pub owner: String,
    pub rls: bool,
    /// 받은 쪽의 역할 이름마다의 권한. 누구나(PUBLIC)는 `public` 으로 적는다.
    pub privileges: BTreeMap<String, BTreeSet<Privilege>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleState {
    pub name: String,
    pub login: bool,
    pub superuser: bool,
    pub create_db: bool,
    pub create_role: bool,
    pub replication: bool,
    pub bypass_rls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub group: String,
    pub member: String,
    pub inherit: bool,
    pub set: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum Finding {
    SchemaNotDeclared {
        schema: String,
    },
    TableNotInAccess {
        table: String,
    },
    TableMissing {
        table: TableRef,
    },
    RlsOff {
        table: TableRef,
    },
    WrongOwner {
        table: String,
        owner: String,
    },
    PrivilegeMissing {
        table: TableRef,
        role: Ident,
        privilege: Privilege,
    },
    PrivilegeExtra {
        table: TableRef,
        role: Ident,
        privilege: Privilege,
    },
    UnexpectedGrantee {
        table: String,
        grantee: String,
    },
    RoleMissing {
        role: String,
    },
    RoleNotDeclared {
        role: String,
    },
    RoleTooPowerful {
        role: String,
        attribute: String,
    },
    GroupCanLogin {
        role: String,
    },
    UnexpectedMembership {
        group: String,
        member: String,
    },
    CanSwitchRole {
        group: String,
        member: String,
    },
    PublicCanConnect,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaNotDeclared { schema } => {
                write!(
                    f,
                    "스키마 `{schema}` 가 DB 에 있지만 `[database].schemas` 에 없습니다"
                )
            }
            Self::TableNotInAccess { table } => write!(
                f,
                "표 `{table}` 이 권한 표에 없습니다. 누가 무엇을 할 수 있는지 적어 주세요(아무도 못 쓰게 하려면 모든 역할에 none)"
            ),
            Self::TableMissing { table } => {
                write!(f, "권한 표에 적힌 표 `{table}` 이 DB 에 없습니다")
            }
            Self::RlsOff { table } => write!(
                f,
                "표 `{table}` 에 행 단위 규칙이 꺼져 있습니다. 켜거나, 끄는 까닭을 권한 표에 `rls = \"off: 까닭\"` 으로 적어 주세요"
            ),
            Self::WrongOwner { table, owner } => {
                write!(
                    f,
                    "표 `{table}` 의 주인이 `{owner}` 입니다. 표는 인스턴스의 소유자 역할만 갖습니다"
                )
            }
            Self::PrivilegeMissing {
                table,
                role,
                privilege,
            } => write!(
                f,
                "역할 `{role}` 에게 표 `{table}` 의 {} 권한이 없습니다. 권한 표에는 있습니다",
                privilege.sql()
            ),
            Self::PrivilegeExtra {
                table,
                role,
                privilege,
            } => write!(
                f,
                "역할 `{role}` 에게 표 `{table}` 의 {} 권한이 있습니다. 권한 표에는 없습니다",
                privilege.sql()
            ),
            Self::UnexpectedGrantee { table, grantee } => {
                write!(
                    f,
                    "표 `{table}` 의 권한을 `{grantee}` 가 갖고 있습니다. 권한은 업무 역할만 받습니다"
                )
            }
            Self::RoleMissing { role } => write!(f, "역할 `{role}` 이 DB 에 없습니다"),
            Self::RoleNotDeclared { role } => {
                write!(f, "역할 `{role}` 이 DB 에 있지만 선언에는 없습니다")
            }
            Self::RoleTooPowerful { role, attribute } => {
                write!(f, "역할 `{role}` 에 `{attribute}` 속성이 있습니다")
            }
            Self::GroupCanLogin { role } => write!(
                f,
                "권한 묶음 `{role}` 으로 로그인할 수 있습니다. 묶음은 로그인하지 못해야 합니다"
            ),
            Self::UnexpectedMembership { group, member } => {
                write!(
                    f,
                    "`{member}` 가 `{group}` 에 딸려 있습니다. 선언에 없는 멤버십입니다"
                )
            }
            Self::CanSwitchRole { group, member } => {
                write!(f, "`{member}` 가 `{group}` 으로 역할을 바꿔 탈 수 있습니다")
            }
            Self::PublicCanConnect => write!(f, "누구나 이 database 에 접속할 수 있습니다"),
        }
    }
}

/// 레이어와 Postgres 가 두는 스키마. 선언에 없어도 된다.
const LAYER_SCHEMAS: [&str; 2] = ["public", "orbital"];

/// Orbital Auth 의 스키마. `[auth]` 를 선언한 인스턴스에만 있어야 한다.
pub const AUTH_SCHEMA: &str = "orbital_auth";

/// 실제 DB 가 선언과 권한 표에 맞는지 본다. 빈 목록이 통과다.
pub fn judge(
    names: &Names,
    manifest: &ValidManifest,
    access: &Access,
    snapshot: &Snapshot,
) -> Vec<Finding> {
    let database = &manifest.get().database;
    let mut findings = Vec::new();

    if snapshot.public_can_connect {
        findings.push(Finding::PublicCanConnect);
    }

    let auth = manifest.get().auth.is_some();
    for schema in &snapshot.schemas {
        let declared = database
            .schemas
            .iter()
            .any(|candidate| candidate.as_str() == schema);
        let layer = LAYER_SCHEMAS.contains(&schema.as_str()) || (auth && schema == AUTH_SCHEMA);
        if !declared && !layer {
            findings.push(Finding::SchemaNotDeclared {
                schema: schema.clone(),
            });
        }
    }

    let groups: BTreeMap<String, &Ident> = database
        .roles
        .iter()
        .map(|role| (names.group(role), role))
        .collect();
    let owner = names.owner();

    let mut seen = BTreeSet::new();
    for state in &snapshot.tables {
        let Some(schema) = database
            .schemas
            .iter()
            .find(|candidate| candidate.as_str() == state.schema)
        else {
            continue;
        };
        let label = format!("{}.{}", state.schema, state.table);
        if state.owner != owner {
            findings.push(Finding::WrongOwner {
                table: label.clone(),
                owner: state.owner.clone(),
            });
        }
        for (grantee, privileges) in &state.privileges {
            if grantee != &owner && !groups.contains_key(grantee) && !privileges.is_empty() {
                findings.push(Finding::UnexpectedGrantee {
                    table: label.clone(),
                    grantee: grantee.clone(),
                });
            }
        }
        let Ok(table) = Ident::parse(&state.table) else {
            findings.push(Finding::TableNotInAccess { table: label });
            continue;
        };
        let table = TableRef {
            schema: schema.clone(),
            table,
        };
        let Some(declared) = access.tables.get(&table) else {
            findings.push(Finding::TableNotInAccess { table: label });
            continue;
        };
        seen.insert(table.clone());

        if declared.rls == Rls::On && !state.rls {
            findings.push(Finding::RlsOff {
                table: table.clone(),
            });
        }
        for role in &database.roles {
            let wanted: BTreeSet<Privilege> = access
                .grant(&table, role)
                .privileges()
                .into_iter()
                .collect();
            let empty = BTreeSet::new();
            let actual = state.privileges.get(&names.group(role)).unwrap_or(&empty);
            for privilege in wanted.difference(actual) {
                findings.push(Finding::PrivilegeMissing {
                    table: table.clone(),
                    role: role.clone(),
                    privilege: *privilege,
                });
            }
            for privilege in actual.difference(&wanted) {
                findings.push(Finding::PrivilegeExtra {
                    table: table.clone(),
                    role: role.clone(),
                    privilege: *privilege,
                });
            }
        }
    }
    for table in access.tables.keys() {
        if !seen.contains(table) {
            findings.push(Finding::TableMissing {
                table: table.clone(),
            });
        }
    }

    let logins = logins(names, manifest);
    let mut wanted_roles: BTreeMap<String, bool> = BTreeMap::new();
    wanted_roles.insert(owner.clone(), false);
    wanted_roles.insert(names.migrator(), true);
    if auth {
        wanted_roles.insert(names.auth(), true);
    }
    wanted_roles.extend(groups.keys().map(|group| (group.clone(), false)));
    wanted_roles.extend(logins.iter().map(|login| (login.name.clone(), true)));

    for state in snapshot
        .roles
        .iter()
        .filter(|state| names.owns(&state.name))
    {
        match wanted_roles.get(&state.name) {
            None => findings.push(Finding::RoleNotDeclared {
                role: state.name.clone(),
            }),
            Some(may_login) => {
                if state.login && !may_login {
                    findings.push(Finding::GroupCanLogin {
                        role: state.name.clone(),
                    });
                }
            }
        }
        for (attribute, on) in [
            ("SUPERUSER", state.superuser),
            ("CREATEDB", state.create_db),
            ("CREATEROLE", state.create_role),
            ("REPLICATION", state.replication),
            ("BYPASSRLS", state.bypass_rls),
        ] {
            if on {
                findings.push(Finding::RoleTooPowerful {
                    role: state.name.clone(),
                    attribute: attribute.to_owned(),
                });
            }
        }
    }
    for role in wanted_roles.keys() {
        if !snapshot.roles.iter().any(|state| &state.name == role) {
            findings.push(Finding::RoleMissing { role: role.clone() });
        }
    }

    let mut wanted_memberships: BTreeSet<(String, String)> = BTreeSet::new();
    wanted_memberships.insert((owner.clone(), names.migrator()));
    wanted_memberships.extend(
        logins
            .iter()
            .map(|login| (names.group(&login.role), login.name.clone())),
    );
    for membership in &snapshot.memberships {
        let pair = (membership.group.clone(), membership.member.clone());
        if !wanted_memberships.contains(&pair) {
            findings.push(Finding::UnexpectedMembership {
                group: pair.0,
                member: pair.1,
            });
        } else if membership.set && membership.group != owner {
            findings.push(Finding::CanSwitchRole {
                group: pair.0,
                member: pair.1,
            });
        }
    }

    findings
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::access::tests::{ACCESS, access, ident, manifest, table};
    use crate::plan::tests::names;
    use crate::plan::{Step, grants, provision};

    /// 계획을 그대로 실행했을 때의 DB 모습을 만든다. 실제 DB 대신 단계를 읽어 흉내 낸다.
    pub(crate) fn applied(tables: &[TableRef], rls_on: &[TableRef]) -> Snapshot {
        let names = names();
        let manifest = manifest();
        let access = access(ACCESS).unwrap();
        let mut snapshot = Snapshot {
            schemas: vec!["public".to_owned(), "orbital".to_owned()],
            ..Snapshot::default()
        };
        for step in provision(&names, &manifest) {
            match step {
                Step::CreateRole { name, login } => snapshot.roles.push(RoleState {
                    name,
                    login,
                    superuser: false,
                    create_db: false,
                    create_role: false,
                    replication: false,
                    bypass_rls: false,
                }),
                Step::GrantMembership {
                    group,
                    member,
                    inherit,
                    set,
                } => {
                    snapshot.memberships.push(Membership {
                        group,
                        member,
                        inherit,
                        set,
                    });
                }
                Step::CreateSchema { schema, .. } => snapshot.schemas.push(schema.to_string()),
                _ => {}
            }
        }
        for target in tables {
            snapshot.tables.push(TableState {
                schema: target.schema.to_string(),
                table: target.table.to_string(),
                owner: names.owner(),
                rls: rls_on.contains(target),
                privileges: BTreeMap::new(),
            });
        }
        for step in grants(&names, &manifest, &access, tables) {
            if let Step::GrantTable {
                table: target,
                role,
                privileges,
            } = step
            {
                let state = snapshot
                    .tables
                    .iter_mut()
                    .find(|state| {
                        state.schema == target.schema.as_str()
                            && state.table == target.table.as_str()
                    })
                    .unwrap();
                state.privileges.entry(role).or_default().extend(privileges);
            }
        }
        snapshot
    }

    fn standard() -> Snapshot {
        applied(
            &[table("payroll", "payslip"), table("hr", "department")],
            &[table("payroll", "payslip")],
        )
    }

    fn run(snapshot: &Snapshot) -> Vec<Finding> {
        judge(&names(), &manifest(), &access(ACCESS).unwrap(), snapshot)
    }

    fn payslip(snapshot: &mut Snapshot) -> &mut TableState {
        snapshot
            .tables
            .iter_mut()
            .find(|state| state.table == "payslip")
            .unwrap()
    }

    #[test]
    fn 계획대로_세운_db_는_검사를_통과한다() {
        assert_eq!(run(&standard()), vec![]);
    }

    #[test]
    fn 권한_표에_없는_권한이_하나라도_있으면_실패한다() {
        let mut snapshot = standard();
        payslip(&mut snapshot)
            .privileges
            .entry("i_k3f9x2ab_r_manager".to_owned())
            .or_default()
            .insert(Privilege::Select);
        assert_eq!(
            run(&snapshot),
            vec![Finding::PrivilegeExtra {
                table: table("payroll", "payslip"),
                role: ident("manager"),
                privilege: Privilege::Select
            }]
        );
    }

    #[test]
    fn 권한_표에_있는_권한이_하나라도_없으면_실패한다() {
        let mut snapshot = standard();
        payslip(&mut snapshot)
            .privileges
            .get_mut("i_k3f9x2ab_r_payroll_admin")
            .unwrap()
            .remove(&Privilege::Delete);
        assert_eq!(
            run(&snapshot),
            vec![Finding::PrivilegeMissing {
                table: table("payroll", "payslip"),
                role: ident("payroll_admin"),
                privilege: Privilege::Delete
            }]
        );
    }

    #[test]
    fn 행_단위_규칙이_꺼진_표는_끈_까닭이_권한_표에_없으면_실패한다() {
        let mut snapshot = standard();
        payslip(&mut snapshot).rls = false;
        assert_eq!(
            run(&snapshot),
            vec![Finding::RlsOff {
                table: table("payroll", "payslip")
            }]
        );
        // hr.department 는 권한 표에 끈 까닭이 있어서 꺼져 있어도 통과한다
        assert!(
            !standard()
                .tables
                .iter()
                .find(|state| state.table == "department")
                .unwrap()
                .rls
        );
    }

    #[test]
    fn 선언한_스키마의_표가_권한_표에_없으면_실패한다() {
        let snapshot = applied(
            &[
                table("payroll", "payslip"),
                table("hr", "department"),
                table("payroll", "bonus"),
            ],
            &[table("payroll", "payslip"), table("payroll", "bonus")],
        );
        assert_eq!(
            run(&snapshot),
            vec![Finding::TableNotInAccess {
                table: "payroll.bonus".to_owned()
            }]
        );
    }

    #[test]
    fn 권한_표에_적힌_표가_db_에_없으면_실패한다() {
        let snapshot = applied(
            &[table("payroll", "payslip")],
            &[table("payroll", "payslip")],
        );
        assert_eq!(
            run(&snapshot),
            vec![Finding::TableMissing {
                table: table("hr", "department")
            }]
        );
    }

    #[test]
    fn 업무_역할이_아닌_쪽이_표의_권한을_가지면_실패한다() {
        let mut snapshot = standard();
        payslip(&mut snapshot)
            .privileges
            .insert("public".to_owned(), [Privilege::Select].into());
        payslip(&mut snapshot).privileges.insert(
            "i_k3f9x2ab_s_api_employee".to_owned(),
            [Privilege::Select].into(),
        );
        assert_eq!(
            run(&snapshot),
            vec![
                Finding::UnexpectedGrantee {
                    table: "payroll.payslip".to_owned(),
                    grantee: "i_k3f9x2ab_s_api_employee".to_owned()
                },
                Finding::UnexpectedGrantee {
                    table: "payroll.payslip".to_owned(),
                    grantee: "public".to_owned()
                },
            ]
        );
    }

    #[test]
    fn 업무_역할이_표를_소유하면_실패한다() {
        let mut snapshot = standard();
        payslip(&mut snapshot).owner = "i_k3f9x2ab_r_payroll_admin".to_owned();
        assert_eq!(
            run(&snapshot),
            vec![Finding::WrongOwner {
                table: "payroll.payslip".to_owned(),
                owner: "i_k3f9x2ab_r_payroll_admin".to_owned()
            }]
        );
    }

    #[test]
    fn 선언하지_않은_스키마가_db_에_있으면_실패한다() {
        let mut snapshot = standard();
        snapshot.schemas.push("scratch".to_owned());
        assert_eq!(
            run(&snapshot),
            vec![Finding::SchemaNotDeclared {
                schema: "scratch".to_owned()
            }]
        );
    }

    #[test]
    fn 로그인이_다른_역할로_바꿔_탈_수_있으면_실패한다() {
        let mut snapshot = standard();
        snapshot
            .memberships
            .iter_mut()
            .find(|membership| membership.member == "i_k3f9x2ab_s_api_employee")
            .unwrap()
            .set = true;
        assert_eq!(
            run(&snapshot),
            vec![Finding::CanSwitchRole {
                group: "i_k3f9x2ab_r_employee".to_owned(),
                member: "i_k3f9x2ab_s_api_employee".to_owned()
            }]
        );
    }

    #[test]
    fn 선언에_없는_멤버십이_있으면_실패한다() {
        let mut snapshot = standard();
        snapshot.memberships.push(Membership {
            group: "i_k3f9x2ab_r_payroll_admin".to_owned(),
            member: "i_k3f9x2ab_s_api_employee".to_owned(),
            inherit: true,
            set: false,
        });
        assert_eq!(
            run(&snapshot),
            vec![Finding::UnexpectedMembership {
                group: "i_k3f9x2ab_r_payroll_admin".to_owned(),
                member: "i_k3f9x2ab_s_api_employee".to_owned()
            }]
        );
    }

    #[test]
    fn 권한_묶음으로_로그인할_수_있거나_역할에_센_속성이_있으면_실패한다() {
        let mut snapshot = standard();
        let group = snapshot
            .roles
            .iter_mut()
            .find(|state| state.name == "i_k3f9x2ab_r_employee")
            .unwrap();
        group.login = true;
        group.bypass_rls = true;
        assert_eq!(
            run(&snapshot),
            vec![
                Finding::GroupCanLogin {
                    role: "i_k3f9x2ab_r_employee".to_owned()
                },
                Finding::RoleTooPowerful {
                    role: "i_k3f9x2ab_r_employee".to_owned(),
                    attribute: "BYPASSRLS".to_owned()
                },
            ]
        );
    }

    #[test]
    fn 선언에_없는_역할이_남아_있거나_있어야_할_역할이_없으면_실패한다() {
        let mut snapshot = standard();
        snapshot
            .roles
            .retain(|state| state.name != "i_k3f9x2ab_migrator");
        snapshot.roles.push(RoleState {
            name: "i_k3f9x2ab_s_worker_employee".to_owned(),
            login: true,
            superuser: false,
            create_db: false,
            create_role: false,
            replication: false,
            bypass_rls: false,
        });
        assert_eq!(
            run(&snapshot),
            vec![
                Finding::RoleNotDeclared {
                    role: "i_k3f9x2ab_s_worker_employee".to_owned()
                },
                Finding::RoleMissing {
                    role: "i_k3f9x2ab_migrator".to_owned()
                },
            ]
        );
    }

    /// 계획대로 세운 DB 에 Orbital Auth 의 스키마와 인증 역할을 더한다.
    fn with_auth_installed() -> Snapshot {
        let mut snapshot = standard();
        snapshot.schemas.push(AUTH_SCHEMA.to_owned());
        snapshot.roles.push(RoleState {
            name: names().auth(),
            login: true,
            superuser: false,
            create_db: false,
            create_role: false,
            replication: false,
            bypass_rls: false,
        });
        snapshot
    }

    #[test]
    fn auth_를_선언한_db_는_orbital_auth_와_인증_역할이_있어도_통과한다() {
        let manifest = crate::plan::tests::with_auth();
        let access = Access::parse(
            &toml::from_str::<crate::access::RawAccess>(ACCESS).unwrap(),
            &manifest,
        )
        .unwrap();
        assert_eq!(
            judge(&names(), &manifest, &access, &with_auth_installed()),
            vec![]
        );
        // 인증 역할이 없으면 모자란 것이다
        assert_eq!(
            judge(&names(), &manifest, &access, &standard()),
            vec![Finding::RoleMissing {
                role: names().auth()
            }]
        );
    }

    #[test]
    fn auth_를_선언하지_않은_db_에_orbital_auth_나_인증_역할이_있으면_실패한다() {
        assert_eq!(
            run(&with_auth_installed()),
            vec![
                Finding::SchemaNotDeclared {
                    schema: AUTH_SCHEMA.to_owned()
                },
                Finding::RoleNotDeclared {
                    role: names().auth()
                },
            ]
        );
    }

    #[test]
    fn 누구나_database_에_접속할_수_있으면_실패한다() {
        let mut snapshot = standard();
        snapshot.public_can_connect = true;
        assert_eq!(run(&snapshot), vec![Finding::PublicCanConnect]);
    }
}
