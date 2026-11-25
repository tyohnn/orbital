//! 권한 표(`db/access.toml`)의 모양과 검증.
//!
//! 표마다, 업무 역할마다 무엇을 할 수 있는지 적는다. 레이어는 이 표대로 권한을 세우고, 실제 DB 가 이 표와 정확히 같은지 승격 전에 본다.
//! 빠뜨린 것을 「없음」으로 짐작하지 않는다. 표마다 모든 역할을 적어야 하고, 아무것도 못 하게 하려면 `"none"` 이라고 적는다.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::manifest::ValidManifest;
use crate::name::{Ident, TableRef};

/// 어디까지 닿는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    None,
    /// 자기 행만. 행 단위 규칙(RLS)이 가른다.
    Own,
    All,
}

/// 역할 하나가 표 하나에서 할 수 있는 것.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Grant {
    pub read: Reach,
    pub write: Reach,
}

impl Grant {
    pub const NONE: Self = Self {
        read: Reach::None,
        write: Reach::None,
    };

    /// 선언 파일의 말을 읽는다. 받는 말은 다섯이다.
    pub fn parse(text: &str) -> Option<Self> {
        let grant = match text.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["none"] => Self::NONE,
            ["read"] => Self {
                read: Reach::All,
                write: Reach::None,
            },
            ["read", "own"] => Self {
                read: Reach::Own,
                write: Reach::None,
            },
            ["read", "write"] => Self {
                read: Reach::All,
                write: Reach::All,
            },
            ["read", "write", "own"] => Self {
                read: Reach::Own,
                write: Reach::Own,
            },
            _ => return None,
        };
        Some(grant)
    }

    pub fn uses_own(&self) -> bool {
        self.read == Reach::Own || self.write == Reach::Own
    }

    /// 이 권한에 맞는 표 권한. `own` 과 `all` 은 표 권한이 같고 행 단위 규칙이 가른다.
    pub fn privileges(&self) -> Vec<Privilege> {
        let mut privileges = Vec::new();
        if self.read != Reach::None {
            privileges.push(Privilege::Select);
        }
        if self.write != Reach::None {
            privileges.extend([Privilege::Insert, Privilege::Update, Privilege::Delete]);
        }
        privileges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    /// PostgreSQL 17 부터 있다(VACUUM · ANALYZE · REINDEX 같은 관리).
    Maintain,
}

impl Privilege {
    pub const ALL: [Self; 8] = [
        Self::Select,
        Self::Insert,
        Self::Update,
        Self::Delete,
        Self::Truncate,
        Self::References,
        Self::Trigger,
        Self::Maintain,
    ];

    /// Postgres 가 권한을 부르는 이름에서 읽는다.
    pub fn from_sql(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|privilege| privilege.sql() == text)
    }

    pub fn sql(&self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Truncate => "TRUNCATE",
            Self::References => "REFERENCES",
            Self::Trigger => "TRIGGER",
            Self::Maintain => "MAINTAIN",
        }
    }
}

/// 행 단위 규칙을 켰는가. 끄려면 까닭을 적어야 한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rls {
    On,
    Off { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableAccess {
    pub rls: Rls,
    pub roles: BTreeMap<Ident, Grant>,
}

/// 검증을 지난 권한 표.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Access {
    pub tables: BTreeMap<TableRef, TableAccess>,
}

impl Access {
    pub fn grant(&self, table: &TableRef, role: &Ident) -> Grant {
        self.tables
            .get(table)
            .and_then(|access| access.roles.get(role))
            .copied()
            .unwrap_or(Grant::NONE)
    }
}

/// 파일에서 읽은 그대로의 모양. `[스키마.표]` 아래에 `역할 = "말"` 을 적는다.
pub type RawAccess = BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum AccessProblem {
    BadName {
        name: String,
        why: String,
    },
    UndeclaredSchema {
        table: String,
    },
    UndeclaredRole {
        table: String,
        role: String,
    },
    MissingRole {
        table: String,
        role: Ident,
    },
    BadGrant {
        table: String,
        role: String,
        text: String,
    },
    BadRls {
        table: String,
        text: String,
    },
    OwnNeedsRls {
        table: String,
        role: Ident,
    },
}

impl fmt::Display for AccessProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadName { name, why } => write!(f, "`{name}`: {why}"),
            Self::UndeclaredSchema { table } => {
                write!(
                    f,
                    "표 `{table}` 의 스키마가 `[database].schemas` 에 없습니다"
                )
            }
            Self::UndeclaredRole { table, role } => {
                write!(
                    f,
                    "표 `{table}` 에 적힌 역할 `{role}` 이 `[database].roles` 에 없습니다"
                )
            }
            Self::MissingRole { table, role } => write!(
                f,
                "표 `{table}` 에 역할 `{role}` 이 적혀 있지 않습니다. 아무것도 못 하게 하려면 `{role} = \"none\"` 이라고 적어 주세요"
            ),
            Self::BadGrant { table, role, text } => write!(
                f,
                "표 `{table}` 의 `{role} = \"{text}\"` 를 읽지 못했습니다. none · read · read own · read write · read write own 가운데 하나를 적어 주세요"
            ),
            Self::BadRls { table, text } => write!(
                f,
                "표 `{table}` 의 `rls = \"{text}\"` 를 읽지 못했습니다. 행 단위 규칙을 끄려면 `rls = \"off: 까닭\"` 이라고 적어 주세요"
            ),
            Self::OwnNeedsRls { table, role } => write!(
                f,
                "표 `{table}` 은 행 단위 규칙을 껐는데 역할 `{role}` 에 「자기 행만」을 적었습니다. 규칙을 켜거나 own 을 빼 주세요"
            ),
        }
    }
}

/// 권한 표에서 역할 이름이 아닌 칸. 역할 이름으로는 쓰지 못한다.
const RLS_KEY: &str = "rls";

impl Access {
    /// 읽은 그대로의 표를 선언과 맞춰 보고 검증된 권한 표로 만든다.
    pub fn parse(raw: &RawAccess, manifest: &ValidManifest) -> Result<Self, Vec<AccessProblem>> {
        let database = &manifest.get().database;
        let mut problems = Vec::new();
        let mut tables = BTreeMap::new();

        for (schema_text, by_table) in raw {
            for (table_text, by_role) in by_table {
                let label = format!("{schema_text}.{table_text}");
                let schema = match Ident::parse(schema_text) {
                    Ok(schema) => schema,
                    Err(error) => {
                        problems.push(AccessProblem::BadName {
                            name: schema_text.clone(),
                            why: error.to_string(),
                        });
                        continue;
                    }
                };
                let table = match Ident::parse(table_text) {
                    Ok(table) => table,
                    Err(error) => {
                        problems.push(AccessProblem::BadName {
                            name: table_text.clone(),
                            why: error.to_string(),
                        });
                        continue;
                    }
                };
                if !database.schemas.contains(&schema) {
                    problems.push(AccessProblem::UndeclaredSchema {
                        table: label.clone(),
                    });
                    continue;
                }

                let rls = match by_role.get(RLS_KEY).map(String::as_str) {
                    None => Rls::On,
                    Some(text) => match text.strip_prefix("off:").map(str::trim) {
                        Some(reason) if !reason.is_empty() => Rls::Off {
                            reason: reason.to_owned(),
                        },
                        _ => {
                            problems.push(AccessProblem::BadRls {
                                table: label.clone(),
                                text: text.to_owned(),
                            });
                            Rls::On
                        }
                    },
                };

                let mut roles = BTreeMap::new();
                for (role_text, grant_text) in
                    by_role.iter().filter(|(key, _)| key.as_str() != RLS_KEY)
                {
                    let Some(role) = database
                        .roles
                        .iter()
                        .find(|role| role.as_str() == role_text)
                    else {
                        problems.push(AccessProblem::UndeclaredRole {
                            table: label.clone(),
                            role: role_text.clone(),
                        });
                        continue;
                    };
                    match Grant::parse(grant_text) {
                        Some(grant) => {
                            if grant.uses_own() && rls != Rls::On {
                                problems.push(AccessProblem::OwnNeedsRls {
                                    table: label.clone(),
                                    role: role.clone(),
                                });
                            }
                            roles.insert(role.clone(), grant);
                        }
                        None => problems.push(AccessProblem::BadGrant {
                            table: label.clone(),
                            role: role_text.clone(),
                            text: grant_text.clone(),
                        }),
                    }
                }
                for role in &database.roles {
                    if !by_role.contains_key(role.as_str()) {
                        problems.push(AccessProblem::MissingRole {
                            table: label.clone(),
                            role: role.clone(),
                        });
                    }
                }

                tables.insert(TableRef { schema, table }, TableAccess { rls, roles });
            }
        }

        if problems.is_empty() {
            Ok(Self { tables })
        } else {
            Err(problems)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::Manifest;

    pub(crate) const MANIFEST: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build"
start = "npm run start"
path = "/"
roles = ["employee", "manager", "payroll_admin"]

[database]
schemas = ["hr", "payroll"]
roles = ["employee", "manager", "payroll_admin"]
"#;

    pub(crate) const ACCESS: &str = r#"
[payroll.payslip]
employee = "read own"
manager = "none"
payroll_admin = "read write"

[hr.department]
rls = "off: 모든 직원이 보는 부서 목록"
employee = "read"
manager = "read"
payroll_admin = "read write"
"#;

    pub(crate) fn manifest() -> ValidManifest {
        toml::from_str::<Manifest>(MANIFEST)
            .unwrap()
            .check()
            .unwrap()
    }

    pub(crate) fn access(text: &str) -> Result<Access, Vec<AccessProblem>> {
        Access::parse(&toml::from_str::<RawAccess>(text).unwrap(), &manifest())
    }

    pub(crate) fn ident(text: &str) -> Ident {
        Ident::parse(text).unwrap()
    }

    pub(crate) fn table(schema: &str, name: &str) -> TableRef {
        TableRef {
            schema: ident(schema),
            table: ident(name),
        }
    }

    #[test]
    fn 권한의_말은_다섯_가지만_받는다() {
        assert_eq!(Grant::parse("none"), Some(Grant::NONE));
        assert_eq!(
            Grant::parse("read"),
            Some(Grant {
                read: Reach::All,
                write: Reach::None
            })
        );
        assert_eq!(
            Grant::parse("read own"),
            Some(Grant {
                read: Reach::Own,
                write: Reach::None
            })
        );
        assert_eq!(
            Grant::parse("read write"),
            Some(Grant {
                read: Reach::All,
                write: Reach::All
            })
        );
        assert_eq!(
            Grant::parse("read write own"),
            Some(Grant {
                read: Reach::Own,
                write: Reach::Own
            })
        );
        for other in ["", "write", "all", "read  own  write", "READ", "owner"] {
            assert_eq!(Grant::parse(other), None, "{other}");
        }
    }

    #[test]
    fn 읽기만_주면_select_만_쓰기까지_주면_네_권한을_준다() {
        assert_eq!(Grant::NONE.privileges(), vec![]);
        assert_eq!(
            Grant::parse("read own").unwrap().privileges(),
            vec![Privilege::Select]
        );
        assert_eq!(
            Grant::parse("read write").unwrap().privileges(),
            vec![
                Privilege::Select,
                Privilege::Insert,
                Privilege::Update,
                Privilege::Delete
            ]
        );
    }

    #[test]
    fn 표마다_역할마다의_권한을_읽는다() {
        let access = access(ACCESS).unwrap();
        assert_eq!(
            access
                .grant(&table("payroll", "payslip"), &ident("employee"))
                .read,
            Reach::Own
        );
        assert_eq!(
            access.grant(&table("payroll", "payslip"), &ident("manager")),
            Grant::NONE
        );
        assert_eq!(
            access
                .grant(&table("hr", "department"), &ident("payroll_admin"))
                .write,
            Reach::All
        );
        assert_eq!(
            access.tables[&table("hr", "department")].rls,
            Rls::Off {
                reason: "모든 직원이 보는 부서 목록".to_owned()
            }
        );
    }

    #[test]
    fn 적지_않은_표는_어떤_역할에게도_권한이_없다() {
        let access = access(ACCESS).unwrap();
        assert_eq!(
            access.grant(&table("payroll", "bonus"), &ident("payroll_admin")),
            Grant::NONE
        );
    }

    #[test]
    fn 표에_빠진_역할이_있으면_받지_않는다() {
        let text = ACCESS.replace("manager = \"none\"\n", "");
        assert_eq!(
            access(&text),
            Err(vec![AccessProblem::MissingRole {
                table: "payroll.payslip".to_owned(),
                role: ident("manager")
            }])
        );
    }

    #[test]
    fn 선언하지_않은_스키마와_역할은_받지_않는다() {
        let schema = ACCESS.replace("[payroll.payslip]", "[finance.payslip]");
        assert_eq!(
            access(&schema),
            Err(vec![AccessProblem::UndeclaredSchema {
                table: "finance.payslip".to_owned()
            }])
        );
        let role = ACCESS.replace(
            "manager = \"none\"",
            "manager = \"none\"\nauditor = \"read\"",
        );
        assert_eq!(
            access(&role),
            Err(vec![AccessProblem::UndeclaredRole {
                table: "payroll.payslip".to_owned(),
                role: "auditor".to_owned()
            }])
        );
    }

    #[test]
    fn 읽지_못한_말은_까닭과_함께_돌려준다() {
        let text = ACCESS.replace("employee = \"read own\"", "employee = \"read mine\"");
        assert_eq!(
            access(&text),
            Err(vec![AccessProblem::BadGrant {
                table: "payroll.payslip".to_owned(),
                role: "employee".to_owned(),
                text: "read mine".to_owned()
            }])
        );
    }

    #[test]
    fn 행_단위_규칙을_끄려면_까닭을_적어야_한다() {
        for bad in ["off", "off:", "off:   ", "false"] {
            let text = ACCESS.replace(
                "rls = \"off: 모든 직원이 보는 부서 목록\"",
                &format!("rls = \"{bad}\""),
            );
            assert_eq!(
                access(&text),
                Err(vec![AccessProblem::BadRls {
                    table: "hr.department".to_owned(),
                    text: bad.to_owned()
                }]),
                "{bad}"
            );
        }
    }

    #[test]
    fn 행_단위_규칙을_끈_표에는_자기_행만을_적지_못한다() {
        let text = ACCESS.replace("employee = \"read\"", "employee = \"read own\"");
        assert_eq!(
            access(&text),
            Err(vec![AccessProblem::OwnNeedsRls {
                table: "hr.department".to_owned(),
                role: ident("employee")
            }])
        );
    }

    #[test]
    fn 표의_이름에_따옴표나_대문자가_있으면_받지_않는다() {
        let text = ACCESS.replace("[payroll.payslip]", "[payroll.\"pay;drop\"]");
        assert!(matches!(
            access(&text).unwrap_err().as_slice(),
            [AccessProblem::BadName { .. }]
        ));
    }
}
