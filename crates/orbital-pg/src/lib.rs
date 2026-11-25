//! Postgres 어댑터.
//!
//! core 의 계획([`Step`])을 실제 DB 에 실행하고, 실제 DB 의 모습을 읽어 core 의 검사([`Snapshot`])에 넘긴다.
//! 「맞는가」는 여기서 따지지 않는다. 판정은 core 가 한다.
//!
//! 관리 연결([`Admin`])은 레이어만 갖는다. 에이전트의 토큰으로는 이 연결에 닿지 못한다.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use orbital_core::access::{Access, Privilege};
use orbital_core::check::{Membership, RoleState, Snapshot, TableState};
use orbital_core::manifest::ValidManifest;
use orbital_core::name::{Ident, TableRef};
use orbital_core::plan::{Names, Place, Step, grants, provision};
use postgres::error::SqlState;
use postgres::{Client, Config, NoTls};

pub mod identity;
pub mod migrations;
pub mod rehearsal;

#[derive(Debug)]
pub enum Error {
    /// 접속 주소를 읽지 못했다.
    Url(String),
    /// Postgres 가 거절했다. `doing` 은 무엇을 하다 깨졌는지다.
    Pg {
        doing: &'static str,
        source: postgres::Error,
    },
    /// 원본 database 에 다른 연결이 있어 복제하지 못했다.
    Busy,
    /// 되돌릴 지점이 없다.
    NoSuchPoint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(why) => write!(f, "DB 의 주소를 읽지 못했습니다: {why}"),
            // Postgres 의 오류에서 SQLSTATE 만 싣는다. 문구와 DETAIL 에는 행의 값이 섞일 수 있다.
            Self::Pg { doing, source } => match source.code() {
                Some(code) => write!(
                    f,
                    "{doing} 하다가 DB 가 거절했습니다(SQLSTATE {})",
                    code.code()
                ),
                None => write!(f, "{doing} 하다가 DB 와의 연결이 끊겼습니다"),
            },
            Self::Busy => write!(
                f,
                "원본 database 에 다른 연결이 있어 복제하지 못했습니다. 잠시 뒤에 다시 해 주세요"
            ),
            Self::NoSuchPoint => write!(f, "되돌릴 지점이 없습니다"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn pg(doing: &'static str) -> impl FnOnce(postgres::Error) -> Error {
    move |source| Error::Pg { doing, source }
}

/// 이름은 모두 core 가 검증한 글자(소문자 · 숫자 · 밑줄)로만 지어진다.
pub(crate) fn quote(name: &str) -> String {
    format!("\"{name}\"")
}

/// 레이어의 관리 연결.
pub struct Admin {
    config: Config,
    cluster: Client,
}

impl Admin {
    /// 클러스터의 관리 역할로 붙는다. `url` 은 `postgres://사용자@주소:포트/postgres` 모양이다.
    pub fn connect(url: &str) -> Result<Self, Error> {
        let config: Config = url
            .parse()
            .map_err(|error: postgres::Error| Error::Url(error.to_string()))?;
        let cluster = config.connect(NoTls).map_err(pg("관리 연결을 여"))?;
        Ok(Self { config, cluster })
    }

    /// 관리 역할로 database 하나에 붙는다.
    pub(crate) fn database(&self, name: &str) -> Result<Client, Error> {
        self.config
            .clone()
            .dbname(name)
            .connect(NoTls)
            .map_err(pg("database 에 붙"))
    }

    /// 어떤 역할로 database 에 붙어 본다. 운영에서는 proxy 만 이 길을 갖는다. 테스트가 「그 역할로 해 봤을 때」를 재는 데 쓴다.
    pub fn connect_as(&self, database: &str, role: &str) -> Result<Client, postgres::Error> {
        self.config
            .clone()
            .dbname(database)
            .user(role)
            .connect(NoTls)
    }

    fn role_exists(&mut self, name: &str) -> Result<bool, Error> {
        let row = self
            .cluster
            .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&name])
            .map_err(pg("역할을 찾"))?;
        Ok(row.is_some())
    }

    fn database_exists(&mut self, name: &str) -> Result<bool, Error> {
        let row = self
            .cluster
            .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&name])
            .map_err(pg("database 를 찾"))?;
        Ok(row.is_some())
    }

    /// 단계를 실행한다. 이미 있는 역할 · database · 스키마는 건너뛴다. 그래서 같은 계획을 다시 돌려도 된다.
    fn run(&mut self, names: &Names, steps: &[Step]) -> Result<(), Error> {
        let mut inside: Option<Client> = None;
        for step in steps {
            match step.place() {
                Place::Cluster => {
                    let skip = match step {
                        Step::CreateRole { name, .. } => self.role_exists(name)?,
                        Step::CreateDatabase { name } => self.database_exists(name)?,
                        _ => false,
                    };
                    if !skip {
                        self.cluster
                            .batch_execute(&step.sql())
                            .map_err(pg("역할과 database 를 세우"))?;
                    }
                }
                Place::Database => {
                    if inside.is_none() {
                        inside = Some(self.database(&names.database())?);
                    }
                    let client = inside.as_mut().expect("바로 위에서 채웠다");
                    if let Step::CreateSchema { schema, .. } = step {
                        let found = client
                            .query_opt(
                                "SELECT 1 FROM pg_namespace WHERE nspname = $1",
                                &[&schema.as_str()],
                            )
                            .map_err(pg("스키마를 찾"))?;
                        if found.is_some() {
                            continue;
                        }
                    }
                    client
                        .batch_execute(&step.sql())
                        .map_err(pg("스키마와 권한을 세우"))?;
                }
            }
        }
        Ok(())
    }

    /// 인스턴스를 세운다. 역할, database, 스키마까지다.
    pub fn provision(&mut self, names: &Names, manifest: &ValidManifest) -> Result<(), Error> {
        self.run(names, &provision(names, manifest))
    }

    /// 마이그레이션을 돌린다. 마이그레이션 역할로 들어가 소유자가 되어 실행하므로, 만든 표는 소유자의 것이 된다.
    pub fn migrate(&mut self, names: &Names, migrations: &[&str]) -> Result<(), Error> {
        let mut client = self
            .connect_as(&names.database(), &names.migrator())
            .map_err(pg("마이그레이션 역할로 붙"))?;
        client
            .batch_execute(&format!("SET ROLE {}", quote(&names.owner())))
            .map_err(pg("소유자가 되"))?;
        for migration in migrations {
            let mut transaction = client.transaction().map_err(pg("마이그레이션을 시작"))?;
            transaction
                .batch_execute(migration)
                .map_err(pg("마이그레이션을 실행"))?;
            transaction.commit().map_err(pg("마이그레이션을 마무리"))?;
        }
        Ok(())
    }

    /// 선언한 스키마에 실제로 있는 표.
    pub fn tables(
        &mut self,
        names: &Names,
        manifest: &ValidManifest,
    ) -> Result<Vec<TableRef>, Error> {
        let mut client = self.database(&names.database())?;
        let rows = client
            .query(
                "SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE c.relkind IN ('r', 'p') ORDER BY 1, 2",
                &[],
            )
            .map_err(pg("표의 목록을 읽"))?;
        let declared = &manifest.get().database.schemas;
        let mut tables = Vec::new();
        for row in rows {
            let (schema, table): (String, String) = (row.get(0), row.get(1));
            let Some(schema) = declared
                .iter()
                .find(|candidate| candidate.as_str() == schema)
            else {
                continue;
            };
            // 이름이 규칙에 맞지 않는 표는 계획에 넣지 않는다. 권한 검사가 「권한 표에 없는 표」로 잡는다.
            if let Ok(table) = Ident::parse(&table) {
                tables.push(TableRef {
                    schema: schema.clone(),
                    table,
                });
            }
        }
        Ok(tables)
    }

    /// 권한 표대로 권한을 다시 세운다. 마이그레이션 뒤에 부른다.
    pub fn grant(
        &mut self,
        names: &Names,
        manifest: &ValidManifest,
        access: &Access,
    ) -> Result<(), Error> {
        let tables = self.tables(names, manifest)?;
        self.run(names, &grants(names, manifest, access, &tables))
    }

    /// 실제 DB 의 모습을 읽는다. core 의 `check::judge` 에 넘긴다.
    pub fn snapshot(&mut self, names: &Names) -> Result<Snapshot, Error> {
        let mut client = self.database(&names.database())?;
        let reading = "DB 의 모습을 읽";

        let schemas = client
            .query(
                "SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' ORDER BY 1",
                &[],
            )
            .map_err(pg(reading))?
            .iter()
            .map(|row| row.get(0))
            .collect();

        let mut tables: BTreeMap<(String, String), TableState> = BTreeMap::new();
        let rows = client
            .query(
                "SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner), c.relrowsecurity \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE c.relkind IN ('r', 'p') AND n.nspname !~ '^pg_' AND n.nspname NOT IN ('information_schema', 'orbital')",
                &[],
            )
            .map_err(pg(reading))?;
        for row in rows {
            let (schema, table): (String, String) = (row.get(0), row.get(1));
            tables.insert(
                (schema.clone(), table.clone()),
                TableState {
                    schema,
                    table,
                    owner: row.get(2),
                    rls: row.get(3),
                    privileges: BTreeMap::new(),
                },
            );
        }
        // 권한을 받은 쪽이 0 이면 누구나(PUBLIC)다
        let rows = client
            .query(
                "SELECT n.nspname, c.relname, COALESCE(r.rolname, 'public'), a.privilege_type \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a \
                 LEFT JOIN pg_roles r ON r.oid = a.grantee \
                 WHERE c.relkind IN ('r', 'p') AND n.nspname !~ '^pg_' AND n.nspname NOT IN ('information_schema', 'orbital')",
                &[],
            )
            .map_err(pg(reading))?;
        for row in rows {
            let key: (String, String) = (row.get(0), row.get(1));
            let (grantee, privilege): (String, String) = (row.get(2), row.get(3));
            let (Some(state), Some(privilege)) =
                (tables.get_mut(&key), Privilege::from_sql(&privilege))
            else {
                continue;
            };
            state
                .privileges
                .entry(grantee)
                .or_insert_with(BTreeSet::new)
                .insert(privilege);
        }

        let prefix = format!("{}_", names.prefix());
        let roles = client
            .query(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls \
                 FROM pg_roles WHERE left(rolname, length($1)) = $1 ORDER BY 1",
                &[&prefix],
            )
            .map_err(pg(reading))?
            .iter()
            .map(|row| RoleState {
                name: row.get(0),
                login: row.get(1),
                superuser: row.get(2),
                create_db: row.get(3),
                create_role: row.get(4),
                replication: row.get(5),
                bypass_rls: row.get(6),
            })
            .collect();

        let memberships = client
            .query(
                "SELECT g.rolname, m.rolname, a.inherit_option, a.set_option \
                 FROM pg_auth_members a JOIN pg_roles g ON g.oid = a.roleid JOIN pg_roles m ON m.oid = a.member \
                 WHERE left(g.rolname, length($1)) = $1 OR left(m.rolname, length($1)) = $1 ORDER BY 1, 2",
                &[&prefix],
            )
            .map_err(pg(reading))?
            .iter()
            .map(|row| Membership { group: row.get(0), member: row.get(1), inherit: row.get(2), set: row.get(3) })
            .collect();

        let public_can_connect: bool = client
            .query_one(
                "SELECT has_database_privilege('public', current_database(), 'CONNECT')",
                &[],
            )
            .map_err(pg(reading))?
            .get(0);

        Ok(Snapshot {
            schemas,
            tables: tables.into_values().collect(),
            roles,
            memberships,
            public_can_connect,
        })
    }

    /// 이 인스턴스의 머리말을 가진 database(본체 · 사본 · 되돌릴 지점)의 이름.
    pub(crate) fn databases(&mut self, names: &Names) -> Result<Vec<String>, Error> {
        let prefix = names.prefix();
        let rows = self
            .cluster
            .query(
                "SELECT datname FROM pg_database WHERE datname = $1 OR left(datname, length($1) + 1) = $1 || '_' ORDER BY 1",
                &[&prefix],
            )
            .map_err(pg("database 의 목록을 읽"))?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    /// 인스턴스를 걷는다. database 와 사본, 역할을 모두 지운다. 되돌릴 수 없다.
    pub fn destroy(&mut self, names: &Names) -> Result<(), Error> {
        for database in self.databases(names)? {
            self.cluster
                .batch_execute(&format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    quote(&database)
                ))
                .map_err(pg("database 를 지우"))?;
        }
        let prefix = format!("{}_", names.prefix());
        let roles = self
            .cluster
            .query(
                "SELECT rolname FROM pg_roles WHERE left(rolname, length($1)) = $1",
                &[&prefix],
            )
            .map_err(pg("역할의 목록을 읽"))?;
        for row in roles {
            let role: String = row.get(0);
            self.cluster
                .batch_execute(&format!("DROP ROLE IF EXISTS {}", quote(&role)))
                .map_err(pg("역할을 지우"))?;
        }
        Ok(())
    }
}

/// Postgres 의 오류가 「다른 연결이 쓰고 있다」인가.
pub(crate) fn is_busy(error: &postgres::Error) -> bool {
    error.code() == Some(&SqlState::OBJECT_IN_USE)
}
