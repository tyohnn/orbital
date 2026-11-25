//! 예행연습과 되돌릴 지점. 둘 다 운영 database 의 복제로 한다.
//!
//! 복제는 PostgreSQL 18 부터 있는 `STRATEGY = FILE_COPY` 를 쓴다. 블록을 나눠 쓰는 파일시스템(XFS 같은)에서는 크기와 거의 무관하게 끝난다.
//! 사본은 만들자마자 아무도 접속하지 못하게 막는다. 인스턴스의 로그인도, 에이전트의 토큰도 닿지 못한다.
//!
//! 예행연습이 돌려주는 것은 숫자뿐이다. 통과했는지, 얼마나 걸렸는지, 몇 번째에서 멈췄는지, 표마다 행이 몇 개인지다.
//! Postgres 의 오류 문구는 싣지 않는다. 문구와 DETAIL 에 행의 값이 섞일 수 있어서 SQLSTATE 만 싣는다.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use orbital_core::manifest::ValidManifest;
use orbital_core::plan::{Names, Step, logins};

use crate::{Admin, Error, is_busy, pg, quote};

/// 표 하나의 행 수. 마이그레이션이 표를 지웠으면 `after` 가 없다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCount {
    pub table: String,
    pub before: Option<i64>,
    pub after: Option<i64>,
}

/// 예행연습의 결과. 행의 내용은 어디에도 없다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rehearsal {
    pub passed: bool,
    pub millis: u64,
    /// 실패했다면 몇 번째 마이그레이션에서 멈췄는가(0부터).
    pub failed_at: Option<usize>,
    /// 실패했다면 Postgres 의 SQLSTATE.
    pub sqlstate: Option<String>,
    pub tables: Vec<TableCount>,
}

/// 승격 직전의 운영 DB 를 떠 둔 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    database: String,
}

impl RestorePoint {
    /// 적어 둔 이름에서 되돌릴 지점을 다시 가리킨다. 그 이름의 database 가 없으면 `restore` 가 없다고 답한다.
    pub fn named(database: impl Into<String>) -> Self {
        Self {
            database: database.into(),
        }
    }

    pub fn database(&self) -> &str {
        &self.database
    }
}

/// 사본의 이름에 붙일 꼬리. 같은 인스턴스에서 겹치지 않으면 된다.
fn suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut rest = nanos % 36u128.pow(10);
    let mut text = String::new();
    while rest > 0 {
        text.push(char::from_digit((rest % 36) as u32, 36).expect("36 보다 작다"));
        rest /= 36;
    }
    text
}

fn counts(client: &mut postgres::Client) -> Result<Vec<(String, i64)>, Error> {
    let rows = client
        .query(
            "SELECT n.nspname || '.' || c.relname, format('%I.%I', n.nspname, c.relname) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r', 'p') AND n.nspname !~ '^pg_' AND n.nspname NOT IN ('information_schema', 'orbital') \
             ORDER BY 1",
            &[],
        )
        .map_err(pg("표의 목록을 읽"))?;
    let mut found = Vec::new();
    for row in rows {
        let (label, quoted): (String, String) = (row.get(0), row.get(1));
        let count: i64 = client
            .query_one(&format!("SELECT count(*) FROM {quoted}"), &[])
            .map_err(pg("행의 수를 세"))?
            .get(0);
        found.push((label, count));
    }
    Ok(found)
}

impl Admin {
    /// database 를 복제한다. 사본에는 아무도 접속하지 못한다.
    fn clone_database(&mut self, source: &str, target: &str) -> Result<(), Error> {
        let create = format!(
            "CREATE DATABASE {} TEMPLATE {} STRATEGY = FILE_COPY ALLOW_CONNECTIONS = false",
            quote(target),
            quote(source)
        );
        match self.cluster.batch_execute(&create) {
            Ok(()) => {}
            Err(error) if is_busy(&error) => return Err(Error::Busy),
            Err(error) => return Err(pg("database 를 복제")(error)),
        }
        // database 의 접속 권한은 복제되지 않아서, 사본은 누구나 접속할 수 있는 채로 생긴다. 문을 열기 전에 걷는다
        self.cluster
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE {} FROM PUBLIC",
                quote(target)
            ))
            .map_err(pg("사본의 권한을 걷"))
    }

    fn open(&mut self, database: &str, open: bool) -> Result<(), Error> {
        self.cluster
            .batch_execute(&format!(
                "ALTER DATABASE {} ALLOW_CONNECTIONS {open}",
                quote(database)
            ))
            .map_err(pg("database 의 문을 여닫"))
    }

    fn drop_database(&mut self, database: &str) -> Result<(), Error> {
        self.cluster
            .batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote(database)
            ))
            .map_err(pg("database 를 지우"))
    }

    /// 운영 DB 의 문을 닫고 붙어 있는 연결을 끊는다. 복제는 원본에 다른 연결이 없어야 한다.
    ///
    /// 닫혀 있는 동안 앱의 요청은 DB 에 붙지 못한다. 복제가 끝나면 곧바로 [`Admin::resume`] 으로 연다.
    /// proxy 가 요청을 붙잡아 주기 전까지의 모양이다.
    pub fn quiesce(&mut self, names: &Names) -> Result<(), Error> {
        let database = names.database();
        self.open(&database, false)?;
        self.cluster
            .execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
                &[&database],
            )
            .map_err(pg("운영 DB 의 연결을 끊"))?;
        Ok(())
    }

    /// 닫았던 운영 DB 의 문을 다시 연다.
    pub fn resume(&mut self, names: &Names) -> Result<(), Error> {
        self.open(&names.database(), true)
    }

    /// 운영 DB 의 사본에 마이그레이션을 미리 돌려 본다. 운영은 건드리지 않고, 사본은 끝나면 지운다.
    pub fn rehearse(&mut self, names: &Names, migrations: &[&str]) -> Result<Rehearsal, Error> {
        let copy = format!("{}_reh_{}", names.prefix(), suffix());
        self.clone_database(&names.database(), &copy)?;
        let result = self.rehearse_in(names, &copy, migrations);
        // 예행연습이 어떻게 끝났든 사본은 지운다
        self.drop_database(&copy)?;
        result
    }

    fn rehearse_in(
        &mut self,
        names: &Names,
        copy: &str,
        migrations: &[&str],
    ) -> Result<Rehearsal, Error> {
        // 사본의 문을 열고 마이그레이션 역할에게만 접속을 준다. 그 역할로는 레이어만 들어간다.
        // 관리 연결에서 역할만 바꿔 돌리지 않는다. 그러면 마이그레이션이 `RESET ROLE` 한 줄로 관리 권한을 되찾는다.
        self.open(copy, true)?;
        self.cluster
            .batch_execute(&format!(
                "GRANT CONNECT ON DATABASE {} TO {}",
                quote(copy),
                quote(&names.migrator())
            ))
            .map_err(pg("사본의 문을 여"))?;
        let before = counts(&mut self.database(copy)?)?;
        let mut client = self
            .connect_as(copy, &names.migrator())
            .map_err(pg("마이그레이션 역할로 사본에 붙"))?;
        client
            .batch_execute(&format!("SET ROLE {}", quote(&names.owner())))
            .map_err(pg("소유자가 되"))?;

        let started = Instant::now();
        let mut failure = None;
        for (index, migration) in migrations.iter().enumerate() {
            let mut transaction = client.transaction().map_err(pg("예행연습을 시작"))?;
            if let Err(error) = transaction
                .batch_execute(migration)
                .and_then(|()| transaction.commit())
            {
                failure = Some((index, error.code().map(|code| code.code().to_owned())));
                break;
            }
        }
        let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        drop(client);
        let after = counts(&mut self.database(copy)?)?;
        let mut tables: Vec<TableCount> = before
            .iter()
            .map(|(table, count)| TableCount {
                table: table.clone(),
                before: Some(*count),
                after: after
                    .iter()
                    .find(|(name, _)| name == table)
                    .map(|(_, count)| *count),
            })
            .collect();
        for (table, count) in &after {
            if !before.iter().any(|(name, _)| name == table) {
                tables.push(TableCount {
                    table: table.clone(),
                    before: None,
                    after: Some(*count),
                });
            }
        }

        Ok(Rehearsal {
            passed: failure.is_none(),
            millis,
            failed_at: failure.as_ref().map(|(index, _)| *index),
            sqlstate: failure.and_then(|(_, code)| code),
            tables,
        })
    }

    /// 지금의 운영 DB 를 되돌릴 지점으로 떠 둔다. 승격 직전에 부른다.
    pub fn mark(&mut self, names: &Names) -> Result<RestorePoint, Error> {
        let database = format!("{}_rp_{}", names.prefix(), suffix());
        self.clone_database(&names.database(), &database)?;
        Ok(RestorePoint { database })
    }

    /// 되돌릴 지점으로 돌아간다. 지점을 뜬 뒤에 쓴 데이터는 사라진다.
    ///
    /// 운영 DB 의 연결을 모두 끊고, 이름을 바꿔 지점을 운영 자리에 놓는다. database 의 접속 권한은 복제되지 않으므로 선언대로 다시 준다.
    pub fn restore(
        &mut self,
        names: &Names,
        manifest: &ValidManifest,
        point: &RestorePoint,
    ) -> Result<(), Error> {
        if !self.databases(names)?.contains(&point.database) {
            return Err(Error::NoSuchPoint);
        }
        let live = names.database();
        let aside = format!("{}_old_{}", names.prefix(), suffix());

        self.open(&live, false)?;
        self.cluster
            .execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
                &[&live],
            )
            .map_err(pg("운영 DB 의 연결을 끊"))?;
        let rename = |from: &str, to: &str| {
            format!("ALTER DATABASE {} RENAME TO {}", quote(from), quote(to))
        };
        self.cluster
            .batch_execute(&rename(&live, &aside))
            .map_err(pg("운영 DB 를 옆으로 치우"))?;
        self.cluster
            .batch_execute(&rename(&point.database, &live))
            .map_err(pg("되돌릴 지점을 운영 자리에 놓"))?;

        let mut steps = vec![Step::GrantConnect {
            database: live.clone(),
            role: names.migrator(),
        }];
        steps.extend(
            logins(names, manifest)
                .into_iter()
                .map(|login| Step::GrantConnect {
                    database: live.clone(),
                    role: login.name,
                }),
        );
        for step in steps {
            self.cluster
                .batch_execute(&step.sql())
                .map_err(pg("접속 권한을 다시 주"))?;
        }
        self.open(&live, true)?;
        self.drop_database(&aside)
    }

    /// 쓰지 않게 된 되돌릴 지점을 지운다.
    pub fn forget(&mut self, point: RestorePoint) -> Result<(), Error> {
        self.drop_database(&point.database)
    }
}
