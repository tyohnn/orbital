//! 실제 PostgreSQL 에 인스턴스를 세워 재는 테스트(사다리 3단계).
//!
//! 「못 한다」는 권한을 조회해서가 아니라, 그 역할로 접속해 해 봤을 때 거절되는 것으로 잰다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. `scripts/pg-local.sh` 가 띄우고 주소를 찍는다.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use orbital_core::access::{Access, Privilege, RawAccess};
use orbital_core::check::{Finding, judge};
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::{Ident, InstanceId, TableRef};
use orbital_core::plan::Names;
use orbital_pg::identity::{Claims, sign};
use orbital_pg::{Admin, Error};
use postgres::Client;
use postgres::error::SqlState;

const MANIFEST: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build -w api"
start = "npm run start -w api"
path = "/api"
roles = ["employee", "manager", "payroll_admin"]

[[service]]
name = "web"
kind = "server"
build = "npm run build -w web"
start = "npm run start -w web"
path = "/"
roles = ["employee"]

[database]
schemas = ["hr", "payroll"]
roles = ["employee", "manager", "payroll_admin"]
"#;

const ACCESS: &str = r#"
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

/// 스캐폴드의 마이그레이션. 인스턴스의 식별자를 모른다. 행 단위 규칙은 `orbital.role()` 과 `orbital.subject()` 로 가른다.
const MIGRATION: &str = r#"
CREATE TABLE hr.department (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text NOT NULL);
CREATE TABLE payroll.payslip (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee text NOT NULL,
    amount int NOT NULL
);
ALTER TABLE payroll.payslip ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON payroll.payslip FOR SELECT
    USING ((SELECT orbital.role()) = 'employee' AND employee = (SELECT orbital.subject()));
CREATE POLICY admin ON payroll.payslip
    USING ((SELECT orbital.role()) = 'payroll_admin') WITH CHECK ((SELECT orbital.role()) = 'payroll_admin');
INSERT INTO hr.department (name) VALUES ('인사'), ('재무');
INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_1', 100), ('emp_1', 110), ('emp_2', 200);
"#;

const KEY: &[u8] = b"test-signing-key-not-a-real-secret";
/// 테스트의 신원에 싣는 업무 역할. 선언의 역할을 모두 싣는다(역할을 견주는 일은 `roles.rs` 가 잰다).
const ROLES: [&str; 3] = ["employee", "manager", "payroll_admin"];
const FAR_FUTURE: u64 = 4_000_000_000;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 테스트마다 새로 짓는 식별자. 서로 섞이지 않는다.
fn fresh_id() -> InstanceId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut rest = (nanos % 36u128.pow(8)) as u64 * 1296
        + u64::from(COUNTER.fetch_add(1, Ordering::Relaxed) % 1296);
    let mut text = String::from("t");
    for _ in 0..10 {
        text.push(char::from_digit((rest % 36) as u32, 36).unwrap());
        rest /= 36;
    }
    InstanceId::parse(&text).unwrap()
}

fn ident(text: &str) -> Ident {
    Ident::parse(text).unwrap()
}

fn access(manifest: &ValidManifest, text: &str) -> Access {
    Access::parse(&toml::from_str::<RawAccess>(text).unwrap(), manifest).unwrap()
}

/// 세워 둔 인스턴스 하나. 테스트가 끝나면 걷는다.
struct Bench {
    admin: Admin,
    names: Names,
    manifest: ValidManifest,
    access: Access,
}

impl Bench {
    fn new() -> Option<Self> {
        let url = std::env::var("ORBITAL_PG").ok()?;
        let mut admin = Admin::connect(&url).expect("ORBITAL_PG 에 붙지 못했습니다");
        let names = Names::new(fresh_id());
        let manifest = toml::from_str::<Manifest>(MANIFEST)
            .unwrap()
            .check()
            .unwrap();
        let access = access(&manifest, ACCESS);
        admin.provision(&names, &manifest).unwrap();
        // 세우다가 깨져도 걷히도록, 여기부터는 다 지은 값 위에서 세운다(값이 떨어질 때 `Drop` 이 걷는다)
        let mut bench = Self {
            admin,
            names,
            manifest,
            access,
        };
        let (admin, names, manifest) = (&mut bench.admin, &bench.names, &bench.manifest);
        admin.install_identity(names, KEY).unwrap();
        admin.migrate(names, &[MIGRATION]).unwrap();
        admin.grant(names, manifest, &bench.access).unwrap();
        Some(bench)
    }

    /// 서비스가 업무 역할로 들어간 연결.
    fn login(&self, service: &str, role: &str) -> Client {
        self.admin
            .connect_as(
                &self.names.database(),
                &self.names.login(&ident(service), &ident(role)),
            )
            .unwrap()
    }

    /// 관리 역할로 인스턴스의 database 에 들어간 연결. 검사가 잡아야 하는 어긋남을 일부러 만드는 데 쓴다.
    fn superuser(&self) -> Client {
        self.admin
            .connect_as(&self.names.database(), "postgres")
            .unwrap()
    }

    fn findings(&mut self) -> Vec<Finding> {
        let snapshot = self.admin.snapshot(&self.names).unwrap();
        judge(&self.names, &self.manifest, &self.access, &snapshot)
    }

    fn identity(&self, subject: &str) -> String {
        sign(
            KEY,
            &self.names,
            &Claims {
                subject: Some(subject.to_owned()),
                roles: ROLES.iter().map(|role| (*role).to_owned()).collect(),
                session: None,
                client: None,
                expires_at: FAR_FUTURE,
            },
        )
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = self.admin.destroy(&self.names);
    }
}

macro_rules! bench {
    () => {
        match Bench::new() {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn denied(result: Result<u64, postgres::Error>) -> bool {
    matches!(result, Err(error) if error.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE))
}

/// 신원을 실은 트랜잭션에서 급여 명세의 주인들을 읽는다.
fn payslip_owners(client: &mut Client, identity: Option<&str>) -> Vec<String> {
    let mut transaction = client.transaction().unwrap();
    if let Some(identity) = identity {
        transaction
            .execute(
                "SELECT set_config('orbital.identity', $1, true)",
                &[&identity],
            )
            .unwrap();
    }
    let rows = transaction
        .query("SELECT employee FROM payroll.payslip ORDER BY id", &[])
        .unwrap();
    rows.iter().map(|row| row.get(0)).collect()
}

// ---- 역할과 권한 ----

#[test]
fn 계획대로_세운_실제_db_는_권한_검사를_통과한다() {
    let mut bench = bench!();
    assert_eq!(bench.findings(), vec![]);
}

#[test]
fn 같은_계획을_두_번_세워도_된다() {
    let mut bench = bench!();
    bench
        .admin
        .provision(&bench.names, &bench.manifest)
        .unwrap();
    bench
        .admin
        .grant(&bench.names, &bench.manifest, &bench.access)
        .unwrap();
    assert_eq!(bench.findings(), vec![]);
}

#[test]
fn 업무_역할은_다른_업무_역할로_바꿔_타지_못한다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    for target in [
        bench.names.group(&ident("payroll_admin")),
        bench.names.group(&ident("employee")),
        bench.names.owner(),
        bench.names.migrator(),
        bench.names.login(&ident("api"), &ident("payroll_admin")),
    ] {
        assert!(
            denied(employee.execute(&format!("SET ROLE \"{target}\""), &[])),
            "{target}"
        );
        assert!(
            denied(employee.execute(&format!("SET SESSION AUTHORIZATION \"{target}\""), &[])),
            "{target}"
        );
    }
}

#[test]
fn 업무_역할은_표를_만들거나_고치지_못한다() {
    let bench = bench!();
    let mut admin = bench.login("api", "payroll_admin");
    for statement in [
        "CREATE TABLE hr.scratch (id int)",
        "CREATE TABLE public.scratch (id int)",
        "CREATE SCHEMA scratch",
        "ALTER TABLE payroll.payslip ADD COLUMN note text",
        "ALTER TABLE payroll.payslip DISABLE ROW LEVEL SECURITY",
        "DROP POLICY own ON payroll.payslip",
        "DROP TABLE payroll.payslip",
        "TRUNCATE payroll.payslip",
    ] {
        assert!(denied(admin.execute(statement, &[])), "{statement}");
    }
}

#[test]
fn 권한_표가_none_인_역할은_그_표를_읽지_못한다() {
    let bench = bench!();
    let mut manager = bench.login("api", "manager");
    assert!(denied(
        manager.execute("SELECT * FROM payroll.payslip", &[])
    ));
    // 부서 목록은 권한 표에 read 로 적혀 있다
    assert_eq!(
        manager
            .query("SELECT name FROM hr.department", &[])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn 읽기만_받은_역할은_쓰지_못하고_쓰기를_받은_역할은_쓴다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    assert!(denied(employee.execute(
        "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_1', 1)",
        &[]
    )));
    assert!(denied(
        employee.execute("UPDATE hr.department SET name = 'x'", &[])
    ));
    let mut admin = bench.login("api", "payroll_admin");
    assert_eq!(
        admin
            .execute(
                "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_3', 300)",
                &[]
            )
            .unwrap(),
        1
    );
}

#[test]
fn 서비스에_적지_않은_역할의_로그인은_db_에_없다() {
    let bench = bench!();
    let database = bench.names.database();
    // web 서비스는 employee 만 적었다
    assert!(
        bench
            .admin
            .connect_as(
                &database,
                &bench.names.login(&ident("web"), &ident("employee"))
            )
            .is_ok()
    );
    assert!(
        bench
            .admin
            .connect_as(
                &database,
                &bench.names.login(&ident("web"), &ident("payroll_admin"))
            )
            .is_err()
    );
}

#[test]
fn 소유자와_권한_묶음으로는_로그인하지_못한다() {
    let bench = bench!();
    let database = bench.names.database();
    assert!(
        bench
            .admin
            .connect_as(&database, &bench.names.owner())
            .is_err()
    );
    assert!(
        bench
            .admin
            .connect_as(&database, &bench.names.group(&ident("payroll_admin")))
            .is_err()
    );
}

#[test]
fn 한_인스턴스의_어떤_역할도_다른_인스턴스의_database_에_접속하지_못한다() {
    let ours = bench!();
    let theirs = bench!();
    let mut roles = vec![ours.names.migrator(), ours.names.owner()];
    for role in ["employee", "manager", "payroll_admin"] {
        roles.push(ours.names.login(&ident("api"), &ident(role)));
        roles.push(ours.names.group(&ident(role)));
    }
    for role in roles {
        assert!(
            theirs
                .admin
                .connect_as(&theirs.names.database(), &role)
                .is_err(),
            "{role}"
        );
    }
    // 제 database 에는 들어간다
    assert!(
        ours.admin
            .connect_as(
                &ours.names.database(),
                &ours.names.login(&ident("api"), &ident("employee"))
            )
            .is_ok()
    );
}

#[test]
fn 마이그레이션은_선언에_없는_스키마를_만들지_못한다() {
    let mut bench = bench!();
    let result = bench
        .admin
        .migrate(&bench.names, &["CREATE SCHEMA scratch"]);
    assert!(matches!(result, Err(Error::Pg { .. })));
    assert_eq!(bench.findings(), vec![]);
}

#[test]
fn 권한_표에_없는_grant_가_하나라도_있으면_검사가_실패한다() {
    let mut bench = bench!();
    let manager = bench.names.group(&ident("manager"));
    bench
        .superuser()
        .batch_execute(&format!("GRANT SELECT ON payroll.payslip TO \"{manager}\""))
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::PrivilegeExtra {
            table: TableRef {
                schema: ident("payroll"),
                table: ident("payslip")
            },
            role: ident("manager"),
            privilege: Privilege::Select
        }]
    );
}

#[test]
fn 누구나에게_준_권한도_검사가_잡는다() {
    let mut bench = bench!();
    bench
        .superuser()
        .batch_execute("GRANT SELECT ON hr.department TO PUBLIC")
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::UnexpectedGrantee {
            table: "hr.department".to_owned(),
            grantee: "public".to_owned()
        }]
    );
}

#[test]
fn 행_단위_규칙을_끈_표는_끈_까닭이_없으면_검사가_실패한다() {
    let mut bench = bench!();
    bench
        .superuser()
        .batch_execute("ALTER TABLE payroll.payslip DISABLE ROW LEVEL SECURITY")
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::RlsOff {
            table: TableRef {
                schema: ident("payroll"),
                table: ident("payslip")
            }
        }]
    );
}

#[test]
fn 권한_표에_없는_표를_마이그레이션이_만들면_검사가_실패하고_아무도_그_표를_읽지_못한다() {
    let mut bench = bench!();
    bench
        .admin
        .migrate(
            &bench.names,
            &["CREATE TABLE payroll.bonus (id int, employee text)"],
        )
        .unwrap();
    bench
        .admin
        .grant(&bench.names, &bench.manifest, &bench.access)
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::TableNotInAccess {
            table: "payroll.bonus".to_owned()
        }]
    );
    assert!(denied(
        bench
            .login("api", "payroll_admin")
            .execute("SELECT * FROM payroll.bonus", &[])
    ));
}

#[test]
fn 권한_표에서_권한을_빼고_다시_세우면_앞에서_준_권한이_사라진다() {
    let mut bench = bench!();
    let narrowed = ACCESS.replace(
        "payroll_admin = \"read write\"\n\n",
        "payroll_admin = \"read\"\n\n",
    );
    bench.access = access(&bench.manifest, &narrowed);
    bench
        .admin
        .grant(&bench.names, &bench.manifest, &bench.access)
        .unwrap();
    assert_eq!(bench.findings(), vec![]);
    let mut admin = bench.login("api", "payroll_admin");
    assert!(denied(admin.execute(
        "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_3', 300)",
        &[]
    )));
    assert_eq!(
        admin
            .query("SELECT 1 FROM payroll.payslip", &[])
            .unwrap()
            .len(),
        3
    );
}

// ---- 서명된 신원 ----

#[test]
fn 서명된_신원이_있으면_자기_행만_돌아온다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    assert_eq!(
        payslip_owners(&mut employee, Some(&bench.identity("emp_1"))),
        vec!["emp_1", "emp_1"]
    );
    assert_eq!(
        payslip_owners(&mut employee, Some(&bench.identity("emp_2"))),
        vec!["emp_2"]
    );
}

#[test]
fn 신원은_트랜잭션이_끝나면_남지_않는다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    assert_eq!(
        payslip_owners(&mut employee, Some(&bench.identity("emp_1"))).len(),
        2
    );
    // 같은 연결의 다음 트랜잭션은 신원을 다시 실어야 한다
    assert_eq!(payslip_owners(&mut employee, None), Vec::<String>::new());
}

#[test]
fn 서명이_없거나_틀린_신원으로는_어떤_행도_읽지_못한다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    let valid = bench.identity("emp_1");
    let wrong_key = sign(
        b"another-key",
        &bench.names,
        &Claims {
            subject: Some("emp_1".to_owned()),
            roles: ROLES.iter().map(|role| (*role).to_owned()).collect(),
            session: None,
            client: None,
            expires_at: FAR_FUTURE,
        },
    );
    // emp_2 의 내용에 emp_1 의 서명을 붙인다
    let other = bench.identity("emp_2");
    let spliced = format!(
        "v1.{}.{}",
        other.split('.').nth(1).unwrap(),
        valid.split('.').nth(2).unwrap()
    );
    let unsigned = format!("v1.{}.", other.split('.').nth(1).unwrap());

    assert_eq!(payslip_owners(&mut employee, None), Vec::<String>::new());
    for forged in [
        "", "emp_1", "v1.zz.zz", "v2.00.00", &wrong_key, &spliced, &unsigned,
    ] {
        assert_eq!(
            payslip_owners(&mut employee, Some(forged)),
            Vec::<String>::new(),
            "{forged}"
        );
    }
}

#[test]
fn 만료된_신원과_다른_인스턴스의_신원은_읽히지_않는다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    let expired = sign(
        KEY,
        &bench.names,
        &Claims {
            subject: Some("emp_1".to_owned()),
            roles: ROLES.iter().map(|role| (*role).to_owned()).collect(),
            session: None,
            client: None,
            expires_at: 1,
        },
    );
    assert_eq!(
        payslip_owners(&mut employee, Some(&expired)),
        Vec::<String>::new()
    );
    // 같은 열쇠로 서명했어도 다른 인스턴스의 것은 읽히지 않는다
    let elsewhere = Names::new(InstanceId::parse("zzzzzzzz").unwrap());
    let foreign = sign(
        KEY,
        &elsewhere,
        &Claims {
            subject: Some("emp_1".to_owned()),
            roles: ROLES.iter().map(|role| (*role).to_owned()).collect(),
            session: None,
            client: None,
            expires_at: FAR_FUTURE,
        },
    );
    assert_eq!(
        payslip_owners(&mut employee, Some(&foreign)),
        Vec::<String>::new()
    );
}

#[test]
fn 주입된_sql_이_신원의_값을_바꿔도_다른_사람이_되지_못한다() {
    let bench = bench!();
    let mut employee = bench.login("api", "employee");
    let mut transaction = employee.transaction().unwrap();
    transaction
        .execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&bench.identity("emp_1")],
        )
        .unwrap();
    // 여기부터는 주입된 SQL 이 할 법한 일이다. emp_2 인 척해 본다
    let claim = r#"{"iid":"x","sub":"emp_2","exp":4000000000}"#;
    let hex: String = claim.bytes().map(|byte| format!("{byte:02x}")).collect();
    transaction
        .execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&format!("v1.{hex}.00")],
        )
        .unwrap();
    let rows = transaction
        .query("SELECT employee FROM payroll.payslip", &[])
        .unwrap();
    assert!(rows.is_empty(), "서명 없는 값으로 남의 행이 보였습니다");
    transaction
        .execute("SET LOCAL orbital.identity = 'emp_2'", &[])
        .unwrap();
    assert!(
        transaction
            .query("SELECT employee FROM payroll.payslip", &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn 업무_역할은_서명의_열쇠를_읽지_못하고_검증_함수를_바꾸지_못한다() {
    let bench = bench!();
    let mut employee = bench.login("api", "payroll_admin");
    assert!(denied(
        employee.execute("SELECT signing_key FROM orbital.instance", &[])
    ));
    assert!(denied(
        employee.execute("UPDATE orbital.instance SET signing_key = 'x'", &[])
    ));
    assert!(denied(employee.execute(
        "CREATE OR REPLACE FUNCTION orbital.subject() RETURNS text LANGUAGE sql AS $$ SELECT 'emp_2' $$",
        &[]
    )));
    assert!(denied(employee.execute(
        "CREATE FUNCTION orbital.x() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$",
        &[]
    )));
}

#[test]
fn 행_단위_규칙은_연결의_업무_역할을_안다() {
    let bench = bench!();
    // 급여 관리자는 신원 없이도 모든 행을 읽는다. 정책이 `orbital.role()` 로 가른다
    assert_eq!(
        payslip_owners(&mut bench.login("api", "payroll_admin"), None).len(),
        3
    );
    // 같은 직원 역할이면 어느 서비스로 들어와도 같은 규칙이 걸린다
    assert_eq!(
        payslip_owners(
            &mut bench.login("web", "employee"),
            Some(&bench.identity("emp_2"))
        ),
        vec!["emp_2"]
    );
    let role: String = bench
        .login("web", "employee")
        .query_one("SELECT orbital.role()", &[])
        .unwrap()
        .get(0);
    assert_eq!(role, "employee");
}

// ---- 리허설과 되돌리기 ----

fn databases(bench: &Bench) -> Vec<String> {
    let mut client = bench.admin.connect_as("postgres", "postgres").unwrap();
    let pattern = format!("{}%", bench.names.prefix());
    client
        .query(
            "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY 1",
            &[&pattern],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[test]
fn 리허설은_숫자만_돌려주고_운영은_그대로다() {
    let mut bench = bench!();
    let result = bench
        .admin
        .rehearse(
            &bench.names,
            &[
                "ALTER TABLE payroll.payslip ADD COLUMN note text",
                "DELETE FROM payroll.payslip WHERE employee = 'emp_2'",
            ],
        )
        .unwrap();
    assert!(result.passed);
    assert_eq!(result.failed_at, None);
    let payslip = result
        .tables
        .iter()
        .find(|count| count.table == "payroll.payslip")
        .unwrap();
    assert_eq!((payslip.before, payslip.after), (Some(3), Some(2)));
    assert!(
        !format!("{result:?}").contains("emp_"),
        "결과에 행의 내용이 있습니다"
    );

    // 운영에는 열도 없고 행도 그대로다
    let mut admin = bench.login("api", "payroll_admin");
    assert_eq!(
        admin
            .query("SELECT 1 FROM payroll.payslip", &[])
            .unwrap()
            .len(),
        3
    );
    assert!(
        admin
            .query("SELECT note FROM payroll.payslip", &[])
            .is_err()
    );
}

#[test]
fn 리허설의_사본은_끝나면_지워진다() {
    let mut bench = bench!();
    bench
        .admin
        .rehearse(
            &bench.names,
            &["ALTER TABLE payroll.payslip ADD COLUMN note text"],
        )
        .unwrap();
    bench
        .admin
        .rehearse(&bench.names, &["THIS IS NOT SQL"])
        .unwrap();
    assert_eq!(databases(&bench), vec![bench.names.database()]);
}

#[test]
fn 실패한_리허설은_몇_번째에서_멈췄는지와_sqlstate_만_돌려준다() {
    let mut bench = bench!();
    let result = bench
        .admin
        .rehearse(
            &bench.names,
            &[
                "ALTER TABLE payroll.payslip ADD COLUMN note text",
                "INSERT INTO payroll.payslip (id, employee, amount) OVERRIDING SYSTEM VALUE SELECT id, employee, amount FROM payroll.payslip",
                "DROP TABLE hr.department",
            ],
        )
        .unwrap();
    assert!(!result.passed);
    assert_eq!(result.failed_at, Some(1));
    // 겹친 키. Postgres 의 DETAIL 에는 겹친 값이 적히지만 결과에는 SQLSTATE 만 있다
    assert_eq!(result.sqlstate.as_deref(), Some("23505"));
    assert!(!format!("{result:?}").contains("emp_"));
}

#[test]
fn 사본에는_인스턴스의_어떤_역할도_접속하지_못한다() {
    let mut bench = bench!();
    let point = bench.admin.mark(&bench.names).unwrap();
    for role in [
        bench.names.login(&ident("api"), &ident("payroll_admin")),
        bench.names.login(&ident("api"), &ident("employee")),
        bench.names.migrator(),
    ] {
        assert!(
            bench.admin.connect_as(point.database(), &role).is_err(),
            "{role}"
        );
    }
    bench.admin.forget(point).unwrap();
    assert_eq!(databases(&bench), vec![bench.names.database()]);
}

#[test]
fn 되돌릴_지점으로_돌아가면_그_뒤에_쓴_것이_사라지고_권한은_그대로다() {
    let mut bench = bench!();
    let point = bench.admin.mark(&bench.names).unwrap();

    // 승격: 마이그레이션이 돌고, 그 뒤에 사람이 데이터를 쓴다
    bench
        .admin
        .migrate(
            &bench.names,
            &["ALTER TABLE payroll.payslip ADD COLUMN note text"],
        )
        .unwrap();
    bench
        .login("api", "payroll_admin")
        .execute(
            "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_3', 300)",
            &[],
        )
        .unwrap();

    bench
        .admin
        .restore(&bench.names, &bench.manifest, &point)
        .unwrap();

    let mut admin = bench.login("api", "payroll_admin");
    assert_eq!(
        admin
            .query("SELECT 1 FROM payroll.payslip", &[])
            .unwrap()
            .len(),
        3
    );
    assert!(
        admin
            .query("SELECT note FROM payroll.payslip", &[])
            .is_err()
    );
    drop(admin);
    assert_eq!(bench.findings(), vec![]);
    assert_eq!(databases(&bench), vec![bench.names.database()]);
    assert_eq!(
        payslip_owners(
            &mut bench.login("api", "employee"),
            Some(&bench.identity("emp_1"))
        )
        .len(),
        2
    );
}

#[test]
fn 없는_지점으로는_돌아가지_못하고_운영은_그대로다() {
    let mut bench = bench!();
    let point = bench.admin.mark(&bench.names).unwrap();
    let kept = point.clone();
    bench.admin.forget(point).unwrap();
    assert!(matches!(
        bench.admin.restore(&bench.names, &bench.manifest, &kept),
        Err(Error::NoSuchPoint)
    ));
    assert_eq!(
        bench
            .login("api", "payroll_admin")
            .query("SELECT 1 FROM payroll.payslip", &[])
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn 원본에_끝나지_않는_연결이_있으면_복제하지_않고_바쁘다고_답한다() {
    let mut bench = bench!();
    let _held = bench.login("api", "employee");
    assert!(matches!(
        bench.admin.rehearse(&bench.names, &[]),
        Err(Error::Busy)
    ));
    assert_eq!(databases(&bench), vec![bench.names.database()]);
}

// ---- 마이그레이션이 관리 권한을 얻으려 할 때 ----

fn role_exists(bench: &Bench, name: &str) -> bool {
    let mut client = bench.admin.connect_as("postgres", "postgres").unwrap();
    client
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&name])
        .unwrap()
        .is_some()
}

#[test]
fn 리허설의_마이그레이션이_역할을_되돌려도_관리_권한을_얻지_못한다() {
    let mut bench = bench!();
    let intruder = format!("{}_x_intruder", bench.names.prefix());
    let attack = format!("RESET ROLE; CREATE ROLE \"{intruder}\" SUPERUSER LOGIN");
    let result = bench.admin.rehearse(&bench.names, &[&attack]).unwrap();
    assert!(!result.passed);
    assert_eq!(result.sqlstate.as_deref(), Some("42501"));
    assert!(!role_exists(&bench, &intruder));
    // 다른 database 를 읽는 길도 없다
    let result = bench
        .admin
        .rehearse(
            &bench.names,
            &["RESET ROLE; COPY (SELECT 1) TO PROGRAM 'true'"],
        )
        .unwrap();
    assert_eq!(result.sqlstate.as_deref(), Some("42501"));
}
#[test]
fn 운영의_마이그레이션이_역할을_되돌려도_관리_권한을_얻지_못한다() {
    let mut bench = bench!();
    let intruder = format!("{}_x_intruder", bench.names.prefix());
    let attack = format!("RESET ROLE; CREATE ROLE \"{intruder}\" SUPERUSER LOGIN");
    assert!(matches!(
        bench.admin.migrate(&bench.names, &[&attack]),
        Err(Error::Pg { .. })
    ));
    assert!(matches!(
        bench
            .admin
            .migrate_named(&bench.names, &[("900_attack.sql", &attack)]),
        Err(Error::Pg { .. })
    ));
    assert!(!role_exists(&bench, &intruder));
    assert_eq!(
        bench.admin.applied(&bench.names).unwrap(),
        Vec::<String>::new()
    );
}

// ---- 이름이 붙은 마이그레이션 ----

#[test]
fn 이미_돈_마이그레이션은_다시_돌리지_않는다() {
    let mut bench = bench!();
    let scripts = [
        (
            "010_note.sql",
            "ALTER TABLE payroll.payslip ADD COLUMN note text",
        ),
        (
            "020_paid.sql",
            "ALTER TABLE payroll.payslip ADD COLUMN paid boolean",
        ),
    ];
    assert_eq!(
        bench
            .admin
            .pending(&bench.names, &["010_note.sql", "020_paid.sql"])
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        bench
            .admin
            .migrate_named(&bench.names, &scripts[..1])
            .unwrap(),
        vec!["010_note.sql"]
    );
    // 다시 돌리면 「이미 있는 열」로 깨질 것이 건너뛰어진다
    assert_eq!(
        bench.admin.migrate_named(&bench.names, &scripts).unwrap(),
        vec!["020_paid.sql"]
    );
    assert_eq!(
        bench.admin.migrate_named(&bench.names, &scripts).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        bench.admin.applied(&bench.names).unwrap(),
        vec!["010_note.sql", "020_paid.sql"]
    );
    assert_eq!(
        bench
            .admin
            .pending(&bench.names, &["010_note.sql", "030_new.sql"])
            .unwrap(),
        vec!["030_new.sql"]
    );
}

#[test]
fn 실패한_마이그레이션은_이름이_남지_않고_앞에서_돈_것은_남는다() {
    let mut bench = bench!();
    let scripts = [
        (
            "010_note.sql",
            "ALTER TABLE payroll.payslip ADD COLUMN note text",
        ),
        (
            "020_broken.sql",
            "ALTER TABLE payroll.payslip ADD COLUMN paid boolean; SELECT 1 / 0",
        ),
    ];
    assert!(bench.admin.migrate_named(&bench.names, &scripts).is_err());
    assert_eq!(
        bench.admin.applied(&bench.names).unwrap(),
        vec!["010_note.sql"]
    );
    // 실패한 마이그레이션이 더한 열은 함께 되돌아갔다
    assert!(
        bench
            .login("api", "payroll_admin")
            .query("SELECT paid FROM payroll.payslip", &[])
            .is_err()
    );
}

#[test]
fn 업무_역할은_마이그레이션의_기록을_읽거나_고치지_못한다() {
    let mut bench = bench!();
    bench
        .admin
        .migrate_named(
            &bench.names,
            &[(
                "010_note.sql",
                "ALTER TABLE payroll.payslip ADD COLUMN note text",
            )],
        )
        .unwrap();
    let mut admin = bench.login("api", "payroll_admin");
    assert!(denied(
        admin.execute("SELECT * FROM orbital.migration", &[])
    ));
    assert!(denied(admin.execute("DELETE FROM orbital.migration", &[])));
    assert!(denied(admin.execute(
        "INSERT INTO orbital.migration (name) VALUES ('999_fake.sql')",
        &[]
    )));
}

#[test]
fn 되돌릴_지점으로_돌아가면_마이그레이션의_기록도_그때로_돌아간다() {
    let mut bench = bench!();
    let point = bench.admin.mark(&bench.names).unwrap();
    bench
        .admin
        .migrate_named(
            &bench.names,
            &[(
                "010_note.sql",
                "ALTER TABLE payroll.payslip ADD COLUMN note text",
            )],
        )
        .unwrap();
    bench
        .admin
        .restore(&bench.names, &bench.manifest, &point)
        .unwrap();
    assert_eq!(
        bench.admin.applied(&bench.names).unwrap(),
        Vec::<String>::new()
    );
    // 같은 마이그레이션을 다시 돌릴 수 있다
    assert_eq!(
        bench
            .admin
            .migrate_named(
                &bench.names,
                &[(
                    "010_note.sql",
                    "ALTER TABLE payroll.payslip ADD COLUMN note text"
                )]
            )
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn 운영_db_의_문을_닫고_연결을_끊으면_복제할_수_있고_다시_열면_붙는다() {
    let mut bench = bench!();
    let mut held = bench.login("api", "employee");
    bench.admin.quiesce(&bench.names).unwrap();
    // 닫혀 있는 동안에는 새로 붙지 못하고, 붙어 있던 연결은 끊겼다
    let login = bench.names.login(&ident("api"), &ident("employee"));
    assert!(
        bench
            .admin
            .connect_as(&bench.names.database(), &login)
            .is_err()
    );
    assert!(held.query("SELECT 1", &[]).is_err());
    let result = bench
        .admin
        .rehearse(
            &bench.names,
            &["ALTER TABLE payroll.payslip ADD COLUMN note text"],
        )
        .unwrap();
    assert!(result.passed);
    bench.admin.resume(&bench.names).unwrap();
    assert_eq!(
        payslip_owners(
            &mut bench.login("api", "employee"),
            Some(&bench.identity("emp_1"))
        )
        .len(),
        2
    );
}
