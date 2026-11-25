//! 신원에 실린 업무 역할을 DB 가 견주는지 실제 PostgreSQL 에서 잰다(사다리 3단계).
//!
//! `[auth]` 를 선언한 인스턴스에서는 권한 표의 표마다 역할 제한 정책(`orbital_role`)이 서서, 지금 연결의 업무 역할이
//! 서명된 신원의 `roles` 에 없으면 어떤 행도 읽고 쓰지 못한다. 「못 한다」는 그 역할로 접속해 해 보는 것으로 잰다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use orbital_core::access::{Access, RawAccess};
use orbital_core::auth::SeedUsers;
use orbital_core::check::{Finding, judge, unguarded};
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::{Ident, InstanceId, TableRef};
use orbital_core::plan::Names;
use orbital_pg::Admin;
use orbital_pg::identity::{Claims, sign};
use postgres::Client;
use postgres::error::SqlState;
use sha2::Sha256;

const MANIFEST: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "b"
start = "s"
path = "/"
roles = ["employee", "manager", "payroll_admin"]

[database]
schemas = ["hr", "payroll"]
roles = ["employee", "manager", "payroll_admin"]

[auth]
methods = ["email_link"]
login_path = "/login"
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

/// 직원은 자기 명세만, 급여 관리자는 모두. 행 단위 규칙은 연결의 업무 역할(`orbital.role()`)과 사람(`orbital.subject()`)으로 가른다.
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
INSERT INTO payroll.payslip (employee, amount) VALUES ('emp1', 100), ('emp1', 110), ('emp2', 200);
"#;

const SEED_USERS: &str = r#"
[[user]]
id = "emp1"
email = "emp1@example.test"
roles = ["employee"]

[[user]]
id = "adm1"
email = "adm1@example.test"
roles = ["payroll_admin"]
"#;

const KEY: &[u8] = b"test-signing-key-not-a-real-secret";
const FAR_FUTURE: u64 = 4_000_000_000;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 다른 테스트 바이너리와 겹치지 않게 머리 글자를 `r` 로 둔다.
fn fresh_id() -> InstanceId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut rest = (nanos % 36u128.pow(8)) as u64 * 1296
        + u64::from(COUNTER.fetch_add(1, Ordering::Relaxed) % 1296);
    let mut text = String::from("r");
    for _ in 0..10 {
        text.push(char::from_digit((rest % 36) as u32, 36).unwrap());
        rest /= 36;
    }
    InstanceId::parse(&text).unwrap()
}

fn ident(text: &str) -> Ident {
    Ident::parse(text).unwrap()
}

struct Bench {
    admin: Admin,
    names: Names,
    manifest: ValidManifest,
    access: Access,
}

impl Bench {
    fn new(auth: bool) -> Option<Self> {
        let url = std::env::var("ORBITAL_PG").ok()?;
        let mut admin = Admin::connect(&url).expect("ORBITAL_PG 에 붙지 못했습니다");
        let names = Names::new(fresh_id());
        let text = if auth {
            MANIFEST.to_owned()
        } else {
            MANIFEST.split("[auth]").next().unwrap().to_owned()
        };
        let manifest = toml::from_str::<Manifest>(&text).unwrap().check().unwrap();
        let access =
            Access::parse(&toml::from_str::<RawAccess>(ACCESS).unwrap(), &manifest).unwrap();
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
        admin.install_auth(names, manifest).unwrap();
        if auth {
            let users = toml::from_str::<SeedUsers>(SEED_USERS)
                .unwrap()
                .check(manifest)
                .unwrap();
            admin.seed_users(names, &users, 1).unwrap();
        }
        admin.migrate(names, &[MIGRATION]).unwrap();
        admin.grant(names, manifest, &bench.access).unwrap();
        Some(bench)
    }

    fn login(&self, role: &str) -> Client {
        self.admin
            .connect_as(
                &self.names.database(),
                &self.names.login(&ident("api"), &ident(role)),
            )
            .unwrap()
    }

    fn superuser(&self) -> Client {
        self.admin
            .connect_as(&self.names.database(), "postgres")
            .unwrap()
    }

    /// 사람(`subject`)과 업무 역할을 실은 신원.
    fn identity(&self, subject: Option<&str>, roles: &[&str]) -> String {
        sign(
            KEY,
            &self.names,
            &Claims {
                subject: subject.map(str::to_owned),
                roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                session: subject.map(|_| "s_test".to_owned()),
                client: None,
                expires_at: FAR_FUTURE,
            },
        )
    }

    fn findings(&mut self) -> Vec<Finding> {
        let snapshot = self.admin.snapshot(&self.names).unwrap();
        judge(&self.names, &self.manifest, &self.access, &snapshot)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = self.admin.destroy(&self.names);
    }
}

macro_rules! bench {
    ($auth:expr) => {
        match Bench::new($auth) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

/// 신원을 실은 트랜잭션에서 문장 하나를 돌려, 첫 열을 글자로 돌려준다.
fn rows(
    client: &mut Client,
    identity: Option<&str>,
    sql: &str,
) -> Result<Vec<String>, postgres::Error> {
    let mut transaction = client.transaction()?;
    if let Some(identity) = identity {
        transaction.execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&identity],
        )?;
    }
    let found = transaction.query(sql, &[])?;
    let values = found
        .iter()
        .map(|row| {
            row.try_get::<_, String>(0)
                .or_else(|_| row.try_get::<_, i32>(0).map(|value| value.to_string()))
                .or_else(|_| row.try_get::<_, bool>(0).map(|value| value.to_string()))
                .unwrap_or_default()
        })
        .collect();
    transaction.commit()?;
    Ok(values)
}

fn payslips(client: &mut Client, identity: Option<&str>) -> Vec<String> {
    rows(
        client,
        identity,
        "SELECT employee FROM payroll.payslip ORDER BY id",
    )
    .unwrap()
}

// ---- 업무 역할을 견준다 ----

#[test]
fn 신원에_없는_업무_역할의_연결에서는_자기_행도_모든_행도_읽지_못한다() {
    let bench = bench!(true);
    let employee = bench.identity(Some("emp1"), &["employee"]);
    let admin = bench.identity(Some("adm1"), &["payroll_admin"]);
    // 직원의 신원으로 급여 관리자의 연결을 타면(앱의 버그) 모든 행 권한이 듣지 않는다
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), Some(&employee)),
        Vec::<String>::new()
    );
    // 급여 관리자의 신원으로 직원의 연결을 타도 자기 행조차 없다
    assert_eq!(
        payslips(&mut bench.login("employee"), Some(&admin)),
        Vec::<String>::new()
    );
    // 신원이 없으면 급여 관리자의 연결도 아무것도 읽지 못한다
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), None),
        Vec::<String>::new()
    );
    // 쓰기도 막힌다
    let wrote = rows(
        &mut bench.login("payroll_admin"),
        Some(&employee),
        "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp1', 1) RETURNING employee",
    );
    assert_eq!(
        wrote.unwrap_err().code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let changed = rows(
        &mut bench.login("payroll_admin"),
        Some(&employee),
        "UPDATE payroll.payslip SET amount = 0 RETURNING employee",
    )
    .unwrap();
    assert!(changed.is_empty());
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), Some(&admin)).len(),
        3
    );
}

#[test]
fn 신원에_있는_업무_역할의_연결에서는_권한_표대로_읽고_쓴다() {
    let mut bench = bench!(true);
    assert_eq!(bench.findings(), vec![]);
    let employee = bench.identity(Some("emp1"), &["employee"]);
    let admin = bench.identity(Some("adm1"), &["payroll_admin"]);
    assert_eq!(
        payslips(&mut bench.login("employee"), Some(&employee)),
        vec!["emp1", "emp1"]
    );
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), Some(&admin)),
        vec!["emp1", "emp1", "emp2"]
    );
    let wrote = rows(
        &mut bench.login("payroll_admin"),
        Some(&admin),
        "INSERT INTO payroll.payslip (employee, amount) VALUES ('emp3', 300) RETURNING employee",
    )
    .unwrap();
    assert_eq!(wrote, vec!["emp3"]);
    // 역할이 둘인 사람은 연결의 역할대로만 읽는다
    let both = bench.identity(Some("emp1"), &["employee", "payroll_admin"]);
    assert_eq!(
        payslips(&mut bench.login("employee"), Some(&both)),
        vec!["emp1", "emp1"]
    );
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), Some(&both)).len(),
        4
    );
    // 권한 표가 none 인 역할은 신원에 있어도 표의 권한이 없다
    let manager = bench.identity(Some("emp1"), &["manager"]);
    let denied = rows(
        &mut bench.login("manager"),
        Some(&manager),
        "SELECT employee FROM payroll.payslip",
    );
    assert_eq!(
        denied.unwrap_err().code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
}

#[test]
fn 사용자_없이_서명된_신원은_그_역할의_모든_행_권한만_쓰고_자기_행은_읽지_못한다() {
    let bench = bench!(true);
    let job = |role: &str| {
        sign(
            KEY,
            &bench.names,
            &Claims::for_role(&ident(role), FAR_FUTURE),
        )
    };
    assert_eq!(
        payslips(
            &mut bench.login("payroll_admin"),
            Some(&job("payroll_admin"))
        ),
        vec!["emp1", "emp1", "emp2"]
    );
    // 사람이 없으니 자기 행은 없다
    assert_eq!(
        payslips(&mut bench.login("employee"), Some(&job("employee"))),
        Vec::<String>::new()
    );
    let subject = rows(
        &mut bench.login("employee"),
        Some(&job("employee")),
        "SELECT coalesce(orbital.subject(), 'none')",
    )
    .unwrap();
    assert_eq!(subject, vec!["none"]);
    // 그 역할이 아닌 연결에서는 아무것도 읽지 못한다
    assert_eq!(
        payslips(&mut bench.login("payroll_admin"), Some(&job("employee"))),
        Vec::<String>::new()
    );
}

/// 앞의 형식(`v1`). 업무 역할이 없고 사람과 만료만 있다. 같은 열쇠로 바르게 서명한다.
fn old_identity(names: &Names, body: &str) -> String {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let _ = names;
    let signed = format!("v1.{}", hex(body.as_bytes()));
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(signed.as_bytes());
    format!("{signed}.{}", hex(&mac.finalize().into_bytes()))
}

#[test]
fn 옛_형식의_신원은_읽히지_않는다() {
    let bench = bench!(true);
    let iid = bench.names.instance().as_str();
    for body in [
        format!(r#"{{"iid":"{iid}","sub":"emp1","exp":{FAR_FUTURE}}}"#),
        format!(
            r#"{{"iid":"{iid}","sub":"emp1","exp":{FAR_FUTURE},"roles":["employee","payroll_admin"]}}"#
        ),
    ] {
        let old = old_identity(&bench.names, &body);
        assert_eq!(
            payslips(&mut bench.login("employee"), Some(&old)),
            Vec::<String>::new()
        );
        assert_eq!(
            payslips(&mut bench.login("payroll_admin"), Some(&old)),
            Vec::<String>::new()
        );
        let read = rows(
            &mut bench.login("employee"),
            Some(&old),
            "SELECT coalesce(orbital.subject(), 'none') || ' ' || orbital.granted()::text",
        )
        .unwrap();
        assert_eq!(read, vec!["none false"]);
    }
    // 새 형식은 읽힌다
    let new = bench.identity(Some("emp1"), &["employee"]);
    assert_eq!(payslips(&mut bench.login("employee"), Some(&new)).len(), 2);
}

#[test]
fn 신원의_업무_역할은_orbital_me_의_역할과_같고_me_는_그_역할의_연결에서만_읽힌다() {
    let bench = bench!(true);
    let employee = bench.identity(Some("emp1"), &["employee"]);
    let me = rows(
        &mut bench.login("employee"),
        Some(&employee),
        "SELECT array_to_string(roles, ',') FROM orbital.me",
    )
    .unwrap();
    assert_eq!(me, vec!["employee"]);
    let elsewhere = rows(
        &mut bench.login("payroll_admin"),
        Some(&employee),
        "SELECT id FROM orbital.me",
    )
    .unwrap();
    assert!(elsewhere.is_empty());
}

#[test]
fn orbital_client_는_mcp_로_들어온_요청의_클라이언트를_돌려주고_브라우저의_세션이면_null_이다() {
    let bench = bench!(true);
    let client = |client: Option<&str>, roles: &[&str], login: &str| -> Vec<String> {
        let identity = sign(
            KEY,
            &bench.names,
            &Claims {
                subject: Some("emp1".to_owned()),
                roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                session: None,
                client: client.map(str::to_owned),
                expires_at: FAR_FUTURE,
            },
        );
        rows(
            &mut bench.login(login),
            Some(&identity),
            "SELECT coalesce(orbital.client(), 'none')",
        )
        .unwrap()
    };
    assert_eq!(client(Some("c_1"), &["employee"], "employee"), vec!["c_1"]);
    assert_eq!(client(None, &["employee"], "employee"), vec!["none"]);
    // 연결의 업무 역할이 신원에 없으면 클라이언트도 없다
    assert_eq!(
        client(Some("c_1"), &["employee"], "payroll_admin"),
        vec!["none"]
    );
}

/// 실행 계획(JSON)의 마디를 모두 모은다.
fn plan_nodes(node: &serde_json::Value, found: &mut Vec<serde_json::Value>) {
    found.push(node.clone());
    if let Some(children) = node["Plans"].as_array() {
        for child in children {
            plan_nodes(child, found);
        }
    }
}

#[test]
fn 역할_제한_정책의_검증은_행마다가_아니라_문장마다_한_번_돈다() {
    let bench = bench!(true);
    bench
        .superuser()
        .batch_execute(
            "INSERT INTO payroll.payslip (employee, amount) SELECT 'emp1', n FROM generate_series(1, 500) n",
        )
        .unwrap();
    let identity = bench.identity(Some("emp1"), &["employee"]);
    let mut employee = bench.login("employee");
    let mut transaction = employee.transaction().unwrap();
    transaction
        .execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&identity],
        )
        .unwrap();
    let text = transaction
        .simple_query(
            "EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT employee FROM payroll.payslip",
        )
        .unwrap()
        .into_iter()
        .find_map(|message| match message {
            postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_owned),
            _ => None,
        })
        .unwrap();
    let explained: serde_json::Value = serde_json::from_str(&text).unwrap();
    transaction.commit().unwrap();
    let mut nodes = Vec::new();
    plan_nodes(&explained[0]["Plan"], &mut nodes);

    // 검증 함수는 따로 된 마디(InitPlan)에서 문장마다 한 번만 돈다
    for function in ["orbital.granted()", "orbital.subject()", "orbital.role()"] {
        let once = nodes.iter().find(|node| {
            node["Parent Relationship"] == "InitPlan"
                && node["Output"].as_array().is_some_and(|output| {
                    output
                        .iter()
                        .any(|item| item.as_str().is_some_and(|text| text.contains(function)))
                })
        });
        let once =
            once.unwrap_or_else(|| panic!("{function} 이 InitPlan 에 없습니다: {explained}"));
        assert_eq!(once["Actual Loops"], 1, "{function}: {once}");
    }
    // 표를 읽는 마디는 행마다 함수를 부르지 않고 InitPlan 의 값만 견준다
    let scan = nodes
        .iter()
        .find(|node| node["Relation Name"] == "payslip")
        .unwrap_or_else(|| panic!("{explained}"));
    let filter = scan["Filter"].as_str().unwrap_or_default();
    assert!(!filter.contains("orbital.granted("), "{filter}");
    assert!(!filter.contains("orbital.subject("), "{filter}");
    assert!(!filter.contains("orbital.role("), "{filter}");
    // PostgreSQL 18 부터 행 수를 소수로 적는다
    let examined = scan["Actual Rows"]
        .as_f64()
        .unwrap_or_else(|| panic!("{scan}"))
        + scan["Rows Removed by Filter"].as_f64().unwrap_or(0.0);
    assert!(examined > 500.0, "{scan}");
}

// ---- 권한 검사 ----

#[test]
fn 권한_검사는_실제_db_의_역할_제한_정책을_읽어_없거나_바뀌면_잡는다() {
    let mut bench = bench!(true);
    assert_eq!(bench.findings(), vec![]);
    let payslip = TableRef {
        schema: ident("payroll"),
        table: ident("payslip"),
    };
    // 행 단위 규칙을 끈 표에는 정책이 걸리지 않는다. 실패는 아니고 따로 알린다
    assert_eq!(
        unguarded(&bench.manifest, &bench.access),
        vec![TableRef {
            schema: ident("hr"),
            table: ident("department")
        }]
    );
    bench
        .superuser()
        .batch_execute(
            "DROP POLICY orbital_role ON payroll.payslip; \
             CREATE POLICY orbital_role ON payroll.payslip AS PERMISSIVE USING (true)",
        )
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::RolePolicyWrong {
            table: payslip.clone()
        }]
    );
    bench
        .superuser()
        .batch_execute("DROP POLICY orbital_role ON payroll.payslip")
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::RolePolicyMissing { table: payslip }]
    );
    // 권한을 다시 세우면 정책도 다시 선다
    bench
        .admin
        .grant(&bench.names, &bench.manifest, &bench.access)
        .unwrap();
    assert_eq!(bench.findings(), vec![]);
}

#[test]
fn 마이그레이션은_역할_제한_정책을_지울_수_있지만_권한_검사가_잡는다() {
    let mut bench = bench!(true);
    bench
        .admin
        .migrate(
            &bench.names,
            &["DROP POLICY orbital_role ON payroll.payslip"],
        )
        .unwrap();
    assert_eq!(
        bench.findings(),
        vec![Finding::RolePolicyMissing {
            table: TableRef {
                schema: ident("payroll"),
                table: ident("payslip")
            }
        }]
    );
}

#[test]
fn auth_를_선언하지_않은_인스턴스에는_역할_제한_정책이_없고_전과_같이_읽힌다() {
    let mut bench = bench!(false);
    assert_eq!(bench.findings(), vec![]);
    let policies: i64 = bench
        .superuser()
        .query_one(
            "SELECT count(*) FROM pg_policy WHERE polname = 'orbital_role'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(policies, 0);
    // 신원 없이 「모든 행」 권한이 그대로 돈다
    assert_eq!(payslips(&mut bench.login("payroll_admin"), None).len(), 3);
    assert_eq!(
        payslips(&mut bench.login("employee"), None),
        Vec::<String>::new()
    );
    // 사람의 신원(사용자가 없으니 레이어가 서명하지 않지만, 서명이 맞으면)으로는 자기 행만 읽는다
    let employee = bench.identity(Some("emp1"), &["employee"]);
    assert_eq!(
        payslips(&mut bench.login("employee"), Some(&employee)),
        vec!["emp1", "emp1"]
    );
    assert!(unguarded(&bench.manifest, &bench.access).is_empty());
}
