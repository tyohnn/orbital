//! proxy 를 실제 PostgreSQL 앞에 세워 재는 테스트(사다리 3단계).
//!
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. `scripts/pg-local.sh` 가 띄우고 주소를 찍는다.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_core::access::{Access, RawAccess};
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::{Ident, InstanceId};
use orbital_core::plan::Names;
use orbital_pg::Admin;
use orbital_pg::identity::{Claims, sign};
use orbital_proxy::{Route, serve};
use postgres::error::SqlState;
use postgres::{Client, Config, NoTls};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

const MANIFEST: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build -w api"
start = "npm run start -w api"
path = "/api"
roles = ["employee", "payroll_admin"]

[[service]]
name = "web"
kind = "server"
build = "npm run build -w web"
start = "npm run start -w web"
path = "/"
roles = ["employee"]

[database]
schemas = ["payroll"]
roles = ["employee", "payroll_admin"]
"#;

const ACCESS: &str = r#"
[payroll.payslip]
employee = "read own"
payroll_admin = "read write"
"#;

const MIGRATION: &str = r#"
CREATE TABLE payroll.payslip (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, employee text NOT NULL, amount int NOT NULL);
ALTER TABLE payroll.payslip ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON payroll.payslip FOR SELECT
    USING ((SELECT orbital.role()) = 'employee' AND employee = (SELECT orbital.subject()));
CREATE POLICY admin ON payroll.payslip
    USING ((SELECT orbital.role()) = 'payroll_admin') WITH CHECK ((SELECT orbital.role()) = 'payroll_admin');
INSERT INTO payroll.payslip (employee, amount) VALUES ('emp_1', 100), ('emp_1', 110), ('emp_2', 200);
"#;

const KEY: &[u8] = b"test-signing-key-not-a-real-secret";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_id() -> InstanceId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut rest = (nanos % 36u128.pow(8)) as u64 * 1296
        + u64::from(COUNTER.fetch_add(1, Ordering::Relaxed) % 1296);
    let mut text = String::from("p");
    for _ in 0..10 {
        text.push(char::from_digit((rest % 36) as u32, 36).unwrap());
        rest /= 36;
    }
    InstanceId::parse(&text).unwrap()
}

/// 세워 둔 인스턴스 하나와, 서비스마다 그 앞에 선 proxy.
struct Bench {
    admin: Admin,
    names: Names,
    manifest: ValidManifest,
    upstream: String,
    runtime: Runtime,
}

impl Bench {
    fn new() -> Option<Self> {
        let url = std::env::var("ORBITAL_PG").ok()?;
        let config: Config = url.parse().unwrap();
        let upstream = format!(
            "127.0.0.1:{}",
            config.get_ports().first().copied().unwrap_or(5432)
        );
        let mut admin = Admin::connect(&url).expect("ORBITAL_PG 에 붙지 못했습니다");
        let names = Names::new(fresh_id());
        let manifest = toml::from_str::<Manifest>(MANIFEST)
            .unwrap()
            .check()
            .unwrap();
        let access =
            Access::parse(&toml::from_str::<RawAccess>(ACCESS).unwrap(), &manifest).unwrap();
        admin.provision(&names, &manifest).unwrap();
        admin.install_identity(&names, KEY).unwrap();
        admin.migrate(&names, &[MIGRATION]).unwrap();
        admin.grant(&names, &manifest, &access).unwrap();
        Some(Self {
            admin,
            names,
            manifest,
            upstream,
            runtime: Runtime::new().unwrap(),
        })
    }

    /// 서비스 하나의 proxy 를 세우고 듣는 포트를 돌려준다.
    fn proxy(&self, service: &str) -> u16 {
        let route =
            Route::for_service(&self.names, &self.manifest, &Ident::parse(service).unwrap());
        let listener = self
            .runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        self.runtime
            .spawn(serve(listener, self.upstream.clone(), route));
        port
    }

    fn identity(&self, subject: &str) -> String {
        sign(
            KEY,
            &self.names,
            &Claims {
                subject: Some(subject.to_owned()),
                roles: vec!["employee".to_owned(), "payroll_admin".to_owned()],
                session: None,
                client: None,
                expires_at: 4_000_000_000,
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

/// 서비스가 하듯이 붙는다. 비밀번호는 없고, 사용자 자리에 업무 역할의 이름을 적는다.
fn through(port: u16, role: &str) -> Config {
    let mut config = Config::new();
    config.host("127.0.0.1").port(port).user(role).dbname("app");
    config
}

fn text(client: &mut Client, sql: &str) -> String {
    client.query_one(sql, &[]).unwrap().get(0)
}

#[test]
fn 서비스는_비밀번호_없이_업무_역할의_이름만으로_붙는다() {
    let bench = bench!();
    let mut client = through(bench.proxy("web"), "employee")
        .connect(NoTls)
        .unwrap();
    assert_eq!(
        text(&mut client, "SELECT session_user::text"),
        format!("{}_s_web_employee", bench.names.prefix())
    );
    assert_eq!(text(&mut client, "SELECT orbital.role()"), "employee");
}

#[test]
fn database_의_이름을_무엇으로_적어도_제_인스턴스의_database_에_붙는다() {
    let bench = bench!();
    let mut config = through(bench.proxy("web"), "employee");
    config.dbname("postgres");
    let mut client = config.connect(NoTls).unwrap();
    assert_eq!(
        text(&mut client, "SELECT current_database()::text"),
        bench.names.database()
    );
}

#[test]
fn 서비스의_선언에_없는_역할로는_붙지_못한다() {
    let bench = bench!();
    let port = bench.proxy("web");
    // web 서비스는 employee 만 적었다. api 서비스는 payroll_admin 도 적었다
    for role in [
        "payroll_admin",
        "postgres",
        &bench.names.migrator(),
        &bench.names.owner(),
    ] {
        let error = through(port, role)
            .connect(NoTls)
            .err()
            .unwrap_or_else(|| panic!("{role} 로 붙었습니다"));
        assert_eq!(
            error.code(),
            Some(&SqlState::INVALID_AUTHORIZATION_SPECIFICATION),
            "{role}"
        );
    }
    assert!(
        through(bench.proxy("api"), "payroll_admin")
            .connect(NoTls)
            .is_ok()
    );
}

#[test]
fn 같은_역할이라도_서비스마다_다른_로그인으로_들어간다() {
    let bench = bench!();
    let mut web = through(bench.proxy("web"), "employee")
        .connect(NoTls)
        .unwrap();
    let mut api = through(bench.proxy("api"), "employee")
        .connect(NoTls)
        .unwrap();
    assert_ne!(
        text(&mut web, "SELECT session_user::text"),
        text(&mut api, "SELECT session_user::text")
    );
}

#[test]
fn 연결을_시작하며_실어_보낸_역할_바꾸기_설정은_db_에_닿지_않는다() {
    let bench = bench!();
    let mut config = through(bench.proxy("api"), "employee");
    config.options(&format!(
        "-c role={}",
        bench.names.group(&Ident::parse("payroll_admin").unwrap())
    ));
    // 대조: 같은 설정을 proxy 없이 DB 에 바로 보내면 「그 역할이 될 수 없다」로 연결이 깨진다
    let mut direct: Config = std::env::var("ORBITAL_PG").unwrap().parse().unwrap();
    direct
        .dbname(&bench.names.database())
        .user(&format!("{}_s_api_employee", bench.names.prefix()));
    direct.options(config.get_options().unwrap());
    assert!(direct.connect(NoTls).is_err());
    // proxy 는 그 설정을 버리므로 직원으로 붙는다
    let mut client = config.connect(NoTls).unwrap();
    assert_eq!(
        text(&mut client, "SELECT current_user::text"),
        format!("{}_s_api_employee", bench.names.prefix())
    );
}

#[test]
fn proxy_를_거친_연결에서도_서명된_신원으로_자기_행만_돌아온다() {
    let bench = bench!();
    let mut client = through(bench.proxy("web"), "employee")
        .connect(NoTls)
        .unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&bench.identity("emp_1")],
        )
        .unwrap();
    let rows = transaction
        .query("SELECT employee FROM payroll.payslip", &[])
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>(),
        vec!["emp_1", "emp_1"]
    );
    drop(transaction);
    assert!(
        client
            .query("SELECT employee FROM payroll.payslip", &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn proxy_를_거친_연결에서도_역할을_바꿔_타지_못한다() {
    let bench = bench!();
    let mut client = through(bench.proxy("api"), "employee")
        .connect(NoTls)
        .unwrap();
    let admin = bench.names.group(&Ident::parse("payroll_admin").unwrap());
    let error = client
        .execute(&format!("SET ROLE \"{admin}\""), &[])
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
}

#[test]
fn 질의를_멈춰_달라는_요청은_proxy_를_지나_db_에_닿는다() {
    let bench = bench!();
    let mut client = through(bench.proxy("api"), "employee")
        .connect(NoTls)
        .unwrap();
    let cancel = client.cancel_token();
    let sleeper = std::thread::spawn(move || client.batch_execute("SELECT pg_sleep(30)"));
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    cancel.cancel_query(NoTls).unwrap();
    let error = sleeper.join().unwrap().unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::QUERY_CANCELED));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn 큰_결과도_그대로_지나간다() {
    let bench = bench!();
    let mut client = through(bench.proxy("api"), "payroll_admin")
        .connect(NoTls)
        .unwrap();
    let rows = client
        .query(
            "SELECT repeat('x', 1000) FROM generate_series(1, 20000)",
            &[],
        )
        .unwrap();
    assert_eq!(rows.len(), 20_000);
    assert_eq!(rows[19_999].get::<_, String>(0).len(), 1_000);
}
