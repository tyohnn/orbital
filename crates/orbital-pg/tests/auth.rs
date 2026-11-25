//! Orbital Auth 를 실제 PostgreSQL 에 세워 재는 테스트(사다리 3단계).
//!
//! 「못 한다」는 그 역할로 접속해 해 봤을 때 거절되는 것으로 잰다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use orbital_core::access::{Access, RawAccess};
use orbital_core::auth::INVITATION_TTL;
use orbital_core::check::{Finding, judge};
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::{Ident, InstanceId};
use orbital_core::plan::Names;
use orbital_pg::Admin;
use orbital_pg::auth::{AuthError, AuthStore, Secret};
use orbital_pg::identity::{Claims, sign};
use postgres::Client;
use postgres::error::SqlState;

const MANIFEST: &str = r#"
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
kind = "server"
build = "npm run build -w web"
start = "npm run start -w web"
path = "/"
roles = ["member"]

[database]
schemas = ["app"]
roles = ["member", "manager"]

[auth]
methods = ["email_link"]
login_path = "/login"
directory = ["manager"]
"#;

const ACCESS: &str = r#"
[app.note]
member = "read write own"
manager = "read"
"#;

/// 앱의 표가 레이어의 사용자를 외래 키로 가리킨다.
const MIGRATION: &str = r#"
CREATE TABLE app.note (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    author text NOT NULL REFERENCES orbital_auth.users (id),
    body text NOT NULL
);
ALTER TABLE app.note ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON app.note USING (author = (SELECT orbital.subject()));
"#;

/// 로그인을 레이어에 맡기지 않는 인스턴스. 앞의 테스트들과 같은 모양이다.
const MANIFEST_WITHOUT_AUTH: &str = r#"
[[service]]
name = "api"
kind = "server"
build = "npm run build -w api"
start = "npm run start -w api"
path = "/"
roles = ["member", "manager"]

[database]
schemas = ["app"]
roles = ["member", "manager"]
"#;

const MIGRATION_WITHOUT_AUTH: &str = r#"
CREATE TABLE app.note (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, author text NOT NULL, body text NOT NULL);
ALTER TABLE app.note ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON app.note USING (author = (SELECT orbital.subject()));
"#;

const KEY: &[u8] = b"test-signing-key-not-a-real-secret";
const FAR_FUTURE: u64 = 4_000_000_000;
const NOW: u64 = 1_800_000_000;
const TABLES: [&str; 7] = [
    "users",
    "user_role",
    "login",
    "invitation",
    "email_link",
    "session",
    "google_ticket",
];

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 테스트마다 새로 짓는 식별자. `database.rs` 와 머리 글자를 달리해 두 테스트 바이너리가 겹치지 않는다.
fn fresh_id() -> InstanceId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut rest = (nanos % 36u128.pow(8)) as u64 * 1296
        + u64::from(COUNTER.fetch_add(1, Ordering::Relaxed) % 1296);
    let mut text = String::from("a");
    for _ in 0..10 {
        text.push(char::from_digit((rest % 36) as u32, 36).unwrap());
        rest /= 36;
    }
    InstanceId::parse(&text).unwrap()
}

fn ident(text: &str) -> Ident {
    Ident::parse(text).unwrap()
}

/// 세워 둔 인스턴스 하나. 테스트가 끝나면 걷는다.
struct Bench {
    admin: Admin,
    names: Names,
    manifest: ValidManifest,
    access: Access,
}

impl Bench {
    fn new(manifest: &str, migration: &str) -> Option<Self> {
        let url = std::env::var("ORBITAL_PG").ok()?;
        let mut admin = Admin::connect(&url).expect("ORBITAL_PG 에 붙지 못했습니다");
        let names = Names::new(fresh_id());
        let manifest = toml::from_str::<Manifest>(manifest)
            .unwrap()
            .check()
            .unwrap();
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
        admin.migrate(names, &[migration]).unwrap();
        admin.grant(names, manifest, &bench.access).unwrap();
        Some(bench)
    }

    fn store(&self) -> AuthStore {
        self.admin.auth_store(&self.names, &self.manifest).unwrap()
    }

    fn login(&self, service: &str, role: &str) -> Client {
        self.admin
            .connect_as(
                &self.names.database(),
                &self.names.login(&ident(service), &ident(role)),
            )
            .unwrap()
    }

    /// 마이그레이션 역할로 들어와 소유자가 된 연결. 마이그레이션이 하는 일을 그대로 해 본다.
    fn migrator(&self, as_owner: bool) -> Client {
        let mut client = self
            .admin
            .connect_as(&self.names.database(), &self.names.migrator())
            .unwrap();
        if as_owner {
            client
                .batch_execute(&format!("SET ROLE \"{}\"", self.names.owner()))
                .unwrap();
        }
        client
    }

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
                roles: vec!["member".to_owned(), "manager".to_owned()],
                session: None,
                client: None,
                expires_at: FAR_FUTURE,
            },
        )
    }

    fn role_exists(&self, name: &str) -> bool {
        let mut client = self.admin.connect_as("postgres", "postgres").unwrap();
        client
            .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&name])
            .unwrap()
            .is_some()
    }

    fn count(&self, table: &str) -> i64 {
        self.superuser()
            .query_one(&format!("SELECT count(*) FROM orbital_auth.{table}"), &[])
            .unwrap()
            .get(0)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = self.admin.destroy(&self.names);
    }
}

macro_rules! bench {
    () => {
        bench!(MANIFEST, MIGRATION)
    };
    ($manifest:expr, $migration:expr) => {
        match Bench::new($manifest, $migration) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn denied<T>(result: Result<T, postgres::Error>) -> bool {
    matches!(result, Err(error) if error.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE))
}

fn secret(byte: u8) -> Secret {
    Secret::from_bytes([byte; 32])
}

/// 초대하고 링크를 만들어 들어온다. 사용자의 식별자와 세션의 토큰을 돌려준다.
fn sign_in(store: &mut AuthStore, email: &str, roles: &[&str]) -> (String, Secret) {
    let roles: Vec<Ident> = roles.iter().map(|role| ident(role)).collect();
    store.invite(email, &roles, NOW).unwrap();
    let browser = secret(9);
    let link = store
        .request_link(email, "/inbox", &browser, NOW)
        .unwrap()
        .expect("초대받은 이메일이니 링크가 만들어져야 합니다");
    let entered = store.enter(&link, &browser, NOW + 1).unwrap();
    (entered.user.id, entered.session)
}

// ---- 누가 읽고 쓰나 ----

#[test]
fn 업무_역할과_소유자와_마이그레이션_역할은_orbital_auth_의_표를_읽지_못한다() {
    let bench = bench!();
    sign_in(&mut bench.store(), "kim@example.com", &["member"]);
    let mut clients = vec![
        ("api/member", bench.login("api", "member")),
        ("api/manager", bench.login("api", "manager")),
        ("web/member", bench.login("web", "member")),
        ("migrator", bench.migrator(false)),
        ("owner", bench.migrator(true)),
    ];
    for (who, client) in &mut clients {
        for (table, column) in TABLES.iter().zip([
            "name", "role", "subject", "roles", "next", "user_id", "next",
        ]) {
            for statement in [
                format!("SELECT * FROM orbital_auth.{table}"),
                format!("DELETE FROM orbital_auth.{table}"),
                format!("UPDATE orbital_auth.{table} SET {column} = {column}"),
            ] {
                assert!(
                    denied(client.execute(&statement, &[])),
                    "{who}: {statement}"
                );
            }
        }
    }
}

#[test]
fn 마이그레이션은_사용자를_참조하는_외래_키를_만들고_사용자_표를_고치지는_못한다() {
    let mut bench = bench!();
    let (user, _) = sign_in(&mut bench.store(), "kim@example.com", &["member"]);
    bench
        .admin
        .migrate(
            &bench.names,
            &["CREATE TABLE app.extra (id int PRIMARY KEY, owner_id text REFERENCES orbital_auth.users (id))"],
        )
        .unwrap();
    let mut owner = bench.migrator(true);
    // 외래 키가 실제로 사용자를 가리킨다
    owner
        .execute("INSERT INTO app.extra VALUES (1, $1)", &[&user])
        .unwrap();
    let missing = owner.execute(
        "INSERT INTO app.extra VALUES (2, 'u_aaaaaaaaaaaaaaaaaaaa')",
        &[],
    );
    assert_eq!(
        missing.unwrap_err().code(),
        Some(&SqlState::FOREIGN_KEY_VIOLATION)
    );
    for statement in [
        "SELECT id FROM orbital_auth.users",
        "UPDATE orbital_auth.users SET name = 'x'",
        "INSERT INTO orbital_auth.users (id, email, created_at) VALUES ('u_bbbbbbbbbbbbbbbbbbbb', 'x@example.com', now())",
        "DELETE FROM orbital_auth.users",
        "TRUNCATE orbital_auth.users CASCADE",
        "ALTER TABLE orbital_auth.users ADD COLUMN note text",
        "ALTER TABLE orbital_auth.users DROP CONSTRAINT users_pkey CASCADE",
        "DROP TABLE orbital_auth.users CASCADE",
        "CREATE TABLE orbital_auth.extra (id int)",
        "CREATE OR REPLACE VIEW orbital.me AS SELECT 1",
    ] {
        assert!(denied(owner.execute(statement, &[])), "{statement}");
    }
    // 마이그레이션의 길로 돌려도 같다
    assert!(
        bench
            .admin
            .migrate(&bench.names, &["UPDATE orbital_auth.users SET name = 'x'"])
            .is_err()
    );
}

#[test]
fn 인증_역할은_앱의_표를_읽지_못한다() {
    let bench = bench!();
    let mut auth = bench
        .admin
        .connect_as(&bench.names.database(), &bench.names.auth())
        .unwrap();
    for statement in [
        "SELECT * FROM app.note",
        "INSERT INTO app.note (author, body) VALUES ('x', 'y')",
        "CREATE TABLE app.scratch (id int)",
        "CREATE TABLE public.scratch (id int)",
        "CREATE TABLE orbital_auth.scratch (id int)",
        "SELECT signing_key FROM orbital.instance",
        "SELECT * FROM orbital.migration",
        "ALTER TABLE orbital_auth.users ADD COLUMN note text",
        "DROP TABLE orbital_auth.session",
    ] {
        assert!(denied(auth.execute(statement, &[])), "{statement}");
    }
    for target in [
        bench.names.owner(),
        bench.names.migrator(),
        bench.names.group(&ident("manager")),
    ] {
        assert!(
            denied(auth.execute(&format!("SET ROLE \"{target}\""), &[])),
            "{target}"
        );
    }
    // 제 표는 읽는다
    assert!(auth.query("SELECT 1 FROM orbital_auth.users", &[]).is_ok());
}

#[test]
fn orbital_auth_의_표와_뷰의_주인은_로그인하지_못하고_앱의_표를_읽지_못한다() {
    let bench = bench!();
    let owner = bench.names.auth_owner();
    let mut superuser = bench.superuser();
    // orbital_auth 의 표와 두 뷰의 주인이 모두 그 역할이다
    let rows = superuser
        .query(
            "SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE (n.nspname = 'orbital_auth' AND c.relkind IN ('r', 'p', 'v', 'm')) \
                OR (n.nspname = 'orbital' AND c.relname IN ('me', 'users'))",
            &[],
        )
        .unwrap();
    assert!(rows.len() >= TABLES.len() + 2, "{}", rows.len());
    for row in &rows {
        let (relation, by): (String, String) = (row.get(0), row.get(1));
        assert_eq!(by, owner, "{relation}");
    }
    // 그 역할로 접속해 보면 거절된다
    let refused = bench
        .admin
        .connect_as(&bench.names.database(), &owner)
        .err()
        .expect("주인 역할로는 접속하지 못해야 합니다");
    assert_eq!(
        refused.code(),
        Some(&SqlState::INVALID_AUTHORIZATION_SPECIFICATION),
        "{refused}"
    );
    // 어느 역할에도 딸리지 않고, 아무도 그 역할에 딸리지 않는다
    let memberships: i64 = superuser
        .query_one(
            "SELECT count(*) FROM pg_auth_members WHERE roleid = $1::text::regrole OR member = $1::text::regrole",
            &[&owner],
        )
        .unwrap()
        .get(0);
    assert_eq!(memberships, 0);
    // 그 역할이 되어 해 보면 앱의 표와 레이어의 표에는 닿지 못한다
    superuser
        .batch_execute(&format!("SET ROLE \"{owner}\""))
        .unwrap();
    for statement in [
        "SELECT * FROM app.note",
        "INSERT INTO app.note (author, body) VALUES ('x', 'y')",
        "CREATE TABLE app.scratch (id int)",
        "CREATE TABLE public.scratch (id int)",
        "SELECT signing_key FROM orbital.instance",
        "SELECT * FROM orbital.migration",
        "CREATE TABLE orbital_auth.scratch (id int)",
    ] {
        assert!(denied(superuser.execute(statement, &[])), "{statement}");
    }
    superuser.batch_execute("RESET ROLE").unwrap();
    // 주인이 바뀌어도 뷰는 그대로 돈다(뷰는 주인의 권한으로 표를 읽는다)
    let (user, _) = sign_in(&mut bench.store(), "kim@example.com", &["member"]);
    let mut member = bench.login("api", "member");
    member
        .batch_execute(&format!(
            "SET orbital.identity = '{}'",
            bench.identity(&user)
        ))
        .unwrap();
    let me: Vec<String> = member
        .query("SELECT id FROM orbital.me", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(me, vec![user]);
}

// ---- 토큰과 링크 ----

#[test]
fn 토큰은_해시로만_저장된다_표를_통째로_읽어도_그_값으로는_세션을_찾지_못한다() {
    let bench = bench!();
    let mut store = bench.store();
    store
        .invite("kim@example.com", &[ident("member")], NOW)
        .unwrap();
    let browser = secret(9);
    let link = store
        .request_link("kim@example.com", "/inbox", &browser, NOW)
        .unwrap()
        .unwrap();
    let entered = store.enter(&link, &browser, NOW + 1).unwrap();
    assert!(store.session(&entered.session, NOW + 2).unwrap().is_some());

    let mut superuser = bench.superuser();
    let secrets = [&link, &entered.session, &browser];
    for table in ["email_link", "session"] {
        // 행을 글자로 통째로 읽어도 토큰은 없다
        for row in superuser
            .query(&format!("SELECT t::text FROM orbital_auth.{table} t"), &[])
            .unwrap()
        {
            let text: String = row.get(0);
            for secret in secrets {
                assert!(!text.contains(&secret.to_text()), "{table}");
                let bytes: String = secret
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert!(!text.contains(&bytes), "{table}");
            }
        }
        // 저장된 값을 그대로 토큰으로 내밀어도 세션이 아니다
        let columns = if table == "session" {
            "token_hash, token_hash"
        } else {
            "token_hash, browser_hash"
        };
        for row in superuser
            .query(&format!("SELECT {columns} FROM orbital_auth.{table}"), &[])
            .unwrap()
        {
            for index in 0..2 {
                let stored: Vec<u8> = row.get(index);
                let replayed = Secret::from_bytes(stored.try_into().unwrap());
                assert!(store.session(&replayed, NOW + 2).unwrap().is_none());
                assert!(store.enter(&replayed, &browser, NOW + 2).is_err());
            }
        }
    }
}

#[test]
fn 같은_링크를_동시에_두_번_열어도_세션은_하나만_생긴다() {
    let bench = bench!();
    let mut store = bench.store();
    store
        .invite("kim@example.com", &[ident("member")], NOW)
        .unwrap();
    let browser = secret(9);
    // 한 번은 우연히 차례로 돌 수 있으니 여러 번 겨룬다
    for round in 0..5u64 {
        let link = store
            .request_link("kim@example.com", "/", &browser, NOW + round * 60)
            .unwrap()
            .unwrap();
        let link = Arc::new(link);
        let gate = Arc::new(Barrier::new(2));
        let racers: Vec<_> = (0..2)
            .map(|_| {
                let mut racer = bench.store();
                let (link, gate) = (Arc::clone(&link), Arc::clone(&gate));
                let browser = secret(9);
                std::thread::spawn(move || {
                    gate.wait();
                    racer.enter(&link, &browser, NOW + round * 60 + 1)
                })
            })
            .collect();
        let results: Vec<_> = racers
            .into_iter()
            .map(|racer| racer.join().unwrap())
            .collect();
        let passed = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(passed, 1, "{round}: {results:?}");
        assert!(results.iter().any(|result| matches!(
            result,
            Err(AuthError::Link(orbital_core::auth::LinkRefusal::Used))
        )));
        assert_eq!(bench.count("session"), i64::try_from(round).unwrap() + 1);
    }
    // 사용자도 하나다
    assert_eq!(bench.count("users"), 1);
}

#[test]
fn 초대받지_않은_이메일로는_링크가_만들어지지_않는다() {
    let bench = bench!();
    let mut store = bench.store();
    let browser = secret(9);
    assert!(
        store
            .request_link("stranger@example.com", "/", &browser, NOW)
            .unwrap()
            .is_none()
    );
    assert_eq!(bench.count("email_link"), 0);

    store
        .invite("Kim@Example.com", &[ident("member")], NOW)
        .unwrap();
    // 초대가 만료된 뒤에는 만들어지지 않는다
    assert!(
        store
            .request_link("kim@example.com", "/", &browser, NOW + INVITATION_TTL)
            .unwrap()
            .is_none()
    );
    assert_eq!(bench.count("email_link"), 0);
    // 만료 전에는 대소문자가 달라도 같은 이메일이다
    assert!(
        store
            .request_link("kim@example.com", "/", &browser, NOW + INVITATION_TTL - 1)
            .unwrap()
            .is_some()
    );
    assert_eq!(bench.count("email_link"), 1);
}

#[test]
fn 초대받은_사용자가_처음_들어오면_초대의_업무_역할을_갖고_초대는_받아들여진_것이_된다() {
    let bench = bench!();
    let mut store = bench.store();
    // 선언에 없는 업무 역할로는 초대하지 못한다
    assert!(matches!(
        store.invite("kim@example.com", &[ident("auditor")], NOW),
        Err(AuthError::UndeclaredRoles { .. })
    ));
    assert_eq!(bench.count("invitation"), 0);

    store
        .invite("kim@example.com", &[ident("manager")], NOW)
        .unwrap();
    let browser = secret(9);
    let link = store
        .request_link("kim@example.com", "https://evil.example/", &browser, NOW)
        .unwrap()
        .unwrap();
    // 다른 브라우저로는 들어오지 못하고, 링크는 남는다
    assert!(matches!(
        store.enter(&link, &secret(8), NOW + 1),
        Err(AuthError::Link(
            orbital_core::auth::LinkRefusal::OtherBrowser
        ))
    ));
    let entered = store.enter(&link, &browser, NOW + 1).unwrap();
    assert_eq!(entered.user.roles, vec!["manager".to_owned()]);
    assert_eq!(entered.user.email, "kim@example.com");
    // 바깥으로 가는 next 는 첫 화면으로 바뀌어 있다
    assert_eq!(entered.next, "/");

    let found = store.session(&entered.session, NOW + 2).unwrap().unwrap();
    assert_eq!(found.id, entered.user.id);
    assert_eq!(found.roles, vec!["manager".to_owned()]);
    assert!(found.id.starts_with("u_") && found.id.len() == 22);

    let mut superuser = bench.superuser();
    let accepted: bool = superuser
        .query_one(
            "SELECT accepted_at IS NOT NULL FROM orbital_auth.invitation WHERE email = 'kim@example.com'",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(accepted);
    let login: String = superuser
        .query_one(
            "SELECT user_id FROM orbital_auth.login WHERE provider = 'email' AND subject = 'kim@example.com'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(login, entered.user.id);

    // 두 번째로 들어올 때는 사용자를 새로 만들지 않는다
    let again = store
        .request_link("kim@example.com", "/", &browser, NOW + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        store.enter(&again, &browser, NOW + 61).unwrap().user.id,
        entered.user.id
    );
    assert_eq!(bench.count("users"), 1);

    // 업무 역할을 바꾸면 세션이 새 역할을 돌려준다
    store
        .set_roles(&entered.user.id, &[ident("member"), ident("manager")])
        .unwrap();
    assert_eq!(
        store
            .session(&entered.session, NOW + 62)
            .unwrap()
            .unwrap()
            .roles,
        vec!["manager".to_owned(), "member".to_owned()]
    );
    assert!(matches!(
        store.set_roles(&entered.user.id, &[ident("auditor")]),
        Err(AuthError::UndeclaredRoles { .. })
    ));
}

#[test]
fn 사용자를_빼면_그_사용자의_세션이_모두_없는_것이_된다() {
    let bench = bench!();
    let mut store = bench.store();
    let (kim, first) = sign_in(&mut store, "kim@example.com", &["member"]);
    let browser = secret(9);
    let link = store
        .request_link("kim@example.com", "/", &browser, NOW + 60)
        .unwrap()
        .unwrap();
    let second = store.enter(&link, &browser, NOW + 61).unwrap().session;
    let (_, lee) = sign_in(&mut store, "lee@example.com", &["member"]);

    store.remove(&kim, NOW + 70).unwrap();
    assert!(store.session(&first, NOW + 71).unwrap().is_none());
    assert!(store.session(&second, NOW + 71).unwrap().is_none());
    // 다른 사용자의 세션은 그대로다
    assert!(store.session(&lee, NOW + 71).unwrap().is_some());
    // 막힌 사용자에게는 링크가 만들어지지 않는다
    assert!(
        store
            .request_link("kim@example.com", "/", &browser, NOW + 200)
            .unwrap()
            .is_none()
    );
    let users = store.users().unwrap();
    assert_eq!(users.len(), 2);
    assert!(users.iter().any(|user| user.id == kim && user.disabled));

    // 세션 하나를 거두면 그것만 없는 것이 된다
    let (_, park) = sign_in(&mut store, "park@example.com", &["member"]);
    store.revoke(&lee, NOW + 210).unwrap();
    assert!(store.session(&lee, NOW + 211).unwrap().is_none());
    assert!(store.session(&park, NOW + 211).unwrap().is_some());
}

#[test]
fn orbital_me_는_자기_한_줄만_돌려주고_orbital_users_는_directory_의_역할만_읽는다() {
    let bench = bench!();
    let mut store = bench.store();
    let (kim, _) = sign_in(&mut store, "kim@example.com", &["member"]);
    let (lee, _) = sign_in(&mut store, "lee@example.com", &["manager"]);

    let mut member = bench.login("api", "member");
    let mut transaction = member.transaction().unwrap();
    transaction
        .execute(
            "SELECT set_config('orbital.identity', $1, true)",
            &[&bench.identity(&kim)],
        )
        .unwrap();
    let rows = transaction
        .query("SELECT id, email, roles FROM orbital.me", &[])
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), kim);
    assert_eq!(rows[0].get::<_, String>(1), "kim@example.com");
    assert_eq!(rows[0].get::<_, Vec<String>>(2), vec!["member".to_owned()]);
    transaction.commit().unwrap();
    // 신원이 없으면 아무 줄도 없다
    assert!(
        member
            .query("SELECT id FROM orbital.me", &[])
            .unwrap()
            .is_empty()
    );
    // 서명 없이 남의 식별자를 실어도 남의 줄은 보이지 않는다
    let mut transaction = member.transaction().unwrap();
    transaction
        .execute("SELECT set_config('orbital.identity', $1, true)", &[&lee])
        .unwrap();
    assert!(
        transaction
            .query("SELECT id FROM orbital.me", &[])
            .unwrap()
            .is_empty()
    );
    transaction.commit().unwrap();

    // directory 에 없는 역할은 다른 사용자의 목록을 읽지 못한다
    assert!(denied(member.query("SELECT * FROM orbital.users", &[])));
    assert!(denied(
        bench
            .login("web", "member")
            .query("SELECT * FROM orbital.users", &[])
    ));
    // directory 의 역할은 읽는다. 이름과 이메일만 있다
    let mut manager = bench.login("api", "manager");
    let rows = manager
        .query("SELECT * FROM orbital.users ORDER BY email", &[])
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].columns().len(), 3);
    assert_eq!(rows[1].get::<_, String>("id"), lee);
    // 소유자도 뷰를 바꾸거나 읽지 못한다
    assert!(denied(
        bench
            .migrator(true)
            .query("SELECT * FROM orbital.users", &[])
    ));
}

// ---- 리허설 · 되돌릴 지점 · 검사 ----

#[test]
fn 리허설의_사본과_되돌릴_지점은_사용자와_세션을_함께_갖는다() {
    let mut bench = bench!();
    let mut store = bench.store();
    let (kim, session) = sign_in(&mut store, "kim@example.com", &["member"]);
    drop(store);

    let rehearsal = bench.admin.rehearse(&bench.names, &[]).unwrap();
    for (table, rows) in [("orbital_auth.users", 1), ("orbital_auth.session", 1)] {
        let count = rehearsal
            .tables
            .iter()
            .find(|count| count.table == table)
            .unwrap_or_else(|| panic!("{table}"));
        assert_eq!(
            (count.before, count.after),
            (Some(rows), Some(rows)),
            "{table}"
        );
    }
    assert!(!format!("{rehearsal:?}").contains("kim@"));

    let point = bench.admin.mark(&bench.names).unwrap();
    // 사본에는 인증 역할도 접속하지 못한다
    assert!(
        bench
            .admin
            .connect_as(point.database(), &bench.names.auth())
            .is_err()
    );

    // 지점을 뜬 뒤에 사용자를 빼고 다른 사람이 들어온다
    let mut store = bench.store();
    store.remove(&kim, NOW + 10).unwrap();
    sign_in(&mut store, "lee@example.com", &["member"]);
    drop(store);

    bench
        .admin
        .restore(&bench.names, &bench.manifest, &point)
        .unwrap();
    let mut store = bench.store();
    let found = store.session(&session, NOW + 20).unwrap().unwrap();
    assert_eq!(found.id, kim);
    assert_eq!(store.users().unwrap().len(), 1);
    drop(store);
    assert_eq!(bench.findings(), vec![]);
}

#[test]
fn auth_를_선언한_인스턴스도_계획대로_세우면_권한_검사를_통과한다() {
    let mut bench = bench!();
    assert_eq!(bench.findings(), vec![]);
    // 다시 세워도 같다
    bench
        .admin
        .provision(&bench.names, &bench.manifest)
        .unwrap();
    bench
        .admin
        .install_auth(&bench.names, &bench.manifest)
        .unwrap();
    bench
        .admin
        .grant(&bench.names, &bench.manifest, &bench.access)
        .unwrap();
    assert_eq!(bench.findings(), vec![]);
    assert!(bench.role_exists(&bench.names.auth()));
}

#[test]
fn auth_를_선언하지_않은_인스턴스에는_orbital_auth_도_인증_역할도_없다() {
    let mut bench = bench!(MANIFEST_WITHOUT_AUTH, MIGRATION_WITHOUT_AUTH);
    assert_eq!(bench.findings(), vec![]);
    assert!(!bench.role_exists(&bench.names.auth()));
    let mut superuser = bench.superuser();
    for (what, sql) in [
        (
            "스키마",
            "SELECT 1 FROM pg_namespace WHERE nspname = 'orbital_auth'",
        ),
        (
            "확장",
            "SELECT 1 FROM pg_extension WHERE extname = 'citext'",
        ),
        (
            "뷰",
            "SELECT 1 FROM pg_class WHERE relnamespace = 'orbital'::regnamespace AND relname IN ('me', 'users')",
        ),
    ] {
        assert!(superuser.query(sql, &[]).unwrap().is_empty(), "{what}");
    }
    assert!(matches!(
        bench.admin.auth_store(&bench.names, &bench.manifest),
        Err(AuthError::NotDeclared)
    ));
}

// ---- 횟수 제한 · 세션을 본 시각 · 프리뷰의 씨앗 사용자 ----

#[test]
fn 같은_이메일로_1분_안에_다시_요청하면_링크가_만들어지지_않는다() {
    let bench = bench!();
    let mut store = bench.store();
    store
        .invite("kim@example.com", &[ident("member")], NOW)
        .unwrap();
    let browser = secret(9);
    let first = store.request_link("kim@example.com", "/", &browser, NOW);
    assert!(first.unwrap().is_some());
    // 대소문자가 달라도 같은 이메일이다
    for (email, at) in [("kim@example.com", NOW + 59), ("KIM@example.com", NOW + 30)] {
        assert!(
            store
                .request_link(email, "/", &browser, at)
                .unwrap()
                .is_none(),
            "{email} {at}"
        );
    }
    assert_eq!(bench.count("email_link"), 1);
    assert!(
        store
            .request_link("kim@example.com", "/", &browser, NOW + 60)
            .unwrap()
            .is_some()
    );
    assert_eq!(bench.count("email_link"), 2);
}

#[test]
fn 세션을_본_시각은_마지막으로_적은_지_1분이_지났을_때만_적는다() {
    let bench = bench!();
    let mut store = bench.store();
    let (_, session) = sign_in(&mut store, "kim@example.com", &["member"]);
    let seen = |bench: &Bench| -> i64 {
        bench
            .superuser()
            .query_one(
                "SELECT extract(epoch FROM last_seen_at)::bigint FROM orbital_auth.session",
                &[],
            )
            .unwrap()
            .get(0)
    };
    let made = i64::try_from(NOW + 1).unwrap();
    assert_eq!(seen(&bench), made);
    store.session(&session, NOW + 30).unwrap().unwrap();
    store.session(&session, NOW + 60).unwrap().unwrap();
    assert_eq!(seen(&bench), made);
    store.session(&session, NOW + 61).unwrap().unwrap();
    assert_eq!(seen(&bench), made + 60);
}

#[test]
fn 씨앗_사용자는_u_모양이_아닌_식별자로_들어가고_그_database_에서만_규칙이_넓어진다() {
    let mut bench = bench!();
    let users = toml::from_str::<orbital_core::auth::SeedUsers>(
        "[[user]]\nid = \"u1\"\nemail = \"u1@example.test\"\nroles = [\"member\"]\n",
    )
    .unwrap()
    .check(&bench.manifest)
    .unwrap();
    // 넓히기 전에는 u_ 모양이 아닌 식별자가 들어가지 않는다
    let strict = bench.superuser().execute(
        "INSERT INTO orbital_auth.users (id, email, created_at) VALUES ('u9', 'u9@example.test', now())",
        &[],
    );
    assert_eq!(strict.unwrap_err().code(), Some(&SqlState::CHECK_VIOLATION));
    bench.admin.seed_users(&bench.names, &users, NOW).unwrap();
    let mut store = bench.store();
    let (session, user) = store.start_session("u1", NOW).unwrap();
    assert_eq!(user.roles, vec!["member".to_owned()]);
    assert_eq!(store.session(&session, NOW + 1).unwrap().unwrap().id, "u1");
    // 넓어져도 따옴표나 대문자가 든 식별자는 들어가지 않는다
    let odd = bench.superuser().execute(
        "INSERT INTO orbital_auth.users (id, email, created_at) VALUES ('U\"1', 'x@example.test', now())",
        &[],
    );
    assert_eq!(odd.unwrap_err().code(), Some(&SqlState::CHECK_VIOLATION));
    assert!(matches!(
        store.start_session("nobody", NOW),
        Err(AuthError::NoSuchUser)
    ));
    // 막힌 사용자는 세션을 만들지 못한다
    store.remove("u1", NOW + 2).unwrap();
    assert!(matches!(
        store.start_session("u1", NOW + 3),
        Err(AuthError::UserDisabled)
    ));
}

// ---- 쓰고 남은 줄 ----

#[test]
fn 쓰고_남은_표와_만료된_링크는_지워진다() {
    use orbital_core::oauth::Accepted;
    use orbital_core::sweep::LEFTOVER_RETENTION;
    use orbital_pg::oauth::s256;

    let bench = bench!();
    let mut store = bench.store();
    // 지금(NOW): 김이 링크로 들어오고(링크 · 세션), 로그아웃한 세션 하나와 살아 있는 세션 하나를 둔다
    let (kim, old_session) = sign_in(&mut store, "kim@example.com", &["member"]);
    store.revoke(&old_session, NOW + 2).unwrap();
    let (live_session, _) = store.start_session(&kim, NOW + 3).unwrap();
    // Google 로그인의 표, MCP 의 인가 요청 · 코드 · 토큰(access 1시간, refresh 30일)
    store
        .issue_google_ticket("kim@example.com", "google-sub", "/", &[1; 32], NOW)
        .unwrap();
    let redirect = "https://client.example/callback".to_owned();
    let client = store
        .register_client(
            "registered",
            "클라이언트",
            std::slice::from_ref(&redirect),
            None,
            NOW,
        )
        .unwrap();
    let verifier = "v".repeat(43);
    let accepted = Accepted {
        client_id: client.clone(),
        redirect_uri: redirect.clone(),
        code_challenge: s256(&verifier),
        resource: "https://app.example/mcp".to_owned(),
        scope: "mcp".to_owned(),
        state: None,
    };
    let request = store.open_request(&kim, &accepted, NOW).unwrap();
    let location = store
        .decide(&request, &kim, true, "https://app.example", NOW)
        .unwrap();
    let code = location
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("code="))
        .and_then(Secret::parse)
        .expect("승인의 주소에 코드가 없습니다");
    store
        .exchange_code(&code, &verifier, &client, &redirect, None, NOW)
        .unwrap();
    // 만료가 하루가 되지 않은 동안은 아무것도 지우지 않는다
    let soon = NOW + 60 * 60;
    store
        .invite("lee@example.com", &[ident("member")], soon)
        .unwrap();
    store
        .request_link("lee@example.com", "/", &secret(8), soon)
        .unwrap()
        .unwrap();
    for (table, count) in [
        ("email_link", 2),
        ("google_ticket", 1),
        ("oauth_request", 1),
        ("oauth_code", 1),
        ("session", 2),
        ("oauth_token", 2),
    ] {
        assert_eq!(bench.count(table), count, "{table}");
    }

    // 이틀 뒤 이가 새 링크로 들어온다(새 줄을 적는다). 쓴 지 오래됐거나 만료된 줄은 함께 지워진다
    let later = NOW + 2 * LEFTOVER_RETENTION;
    let link = store
        .request_link("lee@example.com", "/", &secret(7), later)
        .unwrap()
        .unwrap();
    store.enter(&link, &secret(7), later + 1).unwrap();
    for (table, count) in [
        // 이가 방금 받은 링크 하나
        ("email_link", 1),
        ("google_ticket", 0),
        ("oauth_request", 0),
        ("oauth_code", 0),
        // 김의 살아 있는 세션과 이의 새 세션. 로그아웃한 세션은 지워졌다
        ("session", 2),
        // 만료 전인 refresh 토큰은 남는다(다시 쓰이면 그 승인을 거두는 근거다)
        ("oauth_token", 1),
    ] {
        assert_eq!(bench.count(table), count, "{table}");
    }
    // 살아 있는 세션은 그대로 읽힌다
    assert!(store.session(&live_session, later + 2).unwrap().is_some());
}
