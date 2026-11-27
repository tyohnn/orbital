//! 팩토리(조직)와 service key 는 레이어의 기록(control database)에 있다. 대시보드가 가입을 받으면 운영자 키로 조직을 만들고 첫 키를 받아
//! 한 번만 보여 주고, 팩토리는 그 키로 키를 더 만들고 보고 폐기한다. 같은 control database 를 보는 관리 서버 둘(기계 `a` · `b`)을 띄워 잰다.
//!
//! 실제 PostgreSQL 과 실제 git 으로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에 바로 넣는다. 막는 테스트는 그 키로 실제로 해 본다.
//! 테스트의 키는 한눈에 가짜인 글자이고, 레이어가 낸 키는 테스트가 답에서 받는다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use orbital_core::name::Ident;
use orbital_run::LocalRunner;
use orbital_server::http::{Call, handle, handle_call};
use orbital_server::layer::{Layer, Options};
use orbital_server::records::drop_database;
use orbital_server::seal::SealKey;
use orbital_server::token::hex;
use postgres::{Client, Config, NoTls};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)에 적은 열쇠. 조직 `factory` 의 것이다.
const FACTORY: &str = "sk_test_factory";
/// 설정에만 있는 다른 조직 `other` 의 열쇠.
const OTHER: &str = "sk_test_other";
/// 운영자 키(`ORBITAL_ADMIN_KEY`).
const ADMIN: &str = "admin_key_for_tests_0123456789abcdef";
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sha(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

fn git(folder: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(folder)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=factory",
            "-c",
            "user.email=factory@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// 폴더 아래의 모든 파일의 내용을 바이트로 이어 붙인다.
fn all_bytes(folder: &Path, into: &mut Vec<u8>) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => all_bytes(&path, into),
            Ok(kind) if kind.is_file() => {
                if let Ok(bytes) = fs::read(&path) {
                    into.extend_from_slice(&bytes);
                }
                into.extend_from_slice(path.to_string_lossy().as_bytes());
            }
            _ => {}
        }
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn fresh_name(lead: &str) -> Ident {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    Ident::parse(&format!(
        "{lead}_{}_{}_{}",
        std::process::id() % 100_000,
        COUNTER.fetch_add(1, Ordering::Relaxed),
        nanos % 1000
    ))
    .unwrap()
}

/// 낸 열쇠(값과 식별자).
#[derive(Clone)]
struct Key {
    value: String,
    id: String,
}

/// 같은 control database 를 보는 관리 서버들.
struct Bench {
    scratch: PathBuf,
    pg_url: String,
    control: Ident,
    /// 레이어의 시계. 0 이면 실제 시각이다.
    clock: Arc<AtomicU64>,
    /// 운영자 키를 줄까.
    admin: bool,
    test_limit: u32,
    servers: BTreeMap<String, Layer>,
    /// (인스턴스, 놓인 기계). 끝날 때 걷는다.
    instances: Vec<(String, String)>,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-organizations-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        Some(Self {
            scratch,
            pg_url,
            control: fresh_name("ctl"),
            clock: Arc::new(AtomicU64::new(0)),
            admin: true,
            test_limit: 10,
            servers: BTreeMap::new(),
            instances: Vec::new(),
        })
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    /// 기계 하나의 관리 서버를 띄운다. 이미 떠 있으면 내리고 다시 띄운다(같은 기계의 관리 서버는 하나만 뜬다).
    fn open(&mut self, machine: &str) {
        self.servers.remove(machine);
        let clock = Arc::clone(&self.clock);
        let options = Options {
            seal_key: Some(SealKey::from_bytes([7; 32])),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(machine).unwrap(),
            token_key: Some([3; 32].to_vec()),
            admin_key: self.admin.then(|| ADMIN.to_owned()),
            test_instance_limit: self.test_limit,
            clock: Arc::new(move || match clock.load(Ordering::SeqCst) {
                0 => now(),
                at => at,
            }),
            ..Options::new(
                self.home(machine),
                self.pg_url.clone(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        };
        let layer = Layer::open(options).expect("레이어를 열지 못했습니다");
        self.servers.insert(machine.to_owned(), layer);
    }

    fn layer(&self, name: &str) -> &Layer {
        &self.servers[name]
    }

    /// 관리 서버의 HTTP 층에 바로 넣는다. (상태, 본문의 JSON, 본문의 날것).
    fn raw(
        &self,
        on: &str,
        method: &str,
        path: &str,
        bearer: &str,
        body: &[u8],
    ) -> (u16, Value, String) {
        let reply = handle(self.layer(on), method, path, Some(bearer), body);
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
            String::from_utf8_lossy(&reply.body).into_owned(),
        )
    }

    fn call(&self, on: &str, method: &str, path: &str, bearer: &str, body: &[u8]) -> (u16, Value) {
        let (status, json, _) = self.raw(on, method, path, bearer, body);
        (status, json)
    }

    fn post(&self, on: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
        self.call(on, "POST", path, bearer, body.to_string().as_bytes())
    }

    /// 운영자가 조직을 만든다. 첫 키를 돌려준다.
    fn organization(&self, on: &str, id: &str, kind: &str) -> Key {
        let (status, body) = self.post(
            on,
            "/v1/admin/organizations",
            ADMIN,
            &json!({ "id": id, "label": format!("{id} 개발사"), "kind": kind }),
        );
        assert_eq!(status, 201, "{body}");
        assert_eq!(body["organization"], id);
        Key {
            value: body["key"]["secret"].as_str().unwrap().to_owned(),
            id: body["key"]["id"].as_str().unwrap().to_owned(),
        }
    }

    /// 조직의 키로 키를 하나 더 낸다.
    fn issue(&self, on: &str, key: &str, label: &str) -> Key {
        let (status, body) = self.post(on, "/v1/keys", key, &json!({ "label": label }));
        assert_eq!(status, 201, "{body}");
        assert_eq!(body["label"], label);
        Key {
            value: body["secret"].as_str().unwrap().to_owned(),
            id: body["id"].as_str().unwrap().to_owned(),
        }
    }

    fn keys(&self, on: &str, key: &str) -> Vec<Value> {
        let (status, body) = self.call(on, "GET", "/v1/keys", key, &[]);
        assert_eq!(status, 200, "{body}");
        body["keys"].as_array().unwrap().clone()
    }

    fn revoke(&self, on: &str, key: &str, id: &str) -> (u16, Value) {
        self.call(on, "POST", &format!("/v1/keys/{id}/revoke"), key, &[])
    }

    /// 운영자 키로 `/v1/admin/organizations/{id}{tail}` 에 POST 한다.
    fn admin(&self, on: &str, id: &str, tail: &str) -> (u16, Value) {
        self.call(
            on,
            "POST",
            &format!("/v1/admin/organizations/{id}{tail}"),
            ADMIN,
            &[],
        )
    }

    /// service key 로만 되는 길 하나. 키가 살아 있는지 본다.
    fn alive(&self, on: &str, key: &str) -> u16 {
        self.call(on, "GET", "/v1/settings/auth", key, &[]).0
    }

    /// 그 열쇠의 조직에 스캐폴드를 올린다.
    fn upload(&self, on: &str, key: &str) {
        let label = sha(key);
        let folder = self.scratch.join(format!("scaffold-{}", &label[..12]));
        let _ = fs::remove_dir_all(&folder);
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/records"),
            &folder,
        );
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{}.bundle", &label[..12]));
        git(
            &folder,
            &[
                "bundle",
                "create",
                "--quiet",
                bundle.to_str().unwrap(),
                "--all",
            ],
        );
        let (status, body) = self.call(
            on,
            "PUT",
            "/v1/apps/records",
            key,
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
    }

    /// 인스턴스를 세워 본다. (상태, 본문).
    fn try_instance(&mut self, on: &str, key: &str) -> (u16, Value) {
        let (status, body) = self.post(
            on,
            "/v1/instances",
            key,
            &json!({ "app": "records", "version": "v1" }),
        );
        if status == 200 {
            self.instances
                .push((body["instance"].as_str().unwrap().to_owned(), on.to_owned()));
        }
        (status, body)
    }

    fn instance(&mut self, on: &str, key: &str) -> String {
        let (status, body) = self.try_instance(on, key);
        assert_eq!(status, 200, "{body}");
        body["instance"].as_str().unwrap().to_owned()
    }

    fn destroy(&self, on: &str, key: &str, instance: &str) {
        let (status, body) =
            self.call(on, "DELETE", &format!("/v1/instances/{instance}"), key, &[]);
        assert_eq!(status, 200, "{body}");
    }

    fn control(&self) -> Client {
        let mut config: Config = self.pg_url.parse().unwrap();
        config.dbname(self.control.as_str());
        config.connect(NoTls).unwrap()
    }

    /// control database 의 모든 표의 모든 줄을 글로.
    fn everything(&self) -> String {
        let mut client = self.control();
        let tables: Vec<String> = client
            .query(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'orbital' ORDER BY 1",
                &[],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        let mut text = String::new();
        for table in tables {
            for row in client
                .query(
                    &format!("SELECT row_to_json(t)::text FROM orbital.\"{table}\" t"),
                    &[],
                )
                .unwrap()
            {
                text.push_str(&row.get::<_, String>(0));
                text.push('\n');
            }
        }
        text
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // 열쇠가 닫혔을 수 있다. 인스턴스의 database 는 관리 역할로 걷고, 코드 저장소는 폴더와 함께 걷는다
        for (instance, _) in &self.instances {
            if let Ok(mut admin) = orbital_pg::Admin::connect(&self.pg_url) {
                let names = orbital_core::plan::Names::new(
                    orbital_core::name::InstanceId::parse(instance).unwrap(),
                );
                let _ = admin.destroy(&names);
            }
        }
        self.servers.clear();
        let _ = drop_database(&self.pg_url, &self.control);
        let _ = fs::remove_dir_all(&self.scratch);
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

fn ids(keys: &[Value]) -> Vec<String> {
    keys.iter()
        .map(|key| key["id"].as_str().unwrap().to_owned())
        .collect()
}

/// 그 조직의 살아 있는 키를 기록에서 모두 폐기한다. API 로는 마지막 키를 폐기하지 못하므로, 키의 비밀을 모두 잃은 조직을 이렇게 만든다.
fn lose_all_keys(bench: &Bench, organization: &str) {
    bench
        .control()
        .execute(
            "UPDATE orbital.service_key SET revoked_at = 1 WHERE organization = $1 AND revoked_at IS NULL",
            &[&organization],
        )
        .unwrap();
}

// ---- 운영자와 첫 키 ----

#[test]
fn 운영자_키로_조직을_만들면_첫_service_key_를_한_번만_보여_주고_그_키로_부른다() {
    let mut bench = bench!();
    bench.open("a");
    let (status, body) = bench.post(
        "a",
        "/v1/admin/organizations",
        ADMIN,
        &json!({ "id": "acme", "label": "Acme 팩토리" }),
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["organization"], "acme");
    let first = Key {
        value: body["key"]["secret"].as_str().unwrap().to_owned(),
        id: body["key"]["id"].as_str().unwrap().to_owned(),
    };
    assert!(first.value.starts_with("orb_sk_"), "{}", first.value);
    assert!(first.id.starts_with("key_"), "{}", first.id);
    assert!(body["key"]["revoked_at"].is_null());
    // 그 키로 조직의 일을 한다: 앱을 올리고 인스턴스를 세운다
    bench.upload("a", &first.value);
    let instance = bench.instance("a", &first.value);
    // 목록에는 그 키가 있되 비밀은 다시 보이지 않는다
    let keys = bench.keys("a", &first.value);
    assert_eq!(ids(&keys), vec![first.id.clone()]);
    assert!(keys[0].get("secret").is_none());
    assert!(
        !Value::Array(keys.clone())
            .to_string()
            .contains(&first.value)
    );
    // 운영자는 조직의 이름과 숫자를 본다. 종류를 적지 않았으면 운영의 조직이다
    let (status, report) = bench.call("a", "GET", "/v1/admin/organizations/acme", ADMIN, &[]);
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["name"], "Acme 팩토리");
    assert_eq!(report["kind"], "live");
    assert_eq!(report["instances"], 1);
    assert_eq!(report["keys"], 1);
    let (status, list) = bench.call("a", "GET", "/v1/admin/organizations", ADMIN, &[]);
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["organizations"][0]["id"], "acme");
    assert!(!list.to_string().contains(&first.value));
    bench.destroy("a", &first.value, &instance);
}

#[test]
fn 시험용_조직과_운영의_조직의_키는_모두_orb_sk_로_시작하고_종류는_조직이_안다() {
    let mut bench = bench!();
    bench.open("a");
    let test = bench.organization("a", "sandbox", "test");
    let live = bench.organization("a", "acme", "live");
    for key in [
        test.value.clone(),
        live.value.clone(),
        bench.issue("a", &test.value, "둘째").value,
        bench.issue("a", &live.value, "둘째").value,
    ] {
        assert!(key.starts_with("orb_sk_"), "{key}");
        assert!(!key.contains("test") && !key.contains("live"), "{key}");
    }
    for (id, kind) in [("sandbox", "test"), ("acme", "live")] {
        let (status, report) = bench.call(
            "a",
            "GET",
            &format!("/v1/admin/organizations/{id}"),
            ADMIN,
            &[],
        );
        assert_eq!(status, 200, "{report}");
        assert_eq!(report["kind"], kind);
    }
    // 모르는 종류는 받지 않는다
    let (status, _) = bench.post(
        "a",
        "/v1/admin/organizations",
        ADMIN,
        &json!({ "id": "odd", "kind": "trial" }),
    );
    assert!((400..500).contains(&status), "{status}");
}

#[test]
fn 운영자_키가_없거나_틀리거나_service_key_면_조직을_만들지_못한다() {
    let mut bench = bench!();
    bench.open("a");
    let body = json!({ "id": "acme" }).to_string();
    for bearer in [
        None,
        Some("wrong_admin_key_0123456789abcdef0123"),
        Some(FACTORY),
    ] {
        let reply = handle(
            bench.layer("a"),
            "POST",
            "/v1/admin/organizations",
            bearer,
            body.as_bytes(),
        );
        assert_eq!(reply.status, 401, "{bearer:?}");
    }
    let acme = bench.organization("a", "acme", "live");
    let (status, _) = bench.post(
        "a",
        "/v1/admin/organizations",
        &acme.value,
        &json!({ "id": "other" }),
    );
    assert_eq!(status, 401);
    assert_eq!(bench.layer("a").records().organizations().unwrap().len(), 1);
}

#[test]
fn 운영자_키를_주지_않은_레이어에서는_운영자의_길이_누구에게도_열리지_않는다() {
    let mut bench = bench!();
    bench.admin = false;
    bench.open("a");
    for (method, path) in [
        ("POST", "/v1/admin/organizations"),
        ("GET", "/v1/admin/organizations"),
        ("GET", "/v1/admin/organizations/factory"),
        ("POST", "/v1/admin/organizations/factory/keys"),
        ("POST", "/v1/admin/organizations/factory/reset-keys"),
        ("POST", "/v1/admin/organizations/factory/close"),
    ] {
        for bearer in [ADMIN, FACTORY] {
            let body = json!({ "id": "acme", "label": "Acme" });
            let (status, answer) =
                bench.call("a", method, path, bearer, body.to_string().as_bytes());
            assert_eq!(status, 401, "{method} {path}: {answer}");
        }
    }
    assert!(
        bench
            .layer("a")
            .records()
            .organizations()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn 이미_있는_조직이나_환경_변수의_조직은_다시_만들지_못하고_이름이_틀리면_400_이다() {
    let mut bench = bench!();
    bench.open("a");
    bench.organization("a", "acme", "live");
    for id in ["acme", "factory"] {
        let (status, again) = bench.post(
            "a",
            "/v1/admin/organizations",
            ADMIN,
            &json!({ "id": id, "kind": "test" }),
        );
        assert_eq!(status, 409, "{id}: {again}");
        // 첫 키도 새로 나오지 않는다
        assert!(again.get("key").is_none());
    }
    for id in ["", "Acme", "-acme", "ac me", "아크미", "acme; DROP"] {
        let (status, _) = bench.post("a", "/v1/admin/organizations", ADMIN, &json!({ "id": id }));
        assert_eq!(status, 400, "{id}");
    }
    // 하이픈과 숫자로 시작하는 이름(대시보드가 짓는 이름)은 받는다
    bench.organization("a", "0-factory-co_1", "live");
    assert_eq!(bench.layer("a").records().organizations().unwrap().len(), 2);
}

#[test]
fn 운영자의_열쇠로는_인스턴스_승격_비밀_사용자_열쇠의_일을_하지_못한다() {
    let mut bench = bench!();
    bench.open("a");
    bench.upload("a", FACTORY);
    let instance = bench.instance("a", FACTORY);
    let at = |tail: &str| format!("/v1/instances/{instance}{tail}");
    let promotion =
        json!({ "release": "r", "change": "customer_request", "approved_by": "customer" })
            .to_string();
    let cases: Vec<(&str, String, Vec<u8>)> = vec![
        (
            "POST",
            "/v1/instances".to_owned(),
            json!({ "app": "records", "version": "v1" })
                .to_string()
                .into_bytes(),
        ),
        ("PUT", "/v1/apps/records".to_owned(), b"bundle".to_vec()),
        (
            "POST",
            at("/sessions"),
            json!({ "can": ALL }).to_string().into_bytes(),
        ),
        ("POST", at("/promotions"), promotion.into_bytes()),
        ("GET", at("/secrets"), Vec::new()),
        (
            "PUT",
            at("/secrets/BANK_API_KEY"),
            json!({ "stage": "production", "value": "v" })
                .to_string()
                .into_bytes(),
        ),
        ("GET", at("/users"), Vec::new()),
        ("DELETE", at(""), Vec::new()),
        ("GET", "/v1/keys".to_owned(), Vec::new()),
        (
            "POST",
            "/v1/keys".to_owned(),
            json!({ "label": "몰래" }).to_string().into_bytes(),
        ),
        (
            "POST",
            "/v1/keys/key_0000000000000000/revoke".to_owned(),
            Vec::new(),
        ),
        ("GET", "/v1/settings/auth".to_owned(), Vec::new()),
        (
            "GET",
            at("/git/info/refs?service=git-upload-pack"),
            Vec::new(),
        ),
    ];
    for (method, path, body) in &cases {
        let (status, answer) = bench.call("a", method, path, ADMIN, body);
        assert_eq!(status, 403, "{method} {path}: {answer}");
    }
    // 아무것도 바뀌지 않았다
    let records = bench.layer("a").records();
    assert_eq!(records.instances().unwrap().len(), 1);
    assert!(records.instance(&instance).unwrap().is_some());
    assert!(records.organizations().unwrap().is_empty());
    bench.destroy("a", FACTORY, &instance);
}

#[test]
fn service_key_와_작업의_토큰으로는_운영자의_길을_열지_못하고_토큰으로는_열쇠를_내지_못한다() {
    let mut bench = bench!();
    bench.open("a");
    let recorded = bench.organization("a", "acme", "live");
    bench.upload("a", &recorded.value);
    let instance = bench.instance("a", &recorded.value);
    let (status, opened) = bench.post(
        "a",
        &format!("/v1/instances/{instance}/sessions"),
        &recorded.value,
        &json!({ "can": ALL }),
    );
    assert_eq!(status, 200, "{opened}");
    let token = opened["token"].as_str().unwrap().to_owned();
    // 서명이 맞든 틀리든 토큰 쪽에는 키의 길과 운영자의 길이 없다
    let forged = "orb1.eyJ9.forged";
    for bearer in [FACTORY, recorded.value.as_str(), token.as_str(), forged] {
        let (status, answer) = bench.post(
            "a",
            "/v1/admin/organizations",
            bearer,
            &json!({ "id": "intruder" }),
        );
        assert_eq!(status, 401, "{answer}");
        for tail in ["/keys", "/reset-keys", "/close"] {
            let (status, answer) = bench.call(
                "a",
                "POST",
                &format!("/v1/admin/organizations/acme{tail}"),
                bearer,
                &[],
            );
            assert_eq!(status, 401, "{tail}: {answer}");
        }
        let (status, answer) = bench.call("a", "GET", "/v1/admin/organizations", bearer, &[]);
        assert_eq!(status, 401, "{answer}");
    }
    for bearer in [token.as_str(), forged] {
        let (status, answer) = bench.post("a", "/v1/keys", bearer, &json!({ "label": "몰래" }));
        assert_eq!(status, 404, "{answer}");
        let (status, answer) = bench.call("a", "GET", "/v1/keys", bearer, &[]);
        assert_eq!(status, 404, "{answer}");
        let (status, answer) = bench.revoke("a", bearer, &recorded.id);
        assert_eq!(status, 404, "{answer}");
    }
    // 아무것도 바뀌지 않았다
    let records = bench.layer("a").records();
    assert_eq!(records.organizations().unwrap().len(), 1);
    assert_eq!(records.keys("acme").unwrap().len(), 1);
    assert!(
        records
            .organization("acme")
            .unwrap()
            .unwrap()
            .closed_at
            .is_none()
    );
    bench.destroy("a", &recorded.value, &instance);
}

// ---- 키 만들기와 목록 ----

#[test]
fn 조직의_키로_새_키를_만들고_목록에는_만든_차례로_비밀_없이_보인다() {
    let mut bench = bench!();
    bench.open("a");
    let first = bench.organization("a", "acme", "live");
    let deploy = bench.issue("a", &first.value, "배포 서버");
    let laptop = bench.issue("a", &first.value, "노트북");
    assert_eq!(bench.alive("a", &deploy.value), 200);
    let listed = bench.keys("a", &deploy.value);
    assert_eq!(
        ids(&listed),
        vec![first.id.clone(), deploy.id.clone(), laptop.id.clone()]
    );
    assert_eq!(listed[1]["label"], "배포 서버");
    let text = Value::Array(listed).to_string();
    for secret in [&first.value, &deploy.value, &laptop.value] {
        assert!(!text.contains(secret.as_str()));
    }
    // 이름 없이 불러도 되고, 이름은 100글자까지다
    let (status, unnamed) = bench.call("a", "POST", "/v1/keys", &first.value, &[]);
    assert_eq!(status, 201, "{unnamed}");
    assert_eq!(unnamed["label"], "");
    let (status, _) = bench.post(
        "a",
        "/v1/keys",
        &first.value,
        &json!({ "label": "가".repeat(100) }),
    );
    assert_eq!(status, 201);
    let (status, _) = bench.post(
        "a",
        "/v1/keys",
        &first.value,
        &json!({ "label": "가".repeat(101) }),
    );
    assert_eq!(status, 400);
    // 줄바꿈 같은 제어 문자는 받지 않는다
    let (status, _) = bench.post(
        "a",
        "/v1/keys",
        &first.value,
        &json!({ "label": "둘\n째 줄" }),
    );
    assert_eq!(status, 400);
    assert_eq!(bench.keys("a", &first.value).len(), 5);
}

// ---- 값은 남지 않는다 ----

#[test]
fn 열쇠의_값은_기록과_목록과_오류와_관리_서버의_폴더_어디에도_남지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    let first = bench.organization("a", "acme", "live");
    let second = bench.issue("b", &first.value, "둘째");
    let third = bench.issue("a", &second.value, "셋째").value;
    let values = [first.value.clone(), second.value.clone(), third.clone()];
    // 키를 쓰고, 폐기하고, 폐기한 키로 해 보고, 틀린 일도 해 본다
    bench.upload("a", &first.value);
    let instance = bench.instance("a", &second.value);
    let mut answers = String::new();
    let (status, _, raw) = bench.raw("a", "GET", "/v1/keys", &third, &[]);
    assert_eq!(status, 200);
    answers.push_str(&raw);
    let (status, _, raw) = bench.raw(
        "b",
        "POST",
        &format!("/v1/keys/{}/revoke", second.id),
        &first.value,
        &[],
    );
    assert_eq!(status, 200);
    answers.push_str(&raw);
    for on in ["a", "b"] {
        let (status, _, raw) = bench.raw(on, "GET", "/v1/keys", &second.value, &[]);
        assert_eq!(status, 401, "{raw}");
        answers.push_str(&raw);
        let (status, _, raw) = bench.raw(on, "POST", "/v1/keys", &first.value, b"{ not json");
        assert!(status >= 400);
        answers.push_str(&raw);
        let (_, _, raw) = bench.raw(
            on,
            "GET",
            &format!("/v1/instances/{instance}/git/info/refs?service=git-upload-pack"),
            &first.value,
            &[],
        );
        answers.push_str(&raw);
    }
    bench.destroy("a", &first.value, &instance);
    let records = bench.everything();
    let mut files = Vec::new();
    all_bytes(&bench.scratch, &mut files);
    for value in &values {
        // 머리말(`orb_sk_`)을 뗀 몸의 일부도 없다
        let body = &value["orb_sk_".len()..];
        for (place, found) in [
            ("기록", records.contains(body)),
            ("답", answers.contains(body)),
            ("폴더", contains(&files, body)),
        ] {
            assert!(!found, "키의 값이 {place}에 남았습니다");
        }
        // 기록에는 sha256 만 있다
        assert!(
            records.contains(&sha(value)),
            "기록에 키의 sha256 이 없습니다"
        );
    }
}

#[test]
fn 키는_해시로만_기록에_두고_관리_서버가_다시_떠도_남는다() {
    let mut bench = bench!();
    bench.open("a");
    let first = bench.organization("a", "acme", "live");
    let second = bench.issue("a", &first.value, "배포 서버");
    assert_eq!(bench.revoke("a", &first.value, &second.id).0, 200);
    bench.open("a");
    assert_eq!(bench.alive("a", &first.value), 200);
    assert_eq!(bench.alive("a", &second.value), 401);
    assert_eq!(bench.keys("a", &first.value).len(), 2);
}

// ---- 바꾸기와 폐기하기 ----

#[test]
fn 열쇠를_바꾸는_동안_옛_열쇠와_새_열쇠가_함께_살고_옛_것을_거두면_다음_요청부터_받지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    let old = bench.organization("a", "acme", "live");
    bench.upload("a", &old.value);
    let instance = bench.instance("a", &old.value);
    let production = format!("/v1/instances/{instance}/production");
    let new = bench.issue("a", &old.value, "새 키");
    // 둘이 함께 산다
    for key in [&old.value, &new.value] {
        assert_eq!(bench.call("a", "GET", &production, key, &[]).0, 200);
    }
    // 새 키로 옛 키를 폐기한다
    let (status, revoked) = bench.revoke("a", &new.value, &old.id);
    assert_eq!(status, 200, "{revoked}");
    assert!(revoked["revoked_at"].is_u64());
    // 다음 요청부터 옛 키는 어떤 길에서도 받지 않는다
    for (method, path) in [
        ("GET", production.clone()),
        ("GET", "/v1/keys".to_owned()),
        ("POST", "/v1/keys".to_owned()),
        ("POST", "/v1/instances".to_owned()),
        ("GET", "/v1/settings/auth".to_owned()),
    ] {
        let (status, answer) = bench.call("a", method, &path, &old.value, b"{}");
        assert_eq!(status, 401, "{method} {path}: {answer}");
        assert_eq!(answer["error"], "unauthorized");
    }
    // git 의 길에서도 폐기한 키는 401 이다(service key 로 열지 않는다는 403 이 아니다)
    let (status, _) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/git/info/refs?service=git-upload-pack"),
        &old.value,
        &[],
    );
    assert_eq!(status, 401);
    // 새 키는 그대로 되고, 목록에 폐기한 때가 보인다
    assert_eq!(bench.call("a", "GET", &production, &new.value, &[]).0, 200);
    let keys = bench.keys("a", &new.value);
    let listed = keys
        .iter()
        .find(|key| key["id"] == old.id.as_str())
        .unwrap();
    assert!(listed["revoked_at"].is_u64());
    // 이미 폐기한 것을 다시 폐기하면 같은 답이고 아무것도 바뀌지 않는다
    let (status, again) = bench.revoke("a", &new.value, &old.id);
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["revoked_at"], revoked["revoked_at"]);
    bench.destroy("a", &new.value, &instance);
}

#[test]
fn 한_관리_서버에서_낸_열쇠는_다른_관리_서버가_바로_받고_거둔_열쇠는_다른_관리_서버도_다음_요청부터_받지_않는다()
 {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    let first = bench.organization("a", "acme", "live");
    // a 에서 만든 조직의 키를 b 가 받는다
    assert_eq!(bench.keys("b", &first.value).len(), 1);
    for (issued_on, revoked_on, used_on) in [
        ("a", "a", "b"),
        ("b", "b", "a"),
        ("a", "b", "a"),
        ("b", "a", "b"),
    ] {
        let key = bench.issue(issued_on, &first.value, "돌려 쓰는 키");
        for on in ["a", "b"] {
            assert_eq!(
                bench.call(on, "GET", "/v1/keys", &key.value, &[]).0,
                200,
                "{on}"
            );
        }
        let (status, body) = bench.revoke(revoked_on, &first.value, &key.id);
        assert_eq!(status, 200, "{body}");
        for on in [used_on, revoked_on] {
            let (status, body) = bench.call(on, "GET", "/v1/keys", &key.value, &[]);
            assert_eq!(status, 401, "{on}: {body}");
        }
    }
}

#[test]
fn 다른_조직의_열쇠는_보지도_거두지도_못하고_없는_것과_같다() {
    let mut bench = bench!();
    bench.open("a");
    let acme = bench.organization("a", "acme", "live");
    let acme_second = bench.issue("a", &acme.value, "둘째");
    let beta = bench.organization("a", "beta", "test");
    // beta 의 목록에는 acme 의 키가 없다
    let listed = bench.keys("a", &beta.value);
    assert!(
        listed
            .iter()
            .all(|key| key["id"] != acme.id.as_str() && key["id"] != acme_second.id.as_str())
    );
    // acme 의 키를 폐기해 보면 없는 키와 같은 답이다
    let (status, other) = bench.revoke("a", &beta.value, &acme_second.id);
    let (unknown_status, unknown) = bench.revoke("a", &beta.value, "key_0000000000000000");
    assert_eq!((status, unknown_status), (404, 404), "{other} {unknown}");
    assert_eq!(other, unknown);
    // 설정에만 있는 조직의 키로도 폐기하지 못한다
    assert_eq!(bench.revoke("a", FACTORY, &acme_second.id).0, 404);
    // acme 의 키는 그대로 산다
    assert_eq!(
        bench
            .call("a", "GET", "/v1/keys", &acme_second.value, &[])
            .0,
        200
    );
    assert!(
        bench
            .layer("a")
            .records()
            .keys("acme")
            .unwrap()
            .iter()
            .all(|key| key.revoked_at.is_none())
    );
}

#[test]
fn 조직의_마지막_살아_있는_키는_폐기하지_못하고_새_키를_만든_뒤에는_폐기한다() {
    let mut bench = bench!();
    bench.open("a");
    let only = bench.organization("a", "acme", "live");
    let (status, refused) = bench.revoke("a", &only.value, &only.id);
    assert_eq!(status, 409, "{refused}");
    assert_eq!(bench.alive("a", &only.value), 200);
    // 새 키를 만든 뒤에는 앞의 키를 폐기하고, 그러면 새 키가 마지막 키다
    let second = bench.issue("a", &only.value, "새 키");
    assert_eq!(bench.revoke("a", &second.value, &only.id).0, 200);
    assert_eq!(bench.alive("a", &only.value), 401);
    assert_eq!(bench.revoke("a", &second.value, &second.id).0, 409);
}

#[test]
fn 운영자는_살아_있는_키가_없는_조직에만_키를_내어_되살린다() {
    let mut bench = bench!();
    bench.open("a");
    let first = bench.organization("a", "acme", "live");
    // 살아 있는 키가 있으면 운영자는 키를 내지 않는다
    assert_eq!(bench.admin("a", "acme", "/keys").0, 409);
    // 설정의 키가 있는 조직에도, 없는 조직에도 내지 않고, service key 로는 부르지 못한다
    assert_eq!(bench.admin("a", "factory", "/keys").0, 409);
    assert_eq!(bench.admin("a", "nobody", "/keys").0, 404);
    let (status, _) = bench.call(
        "a",
        "POST",
        "/v1/admin/organizations/acme/keys",
        &first.value,
        &[],
    );
    assert_eq!(status, 401);
    // 키의 비밀을 모두 잃은 조직에는 하나를 내어 되살린다
    lose_all_keys(&bench, "acme");
    assert_eq!(bench.alive("a", &first.value), 401);
    let (status, issued) = bench.post(
        "a",
        "/v1/admin/organizations/acme/keys",
        ADMIN,
        &json!({ "label": "되찾은 키" }),
    );
    assert_eq!(status, 201, "{issued}");
    assert_eq!(issued["label"], "되찾은 키");
    let recovered = issued["secret"].as_str().unwrap().to_owned();
    assert_eq!(bench.alive("a", &recovered), 200);
    // 되살린 뒤에는 다시 살아 있는 키가 있으므로 더 내지 않는다
    assert_eq!(bench.admin("a", "acme", "/keys").0, 409);
}

#[test]
fn 운영자가_키를_갈면_새어_나간_키와_그것으로_낸_키가_한_번에_끊기고_새_키_하나로만_부른다() {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    let leaked = bench.organization("a", "acme", "live");
    let other = bench.organization("a", "other_co", "live");
    // 새어 나간 키를 쥔 쪽이 키를 더 내 두고, 주인의 키를 폐기했다
    let owner = bench.issue("a", &leaked.value, "주인의 서버");
    let planted = bench.issue("b", &leaked.value, "심어 둔 키");
    assert_eq!(bench.revoke("a", &planted.value, &owner.id).0, 200);
    // service key 로는 이 길을 열지 못한다
    let (status, _) = bench.call(
        "a",
        "POST",
        "/v1/admin/organizations/acme/reset-keys",
        &leaked.value,
        &[],
    );
    assert_eq!(status, 401);
    // 운영자가 키를 간다. 살아 있는 키가 있어도 한다
    let (status, fresh) = bench.admin("a", "acme", "/reset-keys");
    assert_eq!(status, 201, "{fresh}");
    let recovered = fresh["secret"].as_str().unwrap().to_owned();
    // 새어 나간 키도 그것으로 낸 키도 어느 관리 서버에서든 받지 않는다. 키를 더 내지도 못한다
    for on in ["a", "b"] {
        for dead in [&leaked.value, &planted.value, &owner.value] {
            assert_eq!(bench.call(on, "GET", "/v1/keys", dead, &[]).0, 401, "{on}");
            let (status, _) = bench.post(on, "/v1/keys", dead, &json!({ "label": "버티기" }));
            assert_eq!(status, 401, "{on}");
        }
    }
    // 새 키 하나만 살아 있다
    let alive: Vec<Value> = bench
        .keys("b", &recovered)
        .into_iter()
        .filter(|key| key["revoked_at"].is_null())
        .collect();
    assert_eq!(alive.len(), 1, "{alive:?}");
    assert_eq!(alive[0]["id"], fresh["id"]);
    // 다른 조직의 키는 그대로다
    assert_eq!(bench.alive("a", &other.value), 200);
    // 설정의 키가 있는 조직과 없는 조직의 키는 갈지 않는다
    assert_eq!(bench.admin("a", "factory", "/reset-keys").0, 409);
    assert_eq!(bench.admin("a", "nobody", "/reset-keys").0, 404);
    assert_eq!(bench.alive("a", FACTORY), 200);
}

#[test]
fn 운영자가_키를_가는_사이에_다른_관리_서버가_내던_키도_기다렸다가_함께_폐기한다() {
    let mut bench = bench!();
    bench.open("a");
    let leaked = bench.organization("a", "acme", "live");
    // 다른 관리 서버가 새어 나간 키로 키를 내는 중이다: 조직의 줄을 잡은 채 아직 commit 하지 않았다
    let planted = "orb_sk_planted_by_the_other_server_not_a_secret";
    let mut other = bench.control();
    let mut pending = other.transaction().unwrap();
    pending
        .execute(
            "INSERT INTO orbital.service_key (id, organization, digest, label, created_at) VALUES ('key_planted', 'acme', $1, '심어 둔 키', 1)",
            &[&sha(planted)],
        )
        .unwrap();
    std::thread::scope(|scope| {
        let reset = scope.spawn(|| bench.admin("a", "acme", "/reset-keys"));
        // 키 갈기는 조직의 줄을 기다린다. 그사이에 다른 관리 서버가 commit 한다
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            !reset.is_finished(),
            "키 갈기가 조직의 줄을 기다리지 않았습니다"
        );
        pending.commit().unwrap();
        let (status, fresh) = reset.join().unwrap();
        assert_eq!(status, 201, "{fresh}");
    });
    // 기다렸다가 함께 폐기했으므로 심어 둔 키도 받지 않는다
    assert_eq!(bench.alive("a", planted), 401);
    assert_eq!(bench.alive("a", &leaked.value), 401);
    assert_eq!(
        bench
            .layer("a")
            .records()
            .organization_counts("acme")
            .unwrap()
            .1,
        1
    );
}

// ---- 조직 닫기 ----

#[test]
fn 인스턴스가_남은_조직은_닫지_못하고_먼저_지울_인스턴스를_알린다() {
    let mut bench = bench!();
    bench.open("a");
    let key = bench.organization("a", "acme", "live");
    bench.upload("a", &key.value);
    let instance = bench.instance("a", &key.value);
    let (status, refused) = bench.admin("a", "acme", "/close");
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["message"].as_str().unwrap().contains(&instance),
        "{refused}"
    );
    // 닫지 않았으므로 키는 그대로 산다
    assert_eq!(bench.call("a", "GET", "/v1/keys", &key.value, &[]).0, 200);
    bench.destroy("a", &key.value, &instance);
    let (status, closed) = bench.admin("a", "acme", "/close");
    assert_eq!(status, 200, "{closed}");
    assert!(closed["organization"]["closed_at"].is_u64());
    // 없는 조직은 닫지 못한다
    assert_eq!(bench.admin("a", "nobody", "/close").0, 404);
}

#[test]
fn 닫힌_조직의_열쇠는_기록의_것이든_설정의_것이든_어느_관리_서버에서든_받지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    // 설정의 키(FACTORY)로 키를 내면 같은 조직 이름의 기록이 생긴다
    let recorded = bench.issue("a", FACTORY, "기록의 키");
    let second = bench.issue("a", &recorded.value, "둘째");
    for key in [FACTORY, recorded.value.as_str(), second.value.as_str()] {
        assert_eq!(bench.alive("b", key), 200);
    }
    let (status, closed) = bench.admin("b", "factory", "/close");
    assert_eq!(status, 200, "{closed}");
    for on in ["a", "b"] {
        for key in [FACTORY, recorded.value.as_str(), second.value.as_str()] {
            let (status, answer) = bench.call(on, "GET", "/v1/settings/auth", key, &[]);
            assert_eq!(status, 401, "{on}: {answer}");
            assert!(
                answer["message"].as_str().unwrap().contains("닫힌"),
                "{answer}"
            );
        }
    }
    // 닫힌 조직에는 운영자도 키를 내거나 갈지 않는다
    bench.organization("a", "acme", "live");
    assert_eq!(bench.admin("a", "acme", "/close").0, 200);
    lose_all_keys(&bench, "acme");
    assert_eq!(bench.admin("a", "acme", "/keys").0, 409);
    assert_eq!(bench.admin("a", "acme", "/reset-keys").0, 409);
    // 다른 조직(설정에만 있는 other)은 그대로다
    assert_eq!(bench.alive("a", OTHER), 200);
}

// ---- 시험용 조직 ----

#[test]
fn 시험용_조직은_인스턴스의_상한을_넘지_못하고_운영의_조직은_상한을_받지_않는다() {
    let mut bench = bench!();
    bench.test_limit = 2;
    bench.open("a");
    let test = bench.organization("a", "sandbox", "test");
    let live = bench.organization("a", "acme", "live");
    bench.upload("a", &test.value);
    bench.upload("a", &live.value);
    let first = bench.instance("a", &test.value);
    bench.instance("a", &test.value);
    let (status, refused) = bench.try_instance("a", &test.value);
    assert_eq!(status, 409, "{refused}");
    let message = refused["message"].as_str().unwrap();
    assert!(
        message.contains("2개까지") && message.contains("DELETE"),
        "{message}"
    );
    // 거절한 것은 기록에도 저장소에도 남지 않는다
    assert_eq!(
        bench
            .layer("a")
            .records()
            .organization_counts("sandbox")
            .unwrap()
            .0,
        2
    );
    // 하나를 지우면 다시 세운다
    bench.destroy("a", &test.value, &first);
    bench.instance("a", &test.value);
    // 운영의 조직은 상한을 받지 않는다
    for _ in 0..3 {
        bench.instance("a", &live.value);
    }
    // 설정에만 있는 조직도 운영의 조직으로 본다
    bench.upload("a", FACTORY);
    for _ in 0..3 {
        bench.instance("a", FACTORY);
    }
}

// ---- 설정의 키와 함께 살기 ----

#[test]
fn 설정의_열쇠와_기록의_열쇠가_같은_조직_이름을_가리켜_함께_산다() {
    let mut bench = bench!();
    bench.open("a");
    bench.upload("a", FACTORY);
    let instance = bench.instance("a", FACTORY);
    // 설정에만 있는 조직의 목록은 비어 있다(설정의 키는 목록에 보이지 않는다)
    assert!(bench.keys("a", FACTORY).is_empty());
    // 설정의 키로 키를 내면 그 조직의 기록이 운영의 조직으로 생기고, 그 키가 같은 인스턴스를 본다
    let recorded = bench.issue("a", FACTORY, "API 로 만든 키");
    let production = format!("/v1/instances/{instance}/production");
    for key in [FACTORY, recorded.value.as_str()] {
        assert_eq!(bench.call("a", "GET", &production, key, &[]).0, 200);
    }
    let organization = bench
        .layer("a")
        .records()
        .organization("factory")
        .unwrap()
        .unwrap();
    assert_eq!(organization.kind, orbital_core::organization::Kind::Live);
    // 설정의 키는 목록에 보이지 않는다
    assert_eq!(ids(&bench.keys("a", FACTORY)), vec![recorded.id.clone()]);
    // 기록의 키로도 키를 낸다
    let more = bench.issue("a", &recorded.value, "기록의 키로 낸 것");
    assert_eq!(bench.call("a", "GET", &production, &more.value, &[]).0, 200);
    // 다른 조직(other)의 키에는 여전히 없는 인스턴스다
    assert_eq!(bench.call("a", "GET", &production, OTHER, &[]).0, 404);
    bench.destroy("a", &recorded.value, &instance);
}

#[test]
fn 환경_변수의_키는_부트스트랩으로_계속_쓰이고_그_조직의_마지막_기록의_키도_폐기한다() {
    let mut bench = bench!();
    bench.open("a");
    assert_eq!(bench.alive("a", FACTORY), 200);
    let made = bench.issue("a", FACTORY, "API 로 만든 키");
    // 설정의 키가 있으니 마지막 기록의 키도 폐기한다. 조직은 잠기지 않는다
    assert_eq!(bench.revoke("a", FACTORY, &made.id).0, 200);
    assert_eq!(bench.alive("a", FACTORY), 200);
    assert_eq!(bench.alive("a", &made.value), 401);
}

// ---- 옛 기록 파일에서 옮기기 ----

#[test]
fn 옛_registry_json_의_조직과_키는_처음_뜰_때_옮겨져_같은_비밀이_계속_통한다() {
    let mut bench = bench!();
    // `main` 의 레이어가 적던 모양. 비밀은 없고 sha256 만 있다
    let live = "orb_sk_old_live_key_not_a_secret_0000000000";
    let gone = "orb_sk_old_revoked_key_not_a_secret_00000000";
    let home = bench.home("a");
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("registry.json"),
        json!({
            "organizations": {
                "old-factory": {
                    "label": "옛 팩토리",
                    "created_at": 1_800_000_000_u64,
                    "keys": [
                        { "id": "key_0000000000000001", "label": "", "digest": sha(live), "created_at": 1_800_000_000_u64 },
                        { "id": "key_0000000000000002", "label": "배포 서버", "digest": sha(gone), "created_at": 1_800_000_100_u64, "revoked_at": 1_800_000_200_u64 }
                    ]
                }
            },
            "instances": {},
            "rollouts": {}
        })
        .to_string(),
    )
    .unwrap();
    bench.open("a");
    assert!(home.join("registry.json.imported").is_file());
    // 같은 비밀이 계속 통하고, 폐기한 키는 그대로 폐기한 것이다. 다른 관리 서버도 같다
    bench.open("b");
    for on in ["a", "b"] {
        assert_eq!(bench.alive(on, live), 200, "{on}");
        assert_eq!(bench.alive(on, gone), 401, "{on}");
    }
    let keys = bench.keys("a", live);
    assert_eq!(
        ids(&keys),
        vec!["key_0000000000000001", "key_0000000000000002"]
    );
    assert_eq!(keys[1]["label"], "배포 서버");
    assert_eq!(keys[1]["revoked_at"], 1_800_000_200_u64);
    let (status, report) = bench.call(
        "a",
        "GET",
        "/v1/admin/organizations/old-factory",
        ADMIN,
        &[],
    );
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["name"], "옛 팩토리");
    assert_eq!(report["kind"], "live");
    assert_eq!(report["keys"], 1);
    // 옮긴 조직은 마지막 살아 있는 키를 폐기하지 못한다
    assert_eq!(bench.revoke("a", live, "key_0000000000000001").0, 409);
    // 다시 떠도 두 번 옮기지 않는다
    bench.open("a");
    assert_eq!(bench.keys("a", live).len(), 2);
}

// ---- 기록을 읽지 못할 때 ----

#[test]
fn 기록을_읽지_못하면_열쇠를_없는_것이라고_답하지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    let recorded = bench.organization("a", "acme", "live");
    bench.upload("a", FACTORY);
    let instance = bench.instance("a", FACTORY);
    let git = format!("/v1/instances/{instance}/git/info/refs?service=git-upload-pack");
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.service_key RENAME TO service_key_away")
        .unwrap();
    let recorded_answer = bench.call("a", "GET", "/v1/keys", &recorded.value, &[]);
    let git_answer = bench.call("a", "GET", &git, &recorded.value, &[]);
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.service_key_away RENAME TO service_key")
        .unwrap();
    assert_eq!(recorded_answer.0, 500, "{}", recorded_answer.1);
    assert_eq!(git_answer.0, 500, "{}", git_answer.1);
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.organization RENAME TO organization_away")
        .unwrap();
    let configured_answer = bench.call("a", "GET", "/v1/settings/auth", FACTORY, &[]);
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.organization_away RENAME TO organization")
        .unwrap();
    assert_eq!(configured_answer.0, 500, "{}", configured_answer.1);
    // 기록이 돌아오면 다시 된다
    assert_eq!(
        bench.call("a", "GET", "/v1/keys", &recorded.value, &[]).0,
        200
    );
    bench.destroy("a", FACTORY, &instance);
}

// ---- 마지막으로 쓴 때 ----

#[test]
fn 마지막으로_쓴_때는_분_단위로_뭉쳐_적고_같은_분_안에서는_다시_적지_않는다() {
    let mut bench = bench!();
    // 분의 시작
    let minute = 1_900_000_020_u64;
    assert_eq!(minute % 60, 0);
    bench.clock.store(minute + 5, Ordering::SeqCst);
    bench.open("a");
    let key = bench.organization("a", "acme", "live");
    let row = |bench: &Bench| -> (Option<i64>, String) {
        let row = bench
            .control()
            .query_one(
                "SELECT used_at, xmin::text FROM orbital.service_key WHERE id = $1",
                &[&key.id],
            )
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(row(&bench).0, None);
    assert_eq!(bench.call("a", "GET", "/v1/keys", &key.value, &[]).0, 200);
    let (used, written) = row(&bench);
    assert_eq!(used, Some(i64::try_from(minute).unwrap()));
    // 같은 분 안에서는 몇 번을 써도 줄을 다시 적지 않는다
    bench.clock.store(minute + 59, Ordering::SeqCst);
    for _ in 0..5 {
        assert_eq!(bench.call("a", "GET", "/v1/keys", &key.value, &[]).0, 200);
    }
    assert_eq!(row(&bench), (used, written.clone()));
    // 다음 분에 쓰면 그 분으로 한 번 적는다
    bench.clock.store(minute + 60, Ordering::SeqCst);
    assert_eq!(bench.call("a", "GET", "/v1/keys", &key.value, &[]).0, 200);
    let (later, rewritten) = row(&bench);
    assert_eq!(later, Some(i64::try_from(minute + 60).unwrap()));
    assert_ne!(rewritten, written);
    // 목록에 그 때가 보인다
    assert_eq!(bench.keys("a", &key.value)[0]["used_at"], minute + 60);
}

// ---- 넘겨받은 요청 ----

#[test]
fn 넘겨받았다는_머리말은_거둔_열쇠를_살리지_못한다() {
    let mut bench = bench!();
    bench.open("a");
    let first = bench.organization("a", "acme", "live");
    let second = bench.issue("a", &first.value, "둘째");
    bench.revoke("a", &first.value, &second.id);
    let authorization = format!("Bearer {}", second.value);
    for forwarded_by in [None, Some("b")] {
        let reply = handle_call(
            bench.layer("a"),
            &Call {
                method: "GET",
                path: "/v1/keys",
                authorization: Some(&authorization),
                content_type: None,
                content_encoding: None,
                forwarded_by,
                body: &[],
            },
        );
        assert_eq!(reply.status, 401, "{forwarded_by:?}");
    }
}
