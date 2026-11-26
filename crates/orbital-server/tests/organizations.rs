//! 조직과 service key 는 레이어의 기록(control database)에 있다. 운영자의 열쇠로 조직을 만들고 첫 열쇠를 내고, 조직은 자기 열쇠를
//! 더 내고 보고 거둔다. 같은 control database 를 보는 관리 서버 둘(기계 `a` · `b`)을 띄워 잰다.
//!
//! 실제 PostgreSQL 과 실제 git 으로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에 바로 넣는다. 막는 테스트는 그 열쇠로 실제로 해 본다.
//! 테스트의 열쇠는 한눈에 가짜인 글자이고, 레이어가 낸 열쇠는 테스트가 답에서 받는다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

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
/// 운영자의 열쇠(`ORBITAL_OPERATOR_KEY`).
const OPERATOR: &str = "op_test_operator_key_not_a_secret_0000";
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
    /// 운영자의 열쇠를 줄까.
    operator: bool,
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
            operator: true,
            test_limit: 10,
            servers: BTreeMap::new(),
            instances: Vec::new(),
        })
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    fn open(&mut self, machine: &str) {
        let clock = Arc::clone(&self.clock);
        let options = Options {
            seal_key: Some(SealKey::from_bytes([7; 32])),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(machine).unwrap(),
            token_key: Some([3; 32].to_vec()),
            operator_key: self.operator.then(|| OPERATOR.to_owned()),
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

    /// 운영자가 조직을 만든다. 첫 열쇠를 돌려준다.
    fn organization(&self, on: &str, id: &str, kind: &str) -> Key {
        let (status, body) = self.post(
            on,
            "/v1/operator/organizations",
            OPERATOR,
            &json!({ "id": id, "name": format!("{id} 개발사"), "kind": kind, "label": "첫 열쇠" }),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["organization"]["id"], id);
        assert_eq!(body["organization"]["kind"], kind);
        Key {
            value: body["key"]["key"].as_str().unwrap().to_owned(),
            id: body["key"]["id"].as_str().unwrap().to_owned(),
        }
    }

    /// 조직의 열쇠로 열쇠를 하나 더 낸다.
    fn issue(&self, on: &str, key: &str, label: &str) -> Key {
        let (status, body) = self.post(on, "/v1/keys", key, &json!({ "label": label }));
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["label"], label);
        Key {
            value: body["key"].as_str().unwrap().to_owned(),
            id: body["id"].as_str().unwrap().to_owned(),
        }
    }

    fn keys(&self, on: &str, key: &str) -> Vec<Value> {
        let (status, body) = self.call(on, "GET", "/v1/keys", key, &[]);
        assert_eq!(status, 200, "{body}");
        body["keys"].as_array().unwrap().clone()
    }

    fn revoke(&self, on: &str, key: &str, id: &str) -> (u16, Value) {
        self.call(on, "DELETE", &format!("/v1/keys/{id}"), key, &[])
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

// ---- 운영자와 첫 열쇠 ----

#[test]
fn 운영자의_열쇠로_만든_조직은_첫_열쇠를_한_번만_답에_싣고_그_열쇠로_조직의_일을_한다() {
    let mut bench = bench!();
    bench.open("a");
    let first = bench.organization("a", "acme", "live");
    assert!(first.value.starts_with("sk_live_"), "{}", first.value);
    // 그 열쇠로 조직의 일을 한다: 앱을 올리고 인스턴스를 세운다
    bench.upload("a", &first.value);
    let instance = bench.instance("a", &first.value);
    // 목록에는 그 열쇠가 있되 값은 없다
    let keys = bench.keys("a", &first.value);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], first.id.as_str());
    assert_eq!(keys[0]["label"], "첫 열쇠");
    assert_eq!(keys[0]["prefix"], "sk_live_");
    assert!(!keys[0].to_string().contains(&first.value));
    // 운영자는 조직의 이름과 숫자를 본다
    let (status, report) = bench.call("a", "GET", "/v1/operator/organizations/acme", OPERATOR, &[]);
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["instances"], 1);
    assert_eq!(report["keys"], 1);
    let (status, list) = bench.call("a", "GET", "/v1/operator/organizations", OPERATOR, &[]);
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["organizations"][0]["id"], "acme");
    assert!(!list.to_string().contains(&first.value));
    // 같은 조직을 두 번 만들지 못한다. 첫 열쇠도 새로 나오지 않는다
    let (status, again) = bench.post(
        "a",
        "/v1/operator/organizations",
        OPERATOR,
        &json!({ "id": "acme", "name": "다른 이름", "kind": "test" }),
    );
    assert_eq!(status, 409, "{again}");
    assert!(again.get("key").is_none());
    // 조직의 식별자는 검증된 이름이어야 한다
    let (status, bad) = bench.post(
        "a",
        "/v1/operator/organizations",
        OPERATOR,
        &json!({ "id": "Acme; DROP", "name": "이름", "kind": "live" }),
    );
    assert_eq!(status, 422, "{bad}");
    bench.destroy("a", &first.value, &instance);
}

#[test]
fn 시험용_조직의_열쇠는_sk_test_로_시작하고_운영의_조직의_열쇠는_sk_live_로_시작한다() {
    let mut bench = bench!();
    bench.open("a");
    let test = bench.organization("a", "sandbox", "test");
    let live = bench.organization("a", "acme", "live");
    assert!(test.value.starts_with("sk_test_"), "{}", test.value);
    assert!(live.value.starts_with("sk_live_"), "{}", live.value);
    assert!(
        bench
            .issue("a", &test.value, "둘째")
            .value
            .starts_with("sk_test_")
    );
    assert!(
        bench
            .issue("a", &live.value, "둘째")
            .value
            .starts_with("sk_live_")
    );
    let (status, issued) = bench.post(
        "a",
        "/v1/operator/organizations/sandbox/keys",
        OPERATOR,
        &json!({ "label": "운영자가 낸 것" }),
    );
    assert_eq!(status, 200, "{issued}");
    assert!(issued["key"].as_str().unwrap().starts_with("sk_test_"));
}

#[test]
fn 운영자의_열쇠를_주지_않은_레이어에는_운영자의_길이_없다() {
    let mut bench = bench!();
    bench.operator = false;
    bench.open("a");
    for (method, path) in [
        ("POST", "/v1/operator/organizations"),
        ("GET", "/v1/operator/organizations"),
        ("GET", "/v1/operator/organizations/factory"),
        ("POST", "/v1/operator/organizations/factory/keys"),
        ("POST", "/v1/operator/organizations/factory/close"),
    ] {
        for bearer in [OPERATOR, FACTORY] {
            let body = json!({ "id": "acme", "name": "Acme", "kind": "live", "label": "열쇠" });
            let (status, answer) =
                bench.call("a", method, path, bearer, body.to_string().as_bytes());
            assert_eq!(status, 404, "{method} {path}: {answer}");
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
        ("GET", "/v1/settings/auth".to_owned(), Vec::new()),
        (
            "GET",
            at("/git/info/refs?service=git-upload-pack"),
            Vec::new(),
        ),
    ];
    for (method, path, body) in &cases {
        let (status, answer) = bench.call("a", method, path, OPERATOR, body);
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
    let new = json!({ "id": "intruder", "name": "몰래", "kind": "live" });
    for bearer in [FACTORY, recorded.value.as_str(), token.as_str()] {
        let (status, answer) = bench.post("a", "/v1/operator/organizations", bearer, &new);
        assert_eq!(status, 403, "{answer}");
        let (status, answer) = bench.post(
            "a",
            "/v1/operator/organizations/acme/keys",
            bearer,
            &json!({ "label": "몰래" }),
        );
        assert_eq!(status, 403, "{answer}");
        let (status, answer) = bench.call(
            "a",
            "POST",
            "/v1/operator/organizations/acme/close",
            bearer,
            &[],
        );
        assert_eq!(status, 403, "{answer}");
    }
    // 작업의 토큰에는 열쇠의 길이 없다
    let (status, answer) = bench.post("a", "/v1/keys", &token, &json!({ "label": "몰래" }));
    assert_eq!(status, 404, "{answer}");
    let (status, answer) = bench.call("a", "GET", "/v1/keys", &token, &[]);
    assert_eq!(status, 404, "{answer}");
    let (status, answer) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/keys/{}", recorded.id),
        &token,
        &[],
    );
    assert_eq!(status, 404, "{answer}");
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

// ---- 값은 남지 않는다 ----

#[test]
fn 열쇠의_값은_기록과_목록과_오류와_관리_서버의_폴더_어디에도_남지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    let first = bench.organization("a", "acme", "live");
    let second = bench.issue("b", &first.value, "둘째");
    let (status, issued) = bench.post(
        "a",
        "/v1/operator/organizations/acme/keys",
        OPERATOR,
        &json!({ "label": "셋째" }),
    );
    assert_eq!(status, 200, "{issued}");
    let third = issued["key"].as_str().unwrap().to_owned();
    let values = [first.value.clone(), second.value.clone(), third.clone()];
    // 열쇠를 쓰고, 거두고, 거둔 열쇠로 해 보고, 틀린 일도 해 본다
    bench.upload("a", &first.value);
    let instance = bench.instance("a", &second.value);
    let mut answers = String::new();
    let (status, _, raw) = bench.raw("a", "GET", "/v1/keys", &third, &[]);
    assert_eq!(status, 200);
    answers.push_str(&raw);
    let (status, _, raw) = bench.raw(
        "b",
        "DELETE",
        &format!("/v1/keys/{}", second.id),
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
        // 머리말을 뗀 몸의 일부도 없다
        let body = &value[8..];
        for (place, found) in [
            ("기록", records.contains(body)),
            ("답", answers.contains(body)),
            ("폴더", contains(&files, body)),
        ] {
            assert!(!found, "열쇠의 값이 {place}에 남았습니다");
        }
        // 기록에는 sha256 만 있다
        assert!(
            records.contains(&sha(value)),
            "기록에 열쇠의 sha256 이 없습니다"
        );
    }
}

// ---- 바꾸기와 거두기 ----

#[test]
fn 열쇠를_바꾸는_동안_옛_열쇠와_새_열쇠가_함께_살고_옛_것을_거두면_다음_요청부터_받지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    let old = bench.organization("a", "acme", "live");
    bench.upload("a", &old.value);
    let instance = bench.instance("a", &old.value);
    let production = format!("/v1/instances/{instance}/production");
    let new = bench.issue("a", &old.value, "새 열쇠");
    // 둘이 함께 산다
    for key in [&old.value, &new.value] {
        assert_eq!(bench.call("a", "GET", &production, key, &[]).0, 200);
    }
    // 새 열쇠로 옛 열쇠를 거둔다
    let (status, revoked) = bench.revoke("a", &new.value, &old.id);
    assert_eq!(status, 200, "{revoked}");
    assert!(revoked["revoked_at"].is_u64());
    // 다음 요청부터 옛 열쇠는 어떤 길에서도 받지 않는다
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
    // git 의 길에서도 거둔 열쇠는 401 이다(service key 로 열지 않는다는 403 이 아니다)
    let (status, _) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/git/info/refs?service=git-upload-pack"),
        &old.value,
        &[],
    );
    assert_eq!(status, 401);
    // 새 열쇠는 그대로 되고, 목록에 거둔 때가 보인다
    assert_eq!(bench.call("a", "GET", &production, &new.value, &[]).0, 200);
    let keys = bench.keys("a", &new.value);
    let listed = keys
        .iter()
        .find(|key| key["id"] == old.id.as_str())
        .unwrap();
    assert!(listed["revoked_at"].is_u64());
    // 이미 거둔 것을 다시 거두면 아무것도 바뀌지 않는다
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
    // a 에서 만든 조직의 열쇠를 b 가 받는다
    assert_eq!(bench.keys("b", &first.value).len(), 1);
    for (issued_on, revoked_on, used_on) in [
        ("a", "a", "b"),
        ("b", "b", "a"),
        ("a", "b", "a"),
        ("b", "a", "b"),
    ] {
        let key = bench.issue(issued_on, &first.value, "돌려 쓰는 열쇠");
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
    // beta 의 목록에는 acme 의 열쇠가 없다
    let listed = bench.keys("a", &beta.value);
    assert!(
        listed
            .iter()
            .all(|key| key["id"] != acme.id.as_str() && key["id"] != acme_second.id.as_str())
    );
    // acme 의 열쇠를 거둬 보면 없는 열쇠와 같은 답이다
    let (status, other) = bench.revoke("a", &beta.value, &acme_second.id);
    let (unknown_status, unknown) = bench.revoke("a", &beta.value, "key_0000000000000000");
    assert_eq!((status, unknown_status), (404, 404), "{other} {unknown}");
    assert_eq!(other, unknown);
    // 설정에만 있는 조직의 열쇠도 거두지 못한다
    assert_eq!(bench.revoke("a", FACTORY, &acme_second.id).0, 404);
    // acme 의 열쇠는 그대로 산다
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
fn 살아_있는_마지막_열쇠는_거두지_못하고_운영자가_새_열쇠를_낼_수_있다() {
    let mut bench = bench!();
    bench.open("a");
    let only = bench.organization("a", "acme", "live");
    let (status, refused) = bench.revoke("a", &only.value, &only.id);
    assert_eq!(status, 409, "{refused}");
    assert_eq!(bench.call("a", "GET", "/v1/keys", &only.value, &[]).0, 200);
    // 운영자가 새 열쇠를 낸다. 그러면 옛 것을 거둘 수 있다
    let (status, issued) = bench.post(
        "a",
        "/v1/operator/organizations/acme/keys",
        OPERATOR,
        &json!({ "label": "되찾은 열쇠" }),
    );
    assert_eq!(status, 200, "{issued}");
    let recovered = issued["key"].as_str().unwrap().to_owned();
    let (status, body) = bench.revoke("a", &recovered, &only.id);
    assert_eq!(status, 200, "{body}");
    assert_eq!(bench.call("a", "GET", "/v1/keys", &only.value, &[]).0, 401);
    // 스스로를 거두는 것도 마지막이면 거절이다
    let id = issued["id"].as_str().unwrap();
    assert_eq!(bench.revoke("a", &recovered, id).0, 409);
    // 없는 조직에는 운영자도 열쇠를 내지 못한다
    let (status, _) = bench.post(
        "a",
        "/v1/operator/organizations/nobody/keys",
        OPERATOR,
        &json!({ "label": "열쇠" }),
    );
    assert_eq!(status, 404);
}

#[test]
fn 운영자가_다른_열쇠를_모두_거두며_새_열쇠를_내면_새어_나간_열쇠와_그것으로_낸_열쇠가_한_번에_끊긴다()
 {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    let leaked = bench.organization("a", "acme", "live");
    let other = bench.organization("a", "other", "live");
    // 새어 나간 열쇠를 쥔 쪽이 열쇠를 더 내 두고, 주인의 열쇠를 거뒀다
    let owner = bench.issue("a", &leaked.value, "주인의 서버");
    let planted = bench.issue("b", &leaked.value, "심어 둔 열쇠");
    assert_eq!(bench.revoke("a", &planted.value, &owner.id).0, 200);

    // service key 로는 이 길을 열지 못한다
    let (status, _) = bench.post(
        "a",
        "/v1/operator/organizations/acme/keys",
        &leaked.value,
        &json!({ "label": "되찾기", "revoke_others": true }),
    );
    assert_eq!(status, 403);
    // 운영자가 다른 열쇠를 모두 거두며 새 열쇠를 낸다. 거둔 수가 답에 있다(살아 있던 둘)
    let (status, issued) = bench.post(
        "a",
        "/v1/operator/organizations/acme/keys",
        OPERATOR,
        &json!({ "label": "되찾은 열쇠", "revoke_others": true }),
    );
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["revoked"], 2, "{issued}");
    let recovered = issued["key"].as_str().unwrap().to_owned();
    // 새어 나간 열쇠도 그것으로 낸 열쇠도 어느 관리 서버에서든 받지 않는다. 열쇠를 더 내지도 못한다
    for on in ["a", "b"] {
        for dead in [&leaked.value, &planted.value, &owner.value] {
            assert_eq!(bench.call(on, "GET", "/v1/keys", dead, &[]).0, 401, "{on}");
            let (status, _) = bench.post(on, "/v1/keys", dead, &json!({ "label": "버티기" }));
            assert_eq!(status, 401, "{on}");
        }
    }
    // 새 열쇠 하나만 살아 있다
    let alive: Vec<Value> = bench
        .keys("b", &recovered)
        .into_iter()
        .filter(|key| key["revoked_at"].is_null())
        .collect();
    assert_eq!(alive.len(), 1, "{alive:?}");
    assert_eq!(alive[0]["id"], issued["id"]);
    // 다른 조직의 열쇠는 그대로다
    assert_eq!(bench.call("a", "GET", "/v1/keys", &other.value, &[]).0, 200);
    // 거두지 않고 내는 것(기본)은 다른 열쇠를 건드리지 않는다
    let (status, more) = bench.post(
        "a",
        "/v1/operator/organizations/acme/keys",
        OPERATOR,
        &json!({ "label": "하나 더" }),
    );
    assert_eq!(status, 200, "{more}");
    assert_eq!(more["revoked"], 0, "{more}");
    assert_eq!(bench.call("a", "GET", "/v1/keys", &recovered, &[]).0, 200);
}

// ---- 조직 닫기 ----

#[test]
fn 인스턴스가_남은_조직은_닫지_못하고_먼저_지울_인스턴스를_알린다() {
    let mut bench = bench!();
    bench.open("a");
    let key = bench.organization("a", "acme", "live");
    bench.upload("a", &key.value);
    let instance = bench.instance("a", &key.value);
    let (status, refused) = bench.call(
        "a",
        "POST",
        "/v1/operator/organizations/acme/close",
        OPERATOR,
        &[],
    );
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["message"].as_str().unwrap().contains(&instance),
        "{refused}"
    );
    // 닫지 않았으므로 열쇠는 그대로 산다
    assert_eq!(bench.call("a", "GET", "/v1/keys", &key.value, &[]).0, 200);
    bench.destroy("a", &key.value, &instance);
    let (status, closed) = bench.call(
        "a",
        "POST",
        "/v1/operator/organizations/acme/close",
        OPERATOR,
        &[],
    );
    assert_eq!(status, 200, "{closed}");
    assert!(closed["organization"]["closed_at"].is_u64());
    // 없는 조직은 닫지 못한다
    assert_eq!(
        bench
            .call(
                "a",
                "POST",
                "/v1/operator/organizations/nobody/close",
                OPERATOR,
                &[]
            )
            .0,
        404
    );
}

#[test]
fn 닫힌_조직의_열쇠는_기록의_것이든_설정의_것이든_어느_관리_서버에서든_받지_않는다() {
    let mut bench = bench!();
    bench.open("a");
    bench.open("b");
    // 설정의 열쇠(FACTORY)와 같은 조직 이름으로 기록의 조직을 만든다
    let recorded = bench.organization("a", "factory", "live");
    let second = bench.issue("a", &recorded.value, "둘째");
    for key in [FACTORY, recorded.value.as_str(), second.value.as_str()] {
        assert_eq!(bench.call("b", "GET", "/v1/settings/auth", key, &[]).0, 200);
    }
    let (status, closed) = bench.call(
        "b",
        "POST",
        "/v1/operator/organizations/factory/close",
        OPERATOR,
        &[],
    );
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
    // 닫힌 조직에는 운영자도 열쇠를 내지 않는다
    let (status, _) = bench.post(
        "a",
        "/v1/operator/organizations/factory/keys",
        OPERATOR,
        &json!({ "label": "열쇠" }),
    );
    assert_eq!(status, 409);
    // 다른 조직(설정에만 있는 other)은 그대로다
    assert_eq!(
        bench.call("a", "GET", "/v1/settings/auth", OTHER, &[]).0,
        200
    );
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

// ---- 설정의 열쇠와 함께 살기 ----

#[test]
fn 설정의_열쇠와_기록의_열쇠가_같은_조직_이름을_가리켜_함께_산다() {
    let mut bench = bench!();
    bench.open("a");
    bench.upload("a", FACTORY);
    let instance = bench.instance("a", FACTORY);
    // 설정에만 있는 조직은 열쇠를 내지 못한다(기록에 조직이 없다). 목록은 비어 있다
    let (status, refused) = bench.post("a", "/v1/keys", FACTORY, &json!({ "label": "열쇠" }));
    assert_eq!(status, 409, "{refused}");
    assert!(bench.keys("a", FACTORY).is_empty());
    // 운영자가 같은 이름으로 조직을 만들면 기록의 열쇠가 같은 인스턴스를 본다
    let recorded = bench.organization("a", "factory", "live");
    let production = format!("/v1/instances/{instance}/production");
    for key in [FACTORY, recorded.value.as_str()] {
        assert_eq!(bench.call("a", "GET", &production, key, &[]).0, 200);
    }
    // 설정의 열쇠로도 이제 열쇠를 낸다
    let more = bench.issue("a", FACTORY, "설정의 열쇠로 낸 것");
    assert_eq!(bench.call("a", "GET", &production, &more.value, &[]).0, 200);
    // 다른 조직(other)의 열쇠에는 여전히 없는 인스턴스다
    assert_eq!(bench.call("a", "GET", &production, OTHER, &[]).0, 404);
    bench.destroy("a", &recorded.value, &instance);
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
