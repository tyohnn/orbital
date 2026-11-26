//! 이벤트와 웹훅. 레이어의 상태가 바뀐 것을 조직마다 차례대로 쌓아 물어보는 길(`GET /v1/events`)로 내주고, 조직이 건 주소로 서명해 보낸다.
//!
//! 실제 PostgreSQL 과 실제 git, 실제 HTTP 의 받는 서버(이 테스트가 127.0.0.1 에 띄운다)로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에
//! 바로 넣고, 보내는 일은 뒤의 스레드를 끄고(`webhook_every: None`) `deliver_due` 를 바로 불러 잰다. 시간은 레이어의 시계를 갈아 끼운다.
//! 막는 테스트는 실제로 걸어 보고 보내 본다. 이름을 푸는 일은 갈아 끼워 「사설 주소로 풀리는 이름」을 만든다.
//! 테스트의 열쇠와 비밀은 한눈에 가짜인 글자다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use orbital_core::event::{Body, GIVE_UP_AFTER, Note, RETENTION};
use orbital_core::name::{Ident, InstanceId};
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, Options};
use orbital_server::records::drop_database;
use orbital_server::seal::SealKey;
use orbital_server::token::hex;
use orbital_server::webhook::Resolve;
use postgres::{Client, Config, NoTls};
use serde_json::{Value, json};
use sha2::Sha256;

/// 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)에 적은 열쇠. 조직 `factory` 의 것이다.
const FACTORY: &str = "sk_test_factory_events";
/// 다른 조직 `other` 의 열쇠.
const OTHER: &str = "sk_test_other_events";
/// 운영자의 열쇠.
const OPERATOR: &str = "op_test_operator_key_not_a_secret_0000";
/// 밖에서 넣는 비밀의 값(가짜).
const BANK: &str = "sk_live_bank_FAKE_Ev71pZ";
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// 폴더 아래의 모든 파일의 내용과 경로를 바이트로 이어 붙인다.
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

/// 서명을 확인한다(SDK 와 같은 규칙). 맞으면 `t` 를 돌려준다.
fn verify(secret: &str, header: &str, body: &[u8]) -> Option<u64> {
    let mut at = None;
    let mut given = Vec::new();
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", value)) => at = value.parse::<u64>().ok(),
            Some(("v1", value)) => given.push(value.to_owned()),
            _ => {}
        }
    }
    let at = at?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{at}.").as_bytes());
    mac.update(body);
    let expected = hex(&mac.finalize().into_bytes());
    given.contains(&expected).then_some(at)
}

// ---- 이름 풀기 ----

/// 갈아 끼우는 이름 풀기. 모든 이름이 지금 정한 주소로 풀린다.
struct FakeResolver(Mutex<Vec<IpAddr>>);

impl FakeResolver {
    fn to(addresses: &[&str]) -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            addresses.iter().map(|text| text.parse().unwrap()).collect(),
        )))
    }

    fn point(&self, addresses: &[&str]) {
        *self.0.lock().unwrap() = addresses.iter().map(|text| text.parse().unwrap()).collect();
    }
}

impl Resolve for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

// ---- 받는 서버 ----

/// 받은 요청 하나.
#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Received {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// 127.0.0.1 에 뜨는 받는 서버. 답할 상태를 차례로 정해 두고, 다 쓰면 200 이다.
struct Receiver {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    answers: Arc<Mutex<Vec<u16>>>,
    /// 답하기 전에 기다리는 시간(밀리초).
    delay: Arc<AtomicU64>,
    /// 있으면 이 주소로 가라고(302. 따라가는 쪽은 GET 으로 바꿔 따라간다) 답한다.
    redirect: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Receiver {
    fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let answers = Arc::new(Mutex::new(Vec::<u16>::new()));
        let delay = Arc::new(AtomicU64::new(0));
        let redirect = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (received, answers, delay, redirect, stop) = (
                Arc::clone(&received),
                Arc::clone(&answers),
                Arc::clone(&delay),
                Arc::clone(&redirect),
                Arc::clone(&stop),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(50))
                    else {
                        continue;
                    };
                    let mut body = Vec::new();
                    let _ = io::Read::read_to_end(request.as_reader(), &mut body);
                    let headers = request
                        .headers()
                        .iter()
                        .map(|header| {
                            (
                                header.field.as_str().as_str().to_ascii_lowercase(),
                                header.value.as_str().to_owned(),
                            )
                        })
                        .collect();
                    received.lock().unwrap().push(Received {
                        path: request.url().to_owned(),
                        headers,
                        body,
                    });
                    let wait = delay.load(Ordering::SeqCst);
                    if wait > 0 {
                        std::thread::sleep(Duration::from_millis(wait));
                    }
                    let location = redirect.lock().unwrap().clone();
                    let response = match location {
                        Some(location) => tiny_http::Response::from_string("")
                            .with_status_code(302)
                            .with_header(
                                tiny_http::Header::from_bytes("location", location.as_bytes())
                                    .unwrap(),
                            ),
                        None => {
                            let mut queue = answers.lock().unwrap();
                            let status = if queue.is_empty() {
                                200
                            } else {
                                queue.remove(0)
                            };
                            // 답의 본문에 무엇이 와도 레이어는 읽지 않는다
                            tiny_http::Response::from_string(format!("answer-body-{status}"))
                                .with_status_code(status)
                        }
                    };
                    let _ = request.respond(response);
                }
            })
        };
        Self {
            port,
            received,
            answers,
            delay,
            redirect,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/hooks/orbital", self.port)
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    fn ids(&self) -> Vec<u64> {
        self.received()
            .iter()
            .map(|received| received.json()["id"].as_u64().unwrap())
            .collect()
    }

    fn answer(&self, statuses: &[u16]) {
        self.answers.lock().unwrap().extend_from_slice(statuses);
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---- 관리 서버들 ----

struct Bench {
    scratch: PathBuf,
    pg_url: String,
    control: Ident,
    /// 레이어의 시계. 0 이면 실제 시각이다.
    clock: Arc<AtomicU64>,
    resolver: Arc<FakeResolver>,
    servers: BTreeMap<String, Layer>,
    instances: Vec<String>,
}

/// 레이어를 여는 갈래.
#[derive(Clone)]
struct Setup {
    /// 개발용 웹훅(사설 주소와 http).
    dev: bool,
    seal: Option<[u8; 32]>,
    previous: Option<[u8; 32]>,
    /// 뒤의 스레드가 보는 간격. 없으면 테스트가 `deliver_due` 를 부른다.
    every: Option<Duration>,
    timeout: Duration,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            dev: true,
            seal: Some([7; 32]),
            previous: None,
            every: None,
            timeout: Duration::from_secs(5),
        }
    }
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-events-{}-{}",
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
            resolver: FakeResolver::to(&["127.0.0.1"]),
            servers: BTreeMap::new(),
            instances: Vec::new(),
        })
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    fn open(&mut self, machine: &str, setup: &Setup) {
        let clock = Arc::clone(&self.clock);
        let options = Options {
            seal_key: setup.seal.map(SealKey::from_bytes),
            previous_seal_key: setup.previous.map(SealKey::from_bytes),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(machine).unwrap(),
            token_key: Some([3; 32].to_vec()),
            operator_key: Some(OPERATOR.to_owned()),
            clock: Arc::new(move || match clock.load(Ordering::SeqCst) {
                0 => now(),
                at => at,
            }),
            dev_webhooks: setup.dev,
            webhook_resolver: self.resolver.clone(),
            webhook_timeout: setup.timeout,
            webhook_every: setup.every,
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

    fn call(&self, on: &str, method: &str, path: &str, bearer: &str, body: &[u8]) -> (u16, Value) {
        let reply = handle(self.layer(on), method, path, Some(bearer), body);
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
        )
    }

    fn post(&self, on: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
        self.call(on, "POST", path, bearer, body.to_string().as_bytes())
    }

    fn put(&self, on: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
        self.call(on, "PUT", path, bearer, body.to_string().as_bytes())
    }

    /// 웹훅을 건다. 서명의 비밀을 돌려준다.
    fn hook(&self, on: &str, key: &str, url: &str) -> String {
        let (status, body) = self.put(on, "/v1/settings/webhook", key, &json!({ "url": url }));
        assert_eq!(status, 200, "{body}");
        body["secret"].as_str().unwrap().to_owned()
    }

    fn webhook(&self, on: &str, key: &str) -> Value {
        let (status, body) = self.call(on, "GET", "/v1/settings/webhook", key, &[]);
        assert_eq!(status, 200, "{body}");
        body["webhook"].clone()
    }

    fn events(&self, on: &str, key: &str, query: &str) -> Value {
        let (status, body) = self.call(on, "GET", &format!("/v1/events{query}"), key, &[]);
        assert_eq!(status, 200, "{body}");
        body
    }

    fn kinds(&self, on: &str, key: &str) -> Vec<String> {
        self.events(on, key, "?limit=500")["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["type"].as_str().unwrap().to_owned())
            .collect()
    }

    /// 스캐폴드를 올린다. `crash` 면 운영에서만 뜨지 않는 서버다.
    fn upload(&self, on: &str, key: &str, crash: bool) {
        let folder = self.scratch.join(format!("scaffold-{on}-{crash}"));
        let _ = fs::remove_dir_all(&folder);
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/records"),
            &folder,
        );
        if crash {
            let server = fs::read_to_string(folder.join("server.js")).unwrap();
            fs::write(
                folder.join("server.js"),
                format!(
                    "if (process.env.ORBITAL_STAGE === \"production\") process.exit(1);\n{server}"
                ),
            )
            .unwrap();
        }
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{on}-{crash}.bundle"));
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

    fn instance(&mut self, on: &str, key: &str) -> String {
        let (status, body) = self.post(
            on,
            "/v1/instances",
            key,
            &json!({ "app": "records", "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push(instance.clone());
        instance
    }

    fn token(&self, on: &str, key: &str, instance: &str) -> String {
        let (status, body) = self.post(
            on,
            &format!("/v1/instances/{instance}/sessions"),
            key,
            &json!({ "can": ALL }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 프리뷰를 세우고 승격을 요청해 운영에 올려 본다. (release, 승격의 답의 상태).
    fn ship(&self, on: &str, key: &str, instance: &str, token: &str) -> (String, u16) {
        let (status, preview) = self.call(
            on,
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, body) = self.put(
            on,
            &format!("/v1/instances/{instance}/secrets/BANK_API_KEY"),
            key,
            &json!({ "stage": "production", "value": BANK }),
        );
        assert_eq!(status, 200, "{body}");
        let (status, body) = self.post(
            on,
            &format!("/v1/instances/{instance}/promotion-requests"),
            token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let (status, _) = self.post(
            on,
            &format!("/v1/instances/{instance}/promotions"),
            key,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        (release, status)
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

    /// 이벤트를 기록에 바로 쌓는다(보내는 일만 재는 테스트).
    fn append(&self, on: &str, organization: &str, count: usize) {
        let notes: Vec<Note> = (0..count)
            .map(|at| Note {
                instance: None,
                body: Body::SecretRequested {
                    name: format!("KEY_{at}"),
                },
            })
            .collect();
        self.layer(on)
            .records()
            .append_events(organization, now(), &notes)
            .unwrap();
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // 레이어로 지우면 떠 있는 프리뷰의 database 도 함께 걷힌다. 레이어가 없으면 관리 역할로 걷는다
        if self.servers.contains_key("a") {
            for instance in &self.instances {
                let _ = handle(
                    &self.servers["a"],
                    "DELETE",
                    &format!("/v1/instances/{instance}"),
                    Some(FACTORY),
                    &[],
                );
            }
        }
        for instance in &self.instances {
            if let Ok(mut admin) = orbital_pg::Admin::connect(&self.pg_url) {
                let names = orbital_core::plan::Names::new(InstanceId::parse(instance).unwrap());
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

// ---- 쌓기와 물어보기 ----

#[test]
fn 인스턴스를_세우고_지우면_그_조직의_이벤트가_차례대로_쌓이고_다른_조직에는_보이지_않는다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.upload("a", FACTORY, false);
    let first = bench.instance("a", FACTORY);
    let second = bench.instance("a", FACTORY);
    let (status, body) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{first}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    bench.instances.retain(|instance| instance != &first);
    let all = bench.events("a", FACTORY, "");
    let events = all["events"].as_array().unwrap();
    let seen: Vec<(String, String)> = events
        .iter()
        .map(|event| {
            (
                event["type"].as_str().unwrap().to_owned(),
                event["instance"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("instance.created".to_owned(), first.clone()),
            ("instance.created".to_owned(), second.clone()),
            ("instance.deleted".to_owned(), first.clone()),
        ]
    );
    assert_eq!(
        events[0]["data"],
        json!({ "app": "records", "version": "v1" })
    );
    assert_eq!(events[2]["data"], json!({ "app": "records" }));
    assert_eq!(events[0]["organization"], "factory");
    let ids: Vec<u64> = events
        .iter()
        .map(|event| event["id"].as_u64().unwrap())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    assert_eq!(all["has_more"], false);
    // after 로 이어 받는다. limit 이 차면 뒤에 더 있다고 알린다
    let page = bench.events("a", FACTORY, "?limit=2");
    assert_eq!(page["events"].as_array().unwrap().len(), 2);
    assert_eq!(page["has_more"], true);
    assert_eq!(page["next"], ids[1]);
    let rest = bench.events("a", FACTORY, &format!("?after={}", ids[1]));
    assert_eq!(rest["events"].as_array().unwrap().len(), 1);
    assert_eq!(rest["events"][0]["id"], ids[2]);
    assert_eq!(rest["next"], ids[2]);
    let empty = bench.events("a", FACTORY, &format!("?after={}", ids[2]));
    assert_eq!(empty["events"], json!([]));
    assert_eq!(empty["next"], ids[2]);
    // 다른 조직에는 보이지 않는다(다른 조직의 id 뒤를 물어도)
    assert_eq!(bench.events("a", OTHER, "")["events"], json!([]));
    assert_eq!(bench.events("a", OTHER, "?after=0")["events"], json!([]));
    // 틀린 질의는 고칠 것을 알린다
    let (status, body) = bench.call("a", "GET", "/v1/events?after=-1&limit=501", FACTORY, &[]);
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["details"].as_array().unwrap().len(), 2);
}

#[test]
fn 토큰과_운영자의_열쇠로는_이벤트를_보지도_웹훅을_걸지도_못한다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.upload("a", FACTORY, false);
    let instance = bench.instance("a", FACTORY);
    let token = bench.token("a", FACTORY, &instance);
    let receiver = Receiver::start();
    let hook = json!({ "url": receiver.url() }).to_string();
    for bearer in [token.as_str(), OPERATOR] {
        let (status, body) = bench.call("a", "GET", "/v1/events", bearer, &[]);
        assert_eq!(status, 403, "{body}");
        for method in ["GET", "PUT", "DELETE"] {
            let (status, body) =
                bench.call("a", method, "/v1/settings/webhook", bearer, hook.as_bytes());
            assert_eq!(status, 403, "{method} {body}");
        }
    }
    let (status, _) = bench.call("a", "GET", "/v1/events", "sk_test_unknown_events", &[]);
    assert_eq!(status, 401);
    // 아무것도 걸리지 않았다
    assert_eq!(bench.webhook("a", FACTORY), Value::Null);
    assert_eq!(
        bench
            .control()
            .query_one("SELECT count(*) FROM orbital.webhook", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

#[test]
fn 기록을_고치는_트랜잭션이_깨지면_그_이벤트도_남지_않는다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.upload("a", FACTORY, false);
    let instance = bench.instance("a", FACTORY);
    let id = InstanceId::parse(&instance).unwrap();
    let records = bench.layer("a").records();
    let before = bench.kinds("a", FACTORY).len();
    // 고치는 쪽이 이벤트를 적은 뒤 거절하면 둘 다 적지 않는다
    let refused: Result<Option<()>, orbital_server::records::RecordError> = records
        .update_instance_noting(&instance, now(), |_, notes| {
            notes.push(Note {
                instance: Some(id.clone()),
                body: Body::PromotionRequested {
                    release: "r_never".to_owned(),
                    commit: "c".repeat(40),
                },
            });
            Err(orbital_server::records::RecordError("거절".to_owned()))
        });
    assert!(refused.is_err());
    assert_eq!(bench.kinds("a", FACTORY).len(), before);
    // rollout 의 줄도 같다: 거절한 고침은 진행도 이벤트도 남기지 않고, 받아들인 고침은 그 진행의 이벤트를 함께 남긴다
    let rollout = orbital_core::rollout::Rollout::new(
        "records".to_owned(),
        "a".repeat(40),
        orbital_core::release::Change::SecurityUpdate,
        vec![vec![id.clone()]],
    )
    .unwrap();
    records
        .insert_rollout(
            "ro_events_test",
            &orbital_server::registry::RolloutRecord {
                organization: "factory".to_owned(),
                rollout,
            },
        )
        .unwrap();
    let applied = orbital_core::rollout::Event::Applied {
        instance: id.clone(),
    };
    let refused: Result<Option<()>, orbital_server::records::RecordError> =
        records.update_rollout("ro_events_test", now(), |record| {
            record.rollout = record.rollout.step(&applied).unwrap();
            Err(orbital_server::records::RecordError("거절".to_owned()))
        });
    assert!(refused.is_err());
    assert_eq!(bench.kinds("a", FACTORY).len(), before);
    records
        .update_rollout("ro_events_test", now(), |record| {
            record.rollout = record.rollout.step(&applied).unwrap();
            Ok::<(), orbital_server::records::RecordError>(())
        })
        .unwrap();
    let previewed = orbital_core::rollout::Event::Previewed {
        instance: id.clone(),
    };
    let checked = orbital_core::rollout::Event::Checked {
        instance: id.clone(),
        access_passed: false,
        conformance_passed: true,
    };
    records
        .update_rollout("ro_events_test", now(), |record| {
            record.rollout = record
                .rollout
                .step(&previewed)
                .and_then(|next| next.step(&checked))
                .map_err(|_| orbital_server::records::RecordError("거절".to_owned()))?;
            Ok::<(), orbital_server::records::RecordError>(())
        })
        .unwrap();
    let events = bench.events("a", FACTORY, "?limit=500");
    let tail: Vec<Value> = events["events"].as_array().unwrap()[before..].to_vec();
    let kinds: Vec<&str> = tail
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["rollout.advanced", "rollout.advanced", "rollout.halted"]
    );
    assert_eq!(tail[0]["instance"], instance.as_str());
    assert_eq!(tail[0]["data"]["progress"], json!({ "state": "applied" }));
    assert_eq!(
        tail[1]["data"]["progress"],
        json!({ "state": "failed", "reason": "access_check_failed" })
    );
    assert_eq!(tail[2]["data"]["failed"][0]["instance"], instance.as_str());
    assert_eq!(tail[2]["data"]["tally"]["failed"], 1);
}

#[test]
fn rollout_을_거두면_거둠이_쌓인다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.upload("a", FACTORY, false);
    let instance = bench.instance("a", FACTORY);
    let (status, rollout) = bench.post(
        "a",
        "/v1/apps/records/rollouts",
        FACTORY,
        &json!({ "change": "security_update", "waves": [[instance]] }),
    );
    assert_eq!(status, 200, "{rollout}");
    let id = rollout["id"].as_str().unwrap();
    let (status, body) = bench.post(
        "a",
        &format!("/v1/rollouts/{id}/cancel"),
        FACTORY,
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    let events = bench.events("a", FACTORY, "?limit=500");
    let last = events["events"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["type"], "rollout.cancelled");
    assert_eq!(last["data"]["rollout"], id);
    assert_eq!(last["data"]["app"], "records");
    assert_eq!(last["data"]["tally"]["waiting"], 1);
    assert!(last.get("instance").is_none(), "{last}");
}

#[test]
fn 승격의_요청과_승격과_비밀의_요청이_이벤트로_가고_어디에도_값이_없다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    let secret = bench.hook("a", FACTORY, &receiver.url());
    bench.upload("a", FACTORY, false);
    let instance = bench.instance("a", FACTORY);
    let token = bench.token("a", FACTORY, &instance);
    let (release, status) = bench.ship("a", FACTORY, &instance, &token);
    assert_eq!(status, 200);
    let (status, body) = bench.post(
        "a",
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/request"),
        &token,
        &json!({ "reason": "송금 API 의 키가 필요합니다 reason-text-marker" }),
    );
    assert_eq!(status, 200, "{body}");
    let report = bench.layer("a").deliver_due();
    assert_eq!(report.sent, 4, "{report:?}");
    let received = receiver.received();
    let kinds: Vec<String> = received
        .iter()
        .map(|received| received.json()["type"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "instance.created",
            "promotion.requested",
            "promotion.succeeded",
            "secret.requested"
        ]
    );
    let succeeded = received[2].json();
    assert_eq!(succeeded["instance"], instance.as_str());
    assert_eq!(succeeded["data"]["release"], release.as_str());
    assert_eq!(succeeded["data"]["change"], "customer_request");
    assert_eq!(succeeded["data"]["approved_by"], "customer");
    assert_eq!(succeeded["data"]["migrations"], 1);
    assert_eq!(succeeded["data"]["previous_release"], Value::Null);
    assert_eq!(
        received[3].json()["data"],
        json!({ "name": "BANK_API_KEY" })
    );
    assert_eq!(received[1].json()["data"]["release"], release.as_str());
    for one in &received {
        assert_eq!(one.path, "/hooks/orbital");
        assert_eq!(one.headers["content-type"], "application/json");
        assert!(verify(&secret, &one.headers["orbital-signature"], &one.body).is_some());
        assert_eq!(
            one.headers["orbital-event-id"],
            one.json()["id"].as_u64().unwrap().to_string()
        );
    }
    // 값 · 토큰 · 열쇠 · 서명의 비밀 · 에이전트가 적은 글은 기록의 어느 줄에도, 관리 서버의 폴더에도, 받은 본문에도 없다
    let mut bodies = Vec::new();
    for one in &received {
        bodies.extend_from_slice(&one.body);
        for value in one.headers.values() {
            bodies.extend_from_slice(value.as_bytes());
        }
    }
    let records = bench.everything();
    // 에이전트가 적은 까닭은 요청의 줄(`secret_request`)에만 있고 이벤트와 웹훅의 줄에는 없다
    let mut client = bench.control();
    let mut delivered = String::new();
    for table in ["event", "webhook"] {
        for row in client
            .query(
                &format!("SELECT row_to_json(t)::text FROM orbital.{table} t"),
                &[],
            )
            .unwrap()
        {
            delivered.push_str(&row.get::<_, String>(0));
        }
    }
    assert!(!delivered.contains("reason-text-marker"));
    assert!(records.contains("reason-text-marker"), "시험이 헛돕니다");
    let mut folder = Vec::new();
    all_bytes(&bench.home("a"), &mut folder);
    let webhook = bench.webhook("a", FACTORY).to_string();
    let list = bench.events("a", FACTORY, "?limit=500").to_string();
    for needle in [
        BANK,
        FACTORY,
        token.as_str(),
        secret.as_str(),
        "reason-text-marker",
        "answer-body-",
    ] {
        assert!(!contains(&bodies, needle), "받은 본문에 {needle}");
        assert!(
            needle == "reason-text-marker" || !records.contains(needle),
            "기록에 {needle}"
        );
        assert!(!contains(&folder, needle), "관리 서버의 폴더에 {needle}");
        assert!(!webhook.contains(needle), "웹훅의 모습에 {needle}");
        assert!(!list.contains(needle), "이벤트의 목록에 {needle}");
    }
    // 이벤트의 몸에는 정한 칸만 있다
    for one in &received {
        let event = one.json();
        let keys: Vec<&str> = event
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "created_at",
                "data",
                "id",
                "instance",
                "organization",
                "type"
            ]
        );
    }
}

#[test]
fn 운영에서_서지_못해_되돌려진_승격은_승격이_되돌려짐으로_쌓인다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.upload("a", FACTORY, true);
    let instance = bench.instance("a", FACTORY);
    let token = bench.token("a", FACTORY, &instance);
    let (release, status) = bench.ship("a", FACTORY, &instance, &token);
    assert_ne!(status, 200);
    let events = bench.events("a", FACTORY, "?limit=500");
    let events = events["events"].as_array().unwrap();
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "instance.created",
            "promotion.requested",
            "promotion.failed"
        ]
    );
    let failed = &events[2];
    assert_eq!(failed["instance"], instance.as_str());
    assert_eq!(failed["data"]["release"], release.as_str());
    assert_eq!(failed["data"]["previous_release"], Value::Null);
    assert_eq!(failed["data"]["migrated"], true);
    assert!(!kinds.contains(&"promotion.succeeded"));
}

// ---- 걸기 ----

#[test]
fn 웹훅의_서명_비밀은_건_답에만_있고_기록에는_봉인한_글로만_있으며_열쇠가_없는_레이어는_걸지_못한다()
 {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    let (status, body) = bench.put(
        "a",
        "/v1/settings/webhook",
        FACTORY,
        &json!({ "url": receiver.url() }),
    );
    assert_eq!(status, 200, "{body}");
    let secret = body["secret"].as_str().unwrap().to_owned();
    assert!(
        secret.starts_with("whsec_") && secret.len() == 6 + 64,
        "{secret}"
    );
    assert_eq!(body["webhook"]["url"], receiver.url());
    let shown = bench.webhook("a", FACTORY);
    assert_eq!(shown["url"], receiver.url());
    assert!(shown["created_at"].is_u64());
    assert!(!shown.to_string().contains(&secret));
    let sealed: String = bench
        .control()
        .query_one(
            "SELECT secret FROM orbital.webhook WHERE organization = 'factory'",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(sealed.starts_with("seal1."), "{sealed}");
    assert!(!bench.everything().contains(&secret));
    // 다시 걸면 비밀이 바뀐다. 떼면 없다
    let again = bench.hook("a", FACTORY, &receiver.url());
    assert_ne!(again, secret);
    let (status, body) = bench.call("a", "DELETE", "/v1/settings/webhook", FACTORY, &[]);
    assert_eq!((status, body["removed"].clone()), (200, json!(true)));
    assert_eq!(bench.webhook("a", FACTORY), Value::Null);
    // 봉인의 열쇠가 없는 레이어
    bench.servers.clear();
    bench.open(
        "b",
        &Setup {
            seal: None,
            ..Setup::default()
        },
    );
    let (status, body) = bench.put(
        "b",
        "/v1/settings/webhook",
        FACTORY,
        &json!({ "url": receiver.url() }),
    );
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("ORBITAL_SEAL_KEY"),
        "{body}"
    );
}

#[test]
fn 개발용이_아닌_레이어는_http_와_사설_주소와_사설_주소로_풀리는_이름을_걸지_못한다() {
    let mut bench = bench!();
    bench.open(
        "a",
        &Setup {
            dev: false,
            ..Setup::default()
        },
    );
    let receiver = Receiver::start();
    let refused = |bench: &Bench, url: &str| {
        let (status, body) =
            bench.put("a", "/v1/settings/webhook", FACTORY, &json!({ "url": url }));
        assert_eq!(status, 422, "{url}: {body}");
    };
    refused(&bench, &receiver.url());
    refused(
        &bench,
        &format!("https://127.0.0.1:{}/hooks", receiver.port),
    );
    refused(&bench, "https://169.254.169.254/latest/meta-data/");
    refused(&bench, "https://10.0.0.7/hooks");
    refused(&bench, "https://[::1]/hooks");
    refused(&bench, "https://[::ffff:127.0.0.1]/hooks");
    refused(&bench, "https://[fe80::1]/hooks");
    refused(&bench, "https://user@hooks.example.test/hooks");
    refused(&bench, "https://hooks.example.test/hooks#part");
    // 이름이 안쪽으로 풀리면 걸지 못한다. 무엇으로 풀렸는지는 알리지 않는다
    for inside in [
        "127.0.0.1",
        "10.0.0.7",
        "169.254.169.254",
        "100.64.0.1",
        "fd00::7",
    ] {
        bench.resolver.point(&[inside]);
        let (status, body) = bench.put(
            "a",
            "/v1/settings/webhook",
            FACTORY,
            &json!({ "url": "https://hooks.example.test/hooks" }),
        );
        assert_eq!(status, 422, "{inside}: {body}");
        assert!(!body.to_string().contains(inside), "{body}");
    }
    // 바깥과 안쪽이 섞여 풀려도 걸지 못한다
    bench.resolver.point(&["8.8.8.8", "127.0.0.1"]);
    let (status, _) = bench.put(
        "a",
        "/v1/settings/webhook",
        FACTORY,
        &json!({ "url": "https://hooks.example.test/hooks" }),
    );
    assert_eq!(status, 422);
    assert_eq!(bench.webhook("a", FACTORY), Value::Null);
    assert!(receiver.received().is_empty());
    // 바깥으로만 풀리는 이름은 건다(보내지는 않는다)
    bench.resolver.point(&["8.8.8.8"]);
    bench.hook("a", FACTORY, "https://hooks.example.test/hooks");
}

// ---- 보내기 ----

#[test]
fn 걸_때는_바깥으로_풀리던_이름이_보낼_때_안쪽으로_풀리면_보내지_않는다() {
    let mut bench = bench!();
    bench.open(
        "a",
        &Setup {
            dev: false,
            ..Setup::default()
        },
    );
    let receiver = Receiver::start();
    bench.resolver.point(&["8.8.8.8"]);
    bench.hook(
        "a",
        FACTORY,
        &format!("https://hooks.example.test:{}/hooks", receiver.port),
    );
    // 이름이 이제 받는 서버(127.0.0.1)를 가리킨다
    bench.resolver.point(&["127.0.0.1"]);
    bench.append("a", "factory", 1);
    let report = bench.layer("a").deliver_due();
    assert_eq!(report.retrying, 1, "{report:?}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(receiver.received().is_empty(), "안쪽으로 보냈습니다");
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["last_error"], "refused_address", "{delivery}");
    assert_eq!(delivery["failures"], 1);
    assert_eq!(delivery["pending"], 1);
    assert_eq!(delivery["last_status"], Value::Null);
}

#[test]
fn 걸어_둔_주소로_이벤트가_서명과_함께_가고_리다이렉트는_따라가지_않는다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    let inner = Receiver::start();
    let secret = bench.hook("a", FACTORY, &receiver.url());
    bench.append("a", "factory", 1);
    let at = now() + 1_000;
    bench.clock.store(at, Ordering::SeqCst);
    assert_eq!(bench.layer("a").deliver_due().sent, 1);
    let first = receiver.received()[0].clone();
    // 서명은 그 비밀로 맞고, 한 글자라도 바뀌면 맞지 않는다
    let header = first.headers["orbital-signature"].clone();
    assert_eq!(verify(&secret, &header, &first.body), Some(at));
    let mut tampered = first.body.clone();
    tampered[1] ^= 1;
    assert_eq!(verify(&secret, &header, &tampered), None);
    assert_eq!(verify("whsec_other", &header, &first.body), None);
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["pending"], 0);
    assert_eq!(delivery["last_status"], 200);
    assert_eq!(delivery["delivered_at"], at);
    assert_eq!(delivery["next_at"], Value::Null);
    // 받는 쪽이 안쪽의 다른 주소로 가라고 답해도 따라가지 않는다
    *receiver.redirect.lock().unwrap() = Some(format!("{}/inner", inner.url()));
    bench.append("a", "factory", 1);
    assert_eq!(bench.layer("a").deliver_due().retrying, 1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(inner.received().is_empty(), "리다이렉트를 따라갔습니다");
    assert_eq!(receiver.received().len(), 2, "리다이렉트를 따라갔습니다");
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["last_status"], 302, "{delivery}");
    assert_eq!(delivery["last_error"], "status");
    assert!(!delivery.to_string().contains("answer-body"));
}

#[test]
fn 받는_쪽이_실패하면_물러나며_다시_보내고_앞의_것이_가기_전에는_뒤의_것을_보내지_않는다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    bench.hook("a", FACTORY, &receiver.url());
    bench.append("a", "factory", 2);
    let start = now() + 1_000;
    bench.clock.store(start, Ordering::SeqCst);
    receiver.answer(&[500, 503]);
    let layer = bench.layer("a");
    assert_eq!(layer.deliver_due().retrying, 1);
    let first = receiver.ids()[0];
    // 30초가 지나기 전에는 보내지 않고, 뒤의 것을 먼저 보내지도 않는다
    bench.clock.store(start + 29, Ordering::SeqCst);
    assert_eq!(layer.deliver_due().sent + layer.deliver_due().retrying, 0);
    assert_eq!(receiver.ids(), [first]);
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["next_at"], start + 30, "{delivery}");
    assert_eq!(delivery["last_status"], 500);
    assert_eq!(delivery["failures"], 1);
    bench.clock.store(start + 30, Ordering::SeqCst);
    assert_eq!(layer.deliver_due().retrying, 1);
    assert_eq!(
        bench.webhook("a", FACTORY)["delivery"]["next_at"],
        start + 30 + 120
    );
    // 다시 실패한 뒤 2분이 지나면 앞의 것이 가고 이어서 뒤의 것이 간다
    bench.clock.store(start + 150, Ordering::SeqCst);
    assert_eq!(layer.deliver_due().sent, 2);
    let ids = receiver.ids();
    assert_eq!(ids[..3], [first, first, first]);
    assert_eq!(ids.len(), 4);
    assert!(ids[3] > first);
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["failures"], 0);
    assert_eq!(delivery["pending"], 0);
    assert_eq!(delivery["delivered_through"], ids[3]);
}

#[test]
fn 하루_동안_보내지_못한_이벤트는_그만두고_실패로_적은_뒤_다음_것을_보낸다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    bench.hook("a", FACTORY, &receiver.url());
    bench.append("a", "factory", 2);
    let start = now() + 1_000;
    let mut at = start;
    bench.clock.store(at, Ordering::SeqCst);
    receiver.answer(&[500; 64]);
    let layer = bench.layer("a");
    let mut abandoned = 0;
    for _ in 0..20 {
        let report = layer.deliver_due();
        abandoned += report.abandoned;
        if abandoned > 0 {
            break;
        }
        let next = bench.webhook("a", FACTORY)["delivery"]["next_at"]
            .as_u64()
            .unwrap();
        assert!(next <= start + GIVE_UP_AFTER, "{next}");
        at = next;
        bench.clock.store(at, Ordering::SeqCst);
    }
    assert_eq!(abandoned, 1);
    assert_eq!(at, start + GIVE_UP_AFTER);
    let first = receiver.ids()[0];
    let delivery = bench.webhook("a", FACTORY)["delivery"].clone();
    assert_eq!(delivery["abandoned"], 1, "{delivery}");
    assert_eq!(delivery["last_abandoned"], first);
    assert_eq!(delivery["delivered_through"], first);
    // 그만둔 뒤 바로 뒤의 것으로 넘어간다(같은 부름에서 보내 보고, 실패했으니 30초 뒤에 다시 보낸다)
    let second = *receiver.ids().last().unwrap();
    assert!(second > first);
    receiver.answers.lock().unwrap().clear();
    bench.clock.store(at + 30, Ordering::SeqCst);
    assert_eq!(layer.deliver_due().sent, 1);
    assert_eq!(receiver.ids().last(), Some(&second));
    assert_eq!(bench.webhook("a", FACTORY)["delivery"]["pending"], 0);
}

#[test]
fn 답을_기다리는_시간에_상한이_있다() {
    let mut bench = bench!();
    bench.open(
        "a",
        &Setup {
            timeout: Duration::from_millis(500),
            ..Setup::default()
        },
    );
    let receiver = Receiver::start();
    receiver.delay.store(3_000, Ordering::SeqCst);
    bench.hook("a", FACTORY, &receiver.url());
    bench.append("a", "factory", 1);
    let started = Instant::now();
    assert_eq!(bench.layer("a").deliver_due().retrying, 1);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        bench.webhook("a", FACTORY)["delivery"]["last_error"],
        "timed_out"
    );
}

#[test]
fn 느리게_답하는_받는_쪽이_다른_조직의_전달을_붙들지_못한다() {
    let mut bench = bench!();
    bench.open(
        "a",
        &Setup {
            every: Some(Duration::from_millis(50)),
            timeout: Duration::from_secs(8),
            ..Setup::default()
        },
    );
    let slow = Receiver::start();
    slow.delay.store(4_000, Ordering::SeqCst);
    let fast = Receiver::start();
    bench.hook("a", FACTORY, &slow.url());
    bench.hook("a", OTHER, &fast.url());

    // 느린 쪽에 보낼 것이 줄을 섰고, 첫 요청이 답을 기다리는 중이다
    bench.append("a", "factory", 3);
    let started = Instant::now();
    while slow.received().is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "느린 쪽에 보내지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // 그사이 다른 조직에 이벤트가 생긴다. 느린 쪽의 답을 기다리지 않고 간다
    bench.append("a", "other", 1);
    let asked = Instant::now();
    while fast.received().is_empty() {
        assert!(
            asked.elapsed() < Duration::from_millis(2_000),
            "다른 조직의 이벤트가 느린 받는 쪽을 기다렸습니다"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // 느린 쪽은 아직 첫 요청의 답도 하지 않았다
    assert_eq!(slow.received().len(), 1);
    // 같은 조직 안에서는 차례가 그대로다. 앞의 것이 끝나야 뒤의 것이 간다
    let started = Instant::now();
    while slow.received().len() < 3 {
        assert!(started.elapsed() < Duration::from_secs(20));
        std::thread::sleep(Duration::from_millis(50));
    }
    let ids = slow.ids();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted, "차례가 어긋났거나 겹쳐 갔습니다");
    // 받는 쪽이 마지막 답을 하기 전에 레이어를 내리지 않는다(남은 요청이 끊기지 않게)
    slow.delay.store(0, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(4_200));
}

#[test]
fn 두_관리_서버가_함께_보내도_같은_이벤트는_한_번만_가고_차례가_지켜진다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    bench.open("b", &Setup::default());
    let receiver = Receiver::start();
    receiver.delay.store(20, Ordering::SeqCst);
    let other = Receiver::start();
    bench.hook("a", FACTORY, &receiver.url());
    bench.hook("b", OTHER, &other.url());
    // 한쪽에서 쌓인 이벤트를 두 관리 서버가 함께 보낸다
    bench.append("a", "factory", 12);
    bench.append("b", "other", 5);
    let bench = Arc::new(bench);
    let workers: Vec<JoinHandle<usize>> = ["a", "b", "a", "b"]
        .into_iter()
        .map(|on| {
            let bench = Arc::clone(&bench);
            std::thread::spawn(move || {
                let mut sent = 0;
                for _ in 0..40 {
                    sent += bench.layer(on).deliver_due().sent;
                }
                sent
            })
        })
        .collect();
    let sent: usize = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .sum();
    assert_eq!(sent, 17);
    let ids = receiver.ids();
    assert_eq!(ids.len(), 12, "{ids:?}");
    assert!(
        ids.windows(2).all(|pair| pair[0] < pair[1]),
        "차례가 어긋났거나 겹쳤습니다: {ids:?}"
    );
    let others = other.ids();
    assert_eq!(others.len(), 5);
    assert!(
        others.windows(2).all(|pair| pair[0] < pair[1]),
        "{others:?}"
    );
    // 서로의 이벤트는 섞이지 않는다
    assert!(
        receiver
            .received()
            .iter()
            .all(|one| one.json()["organization"] == "factory")
    );
    assert!(
        other
            .received()
            .iter()
            .all(|one| one.json()["organization"] == "other")
    );
}

#[test]
fn 레이어가_내려가면_보내는_고리가_멈춘다() {
    let mut bench = bench!();
    bench.open(
        "a",
        &Setup {
            every: Some(Duration::from_millis(100)),
            ..Setup::default()
        },
    );
    bench.open("b", &Setup::default());
    let receiver = Receiver::start();
    bench.hook("a", FACTORY, &receiver.url());
    // 뒤의 고리가 스스로 보낸다
    bench.append("a", "factory", 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    while receiver.received().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        receiver.received().len(),
        1,
        "뒤의 고리가 보내지 않았습니다"
    );
    // a 를 내린 뒤 쌓인 것은 아무도 보내지 않는다(b 는 고리를 띄우지 않았다)
    bench.servers.remove("a");
    std::thread::sleep(Duration::from_millis(300));
    bench.append("b", "factory", 1);
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(
        receiver.received().len(),
        1,
        "내려간 레이어의 고리가 보냈습니다"
    );
}

#[test]
fn 보관_기간이_지난_이벤트는_걷는다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let start = now();
    bench.append("a", "factory", 2);
    // 보관 기간 바로 안에서는 남는다
    bench.clock.store(start + RETENTION - 60, Ordering::SeqCst);
    bench.layer("a").deliver_due();
    assert_eq!(bench.kinds("a", FACTORY).len(), 2);
    // 지난 레이어를 다시 열고(걷기는 한 시간에 한 번) 기간이 지난 뒤에 보면 걷혀 있다
    bench.servers.clear();
    bench.open("a", &Setup::default());
    bench.clock.store(start + RETENTION + 60, Ordering::SeqCst);
    bench.layer("a").deliver_due();
    assert!(bench.kinds("a", FACTORY).is_empty());
}

#[test]
fn 봉인의_열쇠를_바꾸면_웹훅의_비밀도_새_열쇠로_다시_봉인되고_같은_비밀로_서명한다() {
    let mut bench = bench!();
    bench.open("a", &Setup::default());
    let receiver = Receiver::start();
    let secret = bench.hook("a", FACTORY, &receiver.url());
    let before: String = bench
        .control()
        .query_one("SELECT secret FROM orbital.webhook", &[])
        .unwrap()
        .get(0);
    bench.servers.clear();
    bench.open(
        "a",
        &Setup {
            seal: Some([9; 32]),
            previous: Some([7; 32]),
            ..Setup::default()
        },
    );
    let resealed = bench.layer("a").resealed().unwrap().clone();
    assert_eq!(resealed.webhook, 1);
    let after: String = bench
        .control()
        .query_one("SELECT secret FROM orbital.webhook", &[])
        .unwrap()
        .get(0);
    assert_ne!(before, after);
    // 옛 열쇠 없이 새 열쇠만으로 다시 떠도 같은 비밀로 서명한다
    bench.servers.clear();
    bench.open(
        "a",
        &Setup {
            seal: Some([9; 32]),
            ..Setup::default()
        },
    );
    bench.append("a", "factory", 1);
    assert_eq!(bench.layer("a").deliver_due().sent, 1);
    let one = receiver.received()[0].clone();
    assert!(verify(&secret, &one.headers["orbital-signature"], &one.body).is_some());
}
