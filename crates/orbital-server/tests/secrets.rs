//! 밖에서 넣는 비밀은 인스턴스와 단계(프리뷰 · 운영)마다 따로 금고에 봉인되고, 에이전트는 값을 한 번도 보지 않고 운영에 오른다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버), 실제 HTTP 로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에 바로 넣고,
//! 사람의 브라우저가 부르는 입력 표의 주소와 띄운 앱에는 실제 HTTP 로 요청한다. 시험용 앱(`fixtures/vault`)은 받은 값의 sha256 만 내준다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_run::LocalRunner;
use orbital_server::http::{answer, handle};
use orbital_server::layer::{Layer, Options, VAULT};
use orbital_server::seal::SealKey;
use orbital_server::token::hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
const SEAL: [u8; 32] = [7; 32];
/// 어디에 새어도 찾을 수 있게 드문 글자로 지은 값.
const BANK: &str = "sk_live_bank_Qz81xVv0pLm";
const BANK_PREVIEW: &str = "sk_test_bank_Hh27cWq3nRe";
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
/// 카드가 선 자리. 레이어와 다른 출처다.
const CARD_ORIGIN: &str = "https://factory-card.example";

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
        .args([
            "-c",
            "user.name=agent",
            "-c",
            "user.email=agent@example.invalid",
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

/// 폴더 아래 모든 파일의 글을 이어 붙인다. 빌드 결과와 코드 저장소(앱의 것)는 뺀다. 값이 어디에도 없는지 볼 때 쓴다.
fn everything_under(folder: &Path) -> String {
    let mut text = String::new();
    let Ok(entries) = fs::read_dir(folder) else {
        return text;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("builds" | "sources" | "apps")
            ) {
                text.push_str(&everything_under(&path));
            }
        } else {
            text.push_str(&String::from_utf8_lossy(
                &fs::read(&path).unwrap_or_default(),
            ));
            text.push('\n');
        }
    }
    text
}

/// 실제 HTTP 의 답.
struct Http {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Http {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

fn http(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> Http {
    let mut request = ureq::request(method, url).timeout(Duration::from_secs(30));
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = if body.is_empty() {
        request.call()
    } else {
        request.send_string(body)
    };
    let response = match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("{method} {url}: {error}"),
    };
    let headers = response
        .headers_names()
        .into_iter()
        .filter_map(|name| {
            let value = response.header(&name)?.to_owned();
            Some((name, value))
        })
        .collect();
    let status = response.status();
    Http {
        status,
        headers,
        body: response.into_string().unwrap_or_default(),
    }
}

/// 레이어 앞의 받기 고리. 멈추면 받던 자리(`Server`)를 돌려준다. 다시 열어도 바깥 주소가 같다.
struct Front {
    stop: Arc<AtomicBool>,
    task: JoinHandle<tiny_http::Server>,
}

fn front(layer: Arc<Layer>, server: tiny_http::Server) -> Front {
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let task = std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
                let layer = Arc::clone(&layer);
                std::thread::spawn(move || answer(&layer, request));
            }
        }
        server
    });
    Front { stop, task }
}

struct Bench {
    scratch: PathBuf,
    home: PathBuf,
    pg_url: String,
    /// 레이어의 바깥 주소. 입력 표의 주소가 이 아래에 선다.
    public: String,
    /// 레이어의 시계를 앞으로 돌리는 초.
    ahead: Arc<AtomicU64>,
    layer: Option<Arc<Layer>>,
    front: Option<Front>,
    instances: Vec<(String, &'static str)>,
}

impl Bench {
    fn new(seal: Option<SealKey>) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-secrets-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&scratch).unwrap();
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let public = format!("http://{}", server.server_addr().to_ip().unwrap());
        let mut bench = Self {
            home: scratch.join("home"),
            scratch,
            pg_url,
            public,
            ahead: Arc::new(AtomicU64::new(0)),
            layer: None,
            front: None,
            instances: Vec::new(),
        };
        bench.open(seal, server);
        for key in [FACTORY, OTHER_FACTORY] {
            bench.upload(key);
        }
        Some(bench)
    }

    fn open(&mut self, seal: Option<SealKey>, server: tiny_http::Server) {
        let ahead = Arc::clone(&self.ahead);
        let layer = Arc::new(
            Layer::open(Options {
                seal_key: seal,
                public_url: self.public.clone(),
                dev_mailbox: true,
                clock: Arc::new(move || now() + ahead.load(Ordering::SeqCst)),
                ..Options::new(
                    self.home.clone(),
                    self.pg_url.clone(),
                    vec![
                        (FACTORY.to_owned(), "factory".to_owned()),
                        (OTHER_FACTORY.to_owned(), "other".to_owned()),
                    ],
                    Box::new(LocalRunner::default()),
                )
            })
            .expect("레이어를 열지 못했습니다"),
        );
        self.front = Some(front(Arc::clone(&layer), server));
        self.layer = Some(layer);
    }

    /// 관리 서버가 내려갔다가 다시 뜬 것처럼 한다. 앞의 레이어가 띄운 것은 모두 내려간다. 봉인의 열쇠를 바꿔 띄울 수 있다.
    fn restart(&mut self, seal: Option<SealKey>) {
        let server = self.shut();
        self.open(seal, server);
    }

    /// 받기 고리를 멈추고 레이어를 내린다. 받던 자리를 돌려준다.
    fn shut(&mut self) -> tiny_http::Server {
        let front = self.front.take().unwrap();
        front.stop.store(true, Ordering::SeqCst);
        let server = front.task.join().unwrap();
        let mut layer = self.layer.take().unwrap();
        // 답하던 일이 끝나 레이어를 쥔 것이 이 테스트뿐일 때 내린다
        let started = Instant::now();
        loop {
            match Arc::try_unwrap(layer) {
                Ok(layer) => {
                    drop(layer);
                    break;
                }
                Err(shared) => {
                    assert!(started.elapsed() < Duration::from_secs(30));
                    layer = shared;
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        server
    }

    fn layer(&self) -> &Layer {
        self.layer.as_ref().unwrap()
    }

    fn upload(&self, key: &str) {
        let folder = self.scratch.join(format!("scaffold-{key}"));
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault"),
            &folder,
        );
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{key}.bundle"));
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
        let (status, body) = self.call("PUT", "/v1/apps/vault", key, &fs::read(bundle).unwrap());
        assert_eq!(status, 200, "{body}");
    }

    fn call(&self, method: &str, path: &str, bearer: &str, body: &[u8]) -> (u16, Value) {
        let reply = handle(self.layer(), method, path, Some(bearer), body);
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
        )
    }

    fn post(&self, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
        self.call("POST", path, bearer, body.to_string().as_bytes())
    }

    fn instance(&mut self, key: &'static str) -> String {
        let (status, body) = self.post(
            "/v1/instances",
            key,
            &json!({ "app": "vault", "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push((instance.clone(), key));
        instance
    }

    fn token(&self, key: &str, instance: &str, can: &[&str]) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/sessions"),
            key,
            &json!({ "can": can }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    fn preview(&self, instance: &str, token: &str) -> Value {
        let (status, preview) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        preview
    }

    /// 에이전트가 프리뷰를 세우고 승격을 요청한 뒤 팩토리가 사람의 승인으로 올린다. (프리뷰, 요청의 답, 승격의 답).
    fn ship(&self, instance: &str, token: &str) -> (Value, (u16, Value), (u16, Value)) {
        let preview = self.preview(instance, token);
        let release = preview["release"].as_str().unwrap().to_owned();
        let requested = self.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            token,
            &json!({ "release": release }),
        );
        let promoted = self.post(
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        (preview, requested, promoted)
    }

    /// 올리고 운영의 주소를 돌려준다.
    fn ship_ok(&self, instance: &str, token: &str) -> String {
        let (_, requested, (status, production)) = self.ship(instance, token);
        assert_eq!(requested.0, 200, "{}", requested.1);
        assert_eq!(status, 200, "{production}");
        url(&production)
    }

    fn put(&self, key: &str, instance: &str, stage: &str, value: &str) -> (u16, Value) {
        self.call(
            "PUT",
            &format!("/v1/instances/{instance}/secrets/BANK_API_KEY"),
            key,
            json!({ "stage": stage, "value": value })
                .to_string()
                .as_bytes(),
        )
    }

    fn put_ok(&self, instance: &str, stage: &str, value: &str) {
        let (status, body) = self.put(FACTORY, instance, stage, value);
        assert_eq!(status, 200, "{body}");
    }

    /// 입력 표를 받는다(service key). 표가 든 주소를 돌려준다.
    fn entry(&self, instance: &str, stage: &str) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/entries"),
            FACTORY,
            &json!({ "stage": stage }),
        );
        assert_eq!(status, 200, "{body}");
        let url = body["url"].as_str().unwrap().to_owned();
        assert!(
            url.starts_with(&format!("{}/v1/secret-entries/", self.public)),
            "{url}"
        );
        let expires_at = body["expires_at"].as_u64().unwrap();
        let issued = now() + self.ahead.load(Ordering::SeqCst);
        assert!(
            expires_at >= issued + 599 && expires_at <= issued + 601,
            "{body}"
        );
        url
    }

    fn list(&self, bearer: &str, instance: &str) -> Value {
        let (status, body) = self.call(
            "GET",
            &format!("/v1/instances/{instance}/secrets"),
            bearer,
            &[],
        );
        assert_eq!(status, 200, "{body}");
        body
    }

    fn production(&self, instance: &str) -> Value {
        self.call(
            "GET",
            &format!("/v1/instances/{instance}/production"),
            FACTORY,
            &[],
        )
        .1
    }

    /// 에이전트가 하듯이 코드를 받아 고치고 올린다.
    fn change(&self, instance: &str, token: &str, edit: &dyn Fn(&Path)) {
        let reply = handle(
            self.layer(),
            "GET",
            &format!("/v1/instances/{instance}/source"),
            Some(token),
            &[],
        );
        assert_eq!(reply.status, 200);
        let at = COUNTER.fetch_add(1, Ordering::Relaxed);
        let bundle = self.scratch.join(format!("pull-{at}.bundle"));
        fs::write(&bundle, reply.body).unwrap();
        let work = self.scratch.join(format!("work-{at}"));
        git(
            &self.scratch,
            &[
                "clone",
                "--quiet",
                bundle.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        edit(&work);
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "--quiet", "-m", "고친다"]);
        let pushed = self.scratch.join(format!("push-{at}.bundle"));
        git(
            &work,
            &[
                "bundle",
                "create",
                "--quiet",
                pushed.to_str().unwrap(),
                "main",
            ],
        );
        let (status, body) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/source"),
            token,
            &fs::read(pushed).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        if self.layer.is_some() {
            for (instance, key) in &self.instances {
                let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), key, &[]);
            }
            let _ = self.shut();
        }
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    () => {
        bench!(Some(SealKey::from_bytes(SEAL)))
    };
    ($seal:expr) => {
        match Bench::new($seal) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn url(report: &Value) -> String {
    report["services"][0]["url"].as_str().unwrap().to_owned()
}

/// 앱이 받은 비밀. 값이 아니라 있는지와 sha256 이다.
fn secret_at(origin: &str) -> Value {
    let reply = http("GET", &format!("{origin}/secret"), &[], "");
    assert_eq!(reply.status, 200, "{}", reply.body);
    reply.json()
}

fn texts(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// 입력 표의 주소로 카드(다른 출처의 브라우저)가 하듯이 값을 보낸다.
fn send_entry(url: &str, body: &Value) -> Http {
    http(
        "POST",
        url,
        &[
            ("Origin", CARD_ORIGIN),
            ("Content-Type", "application/json"),
        ],
        &body.to_string(),
    )
}

fn bank(list: &Value) -> Value {
    list["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|secret| secret["name"] == "BANK_API_KEY")
        .cloned()
        .unwrap_or(Value::Null)
}

// ---- 요청 ----

#[test]
fn 에이전트의_토큰으로_선언한_비밀의_입력을_요청한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);

    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/request"),
        &token,
        &json!({ "reason": "송금 기능이 은행 API 를 부릅니다" }),
    );
    assert_eq!(status, 200, "{body}");
    let listed = bench.list(&token, &instance);
    let shown = bank(&listed);
    assert_eq!(shown["declared"], true);
    assert_eq!(
        shown["requested"]["reason"],
        "송금 기능이 은행 API 를 부릅니다"
    );
    assert!(shown["requested"]["at"].as_u64().unwrap() >= now() - 5);
    assert_eq!(shown["preview"], json!({ "set": false }));
    assert_eq!(shown["production"], json!({ "set": false }));
    // 팩토리도 같은 것을 본다
    assert_eq!(bench.list(FACTORY, &instance), listed);

    // 그 능력이 없는 토큰으로는 요청하지 못한다
    let narrow = bench.token(FACTORY, &instance, &["source", "preview"]);
    let (status, _) = bench.post(
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/request"),
        &narrow,
        &json!({ "reason": "까닭" }),
    );
    assert_eq!(status, 403);
    let (status, _) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/secrets"),
        &narrow,
        &[],
    );
    assert_eq!(status, 403);
}

#[test]
fn 선언하지_않은_이름의_요청은_무엇을_고칠지_알려_주며_거절한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    let ask = |name: &str, reason: &str| {
        bench.post(
            &format!("/v1/instances/{instance}/secrets/{name}/request"),
            &token,
            &json!({ "reason": reason }),
        )
    };
    // 프리뷰를 세우기 전에는 선언한 이름도 요청하지 못한다(레이어가 아직 그 선언을 읽지 않았다)
    let (status, body) = ask("BANK_API_KEY", "송금");
    assert_eq!(status, 422, "{body}");
    let details = texts(&body["details"]).join("\n");
    assert!(details.contains("[secrets] external"), "{details}");
    assert!(details.contains("프리뷰를 세운 뒤"), "{details}");

    bench.preview(&instance, &token);
    assert_eq!(ask("BANK_API_KEY", "송금").0, 200);
    let (status, body) = ask("MAP_KEY", "지도");
    assert_eq!(status, 422, "{body}");
    assert!(texts(&body["details"]).join("\n").contains("`MAP_KEY`"));
    // 이름의 모양이 틀렸거나 까닭이 없으면 그것도 알린다
    let (status, body) = ask("bank_api_key", "송금");
    assert_eq!(status, 422, "{body}");
    let (status, body) = ask("BANK_API_KEY", " ");
    assert_eq!(status, 422, "{body}");
    assert!(texts(&body["details"]).join("\n").contains("까닭"));
    // 거절된 요청은 적히지 않는다
    let listed = bench.list(FACTORY, &instance);
    assert_eq!(listed["secrets"].as_array().unwrap().len(), 1, "{listed}");
}

#[test]
fn 에이전트의_토큰으로는_값을_넣지도_입력_표를_받지도_못한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let path = format!("/v1/instances/{instance}/secrets/BANK_API_KEY");
    for stage in ["preview", "production"] {
        let body = json!({ "stage": stage, "value": BANK }).to_string();
        let (status, put) = bench.call("PUT", &path, &token, body.as_bytes());
        assert_eq!(status, 403, "{put}");
        assert!(
            put["message"]
                .as_str()
                .unwrap()
                .contains("토큰으로는 할 수 없는")
        );
        let (status, _) = bench.call("DELETE", &format!("{path}?stage={stage}"), &token, &[]);
        assert_eq!(status, 403);
        let (status, _) = bench.post(
            &format!("{path}/entries"),
            &token,
            &json!({ "stage": stage }),
        );
        assert_eq!(status, 403);
    }
    let shown = bank(&bench.list(FACTORY, &instance));
    assert_eq!(shown["preview"]["set"], false);
    assert_eq!(shown["production"]["set"], false);
    assert!(!everything_under(&bench.home).contains(BANK));
}

#[test]
fn 비밀의_목록은_이름과_채워졌는지만_돌려준다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);

    for bearer in [FACTORY, token.as_str()] {
        let listed = bench.list(bearer, &instance);
        let secrets = listed["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 1, "{listed}");
        let shown = &secrets[0];
        let mut keys: Vec<&str> = shown
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["declared", "name", "preview", "production"]);
        assert_eq!(shown["name"], "BANK_API_KEY");
        assert_eq!(shown["preview"], json!({ "set": false }));
        assert_eq!(shown["production"]["set"], true);
        let set_at = shown["production"]["set_at"].as_u64().unwrap();
        assert!(set_at >= now() - 60 && set_at <= now() + 5);
        assert_eq!(
            shown["production"].as_object().unwrap().len(),
            2,
            "지문이나 길이를 싣지 않습니다: {shown}"
        );
        let text = listed.to_string();
        assert!(!text.contains(BANK));
        assert!(!text.contains(&sha(BANK)));
    }
}

// ---- 입력 표 ----

#[test]
fn 입력_표로_넣은_값이_운영의_앱에_닿는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let url = bench.entry(&instance, "production");

    let sent = send_entry(&url, &json!({ "value": BANK }));
    assert_eq!(sent.status, 200, "{}", sent.body);
    assert_eq!(
        sent.json(),
        json!({ "name": "BANK_API_KEY", "stage": "production" })
    );
    assert_eq!(sent.header("access-control-allow-origin"), Some("*"));

    let live = bench.ship_ok(&instance, &token);
    assert_eq!(
        secret_at(&live),
        json!({ "present": true, "sha256": sha(BANK) })
    );
}

#[test]
fn 입력_표는_한_번만_쓸_수_있다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let url = bench.entry(&instance, "production");
    assert_eq!(send_entry(&url, &json!({ "value": BANK })).status, 200);
    let again = send_entry(&url, &json!({ "value": "sk_live_attacker" }));
    assert_eq!(again.status, 410, "{}", again.body);
    assert_eq!(again.json()["error"], "gone");
    assert!(
        again.json()["message"]
            .as_str()
            .unwrap()
            .contains("이미 쓴")
    );

    let live = bench.ship_ok(&instance, &token);
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
}

#[test]
fn 입력_표는_십_분이_지나면_쓸_수_없다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);

    // 10분이 되는 때부터 쓰지 못한다
    let late = bench.entry(&instance, "production");
    bench.ahead.store(600, Ordering::SeqCst);
    let sent = send_entry(&late, &json!({ "value": BANK }));
    assert_eq!(sent.status, 410, "{}", sent.body);
    assert!(sent.json()["message"].as_str().unwrap().contains("만료"));
    assert_eq!(
        bank(&bench.list(FACTORY, &instance))["production"]["set"],
        false
    );

    // 그 1초 앞까지는 쓴다
    bench.ahead.store(0, Ordering::SeqCst);
    let fresh = bench.entry(&instance, "production");
    bench.ahead.store(599, Ordering::SeqCst);
    assert_eq!(send_entry(&fresh, &json!({ "value": BANK })).status, 200);
    assert_eq!(
        bank(&bench.list(FACTORY, &instance))["production"]["set"],
        true
    );
}

#[test]
fn 입력_표의_본문은_이름과_단계를_바꾸지_못한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let url = bench.entry(&instance, "preview");

    for (body, status) in [
        (json!({ "value": BANK, "stage": "production" }), 400),
        (json!({ "value": BANK, "name": "MAP_KEY" }), 400),
        (json!({ "value": BANK, "instance": "i0000000000" }), 422),
        (json!({ "value": BANK, "stage": "staging" }), 422),
    ] {
        let sent = send_entry(&url, &body);
        assert_eq!(sent.status, status, "{body}: {}", sent.body);
    }
    // 거절된 본문은 표를 쓰지 않았다. 표의 자리(프리뷰)에는 넣는다
    let sent = send_entry(
        &url,
        &json!({ "value": BANK_PREVIEW, "stage": "preview", "name": "BANK_API_KEY" }),
    );
    assert_eq!(sent.status, 200, "{}", sent.body);
    let shown = bank(&bench.list(FACTORY, &instance));
    assert_eq!(shown["preview"]["set"], true);
    assert_eq!(shown["production"]["set"], false);
}

#[test]
fn 입력_표의_주소는_쿠키와_키_없이_다른_출처의_요청을_받는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let url = bench.entry(&instance, "production");

    // 브라우저의 사전 요청
    let preflight = http(
        "OPTIONS",
        &url,
        &[
            ("Origin", CARD_ORIGIN),
            ("Access-Control-Request-Method", "POST"),
            ("Access-Control-Request-Headers", "content-type"),
        ],
        "",
    );
    assert_eq!(preflight.status, 204, "{}", preflight.body);
    assert_eq!(preflight.header("access-control-allow-origin"), Some("*"));
    assert!(
        preflight
            .header("access-control-allow-methods")
            .unwrap()
            .contains("POST")
    );
    assert!(
        preflight
            .header("access-control-allow-headers")
            .unwrap()
            .contains("content-type")
    );
    // 자격 증명은 열지 않는다
    assert_eq!(preflight.header("access-control-allow-credentials"), None);

    // 쿠키도 키도 없이, 또는 아무 쿠키와 아무 키를 실어도 표만 본다
    let sent = http(
        "POST",
        &url,
        &[
            ("Origin", CARD_ORIGIN),
            ("Content-Type", "application/json"),
            ("Cookie", "__Host-orbital-session=made-up"),
            ("Authorization", "Bearer orb1.made-up"),
        ],
        &json!({ "value": BANK }).to_string(),
    );
    assert_eq!(sent.status, 200, "{}", sent.body);
    assert_eq!(sent.header("access-control-allow-origin"), Some("*"));
    assert_eq!(sent.header("access-control-allow-credentials"), None);
    assert_eq!(sent.header("cache-control"), Some("no-store"));

    // 모르는 표는 없는 것으로 답하되 브라우저가 읽을 수 있게 연다
    let unknown = send_entry(
        &format!("{}/v1/secret-entries/{}", bench.public, "ab".repeat(32)),
        &json!({ "value": BANK }),
    );
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.header("access-control-allow-origin"), Some("*"));
    // 관리 API 의 다른 길은 열지 않는다
    let other = http(
        "GET",
        &format!("{}/v1/instances/{instance}/secrets", bench.public),
        &[
            ("Origin", CARD_ORIGIN),
            ("Authorization", &format!("Bearer {FACTORY}")),
        ],
        "",
    );
    assert_eq!(other.status, 200);
    assert_eq!(other.header("access-control-allow-origin"), None);
}

// ---- service key ----

#[test]
fn service_key_로_넣은_값이_운영의_앱에_닿는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    let (status, body) = bench.put(FACTORY, &instance, "production", BANK);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({ "name": "BANK_API_KEY", "stage": "production" })
    );
    let live = bench.ship_ok(&instance, &token);
    assert_eq!(
        secret_at(&live),
        json!({ "present": true, "sha256": sha(BANK) })
    );
}

// ---- 승격과 단계 ----

#[test]
fn 운영의_값이_없으면_승격하지_못하고_빠진_이름을_알려_준다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    let (preview, (requested, refusal), (promoted, denied)) = bench.ship(&instance, &token);
    let blockers = texts(&preview["blockers"]);
    assert_eq!(blockers.len(), 1, "{preview}");
    assert!(blockers[0].contains("`BANK_API_KEY`"), "{}", blockers[0]);
    assert!(
        blockers[0].contains("에이전트가 고칠 수 없는"),
        "{}",
        blockers[0]
    );
    assert_eq!(requested, 409, "{refusal}");
    assert_eq!(texts(&refusal["details"]), blockers);
    assert_eq!(promoted, 409, "{denied}");
    assert_eq!(texts(&denied["details"]), blockers);
    assert!(bench.production(&instance).is_null());

    // 사람이 운영의 값을 넣으면 오른다
    bench.put_ok(&instance, "production", BANK);
    bench.ship_ok(&instance, &token);
}

#[test]
fn 프리뷰의_값이_없어도_프리뷰는_서고_빠진_이름을_알려_준다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    let preview = bench.preview(&instance, &token);
    assert_eq!(preview["missing_secrets"], json!(["BANK_API_KEY"]));
    let origin = url(&preview);
    assert_eq!(
        secret_at(&origin),
        json!({ "present": false, "sha256": null })
    );
    // 앱의 환경에는 그 이름이 아예 없다
    let names = http("GET", &format!("{origin}/env"), &[], "").json();
    assert!(!texts(&names["names"]).contains(&"BANK_API_KEY".to_owned()));

    // 프리뷰의 값을 넣으면 다음 요청부터 그 값으로 깬다
    bench.put_ok(&instance, "preview", BANK_PREVIEW);
    assert_eq!(secret_at(&origin)["sha256"], sha(BANK_PREVIEW));
    assert_eq!(
        bench.preview(&instance, &token)["missing_secrets"],
        json!([])
    );
}

#[test]
fn 운영의_값은_프리뷰에_건네지지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    // 운영에 올린 뒤에도 프리뷰는 운영의 값을 받지 않는다
    let live = bench.ship_ok(&instance, &token);
    let preview = bench.preview(&instance, &token);
    assert_eq!(preview["missing_secrets"], json!(["BANK_API_KEY"]));
    assert_eq!(
        secret_at(&url(&preview)),
        json!({ "present": false, "sha256": null })
    );
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
}

#[test]
fn 프리뷰의_값은_운영에_건네지지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "preview", BANK_PREVIEW);
    // 프리뷰의 값이 있어도 운영의 칸을 대신하지 않는다
    let (preview, (requested, _), (promoted, _)) = bench.ship(&instance, &token);
    assert_eq!(preview["missing_secrets"], json!([]));
    assert_eq!(texts(&preview["blockers"]).len(), 1, "{preview}");
    assert_eq!((requested, promoted), (409, 409));

    bench.put_ok(&instance, "production", BANK);
    let live = bench.ship_ok(&instance, &token);
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
    let preview = bench.preview(&instance, &token);
    assert_eq!(secret_at(&url(&preview))["sha256"], sha(BANK_PREVIEW));
}

#[test]
fn 빌드와_마이그레이션에는_비밀을_건네지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "preview", BANK_PREVIEW);
    bench.put_ok(&instance, "production", BANK);
    let live = bench.ship_ok(&instance, &token);
    // 빌드는 비밀 없이 돌았다. 서버는 받았다
    let built = http("GET", &format!("{live}/build-env"), &[], "").json();
    let names = texts(&built["names"]);
    assert!(!names.is_empty(), "{built}");
    for name in ["BANK_API_KEY", "SESSION_KEY"] {
        assert!(!names.contains(&name.to_owned()), "{name}: {names:?}");
    }
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
    // 마이그레이션은 레이어가 SQL 로 돌린다. 그 기록과 레이어의 다른 기록(빌드 · 서버의 로그 포함)에 값이 없다
    let logs = everything_under(&bench.home.join("logs"));
    for value in [BANK, BANK_PREVIEW] {
        assert!(!logs.contains(value));
    }
    // 운영 DB 에 마이그레이션이 돌았다
    let mut config: postgres::Config = bench.pg_url.parse().unwrap();
    let mut client = config
        .dbname(&format!("i_{instance}"))
        .connect(postgres::NoTls)
        .unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM ledger.transfer", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[test]
fn 운영의_값을_바꾸면_다음_요청부터_새_값으로_깬다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    let live = bench.ship_ok(&instance, &token);
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));

    bench.put_ok(&instance, "production", "sk_live_bank_rotated_Yt5");
    assert_eq!(secret_at(&live)["sha256"], sha("sk_live_bank_rotated_Yt5"));
    // 입력 표로 바꿔도 같다
    let url = bench.entry(&instance, "production");
    assert_eq!(send_entry(&url, &json!({ "value": BANK })).status, 200);
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
}

#[test]
fn 운영이_쓰는_비밀은_지우지_못한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "preview", BANK_PREVIEW);
    bench.put_ok(&instance, "production", BANK);
    let live = bench.ship_ok(&instance, &token);
    let path = format!("/v1/instances/{instance}/secrets/BANK_API_KEY");

    let (status, body) = bench.call("DELETE", &format!("{path}?stage=production"), FACTORY, &[]);
    assert_eq!(status, 409, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("[secrets] external"), "{message}");
    assert!(message.contains("새 값을 넣어"), "{message}");
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
    // 단계를 적지 않으면 무엇을 지울지 묻는다
    assert_eq!(bench.call("DELETE", &path, FACTORY, &[]).0, 422);
    // 프리뷰의 값은 지운다
    let (status, body) = bench.call("DELETE", &format!("{path}?stage=preview"), FACTORY, &[]);
    assert_eq!((status, body), (200, json!({ "removed": true })));
    let shown = bank(&bench.list(FACTORY, &instance));
    assert_eq!(shown["preview"], json!({ "set": false }));
    assert_eq!(shown["production"]["set"], true);
}

// ---- 금고 ----

#[test]
fn 관리_서버가_다시_떠도_운영의_앱이_비밀을_받는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    bench.ship_ok(&instance, &token);

    bench.restart(Some(SealKey::from_bytes(SEAL)));
    let live = url(&bench.production(&instance));
    assert_eq!(
        secret_at(&live),
        json!({ "present": true, "sha256": sha(BANK) })
    );
}

#[test]
fn 봉인_열쇠가_없으면_값을_넣지_못하고_무엇을_고칠지_알려_준다() {
    let mut bench = bench!(None);
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);

    let (status, body) = bench.put(FACTORY, &instance, "production", BANK);
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("ORBITAL_SEAL_KEY")
    );
    assert!(!body.to_string().contains(BANK));
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/entries"),
        FACTORY,
        &json!({ "stage": "production" }),
    );
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("ORBITAL_SEAL_KEY")
    );
    // 밖에서 넣는 비밀을 선언한 release 는 운영에 오르지 못한다
    let (_, (requested, _), (promoted, _)) = bench.ship(&instance, &token);
    assert_eq!((requested, promoted), (409, 409));
    assert!(!everything_under(&bench.home).contains(BANK));
}

#[test]
fn 금고의_파일에는_값이_평문으로_남지_않고_주인만_읽는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "preview", BANK_PREVIEW);
    bench.put_ok(&instance, "production", BANK);
    bench.ship_ok(&instance, &token);

    let vault = bench.home.join(VAULT);
    let record = fs::read_to_string(&vault).unwrap();
    assert!(record.contains("seal1."), "{record}");
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let everything = everything_under(&bench.home);
    for value in [BANK, BANK_PREVIEW] {
        assert!(!everything.contains(value));
        assert!(!everything.contains(&hex(value.as_bytes())));
        assert!(!everything.contains(&sha(value)));
    }
}

#[test]
fn 봉인된_값을_다른_인스턴스의_자리에_옮겨_심으면_열리지_않는다() {
    let mut bench = bench!();
    let mine = bench.instance(FACTORY);
    let theirs = bench.instance(FACTORY);
    for instance in [&mine, &theirs] {
        let token = bench.token(FACTORY, instance, &ALL);
        bench.preview(instance, &token);
    }
    bench.put_ok(&mine, "production", BANK);

    // 기록을 가져간 쪽이 봉인된 글을 다른 인스턴스와 다른 단계의 자리에 옮겨 심는다
    let server = bench.shut();
    let vault = bench.home.join(VAULT);
    let mut record: Value = serde_json::from_str(&fs::read_to_string(&vault).unwrap()).unwrap();
    let sealed = record["values"][&mine]["BANK_API_KEY"]["production"].clone();
    assert!(sealed["sealed"].as_str().unwrap().starts_with("seal1."));
    record["values"][&theirs] =
        json!({ "BANK_API_KEY": { "production": sealed, "preview": sealed } });
    record["values"][&mine]["BANK_API_KEY"]["preview"] = sealed;
    fs::write(&vault, record.to_string()).unwrap();
    bench.open(Some(SealKey::from_bytes(SEAL)), server);

    let moved = bank(&bench.list(FACTORY, &theirs));
    assert_eq!(moved["production"], json!({ "set": false }));
    assert_eq!(moved["preview"], json!({ "set": false }));
    let shown = bank(&bench.list(FACTORY, &mine));
    assert_eq!(shown["preview"], json!({ "set": false }));
    assert_eq!(shown["production"]["set"], true);
    // 옮겨 심은 값으로는 운영에 오르지 못한다
    let token = bench.token(FACTORY, &theirs, &ALL);
    let (preview, _, (promoted, _)) = bench.ship(&theirs, &token);
    assert_eq!(promoted, 409);
    assert_eq!(secret_at(&url(&preview))["present"], false);
}

#[test]
fn 인스턴스를_지우면_그_비밀도_지워진다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    let (status, _) = bench.post(
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/request"),
        &token,
        &json!({ "reason": "송금" }),
    );
    assert_eq!(status, 200);
    let url = bench.entry(&instance, "preview");
    assert!(
        fs::read_to_string(bench.home.join(VAULT))
            .unwrap()
            .contains(&instance)
    );

    let (status, body) = bench.call("DELETE", &format!("/v1/instances/{instance}"), FACTORY, &[]);
    assert_eq!(status, 200, "{body}");
    bench.instances.clear();
    assert!(
        !fs::read_to_string(bench.home.join(VAULT))
            .unwrap()
            .contains(&instance)
    );
    // 남은 입력 표로도 넣지 못한다
    assert_eq!(send_entry(&url, &json!({ "value": BANK })).status, 404);
}

#[test]
fn 다른_팩토리의_인스턴스에는_비밀을_넣지도_보지도_못한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    let stranger_instance = bench.instance(OTHER_FACTORY);
    let stranger_token = bench.token(OTHER_FACTORY, &stranger_instance, &ALL);

    let path = format!("/v1/instances/{instance}/secrets");
    let put = json!({ "stage": "production", "value": "sk_live_stranger" }).to_string();
    let entry = json!({ "stage": "production" }).to_string();
    let request = json!({ "reason": "남의 것" }).to_string();
    for bearer in [OTHER_FACTORY, stranger_token.as_str()] {
        for (method, tail, body) in [
            ("GET", "", ""),
            ("PUT", "/BANK_API_KEY", put.as_str()),
            ("DELETE", "/BANK_API_KEY?stage=production", ""),
            ("POST", "/BANK_API_KEY/entries", entry.as_str()),
            ("POST", "/BANK_API_KEY/request", request.as_str()),
        ] {
            let (status, answer) =
                bench.call(method, &format!("{path}{tail}"), bearer, body.as_bytes());
            assert_eq!(status, 404, "{method} {tail}: {answer}");
            assert_eq!(answer["error"], "not_found");
        }
    }
    // 아무것도 바뀌지 않았다
    let shown = bank(&bench.list(FACTORY, &instance));
    assert_eq!(shown["production"]["set"], true);
    assert!(shown.get("requested").is_none(), "{shown}");
    let live = bench.ship_ok(&instance, &token);
    assert_eq!(secret_at(&live)["sha256"], sha(BANK));
}

#[test]
fn 값은_어떤_답과_로그와_오류에도_실리지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    let mut replies: Vec<String> = Vec::new();
    replies.push(bench.preview(&instance, &token).to_string());
    let path = format!("/v1/instances/{instance}/secrets/BANK_API_KEY");

    // 틀린 본문의 오류에도 값이 실리지 않는다
    for wrong in [
        json!({ "stage": "staging", "value": BANK }).to_string(),
        json!({ "value": BANK }).to_string(),
        json!({ "stage": "production", "value": BANK, "extra": BANK }).to_string(),
        json!({ "stage": "production", "value": format!("{BANK}\u{0}") }).to_string(),
        json!({ "stage": "production", "value": format!("{BANK}{}", "x".repeat(70_000)) })
            .to_string(),
        format!("{{\"stage\": \"production\", \"value\": \"{BANK}"),
        format!("{{\"stage\": \"production\", \"value\": {BANK}}}"),
        // 값을 다른 칸에 잘못 넣어도 JSON 의 오류 문구가 그것을 되풀이하지 않는다
        json!({ "stage": BANK, "value": "x" }).to_string(),
        json!({ "stage": "production", "value": "x", BANK: true }).to_string(),
    ] {
        let (status, body) = bench.call("PUT", &path, FACTORY, wrong.as_bytes());
        assert_eq!(status, 422, "{body}");
        replies.push(body.to_string());
    }
    let ticket = bench.entry(&instance, "production");
    for wrong in [
        json!({ "value": BANK, "stage": "preview" }),
        json!({ "value": format!("{BANK}\u{0}") }),
        json!({ "value": BANK, "other": BANK }),
        json!({ "value": "x", "stage": BANK }),
        json!({ "value": "x", "name": BANK }),
        json!({ "value": "x", BANK: 1 }),
    ] {
        let sent = send_entry(&ticket, &wrong);
        assert!(sent.status >= 400, "{}", sent.body);
        replies.push(sent.body);
    }
    let sent = http(
        "POST",
        &ticket,
        &[("Content-Type", "application/json")],
        &format!("{{\"value\": \"{BANK}"),
    );
    assert_eq!(sent.status, 422);
    replies.push(sent.body);

    // 넣고, 올리고, 바꾸고, 지우지 못하는 길을 지난다
    let sent = send_entry(&ticket, &json!({ "value": BANK }));
    assert_eq!(sent.status, 200);
    replies.push(sent.body);
    let (status, body) = bench.put(FACTORY, &instance, "preview", BANK_PREVIEW);
    assert_eq!(status, 200);
    replies.push(body.to_string());
    let (preview, requested, promoted) = bench.ship(&instance, &token);
    assert_eq!(promoted.0, 200, "{}", promoted.1);
    replies.extend([
        preview.to_string(),
        requested.1.to_string(),
        promoted.1.to_string(),
    ]);
    replies.push(bench.list(FACTORY, &instance).to_string());
    replies.push(bench.list(&token, &instance).to_string());
    replies.push(bench.production(&instance).to_string());
    replies.push(
        bench
            .call("DELETE", &format!("{path}?stage=production"), FACTORY, &[])
            .1
            .to_string(),
    );
    let live = url(&promoted.1);
    replies.push(http("GET", &format!("{live}/secret"), &[], "").body);

    let all = format!("{}\n{}", replies.join("\n"), everything_under(&bench.home));
    for value in [BANK, BANK_PREVIEW] {
        assert!(!all.contains(value), "`{value}` 가 새었습니다");
        assert!(
            !all.contains(&hex(value.as_bytes())),
            "`{value}` 의 hex 가 새었습니다"
        );
    }
}

// ---- 승인 카드와 되돌리기 ----

#[test]
fn 기다리는_release_는_새로_받게_되는_비밀의_이름을_알려_준다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    let pending = |bench: &Bench| {
        bench
            .call(
                "GET",
                &format!("/v1/instances/{instance}/promotion-request"),
                FACTORY,
                &[],
            )
            .1
    };
    let ask = |bench: &Bench| {
        let preview = bench.preview(&instance, &token);
        let (status, body) = bench.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            &token,
            &json!({ "release": preview["release"] }),
        );
        assert_eq!(status, 200, "{body}");
        preview["release"].as_str().unwrap().to_owned()
    };

    // 첫 운영: 선언한 비밀이 모두 새로 받는 것이다
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    let first = ask(&bench);
    assert_eq!(pending(&bench)["new_secrets"], json!(["BANK_API_KEY"]));
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/promotions"),
        FACTORY,
        &json!({ "release": first, "change": "customer_request", "approved_by": "customer" }),
    );
    assert_eq!(status, 200, "{body}");

    // 비밀을 하나 더 선언한 변경은 그 이름만 새로 받는다
    bench.change(&instance, &token, &|work: &Path| {
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        fs::write(
            work.join("orbital.toml"),
            manifest.replace(
                "external = [\"BANK_API_KEY\"]",
                "external = [\"BANK_API_KEY\", \"MAP_KEY\"]",
            ),
        )
        .unwrap();
    });
    bench.preview(&instance, &token);
    let (status, body) = bench.call(
        "PUT",
        &format!("/v1/instances/{instance}/secrets/MAP_KEY"),
        FACTORY,
        json!({ "stage": "production", "value": "map_live_key" })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    ask(&bench);
    assert_eq!(pending(&bench)["new_secrets"], json!(["MAP_KEY"]));
}

#[test]
fn 되돌릴_release_의_비밀이_빠져_있으면_되돌리지_못한다() {
    let mut bench = bench!();
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance, &ALL);
    // 앞의 release 는 비밀 둘을 쓴다
    bench.change(&instance, &token, &|work: &Path| {
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        fs::write(
            work.join("orbital.toml"),
            manifest.replace(
                "external = [\"BANK_API_KEY\"]",
                "external = [\"BANK_API_KEY\", \"LEGACY_KEY\"]",
            ),
        )
        .unwrap();
    });
    bench.preview(&instance, &token);
    bench.put_ok(&instance, "production", BANK);
    let (status, body) = bench.call(
        "PUT",
        &format!("/v1/instances/{instance}/secrets/LEGACY_KEY"),
        FACTORY,
        json!({ "stage": "production", "value": "legacy_live_key" })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    bench.ship_ok(&instance, &token);

    // 레이어의 운영자가 봉인의 열쇠를 바꿨고 팩토리는 새 release 가 쓰는 값만 다시 넣었다. 앞의 release 의 `LEGACY_KEY` 는 풀리지 않는다
    bench.restart(Some(SealKey::from_bytes([9; 32])));
    bench.put_ok(&instance, "production", BANK);
    // 새 release 는 `LEGACY_KEY` 를 쓰지 않고, 운영에서만 뜨지 않는다
    bench.change(&instance, &token, &|work: &Path| {
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        fs::write(
            work.join("orbital.toml"),
            manifest.replace(
                "external = [\"BANK_API_KEY\", \"LEGACY_KEY\"]",
                "external = [\"BANK_API_KEY\"]",
            ),
        )
        .unwrap();
        let server = fs::read_to_string(work.join("server.js")).unwrap();
        fs::write(
            work.join("server.js"),
            format!("if (process.env.ORBITAL_STAGE === \"production\") process.exit(1);\n{server}"),
        )
        .unwrap();
    });
    let (_, (requested, body), (promoted, refusal)) = bench.ship(&instance, &token);
    assert_eq!(requested, 200, "{body}");
    assert_eq!(promoted, 409, "{refusal}");
    let message = refusal["message"].as_str().unwrap();
    assert!(message.contains("`LEGACY_KEY`"), "{message}");
    assert!(message.contains("되돌리지도 못했습니다"), "{message}");
    // 값 없이 앞의 release 를 띄우지 않았다
    assert!(bench.production(&instance).is_null());
}
