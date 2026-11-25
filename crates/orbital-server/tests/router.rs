//! router 가 서비스를 재우고 깨우는 것과, 레이어가 주소 하나에서 인스턴스마다의 하위 도메인으로 요청을 가르는 것을 실제로 돈다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버), 실제 HTTP 로 잰다. 앱의 프로세스는 개발용 실행기를 감싼 실행기가 띄우고,
//! 몇 번 띄웠는지와 지금 몇 개가 떠 있는지를 센다. 하위 도메인은 `127.0.0.1` 의 한 포트에 `Host` 머리말을 실어 잰다(기준 도메인 `orbital.test`).
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 띄운 router 와 앱은 레이어가 인스턴스를 걷을 때 함께 내린다.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use orbital_core::host::{BaseDomain, Scheme};
use orbital_router::{Mail, Outbox};
use orbital_run::{Job, LocalRunner, RunError, Runner, Running};
use orbital_server::http::handle;
use orbital_server::layer::{Hosting, Layer, OUTBOX, Options};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const ORGANIZATION: &str = "factory";
const BASE: &str = "orbital.test";
/// 테스트에서 재우기까지 기다리는 시간. 실제 기본값은 5분이다.
const SLEEP_AFTER: Duration = Duration::from_millis(400);

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn git(folder: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(folder)
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

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// 조건이 참이 될 때까지 기다린다. 참이 되면 `true` 다.
fn eventually(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    loop {
        if check() {
            return true;
        }
        if started.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---- 손으로 짠 HTTP ----

struct Reply {
    status: u16,
    /// 이름은 소문자다.
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn set_cookie(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .map(|(_, value)| value.as_str())
            .find(|value| value.starts_with(&format!("{name}=")))
    }

    /// `Set-Cookie` 가운데 이 이름의 것을 `이름=값` 으로.
    fn cookie(&self, name: &str) -> String {
        self.set_cookie(name)
            .and_then(|cookie| cookie.split(';').next())
            .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다: {:?}", self.headers))
            .to_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    fn everything(&self) -> String {
        let mut text = format!("{}\n", self.status);
        for (key, value) in &self.headers {
            text.push_str(&format!("{key}: {value}\n"));
        }
        text.push_str(&self.body);
        text
    }
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let Some(end) = rest.windows(2).position(|pair| pair == b"\r\n") else {
            return out;
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&rest[..end])
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .unwrap_or(0);
        if size == 0 {
            return out;
        }
        let start = end + 2;
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size + 2..];
    }
}

/// `address`(`127.0.0.1:포트`)에 요청 하나를 보낸다. `host` 가 `None` 이면 `Host` 머리말을 싣지 않는다.
fn send(
    address: &str,
    host: Option<&str>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    if let Some(host) = host {
        request.push_str(&format!("Host: {host}\r\n"));
    }
    request.push_str("Connection: close\r\n");
    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("답의 머리가 끝나지 않았습니다");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .iter()
        .any(|(key, value)| key == "transfer-encoding" && value.contains("chunked"))
    {
        body = dechunk(&body);
    }
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

const JSON: (&str, &str) = ("Accept", "application/json");

// ---- 세는 실행기 ----

/// 앱의 프로세스를 몇 번 띄웠는지, 지금 몇 개가 떠 있는지, 다음에 띄울 때 어떻게 망가뜨릴지.
#[derive(Default)]
struct Probe {
    starts: AtomicUsize,
    live: Arc<AtomicUsize>,
    /// 띄울 때 건넨 포트. 마지막 것이 지금(또는 마지막으로) 떠 있던 서버의 포트다.
    ports: Mutex<Vec<u16>>,
    sabotage: Mutex<Vec<Sabotage>>,
}

#[derive(Debug, Clone, Copy)]
enum Sabotage {
    /// 실행기가 시작하지 못한다.
    Refuse,
    /// 프로세스는 뜨지만 포트를 열지 않는다.
    NeverListen,
}

impl Probe {
    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn last_port(&self) -> u16 {
        *self.ports.lock().unwrap().last().unwrap()
    }
}

struct CountingRunner {
    inner: LocalRunner,
    probe: Arc<Probe>,
}

struct Counted {
    inner: Box<dyn Running>,
    live: Arc<AtomicUsize>,
    stopped: bool,
}

impl Counted {
    fn forget(&mut self) {
        if !self.stopped {
            self.stopped = true;
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Running for Counted {
    fn alive(&mut self) -> bool {
        self.inner.alive()
    }

    fn stop(&mut self) {
        self.inner.stop();
        self.forget();
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.inner.stop();
        self.forget();
    }
}

impl Runner for CountingRunner {
    fn build(&self, job: &Job<'_>) -> Result<(), RunError> {
        self.inner.build(job)
    }

    fn start(&self, job: &Job<'_>) -> Result<Box<dyn Running>, RunError> {
        self.probe.starts.fetch_add(1, Ordering::SeqCst);
        if let Some(port) = job
            .env
            .iter()
            .find(|(key, _)| key == "PORT")
            .and_then(|(_, value)| value.parse().ok())
        {
            self.probe.ports.lock().unwrap().push(port);
        }
        let sabotage = {
            let mut queued = self.probe.sabotage.lock().unwrap();
            (!queued.is_empty()).then(|| queued.remove(0))
        };
        let inner = match sabotage {
            Some(Sabotage::Refuse) => return Err(RunError::Spawn),
            Some(Sabotage::NeverListen) => self.inner.start(&Job {
                command: "sleep 30",
                ..*job
            })?,
            None => self.inner.start(job)?,
        };
        self.probe.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Counted {
            inner,
            live: Arc::clone(&self.probe.live),
            stopped: false,
        }))
    }
}

// ---- 레이어 ----

struct Bench {
    home: PathBuf,
    scratch: PathBuf,
    pg_url: String,
    hosts: bool,
    probe: Arc<Probe>,
    layer: Option<Layer>,
    instances: Vec<String>,
}

impl Bench {
    /// `hosts` 면 기준 도메인 `orbital.test` 로 하위 도메인을 쓰는 레이어, 아니면 인스턴스마다 포트 하나를 내는 레이어다.
    fn new(hosts: bool) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-router-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&scratch).unwrap();
        let mut bench = Self {
            home: scratch.join("home"),
            scratch,
            pg_url,
            hosts,
            probe: Arc::new(Probe::default()),
            layer: None,
            instances: Vec::new(),
        };
        bench.open();
        bench.upload("cards", &|folder: &Path| {
            copy_tree(&fixture("todo"), folder);
            copy_tree(&fixture("cards"), folder);
        });
        bench.upload("mcp", &|folder: &Path| {
            copy_tree(&fixture("todo"), folder);
            copy_tree(&fixture("mcp"), folder);
        });
        Some(bench)
    }

    /// 같은 기록(`home`)으로 레이어를 연다. 실행기는 새로 센다.
    fn open(&mut self) {
        self.probe = Arc::new(Probe::default());
        let runner = CountingRunner {
            inner: LocalRunner::default(),
            probe: Arc::clone(&self.probe),
        };
        let hosting = self.hosts.then(|| Hosting {
            listen: "127.0.0.1:0".to_owned(),
            base: BaseDomain::parse(BASE).unwrap(),
            scheme: Scheme::Http,
        });
        let layer = Layer::open(Options {
            dev_mailbox: true,
            sleep_after: SLEEP_AFTER,
            wake_timeout: Duration::from_secs(5),
            hosting,
            ..Options::new(
                self.home.clone(),
                self.pg_url.clone(),
                vec![(FACTORY.to_owned(), ORGANIZATION.to_owned())],
                Box::new(runner),
            )
        })
        .expect("레이어를 열지 못했습니다");
        self.layer = Some(layer);
    }

    /// 관리 서버가 내려갔다가 다시 뜬 것처럼 한다. 앞의 레이어가 띄운 것은 모두 내려간다.
    fn restart(&mut self) {
        drop(self.layer.take());
        self.open();
    }

    fn layer(&self) -> &Layer {
        self.layer.as_ref().unwrap()
    }

    fn upload(&self, app: &str, prepare: &dyn Fn(&Path)) {
        let folder = self.scratch.join(format!("scaffold-{app}"));
        prepare(&folder);
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{app}.bundle"));
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
            "PUT",
            &format!("/v1/apps/{app}"),
            FACTORY,
            &fs::read(bundle).unwrap(),
        );
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

    fn instance(&mut self, app: &str) -> String {
        let (status, body) = self.post(
            "/v1/instances",
            FACTORY,
            &json!({ "app": app, "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push(instance.clone());
        instance
    }

    fn token(&self, instance: &str) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/sessions"),
            FACTORY,
            &json!({ "can": ["source", "preview", "rehearse"] }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 미리보기를 세운다. 그 주소와 release 를 돌려준다.
    fn preview(&self, instance: &str, token: &str) -> (String, String) {
        let (status, preview) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        (
            preview["services"][0]["url"].as_str().unwrap().to_owned(),
            preview["release"].as_str().unwrap().to_owned(),
        )
    }

    /// 미리보기 → 승격 요청 → 고객의 승인 → 운영. (인스턴스, 미리보기의 주소, 운영의 주소).
    fn ship_with_preview(&mut self, app: &str) -> (String, String, String) {
        let instance = self.instance(app);
        let token = self.token(&instance);
        let (preview, release) = self.preview(&instance, &token);
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            &token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let (status, production) = self.post(
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        assert_eq!(status, 200, "{production}");
        let live = production["services"][0]["url"]
            .as_str()
            .unwrap()
            .to_owned();
        (instance, preview, live)
    }

    fn ship(&mut self, app: &str) -> (String, String) {
        let (instance, _, live) = self.ship_with_preview(app);
        (instance, live)
    }

    /// 운영의 주소. 팩토리의 서버가 읽는 길로 읽는다.
    fn production_url(&self, instance: &str) -> String {
        let (status, body) = self.call(
            "GET",
            &format!("/v1/instances/{instance}/production"),
            FACTORY,
            &[],
        );
        assert_eq!(status, 200, "{body}");
        body["services"][0]["url"].as_str().unwrap().to_owned()
    }

    fn invite(&self, instance: &str, email: &str) {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/users"),
            FACTORY,
            &json!({ "email": email, "roles": ["member"] }),
        );
        assert_eq!(status, 200, "{body}");
    }

    /// 하위 도메인을 쓰는 레이어가 듣는 주소.
    fn router(&self) -> String {
        self.layer()
            .router_address()
            .expect("하위 도메인을 쓰는 레이어인데 듣는 주소가 없습니다")
            .to_string()
    }

    /// 주소(origin)로 요청한다. 하위 도메인이면 레이어가 듣는 주소에 그 호스트를 싣는다.
    fn http(
        &self,
        method: &str,
        origin: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let host = origin.trim_start_matches("http://");
        let address = if host.ends_with(BASE) {
            self.router()
        } else {
            host.to_owned()
        };
        send(&address, Some(host), method, path, headers, body)
    }

    fn mails_to(&self, email: &str) -> Vec<Mail> {
        Outbox::read(&self.home.join(OUTBOX))
            .into_iter()
            .filter(|mail| mail.to == email)
            .collect()
    }

    /// 링크를 요청하고, 메일함에 링크가 오면 같은 브라우저로 연다. 세션 쿠키(`이름=값`)와 링크를 돌려준다.
    fn sign_in(&self, origin: &str, email: &str) -> (String, String) {
        let before = self.mails_to(email).len();
        let asked = self.http(
            "POST",
            origin,
            "/_orbital/auth/email-link",
            &[("Origin", origin), ("Content-Type", "application/json")],
            &json!({ "email": email, "next": "/cards" }).to_string(),
        );
        assert_eq!(asked.status, 202, "{}", asked.everything());
        let browser = asked.cookie("__Host-orbital-browser");
        assert!(
            eventually(Duration::from_secs(10), || self.mails_to(email).len()
                > before),
            "메일함에 링크가 오지 않았습니다"
        );
        let link = self.mails_to(email).pop().unwrap().link;
        let path = link
            .strip_prefix(origin)
            .unwrap_or_else(|| panic!("링크가 이 주소({origin})가 아닙니다: {link}"))
            .to_owned();
        let opened = self.http("GET", origin, &path, &[("Cookie", &browser)], "");
        assert_eq!(opened.status, 302, "{}", opened.everything());
        (opened.cookie("__Host-orbital-session"), link)
    }

    fn me(&self, origin: &str, cookie: &str) -> Reply {
        self.http(
            "GET",
            origin,
            "/_orbital/auth/me",
            &[("Cookie", cookie), JSON],
            "",
        )
    }

    fn cards(&self, origin: &str, cookie: &str) -> Reply {
        self.http("GET", origin, "/cards", &[("Cookie", cookie), JSON], "")
    }

    fn database_exists(&self, name: &str) -> bool {
        let mut client = postgres::Client::connect(&self.pg_url, postgres::NoTls).unwrap();
        client
            .query_one(
                "SELECT count(*) FROM pg_database WHERE datname = $1",
                &[&name],
            )
            .unwrap()
            .get::<_, i64>(0)
            == 1
    }

    /// 앱의 프로세스가 모두 내려갈 때까지 기다린다.
    fn wait_asleep(&self) {
        assert!(
            eventually(Duration::from_secs(10), || self.probe.live() == 0),
            "정한 시간이 지나도 서비스가 자지 않습니다(떠 있는 것 {})",
            self.probe.live()
        );
    }

    /// 레이어가 남긴 기록을 모두 읽는다.
    fn logs(&self) -> String {
        fn walk(folder: &Path, text: &mut String) {
            let Ok(entries) = fs::read_dir(folder) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, text);
                } else {
                    text.push_str(&String::from_utf8_lossy(
                        &fs::read(&path).unwrap_or_default(),
                    ));
                }
            }
        }
        let mut text = String::new();
        walk(&self.home.join("logs"), &mut text);
        text
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        if self.layer.is_some() {
            for instance in &self.instances {
                let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), FACTORY, &[]);
            }
        }
        drop(self.layer.take());
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    ($hosts:expr) => {
        match Bench::new($hosts) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn titles(reply: &Reply) -> Vec<String> {
    reply
        .json()
        .as_array()
        .unwrap_or_else(|| panic!("{}", reply.everything()))
        .iter()
        .map(|card| card["title"].as_str().unwrap().to_owned())
        .collect()
}

// ---- 재우고 깨우기 ----

#[test]
fn 쉬는_서비스는_프로세스가_없고_첫_요청에_깨어_답한다() {
    let mut bench = bench!(false);
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let (kim, _) = bench.sign_in(&live, "kim@example.com");
    // 승격은 새 release 의 서버가 실제로 뜨는 것을 보고 끝났다
    let started = bench.probe.starts();
    assert!(started >= 1);
    let port = bench.probe.last_port();

    bench.wait_asleep();
    assert!(!listening(port), "재운 서버의 포트가 아직 열려 있습니다");

    let cards = bench.cards(&live, &kim);
    assert_eq!(cards.status, 200, "{}", cards.everything());
    assert_eq!(bench.probe.starts(), started + 1);
    assert_eq!(bench.probe.live(), 1);
    assert!(listening(bench.probe.last_port()));
}

#[test]
fn 요청이_오는_동안에는_재우지_않는다() {
    let mut bench = bench!(false);
    // 로그인 없이도 열리는 서비스(auth 의 기본은 optional)
    let (_, live) = bench.ship("mcp");
    let started = bench.probe.starts();
    // 재우는 시간보다 오래, 그보다 짧은 간격으로 요청이 온다
    let until = Instant::now() + SLEEP_AFTER * 4;
    while Instant::now() < until {
        let page = bench.http("GET", &live, "/login", &[], "");
        assert_eq!(page.status, 200, "{}", page.everything());
        std::thread::sleep(SLEEP_AFTER / 4);
    }
    assert_eq!(bench.probe.starts(), started);
    assert_eq!(bench.probe.live(), 1);

    // 답의 머리를 보낸 뒤 본문을 재우는 시간보다 오래 끄는 요청. 처리 중인 동안에는 재우지 않는다
    let slow = bench.http("GET", &live, "/slow?ms=1500", &[], "");
    assert_eq!(slow.status, 200, "{}", slow.everything());
    assert_eq!(slow.body, "처음끝");
    assert_eq!(bench.probe.starts(), started);
    // 요청이 그친 뒤에는 잔다
    bench.wait_asleep();
}

#[test]
fn 동시에_온_첫_요청들은_서비스를_한_번만_깨운다() {
    let mut bench = bench!(false);
    let (_, live) = bench.ship("cards");
    bench.wait_asleep();
    let started = bench.probe.starts();
    let barrier = Barrier::new(8);
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    bench.http("GET", &live, "/login", &[], "").status
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    assert_eq!(statuses, vec![200; 8]);
    assert_eq!(bench.probe.starts(), started + 1);
    assert_eq!(bench.probe.live(), 1);
}

#[test]
fn 깨우지_못하면_503_으로_답하고_다음_요청에_다시_깨운다() {
    let mut bench = bench!(false);
    let (_, live) = bench.ship("cards");
    bench.wait_asleep();
    let started = bench.probe.starts();
    // 실행기가 시작하지 못하는 때와, 떠도 포트를 열지 않아 시간을 넘기는 때
    bench
        .probe
        .sabotage
        .lock()
        .unwrap()
        .extend([Sabotage::Refuse, Sabotage::NeverListen]);
    for attempt in 1..=2 {
        let failed = bench.http("GET", &live, "/login", &[], "");
        assert_eq!(failed.status, 503, "{}", failed.everything());
        assert!(
            failed
                .header("retry-after")
                .is_some_and(|seconds| seconds.parse::<u64>().is_ok()),
            "{}",
            failed.everything()
        );
        assert_eq!(bench.probe.starts(), started + attempt);
        // 깨우다 만 프로세스는 남기지 않는다
        assert!(eventually(Duration::from_secs(5), || bench.probe.live() == 0));
    }
    let woke = bench.http("GET", &live, "/login", &[], "");
    assert_eq!(woke.status, 200, "{}", woke.everything());
    assert_eq!(bench.probe.starts(), started + 3);
    // 기록에는 서비스의 이름과 갈래만 있다
    let logs = bench.logs();
    assert!(logs.contains("WAKE web refused"), "{logs}");
    assert!(logs.contains("WAKE web timed_out"), "{logs}");
}

#[test]
fn 재운_뒤에도_세션과_데이터는_그대로다() {
    let mut bench = bench!(false);
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let (kim, _) = bench.sign_in(&live, "kim@example.com");
    let made = bench.http(
        "POST",
        &live,
        "/cards",
        &[("Cookie", &kim), JSON],
        "자기 전의 일",
    );
    assert_eq!(made.status, 201, "{}", made.everything());
    bench.wait_asleep();
    assert_eq!(bench.me(&live, &kim).json()["email"], "kim@example.com");
    assert_eq!(titles(&bench.cards(&live, &kim)), vec!["자기 전의 일"]);
}

#[test]
fn 관리_서버가_다시_떠도_운영은_첫_요청에_깬다() {
    let mut bench = bench!(false);
    let (instance, live, preview) = {
        let (instance, preview, live) = bench.ship_with_preview("cards");
        (instance, live, preview)
    };
    bench.invite(&instance, "kim@example.com");
    let (kim, _) = bench.sign_in(&live, "kim@example.com");
    let made = bench.http(
        "POST",
        &live,
        "/cards",
        &[("Cookie", &kim), JSON],
        "다시 뜨기 전의 일",
    );
    assert_eq!(made.status, 201, "{}", made.everything());

    let preview_database = {
        let registry: Value =
            serde_json::from_slice(&fs::read(bench.home.join("registry.json")).unwrap()).unwrap();
        format!(
            "i_{}",
            registry["instances"][&instance]["preview"]
                .as_str()
                .unwrap()
        )
    };
    assert!(bench.database_exists(&preview_database));

    bench.restart();
    // 미리보기는 되살리지 않고, 앞의 레이어가 세운 미리보기의 database 는 걷는다
    assert!(!bench.database_exists(&preview_database));
    // 다시 뜬 레이어는 운영의 router 를 자는 채로 세운다. 앱의 프로세스는 아직 없다
    assert_eq!(bench.probe.starts(), 0);
    let again = bench.production_url(&instance);
    assert_eq!(bench.probe.starts(), 0);
    let cards = bench.cards(&again, &kim);
    assert_eq!(cards.status, 200, "{}", cards.everything());
    assert_eq!(titles(&cards), vec!["다시 뜨기 전의 일"]);
    assert_eq!(bench.probe.starts(), 1);
    // 미리보기는 되살리지 않는다. 다시 세우면 된다
    let preview_port: u16 = preview.rsplit(':').next().unwrap().parse().unwrap();
    assert!(!listening(preview_port), "미리보기가 되살아났습니다");
}

// ---- 하위 도메인 ----

#[test]
fn 인스턴스의_하위_도메인으로_온_요청은_그_인스턴스의_운영으로_간다() {
    let mut bench = bench!(true);
    let (ours, ours_live) = bench.ship("cards");
    let (theirs, theirs_live) = bench.ship("cards");
    assert_eq!(ours_live, format!("http://{ours}.{BASE}"));
    assert_eq!(theirs_live, format!("http://{theirs}.{BASE}"));
    bench.invite(&ours, "kim@example.com");
    bench.invite(&theirs, "kim@example.com");
    let (kim, _) = bench.sign_in(&ours_live, "kim@example.com");
    let (kim_there, _) = bench.sign_in(&theirs_live, "kim@example.com");
    let made = bench.http(
        "POST",
        &ours_live,
        "/cards",
        &[("Cookie", &kim), JSON],
        "우리 쪽의 일",
    );
    assert_eq!(made.status, 201, "{}", made.everything());
    assert_eq!(titles(&bench.cards(&ours_live, &kim)), vec!["우리 쪽의 일"]);
    assert!(titles(&bench.cards(&theirs_live, &kim_there)).is_empty());
    // 팩토리의 서버가 읽는 운영의 주소도 하위 도메인이다
    assert_eq!(bench.production_url(&ours), ours_live);
}

#[test]
fn 미리보기는_운영과_다른_하위_도메인으로_가고_쿠키를_나누지_않는다() {
    let mut bench = bench!(true);
    let (instance, preview, live) = bench.ship_with_preview("cards");
    assert_eq!(preview, format!("http://{instance}-preview.{BASE}"));
    assert_eq!(live, format!("http://{instance}.{BASE}"));
    let entered = bench.http(
        "POST",
        &preview,
        "/_orbital/preview/sign-in",
        &[("Origin", &preview), ("Content-Type", "application/json")],
        &json!({ "user": "u1", "next": "/cards" }).to_string(),
    );
    assert_eq!(entered.status, 302, "{}", entered.everything());
    // 쿠키는 그 하위 도메인에만 걸린다(`Domain` 이 없다)
    let set = entered.set_cookie("__Host-orbital-session").unwrap();
    assert!(!set.to_ascii_lowercase().contains("domain="), "{set}");
    let u1 = entered.cookie("__Host-orbital-session");
    assert_eq!(bench.me(&preview, &u1).status, 200);
    assert_eq!(bench.me(&live, &u1).status, 401);
    // 씨앗 사용자로 들어가는 길은 운영의 하위 도메인에 없다
    let refused = bench.http(
        "POST",
        &live,
        "/_orbital/preview/sign-in",
        &[("Origin", &live), ("Content-Type", "application/json")],
        &json!({ "user": "u1" }).to_string(),
    );
    assert_eq!(refused.status, 404);
}

#[test]
fn 모르는_호스트는_404_다() {
    let mut bench = bench!(true);
    let (instance, live) = bench.ship("cards");
    let router = bench.router();
    let known = format!("{instance}.{BASE}");
    assert_eq!(
        send(&router, Some(&known), "GET", "/login", &[], "").status,
        200
    );
    for host in [
        BASE.to_owned(),
        format!("zz{instance}.{BASE}"),
        format!("x.{instance}.{BASE}"),
        format!("{instance}.{BASE}."),
        format!("{}.{BASE}", instance.to_uppercase()),
        format!("{instance}.other.test"),
        format!("{instance}.{BASE}:80"),
        router.clone(),
        "127.0.0.1".to_owned(),
    ] {
        let reply = send(&router, Some(&host), "GET", "/login", &[], "");
        assert_eq!(reply.status, 404, "{host}: {}", reply.everything());
    }
    // `Host` 가 없거나, 바깥의 머리말로 호스트를 바꿔 치려 해도 그 인스턴스로 가지 않는다
    assert_eq!(send(&router, None, "GET", "/login", &[], "").status, 404);
    for header in ["X-Forwarded-Host", "Forwarded", "X-Original-Host"] {
        let value = if header == "Forwarded" {
            format!("host={known}")
        } else {
            known.clone()
        };
        let reply = send(
            &router,
            Some(BASE),
            "GET",
            "/login",
            &[(header, &value)],
            "",
        );
        assert_eq!(reply.status, 404, "{header}");
    }
    // 요청 줄에 다른 주소를 적어(absolute-form) `Host` 와 어긋나게 해도 그 인스턴스로 가지 않는다
    let mismatched = send(
        &router,
        Some(BASE),
        "GET",
        &format!("http://{known}/login"),
        &[],
        "",
    );
    assert_eq!(mismatched.status, 404);
    // 운영의 주소는 그대로 답한다
    assert_eq!(bench.http("GET", &live, "/login", &[], "").status, 200);
}

#[test]
fn 한_인스턴스의_세션_쿠키는_다른_인스턴스의_하위_도메인에서_읽히지_않는다() {
    let mut bench = bench!(true);
    let (ours, ours_live) = bench.ship("cards");
    let (theirs, theirs_live) = bench.ship("cards");
    bench.invite(&ours, "kim@example.com");
    bench.invite(&theirs, "kim@example.com");
    let (kim, _) = bench.sign_in(&ours_live, "kim@example.com");
    assert_eq!(bench.me(&ours_live, &kim).status, 200);
    assert_eq!(bench.me(&theirs_live, &kim).status, 401);
    assert_eq!(bench.cards(&theirs_live, &kim).status, 401);
}

#[test]
fn 로그인_링크와_oauth_의_발급자는_하위_도메인의_주소로_선다() {
    let mut bench = bench!(true);
    let (instance, live) = bench.ship("mcp");
    let origin = format!("http://{instance}.{BASE}");
    assert_eq!(live, origin);
    bench.invite(&instance, "kim@example.com");
    let (_, link) = bench.sign_in(&live, "kim@example.com");
    assert!(
        link.starts_with(&format!("{origin}/_orbital/auth/callback?token=")),
        "{link}"
    );
    // 상태를 바꾸는 요청은 그 하위 도메인의 화면에서 온 것만 받는다
    for other in [
        bench.router(),
        format!("http://{}", bench.router()),
        format!("http://{instance}-preview.{BASE}"),
        format!("https://{instance}.{BASE}"),
    ] {
        let refused = bench.http(
            "POST",
            &live,
            "/_orbital/auth/email-link",
            &[("Origin", &other), ("Content-Type", "application/json")],
            &json!({ "email": "kim@example.com" }).to_string(),
        );
        assert_eq!(refused.status, 403, "{other}");
    }
    let metadata = bench.http(
        "GET",
        &live,
        "/.well-known/oauth-authorization-server",
        &[JSON],
        "",
    );
    assert_eq!(metadata.status, 200, "{}", metadata.everything());
    assert_eq!(metadata.json()["issuer"], origin);
    assert_eq!(
        metadata.json()["token_endpoint"],
        format!("{origin}/_orbital/oauth/token")
    );
    let resource = bench.http(
        "GET",
        &live,
        "/.well-known/oauth-protected-resource/mcp",
        &[JSON],
        "",
    );
    assert_eq!(resource.json()["resource"], format!("{origin}/mcp"));
    assert_eq!(resource.json()["authorization_servers"], json!([origin]));
    let bare = bench.http("POST", &live, "/mcp", &[JSON], "{}");
    assert_eq!(bare.status, 401);
    assert!(
        bare.header("www-authenticate").unwrap().contains(&format!(
            "{origin}/.well-known/oauth-protected-resource/mcp"
        )),
        "{}",
        bare.everything()
    );
}

#[test]
fn 기준_도메인을_주지_않은_레이어는_전처럼_포트마다_주소를_낸다() {
    let mut bench = bench!(false);
    assert!(bench.layer().router_address().is_none());
    let (ours, ours_live) = bench.ship("cards");
    let (_, theirs_live) = bench.ship("cards");
    for live in [&ours_live, &theirs_live] {
        assert!(live.starts_with("http://127.0.0.1:"), "{live}");
    }
    assert_ne!(ours_live, theirs_live);
    assert_eq!(bench.http("GET", &ours_live, "/login", &[], "").status, 200);
    bench.invite(&ours, "kim@example.com");
    let (_, link) = bench.sign_in(&ours_live, "kim@example.com");
    assert!(link.starts_with(&format!("{ours_live}/_orbital/auth/callback")));
}
