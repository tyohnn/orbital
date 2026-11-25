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
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

    fn check(&self, job: &Job<'_>, limit: Duration) -> Result<(), RunError> {
        self.inner.check(job, limit)
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
    /// 레이어가 읽는 시각(유닉스 초). 0 이면 실제 시각이다. 일정의 때를 테스트가 만든다.
    clock: Arc<AtomicU64>,
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
            clock: Arc::new(AtomicU64::new(0)),
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
        let clock = Arc::clone(&self.clock);
        let layer = Layer::open(Options {
            dev_mailbox: true,
            clock: Arc::new(move || match clock.load(Ordering::SeqCst) {
                0 => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs()),
                at => at,
            }),
            sleep_after: SLEEP_AFTER,
            wake_timeout: Duration::from_secs(5),
            schedule_timeout: Duration::from_secs(1),
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

    /// 프리뷰를 세운다. 그 주소와 release 를 돌려준다.
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

    /// 프리뷰 → 승격 요청 → 고객의 승인 → 운영. (인스턴스, 프리뷰의 주소, 운영의 주소).
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
    // 프리뷰는 되살리지 않고, 앞의 레이어가 세운 프리뷰의 database 는 걷는다
    assert!(!bench.database_exists(&preview_database));
    // 다시 뜬 레이어는 운영의 router 를 자는 채로 세운다. 앱의 프로세스는 아직 없다
    assert_eq!(bench.probe.starts(), 0);
    let again = bench.production_url(&instance);
    assert_eq!(bench.probe.starts(), 0);
    let cards = bench.cards(&again, &kim);
    assert_eq!(cards.status, 200, "{}", cards.everything());
    assert_eq!(titles(&cards), vec!["다시 뜨기 전의 일"]);
    assert_eq!(bench.probe.starts(), 1);
    // 프리뷰는 되살리지 않는다. 다시 세우면 된다
    let preview_port: u16 = preview.rsplit(':').next().unwrap().parse().unwrap();
    assert!(!listening(preview_port), "프리뷰가 되살아났습니다");
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
fn 프리뷰는_운영과_다른_하위_도메인으로_가고_쿠키를_나누지_않는다() {
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

// ---- 공개 경로 · 정적 서비스의 되돌림 · 저장소의 빌드 ----

/// `fixtures/spa` 를 덮은 스캐폴드를 올린다.
fn upload_spa(bench: &Bench) {
    bench.upload("spa", &|folder: &Path| {
        copy_tree(&fixture("todo"), folder);
        copy_tree(&fixture("spa"), folder);
    });
}

#[test]
fn 로그인이_필요한_서비스의_공개_경로는_세션_없이_열리고_세션이_있어도_신원을_싣지_않는다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    let (instance, live) = bench.ship("spa");
    bench.invite(&instance, "kim@example.com");
    let (kim, _) = bench.sign_in(&live, "kim@example.com");

    // 세션 없이도 열린다. 밖에서 실어 보낸 신원 머리말은 지운다
    let open = bench.http(
        "GET",
        &live,
        "/assets/app.js",
        &[JSON, ("x-orbital-identity", "v2.forged")],
        "",
    );
    assert_eq!(open.status, 200, "{}", open.everything());
    assert_eq!(open.json()["public"], json!(true));
    assert_eq!(open.json()["headers"]["x-orbital-identity"], Value::Null);
    // 세션이 있어도 공개 경로에는 신원을 싣지 않는다. 세션 쿠키도 넘기지 않는다
    let signed = bench.http(
        "GET",
        &live,
        "/assets/app.js",
        &[("Cookie", &kim), JSON],
        "",
    );
    assert_eq!(signed.status, 200, "{}", signed.everything());
    assert_eq!(signed.json()["headers"]["x-orbital-identity"], Value::Null);
    assert!(!signed.body.contains("orbital-session"), "{}", signed.body);
    // 같은 세션으로 공개 경로 밖은 신원을 싣는다
    let echo = bench.http("GET", &live, "/echo", &[("Cookie", &kim), JSON], "");
    assert!(
        echo.json()["headers"]["x-orbital-identity"].is_string(),
        "{}",
        echo.everything()
    );

    // 공개 경로 밖과, 앱이 공개 경로 밖으로 읽을 수 있는 경로는 앞처럼 로그인이 필요하다
    for closed in [
        "/cards",
        "/assetsx/a.js",
        "/assets/../cards",
        "/assets/%2e%2e/cards",
        "/assets//a.js",
        "/assets/a%2f..%2f..%2fcards",
    ] {
        let reply = bench.http("GET", &live, closed, &[JSON], "");
        assert_eq!(reply.status, 401, "{closed}: {}", reply.everything());
    }
}

#[test]
fn 정적_서비스는_화면을_원하는_요청에만_화면_안의_경로를_fallback_으로_되돌린다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    let (_, live) = bench.ship("spa");
    let page = ("Accept", "text/html,application/xhtml+xml");
    let index = bench.http("GET", &live, "/app/", &[page], "");
    assert_eq!(index.status, 200);
    for inside in ["/app/payslips/2026-11", "/app/a/b", "/app"] {
        let reply = bench.http("GET", &live, inside, &[page], "");
        assert_eq!(reply.status, 200, "{inside}: {}", reply.everything());
        assert_eq!(reply.body, index.body, "{inside}");
        assert!(
            reply
                .header("content-type")
                .unwrap()
                .starts_with("text/html")
        );
    }
    // 파일처럼 생긴 경로, 화면이 아닌 요청, 폴더 밖은 되돌리지 않는다
    for (path, accept) in [
        ("/app/missing.js", "text/html"),
        ("/app/logo.png", "text/html"),
        ("/app/payslips/2026-11", "application/json"),
        ("/app/../cards", "text/html"),
        ("/app/%2e%2e/cards", "text/html"),
    ] {
        let reply = bench.http("GET", &live, path, &[("Accept", accept)], "");
        assert_eq!(reply.status, 404, "{path} {accept}: {}", reply.everything());
    }
    // 있는 파일은 그대로 나온다
    let script = bench.http("GET", &live, "/app/app.js", &[page], "");
    assert_eq!(script.status, 200);
    assert!(script.body.contains("dataset.path"));
}

#[test]
fn 저장소의_빌드는_서비스의_빌드보다_먼저_한_번만_돌고_그_로그가_프리뷰의_로그에_있다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    let instance = bench.instance("spa");
    let token = bench.token(&instance);
    let (_, release) = bench.preview(&instance, &token);
    let built = bench.home.join("builds").join(&instance).join(&release);
    // 서비스 둘의 빌드가 모두 그 파일을 보고 지났고, 저장소의 빌드는 한 번 돌았다
    assert_eq!(
        fs::read_to_string(built.join("repo-build-runs.txt")).unwrap(),
        "x"
    );
    let (status, logs) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/previews/logs"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{logs}");
    let names: Vec<&str> = logs["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| log["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["build", "build-web", "preview-web", "build-site"]
    );
}

#[test]
fn 저장소의_빌드가_실패하면_서비스의_빌드는_돌지_않고_그_로그를_돌려준다() {
    let mut bench = bench!(false);
    bench.upload("broken", &|folder: &Path| {
        copy_tree(&fixture("todo"), folder);
        copy_tree(&fixture("spa"), folder);
        let manifest = fs::read_to_string(folder.join("orbital.toml"))
            .unwrap()
            .replace(
                "command = \"node -e",
                "command = \"echo 저장소의-빌드가-깨졌다 && false && node -e",
            );
        fs::write(folder.join("orbital.toml"), manifest).unwrap();
    });
    let instance = bench.instance("broken");
    let token = bench.token(&instance);
    let (status, body) = bench.call(
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 422, "{body}");
    let text = body.to_string();
    assert!(text.contains("저장소의-빌드가-깨졌다"), "{text}");
    assert!(text.contains("[build]"), "{text}");
}

// ---- 일정 ----

/// 앱이 남긴 일정의 기록(`jobs.jsonl`). 운영의 빌드 폴더에 있다.
fn jobs(bench: &Bench, instance: &str) -> Vec<Value> {
    let builds = bench.home.join("builds").join(instance);
    let mut lines = Vec::new();
    for entry in fs::read_dir(builds).into_iter().flatten().flatten() {
        if let Ok(text) = fs::read_to_string(entry.path().join("jobs.jsonl")) {
            lines.extend(text.lines().map(|line| serde_json::from_str(line).unwrap()));
        }
    }
    lines
}

/// 일정을 지금 시각으로 부르고, 부른 것이 끝날 때까지 기다린다.
fn tick(bench: &Bench, at: u64) {
    bench.clock.store(at, Ordering::SeqCst);
    for call in bench.layer().call_schedules() {
        call.join().unwrap();
    }
}

/// 2026-11-25 00:00:30 UTC. 분의 중간이다.
const NOON: u64 = 1_795_564_830;

#[test]
fn 운영의_일정은_그_때에_한_번_불리고_레이어만_붙이는_머리말을_싣고_사람의_신원은_싣지_않는다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    bench.clock.store(NOON, Ordering::SeqCst);
    let (instance, _) = bench.ship("spa");

    // 처음 본 일정은 지난 때를 부르지 않고 다음 때를 기다린다
    tick(&bench, NOON);
    assert_eq!(jobs(&bench, &instance), Vec::<Value>::new());
    // 다음 분이 되면 한 번 부른다. 같은 분에 다시 돌아도 다시 부르지 않는다
    tick(&bench, NOON + 30);
    tick(&bench, NOON + 45);
    let ran = jobs(&bench, &instance);
    assert_eq!(ran.len(), 1, "{ran:?}");
    assert_eq!(ran[0]["path"], json!("/jobs/tick"));
    assert_eq!(ran[0]["method"], json!("POST"));
    assert_eq!(
        ran[0]["headers"]["x-orbital-schedule"],
        json!("web * * * * * /jobs/tick")
    );
    assert_eq!(ran[0]["headers"]["x-orbital-identity"], Value::Null);
    assert_eq!(ran[0]["headers"]["cookie"], Value::Null);

    // 레이어가 내려가 있던 동안 놓친 때(9분)는 몰아서 부르지 않고 한 번만 부른다
    tick(&bench, NOON + 30 + 9 * 60);
    let ticks = |bench: &Bench| {
        jobs(bench, &instance)
            .iter()
            .filter(|job| job["path"] == "/jobs/tick")
            .count()
    };
    assert_eq!(ticks(&bench), 2);
    // 다시 뜬 레이어도 이미 부른 때를 다시 부르지 않는다
    bench.restart();
    bench.clock.store(NOON + 30 + 9 * 60, Ordering::SeqCst);
    tick(&bench, NOON + 30 + 9 * 60);
    assert_eq!(ticks(&bench), 2);
    tick(&bench, NOON + 30 + 10 * 60);
    assert_eq!(ticks(&bench), 3);
}

#[test]
fn 일정의_실패는_기록에_남고_팩토리는_마지막_실행의_때와_결과를_본다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    bench.clock.store(NOON, Ordering::SeqCst);
    let (instance, _) = bench.ship("spa");
    tick(&bench, NOON);
    // 00:05 에 두 일정이 함께 온다. 실패하는 일은 다시 부르지 않는다
    tick(&bench, NOON + 5 * 60);
    let failed: Vec<Value> = jobs(&bench, &instance)
        .into_iter()
        .filter(|job| job["path"] == "/jobs/fail")
        .collect();
    assert_eq!(failed.len(), 1);
    let (status, production) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{production}");
    let schedules = production["schedules"].as_array().unwrap();
    let of = |path: &str| {
        schedules
            .iter()
            .find(|schedule| schedule["path"] == path)
            .unwrap_or_else(|| panic!("{path}: {production}"))
            .clone()
    };
    let tick_schedule = of("/jobs/tick");
    assert_eq!(tick_schedule["service"], json!("web"));
    assert_eq!(tick_schedule["cron"], json!("* * * * *"));
    assert_eq!(tick_schedule["next_at"], json!(1_795_565_160u64));
    assert_eq!(tick_schedule["last_run"]["due_at"], json!(1_795_565_100u64));
    assert_eq!(tick_schedule["last_run"]["outcome"], json!("ok"));
    assert_eq!(tick_schedule["last_run"]["status"], json!(200));
    let fail = of("/jobs/fail");
    assert_eq!(fail["last_run"]["outcome"], json!("failed"));
    assert_eq!(fail["last_run"]["status"], json!(500));
    assert_eq!(fail["next_at"], json!(1_795_565_400u64));
    // 정한 시간 안에 답하지 않은 일은 시간 초과로 적는다. 놓친 00:02 와 00:04 가운데 00:04 에 맞춰 한 번 불렀다
    let slow = of("/jobs/slow");
    assert_eq!(slow["last_run"]["outcome"], json!("timed_out"));
    assert_eq!(slow["last_run"]["due_at"], json!(1_795_565_040u64));
    assert_eq!(slow["last_run"]["status"], Value::Null);
    // 레이어의 기록에는 이름과 숫자만 남는다
    assert!(
        bench.logs().contains("SCHEDULE web /jobs/fail failed 500"),
        "{}",
        bench.logs()
    );
}

#[test]
fn 일정의_경로는_밖에서_부르지_못하고_프리뷰의_일정은_부르지_않는다() {
    let mut bench = bench!(false);
    upload_spa(&bench);
    bench.clock.store(NOON, Ordering::SeqCst);
    let (instance, preview, live) = bench.ship_with_preview("spa");
    bench.invite(&instance, "kim@example.com");
    let (kim, _) = bench.sign_in(&live, "kim@example.com");
    for origin in [&live, &preview] {
        for path in [
            "/jobs/tick",
            "/jobs/tick/",
            "/JOBS/Tick",
            "/jobs//tick",
            "/x/../jobs/tick",
            "/jobs/%74ick",
            "/jobs/tick;x",
        ] {
            let reply = bench.http(
                "POST",
                origin,
                path,
                &[
                    ("Cookie", &kim),
                    ("x-orbital-schedule", "web * * * * * /jobs/tick"),
                    JSON,
                ],
                "",
            );
            assert_eq!(reply.status, 404, "{origin}{path}: {}", reply.everything());
        }
    }
    assert_eq!(jobs(&bench, &instance), Vec::<Value>::new());
    // 다른 경로는 앞처럼 간다
    let other = bench.http("POST", &live, "/jobs/other", &[("Cookie", &kim), JSON], "");
    assert_eq!(other.status, 200, "{}", other.everything());
    // 프리뷰는 때가 되어도 부르지 않는다. 운영의 것만 부른다
    tick(&bench, NOON);
    tick(&bench, NOON + 60);
    let ran: Vec<Value> = jobs(&bench, &instance)
        .into_iter()
        .filter(|job| job["path"] == "/jobs/tick")
        .collect();
    assert_eq!(ran.len(), 1);
}

// ---- 다시 뜨기 ----

#[test]
fn 하위_도메인을_쓰지_않는_레이어가_다시_떠도_운영의_포트는_그대로다() {
    let mut bench = bench!(false);
    let (instance, live) = bench.ship("cards");
    bench.restart();
    assert_eq!(bench.production_url(&instance), live);
    assert_eq!(bench.http("GET", &live, "/login", &[], "").status, 200);
    // 그 포트를 누가 쥐고 있으면 새 포트를 잡고 기록을 고친다
    let port: u16 = live.rsplit(':').next().unwrap().parse().unwrap();
    drop(bench.layer.take());
    let squatter = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    bench.open();
    let moved = bench.production_url(&instance);
    assert_ne!(moved, live);
    assert_eq!(bench.http("GET", &moved, "/login", &[], "").status, 200);
    drop(squatter);
    bench.restart();
    assert_eq!(bench.production_url(&instance), moved);
}

#[test]
fn 빌드_폴더가_없는_운영은_레이어를_막지_않고_빌드하는_동안_503_과_retry_after_로_답한다() {
    let mut bench = bench!(false);
    bench.upload("slow", &|folder: &Path| {
        copy_tree(&fixture("todo"), folder);
        copy_tree(&fixture("slow"), folder);
    });
    let (instance, live) = bench.ship("slow");
    let (other, other_live) = bench.ship("cards");
    fs::remove_dir_all(bench.home.join("builds").join(&instance)).unwrap();

    // 다시 뜨는 것은 빌드(3초)를 기다리지 않는다
    let started = Instant::now();
    bench.restart();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    // 그동안 그 인스턴스는 503 과 Retry-After 로 답하고, 다른 인스턴스와 API 는 기다리지 않는다
    let waiting = bench.http("GET", &live, "/health", &[JSON], "");
    assert_eq!(waiting.status, 503, "{}", waiting.everything());
    assert!(waiting.header("retry-after").is_some());
    let started = Instant::now();
    assert_eq!(bench.production_url(&other), other_live);
    assert_eq!(
        bench.http("GET", &other_live, "/login", &[], "").status,
        200
    );
    let (status, _) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    // 빌드가 끝나면 같은 주소에서 선다
    assert!(
        eventually(Duration::from_secs(30), || bench
            .http("GET", &live, "/health", &[JSON], "")
            .status
            == 200),
        "빌드가 끝났는데 서지 않았습니다"
    );
    assert_eq!(bench.production_url(&instance), live);
}
