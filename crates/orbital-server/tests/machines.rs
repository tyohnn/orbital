//! 다른 기계에 놓인 인스턴스의 요청을 그 기계로 넘겨 준다. 같은 control database 를 보는 관리 서버 여럿(기계 `a` · `b` · `c`)을 실제 HTTP 로 띄워 잰다.
//!
//! 관리 서버마다 받기 고리(`Front`)가 실제 포트를 듣고 받은 요청의 수를 센다. 다른 관리 서버로 넘어간 요청은 그 수로 보인다.
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버)로 잰다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orbital_core::host::{BaseDomain, Scheme};
use orbital_core::name::Ident;
use orbital_run::LocalRunner;
use orbital_server::http::{Call, answer, handle, handle_call};
use orbital_server::layer::{Hosting, Layer, Options};
use orbital_server::records::drop_database;
use orbital_server::seal::SealKey;
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
/// 운영자의 열쇠(`ORBITAL_OPERATOR_KEY`). 모든 관리 서버가 같이 쓴다.
const OPERATOR: &str = "op_test_operator_key_not_a_secret_0000";
/// 모든 관리 서버가 같이 쓰는 토큰의 열쇠(`ORBITAL_TOKEN_KEY`).
const TOKEN_KEY: [u8; 32] = [3; 32];
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
const BANK: &str = "sk_live_bank_Rc71pZt0qWe";
const FORWARDED_BY: &str = "x-orbital-forwarded-by";
const BASE: &str = "orbital.test";

static COUNTER: AtomicU32 = AtomicU32::new(0);

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

/// 사람의 git 설정이 섞이지 않는 git. 실패해도 결과를 돌려준다.
fn run_git(folder: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(folder)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=agent",
            "-c",
            "user.email=agent@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .unwrap()
}

fn git(folder: &Path, args: &[&str]) -> String {
    let output = run_git(folder, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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

/// 비어 있는 포트 하나. 잡았다가 놓는다. 그 포트에는 아무도 듣지 않는다.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 실제 HTTP 의 답.
struct Http {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Http {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// 실제 HTTP 로 보낸다. `headers` 를 그대로 싣는다.
fn http(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Http {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(300))
        .redirects(0)
        .build();
    let mut request = agent.request(method, url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = match request.send_bytes(body) {
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
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut response.into_reader(), &mut body).unwrap();
    Http {
        status,
        headers,
        body,
    }
}

/// 관리 서버 앞의 받기 고리. 받은 요청을 센다.
struct Front {
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
    /// 받은 요청의 수.
    hits: Arc<AtomicUsize>,
    /// 받은 요청 가운데 넘겨받은 것(`x-orbital-forwarded-by`)의 수.
    forwarded: Arc<AtomicUsize>,
}

impl Front {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn forwarded(&self) -> usize {
        self.forwarded.load(Ordering::SeqCst)
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn front(layer: Arc<Layer>, server: tiny_http::Server) -> Front {
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let forwarded = Arc::new(AtomicUsize::new(0));
    let (stopping, counting, counting_forwarded) =
        (Arc::clone(&stop), Arc::clone(&hits), Arc::clone(&forwarded));
    let task = std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) {
                counting.fetch_add(1, Ordering::SeqCst);
                if request
                    .headers()
                    .iter()
                    .any(|header| header.field.equiv(FORWARDED_BY))
                {
                    counting_forwarded.fetch_add(1, Ordering::SeqCst);
                }
                let layer = Arc::clone(&layer);
                std::thread::spawn(move || answer(&layer, request));
            }
        }
    });
    Front {
        stop,
        task: Some(task),
        hits,
        forwarded,
    }
}

struct Machine {
    layer: Arc<Layer>,
    front: Front,
    /// 받기 고리의 실제 주소.
    url: String,
    /// 하위 도메인의 요청을 받는 공용 listener 의 실제 주소(`127.0.0.1:포트`). 하위 도메인을 쓰는 레이어만.
    router: Option<String>,
}

/// 기계 하나를 띄울 때 기록에 적을 주소.
#[derive(Clone)]
enum Address {
    /// 자기 받기 고리의 주소.
    Own,
    /// 적지 않는다.
    None,
    /// 이 주소를 적는다(닿지 않는 곳이나 다른 기계).
    Given(String),
}

/// 같은 control database 를 보는 관리 서버들. 모두 실제 포트를 듣는다.
struct Bench {
    scratch: PathBuf,
    pg_url: String,
    control: Ident,
    /// 하위 도메인으로 고객의 요청을 받는 레이어인가.
    hosted: bool,
    machines: BTreeMap<String, Machine>,
    /// (인스턴스, 놓인 기계, service key). 끝날 때 걷는다.
    instances: Vec<(String, String, &'static str)>,
    /// 기계마다 다르게 줄 토큰의 열쇠. 없으면 [`TOKEN_KEY`] 다.
    token_keys: BTreeMap<String, [u8; 32]>,
}

impl Bench {
    fn new(hosted: bool) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-machines-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        Some(Self {
            scratch,
            pg_url,
            control: fresh_name("ctl"),
            hosted,
            machines: BTreeMap::new(),
            instances: Vec::new(),
            token_keys: BTreeMap::new(),
        })
    }

    /// 받기 고리의 자리를 먼저 잡는다. 그래야 그 주소를 기록에 적고 띄운다.
    fn bind() -> (tiny_http::Server, String) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        (server, url)
    }

    /// 기계 `name` 의 관리 서버를 띄운다. 기록에는 `api` 와 (하위 도메인을 쓰면) `router` 의 주소를 적는다.
    fn boot(&mut self, name: &str, api: Address, router: Address) {
        let (server, url) = Self::bind();
        // 공용 listener 의 포트는 띄우기 전에 정해야 기록에 적는다. 잡았다 놓은 포트를 쓴다
        let listen = self.hosted.then(|| format!("127.0.0.1:{}", closed_port()));
        let recorded = |address: &Address, own: Option<String>| match address {
            Address::Own => own,
            Address::None => None,
            Address::Given(given) => Some(given.clone()),
        };
        let options = self.options(
            name,
            recorded(&api, Some(url.clone())),
            recorded(&router, listen.as_ref().map(|at| format!("http://{at}"))),
            listen.clone(),
        );
        let layer = Arc::new(Layer::open(options).expect("레이어를 열지 못했습니다"));
        let front = front(Arc::clone(&layer), server);
        self.machines.insert(
            name.to_owned(),
            Machine {
                layer,
                front,
                url,
                router: listen,
            },
        );
    }

    /// 기계 `name` 의 관리 서버의 설정. 기록에 `api` 와 `router` 의 주소를 적고, `listen` 이 있으면 하위 도메인을 쓴다.
    fn options(
        &self,
        name: &str,
        api: Option<String>,
        router: Option<String>,
        listen: Option<String>,
    ) -> Options {
        Options {
            seal_key: Some(SealKey::from_bytes([7; 32])),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(name).unwrap(),
            token_key: Some(
                self.token_keys
                    .get(name)
                    .copied()
                    .unwrap_or(TOKEN_KEY)
                    .to_vec(),
            ),
            machine_url: api,
            machine_router_url: router,
            operator_key: Some(OPERATOR.to_owned()),
            hosting: listen.map(|listen| Hosting {
                listen,
                base: BaseDomain::parse(BASE).unwrap(),
                scheme: Scheme::Http,
            }),
            sleep_after: Duration::from_millis(800),
            wake_timeout: Duration::from_secs(10),
            schedule_timeout: Duration::from_secs(5),
            ..Options::new(
                self.scratch.join(format!("home-{name}")),
                self.pg_url.clone(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        }
    }

    /// 기계 `name` 의 관리 서버를 내린다.
    fn shut(&mut self, name: &str) {
        if let Some(mut machine) = self.machines.remove(name) {
            machine.front.halt();
        }
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    fn machine(&self, name: &str) -> &Machine {
        &self.machines[name]
    }

    fn layer(&self, name: &str) -> &Layer {
        &self.machines[name].layer
    }

    fn url(&self, name: &str) -> String {
        self.machines[name].url.clone()
    }

    /// 관리 서버의 HTTP 층에 바로 넣는다(다른 기계로 넘기는 일은 실제 HTTP 로 간다).
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

    /// 스캐폴드의 묶음.
    fn scaffold(&self, label: &str, version: &str) -> Vec<u8> {
        self.scaffold_of(&["records"], label, version)
    }

    /// 픽스처 폴더들을 차례로 겹친 스캐폴드의 묶음.
    fn scaffold_of(&self, fixtures: &[&str], label: &str, version: &str) -> Vec<u8> {
        let folder = self.scratch.join(format!("scaffold-{label}"));
        let _ = fs::remove_dir_all(&folder);
        for name in fixtures {
            copy_tree(&fixture(name), &folder);
        }
        git(&folder, &["init", "--quiet"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드"]);
        git(&folder, &["tag", version]);
        let bundle = self.scratch.join(format!("{label}.bundle"));
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
        fs::read(bundle).unwrap()
    }

    fn upload(&self, on: &str) {
        let bundle = self.scaffold(&format!("{on}-v1"), "v1");
        let (status, body) = self.call(on, "PUT", "/v1/apps/records", FACTORY, &bundle);
        assert_eq!(status, 200, "{body}");
    }

    /// `on` 에서 인스턴스를 세운다. 놓인 기계는 `placed` 이어야 한다.
    fn instance(&mut self, on: &str, placed: &str) -> String {
        let (status, body) = self.post(
            on,
            "/v1/instances",
            FACTORY,
            &json!({ "app": "records", "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances
            .push((instance.clone(), placed.to_owned(), FACTORY));
        instance
    }

    fn token(&self, on: &str, instance: &str) -> String {
        let (status, body) = self.post(
            on,
            &format!("/v1/instances/{instance}/sessions"),
            FACTORY,
            &json!({ "can": ALL }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 놓인 기계의 인스턴스 저장소.
    fn repository(&self, machine: &str, instance: &str) -> PathBuf {
        self.home(machine)
            .join("sources")
            .join(format!("{instance}.git"))
    }

    fn record(&self, instance: &str) -> Option<orbital_server::registry::InstanceRecord> {
        self.layer("a").records().instance(instance).unwrap()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for (instance, placed, key) in &self.instances {
            if self.machines.contains_key(placed) {
                let _ = self.call(
                    placed,
                    "DELETE",
                    &format!("/v1/instances/{instance}"),
                    key,
                    &[],
                );
            }
            if let Ok(mut admin) = orbital_pg::Admin::connect(&self.pg_url) {
                let names = orbital_core::plan::Names::new(
                    orbital_core::name::InstanceId::parse(instance).unwrap(),
                );
                let _ = admin.destroy(&names);
            }
        }
        for machine in self.machines.values_mut() {
            machine.front.halt();
        }
        self.machines.clear();
        let _ = drop_database(&self.pg_url, &self.control);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    ($hosted:expr) => {
        match Bench::new($hosted) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

/// 기계 `a` · `b` 를 서로의 주소를 기록에 적어 띄우고, `a` 에 앱을 올려 인스턴스 하나를 세운다.
fn pair(bench: &mut Bench) -> String {
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    bench.upload("a");
    bench.instance("a", "a")
}

// ---- 관리 API 를 놓인 기계로 넘겨 주기 ----

#[test]
fn 기계의_주소는_뜰_때_기록에_적히고_같은_이름으로_뜨려다_막힌_관리_서버는_덮지_못한다() {
    let mut bench = bench!(false);
    bench.boot("a", Address::Own, Address::None);
    let own = bench.url("a");
    let addresses = || bench.layer("a").addresses_of("a").unwrap();
    assert_eq!(addresses().api, Some(own.clone()));
    assert_eq!(addresses().router, None);
    // 같은 이름으로 다른 주소를 들고 뜨려다 막힌다. 주소는 앞의 것 그대로다
    let refused =
        Layer::open(bench.options("a", Some("http://10.9.9.9:7400".to_owned()), None, None));
    assert!(refused.is_err());
    assert_eq!(addresses().api, Some(own.clone()));
    // 틀린 주소로는 뜨지 않고 무엇을 고칠지 알린다. 기록은 그대로다
    for wrong in [
        "ftp://10.0.0.5",
        "http://10.0.0.5:7400/v1",
        "http://user@10.0.0.5",
        "10.0.0.5:7400",
    ] {
        let error = Layer::open(bench.options("c", Some(wrong.to_owned()), None, None))
            .err()
            .unwrap_or_else(|| panic!("{wrong} 로 떴습니다"));
        assert!(error.contains("ORBITAL_MACHINE_URL"), "{wrong}: {error}");
    }
    let error =
        Layer::open(bench.options("c", None, Some("https://10.0.0.5:7480".to_owned()), None))
            .err()
            .expect("https 의 공용 listener 로 떴습니다");
    assert!(error.contains("ORBITAL_MACHINE_ROUTER_URL"), "{error}");
    assert_eq!(addresses().api, Some(own));
    // 주소 없이 다시 뜨면 낡은 주소를 비운다. 그 기계로는 넘기지 않는다
    bench.shut("a");
    bench.boot("a", Address::None, Address::None);
    assert_eq!(bench.layer("a").addresses_of("a").unwrap().api, None);
}

#[test]
fn 다른_기계에_놓인_인스턴스의_프리뷰와_리허설과_승격과_지우기는_놓인_기계로_넘겨져_그_기계가_한다()
{
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    let path = |tail: &str| format!("/v1/instances/{instance}{tail}");
    let token = bench.token("b", &instance);

    // 에이전트의 일: 프리뷰 · 묶음 받기 · 리허설 · 승격의 요청을 b 에 보낸다
    let (status, preview) = bench.call("b", "POST", &path("/previews"), &token, &[]);
    assert_eq!(status, 200, "{preview}");
    let release = preview["release"].as_str().unwrap().to_owned();
    let address = preview["services"][0]["url"].as_str().unwrap().to_owned();
    let answered = http("GET", &address, &[], &[]);
    assert_eq!(answered.status, 200, "{}", answered.text());
    let bundle = handle(bench.layer("b"), "GET", &path("/source"), Some(&token), &[]);
    assert_eq!(bundle.status, 200);
    assert!(
        bundle.body.starts_with(b"# v2 git bundle"),
        "묶음이 아닙니다"
    );
    let (status, rehearsal) = bench.post(
        "b",
        &path("/rehearsals"),
        &token,
        &json!({ "release": release }),
    );
    assert_eq!(status, 200, "{rehearsal}");
    // 팩토리의 일: 비밀(어느 기계나)과 승격(놓인 기계)
    let (status, body) = bench.call(
        "b",
        "PUT",
        &path("/secrets/BANK_API_KEY"),
        FACTORY,
        json!({ "stage": "production", "value": BANK })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = bench.post(
        "b",
        &path("/promotion-requests"),
        &token,
        &json!({ "release": release }),
    );
    assert_eq!(status, 200, "{body}");
    let (status, production) = bench.post(
        "b",
        &path("/promotions"),
        FACTORY,
        &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
    );
    assert_eq!(status, 200, "{production}");
    let live = production["services"][0]["url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(http("GET", &live, &[], &[]).status, 200);

    // 일은 a 가 했다. a 가 넘겨받은 요청을 받았고, b 의 폴더에는 저장소도 빌드도 없다
    assert!(bench.machine("a").front.forwarded() >= 5);
    assert!(bench.repository("a", &instance).is_dir());
    assert!(!bench.repository("b", &instance).exists());
    assert!(!bench.home("b").join("builds").exists());
    let record = bench.record(&instance).unwrap();
    assert_eq!(record.machine, "a");
    assert!(record.production.is_some());

    // 지우기도 넘겨져 a 가 저장소까지 걷는다
    let (status, body) = bench.call("b", "DELETE", &path(""), FACTORY, &[]);
    assert_eq!(status, 200, "{body}");
    assert!(bench.record(&instance).is_none());
    assert!(!bench.repository("a", &instance).exists());
}

#[test]
fn git_으로_받고_올리기도_놓인_기계로_넘겨져_그_기계의_저장소에_닿는다() {
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    let token = bench.token("b", &instance);
    // git 은 b 의 주소만 안다
    let remote = format!("{}/v1/instances/{instance}/git", bench.url("b"));
    let header = format!("http.extraHeader=Authorization: Bearer {token}");
    let work = bench.scratch.join("work");
    let cloned = run_git(
        &bench.scratch,
        &[
            "-c",
            &header,
            "clone",
            "--quiet",
            &remote,
            work.to_str().unwrap(),
        ],
    );
    assert!(
        cloned.status.success(),
        "{}",
        String::from_utf8_lossy(&cloned.stderr)
    );
    let head = git(&bench.repository("a", &instance), &["rev-parse", "main"]);
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), head);

    fs::write(work.join("NOTE.md"), "b 를 거쳐 올린다\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "b 를 거쳐 올린다"]);
    let pushed = git(&work, &["rev-parse", "HEAD"]);
    let output = run_git(&work, &["-c", &header, "push", "--quiet", "origin", "main"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        git(&bench.repository("a", &instance), &["rev-parse", "main"]),
        pushed
    );
    assert!(!bench.repository("b", &instance).exists());
}

#[test]
fn 놓인_기계가_자격을_거절하면_git_이_알아듣는_401_과_basic_의_요청을_그대로_돌려준다() {
    let mut bench = bench!(false);
    // a 만 다른 토큰의 열쇠를 받았다(운영자의 실수). b 가 낸 토큰은 b 에서는 통하고 a 에서는 통하지 않는다
    bench.token_keys.insert("a".to_owned(), [9; 32]);
    let instance = pair(&mut bench);
    let token = bench.token("b", &instance);
    let remote = format!("{}/v1/instances/{instance}/git", bench.url("b"));
    let before = bench.machine("a").front.forwarded();
    let refused = http(
        "GET",
        &format!("{remote}/info/refs?service=git-upload-pack"),
        &[("Authorization", &format!("Bearer {token}"))],
        &[],
    );
    assert_eq!(refused.status, 401, "{}", refused.text());
    assert_eq!(bench.machine("a").front.forwarded(), before + 1);
    assert!(
        refused
            .header("www-authenticate")
            .is_some_and(|value| value.starts_with("Basic")),
        "{:?}",
        refused.headers
    );
    assert_eq!(refused.header("cache-control"), Some("no-store"));
    assert!(
        refused
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
    );
}

#[test]
fn 앱의_스캐폴드와_그_앱의_인스턴스는_앱이_있는_기계로_넘겨져_그_기계에_선다() {
    let mut bench = bench!(false);
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    bench.upload("a");
    // 앱의 새 버전을 b 에 올린다. 앱의 저장소가 있는 a 가 받는다
    let bundle = bench.scaffold("b-v2", "v2");
    let (status, body) = bench.call("b", "PUT", "/v1/apps/records", FACTORY, &bundle);
    assert_eq!(status, 200, "{body}");
    assert!(!bench.home("b").join("apps").exists());
    // 그 앱의 인스턴스를 b 에서 세운다. a 에 선다
    let (status, body) = bench.post(
        "b",
        "/v1/instances",
        FACTORY,
        &json!({ "app": "records", "version": "v2" }),
    );
    assert_eq!(status, 200, "{body}");
    let instance = body["instance"].as_str().unwrap().to_owned();
    bench
        .instances
        .push((instance.clone(), "a".to_owned(), FACTORY));
    assert_eq!(bench.record(&instance).unwrap().machine, "a");
    assert!(bench.repository("a", &instance).is_dir());
    assert!(!bench.repository("b", &instance).exists());
    assert!(bench.machine("a").front.forwarded() >= 2);
}

#[test]
fn 어느_기계나_하는_일은_넘기지_않고_받은_기계가_한다() {
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    let path = |tail: &str| format!("/v1/instances/{instance}{tail}");
    // 비밀의 이름은 프리뷰를 세워야 알려진다. 프리뷰는 a 에서 바로 세운다
    let token = bench.token("a", &instance);
    let (status, preview) = bench.call("a", "POST", &path("/previews"), &token, &[]);
    assert_eq!(status, 200, "{preview}");
    let before = bench.machine("a").front.hits();
    for (method, tail, bearer, body) in [
        ("GET", "/secrets", FACTORY, Value::Null),
        (
            "PUT",
            "/secrets/BANK_API_KEY",
            FACTORY,
            json!({ "stage": "preview", "value": BANK }),
        ),
        (
            "POST",
            "/secrets/BANK_API_KEY/request",
            token.as_str(),
            json!({ "reason": "은행 API 를 부른다" }),
        ),
        ("GET", "/secrets", token.as_str(), Value::Null),
        ("POST", "/sessions", FACTORY, json!({ "can": ["source"] })),
    ] {
        let body = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        let (status, answer) = bench.call("b", method, &path(tail), bearer, &body);
        assert_eq!(status, 200, "{method} {tail}: {answer}");
    }
    assert_eq!(bench.machine("a").front.hits(), before);
}

#[test]
fn 밖에서_고리_막기_머리말을_붙여도_넘겨지지_않고_421_만_얻는다() {
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    let token = bench.token("b", &instance);
    let bearer = format!("Bearer {token}");
    let before = bench.machine("a").front.hits();
    // 밖의 호출자가 b 에 머리말을 붙여 보낸다. b 는 넘기지 않는다
    let refused = http(
        "POST",
        &format!("{}/v1/instances/{instance}/previews", bench.url("b")),
        &[("Authorization", &bearer), (FORWARDED_BY, "a")],
        &[],
    );
    assert_eq!(refused.status, 421, "{}", refused.text());
    assert_eq!(refused.json()["error"], "misplaced");
    assert_eq!(refused.json()["machine"], "a");
    assert_eq!(bench.machine("a").front.hits(), before);
    assert!(bench.record(&instance).unwrap().preview.is_none());
    // 같은 요청을 머리말 없이 보내면 넘겨진다(머리말만이 다르다)
    let forwarded = http(
        "GET",
        &format!("{}/v1/instances/{instance}/previews/logs", bench.url("b")),
        &[("Authorization", &bearer)],
        &[],
    );
    assert_ne!(forwarded.status, 421, "{}", forwarded.text());
    assert_eq!(bench.machine("a").front.hits(), before + 1);
}

#[test]
fn 넘겨받은_요청의_토큰과_service_key_도_놓인_기계가_처음처럼_다시_판정한다() {
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    let other = bench.instance("a", "a");
    let other_token = bench.token("a", &other);
    let path = |tail: &str| format!("/v1/instances/{instance}{tail}");
    let promotion =
        json!({ "release": "r", "change": "customer_request", "approved_by": "customer" })
            .to_string();
    // (메서드, 경로, 자격, 본문, 처음 받은 요청의 답)
    let cases: [(&str, String, String, &[u8], u16); 5] = [
        (
            "POST",
            path("/promotions"),
            format!("Bearer {OTHER_FACTORY}"),
            promotion.as_bytes(),
            404,
        ),
        (
            "DELETE",
            path(""),
            format!("Bearer {OTHER_FACTORY}"),
            &[],
            404,
        ),
        (
            "POST",
            path("/previews"),
            "Bearer orb1.forged.forged".to_owned(),
            &[],
            401,
        ),
        (
            "POST",
            path("/previews"),
            format!("Bearer {other_token}"),
            &[],
            404,
        ),
        (
            "POST",
            path("/previews"),
            "Bearer sk_test_nobody".to_owned(),
            &[],
            401,
        ),
    ];
    let a = bench.layer("a");
    for (method, path, authorization, body, expected) in &cases {
        for forwarded_by in [None, Some("b")] {
            let reply = handle_call(
                a,
                &Call {
                    method,
                    path,
                    authorization: Some(authorization),
                    content_type: Some("application/json"),
                    content_encoding: None,
                    forwarded_by,
                    body,
                },
            );
            assert_eq!(
                reply.status,
                *expected,
                "{method} {path} ({forwarded_by:?}): {}",
                String::from_utf8_lossy(&reply.body)
            );
        }
    }
    // b 에 다른 팩토리의 열쇠나 다른 인스턴스의 토큰으로 오면 b 가 먼저 거절하고 a 로 넘기지 않는다
    let before = bench.machine("a").front.hits();
    for (method, path, authorization, body, expected) in &cases {
        let reply = http(
            method,
            &format!("{}{path}", bench.url("b")),
            &[("Authorization", authorization)],
            body,
        );
        assert_eq!(
            reply.status,
            *expected,
            "b: {method} {path}: {}",
            reply.text()
        );
    }
    assert_eq!(bench.machine("a").front.hits(), before);
    assert!(bench.record(&instance).is_some());
    assert!(bench.record(&instance).unwrap().preview.is_none());
}

#[test]
fn 기록의_service_key_는_넘겨받은_요청에서도_놓인_기계가_다시_판정하고_한쪽이_거둔_열쇠는_넘기기_전에_막힌다()
 {
    let mut bench = bench!(false);
    let instance = pair(&mut bench);
    // 설정의 열쇠(FACTORY)와 같은 조직 이름으로 기록의 조직을 b 에서 만들고 열쇠 둘을 낸다
    let (status, created) = bench.post(
        "b",
        "/v1/operator/organizations",
        OPERATOR,
        &json!({ "id": "factory", "name": "팩토리", "kind": "live" }),
    );
    assert_eq!(status, 200, "{created}");
    let first = created["key"]["key"].as_str().unwrap().to_owned();
    let (status, issued) = bench.post("b", "/v1/keys", &first, &json!({ "label": "둘째" }));
    assert_eq!(status, 200, "{issued}");
    let second = issued["key"].as_str().unwrap().to_owned();
    let second_id = issued["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/instances/{instance}");
    // a 에서 거둔다
    let (status, body) = bench.call("a", "DELETE", &format!("/v1/keys/{second_id}"), &first, &[]);
    assert_eq!(status, 200, "{body}");
    // b 는 거둔 열쇠를 넘기기 전에 막는다. a 에 닿지 않는다
    let before = bench.machine("a").front.hits();
    let reply = http(
        "DELETE",
        &format!("{}{path}", bench.url("b")),
        &[("Authorization", &format!("Bearer {second}"))],
        &[],
    );
    assert_eq!(reply.status, 401, "{}", reply.text());
    assert_eq!(bench.machine("a").front.hits(), before);
    // 넘겨받은 요청이어도 놓인 기계(a)는 열쇠를 다시 판정한다
    let authorization = format!("Bearer {second}");
    let reply = handle_call(
        bench.layer("a"),
        &Call {
            method: "DELETE",
            path: &path,
            authorization: Some(&authorization),
            content_type: None,
            content_encoding: None,
            forwarded_by: Some("b"),
            body: &[],
        },
    );
    assert_eq!(reply.status, 401);
    assert!(bench.record(&instance).is_some());
    // b 에서 낸 살아 있는 열쇠는 b 가 a 로 넘기고 a 가 받는다
    let forwarded = bench.machine("a").front.forwarded();
    let reply = http(
        "DELETE",
        &format!("{}{path}", bench.url("b")),
        &[("Authorization", &format!("Bearer {first}"))],
        &[],
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(bench.machine("a").front.forwarded(), forwarded + 1);
    assert!(bench.record(&instance).is_none());
    assert!(!bench.repository("a", &instance).exists());
}

#[test]
fn 기록의_주소가_엇갈려도_넘겨받은_요청은_다시_넘기지_않는다() {
    let mut bench = bench!(false);
    // c 를 먼저 띄우고, a 의 주소 칸에 c 의 주소를 적는다(잘못 적은 운영자)
    bench.boot("c", Address::Own, Address::None);
    let c = bench.url("c");
    bench.boot("a", Address::Given(c), Address::None);
    bench.boot("b", Address::Own, Address::None);
    bench.upload("a");
    let instance = bench.instance("a", "a");
    let token = bench.token("b", &instance);
    let (status, body) = bench.call(
        "b",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    // b 는 「a」의 주소(실제로는 c)로 한 번 넘기고, c 는 넘겨받은 요청을 다시 넘기지 않고 421 로 답한다
    assert_eq!(status, 421, "{body}");
    assert_eq!(body["machine"], "a");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("넘겨받은 요청은 다시 넘기지 않"),
        "{body}"
    );
    assert_eq!(bench.machine("c").front.hits(), 1);
    assert_eq!(bench.machine("c").front.forwarded(), 1);
    assert_eq!(bench.machine("a").front.hits(), 0);
    assert!(bench.record(&instance).unwrap().preview.is_none());
}

#[test]
fn 놓인_기계의_주소에_닿지_못하면_502_와_기계의_이름으로_답하고_아무것도_하지_않는다() {
    let mut bench = bench!(false);
    let nowhere = format!("http://127.0.0.1:{}", closed_port());
    bench.boot("a", Address::Given(nowhere), Address::None);
    bench.boot("b", Address::Own, Address::None);
    bench.upload("a");
    let instance = bench.instance("a", "a");
    let token = bench.token("b", &instance);
    let (status, body) = bench.call(
        "b",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["error"], "machine_unreachable");
    assert_eq!(body["machine"], "a");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("아무것도 하지 않았습니다"),
        "{body}"
    );
    assert!(bench.record(&instance).unwrap().preview.is_none());
    assert!(!bench.repository("b", &instance).exists());
    // 앱 올리기도 같다
    let bundle = bench.scaffold("b-v2", "v2");
    let (status, body) = bench.call("b", "PUT", "/v1/apps/records", FACTORY, &bundle);
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["machine"], "a");
    assert!(!bench.home("b").join("apps").exists());
}

#[test]
fn 주소를_적지_않은_기계로는_넘기지_않고_421_이다() {
    let mut bench = bench!(false);
    bench.boot("a", Address::None, Address::None);
    bench.boot("b", Address::Own, Address::None);
    bench.upload("a");
    let instance = bench.instance("a", "a");
    let token = bench.token("b", &instance);
    let (status, body) = bench.call(
        "b",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 421, "{body}");
    assert_eq!(body["error"], "misplaced");
    assert_eq!(body["machine"], "a");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("ORBITAL_MACHINE_URL"),
        "{body}"
    );
    assert_eq!(bench.machine("a").front.hits(), 0);
}

// ---- 고객의 요청(앱으로 가는 트래픽)을 놓인 기계로 넘겨 주기 ----

/// 날것의 HTTP 응답.
struct Raw {
    status: u16,
    /// 이름은 소문자다.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        format!(
            "{} {:?} {}",
            self.status,
            self.headers,
            String::from_utf8_lossy(&self.body)
        )
    }

    /// `Set-Cookie` 가운데 이 이름의 것을 `이름=값` 으로.
    fn cookie(&self, name: &str) -> String {
        self.headers
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .filter_map(|(_, value)| value.split(';').next())
            .find(|pair| pair.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다: {:?}", self.headers))
            .to_owned()
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

/// `address`(`127.0.0.1:포트`)에 `Host: host` 로 요청 하나를 보낸다.
fn send(
    address: &str,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Raw {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
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
    Raw {
        status,
        headers,
        body,
    }
}

impl Bench {
    /// 기계의 공용 listener 의 주소(`127.0.0.1:포트`).
    fn listener(&self, machine: &str) -> String {
        self.machine(machine)
            .router
            .clone()
            .expect("하위 도메인을 쓰는 레이어가 아닙니다")
    }

    /// 기계 `a` 에 요청을 되비추는 앱을 올리고 인스턴스 하나의 프리뷰를 세운다. (인스턴스, 프리뷰의 Host).
    fn relay_preview(&mut self) -> (String, String) {
        let bundle = self.scaffold_of(&["todo", "relay"], "relay", "v1");
        let (status, body) = self.call("a", "PUT", "/v1/apps/records", FACTORY, &bundle);
        assert_eq!(status, 200, "{body}");
        let instance = self.instance("a", "a");
        let token = self.token("a", &instance);
        let (status, preview) = self.call(
            "a",
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            &token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        let host = format!("{instance}-preview.{BASE}");
        assert_eq!(
            preview["services"][0]["url"],
            json!(format!("http://{host}"))
        );
        (instance, host)
    }

    /// 씨앗 사용자 `u1` 로 `on` 의 공용 listener 를 거쳐 들어간다. 세션 쿠키(`이름=값`).
    fn sign_in_through(&self, on: &str, host: &str) -> String {
        let origin = format!("http://{host}");
        let entered = send(
            &self.listener(on),
            host,
            "POST",
            "/_orbital/preview/sign-in",
            &[("Origin", &origin), ("Content-Type", "application/json")],
            json!({ "user": "u1", "next": "/echo" })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(entered.status, 302, "{}", entered.text());
        entered.cookie("__Host-orbital-session")
    }
}

#[test]
fn 다른_기계에_놓인_인스턴스의_하위_도메인으로_온_요청은_놓인_기계의_router_로_넘겨져_로그인이_풀리지_않는다()
 {
    let mut bench = bench!(true);
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    let (_, host) = bench.relay_preview();
    // b 를 거쳐 로그인하고, 받은 쿠키로 b 를 거쳐 앱에 간다
    let session = bench.sign_in_through("b", &host);
    let echo = send(
        &bench.listener("b"),
        &host,
        "GET",
        "/echo?q=1",
        &[("Cookie", &session)],
        &[],
    );
    assert_eq!(echo.status, 200, "{}", echo.text());
    let seen = echo.json();
    // 앱은 같은 Host 를 보고, 놓인 기계의 router 가 세션을 확인해 실은 신원만 본다. 레이어의 쿠키는 앱에 닿지 않는다
    assert_eq!(seen["host"], json!(host));
    assert_eq!(seen["path"], json!("/echo?q=1"));
    assert!(seen["layer"]["x-orbital-identity"].is_string(), "{seen}");
    assert_eq!(
        seen["layer"].as_object().unwrap().len(),
        1,
        "신원 밖의 x-orbital- 머리말이 앱에 닿았습니다: {seen}"
    );
    assert_eq!(seen["cookie"], Value::Null);
    // a 에서 받은 쿠키도 b 를 거쳐 그대로 통하고, b 에서 받은 쿠키도 a 에서 통한다
    let there = bench.sign_in_through("a", &host);
    for (on, cookie) in [("b", &there), ("a", &session)] {
        let echo = send(
            &bench.listener(on),
            &host,
            "GET",
            "/echo",
            &[("Cookie", cookie)],
            &[],
        );
        assert!(
            echo.json()["layer"]["x-orbital-identity"].is_string(),
            "{on}: {}",
            echo.text()
        );
    }
    // 쿠키 없이 오면 신원이 없다
    let anonymous = send(&bench.listener("b"), &host, "GET", "/echo", &[], &[]);
    assert_eq!(anonymous.status, 200, "{}", anonymous.text());
    assert_eq!(anonymous.json()["layer"], json!({}));
}

#[test]
fn 넘기는_쪽과_받는_쪽_모두_밖에서_온_x_orbital_머리말을_지우고_고리_막기_머리말은_앱에_닿지_않는다()
 {
    let mut bench = bench!(true);
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    let (_, host) = bench.relay_preview();
    let session = bench.sign_in_through("b", &host);
    let forged = [
        ("x-orbital-identity", "v2.forged.forged"),
        ("x-orbital-schedule", "web:/jobs/tick"),
        ("X-Orbital-Stage", "production"),
    ];
    // 세션 없이 위조한 머리말만 싣는다: 앱은 x-orbital- 머리말을 하나도 보지 못한다
    let anonymous = send(&bench.listener("b"), &host, "GET", "/echo", &forged, &[]);
    assert_eq!(anonymous.status, 200, "{}", anonymous.text());
    assert_eq!(anonymous.json()["layer"], json!({}), "{}", anonymous.text());
    // 세션과 함께 실어도 앱이 보는 신원은 router 가 서명한 것이다
    let mut with_session = forged.to_vec();
    with_session.push(("Cookie", &session));
    let signed = send(
        &bench.listener("b"),
        &host,
        "GET",
        "/echo",
        &with_session,
        &[],
    );
    let layer = signed.json()["layer"].clone();
    assert!(layer["x-orbital-identity"].is_string(), "{}", signed.text());
    assert_ne!(layer["x-orbital-identity"], json!("v2.forged.forged"));
    assert_eq!(layer.as_object().unwrap().len(), 1, "{layer}");
}

#[test]
fn 밖에서_고리_막기_머리말을_붙여_다른_기계의_하위_도메인으로_보내면_넘기지_않고_놓인_기계에서도_아무_권한이_없다()
 {
    let mut bench = bench!(true);
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    let (_, host) = bench.relay_preview();
    let refused = send(
        &bench.listener("b"),
        &host,
        "GET",
        "/echo",
        &[(FORWARDED_BY, "c")],
        &[],
    );
    assert_eq!(refused.status, 404, "{}", refused.text());
    // 놓인 기계에 바로 붙여 보내도 머리말은 앱에 닿지 않고 신원도 생기지 않는다
    let direct = send(
        &bench.listener("a"),
        &host,
        "GET",
        "/echo",
        &[(FORWARDED_BY, "b")],
        &[],
    );
    assert_eq!(direct.status, 200, "{}", direct.text());
    assert_eq!(direct.json()["layer"], json!({}));
}

#[test]
fn 큰_본문과_흘려_보내는_답과_깨우지_못한_503_도_넘겨_준다() {
    let mut bench = bench!(true);
    bench.boot("a", Address::Own, Address::Own);
    bench.boot("b", Address::Own, Address::Own);
    let (instance, host) = bench.relay_preview();
    // 큰 본문: 8MiB 가 그대로 앱에 닿는다
    let body: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|at: usize| (at % 251) as u8)
        .collect();
    let echo = send(
        &bench.listener("b"),
        &host,
        "POST",
        "/echo",
        &[("Content-Type", "application/octet-stream")],
        &body,
    );
    assert_eq!(echo.status, 200, "{}", echo.text());
    assert_eq!(echo.json()["length"], json!(body.len()));
    let digest = {
        use sha2::Digest as _;
        orbital_server::token::hex(&sha2::Sha256::digest(&body))
    };
    assert_eq!(echo.json()["sha256"], json!(digest));
    // 흘려 보내기: 앱이 첫 조각을 보낸 뒤 끝 조각을 1.5초 늦게 보내도 첫 조각은 그 전에 닿는다
    let mut stream = TcpStream::connect(bench.listener("b")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .write_all(
            format!("GET /stream HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let started = std::time::Instant::now();
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !String::from_utf8_lossy(&seen).contains("first") {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "첫 조각 전에 끝났습니다");
        seen.extend_from_slice(&buffer[..read]);
    }
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "첫 조각이 {:?} 뒤에 왔습니다",
        started.elapsed()
    );
    stream.read_to_end(&mut seen).unwrap();
    assert!(String::from_utf8_lossy(&seen).contains("last"));
    // 앱의 503 과 Retry-After 가 그대로 온다
    let busy = send(&bench.listener("b"), &host, "GET", "/busy", &[], &[]);
    assert_eq!(busy.status, 503, "{}", busy.text());
    assert_eq!(busy.header("retry-after"), Some("7"));
    // 놓인 기계의 router 가 깨우지 못한 503 과 Retry-After 도 그대로 온다. 서비스가 잠든 뒤 뜨지 못하게 한다
    let server = find(&bench.home("a").join("builds").join(&instance), "server.js")
        .expect("빌드 폴더에 server.js 가 없습니다");
    fs::write(server.with_file_name("down"), "").unwrap();
    // 요청이 없으면 0.8초 뒤에 잠든다
    std::thread::sleep(Duration::from_secs(3));
    let waking = send(&bench.listener("b"), &host, "GET", "/echo", &[], &[]);
    assert_eq!(waking.status, 503, "{}", waking.text());
    assert_eq!(waking.json()["error"], json!("waking"), "{}", waking.text());
    assert_eq!(waking.header("retry-after"), Some("2"));
}

/// `folder` 아래에서 이름이 `name` 인 파일을 찾는다.
fn find(folder: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(folder).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find(&path, name) {
                return Some(found);
            }
        } else if entry.file_name() == name {
            return Some(path);
        }
    }
    None
}

#[test]
fn 놓인_기계의_listener_주소를_모르면_고객의_요청을_넘기지_않고_404_다() {
    let mut bench = bench!(true);
    bench.boot("a", Address::Own, Address::None);
    bench.boot("b", Address::Own, Address::Own);
    let (_, host) = bench.relay_preview();
    let refused = send(&bench.listener("b"), &host, "GET", "/echo", &[], &[]);
    assert_eq!(refused.status, 404, "{}", refused.text());
    assert_eq!(
        send(&bench.listener("a"), &host, "GET", "/echo", &[], &[]).status,
        200
    );
}
