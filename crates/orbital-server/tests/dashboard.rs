//! 대시보드가 올라설 조회 API. 함대의 목록 · 인스턴스 하나 · release 의 이력 · 운영의 로그와 서비스의 상태 · 연결된 클라이언트 ·
//! 조직의 모습 · rollout 의 목록. 같은 control database 를 보는 관리 서버 둘(기계 `a` · `b`)을 실제 HTTP 로 띄워 잰다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버)로 잰다. 막는 테스트는 그 열쇠로 실제로 두드려 본다.
//! 테스트의 열쇠와 비밀은 한눈에 가짜인 글자다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_core::name::Ident;
use orbital_run::LocalRunner;
use orbital_server::http::{answer, handle};
use orbital_server::layer::{Layer, Options};
use orbital_server::records::drop_database;
use orbital_server::seal::SealKey;
use postgres::{Client, Config, NoTls};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const OTHER: &str = "sk_test_other";
const ADMIN: &str = "admin_key_for_tests_0123456789abcdef";
const TOKEN_KEY: [u8; 32] = [3; 32];
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
/// 운영의 밖에서 넣는 비밀. 어떤 답에도 나오면 안 된다.
const BANK: &str = "sk_live_bank_Dash7qZt0Xw";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

fn git(folder: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(folder)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
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

/// 실제 HTTP 로 GET 한다(앱의 주소).
fn http_get(url: &str) -> u16 {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    match agent.get(url).call() {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(status, _)) => status,
        Err(error) => panic!("GET {url}: {error}"),
    }
}

/// 관리 서버 앞의 받기 고리.
struct Front {
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl Front {
    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
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
    });
    Front {
        stop,
        task: Some(task),
    }
}

struct Machine {
    layer: Arc<Layer>,
    front: Front,
}

/// 같은 control database 를 보는 관리 서버들. 모두 실제 포트를 듣고 서로의 주소를 기록에 적는다.
struct Bench {
    scratch: PathBuf,
    pg_url: String,
    control: Ident,
    machines: BTreeMap<String, Machine>,
    /// (인스턴스, 놓인 기계, service key). 끝날 때 걷는다.
    instances: Vec<(String, String, String)>,
    /// 요청이 없으면 서버 서비스를 재우기까지의 시간.
    sleep_after: Duration,
    /// 운영의 서버 로그를 내주는 레이어인가(레이어의 운영자가 켜는 것). 기본은 켠 것으로 재고, 꺼진 레이어는 따로 잰다.
    production_logs: bool,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-dashboard-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        Some(Self {
            scratch,
            pg_url,
            control: fresh_name("ctl"),
            machines: BTreeMap::new(),
            instances: Vec::new(),
            sleep_after: Duration::from_secs(60),
            production_logs: true,
        })
    }

    fn boot(&mut self, name: &str) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let options = Options {
            seal_key: Some(SealKey::from_bytes([7; 32])),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(name).unwrap(),
            token_key: Some(TOKEN_KEY.to_vec()),
            machine_url: Some(url),
            admin_key: Some(ADMIN.to_owned()),
            test_instance_limit: 7,
            sleep_after: self.sleep_after,
            wake_timeout: Duration::from_secs(10),
            webhook_every: None,
            production_logs: self.production_logs,
            ..Options::new(
                self.home(name),
                self.pg_url.clone(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        };
        let layer = Arc::new(Layer::open(options).expect("레이어를 열지 못했습니다"));
        let front = front(Arc::clone(&layer), server);
        self.machines
            .insert(name.to_owned(), Machine { layer, front });
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    fn layer(&self, name: &str) -> &Layer {
        &self.machines[name].layer
    }

    /// (상태, 본문의 JSON, 본문의 날것).
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

    fn get(&self, on: &str, path: &str, bearer: &str) -> Value {
        let (status, body) = self.call(on, "GET", path, bearer, &[]);
        assert_eq!(status, 200, "{path}: {body}");
        body
    }

    fn post(&self, on: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
        self.call(on, "POST", path, bearer, body.to_string().as_bytes())
    }

    /// 스캐폴드를 올린다. `crash` 면 운영에서만 뜨지 않는 서버다.
    fn upload(&self, on: &str, key: &str, app: &str, crash: bool) {
        let folder = self.scratch.join(format!(
            "scaffold-{app}-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/records"),
            &folder,
        );
        if crash {
            crash_in_production(&folder);
        }
        git(&folder, &["init", "--quiet"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = folder.with_extension("bundle");
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
            &format!("/v1/apps/{app}"),
            key,
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn instance(&mut self, on: &str, key: &str, app: &str) -> String {
        let (status, body) = self.post(
            on,
            "/v1/instances",
            key,
            &json!({ "app": app, "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        let placed = if self
            .layer(on)
            .records()
            .instance(&instance)
            .unwrap()
            .unwrap()
            .machine
            == "b"
        {
            "b"
        } else {
            "a"
        };
        self.instances
            .push((instance.clone(), placed.to_owned(), key.to_owned()));
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

    /// 프리뷰를 세우고 승격을 요청해 운영에 올려 본다. (release, 승격의 답의 상태, 답).
    fn ship(
        &self,
        on: &str,
        instance: &str,
        token: &str,
        approver: Option<&str>,
    ) -> (String, u16, Value) {
        let path = |tail: &str| format!("/v1/instances/{instance}{tail}");
        let (status, preview) = self.call(on, "POST", &path("/previews"), token, &[]);
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, body) = self.call(
            on,
            "PUT",
            &path("/secrets/BANK_API_KEY"),
            FACTORY,
            json!({ "stage": "production", "value": BANK })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(status, 200, "{body}");
        let (status, rehearsal) = self.post(
            on,
            &path("/rehearsals"),
            token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{rehearsal}");
        let (status, body) = self.post(
            on,
            &path("/promotion-requests"),
            token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let mut request =
            json!({ "release": release, "change": "customer_request", "approved_by": "customer" });
        if let Some(approver) = approver {
            request["approver"] = json!(approver);
        }
        let (status, body) = self.post(on, &path("/promotions"), FACTORY, &request);
        (release, status, body)
    }

    /// 에이전트가 하듯이 코드를 받아 고치고 묶음으로 올린다.
    fn change(&self, on: &str, instance: &str, token: &str, edit: impl FnOnce(&Path)) {
        let reply = handle(
            self.layer(on),
            "GET",
            &format!("/v1/instances/{instance}/source"),
            Some(token),
            &[],
        );
        assert_eq!(reply.status, 200);
        let label = COUNTER.fetch_add(1, Ordering::Relaxed);
        let bundle = self.scratch.join(format!("pull-{label}.bundle"));
        fs::write(&bundle, reply.body).unwrap();
        let work = self.scratch.join(format!("work-{label}"));
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
        git(&work, &["commit", "--quiet", "-m", "고침"]);
        let pushed = self.scratch.join(format!("push-{label}.bundle"));
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
            on,
            "POST",
            &format!("/v1/instances/{instance}/source"),
            token,
            &fs::read(pushed).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn control(&self) -> Client {
        let mut config: Config = self.pg_url.parse().unwrap();
        config.dbname(self.control.as_str());
        config.connect(NoTls).unwrap()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // 레이어로 지우면 떠 있는 프리뷰의 database 도 함께 걷힌다. 남은 것은 관리 역할로 걷는다
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

/// 운영에서만 뜨지 않는 서버로 바꾼다.
fn crash_in_production(folder: &Path) {
    let server = fs::read_to_string(folder.join("server.js")).unwrap();
    fs::write(
        folder.join("server.js"),
        format!("if (process.env.ORBITAL_STAGE === \"production\") process.exit(1);\n{server}"),
    )
    .unwrap();
}

/// 함대의 쪽을 끝까지 따라가며 받은 인스턴스의 식별자.
fn walk(bench: &Bench, on: &str, key: &str, limit: u32) -> Vec<String> {
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let query = match &after {
            Some(next) => format!("?limit={limit}&after={next}"),
            None => format!("?limit={limit}"),
        };
        let page = bench.get(on, &format!("/v1/instances{query}"), key);
        let rows = page["instances"].as_array().unwrap();
        assert!(rows.len() <= limit as usize);
        seen.extend(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap().to_owned()),
        );
        if page["has_more"] != true {
            return seen;
        }
        after = Some(page["next"].as_str().unwrap().to_owned());
    }
}

// ---- 함대 ----

#[test]
fn 함대의_목록은_자기_조직의_인스턴스만_만든_차례로_쪽을_나눠_주고_다른_조직의_표식으로는_아무것도_엿보지_못한다()
 {
    let mut bench = bench!();
    bench.boot("a");
    bench.boot("b");
    bench.upload("a", FACTORY, "records", false);
    bench.upload("a", OTHER, "records", false);
    let ours: Vec<String> = (0..5)
        .map(|_| bench.instance("a", FACTORY, "records"))
        .collect();
    let theirs: Vec<String> = (0..2)
        .map(|_| bench.instance("a", OTHER, "records"))
        .collect();
    // 같은 초에 섰으면 식별자의 차례다. 만든 차례(때, 식별자)로 온다
    let mut expected = ours.clone();
    let created: BTreeMap<String, u64> =
        bench.get("a", "/v1/instances?limit=500", FACTORY)["instances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["id"].as_str().unwrap().to_owned(),
                    row["created_at"].as_u64().unwrap(),
                )
            })
            .collect();
    expected.sort_by_key(|id| (created[id], id.clone()));
    // 한 쪽에 둘씩, 끝까지 따라가면 빠짐도 겹침도 없다. 다른 관리 서버도 같은 것을 답한다
    assert_eq!(walk(&bench, "a", FACTORY, 2), expected);
    assert_eq!(walk(&bench, "b", FACTORY, 2), expected);
    assert_eq!(walk(&bench, "a", FACTORY, 500), expected);
    assert_eq!(walk(&bench, "a", OTHER, 1).len(), 2);
    for id in &theirs {
        assert!(!expected.contains(id));
    }
    // 다른 조직의 인스턴스로 지은 표식을 넣어도 다른 조직의 것은 나오지 않는다(자기 것의 그 자리 뒤만)
    let their_cursor = format!("0.{}", theirs[0]);
    let page = bench.get(
        "a",
        &format!("/v1/instances?after={their_cursor}&limit=500"),
        FACTORY,
    );
    for row in page["instances"].as_array().unwrap() {
        assert!(
            ours.contains(&row["id"].as_str().unwrap().to_owned()),
            "{row}"
        );
    }
    // 마지막 쪽의 표식 뒤는 비었고, 표식은 그대로 돌아온다
    let last = bench.get("a", "/v1/instances?limit=500", FACTORY);
    let next = last["next"].as_str().unwrap().to_owned();
    let empty = bench.get("a", &format!("/v1/instances?after={next}"), FACTORY);
    assert_eq!(empty["instances"], json!([]));
    assert_eq!(empty["next"], json!(next));
    assert_eq!(empty["has_more"], false);
    // 틀린 질의는 고칠 것을 모두 알린다
    let (status, body) = bench.call("a", "GET", "/v1/instances?after=1&limit=0", FACTORY, &[]);
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["details"].as_array().unwrap().len(), 2);
    // 작업의 토큰과 운영자 키는 목록을 열지 못한다
    let token = bench.token("a", FACTORY, &ours[0]);
    assert_eq!(bench.call("a", "GET", "/v1/instances", &token, &[]).0, 404);
    assert_eq!(bench.call("a", "GET", "/v1/instances", ADMIN, &[]).0, 403);
}

#[test]
fn 함대의_한_줄은_갈라진_버전과_만든_때와_운영의_release_와_오른_때와_기다리는_요청과_프리뷰를_싣고_다른_조직의_인스턴스는_없는_것과_같다()
 {
    let mut bench = bench!();
    bench.boot("a");
    bench.boot("b");
    bench.upload("a", FACTORY, "records", false);
    let before = now();
    let instance = bench.instance("a", FACTORY, "records");
    let row = bench.get("b", &format!("/v1/instances/{instance}"), FACTORY);
    assert_eq!(row["id"], json!(instance));
    assert_eq!(row["app"], "records");
    assert_eq!(row["version"], "v1");
    assert_eq!(row["machine"], "a");
    assert!(row["created_at"].as_u64().unwrap() >= before, "{row}");
    assert_eq!(row["production"], Value::Null);
    assert_eq!(row["promotion_requested"], Value::Null);
    assert_eq!(row["preview"], false);
    assert_eq!(row["last_promotion"], Value::Null);

    let token = bench.token("a", FACTORY, &instance);
    let (release, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    let row = bench.get("b", &format!("/v1/instances/{instance}"), FACTORY);
    assert_eq!(row["production"]["release"], json!(release));
    assert!(
        row["production"]["promoted_at"].as_u64().unwrap() >= before,
        "{row}"
    );
    assert_eq!(row["preview"], true);
    assert_eq!(row["promotion_requested"], Value::Null);
    assert_eq!(row["last_promotion"]["outcome"], "promoted");
    assert_eq!(row["last_promotion"]["release"], json!(release));
    // 승격을 기다리는 요청은 다른 관리 서버의 목록에도 바로 보인다
    bench.change("a", &instance, &token, |work| {
        fs::write(work.join("NOTE.md"), "고침\n").unwrap();
    });
    let (status, preview) = bench.call(
        "a",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{preview}");
    let waiting = preview["release"].as_str().unwrap().to_owned();
    let (status, body) = bench.post(
        "a",
        &format!("/v1/instances/{instance}/promotion-requests"),
        &token,
        &json!({ "release": waiting }),
    );
    assert_eq!(status, 200, "{body}");
    let listed = bench.get("b", "/v1/instances", FACTORY);
    assert_eq!(
        listed["instances"][0]["promotion_requested"],
        json!(waiting)
    );
    // 프리뷰를 걷으면 프리뷰가 없다
    let (status, body) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        bench.get("b", &format!("/v1/instances/{instance}"), FACTORY)["preview"],
        false
    );
    // 다른 조직에게는 없는 것과 같다. 목록에도 없다
    let (status, body) = bench.call("b", "GET", &format!("/v1/instances/{instance}"), OTHER, &[]);
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        bench.get("b", "/v1/instances", OTHER)["instances"],
        json!([])
    );
    // 값은 어디에도 없다
    let (_, _, raw) = bench.raw("b", "GET", "/v1/instances", FACTORY, &[]);
    assert!(!raw.contains(BANK));
}

// ---- release 의 이력 ----

#[test]
fn 승격과_되돌려진_승격이_이력에_차례대로_쌓이고_승인과_요청과_검사와_리허설의_숫자와_권한의_변화를_싣되_값은_싣지_않는다()
 {
    let mut bench = bench!();
    bench.boot("a");
    bench.boot("b");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let work = orbital_server::token::session_of(&token);
    let history = |on: &str, query: &str| {
        bench.get(
            on,
            &format!("/v1/instances/{instance}/history{query}"),
            FACTORY,
        )
    };
    assert_eq!(history("b", "")["history"], json!([]));

    // 첫 승격: 운영이 없어 리허설이 필요 없다
    let before = now();
    let (first, status, body) = bench.ship("a", &instance, &token, Some("고객사 담당자 7"));
    assert_eq!(status, 200, "{body}");
    // 둘째 승격: 마이그레이션 하나와 권한 하나를 더한다. 리허설의 숫자가 남는다
    bench.change("a", &instance, &token, |work| {
        fs::write(
            work.join("db/migrations/002_memo.sql"),
            "CREATE TABLE ledger.memo (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body text NOT NULL);\n",
        )
        .unwrap();
        let access = fs::read_to_string(work.join("db/access.toml")).unwrap();
        fs::write(
            work.join("db/access.toml"),
            format!("{access}\n[ledger.memo]\nrls = \"off: 시험용 앱의 표\"\nmember = \"read\"\n"),
        )
        .unwrap();
    });
    let (second, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    // 셋째 승격: 운영에서 뜨지 않는 서버. 되돌려진다
    bench.change("a", &instance, &token, crash_in_production);
    let (third, status, body) = bench.ship("a", &instance, &token, None);
    assert_ne!(status, 200, "{body}");

    // 다른 관리 서버가 바로 본다
    let all = history("b", "");
    let lines = all["history"].as_array().unwrap();
    assert_eq!(lines.len(), 3, "{all}");
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["promoted", "promoted", "rolled_back"]);
    let numbers: Vec<u64> = lines
        .iter()
        .map(|line| line["n"].as_u64().unwrap())
        .collect();
    assert_eq!(numbers, [1, 2, 3]);
    assert!(
        lines
            .iter()
            .all(|line| line["at"].as_u64().unwrap() >= before)
    );

    let one = &lines[0];
    assert_eq!(one["release"], json!(first));
    assert_eq!(one["previous_release"], Value::Null);
    assert_eq!(one["change"], "customer_request");
    assert_eq!(one["approved_by"], "customer");
    assert_eq!(one["approver"], "고객사 담당자 7");
    assert_eq!(one["requested_by"], json!(work));
    assert!(one["requested_at"].as_u64().unwrap() >= before);
    assert_eq!(one["access_findings"], 0);
    assert_eq!(one["rehearsal"], "not_needed");
    assert_eq!(one["rehearsed"], Value::Null);
    assert_eq!(one["migrations"], 1);
    assert!(
        one["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sentence| sentence.as_str().unwrap().contains("ledger.transfer")),
        "{one}"
    );

    let two = &lines[1];
    assert_eq!(two["release"], json!(second));
    assert_eq!(two["previous_release"], json!(first));
    assert_eq!(two["approver"], Value::Null);
    assert_eq!(two["rehearsal"], "passed");
    assert!(two["rehearsed"]["millis"].as_u64().is_some(), "{two}");
    assert!(
        two["rehearsed"]["tables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|table| table["table"] == "ledger.transfer"),
        "{two}"
    );
    assert_eq!(two["migrations"], 1);
    // 권한의 변화는 승인 카드의 문장이다: 앞의 운영과 견주어 더한 표만 말한다
    let changes = two["changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .any(|sentence| sentence.as_str().unwrap().contains("ledger.memo")),
        "{two}"
    );
    assert!(
        !changes
            .iter()
            .any(|sentence| sentence.as_str().unwrap().contains("ledger.transfer")),
        "{two}"
    );

    let three = &lines[2];
    assert_eq!(three["release"], json!(third));
    assert_eq!(three["previous_release"], json!(second));
    assert_eq!(three["migrated"], false);
    // 함대의 줄은 실패한 곳을 알리고 운영은 앞의 것 그대로다
    let row = bench.get("b", &format!("/v1/instances/{instance}"), FACTORY);
    assert_eq!(row["last_promotion"]["outcome"], "rolled_back");
    assert_eq!(row["last_promotion"]["release"], json!(third));
    assert_eq!(row["production"]["release"], json!(second));

    // 이어 받기
    let page = history("b", "?limit=2");
    assert_eq!(page["history"].as_array().unwrap().len(), 2);
    assert_eq!(page["has_more"], true);
    assert_eq!(page["next"], 2);
    let rest = history("b", "?after=2");
    assert_eq!(rest["history"][0]["n"], 3);
    assert_eq!(rest["has_more"], false);
    let (status, body) = bench.call(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/history?after=x"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 422, "{body}");

    // 값은 이력의 답에도 기록의 줄에도 없다
    let (_, _, raw) = bench.raw(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/history"),
        FACTORY,
        &[],
    );
    assert!(!raw.contains(BANK));
    assert!(!raw.contains(&token));
    let stored: Vec<String> = bench
        .control()
        .query("SELECT body::text FROM orbital.release_history", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(stored.len(), 3);
    assert!(
        stored
            .iter()
            .all(|text| !text.contains(BANK) && !text.contains(&token))
    );

    // 다른 조직 · 작업의 토큰 · 운영자 키는 이력을 보지 못한다
    assert_eq!(
        bench
            .call(
                "b",
                "GET",
                &format!("/v1/instances/{instance}/history"),
                OTHER,
                &[]
            )
            .0,
        404
    );
    assert_eq!(
        bench
            .call(
                "b",
                "GET",
                &format!("/v1/instances/{instance}/history"),
                &token,
                &[]
            )
            .0,
        404
    );
    assert_eq!(
        bench
            .call(
                "b",
                "GET",
                &format!("/v1/instances/{instance}/history"),
                ADMIN,
                &[]
            )
            .0,
        403
    );
    // 승인한 사람의 이름표가 틀리면 올리지 않고 고칠 것을 알린다
    let (status, body) = bench.post(
        "a",
        &format!("/v1/instances/{instance}/promotions"),
        FACTORY,
        &json!({ "release": second, "change": "customer_request", "approved_by": "customer", "approver": "줄\n바꿈" }),
    );
    assert_eq!(status, 422, "{body}");
    assert_eq!(history("a", "")["history"].as_array().unwrap().len(), 3);
}

#[test]
fn 이력은_인스턴스를_지우면_함께_지워지고_보관의_상한을_넘으면_오랜_것부터_걷힌다() {
    use orbital_core::history::{Entry, KEEP};

    let mut bench = bench!();
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let records = bench.layer("a").records();
    let restored = |at: u64| Entry::Restored {
        release: "r_x".to_owned(),
        to: at,
    };
    // 상한까지 쌓는다. 상한에서는 하나도 걷히지 않는다
    for at in 1..=KEEP {
        records
            .update_instance_logged(&instance, at, |_, _, entries| {
                entries.push(restored(at));
                Ok::<(), orbital_server::records::RecordError>(())
            })
            .unwrap()
            .unwrap();
    }
    let count = || -> (i64, i64) {
        let row = bench
            .control()
            .query_one(
                "SELECT count(*), coalesce(min(n), 0) FROM orbital.release_history",
                &[],
            )
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(count(), (i64::try_from(KEEP).unwrap(), 1));
    // 하나를 더 쌓으면 가장 오랜 하나가 걷힌다
    records
        .update_instance_logged(&instance, KEEP + 1, |_, _, entries| {
            entries.push(restored(KEEP + 1));
            Ok::<(), orbital_server::records::RecordError>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(count(), (i64::try_from(KEEP).unwrap(), 2));
    // 고침이 거절되면 이력도 남지 않는다
    let refused: Result<Option<()>, orbital_server::records::RecordError> = records
        .update_instance_logged(&instance, KEEP + 2, |_, _, entries| {
            entries.push(restored(KEEP + 2));
            Err(orbital_server::records::RecordError("거절".to_owned()))
        });
    assert!(refused.is_err());
    assert_eq!(count(), (i64::try_from(KEEP).unwrap(), 2));
    // 인스턴스를 지우면 이력도 함께 지워진다
    let (status, body) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{instance}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let left = count().0;
    bench.instances.clear();
    assert_eq!(left, 0);
}

// ---- 운영의 로그와 서비스의 상태 ----

#[test]
fn 운영자가_켜지_않은_레이어는_서버가_찍은_로그를_service_key_에도_내주지_않고_빌드의_로그만_내준다()
 {
    let mut bench = bench!();
    bench.production_logs = false;
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let (_, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    // 앱을 깨워 서버의 로그 파일에 글이 있게 한다
    let production = bench.get(
        "a",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
    );
    let url = production["services"][0]["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let _ = ureq::get(&url).timeout(Duration::from_secs(30)).call();
    let log_file_has_text = {
        let mut found = false;
        let mut stack = vec![bench.home("a").join("logs").join(&instance)];
        while let Some(folder) = stack.pop() {
            for entry in fs::read_dir(&folder).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("production-")
                {
                    found |= fs::metadata(&path).is_ok_and(|meta| meta.len() > 0);
                }
            }
        }
        found
    };
    assert!(
        log_file_has_text,
        "서버의 로그 파일에 글이 없어 잴 것이 없습니다"
    );

    let shown = bench.get(
        "a",
        &format!("/v1/instances/{instance}/production/logs"),
        FACTORY,
    );
    assert_eq!(shown["server_logs"], json!(false), "{shown}");
    let names: Vec<&str> = shown["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| log["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["build-web"], "{shown}");
    // 서비스의 상태(이름뿐)는 그대로 보인다
    let services = bench.get(
        "a",
        &format!("/v1/instances/{instance}/production/services"),
        FACTORY,
    );
    assert_eq!(services["services"][0]["name"], "web", "{services}");
}

#[test]
fn 운영의_로그는_service_key_로만_보고_작업의_토큰과_운영자의_열쇠와_다른_조직의_열쇠로는_보지_못한다()
 {
    let mut bench = bench!();
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let logs = format!("/v1/instances/{instance}/production/logs");
    let services = format!("/v1/instances/{instance}/production/services");
    // 운영이 없으면 까닭과 함께 409 다
    let (status, body) = bench.call("a", "GET", &logs, FACTORY, &[]);
    assert_eq!(status, 409, "{body}");
    let (release, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    let shown = bench.get("a", &logs, FACTORY);
    assert_eq!(shown["release"], json!(release));
    let names: Vec<&str> = shown["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| log["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["build-web", "production-web"]);
    // 작업의 토큰은 어떤 능력으로도 운영의 로그와 상태에 닿지 못한다(프리뷰의 로그는 그대로 열려 있다)
    for path in [&logs, &services] {
        let (status, body) = bench.call("a", "GET", path, &token, &[]);
        assert_eq!(status, 403, "{path}: {body}");
        assert!(!body.to_string().contains("production-web"), "{body}");
    }
    let (status, body) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/previews/logs"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    // 운영자 키는 열지 못하고, 다른 조직에게는 없는 것과 같다
    for path in [&logs, &services] {
        assert_eq!(bench.call("a", "GET", path, ADMIN, &[]).0, 403);
        assert_eq!(bench.call("a", "GET", path, OTHER, &[]).0, 404);
    }
    // 열쇠가 없으면 401 이다
    let reply = handle(bench.layer("a"), "GET", &logs, None, &[]);
    assert_eq!(reply.status, 401);
}

#[test]
fn 운영의_로그는_줄_수와_한_줄의_길이에_상한이_있고_레이어의_경로를_가린다() {
    use orbital_core::fleet::{LOG_LINE_MAX, LOG_LINES_MAX};

    let mut bench = bench!();
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let (release, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    // 앱이 찍은 것처럼 서버의 로그에 줄을 더한다: 많은 줄, 레이어의 폴더 경로, 아주 긴 줄
    let file = bench
        .home("a")
        .join("logs")
        .join(&instance)
        .join(&release)
        .join("production-web.log");
    let home = bench.home("a").display().to_string();
    let mut text = fs::read_to_string(&file).unwrap_or_default();
    for at in 0..(LOG_LINES_MAX + 50) {
        text.push_str(&format!("줄 {at}\n"));
    }
    text.push_str(&format!("열었습니다 {home}/builds/{instance}\n"));
    text.push_str(&format!("{}\n", "가".repeat(LOG_LINE_MAX + 10)));
    fs::write(&file, text).unwrap();

    let read = |query: &str| -> Value {
        let shown = bench.get(
            "a",
            &format!("/v1/instances/{instance}/production/logs{query}"),
            FACTORY,
        );
        shown["logs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|log| log["name"] == "production-web")
            .unwrap()
            .clone()
    };
    // 기본은 끝의 200줄이다
    let fallback = read("");
    assert_eq!(fallback["text"].as_str().unwrap().lines().count(), 200);
    // 상한까지는 달라는 만큼, 그 위는 받지 않는다
    let most = read(&format!("?lines={LOG_LINES_MAX}"));
    let lines: Vec<&str> = most["text"].as_str().unwrap().lines().collect();
    assert_eq!(lines.len(), LOG_LINES_MAX as usize);
    let (status, body) = bench.call(
        "a",
        "GET",
        &format!(
            "/v1/instances/{instance}/production/logs?lines={}",
            LOG_LINES_MAX + 1
        ),
        FACTORY,
        &[],
    );
    assert_eq!(status, 422, "{body}");
    // 경로는 가리고, 긴 줄은 상한에서 자르며 자른 수를 알린다
    let tail = read("?lines=2");
    let text = tail["text"].as_str().unwrap();
    assert!(!text.contains(&home), "{text}");
    assert!(
        text.contains(&format!("<레이어>/builds/{instance}")),
        "{text}"
    );
    let long = text.lines().last().unwrap();
    assert!(
        long.chars().count() <= LOG_LINE_MAX + orbital_core::fleet::CLIPPED_MARK.chars().count()
    );
    assert!(long.ends_with(orbital_core::fleet::CLIPPED_MARK));
    assert_eq!(tail["clipped"], 1);
    // 운영의 비밀은 앱이 찍지 않았으니 없다(레이어가 더하지도 않는다)
    assert!(!most.to_string().contains(BANK));
}

#[test]
fn 서비스의_상태는_깨어_있으면_awake_자면_asleep_이다() {
    let mut bench = bench!();
    // 요청이 없으면 3초 뒤에 잔다. 그 안에 본 것은 깨어 있다
    bench.sleep_after = Duration::from_secs(3);
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let (release, status, production) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{production}");
    let path = format!("/v1/instances/{instance}/production/services");
    let state = || bench.get("a", &path, FACTORY);
    // 오른 직전에는 떠 있다
    let shown = state();
    assert_eq!(shown["release"], json!(release));
    assert_eq!(
        shown["services"],
        json!([{ "name": "web", "kind": "server", "state": "awake" }])
    );
    // 요청이 없으면 잔다
    let deadline = Instant::now() + Duration::from_secs(20);
    while state()["services"][0]["state"] != "asleep" {
        assert!(Instant::now() < deadline, "자지 않았습니다");
        std::thread::sleep(Duration::from_millis(100));
    }
    // 요청이 오면 다시 깬다
    let url = production["services"][0]["url"].as_str().unwrap();
    assert_eq!(http_get(url), 200);
    assert_eq!(state()["services"][0]["state"], "awake");
}

#[test]
fn 다른_기계에_놓인_인스턴스의_운영의_로그와_서비스의_상태는_놓인_기계로_넘겨져_답하고_목록과_이력은_받은_기계가_바로_답한다()
 {
    let mut bench = bench!();
    bench.boot("a");
    bench.boot("b");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("b", FACTORY, &instance);
    // b 가 받은 프리뷰와 승격은 a 로 넘겨진다
    let (release, status, body) = bench.ship("b", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    // 운영의 로그와 상태: b 가 받아 a 로 넘긴다. b 에는 로그의 폴더도 없다
    let logs = bench.get(
        "b",
        &format!("/v1/instances/{instance}/production/logs"),
        FACTORY,
    );
    assert_eq!(logs["release"], json!(release));
    assert!(!bench.home("b").join("logs").exists());
    let services = bench.get(
        "b",
        &format!("/v1/instances/{instance}/production/services"),
        FACTORY,
    );
    // 떠 있는 것은 a 의 메모리에만 있다. b 가 스스로 답했다면 `stopped` 다. b 에서 넣은 비밀의 알림이 a 의 서비스를 재웠을 수 있어 자는 것도 받는다
    let state = services["services"][0]["state"].as_str().unwrap();
    assert!(["awake", "asleep"].contains(&state), "{services}");
    // 다른 조직의 열쇠는 넘기기 전에 b 가 막는다
    assert_eq!(
        bench
            .call(
                "b",
                "GET",
                &format!("/v1/instances/{instance}/production/logs"),
                OTHER,
                &[]
            )
            .0,
        404
    );
    // 목록 · 하나 · 이력은 a 를 내려도 b 가 기록만으로 답한다
    bench.machines.get_mut("a").unwrap().front.halt();
    assert_eq!(
        walk(&bench, "b", FACTORY, 10),
        std::slice::from_ref(&instance)
    );
    assert_eq!(
        bench.get("b", &format!("/v1/instances/{instance}"), FACTORY)["production"]["release"],
        json!(release)
    );
    assert_eq!(
        bench.get("b", &format!("/v1/instances/{instance}/history"), FACTORY)["history"][0]["release"],
        json!(release)
    );
    // 놓인 기계에 닿지 못하면 로그는 502 로 알린다(빈 로그라고 답하지 않는다)
    let (status, body) = bench.call(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/production/logs"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["machine"], "a");
}

// ---- 연결된 클라이언트 · 조직 · rollout ----

#[test]
fn 연결된_클라이언트와_조직의_모습과_rollout_의_목록은_자기_조직의_것만_보인다() {
    let mut bench = bench!();
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let token = bench.token("a", FACTORY, &instance);
    let grants = format!("/v1/instances/{instance}/oauth-grants");
    // 운영이 서기 전에는 까닭과 함께 409 다
    assert_eq!(bench.call("a", "GET", &grants, FACTORY, &[]).0, 409);
    let (_, status, body) = bench.ship("a", &instance, &token, None);
    assert_eq!(status, 200, "{body}");
    assert_eq!(bench.get("a", &grants, FACTORY), json!({ "grants": [] }));
    assert_eq!(bench.call("a", "GET", &grants, OTHER, &[]).0, 404);
    assert_eq!(bench.call("a", "GET", &grants, &token, &[]).0, 404);
    assert_eq!(bench.call("a", "GET", &grants, ADMIN, &[]).0, 403);

    // 조직의 모습: 설정에만 있는 조직과 기록의 시험용 조직
    let configured = bench.get("a", "/v1/organization", FACTORY);
    assert_eq!(
        configured,
        json!({ "id": "factory", "name": null, "kind": "live", "created_at": null, "recorded": false, "instances": 1, "instance_limit": null })
    );
    let (status, made) = bench.post(
        "a",
        "/v1/admin/organizations",
        ADMIN,
        &json!({ "id": "acme", "label": "애크미 개발사", "kind": "test" }),
    );
    assert_eq!(status, 201, "{made}");
    let acme = made["key"]["secret"].as_str().unwrap().to_owned();
    let shown = bench.get("a", "/v1/organization", &acme);
    assert_eq!(shown["id"], "acme");
    assert_eq!(shown["name"], "애크미 개발사");
    assert_eq!(shown["kind"], "test");
    assert_eq!(shown["recorded"], true);
    assert_eq!(shown["instances"], 0);
    assert_eq!(shown["instance_limit"], 7);
    assert!(!shown.to_string().contains(&acme));
    assert_eq!(
        bench.call("a", "GET", "/v1/organization", &token, &[]).0,
        404
    );
    assert_eq!(
        bench.call("a", "GET", "/v1/organization", ADMIN, &[]).0,
        403
    );

    // rollout 의 목록: 만든 차례로, 자기 조직의 것만
    let records = bench.layer("a").records();
    let id = orbital_core::name::InstanceId::parse(&instance).unwrap();
    let rollout = |organization: &str| orbital_server::registry::RolloutRecord {
        organization: organization.to_owned(),
        rollout: orbital_core::rollout::Rollout::new(
            "records".to_owned(),
            "a".repeat(40),
            orbital_core::release::Change::SecurityUpdate,
            vec![vec![id.clone()]],
        )
        .unwrap(),
    };
    for (name, organization, at) in [
        ("r_one", "factory", 10),
        ("r_two", "factory", 20),
        ("r_theirs", "other", 15),
        ("r_three", "factory", 20),
    ] {
        records
            .insert_rollout_at(name, &rollout(organization), Some(at))
            .unwrap();
    }
    let first = bench.get("a", "/v1/rollouts?limit=2", FACTORY);
    let ids: Vec<&str> = first["rollouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["r_one", "r_three"]);
    assert_eq!(first["has_more"], true);
    let rest = bench.get(
        "a",
        &format!("/v1/rollouts?after={}", first["next"].as_str().unwrap()),
        FACTORY,
    );
    let ids: Vec<&str> = rest["rollouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["r_two"]);
    assert_eq!(
        rest["rollouts"][0]["instances"][0]["instance"],
        json!(instance)
    );
    let theirs = bench.get("a", "/v1/rollouts", OTHER);
    assert_eq!(theirs["rollouts"].as_array().unwrap().len(), 1);
    assert_eq!(theirs["rollouts"][0]["id"], "r_theirs");
    assert_eq!(bench.call("a", "GET", "/v1/rollouts", &token, &[]).0, 403);
}

#[test]
fn 기록을_읽지_못하면_목록과_이력과_조직의_모습을_빈_것이라고_답하지_않는다() {
    let mut bench = bench!();
    bench.boot("a");
    bench.upload("a", FACTORY, "records", false);
    let instance = bench.instance("a", FACTORY, "records");
    let away = |table: &str, back: bool| {
        let (from, to) = if back {
            (format!("{table}_away"), table.to_owned())
        } else {
            (table.to_owned(), format!("{table}_away"))
        };
        bench
            .control()
            .batch_execute(&format!("ALTER TABLE orbital.{from} RENAME TO {to}"))
            .unwrap();
    };
    away("release_history", false);
    let fleet = bench.call("a", "GET", "/v1/instances", FACTORY, &[]);
    let one = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}"),
        FACTORY,
        &[],
    );
    let history = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/history"),
        FACTORY,
        &[],
    );
    away("release_history", true);
    assert_eq!(fleet.0, 500, "{}", fleet.1);
    assert_eq!(one.0, 500, "{}", one.1);
    assert_eq!(history.0, 500, "{}", history.1);
    away("rollout", false);
    let rollouts = bench.call("a", "GET", "/v1/rollouts", FACTORY, &[]);
    away("rollout", true);
    assert_eq!(rollouts.0, 500, "{}", rollouts.1);
    away("instance", false);
    let organization = bench.call("a", "GET", "/v1/organization", FACTORY, &[]);
    away("instance", true);
    assert_eq!(organization.0, 500, "{}", organization.1);
    // 기록이 돌아오면 다시 된다
    assert_eq!(
        bench.get("a", "/v1/instances", FACTORY)["instances"][0]["id"],
        json!(instance)
    );
}

#[test]
fn 조직의_인스턴스_500개에서_한_쪽을_읽는_시간을_잰다() {
    let mut bench = bench!();
    bench.boot("a");
    // 인스턴스의 줄만 기록에 바로 넣는다(저장소와 DB 는 없다. 목록은 기록만 읽는다)
    let mut client = bench.control();
    client
        .batch_execute(
            "INSERT INTO orbital.instance (id, organization, app, machine, body, created_at)
             SELECT 'k' || lpad(g::text, 9, '0'), 'factory', 'records', 'a',
                    jsonb_build_object('version', 'v1', 'production', jsonb_build_object('release', 'r_' || g, 'promoted_at', 1900000000 + g)),
                    1900000000 + (g / 3)
             FROM generate_series(1, 500) g;
             INSERT INTO orbital.release_history (instance, n, kind, at, body)
             SELECT 'k' || lpad(g::text, 9, '0'), n, 'promoted', 1900000000 + n, jsonb_build_object('kind', 'promoted', 'release', 'r_' || n)
             FROM generate_series(1, 500) g, generate_series(1, 5) n;
             INSERT INTO orbital.instance (id, organization, app, machine, body, created_at)
             SELECT 'z' || lpad(g::text, 9, '0'), 'other', 'records', 'a', '{}'::jsonb, 1900000000 + g
             FROM generate_series(1, 500) g;
             ANALYZE orbital.instance; ANALYZE orbital.release_history;",
        )
        .unwrap();
    let measure = |query: &str, rounds: u32| -> (f64, Value) {
        let mut last = Value::Null;
        let started = Instant::now();
        for _ in 0..rounds {
            last = bench.get("a", &format!("/v1/instances{query}"), FACTORY);
        }
        (
            started.elapsed().as_secs_f64() * 1000.0 / f64::from(rounds),
            last,
        )
    };
    let (_, warm) = measure("?limit=100", 3);
    assert_eq!(warm["instances"].as_array().unwrap().len(), 100);
    let (hundred, first) = measure("?limit=100", 20);
    let middle = first["next"].as_str().unwrap().to_owned();
    let (after, page) = measure(&format!("?limit=100&after={middle}"), 20);
    assert_eq!(page["instances"].as_array().unwrap().len(), 100);
    let (all, whole) = measure("?limit=500", 10);
    assert_eq!(whole["instances"].as_array().unwrap().len(), 500);
    assert_eq!(whole["has_more"], false);
    assert_eq!(whole["instances"][0]["last_promotion"]["release"], "r_5");
    // 다른 조직의 줄은 섞이지 않는다
    assert!(
        whole["instances"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"].as_str().unwrap().starts_with('k'))
    );
    // 한 쪽만 읽는다: 질의의 계획이 조직의 색인으로 자른다
    let plan: Vec<String> = client
        .query(
            "EXPLAIN SELECT id FROM orbital.instance i WHERE i.organization = 'factory' AND (coalesce(i.created_at, 0), i.id) > (0, '') ORDER BY coalesce(i.created_at, 0), i.id LIMIT 101",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    eprintln!(
        "함대의 한 쪽(인스턴스 500 · 이력 2500): limit 100 첫 쪽 {hundred:.2}ms · 가운데 쪽 {after:.2}ms · limit 500 {all:.2}ms\n{}",
        plan.join("\n")
    );
    assert!(
        plan.iter().any(|line| line.contains("instance_listing")),
        "{plan:?}"
    );
    // 넣은 줄은 control database 와 함께 걷힌다(저장소와 DB 가 없어 레이어로 지우지 않는다)
}
