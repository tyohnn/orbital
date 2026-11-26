//! 레이어의 기록은 관리 서버의 파일이 아니라 control database 에 있다. 같은 control database 를 보는 관리 서버 둘(기계 `a` · `b`)을 띄워 잰다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버)로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에 바로 넣고, 띄운 앱에는 실제 HTTP 로
//! 요청한다. 관리 서버마다 자기 폴더(`ORBITAL_HOME`)를 갖는다. 기계가 다르면 코드 저장소와 빌드 폴더도 다르다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orbital_core::name::Ident;
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, Options};
use orbital_server::records::{Migration, Records, drop_database, ensure_database, migrate};
use orbital_server::registry::{InstanceRecord, ProductionRecord, ReleaseRecord};
use orbital_server::seal::{SealKey, binding, open, production_binding, seal, secret_binding};
use orbital_server::token::hex;
use postgres::{Client, Config, NoTls};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
const SEAL: [u8; 32] = [7; 32];
/// 모든 관리 서버가 같이 쓰는 토큰의 열쇠(`ORBITAL_TOKEN_KEY`).
const TOKEN_KEY: [u8; 32] = [3; 32];
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
/// 어디에 새어도 찾을 수 있게 드문 글자로 지은 값.
const BANK: &str = "sk_live_bank_Rc71pZt0qWe";
const MAIL_KEY: &str = "re_live_mail_Jh83sLq2vNx";

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

/// 띄운 앱에 실제 HTTP 로 묻는다. 닿지 않으면 `None` 이다.
fn get(url: &str) -> Option<(u16, Value)> {
    let response = match ureq::get(url).timeout(Duration::from_secs(30)).call() {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return None,
    };
    let status = response.status();
    Some((
        status,
        serde_json::from_str(&response.into_string().unwrap_or_default()).unwrap_or(Value::Null),
    ))
}

fn connect(pg_url: &str, database: &str) -> Client {
    let mut config: Config = pg_url.parse().unwrap();
    config.dbname(database);
    config.connect(NoTls).unwrap()
}

/// 테스트마다 다른 이름. `orbital_control` 과 겹치지 않는다.
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

/// 같은 control database 를 보는 관리 서버들.
struct Bench {
    scratch: PathBuf,
    pg_url: String,
    control: Ident,
    /// 레이어의 시계. 0 이면 실제 시각이다.
    clock: Arc<AtomicU64>,
    seal: Option<SealKey>,
    previous_seal: Option<SealKey>,
    /// 기계 → 관리 서버.
    servers: BTreeMap<String, Layer>,
    /// (인스턴스, 놓인 기계, service key). 끝날 때 걷는다.
    instances: Vec<(String, String, &'static str)>,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-records-{}-{}",
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
            seal: Some(SealKey::from_bytes(SEAL)),
            previous_seal: None,
            servers: BTreeMap::new(),
            instances: Vec::new(),
        })
    }

    fn home(&self, machine: &str) -> PathBuf {
        self.scratch.join(format!("home-{machine}"))
    }

    fn options(&self, machine: &str, home: PathBuf) -> Options {
        let clock = Arc::clone(&self.clock);
        Options {
            seal_key: self.seal.clone(),
            previous_seal_key: self.previous_seal.clone(),
            dev_mailbox: true,
            control_database: self.control.clone(),
            machine: Ident::parse(machine).unwrap(),
            token_key: Some(TOKEN_KEY.to_vec()),
            clock: Arc::new(move || match clock.load(Ordering::SeqCst) {
                0 => now(),
                at => at,
            }),
            schedule_timeout: Duration::from_secs(5),
            ..Options::new(
                home,
                self.pg_url.clone(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        }
    }

    /// 기계 `machine` 의 관리 서버를 띄운다.
    fn try_open(&self, machine: &str) -> Result<Layer, String> {
        Layer::open(self.options(machine, self.home(machine)))
    }

    fn open(&mut self, machine: &str) {
        self.open_as(machine, machine);
    }

    fn open_as(&mut self, name: &str, machine: &str) {
        let layer = self.try_open(machine).expect("레이어를 열지 못했습니다");
        self.servers.insert(name.to_owned(), layer);
    }

    fn shut(&mut self, name: &str) {
        drop(self.servers.remove(name));
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

    /// 팩토리가 스캐폴드를 그 관리 서버에 올린다.
    fn upload(&self, on: &str, key: &str) {
        let folder = self.scratch.join(format!("scaffold-{on}-{key}"));
        let _ = fs::remove_dir_all(&folder);
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/records"),
            &folder,
        );
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{on}-{key}.bundle"));
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

    fn instance(&mut self, on: &str, key: &'static str) -> String {
        let (status, body) = self.post(
            on,
            "/v1/instances",
            key,
            &json!({ "app": "records", "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push((instance.clone(), on.to_owned(), key));
        instance
    }

    /// 작업을 연다. (토큰, 작업의 식별자).
    fn work(&self, on: &str, key: &str, instance: &str) -> (String, String) {
        let (status, body) = self.post(
            on,
            &format!("/v1/instances/{instance}/sessions"),
            key,
            &json!({ "can": ALL }),
        );
        assert_eq!(status, 200, "{body}");
        (
            body["token"].as_str().unwrap().to_owned(),
            body["session"].as_str().unwrap().to_owned(),
        )
    }

    fn token(&self, on: &str, key: &str, instance: &str) -> String {
        self.work(on, key, instance).0
    }

    fn put_secret(
        &self,
        on: &str,
        key: &str,
        instance: &str,
        stage: &str,
        value: &str,
    ) -> (u16, Value) {
        self.put(
            on,
            &format!("/v1/instances/{instance}/secrets/BANK_API_KEY"),
            key,
            &json!({ "stage": stage, "value": value }),
        )
    }

    /// 프리뷰를 세운다. release 를 돌려준다.
    fn preview(&self, on: &str, token: &str, instance: &str) -> String {
        let (status, preview) = self.call(
            on,
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        preview["release"].as_str().unwrap().to_owned()
    }

    /// 프리뷰를 세우고 승격을 요청해 운영에 올린다. (release, 운영의 주소).
    fn ship(&self, on: &str, key: &str, instance: &str) -> (String, String) {
        let token = self.token(on, key, instance);
        let release = self.preview(on, &token, instance);
        let (status, body) = self.put_secret(on, key, instance, "production", BANK);
        assert_eq!(status, 200, "{body}");
        let (status, body) = self.post(
            on,
            &format!("/v1/instances/{instance}/promotion-requests"),
            &token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let (status, production) = self.post(
            on,
            &format!("/v1/instances/{instance}/promotions"),
            key,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        assert_eq!(status, 200, "{production}");
        let url = production["services"][0]["url"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
            .to_owned();
        (release, url)
    }

    fn settings(&self, on: &str) -> Value {
        let (status, body) = self.call(on, "GET", "/v1/settings/auth", FACTORY, &[]);
        assert_eq!(status, 200, "{body}");
        body
    }

    fn control(&self) -> Client {
        connect(&self.pg_url, self.control.as_str())
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

    fn rows(&self, query: &str) -> i64 {
        self.control().query_one(query, &[]).unwrap().get(0)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for (instance, machine, key) in &self.instances {
            let placed = self
                .servers
                .iter()
                .find(|(_, layer)| layer.machine() == machine)
                .map(|(name, _)| name.clone());
            if let Some(on) = placed {
                let _ = self.call(
                    &on,
                    "DELETE",
                    &format!("/v1/instances/{instance}"),
                    key,
                    &[],
                );
            }
        }
        // 놓인 기계가 내려가 있어 걷지 못한 인스턴스의 database 는 관리 역할로 걷는다
        for (instance, _, _) in &self.instances {
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

/// 기계 `a` 에 앱을 올리고 인스턴스 하나를 세운다.
fn one_on_a(bench: &mut Bench) -> String {
    bench.open("a");
    bench.upload("a", FACTORY);
    bench.instance("a", FACTORY)
}

// ---- 기록의 자리 ----

#[test]
fn 기록은_관리_서버의_파일이_아니라_control_database_에_있다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.ship("a", FACTORY, &instance);
    let (status, body) = bench.put(
        "a",
        "/v1/settings/auth",
        FACTORY,
        &json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" } }),
    );
    assert_eq!(status, 200, "{body}");
    let (_, work) = bench.work("a", FACTORY, &instance);
    let (status, _) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{instance}/sessions/{work}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200);

    // 관리 서버의 폴더에는 기록 파일이 없다
    let home = bench.home("a");
    for name in orbital_server::records::OLD_FILES {
        assert!(!home.join(name).exists(), "{name} 가 폴더에 있습니다");
    }
    // 기록은 control database 의 줄이다
    for (table, expected) in [
        ("instance", 1),
        ("factory_settings", 1),
        ("vault_value", 1),
        ("revoked_work", 1),
        ("app", 1),
        ("machine", 1),
    ] {
        assert_eq!(
            bench.rows(&format!("SELECT count(*) FROM orbital.{table}")),
            expected,
            "{table}"
        );
    }
    let machine: String = bench
        .control()
        .query_one(
            "SELECT machine FROM orbital.instance WHERE id = $1",
            &[&instance],
        )
        .unwrap()
        .get(0);
    assert_eq!(machine, "a");
    // 인스턴스의 database 와 섞이지 않는다. control database 는 따로 있다
    let present: Vec<String> = connect(&bench.pg_url, "postgres")
        .query(
            "SELECT datname FROM pg_database WHERE datname = $1",
            &[&bench.control.as_str()],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(present, vec![bench.control.as_str().to_owned()]);
}

#[test]
fn 관리_서버의_기록_파일을_모두_지우고_다시_떠도_인스턴스와_운영이_그대로다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (release, url) = bench.ship("a", FACTORY, &instance);
    let (status, before) = get(&format!("{url}/")).unwrap();
    assert_eq!(status, 200);
    bench.shut("a");

    // 그 기계의 것(코드 저장소)만 남기고 폴더의 나머지를 모두 지운다. 빌드 폴더 · 로그 · 토큰의 열쇠 · 메일함도 없다
    let home = bench.home("a");
    for entry in fs::read_dir(&home).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "sources" && name != "apps" {
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }
    }

    bench.open("a");
    let (status, production) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{production}");
    assert_eq!(production["release"], json!(release), "{production}");
    // 운영은 같은 주소에서 다시 서고(빌드를 마치면) 같은 비밀로 깬다
    let started = std::time::Instant::now();
    let after = loop {
        if let Some((200, body)) = get(&format!("{url}/")) {
            break body;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "운영이 다시 서지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(after["bank"], before["bank"]);
    assert_eq!(after["bank"], json!(sha(BANK)));
    assert_eq!(after["session_key"], before["session_key"]);
}

#[test]
fn 두_관리_서버가_같은_기록을_보고_한쪽이_세운_인스턴스를_다른_쪽이_본다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let token = bench.token("a", FACTORY, &instance);
    bench.preview("a", &token, &instance);
    bench.open("b");
    // b 는 a 가 세운 인스턴스를 안다. 작업을 열고 비밀의 목록을 본다
    let token = bench.token("b", FACTORY, &instance);
    let (status, body) = bench.call(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/secrets"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    // 다른 팩토리에게는 없는 것과 같다
    let (status, _) = bench.post(
        "b",
        &format!("/v1/instances/{instance}/sessions"),
        OTHER_FACTORY,
        &json!({ "can": ALL }),
    );
    assert_eq!(status, 404);
    // b 가 넣은 값을 a 가 본다
    let (status, body) = bench.put_secret("b", FACTORY, &instance, "preview", "preview_value");
    assert_eq!(status, 200, "{body}");
    let (status, list) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/secrets"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["secrets"][0]["preview"]["set"], json!(true), "{list}");
}

#[test]
fn 두_관리_서버가_같은_줄을_동시에_고쳐도_한쪽의_변경을_잃지_않는다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.open("b");

    // 팩토리의 설정: a 는 메일을, b 는 Google 을 동시에 넣는다. 둘 다 남는다.
    // 줄을 잠근 채로 둘을 보내 둘 다 그 줄 앞에 서게 한 뒤 놓는다. 읽고 고치는 사이를 잠그지 않으면 뒤의 것이 앞의 것을 덮는다
    let rounds = 12;
    let (status, body) = bench.put("a", "/v1/settings/auth", FACTORY, &json!({ "mail": null }));
    assert_eq!(status, 200, "{body}");
    let mut gate = bench.control();
    let mut held = gate.transaction().unwrap();
    held.query_one(
        "SELECT 1 FROM orbital.factory_settings WHERE organization = 'factory' FOR UPDATE",
        &[],
    )
    .unwrap();
    std::thread::scope(|scope| {
        for (on, body) in [
            (
                "a",
                json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" } }),
            ),
            (
                "b",
                json!({ "google": { "client_id": "client.apps.example", "client_secret": "google_secret_Xa9" } }),
            ),
        ] {
            let bench = &bench;
            scope.spawn(move || {
                let (status, reply) = bench.put(on, "/v1/settings/auth", FACTORY, &body);
                assert_eq!(status, 200, "{reply}");
            });
        }
        std::thread::sleep(Duration::from_millis(500));
        held.commit().unwrap();
    });
    let settings = bench.settings("b");
    assert_eq!(settings["mail"]["configured"], true, "{settings}");
    assert_eq!(settings["google"]["configured"], true, "{settings}");

    // 인스턴스의 줄: 두 관리 서버의 기록이 같은 줄에 release 를 하나씩 더한다. 하나도 잃지 않는다
    std::thread::scope(|scope| {
        let barrier = Arc::new(Barrier::new(2));
        for on in ["a", "b"] {
            let records = bench.layer(on).records();
            let barrier = Arc::clone(&barrier);
            let instance = &instance;
            scope.spawn(move || {
                barrier.wait();
                for round in 0..rounds {
                    records
                        .update_instance(instance, |record| {
                            // 읽고 고치는 사이에 다른 쪽이 끼어들 틈을 준다
                            std::thread::sleep(Duration::from_millis(2));
                            record.releases.insert(
                                format!("{on}-{round}"),
                                ReleaseRecord {
                                    commit: "0".repeat(40),
                                    access_findings: 0,
                                    rehearsal: orbital_core::release::Rehearsed::NotNeeded,
                                    external: Vec::new(),
                                    conformance: orbital_core::release::Conformed::NotDeclared,
                                },
                            );
                            Ok::<(), orbital_server::records::RecordError>(())
                        })
                        .unwrap()
                        .unwrap();
                }
            });
        }
    });
    let record = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap();
    assert_eq!(record.releases.len(), 2 * rounds);
}

// ---- 놓인 기계 ----

#[test]
fn 다른_기계에_놓인_인스턴스의_프리뷰와_승격과_git_은_그_기계가_아니면_하지_않고_정해진_답을_한다()
{
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let token = bench.token("a", FACTORY, &instance);
    let (status, preview) = bench.call(
        "a",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{preview}");
    let release = preview["release"].as_str().unwrap().to_owned();
    bench.open("b");
    // 이 인스턴스의 것(운영과 프리뷰의 database)만 센다. 클러스터에는 같이 도는 다른 테스트의 database 가 오간다
    let preview_before = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap()
        .preview
        .expect("프리뷰의 기록이 없습니다");
    let databases = || -> Vec<String> {
        connect(&bench.pg_url, "postgres")
            .query(
                "SELECT datname FROM pg_database WHERE datname LIKE '%' || $1 || '%' OR datname LIKE '%' || $2 || '%' ORDER BY 1",
                &[&instance, &preview_before],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    };
    let before = databases();
    assert_eq!(
        before.len(),
        1,
        "프리뷰의 database 하나만 있어야 합니다: {before:?}"
    );

    let misplaced = |(status, body): (u16, Value)| {
        assert_eq!(status, 421, "{body}");
        assert_eq!(body["error"], "misplaced", "{body}");
        assert_eq!(body["machine"], "a", "{body}");
    };
    // 에이전트의 일(토큰)
    misplaced(bench.call(
        "b",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    ));
    misplaced(bench.call(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/source"),
        &token,
        &[],
    ));
    misplaced(bench.post(
        "b",
        &format!("/v1/instances/{instance}/promotion-requests"),
        &token,
        &json!({ "release": release }),
    ));
    misplaced(bench.call(
        "b",
        "GET",
        &format!("/v1/instances/{instance}/git/info/refs?service=git-upload-pack"),
        &token,
        &[],
    ));
    // 팩토리의 일(service key)
    misplaced(bench.post(
        "b",
        &format!("/v1/instances/{instance}/promotions"),
        FACTORY,
        &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
    ));
    misplaced(bench.call(
        "b",
        "DELETE",
        &format!("/v1/instances/{instance}"),
        FACTORY,
        &[],
    ));
    // b 는 아무것도 하지 않았다. 새 database 도, 운영도, b 의 폴더의 저장소도 없다
    assert_eq!(databases(), before);
    assert!(!bench.home("b").join("sources").join(&instance).exists());
    let record = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap();
    assert!(record.production.is_none());
    assert!(record.promotion_requested.is_none());
    assert_eq!(record.preview.as_deref(), Some(preview_before.as_str()));
    // 앱의 코드 저장소도 그것을 받은 기계에 있다. b 는 그 앱으로 인스턴스를 세우지 않는다
    misplaced(bench.post(
        "b",
        "/v1/instances",
        FACTORY,
        &json!({ "app": "records", "version": "v1" }),
    ));
}

#[test]
fn 기록만_읽고_쓰는_일은_어느_관리_서버에서나_된다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (release, url) = bench.ship("a", FACTORY, &instance);
    bench.open("b");
    let path = |tail: &str| format!("/v1/instances/{instance}{tail}");

    // 운영의 모습: 같은 release 와 주소
    let (status, production) = bench.call("b", "GET", &path("/production"), FACTORY, &[]);
    assert_eq!(status, 200, "{production}");
    assert_eq!(production["release"], json!(release));
    assert_eq!(
        production["services"][0]["url"]
            .as_str()
            .unwrap()
            .trim_end_matches('/'),
        url
    );
    assert_eq!(production["schedules"][0]["path"], "/jobs/tick");
    // 사용자(인스턴스의 DB 에만 닿는다)
    let (status, body) = bench.post(
        "b",
        &path("/users"),
        FACTORY,
        &json!({ "email": "kim@example.com", "roles": ["member"] }),
    );
    assert_eq!(status, 200, "{body}");
    // b 가 한 초대로 a 의 운영에 들어온다. 들어온 사람은 b 의 목록에도 있다
    let id = orbital_core::name::InstanceId::parse(&instance).unwrap();
    let mut store = bench.layer("a").production_auth("factory", &id).unwrap();
    let browser = orbital_pg::auth::Secret::generate().unwrap();
    let link = store
        .request_link("kim@example.com", "/", &browser, now())
        .unwrap()
        .expect("초대가 보이지 않습니다");
    store.enter(&link, &browser, now()).unwrap();
    let (status, users) = bench.call("b", "GET", &path("/users"), FACTORY, &[]);
    assert_eq!(status, 200, "{users}");
    assert_eq!(users["users"][0]["email"], "kim@example.com", "{users}");
    // 팩토리의 설정
    let (status, body) = bench.put(
        "b",
        "/v1/settings/auth",
        FACTORY,
        &json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" } }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(bench.settings("a")["mail"]["configured"], true);
    // 작업을 열고 닫기, 비밀의 요청 · 목록
    let (token, _) = bench.work("b", FACTORY, &instance);
    let (status, body) = bench.post(
        "b",
        &path("/secrets/BANK_API_KEY/request"),
        &token,
        &json!({ "reason": "송금" }),
    );
    assert_eq!(status, 200, "{body}");
    let (status, list) = bench.call("a", "GET", &path("/secrets"), FACTORY, &[]);
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["secrets"][0]["requested"]["reason"], "송금", "{list}");
    // 운영의 값을 b 에서 바꾸면 a 에 놓인 운영이 곧 새 값으로 깬다(놓인 기계에 알린다)
    let changed = "sk_live_bank_changed_Qp4";
    let (status, body) = bench.put_secret("b", FACTORY, &instance, "production", changed);
    assert_eq!(status, 200, "{body}");
    let started = std::time::Instant::now();
    loop {
        if get(&format!("{url}/")).is_some_and(|(_, body)| body["bank"] == json!(sha(changed))) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "다른 기계에서 바꾼 값으로 깨지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // 입력 표를 b 에서 내고 a 에서 쓴다
    let (status, ticket) = bench.post(
        "b",
        &path("/secrets/BANK_API_KEY/entries"),
        FACTORY,
        &json!({ "stage": "preview" }),
    );
    assert_eq!(status, 200, "{ticket}");
    let (status, body) = bench.post(
        "a",
        "/v1/secret-entries",
        ticket["ticket"].as_str().unwrap(),
        &json!({ "value": "preview_value" }),
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn 다시_뜰_때_제_기계에_놓인_운영만_되살린다() {
    let mut bench = bench!();
    let ours = one_on_a(&mut bench);
    let (_, our_url) = bench.ship("a", FACTORY, &ours);
    bench.open("b");
    bench.upload("b", OTHER_FACTORY);
    let theirs = bench.instance("b", OTHER_FACTORY);
    let (_, their_url) = bench.ship("b", OTHER_FACTORY, &theirs);
    bench.shut("a");
    bench.shut("b");
    assert!(get(&format!("{our_url}/")).is_none());
    assert!(get(&format!("{their_url}/")).is_none());

    // a 의 폴더에 b 의 인스턴스의 코드 저장소가 있어도(나눠 쓰는 디스크처럼) a 는 b 에 놓인 운영을 되살리지 않는다
    copy_tree(
        &bench
            .home("b")
            .join("sources")
            .join(format!("{theirs}.git")),
        &bench
            .home("a")
            .join("sources")
            .join(format!("{theirs}.git")),
    );
    // a 만 다시 띄운다. a 의 운영은 서고 b 의 운영은 서지 않는다
    bench.open("a");
    let (status, _) = get(&format!("{our_url}/")).expect("a 에 놓인 운영이 서지 않았습니다");
    assert_eq!(status, 200);
    assert!(
        get(&format!("{their_url}/")).is_none(),
        "다른 기계에 놓인 운영을 되살렸습니다"
    );
    // b 의 운영의 기록은 그대로다
    let record = bench
        .layer("a")
        .records()
        .instance(&theirs)
        .unwrap()
        .unwrap();
    assert_eq!(record.machine, "b");
    assert!(record.production.is_some());
    // b 를 띄우면 b 의 운영이 선다
    bench.open("b");
    let (status, _) = get(&format!("{their_url}/")).expect("b 에 놓인 운영이 서지 않았습니다");
    assert_eq!(status, 200);
}

#[test]
fn 일정은_그_인스턴스가_놓인_기계만_부르고_같은_때를_두_번_부르지_않는다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.ship("a", FACTORY, &instance);
    // 다른 기계의 관리 서버도 떴다. 놓인 기계(a)는 같은 때에 두 번 깨어 부른다(앞의 부름이 끝나기 전에 다음 분이 왔을 때처럼)
    bench.open("b");

    let start = now();
    bench.clock.store(start, Ordering::SeqCst);
    for on in ["a", "a", "b"] {
        assert!(bench.layer(on).call_schedules().is_empty());
    }
    let schedules = bench.layer("a").records().schedules(&instance).unwrap();
    let next_at = schedules.values().next().unwrap().next_at;
    assert!(next_at > start);

    // 때가 됐다. 셋이 동시에 부른다. 한 번만 부른다
    bench.clock.store(next_at + 5, Ordering::SeqCst);
    let called: Vec<std::thread::JoinHandle<()>> = std::thread::scope(|scope| {
        let barrier = Arc::new(Barrier::new(3));
        let spawned: Vec<_> = ["a", "a", "b"]
            .into_iter()
            .map(|on| {
                let layer = bench.layer(on);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    layer.call_schedules()
                })
            })
            .collect();
        let mut handles: Vec<Vec<std::thread::JoinHandle<()>>> = spawned
            .into_iter()
            .map(|done| done.join().unwrap())
            .collect();
        // 다른 기계(b)는 부르지 않는다
        assert!(handles[2].is_empty());
        handles.drain(..).flatten().collect()
    });
    assert_eq!(called.len(), 1);
    for done in called {
        done.join().unwrap();
    }
    let run = bench
        .layer("b")
        .records()
        .schedules(&instance)
        .unwrap()
        .values()
        .next()
        .unwrap()
        .last_run
        .clone()
        .unwrap();
    assert_eq!(run.due_at, next_at);
    assert_eq!(run.outcome, "ok");
    // 같은 때에 다시 불러도 부르지 않는다
    for on in ["a", "a", "b"] {
        assert!(bench.layer(on).call_schedules().is_empty(), "{on}");
    }
}

#[test]
fn 같은_기계_이름으로_뜬_관리_서버가_있으면_뒤의_것은_뜨지_않고_까닭을_알린다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (_, url) = bench.ship("a", FACTORY, &instance);
    let port_before = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap()
        .production
        .unwrap()
        .port;

    // 같은 이름(a)으로 하나 더 띄운다. 뜨지 않고, 무엇을 하면 되는지 알린다
    let failed = bench.try_open("a").err().expect("떴습니다");
    assert!(
        failed.contains("`a`") && failed.contains("ORBITAL_MACHINE"),
        "{failed}"
    );
    // 뜨다 만 것이 앞의 운영을 건드리지 않았다. 기록의 포트가 그대로이고 앱이 답한다
    let record = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap();
    assert_eq!(record.production.unwrap().port, port_before);
    assert!(get(&format!("{url}/")).is_some_and(|(status, _)| status == 200));
    // 다른 이름으로는 뜬다
    bench.open("b");
    // 앞의 것이 내려가면 같은 이름으로 다시 뜬다
    bench.shut("a");
    bench.open("a");
    assert!(get(&format!("{url}/")).is_some_and(|(status, _)| status == 200));
}

// ---- 다시 뜰 때의 프리뷰 ----

fn database_exists(pg_url: &str, name: &str) -> bool {
    connect(pg_url, "postgres")
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&name])
        .unwrap()
        .is_some()
}

#[test]
fn 다시_뜰_때_앞의_프리뷰를_걷는_일을_기다리지_않고_운영을_먼저_세운다() {
    let mut bench = bench!();
    bench.open("a");
    bench.upload("a", FACTORY);
    // 프리뷰를 세운 채로 운영에 오른 인스턴스 셋
    let mut urls = Vec::new();
    let mut previews = Vec::new();
    for _ in 0..3 {
        let instance = bench.instance("a", FACTORY);
        let (_, url) = bench.ship("a", FACTORY, &instance);
        let preview = bench
            .layer("a")
            .records()
            .instance(&instance)
            .unwrap()
            .unwrap()
            .preview
            .expect("프리뷰의 기록이 없습니다");
        assert!(database_exists(&bench.pg_url, &format!("i_{preview}")));
        urls.push(url);
        previews.push((instance, format!("i_{preview}")));
    }

    bench.shut("a");
    bench.open("a");
    // 레이어가 뜬 때에 앞의 프리뷰의 database 가 아직 남아 있다. 그것들을 다 걷고 나서야 뜨는 것이 아니다
    let left = previews
        .iter()
        .filter(|(_, database)| database_exists(&bench.pg_url, database))
        .count();
    assert!(left > 0, "프리뷰를 모두 걷은 뒤에야 떴습니다");
    // 운영은 이미 서 있다
    for url in &urls {
        assert!(get(&format!("{url}/")).is_some_and(|(status, _)| status == 200));
    }
    // 뒤에서 모두 걷고 기록에서 이름을 지운다
    let started = std::time::Instant::now();
    loop {
        let swept = previews.iter().all(|(instance, database)| {
            !database_exists(&bench.pg_url, database)
                && bench
                    .layer("a")
                    .records()
                    .instance(instance)
                    .unwrap()
                    .unwrap()
                    .preview
                    .is_none()
        });
        if swept {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "앞의 프리뷰가 남았습니다"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// 관리 서버가 프리뷰를 세운 채 내려갔다가 떴고, 뒤에서 걷기 전인 때를 만든다. 프리뷰는 떠 있지 않고 기록에 이름으로만 남아 있다.
/// 다시 뜬 레이어가 뒤에서 걷기를 마친 뒤 같은 이름의 database 와 기록의 이름을 손으로 되돌려 놓는다. (인스턴스, 토큰, database 의 이름).
fn preview_left_in_records(bench: &mut Bench) -> (String, String, String) {
    let instance = one_on_a(bench);
    let token = bench.token("a", FACTORY, &instance);
    bench.preview("a", &token, &instance);
    let preview = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap()
        .preview
        .unwrap();
    let database = format!("i_{preview}");
    bench.shut("a");
    bench.open("a");
    let started = std::time::Instant::now();
    while database_exists(&bench.pg_url, &database)
        || bench
            .layer("a")
            .records()
            .instance(&instance)
            .unwrap()
            .unwrap()
            .preview
            .is_some()
    {
        assert!(started.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(50));
    }
    connect(&bench.pg_url, "postgres")
        .batch_execute(&format!("CREATE DATABASE \"{database}\""))
        .unwrap();
    bench
        .layer("a")
        .records()
        .update_instance(&instance, |record| {
            record.preview = Some(preview.clone());
            Ok::<(), orbital_server::records::RecordError>(())
        })
        .unwrap()
        .unwrap();
    (instance, token, database)
}

#[test]
fn 인스턴스를_지우면_떠_있지_않고_기록에만_남은_프리뷰의_database_도_걷는다() {
    let mut bench = bench!();
    let (instance, _, database) = preview_left_in_records(&mut bench);
    let (status, body) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{instance}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        !database_exists(&bench.pg_url, &database),
        "프리뷰의 database 가 남았습니다"
    );
}

#[test]
fn 기록에만_남은_프리뷰의_database_는_새_프리뷰를_세울_때_걷는다() {
    let mut bench = bench!();
    let (instance, token, database) = preview_left_in_records(&mut bench);
    // 새 프리뷰가 기록의 이름을 덮는다. 덮기 전에 앞의 것을 걷지 않으면 그 database 는 이름을 잃고 클러스터에 남는다
    bench.preview("a", &token, &instance);
    assert!(
        !database_exists(&bench.pg_url, &database),
        "앞의 프리뷰의 database 가 남았습니다"
    );
    let now_recorded = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap()
        .preview
        .unwrap();
    assert_ne!(format!("i_{now_recorded}"), database);
    assert!(database_exists(&bench.pg_url, &format!("i_{now_recorded}")));
}

#[test]
fn 기록에만_남은_프리뷰의_database_는_프리뷰를_걷을_때_걷는다() {
    let mut bench = bench!();
    let (instance, token, database) = preview_left_in_records(&mut bench);
    let (status, body) = bench.call(
        "a",
        "DELETE",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        !database_exists(&bench.pg_url, &database),
        "앞의 프리뷰의 database 가 남았습니다"
    );
    let record = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap();
    assert!(record.preview.is_none());
}

// ---- 기록을 읽지 못할 때 ----

#[test]
fn 금고를_읽지_못하면_서비스를_비밀_없이_띄우지_않는다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (_, url) = bench.ship("a", FACTORY, &instance);
    let (_, app) = get(&format!("{url}/")).unwrap();
    assert_eq!(app["bank"], json!(sha(BANK)));

    // 값을 바꿔 서비스를 재운 뒤, 깨기 전에 금고의 표를 읽지 못하게 한다
    let changed = "sk_live_bank_changed_Zt8";
    let (status, body) = bench.put_secret("a", FACTORY, &instance, "production", changed);
    assert_eq!(status, 200, "{body}");
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.vault_value RENAME TO vault_value_away")
        .unwrap();
    // 깨우지 못했다고 답한다. 비밀이 빠진 앱이 200 으로 답하지 않는다
    for _ in 0..3 {
        let reply = get(&format!("{url}/"));
        assert!(
            reply
                .as_ref()
                .is_some_and(|(status, body)| *status == 503 && body["bank"].is_null()),
            "{reply:?}"
        );
    }
    // 금고가 다시 읽히면 새 값으로 깬다
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.vault_value_away RENAME TO vault_value")
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if get(&format!("{url}/")).is_some_and(|(_, body)| body["bank"] == json!(sha(changed))) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "금고가 다시 읽힌 뒤에도 깨지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn rollout_의_기록을_읽지_못하면_관문을_건너뛰지_않고_승격을_멈춘다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let token = bench.token("a", FACTORY, &instance);
    let release = bench.preview("a", &token, &instance);
    let (status, body) = bench.put_secret("a", FACTORY, &instance, "production", BANK);
    assert_eq!(status, 200, "{body}");
    let (status, body) = bench.post(
        "a",
        &format!("/v1/instances/{instance}/promotion-requests"),
        &token,
        &json!({ "release": release }),
    );
    assert_eq!(status, 200, "{body}");
    let promote = |bench: &Bench| {
        bench.post(
            "a",
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        )
    };

    // rollout 의 표를 읽지 못한다. 이 release 를 멈춰 둔 rollout 이 있는지 알 수 없으므로 올리지 않는다
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.rollout RENAME TO rollout_away")
        .unwrap();
    let (status, body) = promote(&bench);
    assert_eq!(status, 500, "{body}");
    let record = bench
        .layer("a")
        .records()
        .instance(&instance)
        .unwrap()
        .unwrap();
    assert!(record.production.is_none(), "운영에 올랐습니다");
    // 승격을 기다리는 요청의 모습도 「rollout 없음」으로 답하지 않는다
    let (status, body) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/promotion-request"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 500, "{body}");

    // 다시 읽히면 오른다
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.rollout_away RENAME TO rollout")
        .unwrap();
    let (status, body) = promote(&bench);
    assert_eq!(status, 200, "{body}");
}

#[test]
fn 인스턴스의_기록을_읽지_못한_것을_없는_인스턴스라고_답하지_않는다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.instance RENAME TO instance_away")
        .unwrap();
    let (status, body) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
        &[],
    );
    bench
        .control()
        .batch_execute("ALTER TABLE orbital.instance_away RENAME TO instance")
        .unwrap();
    assert_eq!(status, 500, "{body}");
    // 다른 팩토리의 것은 여전히 없는 것이다
    let (status, _) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/production"),
        OTHER_FACTORY,
        &[],
    );
    assert_eq!(status, 404);
}

#[test]
fn 알림을_듣던_연결이_끊겨도_다시_붙고_끊긴_사이에_다른_기계에서_바꾼_비밀도_실린다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (_, url) = bench.ship("a", FACTORY, &instance);
    bench.open("b");
    let (_, app) = get(&format!("{url}/")).unwrap();
    assert_eq!(app["bank"], json!(sha(BANK)));
    let arrives = |value: &str, what: &str| {
        let started = std::time::Instant::now();
        loop {
            if get(&format!("{url}/")).is_some_and(|(_, body)| body["bank"] == json!(sha(value))) {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(20), "{what}");
            std::thread::sleep(Duration::from_millis(200));
        }
    };

    // 알림을 듣는 연결을 모두 끊는다(DB 가 다시 뜬 것처럼). 끊은 것이 있어야 한다
    let listening = "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND query ILIKE 'LISTEN %'";
    assert_eq!(bench.rows(listening), 2);
    bench
        .control()
        .batch_execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND query ILIKE 'LISTEN %'",
        )
        .unwrap();
    // 끊긴 사이에 b 에서 값을 바꾼다. 이 알림은 아무도 듣지 못한다
    let missed = "sk_live_bank_missed_Lm2";
    let (status, body) = bench.put_secret("b", FACTORY, &instance, "production", missed);
    assert_eq!(status, 200, "{body}");
    assert_eq!(bench.rows(listening), 0, "끊기기 전에 값을 바꿨습니다");
    // 다시 붙으면 놓친 값으로 깬다
    arrives(missed, "끊긴 사이에 바뀐 값으로 깨지 않았습니다");
    assert_eq!(bench.rows(listening), 2);
    // 다시 붙은 뒤의 알림도 듣는다
    let later = "sk_live_bank_later_Qr5";
    let (status, body) = bench.put_secret("b", FACTORY, &instance, "production", later);
    assert_eq!(status, 200, "{body}");
    arrives(
        later,
        "다시 붙은 뒤 다른 기계에서 바꾼 값으로 깨지 않았습니다",
    );
}

// ---- 옛 파일에서 옮기기 ----

/// 옛 판의 레이어가 남긴 기록 파일들. 인스턴스 하나(`i0ld0ne1`), 그 금고의 값 하나, 팩토리의 메일 설정, 닫은 작업, 훈련 한 번.
fn write_old_files(home: &Path, vault_instance: &str) {
    fs::create_dir_all(home).unwrap();
    let key = SealKey::from_bytes(SEAL);
    fs::write(
        home.join("registry.json"),
        json!({
            "instances": {
                "i0ld0ne1": {
                    "organization": "factory",
                    "app": "records",
                    "releases": {},
                    "production": null,
                    "preview": null,
                    "schedules": { "web /jobs/tick": { "next_at": 100 } }
                }
            },
            "rollouts": {}
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        home.join("settings.json"),
        json!({
            "organizations": {
                "factory": {
                    "mail": {
                        "provider": "resend",
                        "from": "login@factory.example",
                        "api_key": seal(&key, &binding("factory", "mail.api_key"), MAIL_KEY).unwrap()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        home.join("vault.json"),
        json!({
            "values": {
                vault_instance: {
                    "BANK_API_KEY": {
                        "production": {
                            "sealed": seal(&key, &secret_binding("factory", vault_instance, "production", "BANK_API_KEY"), BANK).unwrap(),
                            "set_at": 5
                        }
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        home.join("revoked.json"),
        json!({ format!("i0ld0ne1/{}", "c".repeat(32)): now() + 3600 }).to_string(),
    )
    .unwrap();
    fs::write(
        home.join("drills.jsonl"),
        format!(
            "{}\n",
            json!({
                "at": 10, "passed": true, "checks": [], "recovery_millis": 1, "drill_millis": 2,
                "exposure_seconds": null, "instances": 0, "failure": null
            })
        ),
    )
    .unwrap();
}

#[test]
fn 옛_파일의_기록은_처음_뜰_때_한_번_옮겨지고_다시_옮겨지지_않는다() {
    let mut bench = bench!();
    write_old_files(&bench.home("a"), "i0ld0ne1");
    bench.open("a");
    let records = bench.layer("a").records();
    let record = records.instance("i0ld0ne1").unwrap().unwrap();
    assert_eq!(record.organization, "factory");
    assert_eq!(record.machine, "a");
    assert_eq!(records.schedules("i0ld0ne1").unwrap().len(), 1);
    assert!(records.revoked("i0ld0ne1", &"c".repeat(32)).unwrap());
    assert_eq!(records.drills().unwrap().len(), 1);
    assert_eq!(bench.settings("a")["mail"]["configured"], true);
    let filled = bench
        .layer("a")
        .records()
        .client()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM orbital.vault_value WHERE instance = 'i0ld0ne1'",
            &[],
        )
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(filled, 1);
    // 옮긴 파일은 이름이 바뀌었다
    for name in orbital_server::records::OLD_FILES {
        assert!(!bench.home("a").join(name).exists(), "{name}");
        assert!(
            bench.home("a").join(format!("{name}.imported")).exists(),
            "{name}"
        );
    }

    // 다시 떠도 다시 옮기지 않는다. 옛 파일이 또 놓여 있어도 기록이 있는 control database 에는 옮기지 않는다
    bench.shut("a");
    fs::write(
        bench.home("a").join("drills.jsonl"),
        "{\"at\":11,\"passed\":true,\"checks\":[],\"recovery_millis\":1,\"drill_millis\":2,\"exposure_seconds\":null,\"instances\":0,\"failure\":null}\n",
    )
    .unwrap();
    bench.open("a");
    assert_eq!(bench.layer("a").records().drills().unwrap().len(), 1);
    assert!(bench.home("a").join("drills.jsonl").exists());
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.instance"), 1);
}

#[test]
fn 옛_파일을_옮기다_실패하면_아무것도_적지_않고_뜨지_않는다() {
    let bench = bench!();
    // 금고에 기록에 없는 인스턴스의 값이 있다. 인스턴스는 옮겨지다가 금고에서 깨진다
    write_old_files(&bench.home("a"), "i0rphan1");
    let failed = bench.try_open("a").err().expect("떴습니다");
    assert!(failed.contains("아무것도 적지 않았습니다"), "{failed}");
    assert!(
        !failed.contains(BANK) && !failed.contains("seal1."),
        "{failed}"
    );
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.instance"), 0);
    assert_eq!(
        bench.rows("SELECT count(*) FROM orbital.factory_settings"),
        0
    );
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.drill"), 0);
    for name in orbital_server::records::OLD_FILES {
        assert!(bench.home("a").join(name).exists(), "{name}");
    }
    // 읽지 못하는 파일도 같다
    fs::write(bench.home("a").join("vault.json"), "{").unwrap();
    let failed = bench.try_open("a").err().expect("떴습니다");
    assert!(failed.contains("vault.json"), "{failed}");
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.instance"), 0);
}

// ---- control database 의 마이그레이션 ----

/// 기록하는 마이그레이션. 돌 때마다 `orbital.trail` 에 자기 번호를 적는다.
fn trail(number: u32) -> Migration {
    let create = if number == 1 {
        "CREATE TABLE orbital.trail (seq bigint GENERATED ALWAYS AS IDENTITY, number int NOT NULL);"
    } else {
        ""
    };
    Migration::named(
        &format!("{number:04}_trail.sql"),
        &format!("{create} INSERT INTO orbital.trail (number) VALUES ({number});"),
    )
    .unwrap()
}

fn trail_of(client: &mut Client) -> Vec<i32> {
    client
        .query("SELECT number FROM orbital.trail ORDER BY seq", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[test]
fn control_database_의_마이그레이션은_차례대로_한_번씩만_적용된다() {
    let bench = bench!();
    ensure_database(&bench.pg_url, &bench.control).unwrap();
    let mut client = bench.control();
    // 저장소의 차례가 섞여 있어도 번호의 차례로 돈다
    assert_eq!(
        migrate(&mut client, &[trail(2), trail(1)]).unwrap(),
        vec![1, 2]
    );
    assert_eq!(trail_of(&mut client), vec![1, 2]);
    // 더한 것만 돈다
    assert_eq!(
        migrate(&mut client, &[trail(1), trail(2), trail(3)]).unwrap(),
        vec![3]
    );
    assert_eq!(
        migrate(&mut client, &[trail(1), trail(2), trail(3)]).unwrap(),
        Vec::<u32>::new()
    );
    assert_eq!(trail_of(&mut client), vec![1, 2, 3]);
    // 빠진 번호가 있으면 아무것도 돌리지 않는다
    let refused = migrate(&mut client, &[trail(1), trail(2), trail(3), trail(5)]).unwrap_err();
    assert!(refused.contains("0004"), "{refused}");
    assert_eq!(trail_of(&mut client), vec![1, 2, 3]);

    // 레이어가 뜰 때도 저장소의 마이그레이션을 한 번씩만 적용한다
    drop(client);
    drop_database(&bench.pg_url, &bench.control).unwrap();
    let mut bench = bench;
    bench.open("a");
    bench.shut("a");
    bench.open("a");
    let applied: Vec<(i32, i64)> = bench
        .control()
        .query(
            "SELECT number, count(*) FROM orbital.migration GROUP BY number ORDER BY number",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let expected: Vec<(i32, i64)> = (1..=i32::try_from(orbital_server::records::MIGRATIONS.len())
        .unwrap())
        .map(|number| (number, 1))
        .collect();
    assert_eq!(applied, expected);
}

#[test]
fn 두_관리_서버가_동시에_떠도_마이그레이션은_한_번만_돈다() {
    let mut bench = bench!();
    // 저장소의 것: 두 번 돌면 깨진다(같은 표를 두 번 만든다). 도는 동안 잠깐 멈춰 다른 쪽이 끼어들 틈을 준다
    ensure_database(&bench.pg_url, &bench.control).unwrap();
    let slow = Migration::named(
        "0001_once.sql",
        "CREATE TABLE orbital.once (at timestamptz DEFAULT clock_timestamp()); SELECT pg_sleep(0.3); INSERT INTO orbital.once DEFAULT VALUES;",
    )
    .unwrap();
    let outcomes: Vec<Result<Vec<u32>, String>> = std::thread::scope(|scope| {
        let barrier = Arc::new(Barrier::new(4));
        let spawned: Vec<_> = (0..4)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let (pg_url, control, slow) = (&bench.pg_url, &bench.control, &slow);
                scope.spawn(move || {
                    let mut client = connect(pg_url, control.as_str());
                    barrier.wait();
                    migrate(&mut client, std::slice::from_ref(slow))
                })
            })
            .collect();
        spawned
            .into_iter()
            .map(|done| done.join().unwrap())
            .collect()
    });
    let ran: Vec<Vec<u32>> = outcomes.into_iter().map(Result::unwrap).collect();
    assert_eq!(
        ran.iter().filter(|applied| *applied == &vec![1]).count(),
        1,
        "{ran:?}"
    );
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.once"), 1);

    // 관리 서버 둘이 처음 보는 control database 로 동시에 뜬다. 둘 다 뜨고 마이그레이션은 한 번씩만 적용된다
    drop_database(&bench.pg_url, &bench.control).unwrap();
    bench.control = fresh_name("ctl");
    let opened: Vec<Result<Layer, String>> = std::thread::scope(|scope| {
        let barrier = Arc::new(Barrier::new(2));
        let spawned: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|machine| {
                let barrier = Arc::clone(&barrier);
                let bench = &bench;
                scope.spawn(move || {
                    barrier.wait();
                    bench.try_open(machine)
                })
            })
            .collect();
        spawned
            .into_iter()
            .map(|done| done.join().unwrap())
            .collect()
    });
    for (machine, layer) in ["a", "b"].into_iter().zip(opened) {
        bench
            .servers
            .insert(machine.to_owned(), layer.expect("뜨지 못했습니다"));
    }
    assert_eq!(
        bench.rows("SELECT count(*) FROM orbital.migration"),
        i64::try_from(orbital_server::records::MIGRATIONS.len()).unwrap()
    );
    assert_eq!(bench.rows("SELECT count(*) FROM orbital.machine"), 2);
}

#[test]
fn 적용한_마이그레이션의_내용이_바뀌었으면_뜨지_않고_알린다() {
    let mut bench = bench!();
    bench.open("a");
    bench.shut("a");
    bench
        .control()
        .execute(
            "UPDATE orbital.migration SET sha256 = 'changed' WHERE number = 1",
            &[],
        )
        .unwrap();
    let failed = bench.try_open("a").err().expect("떴습니다");
    assert!(failed.contains("0001"), "{failed}");
    assert!(
        failed.contains("적용한 마이그레이션은 고치지 않습니다"),
        "{failed}"
    );
    // 마이그레이션 함수에 고친 내용을 넣어도 같다. 아무것도 돌리지 않는다
    let mut client = bench.control();
    let refused = migrate(
        &mut client,
        &[Migration::named("0001_records.sql", "SELECT 1;").unwrap()],
    )
    .unwrap_err();
    assert!(refused.contains("0001"), "{refused}");
}

// ---- 봉인 ----

#[test]
fn 금고의_값과_팩토리의_설정은_database_에도_봉인한_글로만_있다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.ship("a", FACTORY, &instance);
    let (status, body) = bench.put(
        "a",
        "/v1/settings/auth",
        FACTORY,
        &json!({
            "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" },
            "google": { "client_id": "client.apps.example", "client_secret": "google_secret_Xa9" }
        }),
    );
    assert_eq!(status, 200, "{body}");
    let everything = bench.everything();
    assert!(everything.contains("seal1."));
    for value in [BANK, MAIL_KEY, "google_secret_Xa9"] {
        assert!(
            !everything.contains(value),
            "{value} 가 control database 에 있습니다"
        );
        assert!(!everything.contains(&hex(value.as_bytes())));
        assert!(!everything.contains(&sha(value)));
    }
    // 봉인은 그 자리(조직 · 칸, 인스턴스 · 단계 · 이름)에 묶여 있다. 같은 열쇠와 같은 자리로만 풀린다
    let mut client = bench.control();
    let sealed: String = client
        .query_one(
            "SELECT sealed FROM orbital.vault_value WHERE instance = $1 AND stage = 'production'",
            &[&instance],
        )
        .unwrap()
        .get(0);
    let key = SealKey::from_bytes(SEAL);
    assert_eq!(
        open(
            &key,
            &secret_binding("factory", &instance, "production", "BANK_API_KEY"),
            &sealed
        )
        .as_deref(),
        Some(BANK)
    );
    assert_eq!(
        open(
            &key,
            &secret_binding("factory", &instance, "preview", "BANK_API_KEY"),
            &sealed
        ),
        None
    );
    let settings: String = client
        .query_one(
            "SELECT body ->> 'mail' FROM orbital.factory_settings WHERE organization = 'factory'",
            &[],
        )
        .unwrap()
        .get(0);
    let settings: Value = serde_json::from_str(&settings).unwrap();
    assert_eq!(
        open(
            &key,
            &binding("factory", "mail.api_key"),
            settings["api_key"].as_str().unwrap()
        )
        .as_deref(),
        Some(MAIL_KEY)
    );
}

#[test]
fn 운영의_신원_열쇠와_레이어가_만든_비밀은_database_에_봉인한_글로만_있다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (_, url) = bench.ship("a", FACTORY, &instance);
    let (_, app) = get(&format!("{url}/")).unwrap();

    let body: String = bench
        .control()
        .query_one(
            "SELECT body::text FROM orbital.instance WHERE id = $1",
            &[&instance],
        )
        .unwrap()
        .get(0);
    let body: Value = serde_json::from_str(&body).unwrap();
    let identity = body["production"]["identity_key"].as_str().unwrap();
    let generated = body["production"]["generated"]["SESSION_KEY"]
        .as_str()
        .unwrap();
    assert!(identity.starts_with("seal1."), "{identity}");
    assert!(generated.starts_with("seal1."), "{generated}");
    // 풀면 앱이 받은 값이다. 조직 · 인스턴스 · 칸에 묶여 있어 다른 칸이나 다른 인스턴스의 자리로는 풀리지 않는다
    let key = SealKey::from_bytes(SEAL);
    let session_key = open(
        &key,
        &production_binding("factory", &instance, "generated.SESSION_KEY"),
        generated,
    )
    .unwrap();
    assert_eq!(app["session_key"], json!(sha(&session_key)));
    assert!(
        open(
            &key,
            &production_binding("factory", &instance, "identity_key"),
            generated
        )
        .is_none()
    );
    assert!(
        open(
            &key,
            &production_binding("factory", "i0ther00", "generated.SESSION_KEY"),
            generated
        )
        .is_none()
    );
    let plain_identity = open(
        &key,
        &production_binding("factory", &instance, "identity_key"),
        identity,
    )
    .unwrap();
    // 그 열쇠는 인스턴스의 database 에도 있다(신원의 검증 함수가 쓴다). 같은 값이다
    let installed: Vec<u8> = connect(&bench.pg_url, &format!("i_{instance}"))
        .query_one("SELECT signing_key FROM orbital.instance", &[])
        .unwrap()
        .get(0);
    assert_eq!(hex(&installed), plain_identity);
    // control database 의 어느 줄에도 평문이 없다
    let everything = bench.everything();
    for value in [plain_identity.as_str(), session_key.as_str()] {
        assert!(
            !everything.contains(value),
            "평문이 control database 에 있습니다"
        );
    }
    // 답에도 실리지 않는다
    let (_, production) = bench.call(
        "a",
        "GET",
        &format!("/v1/instances/{instance}/production"),
        FACTORY,
        &[],
    );
    let text = production.to_string();
    assert!(
        !text.contains(&plain_identity) && !text.contains(&session_key) && !text.contains("seal1.")
    );
    // 관리 서버의 폴더(로그 · 메일함 · 빌드의 기록)에도 없다. 앱이 받은 코드 저장소와 빌드 결과는 앱의 것이라 보지 않는다
    let mut files = String::new();
    let mut stack = vec![bench.home("a")];
    while let Some(folder) = stack.pop() {
        for entry in fs::read_dir(&folder).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "builds" | "sources" | "apps" | "caches") {
                    stack.push(path);
                }
            } else {
                files.push_str(&String::from_utf8_lossy(
                    &fs::read(&path).unwrap_or_default(),
                ));
            }
        }
    }
    for value in [plain_identity.as_str(), session_key.as_str()] {
        assert!(!files.contains(value), "평문이 관리 서버의 폴더에 있습니다");
    }
}

#[test]
fn 열쇠를_나중에_준_레이어는_평문이던_줄을_봉인으로_바꾼다() {
    let mut bench = bench!();
    // 열쇠가 없는 개발용 레이어가 운영을 적었다. 신원 열쇠와 레이어가 만든 비밀이 평문이다
    let identity = "ab".repeat(32);
    let made = "cd".repeat(32);
    {
        let records = Records::open(
            &bench.pg_url,
            &bench.control,
            &Ident::parse("elsewhere").unwrap(),
            None,
            now(),
        )
        .unwrap();
        records
            .insert_instance(
                "ip1ain00",
                &InstanceRecord {
                    organization: "factory".to_owned(),
                    app: "records".to_owned(),
                    machine: "elsewhere".to_owned(),
                    production: Some(ProductionRecord {
                        release: "r1".to_owned(),
                        previous: None,
                        restore_point: None,
                        identity_key: identity.clone(),
                        generated: BTreeMap::from([("SESSION_KEY".to_owned(), made.clone())]),
                        restored: None,
                        port: None,
                        origin: None,
                        manifest: None,
                    }),
                    ..InstanceRecord::default()
                },
            )
            .unwrap();
        assert!(bench.everything().contains(&identity));
    }
    // 열쇠를 주고 띄우면 평문이던 칸을 봉인한다
    bench.open("a");
    assert_eq!(bench.layer("a").sealed_plaintext(), 2);
    let everything = bench.everything();
    assert!(!everything.contains(&identity));
    assert!(!everything.contains(&made));
    // 기록을 읽으면 풀린 값이다
    let record = bench
        .layer("a")
        .records()
        .instance("ip1ain00")
        .unwrap()
        .unwrap();
    let production = record.production.unwrap();
    assert_eq!(production.identity_key, identity);
    assert_eq!(production.generated["SESSION_KEY"], made);
    // 다시 떠도 더 바꿀 것이 없다
    bench.shut("a");
    bench.open("a");
    assert_eq!(bench.layer("a").sealed_plaintext(), 0);
    bench.shut("a");
    // 걷을 인스턴스가 아니다(기록만 적었다)
    bench
        .control()
        .execute("DELETE FROM orbital.instance WHERE id = 'ip1ain00'", &[])
        .unwrap();
}

#[test]
fn 열쇠를_바꿔_다시_봉인하는_일이_database_의_줄에서도_된다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    let (_, url) = bench.ship("a", FACTORY, &instance);
    let (status, body) = bench.put(
        "a",
        "/v1/settings/auth",
        FACTORY,
        &json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" } }),
    );
    assert_eq!(status, 200, "{body}");
    let before = bench.everything();
    bench.shut("a");

    // 새 열쇠와 옛 열쇠로 뜬다
    let new = SealKey::from_bytes([8; 32]);
    bench.previous_seal = Some(SealKey::from_bytes(SEAL));
    bench.seal = Some(new.clone());
    bench.open("a");
    let report = serde_json::to_value(bench.layer("a").resealed().unwrap()).unwrap();
    assert_eq!(report["settings"], 1, "{report}");
    assert_eq!(report["vault"], 1, "{report}");
    assert_eq!(report["production"], 2, "{report}");
    assert_eq!(report["unopened"], json!([]), "{report}");
    let after = bench.everything();
    assert_ne!(before, after);
    // 줄은 새 열쇠로만 풀린다
    let sealed: String = bench
        .control()
        .query_one(
            "SELECT sealed FROM orbital.vault_value WHERE instance = $1",
            &[&instance],
        )
        .unwrap()
        .get(0);
    let bound = secret_binding("factory", &instance, "production", "BANK_API_KEY");
    assert_eq!(open(&new, &bound, &sealed).as_deref(), Some(BANK));
    assert!(open(&SealKey::from_bytes(SEAL), &bound, &sealed).is_none());

    // 옛 열쇠를 빼고 다시 떠도 운영과 설정이 그대로다
    bench.shut("a");
    bench.previous_seal = None;
    bench.open("a");
    assert_eq!(bench.settings("a")["mail"]["configured"], true);
    let started = std::time::Instant::now();
    loop {
        if get(&format!("{url}/")).is_some_and(|(_, body)| body["bank"] == json!(sha(BANK))) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "운영이 다시 서지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (status, body) = bench.put_secret("a", FACTORY, &instance, "production", BANK);
    assert_eq!(status, 200, "{body}");
}

// ---- 값이 바뀐 것 ----

#[test]
fn 입력_표는_어느_관리_서버에서_써도_한_번만_쓰인다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.open("b");
    let token = bench.token("a", FACTORY, &instance);
    let (status, preview) = bench.call(
        "a",
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{preview}");
    for round in 0..3 {
        let (status, ticket) = bench.post(
            "a",
            &format!("/v1/instances/{instance}/secrets/BANK_API_KEY/entries"),
            FACTORY,
            &json!({ "stage": "production" }),
        );
        assert_eq!(status, 200, "{ticket}");
        let ticket = ticket["ticket"].as_str().unwrap().to_owned();
        // 두 관리 서버가 같은 표를 동시에 받는다
        let statuses: Vec<u16> = std::thread::scope(|scope| {
            let barrier = Arc::new(Barrier::new(2));
            let spawned: Vec<_> = ["a", "b"]
                .into_iter()
                .map(|on| {
                    let barrier = Arc::clone(&barrier);
                    let (bench, ticket) = (&bench, &ticket);
                    scope.spawn(move || {
                        barrier.wait();
                        bench
                            .post(
                                on,
                                "/v1/secret-entries",
                                ticket,
                                &json!({ "value": format!("{BANK}_{on}_{round}") }),
                            )
                            .0
                    })
                })
                .collect();
            spawned
                .into_iter()
                .map(|done| done.join().unwrap())
                .collect()
        });
        let mut sorted = statuses.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![200, 410], "{statuses:?}");
    }
}

#[test]
fn 한_관리_서버에서_닫은_작업은_다른_관리_서버에서도_받지_않는다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.open("b");
    let secrets = format!("/v1/instances/{instance}/secrets");
    for (opened, closed, used) in [("a", "a", "b"), ("b", "b", "a"), ("a", "b", "a")] {
        let (token, work) = bench.work(opened, FACTORY, &instance);
        // 닫기 전에는 두 관리 서버가 모두 받는다
        for on in ["a", "b"] {
            assert_eq!(bench.call(on, "GET", &secrets, &token, &[]).0, 200, "{on}");
        }
        let (status, _) = bench.call(
            closed,
            "DELETE",
            &format!("/v1/instances/{instance}/sessions/{work}"),
            FACTORY,
            &[],
        );
        assert_eq!(status, 200);
        assert_eq!(bench.call(used, "GET", &secrets, &token, &[]).0, 401);
        assert_eq!(bench.call(closed, "GET", &secrets, &token, &[]).0, 401);
    }
}

// ---- 격리와 지우기 ----

#[test]
fn 인스턴스의_어떤_역할도_control_database_에_접속하지_못한다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.ship("a", FACTORY, &instance);
    let prefix = format!("i_{instance}");
    let mut admin = connect(&bench.pg_url, "postgres");
    let roles: Vec<(String, bool)> = admin
        .query(
            "SELECT rolname, rolcanlogin FROM pg_roles WHERE starts_with(rolname, $1) ORDER BY 1",
            &[&prefix],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert!(roles.iter().any(|(_, login)| *login), "{roles:?}");
    for (role, can_login) in &roles {
        let attempt = |database: &str| {
            let mut config: Config = bench.pg_url.parse().unwrap();
            config.user(role).dbname(database);
            config.connect(NoTls)
        };
        if *can_login {
            // 제 database 에는 붙는다(시험이 헛돌지 않는다)
            assert!(attempt(&prefix).is_ok(), "{role}");
        }
        // 로그인하지 못하는 역할(묶음 · 소유자)은 잠깐 로그인을 허락해 붙어 본다. 권한이 막아야 한다
        if !*can_login {
            admin
                .batch_execute(&format!("ALTER ROLE \"{role}\" LOGIN"))
                .unwrap();
        }
        let refused = attempt(bench.control.as_str());
        if !*can_login {
            admin
                .batch_execute(&format!("ALTER ROLE \"{role}\" NOLOGIN"))
                .unwrap();
        }
        let error = refused
            .err()
            .unwrap_or_else(|| panic!("{role} 가 control database 에 붙었습니다"));
        assert_eq!(
            error.code().map(|code| code.code().to_owned()).as_deref(),
            Some("42501"),
            "{role}: {error}"
        );
    }
}

#[test]
fn 인스턴스를_지우면_control_database_의_그_줄들도_모두_지워진다() {
    let mut bench = bench!();
    let instance = one_on_a(&mut bench);
    bench.ship("a", FACTORY, &instance);
    let (token, work) = bench.work("a", FACTORY, &instance);
    let path = |tail: &str| format!("/v1/instances/{instance}{tail}");
    assert_eq!(
        bench
            .post(
                "a",
                &path("/secrets/BANK_API_KEY/request"),
                &token,
                &json!({ "reason": "송금" })
            )
            .0,
        200
    );
    assert_eq!(
        bench
            .post(
                "a",
                &path("/secrets/BANK_API_KEY/entries"),
                FACTORY,
                &json!({ "stage": "preview" })
            )
            .0,
        200
    );
    assert_eq!(
        bench
            .call(
                "a",
                "DELETE",
                &path(&format!("/sessions/{work}")),
                FACTORY,
                &[]
            )
            .0,
        200
    );
    bench.clock.store(now() + 120, Ordering::SeqCst);
    let _ = bench.layer("a").call_schedules();
    let tables = [
        "instance",
        "schedule",
        "vault_value",
        "secret_request",
        "secret_entry",
        "revoked_work",
    ];
    let count = |bench: &Bench, table: &str| -> i64 {
        let column = if table == "instance" {
            "id"
        } else {
            "instance"
        };
        bench
            .control()
            .query_one(
                &format!("SELECT count(*) FROM orbital.{table} WHERE {column} = $1"),
                &[&instance],
            )
            .unwrap()
            .get(0)
    };
    for table in tables {
        assert!(
            count(&bench, table) > 0,
            "{table} 에 줄이 없어 시험이 헛돕니다"
        );
    }
    let (status, body) = bench.call("a", "DELETE", &path(""), FACTORY, &[]);
    assert_eq!(status, 200, "{body}");
    bench.instances.clear();
    for table in tables {
        assert_eq!(count(&bench, table), 0, "{table}");
    }
    assert!(!bench.everything().contains(&instance));
}
