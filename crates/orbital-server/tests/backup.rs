//! 백업과 복구 훈련. 끝 기준은 「복구 훈련이 사람 손 없이 통과한다」이다.
//!
//! 테스트마다 자기 PostgreSQL 클러스터를 따로 세워(`initdb`, WAL 보관을 켠 설정) 그 위에 레이어를 띄운다. 실제 인스턴스 · 실제 앱 프로세스(Node 서버) ·
//! 실제 HTTP 로 잰다. 관리 서버의 API 는 HTTP 층의 `handle` 에 바로 넣고, 띄운 앱에는 실제 HTTP 로 요청한다.
//! 다른 테스트가 함께 쓰는 `ORBITAL_PG` 의 클러스터는 쓰지 않는다. 이 기계에 PostgreSQL 의 도구가 없을 때만 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orbital_backup::{Cluster, LocalStore, Store, Tools};
use orbital_core::backup::{Check, DrillFailure, DrillRecord, RestoreRefusal};
use orbital_core::name::{Ident, InstanceId};
use orbital_pg::auth::Secret;
use orbital_router::SESSION_COOKIE;
use orbital_run::LocalRunner;
use orbital_server::backup::{BackupOptions, DRILLS};
use orbital_server::http::handle;
use orbital_server::layer::{Layer, Options};
use postgres::{Client, NoTls};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
/// 어디에 새어도 찾을 수 있게 드문 글자로 지은 행의 값.
const SECRET_NOTE: &str = "note_value_Wb52kQx9";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// 앞에 쓴 것과 뒤에 쓸 것 사이의 시점(유닉스 초)을 잡는다. 그 초가 지나기를 기다린다.
fn moment() -> u64 {
    let at = now_millis() / 1000 + 1;
    while now_millis() < at * 1000 + 150 {
        std::thread::sleep(Duration::from_millis(20));
    }
    at
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

fn http_get(url: &str, cookie: Option<&str>) -> (u16, Value) {
    let mut request = ureq::get(url).timeout(Duration::from_secs(30));
    if let Some(cookie) = cookie {
        request = request.set("Cookie", cookie);
    }
    let response = match request.call() {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("GET {url}: {error}"),
    };
    let status = response.status();
    (
        status,
        serde_json::from_str(&response.into_string().unwrap_or_default()).unwrap_or(Value::Null),
    )
}

/// 운영에 들어온 사람 하나. 세션 쿠키와 사용자의 식별자.
struct Person {
    id: String,
    cookie: String,
    session: Secret,
}

struct Bench {
    scratch: PathBuf,
    /// 운영 클러스터와 백업을 두는 폴더. Postgres 의 사용자의 것이다.
    postgres: PathBuf,
    home: PathBuf,
    backup_root: PathBuf,
    cluster: Option<Cluster>,
    /// 레이어의 시계를 앞으로 돌리는 초.
    ahead: Arc<AtomicU64>,
    layer: Option<Arc<Layer>>,
    instances: Vec<(String, &'static str)>,
}

impl Bench {
    fn new(require_drill: bool) -> Option<Self> {
        let tools = Tools::find().ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "obs-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&scratch).unwrap();
        // Postgres 의 사용자가 만들고 쓰는 폴더는 따로 둔다(레이어가 root 로 돌면 그 사용자는 레이어의 폴더에 쓰지 못한다)
        let postgres = scratch.with_extension("pg");
        tools.private_folder(&postgres).unwrap();
        let backup_root = postgres.join("backup");
        let archive = LocalStore::open(tools.clone(), backup_root.clone())
            .unwrap()
            .archive_command();
        let cluster = Cluster::init(&tools, &postgres.join("pg"), Some(&archive))
            .expect("운영 클러스터를 세우지 못했습니다");
        let mut bench = Self {
            home: scratch.join("home"),
            postgres,
            scratch,
            backup_root,
            cluster: Some(cluster),
            ahead: Arc::new(AtomicU64::new(0)),
            layer: None,
            instances: Vec::new(),
        };
        bench.open(require_drill);
        for key in [FACTORY, OTHER_FACTORY] {
            bench.upload(key);
        }
        Some(bench)
    }

    fn options(&self, require_drill: bool) -> Options {
        let ahead = Arc::clone(&self.ahead);
        let mut backup = BackupOptions::new(self.backup_root.clone());
        backup.require_drill = require_drill;
        Options {
            dev_mailbox: true,
            clock: Arc::new(move || now() + ahead.load(Ordering::SeqCst)),
            backup: Some(backup),
            ..Options::new(
                self.home.clone(),
                self.pg_url(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        }
    }

    fn open(&mut self, require_drill: bool) {
        let layer = Layer::open(self.options(require_drill)).expect("레이어를 열지 못했습니다");
        self.layer = Some(Arc::new(layer));
    }

    fn pg_url(&self) -> String {
        self.cluster.as_ref().unwrap().url().unwrap()
    }

    fn layer(&self) -> &Layer {
        self.layer.as_ref().unwrap()
    }

    fn client(&self, database: &str) -> Client {
        let url = self.pg_url();
        let url = format!("{}/{database}", url.rsplit_once('/').unwrap().0);
        Client::connect(&url, NoTls).unwrap()
    }

    fn upload(&self, key: &str) {
        let folder = self.scratch.join(format!("scaffold-{key}"));
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ledger"),
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
        let (status, body) = self.call("PUT", "/v1/apps/ledger", key, &fs::read(bundle).unwrap());
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

    fn create(&self, key: &str) -> (u16, Value) {
        self.post(
            "/v1/instances",
            key,
            &json!({ "app": "ledger", "version": "v1" }),
        )
    }

    fn instance(&mut self, key: &'static str) -> String {
        let (status, body) = self.create(key);
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push((instance.clone(), key));
        instance
    }

    fn token(&self, key: &str, instance: &str) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/sessions"),
            key,
            &json!({ "can": ALL }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 에이전트가 프리뷰를 세우고 승격을 요청한다. release 를 돌려준다.
    fn preview(&self, instance: &str, token: &str) -> String {
        let (status, preview) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            token,
            &json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        release
    }

    fn promote(&self, instance: &str, release: &str) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        )
    }

    /// 인스턴스를 세워 운영에 올린다. (인스턴스, 운영의 주소).
    fn shipped(&mut self) -> (String, String) {
        let instance = self.instance(FACTORY);
        let token = self.token(FACTORY, &instance);
        let release = self.preview(&instance, &token);
        let (status, production) = self.promote(&instance, &release);
        assert_eq!(status, 200, "{production}");
        let url = production["services"][0]["url"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
            .to_owned();
        (instance, url)
    }

    /// 운영에 사람 하나를 들인다(초대 → 링크 → 들어오기).
    fn person(&self, instance: &str, email: &str, role: &str) -> Person {
        let id = InstanceId::parse(instance).unwrap();
        let mut store = self.layer().production_auth("factory", &id).unwrap();
        store
            .invite(email, &[Ident::parse(role).unwrap()], now())
            .unwrap();
        let browser = Secret::generate().unwrap();
        let link = store
            .request_link(email, "/", &browser, now())
            .unwrap()
            .unwrap();
        let entered = store.enter(&link, &browser, now()).unwrap();
        Person {
            id: entered.user.id,
            cookie: format!("{SESSION_COOKIE}={}", entered.session.to_text()),
            session: entered.session,
        }
    }

    /// 운영 DB 에 메모를 적는다(관리 역할로).
    fn note(&self, instance: &str, owner: &str, body: &str) {
        self.client(&format!("i_{instance}"))
            .execute(
                "INSERT INTO ledger.note (owner, body) VALUES ($1, $2)",
                &[&owner, &body],
            )
            .unwrap();
    }

    fn notes(&self, instance: &str) -> Vec<String> {
        self.client(&format!("i_{instance}"))
            .query("SELECT body FROM ledger.note ORDER BY id", &[])
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    fn base_backup(&self) {
        self.layer()
            .base_backup()
            .expect("기반 백업을 뜨지 못했습니다");
    }

    fn restore(&self, key: &str, instance: &str, at: u64) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/restore"),
            key,
            &json!({ "at": at }),
        )
    }

    fn drill(&self) -> DrillRecord {
        self.layer().drill().expect("훈련을 돌리지 못했습니다")
    }

    fn drills_text(&self) -> String {
        fs::read_to_string(self.home.join(DRILLS)).unwrap_or_default()
    }

    /// 보관한 WAL 에서 기반 백업이 시작한 뒤의 조각 하나를 지운다. 백업이 깨진 것이다.
    fn break_archive(&self) {
        let tools = Tools::find().unwrap();
        let store = LocalStore::open(tools, self.backup_root.clone()).unwrap();
        // 조각을 여럿 넘긴다
        let mut admin = self.client("postgres");
        for _ in 0..3 {
            admin
                .batch_execute("SELECT pg_current_xact_id(); SELECT pg_switch_wal()")
                .unwrap();
        }
        store.seal(&self.pg_url()).unwrap();
        let backup = store.backups().unwrap().pop().unwrap();
        let archive = store.archive().unwrap();
        let start = archive
            .files
            .iter()
            .position(|file| *file == backup.start_wal)
            .unwrap();
        let missing = archive.files[start + 2].clone();
        assert_eq!(missing.len(), 24, "{:?}", archive.files);
        fs::remove_file(self.backup_root.join("wal").join(missing)).unwrap();
    }

    fn status(&self) -> Value {
        let (status, body) = self.call("GET", "/v1/backup", FACTORY, &[]);
        assert_eq!(status, 200, "{body}");
        body
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        if self.layer.is_some() {
            for (instance, key) in &self.instances {
                let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), key, &[]);
            }
            drop(self.layer.take());
        }
        drop(self.cluster.take());
        if let Ok(tools) = Tools::find() {
            let _ = tools.remove(&self.postgres);
        }
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    () => {
        bench!(false)
    };
    ($require:expr) => {
        match Bench::new($require) {
            Some(bench) => bench,
            // CI 에서는 건너뛰지 않는다. 도구가 없으면 워크플로가 PostgreSQL 을 깔지 못한 것이다
            None if std::env::var_os("CI").is_some() => {
                panic!("CI 에 PostgreSQL 의 도구(/usr/lib/postgresql/<버전>/bin)가 없습니다")
            }
            None => {
                eprintln!(
                    "PostgreSQL 의 도구(/usr/lib/postgresql/<버전>/bin)가 없어 건너뜁니다"
                );
                return;
            }
        }
    };
}

/// 이 경로를 담은 명령줄의 프로세스(Postgres 의 프로세스가 남았는지 본다).
fn processes_under(path: &Path) -> usize {
    let needle = path.to_string_lossy().into_owned();
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .filter(|entry| {
            fs::read(entry.path().join("cmdline"))
                .is_ok_and(|bytes| String::from_utf8_lossy(&bytes).contains(&needle))
        })
        .count()
}

// ---- 복구 훈련 ----

#[test]
fn 훈련이_사람_손_없이_끝까지_돌고_통과한다() {
    let mut bench = bench!();
    let (first, _) = bench.shipped();
    let (second, _) = bench.shipped();
    let person = bench.person(&first, "m1@example.test", "member");
    bench.note(&first, &person.id, SECRET_NOTE);
    bench.note(&second, "someone", "b");

    // 기반 백업이 없어도 훈련이 먼저 뜨고 끝까지 돈다
    let record = bench.drill();
    assert!(record.passed, "{record:#?}");
    assert_eq!(record.failure, None);
    assert_eq!(record.instances, 2);
    let checks: Vec<Check> = record
        .checks
        .iter()
        .map(|checked| checked.check.clone())
        .collect();
    for instance in [&first, &second] {
        for check in [
            Check::Database {
                instance: instance.clone(),
            },
            Check::Fingerprint {
                instance: instance.clone(),
            },
            Check::Roles {
                instance: instance.clone(),
            },
        ] {
            assert!(checks.contains(&check), "{check:?} 가 없습니다: {checks:?}");
        }
    }
    for check in [
        Check::ClusterStarted,
        Check::MarkBeforeKept,
        Check::MarkAfterGone,
        Check::Records,
    ] {
        assert!(checks.contains(&check), "{check:?}");
    }
    assert!(
        checks
            .iter()
            .any(|check| matches!(check, Check::Moved { .. })),
        "{checks:?}"
    );
    assert!(record.recovery_millis > 0);
    assert!(record.exposure_seconds.is_some());
    // 기록에 쌓이고 팩토리에게는 낡지 않았다고 보인다
    assert_eq!(bench.drills_text().lines().count(), 1);
    assert_eq!(bench.status()["fresh"], json!(true));
    // 운영은 그대로다
    assert_eq!(bench.notes(&first), vec![SECRET_NOTE.to_owned()]);
    // 두 번째 훈련은 앞에서 뜬 기반 백업과 그 뒤의 WAL 로 돈다
    let again = bench.drill();
    assert!(again.passed, "{again:#?}");
}

#[test]
fn 백업이_깨져_있으면_훈련이_실패하고_까닭을_적는다() {
    let mut bench = bench!();
    bench.shipped();
    bench.base_backup();
    bench.break_archive();

    let record = bench.drill();
    assert!(!record.passed);
    assert!(
        matches!(
            record.failure,
            Some(DrillFailure::Refused {
                refusal: RestoreRefusal::MissingWal { .. }
            })
        ),
        "{record:#?}"
    );
    let line: Value = serde_json::from_str(bench.drills_text().lines().last().unwrap()).unwrap();
    assert_eq!(line["passed"], json!(false));
    assert_eq!(line["failure"]["kind"], json!("refused"));
    assert_eq!(line["failure"]["refusal"]["reason"], json!("missing_wal"));
    assert_eq!(bench.status()["fresh"], json!(false));
}

#[test]
fn 훈련은_끝나면_옆에_세운_클러스터와_파일을_지운다() {
    let mut bench = bench!();
    bench.shipped();
    let record = bench.drill();
    assert!(record.passed, "{record:#?}");
    let restore = bench.backup_root.join("restore");
    assert_eq!(fs::read_dir(&restore).unwrap().count(), 0);
    assert_eq!(
        processes_under(&restore),
        0,
        "옆의 클러스터의 프로세스가 남았습니다"
    );
    // 옮겨 본 임시 database 도 지웠다
    let left: Vec<String> = bench
        .client("postgres")
        .query(
            "SELECT datname FROM pg_database WHERE datname LIKE '%drill_%'",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    // 실패한 훈련도 지운다
    bench.break_archive();
    assert!(!bench.drill().passed);
    assert_eq!(fs::read_dir(&restore).unwrap().count(), 0);
    assert_eq!(processes_under(&restore), 0);
}

#[test]
fn 훈련의_기록에는_이름과_숫자만_남고_행의_값은_남지_않는다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    let person = bench.person(&instance, "secret.person@example.test", "member");
    bench.note(&instance, &person.id, SECRET_NOTE);
    assert!(bench.drill().passed);
    bench.break_archive();
    assert!(!bench.drill().passed);

    let text = bench.drills_text();
    for leaked in [
        SECRET_NOTE,
        "secret.person",
        person.id.as_str(),
        bench.scratch.to_str().unwrap(),
        "SQLSTATE",
    ] {
        assert!(
            !text.contains(leaked),
            "{leaked} 가 기록에 남았습니다: {text}"
        );
    }
    // 글자로 남는 것은 정한 이름(확인 · 까닭의 갈래)과 인스턴스의 식별자뿐이다
    fn strings(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::String(text) => found.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
            Value::Object(map) => map.values().for_each(|item| strings(item, found)),
            _ => {}
        }
    }
    for line in text.lines() {
        let mut found = Vec::new();
        strings(&serde_json::from_str(line).unwrap(), &mut found);
        for text in found {
            let known = [
                "cluster_started",
                "mark_before_kept",
                "mark_after_gone",
                "database",
                "fingerprint",
                "roles",
                "moved",
                "records",
                "refused",
                "missing_wal",
                "checks",
                "recovery",
                "step",
            ];
            let ours = text == instance
                || text == format!("i_{instance}")
                || text == "orbital_drill"
                || text.len() == 24 && text.bytes().all(|byte| byte.is_ascii_hexdigit());
            assert!(known.contains(&text.as_str()) || ours, "모르는 글 `{text}`");
        }
    }
}

#[test]
fn orbitald_drill_은_훈련이_실패하면_0_이_아닌_코드로_끝난다() {
    let mut bench = bench!();
    bench.shipped();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_orbitald"))
            .arg("drill")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("ORBITAL_HOME", &bench.home)
            .env("ORBITAL_PG", bench.pg_url())
            .env("ORBITAL_BACKUP_DIR", &bench.backup_root)
            .output()
            .unwrap()
    };
    let passed = run();
    assert!(
        passed.status.success(),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    let line: Value = serde_json::from_slice(&passed.stdout).unwrap();
    assert_eq!(line["passed"], json!(true));

    bench.break_archive();
    let failed = run();
    assert!(!failed.status.success());
    assert_ne!(failed.status.code(), Some(0));
    let line: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(line["passed"], json!(false));
    // 두 번 모두 기록에 쌓였다
    assert_eq!(bench.drills_text().lines().count(), 2);
}

// ---- 인스턴스 하나를 되살리기 ----

#[test]
fn 인스턴스_하나를_정한_시점으로_되살리면_그_뒤에_쓴_행이_없고_앱이_되살린_db_에_닿는다() {
    let mut bench = bench!();
    let (instance, url) = bench.shipped();
    let admin = bench.person(&instance, "a1@example.test", "admin");
    bench.base_backup();
    bench.note(&instance, &admin.id, "before");
    let at = moment();
    bench.note(&instance, &admin.id, "after");
    let notes = format!("{url}/notes?as=admin");
    assert_eq!(
        http_get(&notes, Some(&admin.cookie)),
        (200, json!(["before", "after"]))
    );

    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["instance"], json!(instance));
    assert_eq!(report["at"], json!(at));
    assert!(report["millis"].as_u64().is_some());
    assert!(report["tables"].as_u64().unwrap() >= 1);
    assert_eq!(bench.notes(&instance), vec!["before".to_owned()]);
    // 다음 요청이 되살린 DB 에 닿는다. 주소는 그대로다
    assert_eq!(
        http_get(&notes, Some(&admin.cookie)),
        (200, json!(["before"]))
    );
}

#[test]
fn 인스턴스를_되살려도_다른_인스턴스의_행은_그대로다() {
    let mut bench = bench!();
    let (first, _) = bench.shipped();
    let (second, second_url) = bench.shipped();
    let other = bench.person(&second, "a2@example.test", "admin");
    bench.base_backup();
    bench.note(&first, "x", "first-before");
    bench.note(&second, &other.id, "second-before");
    let at = moment();
    bench.note(&first, "x", "first-after");
    bench.note(&second, &other.id, "second-after");
    let roles_before: Vec<String> =
        orbital_backup::roles(&mut bench.client("postgres"), &format!("i_{second}_")).unwrap();

    let (status, report) = bench.restore(FACTORY, &first, at);
    assert_eq!(status, 200, "{report}");
    assert_eq!(bench.notes(&first), vec!["first-before".to_owned()]);
    assert_eq!(
        bench.notes(&second),
        vec!["second-before".to_owned(), "second-after".to_owned()]
    );
    assert_eq!(
        orbital_backup::roles(&mut bench.client("postgres"), &format!("i_{second}_")).unwrap(),
        roles_before
    );
    assert_eq!(
        http_get(&format!("{second_url}/notes?as=admin"), Some(&other.cookie)),
        (200, json!(["second-before", "second-after"]))
    );
}

#[test]
fn 되살린_인스턴스는_권한_검사를_통과하고_업무_역할이_자기_행만_본다() {
    let mut bench = bench!();
    let (instance, url) = bench.shipped();
    let m1 = bench.person(&instance, "m1@example.test", "member");
    let m2 = bench.person(&instance, "m2@example.test", "member");
    bench.base_backup();
    bench.note(&instance, &m1.id, "m1-note");
    bench.note(&instance, &m2.id, "m2-note");
    let at = moment();
    bench.note(&instance, &m1.id, "m1-late");

    // 되살리기는 권한을 다시 세우고 권한 검사를 통과해야 끝난다
    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    let member = format!("{url}/notes?as=member");
    assert_eq!(
        http_get(&member, Some(&m1.cookie)),
        (200, json!(["m1-note"]))
    );
    assert_eq!(
        http_get(&member, Some(&m2.cookie)),
        (200, json!(["m2-note"]))
    );
    // 회원의 신원으로 관리자의 연결을 골라도 행이 나오지 않는다(역할 제한 정책이 되살아났다)
    assert_eq!(
        http_get(&format!("{url}/notes?as=admin"), Some(&m1.cookie)),
        (200, json!([]))
    );
    // 신원이 없으면 아무 행도 없다
    assert_eq!(http_get(&member, None), (200, json!([])));
    // 접속 권한이 선언대로 다시 섰다. 인스턴스의 로그인은 붙고, 누구나(PUBLIC)는 붙지 못한다
    let login = format!("i_{instance}_s_web_member");
    let mut config: postgres::Config = bench.pg_url().parse().unwrap();
    config.user(&login).dbname(&format!("i_{instance}"));
    assert!(config.connect(NoTls).is_ok());
    let public: bool = bench
        .client("postgres")
        .query_one(
            "SELECT has_database_privilege('public', $1, 'CONNECT')",
            &[&format!("i_{instance}")],
        )
        .unwrap()
        .get(0);
    assert!(!public);
}

#[test]
fn 되살린_인스턴스의_사용자와_세션은_그_시점의_것이다() {
    let mut bench = bench!();
    let (instance, url) = bench.shipped();
    let early = bench.person(&instance, "early@example.test", "admin");
    bench.base_backup();
    bench.note(&instance, &early.id, "n");
    let at = moment();
    let late = bench.person(&instance, "late@example.test", "admin");
    // 그 시점 뒤에 로그아웃한 세션은 되살린 뒤 다시 살아 있다
    let id = InstanceId::parse(&instance).unwrap();
    bench
        .layer()
        .production_auth("factory", &id)
        .unwrap()
        .revoke(&early.session, now())
        .unwrap();
    let notes = format!("{url}/notes?as=admin");
    assert_eq!(http_get(&notes, Some(&early.cookie)), (200, json!([])));

    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    let (status, users) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{users}");
    let emails: Vec<&str> = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, vec!["early@example.test"]);
    assert_eq!(http_get(&notes, Some(&early.cookie)), (200, json!(["n"])));
    assert_eq!(http_get(&notes, Some(&late.cookie)), (200, json!([])));
    let mut store = bench.layer().production_auth("factory", &id).unwrap();
    assert!(store.session(&early.session, now()).unwrap().is_some());
    assert!(store.session(&late.session, now()).unwrap().is_none());
}

#[test]
fn 되살리기_전의_상태가_되돌릴_지점으로_남는다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    bench.base_backup();
    bench.note(&instance, "x", "before");
    let at = moment();
    bench.note(&instance, "x", "after");

    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    let point = report["restore_point"].as_str().unwrap().to_owned();
    assert!(point.starts_with(&format!("i_{instance}_rp_")), "{point}");
    // 되돌릴 지점은 아무도 접속하지 못하게 닫혀 있다. 관리 역할로 열어 들여다본다
    let mut admin = bench.client("postgres");
    let open: bool = admin
        .query_one(
            "SELECT datallowconn FROM pg_database WHERE datname = $1",
            &[&point],
        )
        .unwrap()
        .get(0);
    assert!(!open);
    admin
        .batch_execute(&format!(
            "ALTER DATABASE \"{point}\" ALLOW_CONNECTIONS true"
        ))
        .unwrap();
    let kept: Vec<String> = bench
        .client(&point)
        .query("SELECT body FROM ledger.note ORDER BY id", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(kept, vec!["before".to_owned(), "after".to_owned()]);
    admin
        .batch_execute(&format!(
            "ALTER DATABASE \"{point}\" ALLOW_CONNECTIONS false"
        ))
        .unwrap();
    // 레이어의 기록도 그 지점을 가리킨다
    let registry: Value =
        serde_json::from_slice(&fs::read(bench.home.join("registry.json")).unwrap()).unwrap();
    assert_eq!(
        registry["instances"][&instance]["production"]["restore_point"],
        json!(point)
    );
}

impl Bench {
    fn undo(&self, key: &str, instance: &str) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/restore/undo"),
            key,
            &json!({}),
        )
    }
}

#[test]
fn 되살리기를_무르면_되살리기_전의_행이_보이고_다시_무르지는_못한다() {
    let mut bench = bench!();
    let (instance, url) = bench.shipped();
    let admin = bench.person(&instance, "a1@example.test", "admin");
    // 되살린 적이 없으면 무를 것이 없다
    let (status, body) = bench.undo(FACTORY, &instance);
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("되살린"),
        "{body}"
    );

    bench.base_backup();
    bench.note(&instance, &admin.id, "before");
    let at = moment();
    bench.note(&instance, &admin.id, "after");
    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    assert_eq!(bench.notes(&instance), vec!["before".to_owned()]);

    let (status, undone) = bench.undo(FACTORY, &instance);
    assert_eq!(status, 200, "{undone}");
    assert_eq!(undone["instance"], json!(instance));
    assert!(undone["millis"].as_u64().is_some(), "{undone}");
    assert_eq!(
        bench.notes(&instance),
        vec!["before".to_owned(), "after".to_owned()]
    );
    // 다음 요청이 무른 DB 에 닿는다
    assert_eq!(
        http_get(&format!("{url}/notes?as=admin"), Some(&admin.cookie)),
        (200, json!(["before", "after"]))
    );
    // 되돌릴 지점은 하나라 다시 무르지 못한다. 그 지점은 운영 자리로 옮겨 갔다
    let (status, body) = bench.undo(FACTORY, &instance);
    assert_eq!(status, 409, "{body}");
    let point = report["restore_point"].as_str().unwrap();
    let left: i64 = bench
        .client("postgres")
        .query_one(
            "SELECT count(*) FROM pg_database WHERE datname = $1",
            &[&point],
        )
        .unwrap()
        .get(0);
    assert_eq!(left, 0);
    assert_eq!(
        bench.notes(&instance),
        vec!["before".to_owned(), "after".to_owned()]
    );
}

#[test]
fn 되살린_뒤_승격이_있었으면_되살리기를_무르지_못하고_까닭을_알린다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    bench.base_backup();
    bench.note(&instance, "x", "before");
    let at = moment();
    bench.note(&instance, "x", "after");
    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    // 그 뒤에 승격이 있었다. 되돌릴 지점이 그 승격의 것으로 바뀌었다
    let token = bench.token(FACTORY, &instance);
    let release = bench.preview(&instance, &token);
    let (status, body) = bench.promote(&instance, &release);
    assert_eq!(status, 200, "{body}");

    let (status, body) = bench.undo(FACTORY, &instance);
    assert_eq!(status, 409, "{body}");
    assert!(body["message"].as_str().unwrap().contains("승격"), "{body}");
    assert_eq!(bench.notes(&instance), vec!["before".to_owned()]);
}

#[test]
fn 한_인스턴스를_되살리는_동안_다른_인스턴스의_요청은_기다리지_않고_같은_인스턴스는_한_번에_하나만_되살린다()
 {
    let mut bench = bench!();
    let (first, _) = bench.shipped();
    let (second, _) = bench.shipped();
    bench.base_backup();
    bench.note(&first, "x", "before");
    let at = moment();
    bench.note(&first, "x", "after");

    let layer = Arc::clone(bench.layer.as_ref().unwrap());
    let target = first.clone();
    let restoring = std::thread::spawn(move || {
        let started = Instant::now();
        let reply = handle(
            &layer,
            "POST",
            &format!("/v1/instances/{target}/restore"),
            Some(FACTORY),
            json!({ "at": at }).to_string().as_bytes(),
        );
        (reply.status, started.elapsed())
    });
    // 되살리기가 옆에 클러스터를 세우는 동안(초 단위)
    std::thread::sleep(Duration::from_millis(150));
    let asked = Instant::now();
    let (status, body) = bench.call(
        "GET",
        &format!("/v1/instances/{second}/production"),
        FACTORY,
        &[],
    );
    let waited = asked.elapsed();
    assert_eq!(status, 200, "{body}");
    let (status, body) = bench.restore(FACTORY, &first, at);
    let still_running = !restoring.is_finished();
    let (restored, took) = restoring.join().unwrap();
    assert_eq!(restored, 200);
    // 다른 인스턴스의 요청은 되살리기를 기다리지 않는다
    assert!(
        waited < Duration::from_millis(500),
        "{waited:?} (되살리기 {took:?})"
    );
    assert!(
        still_running,
        "되살리기가 너무 빨리 끝나 재지 못했습니다({took:?})"
    );
    // 같은 인스턴스를 겹쳐 되살리지 않는다
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("되살리는 중"),
        "{body}"
    );
    assert_eq!(bench.notes(&first), vec!["before".to_owned()]);
}

#[test]
fn 에이전트의_토큰으로는_되살리지_못한다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    bench.base_backup();
    bench.note(&instance, "x", "before");
    let at = moment();
    bench.note(&instance, "x", "after");
    let token = bench.token(FACTORY, &instance);

    let (status, body) = bench.restore(&token, &instance, at);
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], json!("forbidden"));
    // 무르는 길도 그렇다
    let (status, body) = bench.undo(&token, &instance);
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        bench.notes(&instance),
        vec!["before".to_owned(), "after".to_owned()]
    );
    // 훈련의 모습도 토큰으로는 보지 못한다
    let (status, _) = bench.call("GET", "/v1/backup", &token, &[]);
    assert_eq!(status, 404);
}

#[test]
fn 다른_팩토리의_인스턴스는_되살리지_못한다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    bench.base_backup();
    bench.note(&instance, "x", "before");
    let at = moment();
    bench.note(&instance, "x", "after");

    let (status, body) = bench.restore(OTHER_FACTORY, &instance, at);
    let (missing_status, missing) = bench.restore(OTHER_FACTORY, "izzzzzzzzzz", at);
    // 거부와 부재를 구분하지 않는다
    assert_eq!((status, &body), (missing_status, &missing));
    assert_eq!(status, 404);
    assert_eq!(
        bench.notes(&instance),
        vec!["before".to_owned(), "after".to_owned()]
    );
}

// ---- 훈련이 통과해야 새 고객을 받는다 ----

#[test]
fn 훈련이_낡은_레이어는_켜_두었을_때_새_인스턴스를_받지_않고_이미_선_인스턴스는_그대로_오른다() {
    let mut bench = bench!(true);
    // 한 번도 통과하지 않았다
    let (status, body) = bench.create(FACTORY);
    assert_eq!(status, 409, "{body}");
    assert!(body["message"].as_str().unwrap().contains("훈련"), "{body}");

    assert!(bench.drill().passed);
    let instance = bench.instance(FACTORY);
    let token = bench.token(FACTORY, &instance);

    // 아흐레가 지났다. 새 인스턴스는 받지 않는다
    bench.ahead.store(9 * 24 * 60 * 60, Ordering::SeqCst);
    let (status, body) = bench.create(FACTORY);
    assert_eq!(status, 409, "{body}");
    assert_eq!(bench.status()["fresh"], json!(false));
    // 이미 선 인스턴스의 프리뷰와 승격은 막지 않는다
    let release = bench.preview(&instance, &token);
    let (status, production) = bench.promote(&instance, &release);
    assert_eq!(status, 200, "{production}");

    // 훈련이 다시 통과하면 받는다
    assert!(bench.drill().passed);
    let (status, body) = bench.create(FACTORY);
    assert_eq!(status, 200, "{body}");
    bench
        .instances
        .push((body["instance"].as_str().unwrap().to_owned(), FACTORY));
}

#[test]
fn 팩토리는_훈련의_통과_여부와_숫자만_본다() {
    let mut bench = bench!();
    assert_eq!(bench.status(), json!({ "fresh": false }));
    let (instance, _) = bench.shipped();
    bench.note(&instance, "x", SECRET_NOTE);
    let record = bench.drill();
    assert!(record.passed);

    let status = bench.status();
    assert_eq!(status["fresh"], json!(true));
    assert_eq!(status["last_passed_at"], json!(record.at));
    let last = status["last_drill"].as_object().unwrap();
    assert_eq!(last["passed"], json!(true));
    assert_eq!(last["at"], json!(record.at));
    let mut keys: Vec<&str> = last.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "at",
            "checks",
            "drill_millis",
            "exposure_seconds",
            "failed_checks",
            "instances",
            "passed",
            "recovery_millis",
        ]
    );
    // 글자는 하나도 없다. 숫자와 참 · 거짓만 있다
    for value in last.values() {
        assert!(
            value.is_number() || value.is_boolean() || value.is_null(),
            "{value}"
        );
    }
    let text = status.to_string();
    assert!(!text.contains(SECRET_NOTE));
    assert!(!text.contains(&instance));
    // 다른 팩토리도 같은 레이어의 훈련을 본다(레이어 하나의 일이다)
    let (code, other) = bench.call("GET", "/v1/backup", OTHER_FACTORY, &[]);
    assert_eq!(code, 200);
    assert_eq!(other["fresh"], json!(true));
}

// ---- 앱이 정의한 것은 관리 권한으로 돌지 않는다 ----

impl Bench {
    /// 인스턴스의 마이그레이션 역할로 들어가 소유자가 되어 `ledger.tag` 에 행을 넣는다(앱이 쓰는 것과 같은 권한).
    fn tag(&self, instance: &str, id: i32) {
        let mut config: postgres::Config = self.pg_url().parse().unwrap();
        config
            .user(&format!("i_{instance}_migrator"))
            .dbname(&format!("i_{instance}"));
        let mut client = config.connect(NoTls).unwrap();
        client
            .batch_execute(&format!("SET ROLE \"i_{instance}_owner\""))
            .unwrap();
        client
            .execute("INSERT INTO ledger.tag (id) VALUES ($1)", &[&id])
            .unwrap();
    }

    /// 관리 권한으로 돈 흔적. (표에 적힌 슈퍼유저의 줄 수, 그 인스턴스의 database 이름으로 쓰인 파일).
    fn superuser_traces(&self, instance: &str) -> (i64, Vec<String>) {
        let rows: i64 = self
            .client(&format!("i_{instance}"))
            .query_one(
                "SELECT count(*) FROM ledger.trace WHERE superuser = 'on'",
                &[],
            )
            .unwrap()
            .get(0);
        let files = fs::read_dir("/tmp")
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&format!("orbital-spy-i_{instance}")))
            .collect();
        (rows, files)
    }

    fn clear_traces(instance: &str) {
        for entry in fs::read_dir("/tmp").unwrap().flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("orbital-spy-i_{instance}"))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn tags(&self, instance: &str) -> Vec<i32> {
        self.client(&format!("i_{instance}"))
            .query("SELECT id FROM ledger.tag ORDER BY id", &[])
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// 인스턴스의 database 에 있는 것마다의 주인과 실제 권한. 이름만 있다.
    fn owners_and_grants(&self, instance: &str) -> Vec<String> {
        self.client(&format!("i_{instance}"))
            .query(
                "SELECT format('%s.%s %s %s', n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner)) \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' \
                 UNION ALL \
                 SELECT format('%s.%s %s %s', n.nspname, c.relname, coalesce(r.rolname, 'public'), a.privilege_type) \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a \
                 LEFT JOIN pg_roles r ON r.oid = a.grantee \
                 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'v') \
                 UNION ALL \
                 SELECT format('schema %s %s', nspname, pg_get_userbyid(nspowner)) FROM pg_namespace \
                 WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' \
                 UNION ALL \
                 SELECT format('fn %s.%s %s %s', n.nspname, p.proname, pg_get_userbyid(p.proowner), p.prosecdef) \
                 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' \
                 ORDER BY 1",
                &[],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }
}

#[test]
fn 되살릴_때_앱이_정의한_함수는_관리_권한으로_돌지_않는다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    Bench::clear_traces(&instance);
    bench.base_backup();
    bench.tag(&instance, 1);
    let at = moment();
    bench.tag(&instance, 2);
    assert_eq!(bench.superuser_traces(&instance), (0, Vec::new()));

    let (status, report) = bench.restore(FACTORY, &instance, at);
    let traces = bench.superuser_traces(&instance);
    Bench::clear_traces(&instance);
    assert_eq!(status, 200, "{report}");
    assert_eq!(bench.tags(&instance), vec![1]);
    // 행을 다시 넣으며 CHECK 의 함수가 돌았지만, 관리 권한으로 돈 흔적은 없다
    assert_eq!(traces, (0, Vec::new()));
}

#[test]
fn 훈련도_앱이_정의한_함수를_관리_권한으로_돌리지_않는다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    Bench::clear_traces(&instance);
    bench.tag(&instance, 1);
    bench.tag(&instance, 2);

    let record = bench.drill();
    let traces = bench.superuser_traces(&instance);
    Bench::clear_traces(&instance);
    assert!(record.passed, "{record:#?}");
    // 훈련이 옮겨 본 것은 이 인스턴스의 database 다
    assert!(record.checks.iter().any(|checked| checked.check
        == Check::Moved {
            database: format!("i_{instance}")
        }));
    assert_eq!(traces, (0, Vec::new()));
}

#[test]
fn 되살린_뒤에도_표의_주인과_권한이_되살리기_전과_같다() {
    let mut bench = bench!();
    let (instance, _) = bench.shipped();
    bench.person(&instance, "a1@example.test", "admin");
    bench.base_backup();
    bench.note(&instance, "x", "before");
    let at = moment();
    bench.note(&instance, "x", "after");
    let before = bench.owners_and_grants(&instance);
    let schema_before = orbital_backup::fingerprint(&mut bench.client(&format!("i_{instance}")))
        .unwrap()
        .schema;

    let (status, report) = bench.restore(FACTORY, &instance, at);
    assert_eq!(status, 200, "{report}");
    assert_eq!(bench.owners_and_grants(&instance), before);
    let schema_after = orbital_backup::fingerprint(&mut bench.client(&format!("i_{instance}")))
        .unwrap()
        .schema;
    assert_eq!(schema_after, schema_before);
}
