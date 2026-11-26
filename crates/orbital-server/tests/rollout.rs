//! rollout: 앱(위쪽)의 업데이트 하나를 포크 셋에 밀거나 당긴다. 한 곳이 실패하면 나머지가 멈추고, 적합성 테스트를 통과한 곳만 운영에 오른다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버)와 실제 적합성 테스트(Node 스크립트)로 잰다. 관리 서버의 API 는 HTTP 층의
//! `handle` 에 바로 넣고, 띄운 앱에는 실제 HTTP 로 요청한다. 스캐폴드는 `fixtures/fleet`(v1)이고, 업데이트(v2)는 그 위에
//! `fixtures/fleet-update` 를 덮어 만든다. 포크마다 고치는 자리는 `custom.json` 이다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, Options};
use orbital_server::seal::SealKey;
use serde_json::{Value, json};

/// 레이어마다 다른 control database 의 이름. 같은 `home` 으로 다시 열면 같은 이름이라 다시 뜬 레이어가 같은 기록을 본다.
fn control_of(home: &std::path::Path) -> orbital_core::name::Ident {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    home.hash(&mut hasher);
    orbital_core::name::Ident::parse(&format!("ctl_{:016x}", hasher.finish())).unwrap()
}

/// 테스트가 세운 control database 를 걷는다.
fn forget_control(home: &std::path::Path) {
    if let Ok(pg_url) = std::env::var("ORBITAL_PG") {
        let _ = orbital_server::records::drop_database(&pg_url, &control_of(home));
    }
}

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];
/// 어디에 새어도 찾을 수 있게 드문 글자로 지은 값.
const BANK: &str = "sk_live_bank_Rr93kXa2Pqe";
const BANK_PREVIEW: &str = "sk_test_bank_Mn58tYc1Lzw";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn git(folder: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// 실패해도 되는 git. 성공했는지만 돌려준다.
fn git_may_fail(folder: &Path, args: &[&str]) -> bool {
    Command::new("git")
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
        .unwrap()
        .status
        .success()
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

/// 포크의 `custom.json` 을 바꾼다.
fn custom(work: &Path, value: &Value) {
    fs::write(work.join("custom.json"), value.to_string()).unwrap();
}

fn get(url: &str) -> (u16, Value) {
    let response = ureq::get(url).timeout(Duration::from_secs(30)).call();
    match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => {
            let status = response.status();
            (status, response.into_json().unwrap_or(Value::Null))
        }
        Err(error) => panic!("GET {url}: {error}"),
    }
}

fn url(report: &Value) -> String {
    report["services"][0]["url"].as_str().unwrap().to_owned()
}

/// rollout 의 답에서 인스턴스 하나의 진행.
fn state(rollout: &Value, instance: &str) -> Value {
    rollout["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["instance"] == instance)
        .cloned()
        .unwrap_or(Value::Null)
}

struct Lab {
    scratch: PathBuf,
    home: PathBuf,
    pg_url: String,
    conformance_timeout: Duration,
    layer: Option<Layer>,
    instances: Vec<(String, &'static str)>,
}

impl Lab {
    fn new(conformance_timeout: Duration) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-rollout-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let mut lab = Self {
            home: scratch.join("home"),
            scratch,
            pg_url,
            conformance_timeout,
            layer: None,
            instances: Vec::new(),
        };
        lab.open();
        for key in [FACTORY, OTHER_FACTORY] {
            lab.scaffold(key, "fleet");
        }
        Some(lab)
    }

    fn open(&mut self) {
        self.layer = Some(
            Layer::open(Options {
                seal_key: Some(SealKey::from_bytes([9; 32])),
                dev_mailbox: true,
                conformance_timeout: self.conformance_timeout,
                control_database: control_of(&self.home),
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
    }

    /// 관리 서버가 내려갔다가 다시 뜬 것처럼 한다. 앞의 레이어가 띄운 것은 모두 내려간다.
    fn restart(&mut self) {
        drop(self.layer.take());
        self.open();
    }

    fn layer(&self) -> &Layer {
        self.layer.as_ref().unwrap()
    }

    /// 팩토리가 앱을 고치는 폴더.
    fn upstream(&self, key: &str, app: &str) -> PathBuf {
        self.scratch.join(format!("upstream-{key}-{app}"))
    }

    fn publish(&self, key: &str, app: &str) {
        let folder = self.upstream(key, app);
        let bundle = self.scratch.join(format!(
            "{key}-{app}-{}.bundle",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
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
            key,
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
    }

    /// 스캐폴드 v1 을 올린다.
    fn scaffold(&self, key: &str, app: &str) {
        let folder = self.upstream(key, app);
        copy_tree(&fixture("fleet"), &folder);
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        self.publish(key, app);
    }

    /// 팩토리가 업데이트(v2)를 앱의 `main` 에 올린다. 업데이트 commit 을 돌려준다.
    fn update(&self, key: &str) -> String {
        let folder = self.upstream(key, "fleet");
        copy_tree(&fixture("fleet-update"), &folder);
        git(&folder, &["add", "-A"]);
        git(
            &folder,
            &["commit", "--quiet", "-m", "업데이트 v2: 새 기능"],
        );
        git(&folder, &["tag", "v2"]);
        self.publish(key, "fleet");
        git(&folder, &["rev-parse", "HEAD"])
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

    fn instance_of(&mut self, key: &'static str, app: &str) -> String {
        let (status, body) = self.post(
            "/v1/instances",
            key,
            &json!({ "app": app, "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push((instance.clone(), key));
        instance
    }

    fn instance(&mut self) -> String {
        self.instance_of(FACTORY, "fleet")
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

    /// 에이전트가 하듯이 코드를 받아 온다. 받은 폴더를 돌려준다.
    fn clone_source(&self, instance: &str, token: &str) -> PathBuf {
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
        work
    }

    /// 받은 폴더의 `main` 을 올린다. 올라간 commit 을 돌려준다.
    fn push(&self, instance: &str, token: &str, work: &Path) -> String {
        let pushed = self.scratch.join(format!(
            "push-{}.bundle",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        git(
            work,
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
        body["commit"].as_str().unwrap().to_owned()
    }

    /// 에이전트가 코드를 받아 고치고 올린다.
    fn change(&self, instance: &str, token: &str, edit: &dyn Fn(&Path)) -> String {
        let work = self.clone_source(instance, token);
        edit(&work);
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "--quiet", "-m", "고친다"]);
        self.push(instance, token, &work)
    }

    /// 포크의 `main` 의 끝.
    fn head(&self, instance: &str, token: &str) -> String {
        let work = self.clone_source(instance, token);
        git(&work, &["rev-parse", "main"])
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

    fn request(&self, instance: &str, token: &str, release: &str) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            token,
            &json!({ "release": release }),
        )
    }

    fn promote(&self, instance: &str, release: &str, change: &str, by: &str) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            &json!({ "release": release, "change": change, "approved_by": by }),
        )
    }

    /// 프리뷰를 세우고 승격을 요청한 뒤 올린다. (프리뷰, 승격의 상태, 승격의 답).
    fn ship(&self, instance: &str, token: &str, change: &str, by: &str) -> (Value, u16, Value) {
        let preview = self.preview(instance, token);
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, body) = self.request(instance, token, &release);
        assert_eq!(status, 200, "{body}");
        let (status, production) = self.promote(instance, &release, change, by);
        (preview, status, production)
    }

    fn rollout(&self, key: &str, change: &str, waves: &[&[&str]]) -> (u16, Value) {
        self.post(
            "/v1/apps/fleet/rollouts",
            key,
            &json!({ "change": change, "waves": waves }),
        )
    }

    fn rollout_ok(&self, change: &str, waves: &[&[&str]]) -> Value {
        let (status, rollout) = self.rollout(FACTORY, change, waves);
        assert_eq!(status, 200, "{rollout}");
        rollout
    }

    fn get_rollout(&self, key: &str, id: &str) -> (u16, Value) {
        self.call("GET", &format!("/v1/rollouts/{id}"), key, &[])
    }

    fn now(&self, id: &str) -> Value {
        let (status, rollout) = self.get_rollout(FACTORY, id);
        assert_eq!(status, 200, "{rollout}");
        rollout
    }

    fn apply(&self, key: &str, id: &str, instance: &str) -> (u16, Value) {
        self.call(
            "POST",
            &format!("/v1/rollouts/{id}/instances/{instance}/apply"),
            key,
            &[],
        )
    }

    fn apply_ok(&self, id: &str, instance: &str) -> Value {
        let (status, applied) = self.apply(FACTORY, id, instance);
        assert_eq!(status, 200, "{applied}");
        assert_eq!(applied["applied"], true, "{applied}");
        applied
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
}

impl Drop for Lab {
    fn drop(&mut self) {
        if self.layer.is_some() {
            for (instance, key) in &self.instances {
                let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), key, &[]);
            }
            drop(self.layer.take());
        }
        forget_control(&self.home);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! lab {
    () => {
        lab!(Duration::from_secs(120))
    };
    ($timeout:expr) => {
        match Lab::new($timeout) {
            Some(lab) => lab,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn id(rollout: &Value) -> String {
    rollout["id"].as_str().unwrap().to_owned()
}

fn release(preview: &Value) -> String {
    preview["release"].as_str().unwrap().to_owned()
}

// ---- 끝 기준의 한 바퀴 ----

#[test]
fn 포크_셋에_업데이트_하나를_밀어_적합성_테스트를_통과한_곳만_오른다() {
    let mut lab = lab!();
    let forks: Vec<(String, String)> = (0..3)
        .map(|_| {
            let instance = lab.instance();
            let token = lab.token(FACTORY, &instance);
            (instance, token)
        })
        .collect();
    let [(a, ta), (b, tb), (c, tc)] = &forks[..] else {
        unreachable!()
    };
    // 포크마다 고객의 손이 닿았다. c 는 업데이트의 새 기능을 깨뜨리는 설정을 갖고 있다
    lab.change(a, ta, &|work| {
        custom(work, &json!({ "greeting": "A사입니다" }))
    });
    lab.change(b, tb, &|work| {
        custom(work, &json!({ "greeting": "B사입니다" }))
    });
    lab.change(c, tc, &|work| {
        custom(
            work,
            &json!({ "greeting": "C사입니다", "break_feature": true }),
        )
    });

    let update = lab.update(FACTORY);
    let rollout = lab.rollout_ok("security_update", &[&[a], &[b, c]]);
    let rid = id(&rollout);
    assert_eq!(rollout["commit"], update.as_str());
    assert_eq!(rollout["status"], "running");
    for instance in [a, b, c] {
        lab.apply_ok(&rid, instance);
    }

    // 앞 물결: a 가 통과하고 팩토리의 승인으로 오른다
    let preview = lab.preview(a, ta);
    assert_eq!(preview["conformance"]["passed"], true, "{preview}");
    let (status, body) = lab.request(a, ta, &release(&preview));
    assert_eq!(status, 200, "{body}");
    let (status, production) = lab.promote(a, &release(&preview), "security_update", "factory");
    assert_eq!(status, 200, "{production}");
    assert_eq!(get(&format!("{}/feature", url(&production))).0, 200);
    assert_eq!(
        get(&format!("{}/greeting", url(&production))).1["greeting"],
        "A사입니다"
    );

    // 뒤 물결: b 는 통과하고 c 는 적합성 테스트에서 떨어진다. rollout 이 멈춘다
    let preview_b = lab.preview(b, tb);
    assert_eq!(preview_b["conformance"]["passed"], true, "{preview_b}");
    let preview_c = lab.preview(c, tc);
    assert_eq!(preview_c["conformance"]["passed"], false, "{preview_c}");
    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted");
    assert_eq!(
        state(&now, c),
        json!({ "instance": c, "state": "failed", "reason": "conformance_failed" })
    );
    let (status, body) = lab.request(b, tb, &release(&preview_b));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert_eq!(lab.production(b), Value::Null);

    // 팩토리가 다시 열면 b 가 오르고, c 는 고친 release 로 다시 지나 오른다
    let (status, body) = lab.post(&format!("/v1/rollouts/{rid}/resume"), FACTORY, &json!({}));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    lab.change(c, tc, &|work| {
        custom(work, &json!({ "greeting": "C사입니다" }))
    });
    let (preview_c, status, production_c) = lab.ship(c, tc, "security_update", "factory");
    assert_eq!(preview_c["conformance"]["passed"], true, "{preview_c}");
    assert_eq!(status, 200, "{production_c}");
    assert_eq!(
        get(&format!("{}/greeting", url(&production_c))).1["greeting"],
        "C사입니다"
    );

    let done = lab.now(&rid);
    assert_eq!(done["status"], "done", "{done}");
    for instance in [a, b, c] {
        assert_eq!(state(&done, instance)["state"], "promoted");
    }
}

// ---- 멈춤과 물결 ----

#[test]
fn 한_곳이_실패하면_rollout_이_멈추고_나머지는_오르지_못한다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.change(&b, &tb, &|work| {
        custom(work, &json!({ "greeting": "B", "break_feature": true }))
    });
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);

    let preview_a = lab.preview(&a, &ta);
    assert_eq!(state(&lab.now(&rid), &a)["state"], "passed");
    let preview_b = lab.preview(&b, &tb);
    assert_eq!(preview_b["conformance"]["outcome"], "failed", "{preview_b}");

    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted");
    assert_eq!(state(&now, &b)["reason"], "conformance_failed");
    let (status, body) = lab.request(&a, &ta, &release(&preview_a));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(&a, &release(&preview_a), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert!(body["message"].as_str().unwrap().contains("멈춰"), "{body}");
    assert_eq!(lab.production(&a), Value::Null);
    assert_eq!(state(&lab.now(&rid), &a)["state"], "passed");
}

/// 포크가 DB 를 더하되 권한 표에 적지 않은 표를 마이그레이션이 만든다. 그 release 의 프리뷰는 서지만 권한 검사가 어긋난다.
fn add_unlisted_table(work: &Path) {
    let manifest = fs::read_to_string(work.join("orbital.toml"))
        .unwrap()
        .replace("path = \"/\"\n", "path = \"/\"\nroles = [\"member\"]\n");
    fs::write(
        work.join("orbital.toml"),
        format!(
            "{manifest}\n[database]\nschemas = [\"fleet\"]\nmigrations = \"db/migrations\"\nroles = [\"member\"]\n"
        ),
    )
    .unwrap();
    fs::create_dir_all(work.join("db/migrations")).unwrap();
    fs::write(
        work.join("db/migrations/001_item.sql"),
        "CREATE TABLE fleet.item (id int PRIMARY KEY);\nALTER TABLE fleet.item ENABLE ROW LEVEL SECURITY;\nCREATE TABLE fleet.note (id int PRIMARY KEY);\n",
    )
    .unwrap();
    fs::write(
        work.join("db/access.toml"),
        "[fleet.item]\nmember = \"read\"\n",
    )
    .unwrap();
}

#[test]
fn 업데이트를_담은_release_의_프리뷰에서_권한이_어긋나면_그_인스턴스가_실패로_적히고_rollout_이_멈춘다()
 {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.change(&b, &tb, &add_unlisted_table);
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);

    let preview_a = lab.preview(&a, &ta);
    assert_eq!(state(&lab.now(&rid), &a)["state"], "passed");
    // b 의 프리뷰는 서고 적합성 테스트도 통과하지만 권한 검사가 어긋난다
    let preview_b = lab.preview(&b, &tb);
    assert_eq!(preview_b["conformance"]["passed"], true, "{preview_b}");
    assert!(
        preview_b["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding.as_str().unwrap_or_default().contains("fleet.note"))),
        "{preview_b}"
    );
    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted", "{now}");
    assert_eq!(
        state(&now, &b),
        json!({ "instance": b, "state": "failed", "reason": "access_check_failed" })
    );
    // 멈춘 동안 a 는 통과했어도 오르지 못한다
    let (status, body) = lab.request(&a, &ta, &release(&preview_a));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(&a, &release(&preview_a), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert_eq!(lab.production(&a), Value::Null);
}

#[test]
fn 멈춘_rollout_은_팩토리가_다시_열어야_이어진다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.change(&b, &tb, &|work| {
        custom(work, &json!({ "greeting": "B", "break_feature": true }))
    });
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);
    let preview_a = lab.preview(&a, &ta);
    lab.preview(&b, &tb);
    assert_eq!(lab.now(&rid)["status"], "halted");

    // 에이전트의 토큰으로는 다시 열지 못한다
    let (status, _) = lab.post(&format!("/v1/rollouts/{rid}/resume"), &ta, &json!({}));
    assert_eq!(status, 403);
    assert_eq!(lab.now(&rid)["status"], "halted");

    let (status, resumed) = lab.post(&format!("/v1/rollouts/{rid}/resume"), FACTORY, &json!({}));
    assert_eq!(status, 200, "{resumed}");
    assert_eq!(resumed["status"], "running");
    // 실패한 곳은 처음부터 다시 지난다
    assert_eq!(state(&resumed, &b)["state"], "waiting");
    let (status, body) = lab.request(&a, &ta, &release(&preview_a));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(&a, &release(&preview_a), "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    // 다시 열 것이 없으면 거절한다
    let (status, _) = lab.post(&format!("/v1/rollouts/{rid}/resume"), FACTORY, &json!({}));
    assert_eq!(status, 409);
}

#[test]
fn 앞_물결이_모두_오르기_전에는_뒤_물결이_오르지_못한다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a], &[&b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);

    // 뒤 물결의 b 가 먼저 통과했다. 그래도 a 가 오르기 전에는 오르지 못한다
    let preview_b = lab.preview(&b, &tb);
    let (status, body) = lab.request(&b, &tb, &release(&preview_b));
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(&b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert!(body["message"].as_str().unwrap().contains(&a), "{body}");
    assert_eq!(lab.production(&b), Value::Null);

    let (_, status, body) = lab.ship(&a, &ta, "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    let (status, body) = lab.promote(&b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    assert_eq!(lab.now(&rid)["status"], "done");
}

// ---- 합치기 ----

#[test]
fn 충돌_없는_포크는_레이어가_업데이트를_합친다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "A사입니다" }))
    });
    let before = lab.head(&a, &ta);
    let update = lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("feature_update", &[&[&a]]));

    let applied = lab.apply_ok(&rid, &a);
    assert_eq!(applied["conflicts"], json!([]));
    let merged = applied["commit"].as_str().unwrap().to_owned();
    assert_eq!(state(&lab.now(&rid), &a)["state"], "applied");

    // 합친 commit 은 포크의 앞 commit 과 업데이트를 부모로 둘 다 담는다. 포크의 손길과 업데이트가 함께 있다
    let work = lab.clone_source(&a, &ta);
    assert_eq!(git(&work, &["rev-parse", "main"]), merged);
    let parents = git(&work, &["rev-list", "--parents", "-n", "1", "main"]);
    assert_eq!(
        parents,
        format!("{merged} {before} {update}"),
        "합친 commit 의 부모"
    );
    let custom_text = fs::read_to_string(work.join("custom.json")).unwrap();
    assert!(custom_text.contains("A사입니다"), "{custom_text}");
    let server = fs::read_to_string(work.join("server.js")).unwrap();
    assert!(server.contains("const VERSION = 2;"), "{server}");
    // 다시 불러도 같은 자리다
    let again = lab.apply_ok(&rid, &a);
    assert_eq!(again["commit"], merged.as_str());
}

#[test]
fn 충돌하는_포크는_건드리지_않고_충돌한_파일을_알려_준다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    // 업데이트가 바꾸는 줄을 포크도 바꿨다
    lab.change(&a, &ta, &|work| {
        let path = work.join("server.js");
        let text = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            text.replace("const VERSION = 1;", "const VERSION = \"1-acme\";"),
        )
        .unwrap();
    });
    let before = lab.head(&a, &ta);
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("feature_update", &[&[&a]]));

    let (status, applied) = lab.apply(FACTORY, &rid, &a);
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["applied"], false);
    assert_eq!(applied["conflicts"], json!(["server.js"]));
    assert!(applied.get("commit").is_none(), "{applied}");
    assert_eq!(lab.head(&a, &ta), before);
    assert_eq!(state(&lab.now(&rid), &a)["state"], "waiting");
}

#[test]
fn 에이전트가_충돌을_풀어_올린_commit_이_업데이트를_담으면_적용된_것으로_본다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.change(&a, &ta, &|work| {
        let path = work.join("server.js");
        let text = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            text.replace("const VERSION = 1;", "const VERSION = \"1-acme\";"),
        )
        .unwrap();
    });
    let update = lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("feature_update", &[&[&a]]));
    let (_, applied) = lab.apply(FACTORY, &rid, &a);
    assert_eq!(applied["applied"], false);

    // 토큰으로 진행을 보면 합칠 업데이트가 보인다
    let (status, view) = lab.call("GET", &format!("/v1/instances/{a}/rollout"), &ta, &[]);
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["update"], update.as_str());

    // 업데이트를 담지 않은 commit 을 올려도 적용된 것이 아니다
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "아직 합치지 않았습니다" }))
    });
    assert_eq!(state(&lab.now(&rid), &a)["state"], "waiting");

    // 받은 저장소에 업데이트가 `origin/update` 로 있다. 에이전트가 합쳐 충돌을 풀고 올린다
    let work = lab.clone_source(&a, &ta);
    assert_eq!(git(&work, &["rev-parse", "origin/update"]), update);
    assert!(!git_may_fail(
        &work,
        &["merge", "--no-edit", "origin/update"]
    ));
    git(&work, &["checkout", "--theirs", "server.js"]);
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "--no-edit"]);
    lab.push(&a, &ta, &work);
    assert_eq!(state(&lab.now(&rid), &a)["state"], "applied");

    let preview = lab.preview(&a, &ta);
    assert_eq!(preview["conformance"]["passed"], true, "{preview}");
    assert_eq!(state(&lab.now(&rid), &a)["state"], "passed");
}

#[test]
fn 업데이트를_담지_않은_release_는_rollout_과_무관하게_오른다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.change(&b, &tb, &|work| {
        custom(work, &json!({ "greeting": "B", "break_feature": true }))
    });
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &b);
    lab.preview(&b, &tb);
    assert_eq!(lab.now(&rid)["status"], "halted");

    // a 는 업데이트를 합치지 않고 고객의 요청만 고쳤다. 멈춘 rollout 과 무관하게 고객의 승인으로 오른다
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "고객의 요청" }))
    });
    let (preview, status, production) = lab.ship(&a, &ta, "customer_request", "customer");
    assert_eq!(status, 200, "{production}");
    // 위쪽 v1 의 적합성 테스트가 돌았다
    let output = preview["conformance"]["output"].as_str().unwrap();
    assert!(output.contains("위쪽의 적합성 테스트 v1"), "{output}");
    assert_eq!(get(&format!("{}/feature", url(&production))).0, 404);
    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted");
    assert_eq!(state(&now, &a)["state"], "waiting");
}

// ---- 적합성 테스트 ----

#[test]
fn 적합성_테스트는_포크가_고치거나_지워도_위쪽의_것으로_돈다() {
    let mut lab = lab!();
    let (a, b, c) = (lab.instance(), lab.instance(), lab.instance());
    let (ta, tb, tc) = (
        lab.token(FACTORY, &a),
        lab.token(FACTORY, &b),
        lab.token(FACTORY, &c),
    );
    // rollout 밖의 프리뷰에서도 위쪽(v1)의 것으로 돈다. 포크가 테스트의 폴더와 선언을 지웠다
    lab.change(&c, &tc, &|work| {
        fs::remove_dir_all(work.join("conformance")).unwrap();
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        let cut = manifest.find("# 적합성 테스트").unwrap();
        fs::write(work.join("orbital.toml"), &manifest[..cut]).unwrap();
    });
    let preview_c = lab.preview(&c, &tc);
    assert_eq!(preview_c["conformance"]["passed"], true, "{preview_c}");
    assert!(
        preview_c["conformance"]["output"]
            .as_str()
            .unwrap()
            .contains("위쪽의 적합성 테스트 v1")
    );

    let update = lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);
    // a: 새 기능을 깨뜨리고, 테스트를 늘 통과하게 고치고, 선언의 명령도 바꿨다. 소용없다
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "A", "break_feature": true }));
        fs::write(work.join("conformance/check.mjs"), "process.exit(0);\n").unwrap();
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        fs::write(
            work.join("orbital.toml"),
            manifest.replace("node conformance/check.mjs", "true"),
        )
        .unwrap();
    });
    let preview_a = lab.preview(&a, &ta);
    let conformance = &preview_a["conformance"];
    assert_eq!(conformance["passed"], false, "{preview_a}");
    assert_eq!(conformance["upstream"], update.as_str());
    assert!(
        conformance["output"]
            .as_str()
            .unwrap()
            .contains("위쪽의 적합성 테스트 v2"),
        "{conformance}"
    );
    // b: 테스트를 지웠다. 위쪽의 것이 그대로 돌아 통과한다
    lab.change(&b, &tb, &|work| {
        fs::remove_dir_all(work.join("conformance")).unwrap();
    });
    let preview_b = lab.preview(&b, &tb);
    assert_eq!(preview_b["conformance"]["passed"], true, "{preview_b}");
    assert!(
        preview_b["conformance"]["output"]
            .as_str()
            .unwrap()
            .contains("위쪽의 적합성 테스트 v2")
    );
}

#[test]
fn 적합성_테스트의_자리에는_위쪽의_폴더만_놓이고_포크의_코드는_놓이지_않는다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    // 포크가 테스트의 폴더에 파일을 끼워 넣고, 테스트가 불러 쓸 만한 것을 옆에 둔다
    lab.change(&a, &ta, &|work| {
        fs::write(work.join("conformance/planted.mjs"), "process.exit(0);\n").unwrap();
        fs::create_dir_all(work.join("node_modules/planted")).unwrap();
        fs::write(work.join("node_modules/planted/index.js"), "\n").unwrap();
    });
    let preview = lab.preview(&a, &ta);
    let conformance = &preview["conformance"];
    assert_eq!(conformance["passed"], true, "{preview}");
    let output = conformance["output"].as_str().unwrap();
    // 실행기가 두는 빈 홈(`.orbital-home`)과 위쪽의 폴더뿐이다. 포크의 `server.js` 도 `node_modules` 도 없다
    assert!(
        output.contains(r#"files [".orbital-home","conformance"]"#),
        "{output}"
    );
    assert!(!output.contains("planted"), "{output}");
    // 에이전트에게 가는 글이라 레이어의 폴더 경로(테스트의 홈이 그 아래에 있다)는 가린다
    assert!(output.contains("<레이어>"), "{output}");
    assert!(
        !output.contains(&lab.home.display().to_string()),
        "{output}"
    );
}

#[test]
fn 적합성_테스트를_통과하지_못한_release_는_승격을_요청하지_못한다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "A", "unhealthy": true }))
    });
    let preview = lab.preview(&a, &ta);
    assert_eq!(preview["conformance"]["outcome"], "failed", "{preview}");
    let blockers: Vec<&str> = preview["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        blockers.iter().any(|text| text.contains("적합성 테스트")),
        "{preview}"
    );
    let (status, body) = lab.request(&a, &ta, &release(&preview));
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "denied");
    assert!(
        body["details"][0]
            .as_str()
            .unwrap()
            .contains("적합성 테스트"),
        "{body}"
    );
    // 팩토리가 사람의 승인을 들고 와도 오르지 못한다
    let (status, body) = lab.promote(&a, &release(&preview), "customer_request", "customer");
    assert_eq!(status, 409, "{body}");
    assert_eq!(lab.production(&a), Value::Null);
}

#[test]
fn 적합성_테스트에는_비밀과_운영의_값이_건네지지_않는다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.change(&a, &ta, &|work| {
        let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
        fs::write(
            work.join("orbital.toml"),
            format!(
                "{manifest}\n[secrets]\ngenerated = [\"SESSION_KEY\"]\nexternal = [\"BANK_API_KEY\"]\n"
            ),
        )
        .unwrap();
    });
    // 비밀은 선언한 release 의 프리뷰를 세운 뒤에 넣는다
    lab.preview(&a, &ta);
    for (stage, value) in [("preview", BANK_PREVIEW), ("production", BANK)] {
        let (status, body) = lab.call(
            "PUT",
            &format!("/v1/instances/{a}/secrets/BANK_API_KEY"),
            FACTORY,
            json!({ "stage": stage, "value": value })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(status, 200, "{body}");
    }
    let (_, status, production) = lab.ship(&a, &ta, "customer_request", "customer");
    assert_eq!(status, 200, "{production}");
    let live = url(&production);

    let preview = lab.preview(&a, &ta);
    let output = preview["conformance"]["output"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(preview["conformance"]["passed"], true, "{preview}");
    // 프리뷰의 주소만 건너간다
    assert!(
        output.contains(&format!("\"ORBITAL_PREVIEW_URL\":\"{}\"", url(&preview))),
        "{output}"
    );
    for leaked in [
        BANK,
        BANK_PREVIEW,
        "BANK_API_KEY",
        "SESSION_KEY",
        "PGHOST",
        "ORBITAL_DB",
        "ORBITAL_PG",
        "ORBITAL_STAGE",
        FACTORY,
        live.as_str(),
        lab.pg_url.as_str(),
    ] {
        assert!(
            !output.contains(leaked),
            "`{leaked}` 이 건너갔습니다: {output}"
        );
    }
    // 출력은 끝부분만 남긴다
    assert!(output.chars().count() <= 4000, "{}", output.len());
}

#[test]
fn 적합성_테스트가_제한_시간을_넘기면_실패로_적는다() {
    let mut lab = lab!(Duration::from_secs(3));
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a]]));
    lab.apply_ok(&rid, &a);
    lab.change(&a, &ta, &|work| {
        custom(work, &json!({ "greeting": "A", "slow_feature": true }))
    });
    let preview = lab.preview(&a, &ta);
    let conformance = &preview["conformance"];
    assert_eq!(conformance["outcome"], "timed_out", "{preview}");
    assert_eq!(conformance["passed"], false);
    let millis = conformance["millis"].as_u64().unwrap();
    assert!((3_000..30_000).contains(&millis), "{millis}");
    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted");
    assert_eq!(state(&now, &a)["reason"], "conformance_failed");
    let (status, _) = lab.request(&a, &ta, &release(&preview));
    assert_eq!(status, 409);
}

// ---- 승인자 ----

#[test]
fn 당기기는_고객의_승인으로_밀기는_팩토리의_승인으로_오른다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.update(FACTORY);
    let pull = id(&lab.rollout_ok("feature_update", &[&[&a]]));
    let push = id(&lab.rollout_ok("security_update", &[&[&b]]));
    lab.apply_ok(&pull, &a);
    lab.apply_ok(&push, &b);

    // 당기기(기능 업데이트): rollout 이 정한 change 로만, 고객의 승인으로 오른다
    let preview_a = lab.preview(&a, &ta);
    lab.request(&a, &ta, &release(&preview_a));
    let (status, body) = lab.promote(&a, &release(&preview_a), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("feature_update"),
        "{body}"
    );
    let (status, body) = lab.promote(&a, &release(&preview_a), "feature_update", "factory");
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "denied");
    let (status, body) = lab.promote(&a, &release(&preview_a), "feature_update", "customer");
    assert_eq!(status, 200, "{body}");

    // 밀기(보안 업데이트): 팩토리의 승인으로 오른다
    let preview_b = lab.preview(&b, &tb);
    lab.request(&b, &tb, &release(&preview_b));
    let (status, body) = lab.promote(&b, &release(&preview_b), "security_update", "customer");
    assert_eq!(status, 409, "{body}");
    let (status, body) = lab.promote(&b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    assert_eq!(lab.now(&pull)["status"], "done");
    assert_eq!(lab.now(&push)["status"], "done");
}

#[test]
fn 승격이_되돌려진_인스턴스는_실패로_적히고_rollout_이_멈춘다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    let (first, status, body) = lab.ship(&a, &ta, "customer_request", "customer");
    assert_eq!(status, 200, "{body}");
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    lab.apply_ok(&rid, &b);
    // 프리뷰에서는 서고 운영에서만 뜨지 않는 포크
    lab.change(&a, &ta, &|work| {
        custom(
            work,
            &json!({ "greeting": "A", "crash_in_production": true }),
        )
    });
    let preview_b = lab.preview(&b, &tb);
    lab.request(&b, &tb, &release(&preview_b));
    let (_, status, body) = lab.ship(&a, &ta, "security_update", "factory");
    assert_ne!(status, 200, "{body}");
    // 앞의 release 로 돌아갔다
    assert_eq!(lab.production(&a)["release"], release(&first));

    let now = lab.now(&rid);
    assert_eq!(now["status"], "halted");
    assert_eq!(
        state(&now, &a),
        json!({ "instance": a, "state": "failed", "reason": "rolled_back" })
    );
    let (status, body) = lab.promote(&b, &release(&preview_b), "security_update", "factory");
    assert_eq!(status, 409, "{body}");
}

// ---- 범위 ----

#[test]
fn 다른_앱의_포크는_rollout_에_넣지_못한다() {
    let mut lab = lab!();
    lab.scaffold(FACTORY, "notes");
    let a = lab.instance();
    let note = lab.instance_of(FACTORY, "notes");
    lab.update(FACTORY);
    let (status, body) = lab.rollout(FACTORY, "security_update", &[&[&a, &note]]);
    assert_eq!(status, 422, "{body}");
    assert!(
        body["details"][0].as_str().unwrap().contains(&note),
        "{body}"
    );
    // 만들지 않았으므로 a 는 다른 rollout 에 든다
    lab.rollout_ok("security_update", &[&[&a]]);
}

#[test]
fn 다른_팩토리의_rollout_은_없는_것으로_답한다() {
    let mut lab = lab!();
    let a = lab.instance();
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a]]));
    let missing = "rzzzzzzzzzz";
    for (method, tail) in [
        ("GET", String::new()),
        ("POST", "/resume".to_owned()),
        ("POST", "/cancel".to_owned()),
        ("POST", format!("/instances/{a}/apply")),
    ] {
        let theirs = lab.call(
            method,
            &format!("/v1/rollouts/{rid}{tail}"),
            OTHER_FACTORY,
            &[],
        );
        let nowhere = lab.call(
            method,
            &format!("/v1/rollouts/{missing}{tail}"),
            OTHER_FACTORY,
            &[],
        );
        assert_eq!(theirs.0, 404, "{method} {tail}: {}", theirs.1);
        assert_eq!(theirs, nowhere, "{method} {tail}");
    }
    assert_eq!(lab.now(&rid)["status"], "running");
    assert_eq!(state(&lab.now(&rid), &a)["state"], "waiting");
    // 다른 팩토리의 인스턴스를 넣으려 해도 없는 인스턴스와 같은 답이다
    let theirs = lab.rollout(OTHER_FACTORY, "security_update", &[&[&a]]);
    let nowhere = lab.rollout(OTHER_FACTORY, "security_update", &[&["izzzzzzzzzz"]]);
    assert_eq!(theirs.0, 422, "{}", theirs.1);
    assert_eq!(
        theirs.1["details"][0]
            .as_str()
            .unwrap()
            .replace(a.as_str(), "*"),
        nowhere.1["details"][0]
            .as_str()
            .unwrap()
            .replace("izzzzzzzzzz", "*")
    );
}

#[test]
fn 에이전트의_토큰으로는_rollout_을_만들지도_다시_열지도_못한다() {
    let mut lab = lab!();
    let a = lab.instance();
    let ta = lab.token(FACTORY, &a);
    lab.update(FACTORY);
    let (status, body) = lab.rollout(&ta, "security_update", &[&[&a]]);
    assert_eq!(status, 403, "{body}");
    // 만들어지지 않았으므로 팩토리가 같은 인스턴스로 만들 수 있다
    let rid = id(&lab.rollout_ok("security_update", &[&[&a]]));
    for (method, tail) in [
        ("GET", String::new()),
        ("POST", "/resume".to_owned()),
        ("POST", "/cancel".to_owned()),
        ("POST", format!("/instances/{a}/apply")),
    ] {
        let (status, body) = lab.call(method, &format!("/v1/rollouts/{rid}{tail}"), &ta, &[]);
        assert_eq!(status, 403, "{method} {tail}: {body}");
    }
    let now = lab.now(&rid);
    assert_eq!(now["status"], "running");
    assert_eq!(state(&now, &a)["state"], "waiting");
}

#[test]
fn 에이전트의_토큰은_자기_인스턴스의_진행만_본다() {
    let mut lab = lab!();
    let (a, b, c) = (lab.instance(), lab.instance(), lab.instance());
    let (ta, tc) = (lab.token(FACTORY, &a), lab.token(FACTORY, &c));
    let update = lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("feature_update", &[&[&a], &[&b]]));
    lab.apply_ok(&rid, &a);

    let reply = handle(
        lab.layer(),
        "GET",
        &format!("/v1/instances/{a}/rollout"),
        Some(&ta),
        &[],
    );
    assert_eq!(reply.status, 200);
    let text = String::from_utf8(reply.body).unwrap();
    let view: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        view,
        json!({
            "rollout": rid,
            "update": update,
            "change": "feature_update",
            "halted": false,
            "state": "applied",
        })
    );
    assert!(!text.contains(&b), "{text}");
    // 다른 인스턴스의 진행은 없는 것으로 답한다
    let (status, _) = lab.call("GET", &format!("/v1/instances/{b}/rollout"), &ta, &[]);
    assert_eq!(status, 404);
    // rollout 에 들지 않은 인스턴스에는 진행이 없다
    let (status, view) = lab.call("GET", &format!("/v1/instances/{c}/rollout"), &tc, &[]);
    assert_eq!(status, 200);
    assert_eq!(view, Value::Null);
}

#[test]
fn 한_인스턴스는_같은_앱의_열린_rollout_하나에만_든다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    lab.update(FACTORY);
    let first = id(&lab.rollout_ok("security_update", &[&[&a]]));
    let (status, body) = lab.rollout(FACTORY, "feature_update", &[&[&b], &[&a]]);
    assert_eq!(status, 409, "{body}");
    assert!(body["message"].as_str().unwrap().contains(&a), "{body}");
    // 거둔 rollout 은 열린 것이 아니다
    let (status, body) = lab.post(&format!("/v1/rollouts/{first}/cancel"), FACTORY, &json!({}));
    assert_eq!(status, 200, "{body}");
    lab.rollout_ok("feature_update", &[&[&b], &[&a]]);
}

#[test]
fn rollout_을_거두면_아직_오르지_않은_곳은_그대로_남는다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let (ta, tb) = (lab.token(FACTORY, &a), lab.token(FACTORY, &b));
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a], &[&b]]));
    lab.apply_ok(&rid, &a);
    let merged_b = lab.apply_ok(&rid, &b)["commit"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, status, production) = lab.ship(&a, &ta, "security_update", "factory");
    assert_eq!(status, 200, "{production}");
    lab.preview(&b, &tb);

    let (status, cancelled) = lab.post(&format!("/v1/rollouts/{rid}/cancel"), FACTORY, &json!({}));
    assert_eq!(status, 200, "{cancelled}");
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(state(&cancelled, &a)["state"], "promoted");
    assert_eq!(state(&cancelled, &b)["state"], "passed");
    // 오른 곳은 그대로 운영에 있고, 오르지 않은 곳은 운영에 없으며 합친 코드는 그대로다
    assert_eq!(get(&format!("{}/feature", url(&production))).0, 200);
    assert_eq!(lab.production(&b), Value::Null);
    assert_eq!(lab.head(&b, &tb), merged_b);
    // 거둔 rollout 은 어떤 사건도 받지 않는다
    let (status, _) = lab.apply(FACTORY, &rid, &b);
    assert_eq!(status, 409);
    let (status, _) = lab.post(&format!("/v1/rollouts/{rid}/resume"), FACTORY, &json!({}));
    assert_eq!(status, 409);
    let (_, view) = lab.call("GET", &format!("/v1/instances/{b}/rollout"), &tb, &[]);
    assert_eq!(view, Value::Null);
    assert_eq!(lab.now(&rid)["status"], "cancelled");
}

#[test]
fn 관리_서버가_다시_떠도_rollout_의_진행이_남는다() {
    let mut lab = lab!();
    let (a, b) = (lab.instance(), lab.instance());
    let ta = lab.token(FACTORY, &a);
    lab.update(FACTORY);
    let rid = id(&lab.rollout_ok("security_update", &[&[&a, &b]]));
    lab.apply_ok(&rid, &a);
    let preview = lab.preview(&a, &ta);
    lab.request(&a, &ta, &release(&preview));
    let before = lab.now(&rid);

    lab.restart();
    let after = lab.now(&rid);
    assert_eq!(after, before);
    assert_eq!(state(&after, &a)["state"], "passed");
    assert_eq!(state(&after, &b)["state"], "waiting");
    // 남은 진행대로 이어진다
    let (status, body) = lab.promote(&a, &release(&preview), "security_update", "factory");
    assert_eq!(status, 200, "{body}");
    assert_eq!(state(&lab.now(&rid), &a)["state"], "promoted");
}

// ---- 작업을 닫기 ----

#[test]
fn 닫은_작업의_토큰은_관리_서버가_다시_떠도_받지_않고_다른_팩토리는_그_작업을_닫지_못한다() {
    let mut lab = lab!();
    let instance = lab.instance();
    let (status, opened) = lab.post(
        &format!("/v1/instances/{instance}/sessions"),
        FACTORY,
        &json!({ "can": ALL }),
    );
    assert_eq!(status, 200, "{opened}");
    let token = opened["token"].as_str().unwrap().to_owned();
    let session = opened["session"].as_str().unwrap().to_owned();
    let rollout_of = |lab: &Lab, token: &str| {
        lab.call(
            "GET",
            &format!("/v1/instances/{instance}/rollout"),
            token,
            &[],
        )
        .0
    };
    assert_eq!(rollout_of(&lab, &token), 200);

    // 다른 팩토리는 그 인스턴스의 작업을 닫지 못한다(없는 것과 같다)
    let close = format!("/v1/instances/{instance}/sessions/{session}");
    let (status, _) = lab.call("DELETE", &close, OTHER_FACTORY, &[]);
    assert_eq!(status, 404);
    assert_eq!(rollout_of(&lab, &token), 200);

    let (status, body) = lab.call("DELETE", &close, FACTORY, &[]);
    assert_eq!(status, 200, "{body}");
    assert_eq!(rollout_of(&lab, &token), 401);
    lab.restart();
    assert_eq!(rollout_of(&lab, &token), 401);
    // 새로 연 작업은 돈다. 같은 범위로 같은 초에 열어도 글자가 다르다
    let fresh = lab.token(FACTORY, &instance);
    let again = lab.token(FACTORY, &instance);
    assert_ne!(fresh, again);
    assert_eq!(rollout_of(&lab, &fresh), 200);
}
