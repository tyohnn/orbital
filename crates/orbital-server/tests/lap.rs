//! 한 바퀴를 실제로 돈다. 스캐폴드를 올리고, 인스턴스를 세우고, 에이전트가 토큰으로 코드를 받아 고쳐 올리고,
//! 프리뷰 → 리허설 → 승격 요청 → 사람의 승인 → 운영까지 간다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 프로세스(Node 서버)로 잰다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.
//! 요청은 HTTP 층의 `handle` 에 바로 넣고, 띄운 앱에는 실제 HTTP 로 요청한다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use orbital_router::Outbox;
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, OUTBOX, Options};
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

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orbital-lap-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        forget_control(&self.0.join("home"));
        let _ = fs::remove_dir_all(&self.0);
    }
}

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

/// 세워 둔 레이어 하나와 팩토리가 올린 스캐폴드.
struct Bench {
    scratch: Scratch,
    layer: Layer,
    instances: Vec<String>,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = Scratch::new();
        // 팩토리의 키 없이 운영까지 올린다. 개발용 메일함을 명시해 켠다
        let layer = Layer::open(Options {
            dev_mailbox: true,
            control_database: control_of(&scratch.path("home")),
            ..Options::new(
                scratch.path("home"),
                pg_url,
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        })
        .expect("레이어를 열지 못했습니다");

        // 팩토리가 스캐폴드를 만들어 v1 을 달고 올린다
        let scaffold = scratch.path("scaffold");
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/todo"),
            &scaffold,
        );
        git(&scaffold, &["init", "--quiet", "--initial-branch", "main"]);
        git(&scaffold, &["add", "-A"]);
        git(&scaffold, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&scaffold, &["tag", "v1"]);
        let bundle = scratch.path("scaffold.bundle");
        git(
            &scaffold,
            &[
                "bundle",
                "create",
                "--quiet",
                bundle.to_str().unwrap(),
                "--all",
            ],
        );
        let bench = Self {
            scratch,
            layer,
            instances: Vec::new(),
        };
        let (status, _) = bench.call(
            "PUT",
            "/v1/apps/todo",
            Some(FACTORY),
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(status, 200);
        Some(bench)
    }

    fn call(&self, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> (u16, Value) {
        let reply = handle(&self.layer, method, path, bearer, body);
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
        )
    }

    fn post(&self, path: &str, bearer: &str, body: Value) -> (u16, Value) {
        self.call("POST", path, Some(bearer), body.to_string().as_bytes())
    }

    fn instance(&mut self) -> String {
        let (status, body) = self.post(
            "/v1/instances",
            FACTORY,
            json!({ "app": "todo", "version": "v1" }),
        );
        assert_eq!(status, 200, "{body}");
        let instance = body["instance"].as_str().unwrap().to_owned();
        self.instances.push(instance.clone());
        instance
    }

    fn token(&self, instance: &str, can: &[&str]) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/sessions"),
            FACTORY,
            json!({ "can": can }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 에이전트가 하듯이 코드를 받아 작업 폴더를 만든다.
    fn clone(&self, instance: &str, token: &str, name: &str) -> PathBuf {
        let reply = handle(
            &self.layer,
            "GET",
            &format!("/v1/instances/{instance}/source"),
            Some(token),
            &[],
        );
        assert_eq!(reply.status, 200);
        let bundle = self.scratch.path(&format!("{name}.bundle"));
        fs::write(&bundle, reply.body).unwrap();
        let work = self.scratch.path(name);
        git(
            &self.scratch.0,
            &[
                "clone",
                "--quiet",
                bundle.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        work
    }

    /// 작업 폴더의 변경을 commit 해 올린다.
    fn push(&self, instance: &str, token: &str, work: &Path, message: &str) -> (u16, Value) {
        git(work, &["add", "-A"]);
        git(work, &["commit", "--quiet", "-m", message]);
        let file = self.scratch.path(&format!(
            "push-{}.bundle",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        git(
            work,
            &[
                "bundle",
                "create",
                "--quiet",
                file.to_str().unwrap(),
                "main",
            ],
        );
        self.call(
            "POST",
            &format!("/v1/instances/{instance}/source"),
            Some(token),
            &fs::read(file).unwrap(),
        )
    }

    fn preview(&self, instance: &str, token: &str) -> (u16, Value) {
        self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            Some(token),
            &[],
        )
    }

    fn promote(&self, instance: &str, release: &str, approved_by: &str) -> (u16, Value) {
        self.post(
            &format!("/v1/instances/{instance}/promotions"),
            FACTORY,
            json!({ "release": release, "change": "customer_request", "approved_by": approved_by }),
        )
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for instance in &self.instances {
            let _ = self.call(
                "DELETE",
                &format!("/v1/instances/{instance}"),
                Some(FACTORY),
                &[],
            );
        }
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

const ALL: [&str; 4] = ["source", "preview", "rehearse", "secrets_request"];

fn url(report: &Value) -> String {
    report["services"][0]["url"].as_str().unwrap().to_owned()
}

/// 띄운 앱에 router 를 거쳐 요청한다. `cookie` 는 세션 쿠키(`Cookie` 머리말의 값)다. 신원은 router 가 그 세션을 보고 싣는다.
fn app(method: &str, url: &str, cookie: Option<&str>, body: &str) -> (u16, Value) {
    let mut request = ureq::request(method, url);
    if let Some(cookie) = cookie {
        request = request.set("Cookie", cookie);
    }
    let response = if body.is_empty() {
        request.call()
    } else {
        request.send_string(body)
    };
    match response {
        Ok(response) => (
            response.status(),
            response.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_json().unwrap_or(Value::Null))
        }
        Err(error) => panic!("{url}: {error}"),
    }
}

/// 답의 `Set-Cookie` 가운데 이 이름의 것을 `이름=값` 으로 돌려준다.
fn cookie_pair(response: &ureq::Response, name: &str) -> String {
    response
        .all("set-cookie")
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .and_then(|cookie| cookie.split(';').next())
        .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다"))
        .to_owned()
}

/// 운영의 사람이 하듯이 들어온다. 로그인 링크를 요청하고, 메일함에서 링크를 꺼내 같은 브라우저로 연다. 세션 쿠키를 돌려준다.
fn sign_in(bench: &Bench, origin: &str, email: &str) -> String {
    let outbox = bench.scratch.path("home").join(OUTBOX);
    let sent = || {
        Outbox::read(&outbox)
            .into_iter()
            .filter(|mail| mail.to == email)
            .collect::<Vec<_>>()
    };
    let before = sent().len();
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let asked = agent
        .post(&format!("{origin}/_orbital/auth/email-link"))
        .set("Origin", origin)
        .send_json(json!({ "email": email }))
        .unwrap();
    assert_eq!(asked.status(), 202);
    let browser = cookie_pair(&asked, "__Host-orbital-browser");
    // 메일은 링크 요청의 답을 보낸 뒤에 뒤에서 쌓인다. 새 한 통이 올 때까지 기다린다
    let started = std::time::Instant::now();
    let mail = loop {
        let mails = sent();
        if mails.len() > before || started.elapsed() > std::time::Duration::from_secs(10) {
            break mails.into_iter().nth(before);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let link = mail.expect("메일함에 링크가 없습니다").link;
    let opened = agent.get(&link).set("Cookie", &browser).call().unwrap();
    assert_eq!(opened.status(), 302);
    cookie_pair(&opened, "__Host-orbital-session")
}

fn titles(cards: &Value) -> Vec<String> {
    cards
        .as_array()
        .unwrap()
        .iter()
        .map(|card| card["title"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn 스캐폴드에서_갈라진_코드가_프리뷰와_승인을_거쳐_운영에_서고_고친_것이_다시_오른다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let path = |tail: &str| format!("/v1/instances/{instance}/{tail}");

    // ---- 프리뷰: 그 commit 에서 빌드하고, 씨앗 데이터의 DB 를 세우고, 권한 검사를 돌린다 ----
    let (status, preview) = bench.preview(&instance, &token);
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["findings"], json!([]));
    assert_eq!(preview["blockers"], json!([]));
    assert_eq!(
        preview["changes"],
        json!([
            "`member` 역할이 `todo.card` 표를 자기 행을 읽을 수 있게 됩니다 그리고 자기 행을 고칠 수 있게 됩니다"
        ])
    );
    let release = preview["release"].as_str().unwrap().to_owned();
    let preview_url = url(&preview);
    assert_eq!(
        app("GET", &format!("{preview_url}/health"), None, "").0,
        200
    );

    // 씨앗 사용자로 들어가 요청하면 자기 카드만 보인다. 세션이 없으면 아무것도 보이지 않는다
    let (_, identity) = bench.post(
        &path("previews/identities"),
        &token,
        json!({ "user": "u1" }),
    );
    let u1 = identity["cookie"].as_str().unwrap().to_owned();
    let (status, cards) = app("GET", &format!("{preview_url}/cards"), Some(&u1), "");
    assert_eq!(status, 200, "{cards}");
    assert_eq!(titles(&cards), vec!["씨앗 카드 하나", "씨앗 카드 둘"]);
    assert_eq!(
        app("GET", &format!("{preview_url}/cards"), None, "").1,
        json!([])
    );

    // 앱은 레이어가 건넨 것만 본다. 비밀번호도 DB 의 관리 주소도 없다
    let (_, env) = app("GET", &format!("{preview_url}/env"), None, "");
    let names: Vec<&str> = env["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert!(names.contains(&"SESSION_KEY") && names.contains(&"PGPORT"));
    assert!(
        !names.iter().any(|name| name.contains("PASSWORD")
            || name.starts_with("ORBITAL_PG")
            || name.contains("SERVICE_KEY")),
        "{names:?}"
    );
    // 선언에 없는 역할로는 proxy 가 들여보내지 않는다
    assert_eq!(
        app("GET", &format!("{preview_url}/as-admin"), None, "").1,
        json!({ "error": "28000" })
    );

    // ---- 승격: 에이전트는 요청만 하고, 올리는 것은 사람의 승인을 받은 팩토리의 서버다 ----
    let (status, body) = bench.post(
        &path("promotions"),
        &token,
        json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
    );
    assert_eq!((status, body["error"].as_str()), (403, Some("forbidden")));
    assert_eq!(
        bench
            .post(
                &path("promotion-requests"),
                &token,
                json!({ "release": release })
            )
            .0,
        200
    );
    // 팩토리의 서버는 승인 화면에 세울 것을 읽는다. 어느 release 인지와 권한이 어떻게 바뀌는지다
    let (status, pending) = bench.call("GET", &path("promotion-request"), Some(FACTORY), &[]);
    assert_eq!(status, 200, "{pending}");
    assert_eq!(pending["release"], release);
    assert_eq!(pending["commit"], preview["commit"]);
    assert_eq!(pending["changes"], preview["changes"]);
    assert_eq!(pending["migrations"], json!(["001_card.sql"]));
    // 다른 팩토리에게는 없는 인스턴스이고, 에이전트의 토큰에는 이 길이 없다
    assert_eq!(
        bench
            .call("GET", &path("promotion-request"), Some(OTHER_FACTORY), &[])
            .0,
        404
    );
    assert_eq!(
        bench
            .call("GET", &path("promotion-request"), Some(&token), &[])
            .0,
        404
    );
    // 고객의 요청은 고객이 승인한다. 팩토리의 승인으로는 오르지 않는다
    let (status, body) = bench.promote(&instance, &release, "factory");
    assert_eq!(
        (status, body["message"].as_str()),
        (409, Some("이 변경은 고객이 승인해야 합니다"))
    );
    let (status, production) = bench.promote(&instance, &release, "customer");
    assert_eq!(status, 200, "{production}");
    assert_eq!(production["migrations"], json!(["001_card.sql"]));
    let live = url(&production);
    // 오른 뒤에는 기다리는 요청이 없다
    assert_eq!(
        bench.call("GET", &path("promotion-request"), Some(FACTORY), &[]),
        (200, Value::Null)
    );

    // 운영에는 씨앗 데이터도 씨앗 사용자도 없다. 프리뷰의 세션은 운영에서 읽히지 않는다.
    // 운영의 사람은 팩토리가 초대하고, 링크로 들어온다
    let (status, body) = bench.post(
        &path("users"),
        FACTORY,
        json!({ "email": "u9@example.test", "roles": ["member"] }),
    );
    assert_eq!(status, 200, "{body}");
    let u9 = sign_in(&bench, &live, "u9@example.test");
    assert_eq!(
        app("GET", &format!("{live}/cards"), Some(&u9), "").1,
        json!([])
    );
    assert_eq!(
        app("GET", &format!("{live}/cards"), Some(&u1), "").1,
        json!([])
    );
    assert_eq!(
        app("POST", &format!("{live}/cards"), Some(&u9), "첫 일").0,
        201
    );
    assert_eq!(
        app("POST", &format!("{live}/cards"), Some(&u9), "첫 일").0,
        201
    );
    assert_eq!(
        titles(&app("GET", &format!("{live}/cards"), Some(&u9), "").1),
        vec!["첫 일", "첫 일"]
    );
    // 신원을 밖으로 내주는 길은 없다. 팩토리에게도, 에이전트에게도
    for bearer in [FACTORY, token.as_str()] {
        assert_eq!(
            bench
                .post(
                    &path("production/identities"),
                    bearer,
                    json!({ "subject": "u9" })
                )
                .0,
            404
        );
    }

    // ---- 고치기: 에이전트가 코드를 받아 열을 더하고 올린다 ----
    let work = bench.clone(&instance, &token, "work");
    fs::write(
        work.join("db/migrations/002_done.sql"),
        "ALTER TABLE todo.card ADD COLUMN done boolean NOT NULL DEFAULT false;\n",
    )
    .unwrap();
    let server = fs::read_to_string(work.join("server.js"))
        .unwrap()
        .replace("version: 1", "version: 2");
    fs::write(work.join("server.js"), server).unwrap();
    let (status, pushed) = bench.push(&instance, &token, &work, "카드에 끝냄 표시를 더한다");
    assert_eq!(status, 200, "{pushed}");

    let (status, preview) = bench.preview(&instance, &token);
    assert_eq!(status, 200, "{preview}");
    let second = preview["release"].as_str().unwrap().to_owned();
    assert_ne!(second, release);
    assert_eq!(preview["commit"], pushed["commit"]);
    // 권한 표는 그대로라 권한의 변화는 없다. 운영에 아직 돌지 않은 마이그레이션이 있어 리허설이 필요하다
    assert_eq!(preview["changes"], json!([]));
    assert_eq!(preview["blockers"].as_array().unwrap().len(), 1);
    assert!(preview["blockers"][0].as_str().unwrap().contains("리허설"));
    let (status, body) = bench.post(
        &path("promotion-requests"),
        &token,
        json!({ "release": second }),
    );
    assert_eq!((status, body["error"].as_str()), (409, Some("denied")));
    let (status, body) = bench.promote(&instance, &second, "customer");
    assert_eq!((status, body["error"].as_str()), (409, Some("denied")));

    // 리허설은 운영 데이터의 사본에 돌고 숫자만 돌려준다
    let (status, rehearsal) = bench.post(&path("rehearsals"), &token, json!({ "release": second }));
    assert_eq!(status, 200, "{rehearsal}");
    assert_eq!(
        (rehearsal["needed"].as_bool(), rehearsal["passed"].as_bool()),
        (Some(true), Some(true))
    );
    // 사용자의 표(orbital_auth)도 사본에 함께 있다. 앱의 표만 본다
    let card = rehearsal["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row[0] == "todo.card")
        .cloned();
    assert_eq!(card, Some(json!(["todo.card", 2, 2])));
    assert!(
        !rehearsal.to_string().contains("첫 일"),
        "리허설의 결과에 행의 내용이 있습니다"
    );
    // 리허설 동안 잠깐 닫혔던 운영이 다시 요청을 받는다
    assert_eq!(
        titles(&app("GET", &format!("{live}/cards"), Some(&u9), "").1).len(),
        2
    );

    assert_eq!(
        bench
            .post(
                &path("promotion-requests"),
                &token,
                json!({ "release": second })
            )
            .0,
        200
    );
    let (status, production) = bench.promote(&instance, &second, "customer");
    assert_eq!(status, 200, "{production}");
    assert_eq!(production["migrations"], json!(["002_done.sql"]));
    let live = url(&production);
    assert_eq!(
        app("GET", &format!("{live}/health"), None, "").1["version"],
        2
    );
    // 운영의 데이터는 그대로이고 새 열이 붙었다. 앞의 신원도 그대로 읽힌다(열쇠가 바뀌지 않는다)
    let (_, cards) = app("GET", &format!("{live}/cards"), Some(&u9), "");
    assert_eq!(titles(&cards), vec!["첫 일", "첫 일"]);
    assert_eq!(cards[0]["done"], false);

    // ---- 운영의 데이터에서만 깨지는 마이그레이션: 리허설이 잡고, 운영은 그대로다 ----
    fs::write(
        work.join("db/migrations/003_unique.sql"),
        "CREATE UNIQUE INDEX card_title ON todo.card (title);\n",
    )
    .unwrap();
    assert_eq!(
        bench
            .push(&instance, &token, &work, "제목이 겹치지 않게 한다")
            .0,
        200
    );
    let (status, preview) = bench.preview(&instance, &token);
    // 씨앗 데이터에는 겹치는 제목이 없어서 프리뷰는 선다
    assert_eq!(status, 200, "{preview}");
    let third = preview["release"].as_str().unwrap().to_owned();
    let (_, rehearsal) = bench.post(&path("rehearsals"), &token, json!({ "release": third }));
    assert_eq!(
        (
            rehearsal["passed"].as_bool(),
            rehearsal["sqlstate"].as_str()
        ),
        (Some(false), Some("23505"))
    );
    assert_eq!(rehearsal["failed_at"], "003_unique.sql");
    assert!(!rehearsal.to_string().contains("첫 일"));
    assert_eq!(
        bench
            .post(
                &path("promotion-requests"),
                &token,
                json!({ "release": third })
            )
            .0,
        409
    );
    let (status, body) = bench.promote(&instance, &third, "customer");
    assert_eq!(status, 409, "{body}");
    assert!(
        body["details"][0]
            .as_str()
            .unwrap()
            .contains("리허설이 실패")
    );
    // 운영은 앞의 release 그대로 돈다
    assert_eq!(
        app("GET", &format!("{live}/health"), None, "").1["version"],
        2
    );
    assert_eq!(
        titles(&app("GET", &format!("{live}/cards"), Some(&u9), "").1).len(),
        2
    );
    let (_, production) = bench.call("GET", &path("production"), Some(FACTORY), &[]);
    assert_eq!(production["release"], second);
}

#[test]
fn 운영에서만_뜨지_않는_release_는_앞의_release_와_앞의_db_로_돌아간다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let path = |tail: &str| format!("/v1/instances/{instance}/{tail}");
    // 프리뷰 → (리허설) → 승격 요청 → 승인받은 승격
    let ship = |bench: &Bench| -> (String, u16, Value) {
        let (status, preview) = bench.preview(&instance, &token);
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, rehearsal) =
            bench.post(&path("rehearsals"), &token, json!({ "release": release }));
        assert_eq!(status, 200, "{rehearsal}");
        let (status, body) = bench.post(
            &path("promotion-requests"),
            &token,
            json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let (status, body) = bench.promote(&instance, &release, "customer");
        (release, status, body)
    };

    // 첫 release 가 운영에 서고 사람이 카드를 하나 적는다
    let (first, status, production) = ship(&bench);
    assert_eq!(status, 200, "{production}");
    let (status, body) = bench.post(
        &path("users"),
        FACTORY,
        json!({ "email": "u9@example.test", "roles": ["member"] }),
    );
    assert_eq!(status, 200, "{body}");
    let u9 = sign_in(&bench, &url(&production), "u9@example.test");
    assert_eq!(
        app(
            "POST",
            &format!("{}/cards", url(&production)),
            Some(&u9),
            "남을 일"
        )
        .0,
        201
    );

    // 열을 더하는 마이그레이션과, 운영에서만 뜨지 않는 서버를 올린다
    let work = bench.clone(&instance, &token, "work");
    fs::write(
        work.join("db/migrations/002_done.sql"),
        "ALTER TABLE todo.card ADD COLUMN done boolean NOT NULL DEFAULT false;\n",
    )
    .unwrap();
    let original = fs::read_to_string(work.join("server.js")).unwrap();
    let broken = format!(
        "if (process.env.ORBITAL_STAGE === \"production\") process.exit(1);\n{}",
        original.replace("version: 1", "version: 2")
    );
    fs::write(work.join("server.js"), broken).unwrap();
    assert_eq!(
        bench
            .push(&instance, &token, &work, "운영에서 뜨지 않는다")
            .0,
        200
    );
    // 프리뷰와 리허설은 통과한다. 깨지는 것은 운영에 올린 뒤다
    let (second, status, body) = ship(&bench);
    assert_eq!(
        (status, body["error"].as_str()),
        (422, Some("start_failed")),
        "{body}"
    );

    // 운영은 앞의 release 로 돌고, 앞의 데이터가 그대로 있다
    let (_, production) = bench.call("GET", &path("production"), Some(FACTORY), &[]);
    assert_eq!(production["release"], first);
    assert_ne!(first, second);
    let live = url(&production);
    assert_eq!(
        app("GET", &format!("{live}/health"), None, "").1["version"],
        1
    );
    assert_eq!(
        titles(&app("GET", &format!("{live}/cards"), Some(&u9), "").1),
        vec!["남을 일"]
    );

    // 고쳐서 다시 올리면 같은 마이그레이션이 다시 돈다. 실패한 승격이 돌린 것이 DB 에 남지 않았다
    fs::write(
        work.join("server.js"),
        original.replace("version: 1", "version: 3"),
    )
    .unwrap();
    assert_eq!(bench.push(&instance, &token, &work, "고친다").0, 200);
    let (_, status, production) = ship(&bench);
    assert_eq!(status, 200, "{production}");
    assert_eq!(production["migrations"], json!(["002_done.sql"]));
    let live = url(&production);
    assert_eq!(
        app("GET", &format!("{live}/health"), None, "").1["version"],
        3
    );
    assert_eq!(
        titles(&app("GET", &format!("{live}/cards"), Some(&u9), "").1),
        vec!["남을 일"]
    );
}

#[test]
fn 토큰은_발급받은_인스턴스에서_받은_능력만큼만_쓴다() {
    let mut bench = bench!();
    let ours = bench.instance();
    let theirs = bench.instance();
    let token = bench.token(&ours, &["source"]);

    // 제 인스턴스의 코드는 받는다
    assert_eq!(
        handle(
            &bench.layer,
            "GET",
            &format!("/v1/instances/{ours}/source"),
            Some(&token),
            &[]
        )
        .status,
        200
    );
    // 다른 인스턴스는 없는 것으로 답한다. 없는 인스턴스와 같은 답이다
    let other = bench.call(
        "GET",
        &format!("/v1/instances/{theirs}/source"),
        Some(&token),
        &[],
    );
    let missing = bench.call("GET", "/v1/instances/i0000000000/source", Some(&token), &[]);
    assert_eq!(other.0, 404);
    assert_eq!(other, missing);
    // 받지 않은 능력은 쓰지 못한다
    assert_eq!(bench.preview(&ours, &token).0, 403);
    assert_eq!(
        bench
            .post(
                &format!("/v1/instances/{ours}/rehearsals"),
                &token,
                json!({ "release": "r_x" })
            )
            .0,
        403
    );
    // 토큰으로는 토큰을 내지 못한다
    assert_eq!(
        bench
            .post(
                &format!("/v1/instances/{ours}/sessions"),
                &token,
                json!({ "can": ["preview"] })
            )
            .0,
        404
    );
    // 서명이 틀리거나 없는 토큰
    // 끝 두 글자를 늘 다른 것으로 바꾼다(원래 끝이 `00` 이면 `00` 으로 바꿔도 같은 토큰이다)
    let tail = if token.ends_with("00") { "11" } else { "00" };
    let forged = format!("{}{tail}", &token[..token.len() - 2]);
    assert_eq!(
        bench
            .call(
                "GET",
                &format!("/v1/instances/{ours}/source"),
                Some(&forged),
                &[]
            )
            .0,
        401
    );
    assert_eq!(
        bench
            .call("GET", &format!("/v1/instances/{ours}/source"), None, &[])
            .0,
        401
    );
}

#[test]
fn 다른_팩토리의_service_key_로는_인스턴스가_없는_것으로_보인다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let sessions = format!("/v1/instances/{instance}/sessions");
    assert_eq!(
        bench
            .post(&sessions, OTHER_FACTORY, json!({ "can": ["source"] }))
            .0,
        404
    );
    assert_eq!(
        bench
            .call(
                "GET",
                &format!("/v1/instances/{instance}/production"),
                Some(OTHER_FACTORY),
                &[]
            )
            .0,
        404
    );
    assert_eq!(
        bench
            .call(
                "DELETE",
                &format!("/v1/instances/{instance}"),
                Some(OTHER_FACTORY),
                &[]
            )
            .0,
        404
    );
    // 다른 팩토리는 이 팩토리의 스캐폴드에서 인스턴스를 세우지도 못한다
    assert_eq!(
        bench
            .post(
                "/v1/instances",
                OTHER_FACTORY,
                json!({ "app": "todo", "version": "v1" })
            )
            .0,
        404
    );
    // 모르는 열쇠
    assert_eq!(
        bench
            .post(&sessions, "sk_test_unknown", json!({ "can": ["source"] }))
            .0,
        401
    );
    // 제 팩토리의 열쇠로는 된다
    assert_eq!(
        bench
            .post(&sessions, FACTORY, json!({ "can": ["source"] }))
            .0,
        200
    );
}

#[test]
fn 운영을_바꾸는_능력은_토큰에_적어_달라고_해도_실리지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/sessions"),
        FACTORY,
        json!({ "can": ["source", "promote"] }),
    );
    assert_eq!((status, body["error"].as_str()), (422, Some("problems")));
}

#[test]
fn 코드에_고칠_것이_있으면_프리뷰가_서지_않고_무엇을_고칠지_돌려준다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let work = bench.clone(&instance, &token, "work");
    let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();

    // 선언이 깨졌다
    fs::write(
        work.join("orbital.toml"),
        manifest.replace("start = \"node server.js\"\n", ""),
    )
    .unwrap();
    assert_eq!(
        bench.push(&instance, &token, &work, "실행 명령을 지운다").0,
        200
    );
    let (status, body) = bench.preview(&instance, &token);
    assert_eq!((status, body["error"].as_str()), (422, Some("problems")));
    assert!(
        body["details"][0]
            .as_str()
            .unwrap()
            .contains("실행 명령(`start`)이 없습니다")
    );

    // 빌드가 실패한다. 로그의 끝이 함께 온다
    fs::write(
        work.join("orbital.toml"),
        manifest.replace("node --check server.js", "echo 빌드가 깨졌다 && exit 7"),
    )
    .unwrap();
    assert_eq!(
        bench.push(&instance, &token, &work, "빌드를 깨뜨린다").0,
        200
    );
    let (status, body) = bench.preview(&instance, &token);
    assert_eq!(
        (status, body["error"].as_str()),
        (422, Some("build_failed"))
    );
    assert!(
        body["details"][0]
            .as_str()
            .unwrap()
            .contains("빌드가 깨졌다")
    );

    // 서버가 뜨지 않는다
    fs::write(
        work.join("orbital.toml"),
        manifest.replace(
            "start = \"node server.js\"",
            "start = \"echo 뜨다 말았다 && exit 1\"",
        ),
    )
    .unwrap();
    assert_eq!(
        bench.push(&instance, &token, &work, "서버를 깨뜨린다").0,
        200
    );
    let (status, body) = bench.preview(&instance, &token);
    assert_eq!(
        (status, body["error"].as_str()),
        (422, Some("start_failed"))
    );
    assert!(body["details"][0].as_str().unwrap().contains("뜨다 말았다"));

    // 권한 표에 없는 표를 마이그레이션이 만든다. 프리뷰는 서지만 승격은 요청하지 못한다
    fs::write(work.join("orbital.toml"), &manifest).unwrap();
    fs::write(
        work.join("db/migrations/002_note.sql"),
        "CREATE TABLE todo.note (id int, body text);\n",
    )
    .unwrap();
    assert_eq!(
        bench
            .push(
                &instance,
                &token,
                &work,
                "표를 더하고 권한 표는 그대로 둔다"
            )
            .0,
        200
    );
    let (status, body) = bench.preview(&instance, &token);
    assert_eq!(status, 200, "{body}");
    assert!(
        body["findings"][0]
            .as_str()
            .unwrap()
            .contains("표 `todo.note` 이 권한 표에 없습니다")
    );
    let release = body["release"].as_str().unwrap();
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/promotion-requests"),
        &token,
        json!({ "release": release }),
    );
    assert_eq!(status, 409);
    assert!(body["details"][0].as_str().unwrap().contains("권한 검사"));
    // 승인이 있어도 오르지 않는다
    assert_eq!(bench.promote(&instance, release, "customer").0, 409);
}

#[test]
fn 올리지_않은_commit_과_모르는_release_로는_아무것도_서지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let previews = format!("/v1/instances/{instance}/previews");
    let (status, body) = bench.post(
        &previews,
        &token,
        json!({ "commit": "0123456789abcdef0123456789abcdef01234567" }),
    );
    assert_eq!(status, 422);
    assert!(
        body["details"][0]
            .as_str()
            .unwrap()
            .contains("먼저 올려 주세요")
    );
    assert_eq!(
        bench.post(&previews, &token, json!({ "commit": "main" })).0,
        422
    );
    assert_eq!(bench.promote(&instance, "r_0000000000", "customer").0, 404);
    assert_eq!(
        bench
            .post(
                &format!("/v1/instances/{instance}/rehearsals"),
                &token,
                json!({ "release": "r_0000000000" })
            )
            .0,
        409
    );
}

#[test]
fn 빌드는_인스턴스마다의_홈에서_돌고_다른_인스턴스와_캐시의_자리를_나누지_않는다() {
    let mut bench = bench!();
    let home = bench.scratch.path("home");
    let mut seen = Vec::new();
    for name in ["a", "b"] {
        let instance = bench.instance();
        let token = bench.token(&instance, &ALL);
        // 빌드 명령이 받은 홈을 적게 한다
        let work = bench.clone(&instance, &token, &format!("home-{name}"));
        let manifest = fs::read_to_string(work.join("orbital.toml"))
            .unwrap()
            .replace(
                "build = \"node --check server.js\"",
                "build = \"node --check server.js && echo \\\"$HOME\\\" > build-home.txt\"",
            );
        fs::write(work.join("orbital.toml"), manifest).unwrap();
        assert_eq!(bench.push(&instance, &token, &work, "홈을 적는다").0, 200);
        let (status, preview) = bench.preview(&instance, &token);
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap();
        let built = home.join("builds").join(&instance).join(release);
        let build_home = fs::read_to_string(built.join("build-home.txt")).unwrap();
        seen.push((instance, PathBuf::from(build_home.trim()), built));
    }
    let [(a, a_home, a_built), (b, b_home, b_built)] = <[_; 2]>::try_from(seen).unwrap();
    assert_eq!(a_home, home.join("caches").join(&a));
    assert_eq!(b_home, home.join("caches").join(&b));
    // 캐시는 빌드 폴더 밖이다. 서버로 뜨는 폴더에 빌드의 캐시가 실리지 않는다
    for (cache, built) in [(&a_home, &a_built), (&b_home, &b_built)] {
        assert!(!cache.starts_with(built) && !built.starts_with(cache));
    }
    assert!(!a_home.starts_with(&b_home) && !b_home.starts_with(&a_home));
}

#[test]
fn 인스턴스를_지우면_빌드_폴더와_빌드의_캐시와_기록도_걷는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    assert_eq!(bench.preview(&instance, &token).0, 200);
    let home = bench.scratch.path("home");
    let left = |instance: &str| -> Vec<PathBuf> {
        ["builds", "caches", "logs"]
            .iter()
            .map(|place| home.join(place).join(instance))
            .filter(|folder| folder.exists())
            .collect()
    };
    assert_eq!(left(&instance).len(), 3, "프리뷰가 세 자리를 모두 만든다");
    let (status, body) = bench.call(
        "DELETE",
        &format!("/v1/instances/{instance}"),
        Some(FACTORY),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    bench.instances.retain(|known| *known != instance);
    assert_eq!(left(&instance), Vec::<PathBuf>::new());
}

#[test]
fn 프리뷰를_새로_세우면_프리뷰와_운영에_떠_있지_않은_release_의_빌드_폴더를_걷는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let builds = bench.scratch.path("home").join("builds").join(&instance);
    let releases = || -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&builds)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let sorted = |mut list: Vec<String>| {
        list.sort();
        list
    };
    let release = |preview: &Value| preview["release"].as_str().unwrap().to_owned();
    let (_, first) = bench.preview(&instance, &token);
    let work = bench.clone(&instance, &token, "prune");
    let next = |message: &str| {
        fs::write(work.join("note.txt"), message).unwrap();
        assert_eq!(bench.push(&instance, &token, &work, message).0, 200);
        let (status, preview) = bench.preview(&instance, &token);
        assert_eq!(status, 200, "{preview}");
        preview
    };
    // 운영이 없으면 떠 있는 프리뷰의 것만 남는다
    let second = next("둘째");
    assert_eq!(releases(), vec![release(&second)]);
    assert_ne!(release(&first), release(&second));
    // 운영에 오른 release 의 폴더는 운영이 쓰므로 남는다
    assert_eq!(
        bench
            .post(
                &format!("/v1/instances/{instance}/promotion-requests"),
                &token,
                json!({ "release": release(&second) })
            )
            .0,
        200
    );
    assert_eq!(
        bench.promote(&instance, &release(&second), "customer").0,
        200
    );
    let third = next("셋째");
    let fourth = next("넷째");
    assert_eq!(releases(), sorted(vec![release(&second), release(&fourth)]));
    assert_ne!(release(&third), release(&fourth));
}

#[test]
fn 한_인스턴스의_빌드가_도는_동안에도_다른_요청은_빌드를_기다리지_않는다() {
    let mut bench = bench!();
    let slow = bench.instance();
    let other = bench.instance();
    let token = bench.token(&slow, &ALL);
    // 빌드가 4초 걸리는 commit 을 올린다(npm ci 와 프레임워크의 빌드를 흉내 낸다)
    let work = bench.clone(&slow, &token, "slow");
    let manifest = fs::read_to_string(work.join("orbital.toml"))
        .unwrap()
        .replace(
            "build = \"node --check server.js\"",
            "build = \"sleep 4 && node --check server.js\"",
        );
    fs::write(work.join("orbital.toml"), manifest).unwrap();
    assert_eq!(bench.push(&slow, &token, &work, "느린 빌드").0, 200);
    let bench = &bench;
    std::thread::scope(|scope| {
        let building = scope.spawn(|| bench.preview(&slow, &token));
        std::thread::sleep(std::time::Duration::from_millis(800));
        // 다른 인스턴스의 일과 레이어 전체의 일이 빌드가 끝나기를 기다리지 않는다
        let started = std::time::Instant::now();
        let other_token = bench.token(&other, &ALL);
        let (status, _) = bench.call(
            "GET",
            &format!("/v1/instances/{other}/secrets"),
            Some(&other_token),
            &[],
        );
        assert_eq!(status, 200);
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_secs(2),
            "빌드가 도는 동안 {waited:?} 기다렸습니다"
        );
        let (status, preview) = building.join().unwrap();
        assert_eq!(status, 200, "{preview}");
    });
}

#[test]
fn 빌드가_실패하면_로그의_끝을_돌려주되_레이어의_폴더_경로는_가린다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let work = bench.clone(&instance, &token, "broken");
    // npm 의 오류처럼 홈과 작업 폴더의 경로를 찍고 실패한다
    let manifest = fs::read_to_string(work.join("orbital.toml"))
        .unwrap()
        .replace(
            "build = \"node --check server.js\"",
            "build = \"echo 홈은 $HOME && echo 폴더는 $(pwd) && exit 3\"",
        );
    fs::write(work.join("orbital.toml"), manifest).unwrap();
    assert_eq!(bench.push(&instance, &token, &work, "깨진 빌드").0, 200);
    let (status, body) = bench.preview(&instance, &token);
    assert_eq!(
        (status, body["error"].as_str()),
        (422, Some("build_failed"))
    );
    let log = body["details"][0].as_str().unwrap();
    assert!(log.contains("홈은") && log.contains("폴더는"), "{log}");
    let home = fs::canonicalize(bench.scratch.path("home")).unwrap();
    for hidden in [bench.scratch.path("home"), home] {
        assert!(!log.contains(&hidden.display().to_string()), "{log}");
    }
}

// ---- 선언에서 뺀 역할 ----

/// 이 인스턴스의 역할 가운데 `auditor` 의 것.
fn auditor_roles(instance: &str) -> Vec<String> {
    let url = std::env::var("ORBITAL_PG").unwrap();
    let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    client
        .query(
            "SELECT rolname FROM pg_roles WHERE rolname LIKE $1 ORDER BY 1",
            &[&format!("i_{instance}_%auditor")],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// 작업 폴더의 선언과 권한 표에 업무 역할 `auditor`(읽기만)를 더하거나 뺀다.
fn with_auditor(work: &Path, on: bool) {
    let manifest = fs::read_to_string(work.join("orbital.toml")).unwrap();
    let access = fs::read_to_string(work.join("db/access.toml")).unwrap();
    let (manifest, access) = if on {
        (
            manifest.replace("roles = [\"member\"]", "roles = [\"member\", \"auditor\"]"),
            format!("{access}auditor = \"read\"\n"),
        )
    } else {
        (
            manifest.replace("roles = [\"member\", \"auditor\"]", "roles = [\"member\"]"),
            access.replace("auditor = \"read\"\n", ""),
        )
    };
    fs::write(work.join("orbital.toml"), manifest).unwrap();
    fs::write(work.join("db/access.toml"), access).unwrap();
}

#[test]
fn 선언에서_뺀_업무_역할은_승격에서_걷고_주인인_것이_있으면_멈추며_앞의_release_로_되돌리면_다시_선다()
 {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &ALL);
    let path = |tail: &str| format!("/v1/instances/{instance}/{tail}");
    let ship = |bench: &Bench| -> (u16, Value) {
        let (status, preview) = bench.preview(&instance, &token);
        assert_eq!(status, 200, "{preview}");
        let release = preview["release"].as_str().unwrap().to_owned();
        let (status, body) = bench.post(
            &path("promotion-requests"),
            &token,
            json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        bench.promote(&instance, &release, "customer")
    };
    let work = bench.clone(&instance, &token, "work");

    // 역할을 더해 올린다
    with_auditor(&work, true);
    assert_eq!(
        bench.push(&instance, &token, &work, "감사 역할을 더한다").0,
        200
    );
    let (status, body) = ship(&bench);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        auditor_roles(&instance),
        vec![
            format!("i_{instance}_r_auditor"),
            format!("i_{instance}_s_web_auditor")
        ]
    );

    // 뺀 release 를 올리면 묶음과 로그인이 걷히고 권한 검사를 지난다(남았으면 어긋남으로 보아 오르지 못한다)
    with_auditor(&work, false);
    assert_eq!(
        bench.push(&instance, &token, &work, "감사 역할을 뺀다").0,
        200
    );
    let (status, body) = ship(&bench);
    assert_eq!(status, 200, "{body}");
    assert_eq!(auditor_roles(&instance), Vec::<String>::new());

    // 다시 더하면 다시 선다
    with_auditor(&work, true);
    assert_eq!(bench.push(&instance, &token, &work, "다시 더한다").0, 200);
    let (status, body) = ship(&bench);
    assert_eq!(status, 200, "{body}");
    let (_, production) = bench.call("GET", &path("production"), Some(FACTORY), &[]);
    let with_role = production["release"].as_str().unwrap().to_owned();
    assert_eq!(auditor_roles(&instance).len(), 2);

    // 그 역할이 무엇의 주인이면 걷지 않고 승격을 멈춘다. 운영은 그대로다
    let pg_url = std::env::var("ORBITAL_PG").unwrap();
    let mut config: postgres::Config = pg_url.parse().unwrap();
    config.dbname(&format!("i_{instance}"));
    let mut admin = config.connect(postgres::NoTls).unwrap();
    admin
        .batch_execute(&format!(
            "CREATE SEQUENCE todo.held; ALTER SEQUENCE todo.held OWNER TO i_{instance}_r_auditor"
        ))
        .unwrap();
    with_auditor(&work, false);
    assert_eq!(bench.push(&instance, &token, &work, "또 뺀다").0, 200);
    let (status, body) = ship(&bench);
    assert_eq!(status, 409, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("i_{instance}_r_auditor")),
        "{message}"
    );
    assert!(message.contains("주인"), "{message}");
    let (_, production) = bench.call("GET", &path("production"), Some(FACTORY), &[]);
    assert_eq!(production["release"], json!(with_role));
    assert_eq!(auditor_roles(&instance).len(), 2);
    assert_eq!(
        app("GET", &format!("{}/health", url(&production)), None, "").0,
        200
    );
    admin.batch_execute("DROP SEQUENCE todo.held").unwrap();

    // 역할을 걷은 뒤 새 release 가 운영에서 서지 못하면 앞의 release 로 되돌아가고, 걷은 역할이 다시 선다
    let original = fs::read_to_string(work.join("server.js")).unwrap();
    fs::write(
        work.join("server.js"),
        format!("if (process.env.ORBITAL_STAGE === \"production\") process.exit(1);\n{original}"),
    )
    .unwrap();
    assert_eq!(
        bench
            .push(&instance, &token, &work, "운영에서 뜨지 않는다")
            .0,
        200
    );
    let (status, body) = ship(&bench);
    assert_eq!(
        (status, body["error"].as_str()),
        (422, Some("start_failed")),
        "{body}"
    );
    let (_, production) = bench.call("GET", &path("production"), Some(FACTORY), &[]);
    assert_eq!(production["release"], json!(with_role));
    assert_eq!(auditor_roles(&instance).len(), 2);
    // 다시 선 로그인으로 DB 에 붙는다
    let mut login = config.clone();
    login.user(&format!("i_{instance}_s_web_auditor"));
    assert!(login.connect(postgres::NoTls).is_ok());
}
