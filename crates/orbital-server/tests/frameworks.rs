//! 실제 프레임워크(Next.js, NestJS + Vite)의 본보기를 레이어에 실제로 세운다. 레지스트리에서 `npm ci` 로 받고 실제로 빌드하고 띄운다.
//!
//! 느리고 네트워크에 기대므로 기본 게이트에서는 돌지 않는다. `ORBITAL_FRAMEWORKS=1` 과 `ORBITAL_PG` 가 함께 있어야 돌고,
//! 없으면 건너뛰었다고 찍고 통과한다. `npm run test:frameworks` 가 켜서 부른다. 잰 숫자는 `잰 것:` 으로 찍는다(`--nocapture`).
//!
//! 이 테스트가 레이어의 운영자 노릇을 한다. 빌드에 건넬 환경은 [`OPERATOR_ENV`] 의 이름뿐이고, 값은 이 프로세스의 환경에서 읽는다.
//! 프록시를 지나야 하는 기계에서는 프록시와 CA 묶음이, 바로 나가는 기계(CI)에서는 아무것도 넘어가지 않는다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use orbital_router::Outbox;
use orbital_run::{LocalRunner, build_env};
use orbital_server::http::handle;
use orbital_server::layer::{Layer, OUTBOX, Options};
use orbital_server::seal::SealKey;
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";

/// 운영자가 빌드에 건네는 환경의 이름. 레지스트리에 닿는 데 필요한 것만 적는다.
const OPERATOR_ENV: &str = "HTTPS_PROXY,https_proxy,NO_PROXY,no_proxy,NODE_EXTRA_CA_CERTS,SSL_CERT_FILE,npm_config_https_proxy,npm_config_noproxy,npm_config_registry";

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orbital-frameworks-{}-{}",
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(folder: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// 본보기를 옮긴다. 이 기계에서 받거나 빌드한 것(무시하는 폴더)은 옮기지 않는다. 팩토리가 올리는 것은 commit 한 파일뿐이다.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if ["node_modules", ".next", "dist"].contains(&name.to_str().unwrap_or_default()) {
            continue;
        }
        let target = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// 폴더의 크기(KiB). 없으면 0 이다.
fn kib(folder: &Path) -> u64 {
    Command::new("du")
        .args(["-sk"])
        .arg(folder)
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .and_then(|size| size.parse().ok())
        })
        .unwrap_or(0)
}

/// 이 테스트가 운영자로서 여는 레이어. 빌드에는 [`OPERATOR_ENV`] 의 것만 건넨다.
fn open_layer(home: &Path, pg_url: &str, sleep_after: Duration) -> Layer {
    let runner = LocalRunner {
        build_env: build_env(OPERATOR_ENV, |name| std::env::var(name).ok()).unwrap(),
        ..LocalRunner::default()
    };
    Layer::open(Options {
        dev_mailbox: true,
        // 밖에서 넣는 비밀을 넣으려면 봉인의 열쇠가 있어야 한다. 테스트의 열쇠다
        seal_key: SealKey::from_hex(&"5e".repeat(32)),
        sleep_after,
        ..Options::new(
            home.to_path_buf(),
            pg_url.to_owned(),
            vec![(FACTORY.to_owned(), "factory".to_owned())],
            Box::new(runner),
        )
    })
    .expect("레이어를 열지 못했습니다")
}

/// 세워 둔 레이어 하나와 팩토리가 올린 본보기 하나.
struct Bench {
    scratch: Scratch,
    /// 다시 띄울 때 잠깐 비운다.
    layer: Option<Layer>,
    pg_url: String,
    sleep_after: Duration,
    app: &'static str,
    instances: Vec<String>,
}

impl Bench {
    fn new(app: &'static str, source: &Path, sleep_after: Duration) -> Option<Self> {
        let on = std::env::var("ORBITAL_FRAMEWORKS").is_ok_and(|on| on == "1");
        let pg_url = std::env::var("ORBITAL_PG").ok().filter(|_| on)?;
        let scratch = Scratch::new();
        let layer = open_layer(&scratch.path("home"), &pg_url, sleep_after);
        let scaffold = scratch.path("scaffold");
        copy_tree(source, &scaffold);
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
            layer: Some(layer),
            pg_url,
            sleep_after,
            app,
            instances: Vec::new(),
        };
        let (status, body) = bench.call(
            "PUT",
            &format!("/v1/apps/{app}"),
            Some(FACTORY),
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(status, 200, "{body}");
        Some(bench)
    }

    fn home(&self) -> PathBuf {
        self.scratch.path("home")
    }

    /// 관리 서버를 내렸다가 같은 기록으로 다시 띄운다. 다시 뜨는 데 걸린 시간을 돌려준다.
    fn restart(&mut self) -> Duration {
        drop(self.layer.take());
        let started = Instant::now();
        self.layer = Some(open_layer(&self.home(), &self.pg_url, self.sleep_after));
        started.elapsed()
    }

    fn call(&self, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> (u16, Value) {
        let layer = self.layer.as_ref().expect("레이어가 떠 있지 않습니다");
        let reply = handle(layer, method, path, bearer, body);
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
            json!({ "app": self.app, "version": "v1" }),
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
            json!({ "can": ["source", "preview", "rehearse", "secrets_request"] }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    /// 프리뷰를 세우고 걸린 시간을 함께 돌려준다. 실패하면 빌드와 서버의 로그를 보인다.
    fn preview(&self, instance: &str, token: &str) -> (Value, Duration) {
        let started = Instant::now();
        let (status, preview) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            Some(token),
            &[],
        );
        let took = started.elapsed();
        assert_eq!(status, 200, "{preview}");
        (preview, took)
    }

    fn seed_cookie(&self, instance: &str, token: &str, user: &str) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/previews/identities"),
            token,
            json!({ "user": user }),
        );
        assert_eq!(status, 200, "{body}");
        body["cookie"].as_str().unwrap().to_owned()
    }

    /// 승격을 요청하고 고객의 승인으로 올린다. 걸린 시간을 함께 돌려준다.
    fn promote(&self, instance: &str, token: &str, release: &str) -> (Value, Duration) {
        let path = |tail: &str| format!("/v1/instances/{instance}/{tail}");
        let (status, body) = self.post(
            &path("promotion-requests"),
            token,
            json!({ "release": release }),
        );
        assert_eq!(status, 200, "{body}");
        let started = Instant::now();
        let (status, production) = self.post(
            &path("promotions"),
            FACTORY,
            json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        let took = started.elapsed();
        assert_eq!(status, 200, "{production}");
        (production, took)
    }

    fn production_url(&self, instance: &str) -> String {
        let (status, body) = self.call(
            "GET",
            &format!("/v1/instances/{instance}/production"),
            Some(FACTORY),
            &[],
        );
        assert_eq!(status, 200, "{body}");
        service_url(&body, "web")
    }

    fn built(&self, instance: &str, release: &str) -> PathBuf {
        self.home().join("builds").join(instance).join(release)
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
    ($app:expr, $source:expr) => {
        bench!($app, $source, Duration::from_secs(300))
    };
    ($app:expr, $source:expr, $sleep:expr) => {
        match Bench::new($app, &$source, $sleep) {
            Some(bench) => bench,
            None => {
                eprintln!(
                    "ORBITAL_FRAMEWORKS=1 과 ORBITAL_PG 가 함께 있어야 돕니다. 건너뜁니다(npm run test:frameworks)"
                );
                return;
            }
        }
    };
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// 서비스의 주소. 이름으로 찾는다.
fn service_url(report: &Value, name: &str) -> String {
    report["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["name"] == name)
        .and_then(|service| service["url"].as_str())
        .unwrap_or_else(|| panic!("서비스 `{name}` 가 없습니다: {report}"))
        .to_owned()
}

/// 앱에 router 를 거쳐 요청한다. 넘겨주기(redirect)는 따라가지 않는다. 상태 · 본문 · `Location` 을 돌려준다.
fn app(
    method: &str,
    url: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (u16, String, String) {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut request = agent
        .request(method, url)
        .set("Accept", "text/html, application/json");
    if let Some(cookie) = cookie {
        request = request.set("Cookie", cookie);
    }
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    };
    let response = match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("{url}: {error}"),
    };
    let status = response.status();
    let location = response.header("location").unwrap_or_default().to_owned();
    (status, location, response.into_string().unwrap_or_default())
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("JSON 이 아닙니다: {text}"))
}

fn titles(text: &str) -> Vec<String> {
    json_of(text)
        .as_array()
        .unwrap()
        .iter()
        .map(|todo| todo["title"].as_str().unwrap().to_owned())
        .collect()
}

/// 이 빌드 폴더에서(작업 폴더로) 도는 프로세스의 수. 재운 서버가 정말 내려갔는지 본다. 리눅스의 `/proc` 을 읽는다.
fn processes_in(folder: &Path) -> usize {
    let Ok(folder) = fs::canonicalize(folder) else {
        return 0;
    };
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    fs::read_link(entry.path().join("cwd"))
                        .is_ok_and(|cwd| cwd.starts_with(&folder))
                })
                .count()
        })
        .unwrap_or(0)
}

/// 운영의 사람이 하듯이 들어온다. 로그인 링크를 요청하고 메일함에서 링크를 꺼내 같은 브라우저로 연다. 세션 쿠키를 돌려준다.
fn sign_in(bench: &Bench, origin: &str, email: &str) -> String {
    let outbox = bench.home().join(OUTBOX);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let asked = agent
        .post(&format!("{origin}/_orbital/auth/email-link"))
        .set("Origin", origin)
        .send_json(json!({ "email": email }))
        .unwrap();
    assert_eq!(asked.status(), 202);
    let browser = cookie_pair(&asked, "__Host-orbital-browser");
    let started = Instant::now();
    let link = loop {
        if let Some(mail) = Outbox::read(&outbox)
            .into_iter()
            .find(|mail| mail.to == email)
        {
            break mail.link;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "메일함에 링크가 없습니다"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let opened = agent.get(&link).set("Cookie", &browser).call().unwrap();
    assert_eq!(opened.status(), 302);
    cookie_pair(&opened, "__Host-orbital-session")
}

fn cookie_pair(response: &ureq::Response, name: &str) -> String {
    response
        .all("set-cookie")
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .and_then(|cookie| cookie.split(';').next())
        .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다"))
        .to_owned()
}

// ---- Next.js ----

#[test]
fn nextjs_앱이_레이어에서_빌드되어_프리뷰가_서고_씨앗_사용자가_자기_할_일만_본다() {
    let mut bench = bench!("todo", example("todo-next"));
    let instance = bench.instance();
    let token = bench.token(&instance);
    let (preview, took) = bench.preview(&instance, &token);
    assert_eq!(preview["findings"], json!([]), "{preview}");
    assert_eq!(preview["blockers"], json!([]), "{preview}");
    let release = preview["release"].as_str().unwrap();
    let built = bench.built(&instance, release);
    let cache = bench.home().join("caches").join(&instance);
    eprintln!(
        "잰 것: Next.js 프리뷰 한 번(npm ci + next build + DB + 서버) {:.1}초, node_modules {} KiB, .next {} KiB, 빌드의 캐시 {} KiB",
        took.as_secs_f64(),
        kib(&built.join("node_modules")),
        kib(&built.join(".next")),
        kib(&cache)
    );
    let url = service_url(&preview, "web");

    // 로그인하지 않았으면 앱이 로그인 화면으로 보낸다. 로그인 화면과 그 스크립트는 로그인 없이 열린다
    let (status, location, _) = app("GET", &format!("{url}/"), None, None);
    assert_eq!((status, location.as_str()), (307, "/login?next=/"));
    let (status, _, login) = app("GET", &format!("{url}/login"), None, None);
    assert_eq!(status, 200);
    assert!(login.contains("로그인 링크 받기"), "{login}");
    let script = login
        .split("src=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/_next/static/"))
        .expect("로그인 화면에 스크립트가 없습니다");
    assert_eq!(app("GET", &format!("{url}{script}"), None, None).0, 200);
    assert_eq!(app("GET", &format!("{url}/api/todos"), None, None).0, 401);

    // 씨앗 사용자로 들어가면 자기 할 일만 보인다. 화면(서버에서 그린 HTML)도 JSON 도 같다
    let u1 = bench.seed_cookie(&instance, &token, "u1");
    let (status, _, page) = app("GET", &format!("{url}/"), Some(&u1), None);
    assert_eq!(status, 200, "{page}");
    assert!(
        page.contains("장보기") && page.contains("세탁소 들르기"),
        "{page}"
    );
    assert!(!page.contains("남의 할 일"), "{page}");
    let (status, _, body) = app("GET", &format!("{url}/api/todos"), Some(&u1), None);
    assert_eq!(status, 200, "{body}");
    assert_eq!(titles(&body), vec!["장보기", "세탁소 들르기"]);

    // 더한 것은 더한 사람에게만 보인다
    let (status, _, body) = app(
        "POST",
        &format!("{url}/api/todos"),
        Some(&u1),
        Some(json!({ "title": "우유 사기" })),
    );
    assert_eq!(status, 201, "{body}");
    let (_, _, body) = app("GET", &format!("{url}/api/todos"), Some(&u1), None);
    assert_eq!(titles(&body), vec!["장보기", "세탁소 들르기", "우유 사기"]);
    let u2 = bench.seed_cookie(&instance, &token, "u2");
    let (_, _, body) = app("GET", &format!("{url}/api/todos"), Some(&u2), None);
    assert_eq!(titles(&body), vec!["남의 할 일"]);

    // 화면의 폼(서버 액션)으로 더해도 router 를 지나 같은 사람의 것으로 들어간다. 브라우저가 하듯이 같은 주소의 Origin 을 싣는다
    let (_, _, page) = app("GET", &format!("{url}/"), Some(&u1), None);
    let (status, body) = submit_form(&url, &page, &u1, "화분에 물 주기");
    assert!(status < 400, "{status}: {body}");
    let (_, _, body) = app("GET", &format!("{url}/api/todos"), Some(&u1), None);
    assert_eq!(
        titles(&body),
        vec!["장보기", "세탁소 들르기", "우유 사기", "화분에 물 주기"]
    );
}

/// 서버에서 그린 화면의 폼을 JavaScript 없이 보낸다(서버 액션의 점진적 향상). 폼에 실린 숨은 칸을 그대로 싣는다.
fn submit_form(url: &str, page: &str, cookie: &str, title: &str) -> (u16, String) {
    let hidden: Vec<(String, String)> = page
        .split("<input")
        .skip(1)
        .filter(|tag| tag.contains("type=\"hidden\""))
        .filter_map(|tag| {
            let attribute = |name: &str| {
                tag.split(&format!("{name}=\""))
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .map(|value| value.replace("&quot;", "\"").replace("&amp;", "&"))
            };
            Some((attribute("name")?, attribute("value").unwrap_or_default()))
        })
        .collect();
    assert!(
        hidden
            .iter()
            .any(|(name, _)| name.starts_with("$ACTION_ID_")),
        "화면에 서버 액션의 폼이 없습니다: {page}"
    );
    let boundary = "orbital-form-boundary";
    let mut body = String::new();
    for (name, value) in hidden
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .chain([("title", title)])
    {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    let origin = url.trim_end_matches('/');
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let response = agent
        .post(&format!("{origin}/"))
        .set("Cookie", cookie)
        .set("Origin", origin)
        .set("Accept", "text/html")
        .set(
            "Content-Type",
            &format!("multipart/form-data; boundary={boundary}"),
        )
        .send_string(&body);
    match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => (
            response.status(),
            response.into_string().unwrap_or_default(),
        ),
        Err(error) => panic!("{url}: {error}"),
    }
}

#[test]
fn nextjs_앱이_승인_뒤_운영에_오르고_재운_뒤_첫_요청에_깬다() {
    let sleep_after = Duration::from_secs(3);
    let mut bench = bench!("todo", example("todo-next"), sleep_after);
    let instance = bench.instance();
    let token = bench.token(&instance);
    let (preview, _) = bench.preview(&instance, &token);
    let release = preview["release"].as_str().unwrap().to_owned();
    // 프리뷰에서 빌드한 폴더를 운영이 그대로 쓴다. 다시 빌드하지 않는다
    let (production, took) = bench.promote(&instance, &token, &release);
    eprintln!(
        "잰 것: Next.js 승격(이미 빌드한 release, DB + 마이그레이션 + 서버) {:.1}초",
        took.as_secs_f64()
    );
    let live = service_url(&production, "web");

    // 운영에는 씨앗이 없다. 팩토리가 초대한 사람이 링크로 들어와 자기 할 일만 본다
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        json!({ "email": "u9@example.test", "roles": ["member"] }),
    );
    assert_eq!(status, 200, "{body}");
    let u9 = sign_in(&bench, &live, "u9@example.test");
    let (_, _, body) = app("GET", &format!("{live}/api/todos"), Some(&u9), None);
    assert_eq!(titles(&body), Vec::<String>::new());
    let (status, _, body) = app(
        "POST",
        &format!("{live}/api/todos"),
        Some(&u9),
        Some(json!({ "title": "운영의 첫 할 일" })),
    );
    assert_eq!(status, 201, "{body}");

    // 요청이 없으면 잔다. 빌드 폴더에서 도는 프로세스가 없어진다
    let built = bench.built(&instance, &release);
    let started = Instant::now();
    while processes_in(&built) > 0 {
        assert!(
            started.elapsed() < sleep_after + Duration::from_secs(20),
            "쉬게 두었는데 서버가 내려가지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // 첫 요청에 깨어 답한다
    let started = Instant::now();
    let (status, _, body) = app("GET", &format!("{live}/api/todos"), Some(&u9), None);
    let woke = started.elapsed();
    assert_eq!(status, 200, "{body}");
    assert_eq!(titles(&body), vec!["운영의 첫 할 일"]);
    assert!(processes_in(&built) > 0);
    eprintln!(
        "잰 것: Next.js 운영이 잔 뒤 첫 요청(next start 를 띄워 답하기까지) {:.2}초",
        woke.as_secs_f64()
    );
}

#[test]
fn 관리_서버가_다시_뜨면_운영의_nextjs_앱이_자는_채로_서고_첫_요청에_깬다() {
    let mut bench = bench!("todo", example("todo-next"));
    let instance = bench.instance();
    let token = bench.token(&instance);
    let (preview, _) = bench.preview(&instance, &token);
    let release = preview["release"].as_str().unwrap().to_owned();
    let (production, _) = bench.promote(&instance, &token, &release);
    let live = service_url(&production, "web");
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        json!({ "email": "u9@example.test", "roles": ["member"] }),
    );
    assert_eq!(status, 200, "{body}");
    let u9 = sign_in(&bench, &live, "u9@example.test");
    let (status, _, body) = app(
        "POST",
        &format!("{live}/api/todos"),
        Some(&u9),
        Some(json!({ "title": "다시 떠도 남는 일" })),
    );
    assert_eq!(status, 201, "{body}");
    let built = bench.built(&instance, &release);

    // 빌드 폴더가 남아 있으면 다시 빌드하지 않고 자는 채로 선다. 세션과 데이터는 그대로다
    let took = bench.restart();
    assert_eq!(processes_in(&built), 0, "다시 뜬 운영이 깨어 있습니다");
    // 하위 도메인을 쓰지 않는 레이어는 인스턴스마다 포트를 새로 잡아 주소가 바뀐다. 운영의 주소를 다시 읽는다
    let moved = bench.production_url(&instance);
    assert_ne!(moved, live, "포트가 그대로라면 이 줄을 지웁니다");
    let live = moved;
    let started = Instant::now();
    let (status, _, body) = app("GET", &format!("{live}/api/todos"), Some(&u9), None);
    let woke = started.elapsed();
    assert_eq!(status, 200, "{body}");
    assert_eq!(titles(&body), vec!["다시 떠도 남는 일"]);
    eprintln!(
        "잰 것: 관리 서버를 다시 띄우기(빌드 폴더가 있다) {:.2}초, 그 뒤 첫 요청 {:.2}초",
        took.as_secs_f64(),
        woke.as_secs_f64()
    );

    // 빌드 폴더가 없으면(디스크를 비웠거나 기계를 옮겼다) 다시 뜰 때 그 commit 에서 다시 빌드한다. 인스턴스의 캐시는 남아 있다
    fs::remove_dir_all(&built).unwrap();
    let took = bench.restart();
    let live = bench.production_url(&instance);
    let (status, _, body) = app("GET", &format!("{live}/api/todos"), Some(&u9), None);
    assert_eq!(status, 200, "{body}");
    eprintln!(
        "잰 것: 관리 서버를 다시 띄우기(빌드 폴더가 없어 npm ci + next build 를 다시 한다, 캐시는 있다) {:.1}초",
        took.as_secs_f64()
    );
}

// ---- NestJS + Vite ----

#[test]
fn nestjs_와_vite_앱이_한_저장소에서_빌드되어_api_는_api_에서_화면은_루트에서_선다() {
    let mut bench = bench!("hr", example("hr-nest-vite"));
    let instance = bench.instance();
    let token = bench.token(&instance);
    let (preview, took) = bench.preview(&instance, &token);
    assert_eq!(preview["findings"], json!([]), "{preview}");
    let release = preview["release"].as_str().unwrap();
    let built = bench.built(&instance, release);
    eprintln!(
        "잰 것: NestJS + Vite 프리뷰 한 번(npm ci + nest build + vite build + DB + 서버) {:.1}초, node_modules {} KiB, api/dist {} KiB, web/dist {} KiB",
        took.as_secs_f64(),
        kib(&built.join("node_modules")),
        kib(&built.join("api/dist")),
        kib(&built.join("web/dist"))
    );
    let origin = service_url(&preview, "web");
    assert_eq!(service_url(&preview, "api"), format!("{origin}/api"));

    // 화면은 정적 서비스가 내주고, 화면이 부르는 스크립트도 같은 자리에서 나온다
    let (status, _, page) = app("GET", &format!("{origin}/"), None, None);
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("<title>급여 명세</title>"), "{page}");
    let script = page
        .split("src=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/assets/"))
        .expect("화면에 스크립트가 없습니다");
    assert_eq!(app("GET", &format!("{origin}{script}"), None, None).0, 200);
    // API 는 /api 아래에서 NestJS 가 받는다. 로그인하지 않았으면 NestJS 가 401 로 답한다
    let (status, _, body) = app("GET", &format!("{origin}/api/health"), None, None);
    assert_eq!((status, json_of(&body)), (200, json!({ "ok": true })));
    assert_eq!(
        app("GET", &format!("{origin}/api/payslips"), None, None).0,
        401
    );
    // 정적 서비스는 없는 경로를 index.html 로 되돌리지 않는다(화면 안의 경로를 쓰는 앱은 막힌다. 문서의 구멍)
    assert_eq!(
        app("GET", &format!("{origin}/payslips/2026-11"), None, None).0,
        404
    );

    // 밖에서 넣는 비밀은 프리뷰의 값이 없어 환경 변수 없이 섰고, 운영의 값이 없어 승격이 막힌다
    assert_eq!(preview["missing_secrets"], json!(["BANK_API_KEY"]));
    assert!(
        preview["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("BANK_API_KEY")),
        "{preview}"
    );
    let (status, _, body) = app("POST", &format!("{origin}/api/jobs/payroll"), None, None);
    assert_eq!(
        (status, json_of(&body)),
        (200, json!({ "ran": true, "bank": "missing" }))
    );
}

#[test]
fn 직원은_자기_급여_명세만_팀장은_팀원의_것을_급여_관리자는_전부를_본다() {
    let sleep_after = Duration::from_secs(3);
    let mut bench = bench!("hr", example("hr-nest-vite"), sleep_after);
    let instance = bench.instance();
    let token = bench.token(&instance);
    let (preview, _) = bench.preview(&instance, &token);
    let origin = service_url(&preview, "web");
    let seen = |user: &str| -> (String, Vec<String>) {
        let cookie = bench.seed_cookie(&instance, &token, user);
        let (status, _, body) = app(
            "GET",
            &format!("{origin}/api/payslips"),
            Some(&cookie),
            None,
        );
        assert_eq!(status, 200, "{user}: {body}");
        let answer = json_of(&body);
        let employees = answer["payslips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|payslip| payslip["employee"].as_str().unwrap().to_owned())
            .collect();
        (answer["as"].as_str().unwrap().to_owned(), employees)
    };
    let strings = |list: &[&str]| {
        list.iter()
            .map(|text| (*text).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(seen("e1"), ("employee".to_owned(), strings(&["e1", "e1"])));
    assert_eq!(seen("e2"), ("employee".to_owned(), strings(&["e2"])));
    // 팀장은 자기가 맡은 개발팀(e1 · m1)의 것만 본다. 영업팀(e2)의 것은 보이지 않는다
    assert_eq!(
        seen("m1"),
        ("manager".to_owned(), strings(&["e1", "e1", "m1"]))
    );
    assert_eq!(
        seen("a1"),
        (
            "payroll_admin".to_owned(),
            strings(&["e1", "e1", "e2", "m1"])
        )
    );
    // API 가 잔 뒤에도 화면(정적 서비스)은 바로 나오고, API 는 첫 요청에 깨어 같은 것을 돌려준다
    let built = bench.built(&instance, preview["release"].as_str().unwrap());
    let started = Instant::now();
    while processes_in(&built) > 0 {
        assert!(
            started.elapsed() < sleep_after + Duration::from_secs(20),
            "쉬게 두었는데 API 가 내려가지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(app("GET", &format!("{origin}/"), None, None).0, 200);
    assert_eq!(processes_in(&built), 0, "화면을 내주느라 API 를 깨웠습니다");
    let started = Instant::now();
    let woke = seen("e1");
    eprintln!(
        "잰 것: NestJS API 가 잔 뒤 첫 요청(node dist/main.js 를 띄워 답하기까지, 세션 발급 포함) {:.2}초",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(woke, ("employee".to_owned(), strings(&["e1", "e1"])));
}

// ---- 빌드의 환경과 캐시 ----

/// 빌드가 적어 둔 환경의 이름들.
fn build_env_names(built: &Path) -> Vec<String> {
    fs::read_to_string(built.join("build-env.txt"))
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.to_owned()))
        .collect()
}

#[test]
fn 빌드는_운영자가_정한_환경만_받고_비밀과_관리_연결을_받지_않는다() {
    let mut bench = bench!("tiny", fixture("npm-tiny"));
    let instance = bench.instance();
    let token = bench.token(&instance);
    // 비밀은 선언한 release 의 프리뷰를 세운 뒤에 넣는다. 넣은 뒤 다시 세운 서버는 받고, 빌드는 받지 않아야 한다
    let (first, took) = bench.preview(&instance, &token);
    eprintln!(
        "잰 것: 의존성 하나의 프리뷰(npm ci) {:.1}초",
        took.as_secs_f64()
    );
    assert_eq!(first["missing_secrets"], json!(["BANK_API_KEY"]));
    let (status, body) = bench.call(
        "PUT",
        &format!("/v1/instances/{instance}/secrets/BANK_API_KEY"),
        Some(FACTORY),
        json!({ "stage": "preview", "value": "bank-preview-값" })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    let (preview, _) = bench.preview(&instance, &token);
    assert_eq!(preview["missing_secrets"], json!([]));
    // 빌드가 레지스트리에서 받은 의존성으로 서버가 뜨고, 서버는 비밀과 DB 의 주소를 받는다
    let url = service_url(&preview, "web");
    let (status, _, body) = app("GET", &format!("{url}/"), None, None);
    assert_eq!((status, json_of(&body)), (200, json!({ "ok": true })));
    let (_, _, body) = app("GET", &format!("{url}/env"), None, None);
    let served = json_of(&body);
    for name in ["BANK_API_KEY", "SESSION_KEY", "PGPORT"] {
        assert!(
            served.as_array().unwrap().contains(&json!(name)),
            "{name}: {served}"
        );
    }
    // 서버는 빌드의 환경을 받지 않는다
    for name in build_env(OPERATOR_ENV, |name| std::env::var(name).ok()).unwrap() {
        assert!(
            !served.as_array().unwrap().contains(&json!(name.0)),
            "{}",
            name.0
        );
    }

    let built = bench.built(&instance, preview["release"].as_str().unwrap());
    let names = build_env_names(&built);
    let text = fs::read_to_string(built.join("build-env.txt")).unwrap();
    // 운영자가 적은 이름 가운데 이 기계에 있는 것만 넘어간다
    let operator: Vec<String> = build_env(OPERATOR_ENV, |name| std::env::var(name).ok())
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for name in &operator {
        assert!(names.contains(name), "{name}: {names:?}");
    }
    let allowed = |name: &str| {
        operator.iter().any(|known| known == name)
            || ["PATH", "HOME", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name)
            // npm 이 빌드 명령(`npm config`)을 부르며 스스로 더하는 것
            || name.starts_with("npm_") || name == "NODE" || name == "INIT_CWD" || name == "COLOR" || name == "EDITOR"
    };
    let strangers: Vec<&String> = names.iter().filter(|name| !allowed(name)).collect();
    assert!(
        strangers.is_empty(),
        "운영자가 적지 않은 환경: {strangers:?}"
    );
    // 비밀 · 관리 연결 · 레이어의 설정은 이름도 값도 없다
    for forbidden in [
        "SESSION_KEY",
        "BANK_API_KEY",
        "PGHOST",
        "PGPORT",
        "ORBITAL_",
        "CARGO",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    assert!(!text.contains("bank-preview-값"));
}

#[test]
fn 인스턴스마다_빌드의_캐시와_빌드_폴더를_따로_둔다() {
    let mut bench = bench!("tiny", fixture("npm-tiny"));
    let mut seen = Vec::new();
    for _ in 0..2 {
        let instance = bench.instance();
        let token = bench.token(&instance);
        let (preview, _) = bench.preview(&instance, &token);
        let built = bench.built(&instance, preview["release"].as_str().unwrap());
        let cache = PathBuf::from(
            fs::read_to_string(built.join("build-cache.txt"))
                .unwrap()
                .trim(),
        );
        seen.push((instance, built, cache));
    }
    let [(a, a_built, a_cache), (b, b_built, b_cache)] = <[_; 2]>::try_from(seen).unwrap();
    // npm 의 캐시는 인스턴스의 홈 아래에 쌓이고, 실제로 받은 것이 들어 있다
    let home = bench.home();
    assert_eq!(a_cache, home.join("caches").join(&a).join(".npm"));
    assert_eq!(b_cache, home.join("caches").join(&b).join(".npm"));
    assert!(kib(&a_cache) > 0 && kib(&b_cache) > 0);
    // 서로의 자리와 겹치지 않고, 서버가 뜨는 빌드 폴더에 캐시가 실리지 않는다
    for (one, other) in [
        (&a_cache, &b_cache),
        (&a_built, &b_built),
        (&a_cache, &b_built),
        (&a_built, &b_cache),
    ] {
        assert!(!one.starts_with(other) && !other.starts_with(one));
    }
    assert!(!a_cache.starts_with(&a_built) && !b_cache.starts_with(&b_built));
}
