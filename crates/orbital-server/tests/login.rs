//! 로그인 한 바퀴를 실제로 돈다. 레이어가 미리보기와 운영 앞에 router 를 세우고, 사람은 router 의 주소로만 닿는다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스(Node 서버), 실제 HTTP 로 잰다. router 에는 손으로 짠 HTTP/1.1 요청을 보낸다.
//! 브라우저나 HTTP 라이브러리가 경로의 `..` 를 미리 풀어 버리지 않게, 그리고 답의 머리말을 빠짐없이 견주려는 것이다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 띄운 router 와 앱은 레이어가 인스턴스를 걷을 때 함께 내린다.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use orbital_router::{Mail, Outbox};
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, OUTBOX, Options};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const ORGANIZATION: &str = "factory";

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

    /// `Set-Cookie` 가운데 이 이름의 것을 `이름=값` 으로.
    fn cookie(&self, name: &str) -> String {
        self.set_cookie(name)
            .and_then(|cookie| cookie.split(';').next())
            .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다: {:?}", self.headers))
            .to_owned()
    }

    fn set_cookie(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .map(|(_, value)| value.as_str())
            .find(|value| value.starts_with(&format!("{name}=")))
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// 머리말과 본문을 한 글자열로. 값이 어디에도 없는지 볼 때 쓴다.
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

/// `origin`(`http://127.0.0.1:포트`)에 요청 하나를 보낸다. `path` 는 고치지 않고 그대로 보낸다.
fn http(method: &str, origin: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let address = origin.trim_start_matches("http://");
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
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
const PAGE: (&str, &str) = ("Accept", "text/html,application/xhtml+xml");

// ---- 레이어 ----

struct Bench {
    home: PathBuf,
    scratch: PathBuf,
    pg_url: String,
    layer: Layer,
    instances: Vec<String>,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-login-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&scratch).unwrap();
        let home = scratch.join("home");
        let layer = Layer::open(Options {
            home: home.clone(),
            pg_url: pg_url.clone(),
            service_keys: vec![(FACTORY.to_owned(), ORGANIZATION.to_owned())],
            runner: Box::new(LocalRunner::default()),
        })
        .expect("레이어를 열지 못했습니다");
        let bench = Self {
            home,
            scratch,
            pg_url,
            layer,
            instances: Vec::new(),
        };
        bench.upload("cards", &Self::cards_scaffold);
        bench.upload("plain", &Self::plain_scaffold);
        Some(bench)
    }

    /// 로그인이 필요한 앱. 할 일 카드의 앱에 선언과 정적 파일을 덮고, 정적 폴더 밖을 가리키는 심볼릭 링크를 하나 둔다.
    fn cards_scaffold(folder: &Path) {
        copy_tree(&fixture("todo"), folder);
        copy_tree(&fixture("cards"), folder);
        std::os::unix::fs::symlink("../orbital.toml", folder.join("site/link-out")).unwrap();
        fs::write(folder.join("site/.hidden"), "숨긴 파일").unwrap();
    }

    /// 로그인을 레이어에 맡기지 않는 앱. 할 일 카드의 앱에서 `[auth]` 와 씨앗 사용자를 뺀다.
    fn plain_scaffold(folder: &Path) {
        copy_tree(&fixture("todo"), folder);
        let manifest = fs::read_to_string(folder.join("orbital.toml")).unwrap();
        let without = manifest.split("\n# 로그인은 레이어가").next().unwrap();
        fs::write(folder.join("orbital.toml"), without).unwrap();
        fs::remove_file(folder.join("db/seed/users.toml")).unwrap();
        let migration = folder.join("db/migrations/001_card.sql");
        let sql = fs::read_to_string(&migration)
            .unwrap()
            .replace(" REFERENCES orbital_auth.users (id)", "");
        fs::write(migration, sql).unwrap();
        assert!(
            !fs::read_to_string(folder.join("orbital.toml"))
                .unwrap()
                .contains("[auth]")
        );
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
        let reply = handle(&self.layer, method, path, Some(bearer), body);
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

    /// 미리보기를 세운다. 그 router 의 주소와 release 를 돌려준다.
    fn preview_release(&self, instance: &str, token: &str) -> (String, String) {
        let (status, preview) = self.call(
            "POST",
            &format!("/v1/instances/{instance}/previews"),
            token,
            &[],
        );
        assert_eq!(status, 200, "{preview}");
        assert_eq!(preview["findings"], json!([]), "{preview}");
        (
            preview["services"][0]["url"].as_str().unwrap().to_owned(),
            preview["release"].as_str().unwrap().to_owned(),
        )
    }

    fn preview(&self, instance: &str, token: &str) -> String {
        self.preview_release(instance, token).0
    }

    /// 미리보기 → 승격 요청 → 고객의 승인 → 운영. 운영의 router 의 주소를 돌려준다.
    fn ship(&mut self, app: &str) -> (String, String) {
        let instance = self.instance(app);
        let token = self.token(&instance);
        let (_, release) = self.preview_release(&instance, &token);
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
        (instance, live)
    }

    fn invite(&self, instance: &str, email: &str) {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/users"),
            FACTORY,
            &json!({ "email": email, "roles": ["member"] }),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn mails(&self) -> Vec<Mail> {
        Outbox::read(&self.home.join(OUTBOX))
    }

    fn mails_to(&self, email: &str) -> Vec<Mail> {
        self.mails()
            .into_iter()
            .filter(|mail| mail.to == email)
            .collect()
    }

    /// 사람이 하듯이 들어온다. 링크를 요청하고, 메일함에서 링크를 꺼내 같은 브라우저로 연다. 세션 쿠키(`이름=값`)를 돌려준다.
    fn sign_in(&self, origin: &str, email: &str) -> String {
        let asked = http(
            "POST",
            origin,
            "/_orbital/auth/email-link",
            &[("Origin", origin), ("Content-Type", "application/json")],
            &json!({ "email": email, "next": "/cards" }).to_string(),
        );
        assert_eq!(asked.status, 202, "{}", asked.body);
        let browser = asked.cookie("__Host-orbital-browser");
        let link = self
            .mails_to(email)
            .pop()
            .expect("메일함에 링크가 없습니다")
            .link;
        let path = link
            .strip_prefix(origin)
            .expect("링크가 이 router 의 주소가 아닙니다");
        let opened = http("GET", origin, path, &[("Cookie", &browser)], "");
        assert_eq!(opened.status, 302, "{}", opened.everything());
        assert_eq!(opened.header("location"), Some("/cards"));
        opened.cookie("__Host-orbital-session")
    }

    /// 운영 DB 에서 1분이 지난 것처럼 그 인스턴스의 링크를 모두 앞당긴다. 같은 이메일로 링크를 다시 받으려는 것이다.
    fn age_links(&self, instance: &str) {
        let mut config: postgres::Config = self.pg_url.parse().unwrap();
        let mut client = config
            .dbname(&format!("i_{instance}"))
            .connect(postgres::NoTls)
            .unwrap();
        client
            .batch_execute(
                "UPDATE orbital_auth.email_link SET created_at = created_at - interval '2 minutes'",
            )
            .unwrap();
    }

    fn me(origin: &str, cookie: &str) -> Reply {
        http(
            "GET",
            origin,
            "/_orbital/auth/me",
            &[("Cookie", cookie), JSON],
            "",
        )
    }

    fn cards(origin: &str, cookie: &str) -> Reply {
        http("GET", origin, "/cards", &[("Cookie", cookie), JSON], "")
    }

    /// 레이어가 남긴 기록(빌드 · 앱 · router)을 모두 읽는다.
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
        for instance in &self.instances {
            let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), FACTORY, &[]);
        }
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

fn titles(reply: &Reply) -> Vec<String> {
    reply
        .json()
        .as_array()
        .unwrap_or_else(|| panic!("{}", reply.everything()))
        .iter()
        .map(|card| card["title"].as_str().unwrap().to_owned())
        .collect()
}

// ---- 로그인 한 바퀴 ----

#[test]
fn 초대받은_사용자가_링크로_들어와_자기_카드만_본다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let kim = bench.sign_in(&live, "kim@example.com");
    let lee = bench.sign_in(&live, "lee@example.com");

    let me = Bench::me(&live, &kim);
    assert_eq!(me.status, 200);
    assert_eq!(me.json()["email"], "kim@example.com");
    assert_eq!(me.json()["roles"], json!(["member"]));

    for (cookie, title) in [(&kim, "김의 일"), (&lee, "이의 일")] {
        let made = http("POST", &live, "/cards", &[("Cookie", cookie), JSON], title);
        assert_eq!(made.status, 201, "{}", made.everything());
    }
    assert_eq!(titles(&Bench::cards(&live, &kim)), vec!["김의 일"]);
    assert_eq!(titles(&Bench::cards(&live, &lee)), vec!["이의 일"]);
}

#[test]
fn 초대받지_않은_이메일과_초대받은_이메일에_같은_답이_가고_초대받지_않은_쪽에는_메일이_가지_않는다()
{
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let ask = |email: &str, cookie: Option<&str>| {
        let mut headers = vec![
            ("Origin", live.as_str()),
            ("Content-Type", "application/json"),
        ];
        if let Some(cookie) = cookie {
            headers.push(("Cookie", cookie));
        }
        http(
            "POST",
            &live,
            "/_orbital/auth/email-link",
            &headers,
            &json!({ "email": email }).to_string(),
        )
    };
    // 시각과 표식의 값만 빼고 견준다
    let shape = |reply: &Reply| -> (u16, Vec<(String, String)>, String) {
        let headers = reply
            .headers
            .iter()
            .filter(|(key, _)| key != "date")
            .map(|(key, value)| {
                let value = if key == "set-cookie" {
                    value
                        .split_once(';')
                        .map_or(String::new(), |(_, attributes)| attributes.to_owned())
                } else {
                    value.clone()
                };
                (key.clone(), value)
            })
            .collect();
        (reply.status, headers, reply.body.clone())
    };

    // 표식 쿠키가 없는 브라우저: 둘 다 표식을 심고 같은 답을 받는다
    let invited = ask("kim@example.com", None);
    let stranger = ask("stranger@example.com", None);
    assert_eq!(invited.status, 202);
    assert_eq!(invited.body, "{}");
    assert_eq!(shape(&invited), shape(&stranger));
    // 표식 쿠키가 있는 브라우저: 머리말이 시각 말고는 한 글자도 다르지 않다
    let browser = invited.cookie("__Host-orbital-browser");
    let invited = ask("lee@example.com", Some(&browser));
    let stranger = ask("nobody@example.com", Some(&browser));
    assert_eq!(invited.set_cookie("__Host-orbital-browser"), None);
    let strip = |reply: &Reply| {
        reply
            .headers
            .iter()
            .filter(|(key, _)| key != "date")
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        (invited.status, strip(&invited), &invited.body),
        (stranger.status, strip(&stranger), &stranger.body)
    );

    assert_eq!(bench.mails_to("kim@example.com").len(), 1);
    assert_eq!(bench.mails_to("lee@example.com").len(), 1);
    assert!(bench.mails_to("stranger@example.com").is_empty());
    assert!(bench.mails_to("nobody@example.com").is_empty());
}

#[test]
fn 밖에서_신원_머리말을_실어_보내도_앱에는_닿지_않는다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let kim = bench.sign_in(&live, "kim@example.com");
    let forged = "v1.00.00";
    let echo = http(
        "GET",
        &live,
        "/echo",
        &[
            ("Cookie", &kim),
            ("X-Orbital-Identity", forged),
            ("X-Orbital-Stage", "production"),
            JSON,
        ],
        "",
    );
    assert_eq!(echo.status, 200, "{}", echo.everything());
    let headers = &echo.json()["headers"];
    // router 가 세션을 보고 붙인 신원만 닿는다
    let identity = headers["x-orbital-identity"].as_str().unwrap();
    assert_ne!(identity, forged);
    assert!(identity.starts_with("v1."));
    assert_eq!(headers["x-orbital-stage"], Value::Null);
    // 밖에서 실은 신원으로는 남의 카드를 읽지 못한다(세션이 없으면 앱에 닿지도 않는다)
    let without = http(
        "GET",
        &live,
        "/cards",
        &[("X-Orbital-Identity", identity), JSON],
        "",
    );
    assert_eq!(without.status, 401);
}

#[test]
fn 앱에_닿는_요청에는_세션_쿠키가_없다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let kim = bench.sign_in(&live, "kim@example.com");
    let cookie = format!("{kim}; theme=dark; __Host-orbital-browser=aa");
    let echo = http("GET", &live, "/echo", &[("Cookie", &cookie), JSON], "");
    assert_eq!(echo.status, 200, "{}", echo.everything());
    assert_eq!(echo.json()["headers"]["cookie"], "theme=dark");
    let only = http("GET", &live, "/echo", &[("Cookie", &kim), JSON], "");
    assert_eq!(only.json()["headers"]["cookie"], Value::Null);
    assert!(!only.body.contains(kim.split('=').nth(1).unwrap()));
}

#[test]
fn 로그아웃하면_그_쿠키로는_다음_요청부터_들어가지_못한다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let kim = bench.sign_in(&live, "kim@example.com");
    assert_eq!(Bench::cards(&live, &kim).status, 200);
    let out = http(
        "POST",
        &live,
        "/_orbital/auth/logout",
        &[("Origin", &live), ("Cookie", &kim)],
        "",
    );
    assert_eq!(out.status, 204);
    let cleared = out.set_cookie("__Host-orbital-session").unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert_eq!(Bench::cards(&live, &kim).status, 401);
    assert_eq!(Bench::me(&live, &kim).status, 401);
}

#[test]
fn 사용자를_빼면_그_사용자의_모든_세션이_다음_요청부터_끊긴다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let first = bench.sign_in(&live, "kim@example.com");
    bench.age_links(&instance);
    let second = bench.sign_in(&live, "kim@example.com");
    let lee = bench.sign_in(&live, "lee@example.com");
    assert_ne!(first, second);
    let kim = Bench::me(&live, &first).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for cookie in [&first, &second, &lee] {
        assert_eq!(Bench::cards(&live, cookie).status, 200);
    }

    let id = orbital_core::name::InstanceId::parse(&instance).unwrap();
    let mut store = bench.layer.production_auth(ORGANIZATION, &id).unwrap();
    store.remove(&kim, 1).unwrap();

    for cookie in [&first, &second] {
        assert_eq!(Bench::cards(&live, cookie).status, 401);
        assert_eq!(Bench::me(&live, cookie).status, 401);
    }
    assert_eq!(Bench::cards(&live, &lee).status, 200);
}

#[test]
fn 다른_origin_에서_온_로그아웃과_링크_요청은_받지_않는다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let kim = bench.sign_in(&live, "kim@example.com");
    let evil = "http://evil.example";
    let elsewhere = live.replace("127.0.0.1", "localhost");
    for origin in [Some(evil), Some("null"), Some(elsewhere.as_str()), None] {
        let mut headers = vec![
            ("Cookie", kim.as_str()),
            ("Content-Type", "application/json"),
        ];
        if let Some(origin) = origin {
            headers.push(("Origin", origin));
        }
        let out = http("POST", &live, "/_orbital/auth/logout", &headers, "");
        assert_eq!(out.status, 403, "{origin:?}");
        assert_eq!(out.set_cookie("__Host-orbital-session"), None);
        let asked = http(
            "POST",
            &live,
            "/_orbital/auth/email-link",
            &headers,
            &json!({ "email": "lee@example.com" }).to_string(),
        );
        assert_eq!(asked.status, 403, "{origin:?}");
    }
    // 세션은 그대로이고, 링크는 만들어지지 않았다
    assert_eq!(Bench::me(&live, &kim).status, 200);
    assert!(bench.mails_to("lee@example.com").is_empty());
}

#[test]
fn 로그인이_필요한_서비스에_세션_없이_화면을_열면_로그인_화면으로_가고_화면이_아닌_요청은_401_이다()
{
    let mut bench = bench!();
    let (_, live) = bench.ship("cards");
    let page = http("GET", &live, "/cards?tab=done", &[PAGE], "");
    assert_eq!(page.status, 302);
    assert_eq!(
        page.header("location"),
        Some("/login?next=/cards%3Ftab%3Ddone")
    );
    let api = http("GET", &live, "/cards", &[JSON], "");
    assert_eq!(api.status, 401);
    assert_eq!(api.json(), json!({ "error": "unauthorized" }));
    assert_eq!(http("POST", &live, "/cards", &[PAGE], "새 일").status, 401);
    // 세션 쿠키가 틀려도 같다
    let wrong = http(
        "GET",
        &live,
        "/cards",
        &[("Cookie", "__Host-orbital-session=00"), JSON],
        "",
    );
    assert_eq!(wrong.status, 401);
    // 로그인 화면과 그 아래는 세션 없이 열린다
    let login = http("GET", &live, "/login?error=used", &[PAGE], "");
    assert_eq!(login.status, 200);
    assert!(login.body.contains("<form"));
    // 로그인을 요구하지 않는 정적 서비스도 열린다
    assert_eq!(http("GET", &live, "/static/", &[PAGE], "").status, 200);
}

#[test]
fn 씨앗_사용자로_들어가는_길은_미리보기에만_있고_운영에서는_404_다() {
    let mut bench = bench!();
    let instance = bench.instance("cards");
    let token = bench.token(&instance);
    let preview = bench.preview(&instance, &token);
    let sign_in = |origin: &str, user: &str| {
        http(
            "POST",
            origin,
            "/_orbital/preview/sign-in",
            &[("Origin", origin), ("Content-Type", "application/json")],
            &json!({ "user": user, "next": "/cards" }).to_string(),
        )
    };
    let entered = sign_in(&preview, "u1");
    assert_eq!(entered.status, 302, "{}", entered.everything());
    assert_eq!(entered.header("location"), Some("/cards"));
    let u1 = entered.cookie("__Host-orbital-session");
    assert_eq!(
        titles(&Bench::cards(&preview, &u1)),
        vec!["씨앗 카드 하나", "씨앗 카드 둘"]
    );
    // 씨앗 사용자가 아니면 들어가지 못한다
    assert_eq!(sign_in(&preview, "u9").status, 404);

    let (_, live) = bench.ship("cards");
    let refused = sign_in(&live, "u1");
    assert_eq!(refused.status, 404);
    assert_eq!(refused.set_cookie("__Host-orbital-session"), None);
}

#[test]
fn 한_인스턴스의_세션_쿠키는_다른_인스턴스에서_읽히지_않는다() {
    let mut bench = bench!();
    let (ours, ours_live) = bench.ship("cards");
    let (theirs, theirs_live) = bench.ship("cards");
    bench.invite(&ours, "kim@example.com");
    bench.invite(&theirs, "kim@example.com");
    let kim = bench.sign_in(&ours_live, "kim@example.com");
    assert_eq!(Bench::me(&ours_live, &kim).status, 200);
    assert_eq!(Bench::me(&theirs_live, &kim).status, 401);
    assert_eq!(Bench::cards(&theirs_live, &kim).status, 401);
    // 그 인스턴스에서는 따로 들어온다
    let there = bench.sign_in(&theirs_live, "kim@example.com");
    assert_eq!(Bench::me(&theirs_live, &there).status, 200);
    assert_eq!(Bench::me(&ours_live, &there).status, 401);
}

#[test]
fn 정적_서비스의_파일을_내주고_폴더_밖의_경로는_내주지_않는다() {
    let mut bench = bench!();
    let (_, live) = bench.ship("cards");
    let index = http("GET", &live, "/static/", &[], "");
    assert_eq!(index.status, 200);
    assert!(index.body.contains("정적 서비스의 첫 화면"));
    assert_eq!(
        index.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let script = http("GET", &live, "/static/app.js", &[], "");
    assert_eq!(script.status, 200);
    assert!(script.body.contains("cards"));
    assert_eq!(script.header("x-content-type-options"), Some("nosniff"));
    for outside in [
        "/static/../orbital.toml",
        "/static/%2e%2e/orbital.toml",
        "/static/..%2forbital.toml",
        "/static/site/../../orbital.toml",
        "/static/link-out",
        "/static/.hidden",
        "/static/%2e%2e%2f%2e%2e%2fhome",
        "/static/missing.js",
    ] {
        let reply = http("GET", &live, outside, &[], "");
        assert_eq!(reply.status, 404, "{outside}: {}", reply.everything());
        assert!(!reply.body.contains("[[service]]"), "{outside}");
        assert!(!reply.body.contains("숨긴 파일"), "{outside}");
    }
}

#[test]
fn 세션_토큰은_답과_로그와_오류_어디에도_없고_링크의_토큰은_메일에만_있다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let mut replies = Vec::new();

    let asked = http(
        "POST",
        &live,
        "/_orbital/auth/email-link",
        &[("Origin", &live), ("Content-Type", "application/json")],
        &json!({ "email": "kim@example.com" }).to_string(),
    );
    let browser = asked.cookie("__Host-orbital-browser");
    replies.push(asked);
    let link = bench.mails_to("kim@example.com").pop().unwrap().link;
    let link_token = link.split("token=").nth(1).unwrap().to_owned();
    let path = link.strip_prefix(&live).unwrap().to_owned();
    let opened = http("GET", &live, &path, &[("Cookie", &browser)], "");
    let session = opened.cookie("__Host-orbital-session");
    let session_token = session.split('=').nth(1).unwrap().to_owned();
    // 세션 토큰이 나가는 자리는 이 한 줄(Set-Cookie)뿐이다
    let set = opened.set_cookie("__Host-orbital-session").unwrap();
    assert!(
        set.contains("HttpOnly")
            && set.contains("Secure")
            && set.contains("SameSite=Lax")
            && set.contains("Path=/")
    );
    assert_eq!(opened.header("referrer-policy"), Some("no-referrer"));
    let mut without_set_cookie = opened;
    without_set_cookie
        .headers
        .retain(|(key, _)| key != "set-cookie");
    replies.push(without_set_cookie);

    let cookie = format!("{session}; {browser}");
    replies.push(Bench::me(&live, &cookie));
    replies.push(Bench::cards(&live, &cookie));
    replies.push(http(
        "GET",
        &live,
        "/echo",
        &[("Cookie", &cookie), JSON],
        "",
    ));
    // 다시 연 링크 · 틀린 토큰 · 없는 길의 오류
    replies.push(http("GET", &live, &path, &[("Cookie", &browser)], ""));
    replies.push(http("GET", &live, &path, &[], ""));
    replies.push(http(
        "GET",
        &live,
        "/_orbital/auth/callback?token=zz",
        &[("Cookie", &browser)],
        "",
    ));
    replies.push(http(
        "GET",
        &live,
        "/_orbital/nothing",
        &[("Cookie", &cookie)],
        "",
    ));
    replies.push(http(
        "POST",
        &live,
        "/_orbital/auth/logout",
        &[("Origin", &live), ("Cookie", &cookie)],
        "",
    ));
    assert_eq!(replies[5].header("location"), Some("/login?error=used"));
    assert_eq!(
        replies[6].header("location"),
        Some("/login?error=other_browser")
    );
    assert_eq!(replies[7].header("location"), Some("/login?error=invalid"));

    for reply in &replies {
        let text = reply.everything();
        assert!(
            !text.contains(&session_token),
            "세션 토큰이 답에 있습니다: {text}"
        );
        assert!(
            !text.contains(&link_token),
            "링크의 토큰이 답에 있습니다: {text}"
        );
    }
    let logs = bench.logs();
    assert!(
        logs.contains("GET /_orbital/auth/callback 302"),
        "router 의 기록이 없습니다"
    );
    assert!(
        !logs.contains(&session_token),
        "세션 토큰이 기록에 있습니다"
    );
    assert!(!logs.contains(&link_token), "링크의 토큰이 기록에 있습니다");
    // 링크의 토큰은 메일에만 있다
    let outbox = fs::read_to_string(bench.home.join(OUTBOX)).unwrap();
    assert_eq!(outbox.matches(&link_token).count(), 1);
    assert!(!outbox.contains(&session_token));
}

#[test]
fn auth_를_선언하지_않은_인스턴스의_앱은_router_를_지나도_전과_같이_답한다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("plain");
    let health = http("GET", &live, "/health", &[JSON], "");
    assert_eq!(health.status, 200);
    assert_eq!(health.json(), json!({ "ok": true, "version": 1 }));
    // 밖에서 실은 신원 머리말은 앱에 닿지 않는다. 사용자가 없으니 앱에는 신원이 오지 않는다
    let echo = http(
        "GET",
        &live,
        "/echo",
        &[
            ("X-Orbital-Identity", "v1.00.00"),
            ("Cookie", "theme=dark"),
            JSON,
        ],
        "",
    );
    assert_eq!(echo.json()["headers"]["x-orbital-identity"], Value::Null);
    assert_eq!(echo.json()["headers"]["cookie"], "theme=dark");
    assert_eq!(Bench::cards(&live, "theme=dark").json(), json!([]));
    // 레이어의 로그인 길은 없다
    assert_eq!(http("GET", &live, "/_orbital/auth/me", &[], "").status, 404);
    let asked = http(
        "POST",
        &live,
        "/_orbital/auth/email-link",
        &[("Origin", &live), ("Content-Type", "application/json")],
        &json!({ "email": "kim@example.com" }).to_string(),
    );
    assert_eq!(asked.status, 404);
    // 초대할 사용자도 없다
    let (status, _) = bench.post(
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &json!({ "email": "kim@example.com" }),
    );
    assert_eq!(status, 422);
}

#[test]
fn 에이전트의_토큰으로는_사용자를_초대하지_못한다() {
    let mut bench = bench!();
    let (instance, _) = bench.ship("cards");
    let token = bench.token(&instance);
    let path = format!("/v1/instances/{instance}/users");
    let body = json!({ "email": "kim@example.com", "roles": ["member"] });
    assert_eq!(bench.post(&path, &token, &body).0, 404);
    // 팩토리의 service key 로는 된다. 선언에 없는 업무 역할은 고칠 것으로 돌려준다
    assert_eq!(bench.post(&path, FACTORY, &body).0, 200);
    let (status, problems) = bench.post(
        &path,
        FACTORY,
        &json!({ "email": "lee@example.com", "roles": ["admin"] }),
    );
    assert_eq!(status, 422, "{problems}");
}
