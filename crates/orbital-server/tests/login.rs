//! 로그인 한 바퀴를 실제로 돈다. 레이어가 프리뷰와 운영 앞에 router 를 세우고, 사람은 router 의 주소로만 닿는다.
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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use orbital_pg::oauth::s256;
use orbital_router::{DocumentFetcher, FetchError, Fetched, Mail, Outbox};
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, OUTBOX, Options};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
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
    /// 가짜로 받아 오는 metadata 문서. 실제 네트워크에는 나가지 않는다.
    documents: Arc<FakeDocuments>,
    instances: Vec<String>,
}

/// 주소마다 돌려줄 문서를 테스트가 적어 두는 가짜 가져오기.
#[derive(Default)]
struct FakeDocuments {
    /// 주소마다 문서와 그 답의 `Cache-Control`.
    documents: Mutex<BTreeMap<String, (String, Option<String>)>>,
    asked: Mutex<Vec<String>>,
}

impl FakeDocuments {
    fn put(&self, url: &str, document: &Value) {
        self.put_cached(url, document, None);
    }

    fn put_cached(&self, url: &str, document: &Value, cache_control: Option<&str>) {
        self.documents.lock().unwrap().insert(
            url.to_owned(),
            (document.to_string(), cache_control.map(str::to_owned)),
        );
    }
}

impl DocumentFetcher for FakeDocuments {
    fn fetch(&self, url: &str) -> Result<Fetched, FetchError> {
        self.asked.lock().unwrap().push(url.to_owned());
        self.documents
            .lock()
            .unwrap()
            .get(url)
            .map(|(text, cache_control)| Fetched {
                body: text.as_bytes().to_vec(),
                cache_control: cache_control.clone(),
            })
            .ok_or(FetchError::Unreachable)
    }
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
        let documents = Arc::new(FakeDocuments::default());
        // 이 테스트들은 팩토리의 키 없이 운영까지 올린다. 개발용 메일함을 명시해 켠다
        let layer = Layer::open(Options {
            dev_mailbox: true,
            ..Options::new(
                home.clone(),
                pg_url.clone(),
                vec![
                    (FACTORY.to_owned(), ORGANIZATION.to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        })
        .expect("레이어를 열지 못했습니다")
        .with_document_fetcher(documents.clone());
        let bench = Self {
            home,
            scratch,
            pg_url,
            layer,
            documents,
            instances: Vec::new(),
        };
        bench.upload("cards", &Self::cards_scaffold);
        bench.upload("plain", &Self::plain_scaffold);
        bench.upload("payroll", &|folder: &Path| {
            copy_tree(&fixture("payroll"), folder)
        });
        bench.upload("mcp", &|folder: &Path| {
            copy_tree(&fixture("todo"), folder);
            copy_tree(&fixture("mcp"), folder);
        });
        bench.upload("mcpclosed", &|folder: &Path| {
            copy_tree(&fixture("todo"), folder);
            copy_tree(&fixture("mcp"), folder);
            let manifest = fs::read_to_string(folder.join("orbital.toml")).unwrap();
            fs::write(
                folder.join("orbital.toml"),
                format!("{manifest}dynamic_registration = false\n"),
            )
            .unwrap();
        });
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

    /// 프리뷰를 세운다. 그 router 의 주소와 release 를 돌려준다.
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

    /// 프리뷰 → 승격 요청 → 고객의 승인 → 운영. 운영의 router 의 주소를 돌려준다.
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

    /// 그 이메일로 `count` 통이 쌓일 때까지 기다렸다가 돌려준다. 메일은 링크 요청의 답을 보낸 뒤에 뒤에서 나간다.
    fn wait_mails_to(&self, email: &str, count: usize) -> Vec<Mail> {
        let started = std::time::Instant::now();
        loop {
            let mails = self.mails_to(email);
            if mails.len() >= count || started.elapsed() > Duration::from_secs(10) {
                return mails;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn mails_to(&self, email: &str) -> Vec<Mail> {
        self.mails()
            .into_iter()
            .filter(|mail| mail.to == email)
            .collect()
    }

    /// 사람이 하듯이 들어온다. 링크를 요청하고, 메일함에서 링크를 꺼내 같은 브라우저로 연다. 세션 쿠키(`이름=값`)를 돌려준다.
    fn sign_in(&self, origin: &str, email: &str) -> String {
        let before = self.mails_to(email).len();
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
            .wait_mails_to(email, before + 1)
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

    assert_eq!(bench.wait_mails_to("kim@example.com", 1).len(), 1);
    assert_eq!(bench.wait_mails_to("lee@example.com", 1).len(), 1);
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
    assert!(identity.starts_with("v2."));
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
fn 씨앗_사용자로_들어가는_길은_프리뷰에만_있고_운영에서는_404_다() {
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
    let link = bench
        .wait_mails_to("kim@example.com", 1)
        .pop()
        .unwrap()
        .link;
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

// ---- 신원에 실린 업무 역할 ----

/// 앱에 닿은 신원(`v2.<hex>.<서명>`)의 내용을 읽는다.
fn claims_of(identity: &str) -> Value {
    let mut parts = identity.split('.');
    assert_eq!(parts.next(), Some("v2"), "{identity}");
    let hex = parts.next().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    serde_json::from_slice(&bytes).unwrap()
}

fn identity_at_app(origin: &str, cookie: &str) -> Value {
    let echo = http("GET", origin, "/echo", &[("Cookie", cookie), JSON], "");
    assert_eq!(echo.status, 200, "{}", echo.everything());
    claims_of(
        echo.json()["headers"]["x-orbital-identity"]
            .as_str()
            .unwrap(),
    )
}

#[test]
fn 업무_역할을_거두면_다음_요청의_신원에_그_역할이_없다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("payroll");
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &json!({ "email": "kim@example.com", "roles": ["employee", "payroll_admin"] }),
    );
    assert_eq!(status, 200, "{body}");
    let cookie = bench.sign_in(&live, "kim@example.com");
    let kim = Bench::me(&live, &cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims = identity_at_app(&live, &cookie);
    assert_eq!(claims["sub"], kim.as_str());
    assert_eq!(claims["roles"], json!(["employee", "payroll_admin"]));
    // 세션을 가리키는 것이 실리지만 세션의 토큰은 아니다
    let sid = claims["sid"].as_str().unwrap();
    let token = cookie.split('=').nth(1).unwrap();
    assert!(!sid.is_empty() && !token.contains(sid) && !sid.contains(token));
    // 신원은 요청 하나를 처리할 동안만 쓴다
    let lifetime = claims["exp"].as_u64().unwrap()
        - std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    assert!(lifetime <= 60, "{lifetime}");

    let (status, _) = bench.call(
        "PUT",
        &format!("/v1/instances/{instance}/users/{kim}/roles"),
        FACTORY,
        json!({ "roles": ["employee"] }).to_string().as_bytes(),
    );
    assert_eq!(status, 200);
    let claims = identity_at_app(&live, &cookie);
    assert_eq!(claims["roles"], json!(["employee"]));
    assert_eq!(claims["sid"].as_str(), Some(sid));
}

#[test]
fn 직원의_요청이_앱의_버그로_급여_관리자의_연결을_타도_행이_나오지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance("payroll");
    let token = bench.token(&instance);
    let preview = bench.preview(&instance, &token);
    let enter = |user: &str| {
        let entered = http(
            "POST",
            &preview,
            "/_orbital/preview/sign-in",
            &[
                ("Origin", preview.as_str()),
                ("Content-Type", "application/json"),
            ],
            &json!({ "user": user }).to_string(),
        );
        assert_eq!(entered.status, 302, "{}", entered.everything());
        entered.cookie("__Host-orbital-session")
    };
    let payslips = |cookie: &str, role: &str| -> Value {
        let reply = http(
            "GET",
            &preview,
            &format!("/payslips?as={role}"),
            &[("Cookie", cookie), JSON],
            "",
        );
        assert_eq!(reply.status, 200, "{}", reply.everything());
        reply.json()
    };
    let employee = enter("e1");
    assert_eq!(payslips(&employee, "employee"), json!(["e1", "e1"]));
    // 앱이 연결을 잘못 골라 급여 관리자로 붙어도 직원의 신원으로는 어떤 행도 나오지 않는다
    assert_eq!(payslips(&employee, "payroll_admin"), json!([]));
    let admin = enter("a1");
    assert_eq!(payslips(&admin, "payroll_admin"), json!(["e1", "e1", "e2"]));
    assert_eq!(payslips(&admin, "employee"), json!([]));
}

#[test]
fn 행_단위_규칙을_끈_표는_역할_제한이_걸리지_않는_표로_프리뷰에_알리고_실패로_보지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance("payroll");
    let token = bench.token(&instance);
    let (status, preview) = bench.call(
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        &[],
    );
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["findings"], json!([]));
    assert_eq!(preview["blockers"], json!([]));
    let notices = preview["notices"].as_array().unwrap();
    assert_eq!(notices.len(), 1, "{preview}");
    assert!(notices[0].as_str().unwrap().contains("payroll.calendar"));
    // 그 표는 신원 없이도 권한 표대로 읽힌다
    let url = preview["services"][0]["url"].as_str().unwrap();
    let entered = http(
        "POST",
        url,
        "/_orbital/preview/sign-in",
        &[("Origin", url), ("Content-Type", "application/json")],
        &json!({ "user": "e1" }).to_string(),
    );
    let cookie = entered.cookie("__Host-orbital-session");
    let days = http("GET", url, "/calendar", &[("Cookie", &cookie), JSON], "");
    assert_eq!(days.json(), json!(["25일"]));
}

// ---- 사용자 관리(service key) ----

/// 사용자 관리의 길 넷을 이 열쇠로 두드린다. (상태, 본문)을 차례로 돌려준다.
fn manage(bench: &Bench, instance: &str, bearer: &str, user: &str) -> Vec<(u16, Value)> {
    let base = format!("/v1/instances/{instance}/users");
    vec![
        bench.call("GET", &base, bearer, &[]),
        bench.post(
            &base,
            bearer,
            &json!({ "email": "new@example.com", "roles": ["member"] }),
        ),
        bench.call(
            "PUT",
            &format!("{base}/{user}/roles"),
            bearer,
            json!({ "roles": ["member"] }).to_string().as_bytes(),
        ),
        bench.call("DELETE", &format!("{base}/{user}"), bearer, &[]),
    ]
}

fn users(bench: &Bench, instance: &str) -> Vec<Value> {
    let (status, body) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    body["users"].as_array().unwrap().clone()
}

#[test]
fn 에이전트의_토큰으로는_사용자를_초대하거나_읽지_못한다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let kim_cookie = bench.sign_in(&live, "kim@example.com");
    let kim = Bench::me(&live, &kim_cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = bench.token(&instance);
    for (status, body) in manage(&bench, &instance, &token, &kim) {
        assert_eq!(status, 404, "{body}");
    }
    // 아무것도 바뀌지 않았다
    let listed = users(&bench, &instance);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["disabled"], false);
    assert_eq!(Bench::me(&live, &kim_cookie).status, 200);
    assert!(bench.mails_to("new@example.com").is_empty());
}

#[test]
fn 다른_팩토리의_service_key_로는_사용자가_없는_것으로_보인다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let kim_cookie = bench.sign_in(&live, "kim@example.com");
    let kim = Bench::me(&live, &kim_cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let theirs = manage(&bench, &instance, OTHER_FACTORY, &kim);
    let missing = manage(&bench, "i0000000000", OTHER_FACTORY, &kim);
    for (status, _) in &theirs {
        assert_eq!(*status, 404);
    }
    // 없는 인스턴스와 같은 답이다
    assert_eq!(theirs, missing);
    assert_eq!(Bench::me(&live, &kim_cookie).status, 200);
    assert_eq!(users(&bench, &instance).len(), 1);
}

#[test]
fn 선언에_없는_업무_역할로는_초대하지_못한다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    let path = format!("/v1/instances/{instance}/users");
    for roles in [
        json!(["admin"]),
        json!(["member", "admin"]),
        json!(["Member"]),
    ] {
        let (status, body) = bench.post(
            &path,
            FACTORY,
            &json!({ "email": "kim@example.com", "roles": roles }),
        );
        assert_eq!(status, 422, "{roles}: {body}");
        assert_eq!(body["error"], "problems");
    }
    // 초대가 남지 않았으니 링크도 만들어지지 않는다
    let asked = http(
        "POST",
        &live,
        "/_orbital/auth/email-link",
        &[("Origin", &live), ("Content-Type", "application/json")],
        &json!({ "email": "kim@example.com" }).to_string(),
    );
    assert_eq!(asked.status, 202);
    assert!(bench.mails_to("kim@example.com").is_empty());
    assert!(users(&bench, &instance).is_empty());
}

#[test]
fn 사용자_목록에는_토큰도_세션도_실리지_않는다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let session = bench.sign_in(&live, "kim@example.com");
    let link = bench.mails_to("kim@example.com").pop().unwrap().link;
    let link_token = link.split("token=").nth(1).unwrap().to_owned();
    let session_token = session.split('=').nth(1).unwrap().to_owned();

    let (status, body) = bench.call(
        "GET",
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let listed = body["users"].as_array().unwrap();
    // 초대만 받고 들어오지 않은 사람은 아직 사용자가 아니다
    assert_eq!(listed.len(), 1);
    let kim = listed[0].as_object().unwrap();
    let mut keys: Vec<&str> = kim.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "disabled",
            "email",
            "id",
            "last_signed_in_at",
            "name",
            "roles"
        ]
    );
    assert_eq!(kim["email"], "kim@example.com");
    assert_eq!(kim["roles"], json!(["member"]));
    assert!(kim["last_signed_in_at"].as_u64().is_some());
    let text = body.to_string();
    assert!(!text.contains(&session_token));
    assert!(!text.contains(&link_token));
    // 해시처럼 보이는 긴 hex 도 없다
    let longest_hex = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(longest_hex < 32, "{text}");
}

#[test]
fn 업무_역할을_바꾸면_다음_요청의_me_에_반영된다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("payroll");
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/users"),
        FACTORY,
        &json!({ "email": "kim@example.com", "roles": ["employee"] }),
    );
    assert_eq!(status, 200, "{body}");
    let cookie = bench.sign_in(&live, "kim@example.com");
    let me = Bench::me(&live, &cookie).json();
    assert_eq!(me["roles"], json!(["employee"]));
    let kim = me["id"].as_str().unwrap().to_owned();
    let roles = |roles: Value| {
        bench.call(
            "PUT",
            &format!("/v1/instances/{instance}/users/{kim}/roles"),
            FACTORY,
            json!({ "roles": roles }).to_string().as_bytes(),
        )
    };
    assert_eq!(roles(json!(["employee", "payroll_admin"])).0, 200);
    assert_eq!(
        Bench::me(&live, &cookie).json()["roles"],
        json!(["employee", "payroll_admin"])
    );
    // 선언에 없는 역할은 고칠 것으로 돌려주고, 역할은 그대로다
    assert_eq!(roles(json!(["auditor"])).0, 422);
    assert_eq!(
        Bench::me(&live, &cookie).json()["roles"],
        json!(["employee", "payroll_admin"])
    );
    assert_eq!(roles(json!([])).0, 200);
    assert_eq!(Bench::me(&live, &cookie).json()["roles"], json!([]));
    // 없는 사용자
    let (status, _) = bench.call(
        "PUT",
        &format!("/v1/instances/{instance}/users/u_aaaaaaaaaaaaaaaaaaaa/roles"),
        FACTORY,
        json!({ "roles": [] }).to_string().as_bytes(),
    );
    assert_eq!(status, 404);
}

#[test]
fn 사용자를_빼면_막히고_세션이_끊기며_목록에_막힌_것으로_보인다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("cards");
    bench.invite(&instance, "kim@example.com");
    let cookie = bench.sign_in(&live, "kim@example.com");
    let kim = Bench::me(&live, &cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = bench.call(
        "DELETE",
        &format!("/v1/instances/{instance}/users/{kim}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(Bench::me(&live, &cookie).status, 401);
    assert_eq!(users(&bench, &instance)[0]["disabled"], true);
    let (status, _) = bench.call(
        "DELETE",
        &format!("/v1/instances/{instance}/users/u_aaaaaaaaaaaaaaaaaaaa"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 404);
}

#[test]
fn 운영이_서지_않은_인스턴스의_사용자를_부르면_409_로_까닭을_알린다() {
    let mut bench = bench!();
    let instance = bench.instance("cards");
    for (status, body) in manage(&bench, &instance, FACTORY, "u_aaaaaaaaaaaaaaaaaaaa") {
        assert_eq!(status, 409, "{body}");
        assert!(body["message"].as_str().unwrap().contains("운영"), "{body}");
    }
}

// ---- MCP 의 인가(OAuth 2.1) ----
//
// 테스트가 규격대로 움직이는 클라이언트 노릇을 한다: 401 → 자원 메타데이터 → 인가 서버 메타데이터 → 등록 → 인가 → 로그인 → 동의 → 토큰 → MCP 호출 → 갱신.

const CALLBACK: &str = "http://localhost:7777/callback";
const VERIFIER: &str = "a-verifier-that-is-long-enough-for-pkce-0123456789";

/// 질의와 폼의 값을 감싼다.
fn enc(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={}", enc(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 주소의 질의에서 값 하나를 풀어 읽는다.
fn param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| {
            let bytes = value.as_bytes();
            let mut out = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                if bytes[at] == b'%' {
                    out.push(u8::from_str_radix(&value[at + 1..at + 3], 16).unwrap());
                    at += 3;
                } else {
                    out.push(bytes[at]);
                    at += 1;
                }
            }
            String::from_utf8(out).unwrap()
        })
    })
}

/// 받은 토큰 한 벌.
struct Tokens {
    access: String,
    refresh: String,
}

impl Bench {
    /// MCP 가 있는 인스턴스를 운영에 세우고 사람 하나를 초대해 들여보낸다. (인스턴스, 주소, 세션 쿠키).
    fn mcp_instance(&mut self, app: &str, email: &str) -> (String, String, String) {
        let (instance, live) = self.ship(app);
        self.invite(&instance, email);
        let cookie = self.sign_in(&live, email);
        (instance, live, cookie)
    }

    /// 동적 등록으로 클라이언트를 등록한다.
    fn register(origin: &str) -> String {
        let reply = http(
            "POST",
            origin,
            "/_orbital/oauth/register",
            &[("Content-Type", "application/json")],
            &json!({ "client_name": "테스트 클라이언트", "redirect_uris": [CALLBACK], "application_type": "native", "token_endpoint_auth_method": "none" }).to_string(),
        );
        assert_eq!(reply.status, 201, "{}", reply.everything());
        reply.json()["client_id"].as_str().unwrap().to_owned()
    }

    fn authorize(origin: &str, cookie: Option<&str>, client_id: &str, state: &str) -> Reply {
        let query = form(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", CALLBACK),
            ("code_challenge", &s256(VERIFIER)),
            ("code_challenge_method", "S256"),
            ("resource", &format!("{origin}/mcp")),
            ("scope", "mcp"),
            ("state", state),
        ]);
        let mut headers = vec![PAGE];
        if let Some(cookie) = cookie {
            headers.push(("Cookie", cookie));
        }
        http(
            "GET",
            origin,
            &format!("/_orbital/oauth/authorize?{query}"),
            &headers,
            "",
        )
    }

    /// 인가 요청을 열어 동의 화면으로 가는 요청의 식별자를 받는다.
    fn open_request(origin: &str, cookie: &str, client_id: &str) -> String {
        let reply = Self::authorize(origin, Some(cookie), client_id, "s1");
        assert_eq!(reply.status, 302, "{}", reply.everything());
        let location = reply.header("location").unwrap();
        assert!(
            location.starts_with("/oauth/consent?request="),
            "{location}"
        );
        param(location, "request").unwrap()
    }

    fn decide(origin: &str, cookie: &str, request: &str, verb: &str) -> Reply {
        http(
            "POST",
            origin,
            &format!("/_orbital/oauth/requests/{request}/{verb}"),
            &[("Origin", origin), ("Cookie", cookie)],
            "",
        )
    }

    fn token_request(origin: &str, pairs: &[(&str, &str)]) -> Reply {
        http(
            "POST",
            origin,
            "/_orbital/oauth/token",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form(pairs),
        )
    }

    fn exchange(origin: &str, client_id: &str, code: &str) -> Reply {
        Self::token_request(
            origin,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", VERIFIER),
                ("client_id", client_id),
                ("redirect_uri", CALLBACK),
                ("resource", &format!("{origin}/mcp")),
            ],
        )
    }

    fn refresh(origin: &str, client_id: &str, refresh: &str) -> Reply {
        Self::token_request(
            origin,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", client_id),
            ],
        )
    }

    /// 승인해 코드를 받는다.
    fn code(origin: &str, cookie: &str, client_id: &str) -> String {
        let request = Self::open_request(origin, cookie, client_id);
        let approved = Self::decide(origin, cookie, &request, "approve");
        assert_eq!(approved.status, 200, "{}", approved.everything());
        let redirect = approved.json()["redirect"].as_str().unwrap().to_owned();
        param(&redirect, "code").unwrap()
    }

    /// 등록부터 토큰까지 한 바퀴. (client_id, 토큰).
    fn connect(origin: &str, cookie: &str) -> (String, Tokens) {
        let client_id = Self::register(origin);
        let code = Self::code(origin, cookie, &client_id);
        let issued = Self::exchange(origin, &client_id, &code);
        assert_eq!(issued.status, 200, "{}", issued.everything());
        let body = issued.json();
        (
            client_id,
            Tokens {
                access: body["access_token"].as_str().unwrap().to_owned(),
                refresh: body["refresh_token"].as_str().unwrap().to_owned(),
            },
        )
    }

    fn mcp(origin: &str, access: &str) -> Reply {
        http(
            "POST",
            origin,
            "/mcp",
            &[
                ("Authorization", &format!("Bearer {access}")),
                ("Content-Type", "application/json"),
            ],
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        )
    }

    fn superuser_rows(&self, instance: &str, sql: &str) -> Vec<String> {
        let mut config: postgres::Config = self.pg_url.parse().unwrap();
        let mut client = config
            .dbname(&format!("i_{instance}"))
            .connect(postgres::NoTls)
            .unwrap();
        client
            .query(sql, &[])
            .unwrap()
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
    }
}

#[test]
fn 토큰_없이_mcp_주소에_오면_401_과_함께_인가_서버의_자리를_알려_준다() {
    let mut bench = bench!();
    let (_, live) = bench.ship("mcp");
    let bare = http("POST", &live, "/mcp", &[JSON], "{}");
    assert_eq!(bare.status, 401, "{}", bare.everything());
    let challenge = bare.header("www-authenticate").unwrap().to_owned();
    let metadata_url = format!("{live}/.well-known/oauth-protected-resource/mcp");
    assert_eq!(
        challenge,
        format!("Bearer resource_metadata=\"{metadata_url}\", scope=\"mcp\"")
    );
    for path in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    ] {
        let metadata = http("GET", &live, path, &[JSON], "");
        assert_eq!(metadata.status, 200, "{path}");
        assert_eq!(
            metadata.json(),
            json!({
                "resource": format!("{live}/mcp"),
                "authorization_servers": [live],
                "scopes_supported": ["mcp"],
                "bearer_methods_supported": ["header"],
            }),
            "{path}"
        );
    }
    // 토큰이 있는데 틀렸으면 그렇다고 알린다
    let wrong = http(
        "POST",
        &live,
        "/mcp",
        &[("Authorization", "Bearer abc"), JSON],
        "{}",
    );
    assert_eq!(wrong.status, 401);
    assert!(
        wrong
            .header("www-authenticate")
            .unwrap()
            .contains("error=\"invalid_token\"")
    );
}

#[test]
fn 인가_서버의_metadata_는_규격이_요구하는_칸을_모두_싣는다() {
    let mut bench = bench!();
    let (_, live) = bench.ship("mcp");
    let metadata = http(
        "GET",
        &live,
        "/.well-known/oauth-authorization-server",
        &[JSON],
        "",
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(
        metadata.json(),
        json!({
            "issuer": live,
            "authorization_endpoint": format!("{live}/_orbital/oauth/authorize"),
            "token_endpoint": format!("{live}/_orbital/oauth/token"),
            "registration_endpoint": format!("{live}/_orbital/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": true,
        })
    );
}

#[test]
fn 사용자가_승인하지_않으면_코드가_나오지_않는다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let client_id = Bench::register(&live);
    let request = Bench::open_request(&live, &cookie, &client_id);
    let denied = Bench::decide(&live, &cookie, &request, "deny");
    assert_eq!(denied.status, 200, "{}", denied.everything());
    let redirect = denied.json()["redirect"].as_str().unwrap().to_owned();
    assert!(redirect.starts_with(CALLBACK), "{redirect}");
    assert_eq!(param(&redirect, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&redirect, "state").as_deref(), Some("s1"));
    assert_eq!(param(&redirect, "iss").as_deref(), Some(live.as_str()));
    assert_eq!(param(&redirect, "code"), None);
    // 정한 요청은 다시 정하지 못한다
    assert_eq!(
        Bench::decide(&live, &cookie, &request, "approve").status,
        404
    );
    let codes = bench.superuser_rows(
        &instance,
        "SELECT count(*)::text FROM orbital_auth.oauth_code",
    );
    assert_eq!(codes, vec!["0"]);
}

#[test]
fn 승인은_그_요청을_연_사용자의_세션에서만_받는다() {
    let mut bench = bench!();
    let (instance, live, kim) = bench.mcp_instance("mcp", "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let lee = bench.sign_in(&live, "lee@example.com");
    let client_id = Bench::register(&live);

    // 세션이 없으면 로그인 화면으로 보낸다. 돌아올 곳은 이 인가 요청이다
    let anonymous = Bench::authorize(&live, None, &client_id, "s1");
    assert_eq!(anonymous.status, 302);
    let location = anonymous.header("location").unwrap();
    assert!(location.starts_with("/login?next="), "{location}");
    assert!(
        param(location, "next")
            .unwrap()
            .starts_with("/_orbital/oauth/authorize?")
    );

    let request = Bench::open_request(&live, &kim, &client_id);
    let seen = http(
        "GET",
        &live,
        &format!("/_orbital/oauth/requests/{request}"),
        &[("Cookie", &kim), JSON],
        "",
    );
    assert_eq!(seen.status, 200, "{}", seen.everything());
    assert_eq!(seen.json()["client"]["id"], client_id.as_str());
    assert_eq!(seen.json()["client"]["name"], "테스트 클라이언트");
    assert_eq!(seen.json()["client"]["redirect_host"], "localhost:7777");
    assert_eq!(seen.json()["scopes"], json!(["mcp"]));
    assert_eq!(seen.json()["resource"], format!("{live}/mcp"));
    // 남의 요청과 없는 요청은 같은 404 다
    let theirs = http(
        "GET",
        &live,
        &format!("/_orbital/oauth/requests/{request}"),
        &[("Cookie", &lee), JSON],
        "",
    );
    let missing = http(
        "GET",
        &live,
        &format!("/_orbital/oauth/requests/{}", "0".repeat(64)),
        &[("Cookie", &lee), JSON],
        "",
    );
    assert_eq!((theirs.status, &theirs.body), (404, &missing.body));
    assert_eq!(Bench::decide(&live, &lee, &request, "approve").status, 404);
    assert_eq!(
        Bench::decide(&live, "theme=dark", &request, "approve").status,
        404
    );
    // Origin 이 다르면 받지 않는다
    let elsewhere = http(
        "POST",
        &live,
        &format!("/_orbital/oauth/requests/{request}/approve"),
        &[("Origin", "http://evil.example"), ("Cookie", &kim)],
        "",
    );
    assert_eq!(elsewhere.status, 403);
    // 연 사람은 승인한다
    let approved = Bench::decide(&live, &kim, &request, "approve");
    assert_eq!(approved.status, 200);
    let redirect = approved.json()["redirect"].as_str().unwrap().to_owned();
    assert!(param(&redirect, "code").is_some());
    assert_eq!(param(&redirect, "state").as_deref(), Some("s1"));
    assert_eq!(param(&redirect, "iss").as_deref(), Some(live.as_str()));
}

#[test]
fn 한_번_쓴_코드를_다시_쓰면_그_코드로_낸_토큰이_모두_거둬진다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let client_id = Bench::register(&live);
    let code = Bench::code(&live, &cookie, &client_id);
    let first = Bench::exchange(&live, &client_id, &code);
    assert_eq!(first.status, 200, "{}", first.everything());
    assert_eq!(first.header("cache-control"), Some("no-store"));
    let body = first.json();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["scope"], "mcp");
    let access = body["access_token"].as_str().unwrap().to_owned();
    let refresh = body["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(Bench::mcp(&live, &access).status, 200);

    let again = Bench::exchange(&live, &client_id, &code);
    assert_eq!(again.status, 400);
    assert_eq!(again.json()["error"], "invalid_grant");
    assert_eq!(Bench::mcp(&live, &access).status, 401);
    assert_eq!(
        Bench::refresh(&live, &client_id, &refresh).json()["error"],
        "invalid_grant"
    );
}

#[test]
fn refresh_토큰은_쓸_때마다_바뀌고_쓴_것을_다시_쓰면_그_승인_전체가_거둬진다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let (client_id, first) = Bench::connect(&live, &cookie);
    let renewed = Bench::refresh(&live, &client_id, &first.refresh);
    assert_eq!(renewed.status, 200, "{}", renewed.everything());
    let second = Tokens {
        access: renewed.json()["access_token"].as_str().unwrap().to_owned(),
        refresh: renewed.json()["refresh_token"].as_str().unwrap().to_owned(),
    };
    assert_ne!(second.refresh, first.refresh);
    assert_ne!(second.access, first.access);
    assert_eq!(Bench::mcp(&live, &second.access).status, 200);
    // 다른 클라이언트로는 갈지 못한다
    let other = Bench::register(&live);
    assert_eq!(
        Bench::refresh(&live, &other, &second.refresh).json()["error"],
        "invalid_grant"
    );

    // 쓴 refresh 토큰이 다시 왔다: 훔쳐 간 쪽이 있다고 보고 승인 전체를 거둔다
    let replay = Bench::refresh(&live, &client_id, &first.refresh);
    assert_eq!(replay.status, 400);
    assert_eq!(replay.json()["error"], "invalid_grant");
    assert_eq!(Bench::mcp(&live, &second.access).status, 401);
    assert_eq!(
        Bench::refresh(&live, &client_id, &second.refresh).json()["error"],
        "invalid_grant"
    );
}

#[test]
fn access_토큰과_refresh_토큰은_해시로만_저장된다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let (_, tokens) = Bench::connect(&live, &cookie);
    for table in [
        "oauth_token",
        "oauth_code",
        "oauth_request",
        "oauth_grant",
        "oauth_client",
    ] {
        for row in bench.superuser_rows(
            &instance,
            &format!("SELECT t::text FROM orbital_auth.{table} t"),
        ) {
            assert!(!row.contains(&tokens.access), "{table}");
            assert!(!row.contains(&tokens.refresh), "{table}");
        }
    }
    // 저장된 해시를 그대로 토큰으로 내밀어도 들어가지 못한다
    for stored in bench.superuser_rows(
        &instance,
        "SELECT encode(token_hash, 'hex') FROM orbital_auth.oauth_token",
    ) {
        assert_eq!(Bench::mcp(&live, &stored).status, 401);
    }
    assert_eq!(Bench::mcp(&live, &tokens.access).status, 200);
}

#[test]
fn 다른_인스턴스용으로_낸_토큰은_받지_않는다() {
    let mut bench = bench!();
    let (_, ours, our_cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let (_, theirs, _) = bench.mcp_instance("mcp", "kim@example.com");
    let (client_id, tokens) = Bench::connect(&ours, &our_cookie);
    assert_eq!(Bench::mcp(&ours, &tokens.access).status, 200);
    assert_eq!(Bench::mcp(&theirs, &tokens.access).status, 401);
    assert_eq!(
        Bench::refresh(&theirs, &client_id, &tokens.refresh).status,
        400
    );
    // 다른 인스턴스의 MCP 주소를 대상으로 인가를 받으려 해도 받지 않는다
    let query = form(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", CALLBACK),
        ("code_challenge", &s256(VERIFIER)),
        ("code_challenge_method", "S256"),
        ("resource", &format!("{theirs}/mcp")),
        ("state", "s1"),
    ]);
    let asked = http(
        "GET",
        &ours,
        &format!("/_orbital/oauth/authorize?{query}"),
        &[("Cookie", &our_cookie)],
        "",
    );
    assert_eq!(asked.status, 302);
    assert_eq!(
        param(asked.header("location").unwrap(), "error").as_deref(),
        Some("invalid_target")
    );
}

#[test]
fn mcp_요청은_그_사용자의_신원으로_앱에_닿고_authorization_머리말은_앱에_닿지_않는다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let kim = Bench::me(&live, &cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (client_id, tokens) = Bench::connect(&live, &cookie);
    let reply = Bench::mcp(&live, &tokens.access);
    assert_eq!(reply.status, 200, "{}", reply.everything());
    let headers = &reply.json()["headers"];
    assert_eq!(headers["authorization"], Value::Null);
    assert!(!reply.body.contains(&tokens.access));
    let claims = claims_of(headers["x-orbital-identity"].as_str().unwrap());
    assert_eq!(claims["sub"], kim.as_str());
    assert_eq!(claims["cid"], client_id.as_str());
    assert_eq!(claims["roles"], json!(["member"]));
}

#[test]
fn mcp_로_들어온_사용자도_자기_행만_본다() {
    let mut bench = bench!();
    let (instance, live, kim) = bench.mcp_instance("mcp", "kim@example.com");
    bench.invite(&instance, "lee@example.com");
    let lee = bench.sign_in(&live, "lee@example.com");
    for (cookie, title) in [(&kim, "김의 일"), (&lee, "이의 일")] {
        let made = http("POST", &live, "/cards", &[("Cookie", cookie), JSON], title);
        assert_eq!(made.status, 201, "{}", made.everything());
    }
    let (_, tokens) = Bench::connect(&live, &kim);
    let reply = Bench::mcp(&live, &tokens.access);
    let body = reply.json();
    let titles: Vec<&str> = body["cards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|card| card["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["김의 일"]);
}

#[test]
fn mcp_주소는_세션_쿠키로는_열리지_않는다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let with_cookie = http("POST", &live, "/mcp", &[("Cookie", &cookie), JSON], "{}");
    assert_eq!(with_cookie.status, 401);
    assert!(
        with_cookie
            .header("www-authenticate")
            .unwrap()
            .starts_with("Bearer resource_metadata=")
    );
    // 같은 앱의 다른 경로는 쿠키로 열린다
    assert_eq!(Bench::cards(&live, &cookie).status, 200);
}

#[test]
fn 사용자가_승인을_거두면_그_클라이언트의_토큰이_다음_요청부터_끊긴다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let (client_id, tokens) = Bench::connect(&live, &cookie);
    let grants = http(
        "GET",
        &live,
        "/_orbital/oauth/grants",
        &[("Cookie", &cookie), JSON],
        "",
    );
    assert_eq!(grants.status, 200, "{}", grants.everything());
    let listed = grants.json()["grants"].as_array().unwrap().clone();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["client"]["id"], client_id.as_str());
    let grant = listed[0]["id"].as_str().unwrap().to_owned();
    // Origin 이 없으면 받지 않는다
    let refused = http(
        "DELETE",
        &live,
        &format!("/_orbital/oauth/grants/{grant}"),
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(refused.status, 403);
    assert_eq!(Bench::mcp(&live, &tokens.access).status, 200);
    let revoked = http(
        "DELETE",
        &live,
        &format!("/_orbital/oauth/grants/{grant}"),
        &[("Origin", &live), ("Cookie", &cookie)],
        "",
    );
    assert_eq!(revoked.status, 204);
    assert_eq!(Bench::mcp(&live, &tokens.access).status, 401);
    assert_eq!(
        Bench::refresh(&live, &client_id, &tokens.refresh).json()["error"],
        "invalid_grant"
    );
    let after = http(
        "GET",
        &live,
        "/_orbital/oauth/grants",
        &[("Cookie", &cookie), JSON],
        "",
    );
    assert_eq!(after.json()["grants"], json!([]));
}

#[test]
fn 사용자를_빼면_그_사용자의_토큰이_모두_끊긴다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let kim = Bench::me(&live, &cookie).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (client_id, tokens) = Bench::connect(&live, &cookie);
    let (_, more) = Bench::connect(&live, &cookie);
    let (status, _) = bench.call(
        "DELETE",
        &format!("/v1/instances/{instance}/users/{kim}"),
        FACTORY,
        &[],
    );
    assert_eq!(status, 200);
    for access in [&tokens.access, &more.access] {
        assert_eq!(Bench::mcp(&live, access).status, 401);
    }
    assert_eq!(
        Bench::refresh(&live, &client_id, &tokens.refresh).json()["error"],
        "invalid_grant"
    );
}

#[test]
fn 동적_등록을_끈_인스턴스에는_등록_주소가_없고_metadata_에도_나오지_않는다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcpclosed", "kim@example.com");
    let metadata = http(
        "GET",
        &live,
        "/.well-known/oauth-authorization-server",
        &[JSON],
        "",
    )
    .json();
    assert_eq!(metadata["registration_endpoint"], Value::Null);
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    let register = http(
        "POST",
        &live,
        "/_orbital/oauth/register",
        &[("Content-Type", "application/json")],
        &json!({ "client_name": "x", "redirect_uris": [CALLBACK] }).to_string(),
    );
    assert_eq!(register.status, 404);
    // 팩토리가 미리 등록한 클라이언트로는 들어온다
    let (status, body) = bench.post(
        &format!("/v1/instances/{instance}/oauth-clients"),
        FACTORY,
        &json!({ "name": "팩토리의 앱", "redirect_uris": [CALLBACK] }),
    );
    assert_eq!(status, 200, "{body}");
    let client_id = body["client_id"].as_str().unwrap().to_owned();
    let code = Bench::code(&live, &cookie, &client_id);
    assert_eq!(Bench::exchange(&live, &client_id, &code).status, 200);
    // 미리 등록할 때도 redirect 는 https 이거나 localhost 여야 한다
    let (status, _) = bench.post(
        &format!("/v1/instances/{instance}/oauth-clients"),
        FACTORY,
        &json!({ "name": "x", "redirect_uris": ["http://client.example/cb"] }),
    );
    assert_eq!(status, 422);
    // 에이전트의 토큰에는 이 길이 없다
    let token = bench.token(&instance);
    assert_eq!(
        bench
            .post(
                &format!("/v1/instances/{instance}/oauth-clients"),
                &token,
                &json!({ "name": "x", "redirect_uris": [CALLBACK] })
            )
            .0,
        404
    );
}

#[test]
fn metadata_문서로_자신을_밝힌_클라이언트가_등록_없이_인가를_받는다() {
    let mut bench = bench!();
    let (_, live, cookie) = bench.mcp_instance("mcpclosed", "kim@example.com");
    let url = "https://client.example/oauth/client.json";
    bench.documents.put(
        url,
        &json!({ "client_id": url, "client_name": "문서로 밝힌 클라이언트", "redirect_uris": [CALLBACK] }),
    );
    let request = Bench::open_request(&live, &cookie, url);
    let seen = http(
        "GET",
        &live,
        &format!("/_orbital/oauth/requests/{request}"),
        &[("Cookie", &cookie), JSON],
        "",
    );
    assert_eq!(seen.json()["client"]["name"], "문서로 밝힌 클라이언트");
    let approved = Bench::decide(&live, &cookie, &request, "approve");
    let code = param(approved.json()["redirect"].as_str().unwrap(), "code").unwrap();
    let issued = Bench::exchange(&live, url, &code);
    assert_eq!(issued.status, 200, "{}", issued.everything());
    let access = issued.json()["access_token"].as_str().unwrap().to_owned();
    assert_eq!(Bench::mcp(&live, &access).status, 200);
    // 기억하는 동안에는 다시 와도 문서를 또 받아 오지 않는다
    Bench::open_request(&live, &cookie, url);
    assert_eq!(bench.documents.asked.lock().unwrap().len(), 1);

    // 문서의 식별자가 받아 온 주소와 다르면, 그 문서의 redirect 로 보내지 않고 여기서 멈춘다
    let liar = "https://liar.example/client.json";
    bench.documents.put(
        liar,
        &json!({ "client_id": "https://client.example/oauth/client.json", "client_name": "거짓말", "redirect_uris": [CALLBACK] }),
    );
    let refused = Bench::authorize(&live, Some(&cookie), liar, "s1");
    assert_eq!(refused.status, 400, "{}", refused.everything());
    assert_eq!(refused.header("location"), None);
    // 사설 주소의 문서는 받아 오지도 않는다
    let private = Bench::authorize(&live, Some(&cookie), "https://10.0.0.5/client.json", "s1");
    assert_eq!(private.status, 400);
    assert!(
        !bench
            .documents
            .asked
            .lock()
            .unwrap()
            .iter()
            .any(|asked| asked.contains("10.0.0.5"))
    );
}

fn register_raw(origin: &str) -> Reply {
    http(
        "POST",
        origin,
        "/_orbital/oauth/register",
        &[("Content-Type", "application/json")],
        &json!({ "client_name": "테스트 클라이언트", "redirect_uris": [CALLBACK] }).to_string(),
    )
}

#[test]
fn 동적_등록은_1분에_열_번까지_받고_그_뒤로는_429_다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("mcp");
    for round in 0..10 {
        assert_eq!(register_raw(&live).status, 201, "{round}");
    }
    let refused = register_raw(&live);
    assert_eq!(refused.status, 429, "{}", refused.everything());
    let wait: u64 = refused.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(
        bench.superuser_rows(
            &instance,
            "SELECT count(*)::text FROM orbital_auth.oauth_client"
        ),
        vec!["10"]
    );
    // 1분이 지나면 다시 받는다
    bench.superuser_rows(
        &instance,
        "UPDATE orbital_auth.oauth_client SET created_at = created_at - interval '2 minutes' RETURNING id",
    );
    assert_eq!(register_raw(&live).status, 201);
}

#[test]
fn 한_번도_승인받지_못한_동적_클라이언트는_하루_뒤에_지워진다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcp", "kim@example.com");
    let approved = Bench::register(&live);
    Bench::code(&live, &cookie, &approved);
    let forgotten = Bench::register(&live);
    let fresh = Bench::register(&live);
    // 승인받은 것과 못 받은 것을 이틀 앞으로 당기고, 하나는 그대로 둔다
    bench.superuser_rows(
        &instance,
        &format!(
            "UPDATE orbital_auth.oauth_client SET created_at = created_at - interval '2 days' \
             WHERE id IN ('{approved}', '{forgotten}') RETURNING id"
        ),
    );
    // 다음 등록이 치운다
    Bench::register(&live);
    let left = bench.superuser_rows(
        &instance,
        "SELECT id FROM orbital_auth.oauth_client ORDER BY id",
    );
    assert!(left.contains(&approved), "{left:?}");
    assert!(left.contains(&fresh), "{left:?}");
    assert!(!left.contains(&forgotten), "{left:?}");
}

#[test]
fn mcp_를_선언하지_않은_인스턴스에는_인가_서버의_주소가_없다() {
    let mut bench = bench!();
    let (_, live) = bench.ship("cards");
    for (method, path) in [
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
        ("GET", "/_orbital/oauth/authorize?response_type=code"),
        ("POST", "/_orbital/oauth/token"),
        ("POST", "/_orbital/oauth/register"),
        ("GET", "/_orbital/oauth/grants"),
    ] {
        let reply = http(method, &live, path, &[JSON], "");
        assert_eq!(reply.status, 404, "{method} {path}: {}", reply.everything());
    }
}

// ---- 다른 주소의 브라우저(CORS) ----

const ELSEWHERE: &str = "https://inspector.example";

fn preflight(origin: &str, path: &str, method: &str) -> Reply {
    http(
        "OPTIONS",
        origin,
        path,
        &[
            ("Origin", ELSEWHERE),
            ("Access-Control-Request-Method", method),
            ("Access-Control-Request-Headers", "content-type"),
        ],
        "",
    )
}

#[test]
fn 메타데이터와_토큰과_등록의_주소는_다른_주소의_브라우저에서_부를_수_있다() {
    let mut bench = bench!();
    let (_, live) = bench.ship("mcp");
    let open = [
        ("/.well-known/oauth-authorization-server", "GET"),
        ("/.well-known/oauth-protected-resource/mcp", "GET"),
        ("/_orbital/oauth/token", "POST"),
        ("/_orbital/oauth/register", "POST"),
    ];
    for (path, method) in open {
        let answer = preflight(&live, path, method);
        assert_eq!(answer.status, 204, "{path} {}", answer.everything());
        assert_eq!(
            answer.header("access-control-allow-origin"),
            Some("*"),
            "{path}"
        );
        let methods = answer
            .header("access-control-allow-methods")
            .unwrap_or_default();
        assert!(methods.contains(method), "{path} {methods}");
        let headers = answer
            .header("access-control-allow-headers")
            .unwrap_or_default();
        assert!(
            headers.to_ascii_lowercase().contains("content-type"),
            "{path} {headers}"
        );
        // 쿠키를 싣는 요청은 열지 않는다
        assert_eq!(
            answer.header("access-control-allow-credentials"),
            None,
            "{path}"
        );
    }
    // 실제 답에도 붙는다
    let metadata = http(
        "GET",
        &live,
        "/.well-known/oauth-authorization-server",
        &[("Origin", ELSEWHERE)],
        "",
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.header("access-control-allow-origin"), Some("*"));
    let registered = http(
        "POST",
        &live,
        "/_orbital/oauth/register",
        &[("Origin", ELSEWHERE), ("Content-Type", "application/json")],
        &json!({ "client_name": "검사기", "redirect_uris": [CALLBACK] }).to_string(),
    );
    assert_eq!(registered.status, 201, "{}", registered.everything());
    assert_eq!(registered.header("access-control-allow-origin"), Some("*"));
    let refused = http(
        "POST",
        &live,
        "/_orbital/oauth/token",
        &[
            ("Origin", ELSEWHERE),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        "grant_type=authorization_code&code=nothing",
    );
    assert_eq!(refused.status, 400, "{}", refused.everything());
    assert_eq!(refused.header("access-control-allow-origin"), Some("*"));
    assert_eq!(refused.header("access-control-allow-credentials"), None);
}

#[test]
fn 쿠키를_쓰는_주소는_다른_주소의_브라우저에_열리지_않는다() {
    let mut bench = bench!();
    let (instance, live) = bench.ship("mcp");
    bench.invite(&instance, "ana@example.com");
    let cookie = bench.sign_in(&live, "ana@example.com");
    let closed = [
        ("/_orbital/auth/me", "GET"),
        ("/_orbital/auth/email-link", "POST"),
        ("/_orbital/auth/logout", "POST"),
        ("/_orbital/auth/callback", "GET"),
        ("/_orbital/oauth/authorize", "GET"),
        ("/_orbital/oauth/requests/r_x", "GET"),
        ("/_orbital/oauth/requests/r_x/approve", "POST"),
        ("/_orbital/oauth/grants", "GET"),
        ("/_orbital/oauth/grants/g_x", "DELETE"),
    ];
    for (path, method) in closed {
        let answer = preflight(&live, path, method);
        assert_ne!(answer.status, 204, "{path}");
        assert_eq!(answer.header("access-control-allow-origin"), None, "{path}");
        assert_eq!(
            answer.header("access-control-allow-credentials"),
            None,
            "{path}"
        );
    }
    let me = http(
        "GET",
        &live,
        "/_orbital/auth/me",
        &[("Origin", ELSEWHERE), ("Cookie", &cookie)],
        "",
    );
    assert_eq!(me.status, 200, "{}", me.everything());
    assert_eq!(me.header("access-control-allow-origin"), None);
    let grants = http(
        "GET",
        &live,
        "/_orbital/oauth/grants",
        &[("Origin", ELSEWHERE), ("Cookie", &cookie)],
        "",
    );
    assert_eq!(grants.header("access-control-allow-origin"), None);
}

// ---- metadata 문서를 기억하는 길이 ----

#[test]
fn metadata_문서를_기억하는_길이는_받아_온_답의_cache_control_을_따른다() {
    let mut bench = bench!();
    let (instance, live, cookie) = bench.mcp_instance("mcpclosed", "kim@example.com");
    let remembered = |bench: &Bench, url: &str| -> i64 {
        bench.superuser_rows(
            &instance,
            &format!(
                "SELECT round(extract(epoch FROM fresh_until - now()))::bigint::text \
                 FROM orbital_auth.oauth_client WHERE id = '{url}'"
            ),
        )[0]
        .parse()
        .unwrap()
    };
    let cases = [
        ("https://a.example/client.json", Some("max-age=600"), 600),
        ("https://b.example/client.json", Some("max-age=10"), 300),
        (
            "https://c.example/client.json",
            Some("max-age=31536000"),
            86_400,
        ),
        ("https://d.example/client.json", None, 300),
    ];
    for (url, cache_control, expected) in cases {
        bench.documents.put_cached(
            url,
            &json!({ "client_id": url, "client_name": "문서", "redirect_uris": [CALLBACK] }),
            cache_control,
        );
        Bench::open_request(&live, &cookie, url);
        let seconds = remembered(&bench, url);
        assert!(
            (expected - 5..=expected).contains(&seconds),
            "{url} {seconds}"
        );
    }
    // 기억이 지나면 다시 받아 온다
    let url = "https://a.example/client.json";
    let before = bench.documents.asked.lock().unwrap().len();
    Bench::open_request(&live, &cookie, url);
    assert_eq!(bench.documents.asked.lock().unwrap().len(), before);
    bench.superuser_rows(
        &instance,
        &format!(
            "UPDATE orbital_auth.oauth_client SET fresh_until = now() - interval '1 second' \
             WHERE id = '{url}' RETURNING id"
        ),
    );
    Bench::open_request(&live, &cookie, url);
    assert_eq!(bench.documents.asked.lock().unwrap().len(), before + 1);
    assert!(remembered(&bench, url) > 500);
}
