//! 메일과 Google 로그인은 팩토리가 넣은 키로 한다. 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않는다.
//!
//! 실제 PostgreSQL, 실제 git, 실제 앱 프로세스, 실제 HTTP 로 잰다. Resend 와 Google 은 이 테스트가 세운 가짜 서버다(실제 `api.resend.com` 과
//! Google 은 부르지 않는다). 가짜 Resend 는 받은 요청을 적어 두고, 가짜 Google 의 토큰 주소는 테스트가 미리 적은 `id_token` 을 돌려준다.
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use orbital_core::google::{Stage, StateClaims};
use orbital_router::Outbox;
use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, OUTBOX, Options, SETTINGS};
use orbital_server::login::Endpoints;
use orbital_server::seal::SealKey;
use orbital_server::token::{hex, sign_state};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";
const OTHER_FACTORY: &str = "sk_test_other";
const PUBLIC_URL: &str = "https://layer.example";
const AUTHORIZE: &str = "https://accounts.google.test/o/oauth2/v2/auth";
const SEAL: [u8; 32] = [7; 32];

const MAIL_KEY: &str = "re_factory_secret_0001";
const OTHER_MAIL_KEY: &str = "re_other_secret_0002";
const CLIENT_ID: &str = "factory-client.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "GOCSPX-factory-secret-0003";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// 폴더 아래 모든 파일의 글을 이어 붙인다. 값이 어디에도 없는지 볼 때 쓴다.
fn everything_under(folder: &Path) -> String {
    let mut text = String::new();
    let Ok(entries) = fs::read_dir(folder) else {
        return text;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // 빌드 결과와 코드 저장소는 앱의 것이다
            if !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("builds" | "sources" | "apps")
            ) {
                text.push_str(&everything_under(&path));
            }
        } else {
            text.push_str(&String::from_utf8_lossy(
                &fs::read(&path).unwrap_or_default(),
            ));
            text.push('\n');
        }
    }
    text
}

// ---- 손으로 짠 HTTP ----

struct Reply {
    status: u16,
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

    fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .map(|(_, value)| value.as_str())
            .find(|value| value.starts_with(&format!("{name}=")))
            .and_then(|cookie| cookie.split(';').next())
            .map(str::to_owned)
    }

    fn cookie(&self, name: &str) -> String {
        self.set_cookie(name)
            .unwrap_or_else(|| panic!("`{name}` 쿠키가 없습니다: {}", self.everything()))
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
    if headers.iter().any(|(key, value): &(String, String)| {
        key == "transfer-encoding" && value.contains("chunked")
    }) {
        body = dechunk(&body);
    }
    let body = String::from_utf8_lossy(&body).to_string();
    Reply {
        status,
        headers,
        body,
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

const JSON: (&str, &str) = ("Accept", "application/json");

/// 주소의 질의에서 값 하나를 풀어 꺼낸다.
fn param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    orbital_core::auth::query_value(query, name)
}

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

// ---- 가짜 Resend 와 가짜 Google ----

/// 가짜 Resend 가 받은 한 통.
#[derive(Debug, Clone)]
struct Sent {
    authorization: String,
    user_agent: Option<String>,
    idempotency: Option<String>,
    body: Value,
}

#[derive(Default)]
struct FakeResend {
    sent: Mutex<Vec<Sent>>,
    /// 돌려줄 상태. 기본은 200 이다.
    status: Mutex<u16>,
}

#[derive(Default)]
struct FakeGoogle {
    /// code 마다 돌려줄 `id_token` 의 몸.
    codes: Mutex<BTreeMap<String, Value>>,
    /// 토큰 주소가 받은 요청(폼).
    asked: Mutex<Vec<BTreeMap<String, String>>>,
}

fn header_of(request: &tiny_http::Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str().to_owned())
}

fn reply(request: tiny_http::Request, status: u16, body: &Value) {
    let header = tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap();
    let _ = request.respond(
        tiny_http::Response::from_string(body.to_string())
            .with_status_code(status)
            .with_header(header),
    );
}

fn serve_resend(fake: Arc<FakeResend>) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let mut text = String::new();
            let _ = request.as_reader().read_to_string(&mut text);
            if request.url() != "/emails" || request.method() != &tiny_http::Method::Post {
                reply(request, 404, &json!({ "name": "not_found" }));
                continue;
            }
            fake.sent.lock().unwrap().push(Sent {
                authorization: header_of(&request, "authorization").unwrap_or_default(),
                user_agent: header_of(&request, "user-agent"),
                idempotency: header_of(&request, "idempotency-key"),
                body: serde_json::from_str(&text).unwrap_or(Value::Null),
            });
            let status = *fake.status.lock().unwrap();
            if status == 200 {
                reply(
                    request,
                    200,
                    &json!({ "id": "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794" }),
                );
            } else {
                // Resend 의 오류는 받는 주소를 되풀이할 수 있다. 레이어가 이 본문을 어디에도 싣지 않는지 본다
                reply(
                    request,
                    status,
                    &json!({ "statusCode": status, "name": "validation_error", "message": format!("bad key {MAIL_KEY}") }),
                );
            }
        }
    });
    url
}

fn serve_google(fake: Arc<FakeGoogle>) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/token", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let mut text = String::new();
            let _ = request.as_reader().read_to_string(&mut text);
            let form: BTreeMap<String, String> = text
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .filter_map(|(key, value)| {
                    Some((
                        key.to_owned(),
                        orbital_core::auth::query_value(&format!("v={value}"), "v")?,
                    ))
                })
                .collect();
            fake.asked.lock().unwrap().push(form.clone());
            let claims = form
                .get("code")
                .and_then(|code| fake.codes.lock().unwrap().get(code).cloned());
            let ours = form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET);
            match claims {
                Some(claims) if ours => {
                    let part = |value: &Value| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
                    };
                    let id_token = format!(
                        "{}.{}.c2lnbmF0dXJl",
                        part(&json!({ "alg": "RS256", "kid": "k1" })),
                        part(&claims)
                    );
                    reply(
                        request,
                        200,
                        &json!({ "access_token": "ya29.x", "expires_in": 3599, "token_type": "Bearer", "id_token": id_token }),
                    );
                }
                _ => reply(request, 400, &json!({ "error": "invalid_grant" })),
            }
        }
    });
    url
}

// ---- 레이어 ----

struct Bench {
    home: PathBuf,
    scratch: PathBuf,
    pg_url: String,
    layer: Layer,
    resend: Arc<FakeResend>,
    google: Arc<FakeGoogle>,
    endpoints: Endpoints,
    instances: Vec<(String, &'static str)>,
}

impl Bench {
    fn new(dev_mailbox: bool) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-keys-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&scratch).unwrap();
        let home = scratch.join("home");
        let resend = Arc::new(FakeResend::default());
        *resend.status.lock().unwrap() = 200;
        let google = Arc::new(FakeGoogle::default());
        let endpoints = Endpoints {
            resend: serve_resend(Arc::clone(&resend)),
            google_authorize: AUTHORIZE.to_owned(),
            google_token: serve_google(Arc::clone(&google)),
        };
        let layer = Self::open(
            &home,
            &pg_url,
            Some(SealKey::from_bytes(SEAL)),
            dev_mailbox,
            &endpoints,
        );
        let bench = Self {
            home,
            scratch,
            pg_url,
            layer,
            resend,
            google,
            endpoints,
            instances: Vec::new(),
        };
        for key in [FACTORY, OTHER_FACTORY] {
            bench.upload(key, "cards", &|folder: &Path| {
                copy_tree(&fixture("todo"), folder);
                copy_tree(&fixture("cards"), folder);
            });
            bench.upload(key, "gcards", &|folder: &Path| {
                copy_tree(&fixture("todo"), folder);
                copy_tree(&fixture("cards"), folder);
                let manifest = fs::read_to_string(folder.join("orbital.toml")).unwrap();
                fs::write(
                    folder.join("orbital.toml"),
                    manifest.replace(
                        "methods = [\"email_link\"]",
                        "methods = [\"email_link\", \"google\"]",
                    ),
                )
                .unwrap();
            });
        }
        Some(bench)
    }

    fn open(
        home: &Path,
        pg_url: &str,
        seal_key: Option<SealKey>,
        dev_mailbox: bool,
        endpoints: &Endpoints,
    ) -> Layer {
        Layer::open(Options {
            seal_key,
            public_url: PUBLIC_URL.to_owned(),
            dev_mailbox,
            endpoints: endpoints.clone(),
            ..Options::new(
                home.to_path_buf(),
                pg_url.to_owned(),
                vec![
                    (FACTORY.to_owned(), "factory".to_owned()),
                    (OTHER_FACTORY.to_owned(), "other".to_owned()),
                ],
                Box::new(LocalRunner::default()),
            )
        })
        .expect("레이어를 열지 못했습니다")
    }

    fn upload(&self, key: &str, app: &str, prepare: &dyn Fn(&Path)) {
        let folder = self.scratch.join(format!("scaffold-{key}-{app}"));
        prepare(&folder);
        git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
        git(&folder, &["add", "-A"]);
        git(&folder, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&folder, &["tag", "v1"]);
        let bundle = self.scratch.join(format!("{key}-{app}.bundle"));
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

    fn put_settings(&self, key: &str, body: &Value) -> (u16, Value) {
        self.call("PUT", "/v1/settings/auth", key, body.to_string().as_bytes())
    }

    fn settings(&self, key: &str) -> Value {
        let (status, body) = self.call("GET", "/v1/settings/auth", key, &[]);
        assert_eq!(status, 200, "{body}");
        body
    }

    fn put_mail(&self, key: &str, api_key: &str, from: &str) {
        let (status, body) = self.put_settings(
            key,
            &json!({ "mail": { "provider": "resend", "api_key": api_key, "from": from, "from_name": "할 일 카드" } }),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn put_google(&self, key: &str) {
        let (status, body) = self.put_settings(
            key,
            &json!({ "google": { "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET } }),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn instance(&mut self, key: &'static str, app: &str) -> String {
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

    fn token(&self, key: &str, instance: &str) -> String {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/sessions"),
            key,
            &json!({ "can": ["source", "preview", "rehearse"] }),
        );
        assert_eq!(status, 200, "{body}");
        body["token"].as_str().unwrap().to_owned()
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

    /// 미리보기 → 승격 요청 → 승격. 둘의 답을 돌려준다.
    fn try_ship(&self, key: &str, instance: &str) -> (Value, (u16, Value), (u16, Value)) {
        let token = self.token(key, instance);
        let preview = self.preview(instance, &token);
        let release = preview["release"].as_str().unwrap().to_owned();
        let requested = self.post(
            &format!("/v1/instances/{instance}/promotion-requests"),
            &token,
            &json!({ "release": release }),
        );
        let promoted = self.post(
            &format!("/v1/instances/{instance}/promotions"),
            key,
            &json!({ "release": release, "change": "customer_request", "approved_by": "customer" }),
        );
        (preview, requested, promoted)
    }

    /// 운영까지 올리고 운영의 router 의 주소를 돌려준다.
    fn ship(&mut self, key: &'static str, app: &str) -> (String, String) {
        let instance = self.instance(key, app);
        let (_, requested, (status, production)) = self.try_ship(key, &instance);
        assert_eq!(requested.0, 200, "{}", requested.1);
        assert_eq!(status, 200, "{production}");
        (
            instance,
            production["services"][0]["url"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
    }

    fn invite(&self, key: &str, instance: &str, email: &str) {
        let (status, body) = self.post(
            &format!("/v1/instances/{instance}/users"),
            key,
            &json!({ "email": email, "roles": ["member"] }),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn sent(&self) -> Vec<Sent> {
        self.resend.sent.lock().unwrap().clone()
    }

    fn sent_to(&self, email: &str) -> Vec<Sent> {
        self.sent()
            .into_iter()
            .filter(|sent| sent.body["to"] == json!([email]))
            .collect()
    }

    fn ask_link(origin: &str, email: &str, browser: Option<&str>) -> Reply {
        let mut headers = vec![("Origin", origin), ("Content-Type", "application/json")];
        if let Some(browser) = browser {
            headers.push(("Cookie", browser));
        }
        http(
            "POST",
            origin,
            "/_orbital/auth/email-link",
            &headers,
            &json!({ "email": email, "next": "/cards" }).to_string(),
        )
    }

    /// 이메일 링크로 들어온다. 가짜 Resend 가 받은 메일의 글에서 링크를 꺼낸다.
    fn sign_in_by_mail(&self, origin: &str, email: &str) -> String {
        let asked = Self::ask_link(origin, email, None);
        assert_eq!(asked.status, 202, "{}", asked.body);
        let browser = asked.cookie("__Host-orbital-browser");
        let mail = self
            .sent_to(email)
            .pop()
            .expect("Resend 에 메일이 가지 않았습니다");
        let text = mail.body["text"].as_str().unwrap().to_owned();
        let link = text
            .split_whitespace()
            .find(|word| word.starts_with(origin))
            .expect("메일의 글에 링크가 없습니다")
            .to_owned();
        let opened = http(
            "GET",
            origin,
            link.strip_prefix(origin).unwrap(),
            &[("Cookie", &browser)],
            "",
        );
        assert_eq!(opened.status, 302, "{}", opened.everything());
        opened.cookie("__Host-orbital-session")
    }

    /// Google 로 들어가기를 시작한다. 브라우저의 표식(쿠키)과 Google 로 가는 주소를 돌려준다.
    fn google_start(origin: &str, browser: Option<&str>) -> (String, String) {
        let mut headers = vec![("Accept", "text/html")];
        if let Some(browser) = browser {
            headers.push(("Cookie", browser));
        }
        let started = http(
            "GET",
            origin,
            "/_orbital/auth/google/start?next=%2Fcards",
            &headers,
            "",
        );
        assert_eq!(started.status, 302, "{}", started.everything());
        let location = started.header("location").unwrap().to_owned();
        let browser = match browser {
            Some(browser) => browser.to_owned(),
            None => started.cookie("__Host-orbital-browser"),
        };
        (browser, location)
    }

    /// Google 이 하듯이 사람을 레이어의 콜백으로 돌려보낸다. `claims` 를 고쳐 Google 이 낸 `id_token` 의 몸을 바꾼다.
    fn google_callback(
        &self,
        location: &str,
        email: &str,
        sub: &str,
        change: &dyn Fn(&mut Value),
    ) -> orbital_server::http::Reply {
        let code = format!("code-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
        let mut claims = json!({
            "iss": "https://accounts.google.com",
            "azp": param(location, "client_id").unwrap(),
            "aud": param(location, "client_id").unwrap(),
            "sub": sub,
            "email": email,
            "email_verified": true,
            "nonce": param(location, "nonce").unwrap(),
            "iat": now(),
            "exp": now() + 3600,
        });
        change(&mut claims);
        self.google
            .codes
            .lock()
            .unwrap()
            .insert(code.clone(), claims);
        let state = param(location, "state").unwrap();
        handle(
            &self.layer,
            "GET",
            &format!(
                "/v1/auth/google/callback?code={}&state={}&scope=email%20openid",
                enc(&code),
                enc(&state)
            ),
            None,
            &[],
        )
    }

    /// Google 로 끝까지 들어온다. router 의 마지막 답(돌아갈 곳으로의 302)을 돌려준다.
    fn google_sign_in(&self, origin: &str, email: &str, sub: &str) -> Reply {
        let (browser, location) = Self::google_start(origin, None);
        let back = self.google_callback(&location, email, sub, &|_| {});
        assert_eq!(back.status, 302, "{}", String::from_utf8_lossy(&back.body));
        let ticket = back.location.unwrap();
        let path = ticket
            .strip_prefix(origin)
            .expect("표가 그 인스턴스의 router 로 가지 않습니다");
        http("GET", origin, path, &[("Cookie", &browser)], "")
    }

    fn database(&self, instance: &str) -> postgres::Client {
        let mut config: postgres::Config = self.pg_url.parse().unwrap();
        config
            .dbname(&format!("i_{instance}"))
            .connect(postgres::NoTls)
            .unwrap()
    }

    fn count(&self, instance: &str, sql: &str) -> i64 {
        self.database(instance).query_one(sql, &[]).unwrap().get(0)
    }

    fn logs(&self) -> String {
        everything_under(&self.home.join("logs"))
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for (instance, key) in &self.instances {
            let _ = self.call("DELETE", &format!("/v1/instances/{instance}"), key, &[]);
        }
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    ($dev:expr) => {
        match Bench::new($dev) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
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

fn titles(origin: &str, cookie: &str) -> Vec<String> {
    let reply = http("GET", origin, "/cards", &[("Cookie", cookie), JSON], "");
    reply
        .json()
        .as_array()
        .unwrap_or_else(|| panic!("{}", reply.everything()))
        .iter()
        .map(|card| card["title"].as_str().unwrap().to_owned())
        .collect()
}

fn texts(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ---- 키가 없으면 운영에 오르지 못한다 ----

#[test]
fn 메일_키를_넣지_않은_팩토리의_이메일_링크_로그인은_운영에_오르지_못하고_까닭을_알린다() {
    let mut bench = bench!(false);
    let instance = bench.instance(FACTORY, "cards");
    let (preview, (requested, refusal), (promoted, denied)) = bench.try_ship(FACTORY, &instance);
    let blockers = texts(&preview["blockers"]);
    assert_eq!(blockers.len(), 1, "{preview}");
    assert!(blockers[0].contains("메일 발송 키"), "{}", blockers[0]);
    assert!(
        blockers[0].contains("에이전트가 고칠 수 없는"),
        "{}",
        blockers[0]
    );
    assert!(blockers[0].contains("Resend"), "{}", blockers[0]);
    assert_eq!(requested, 409, "{refusal}");
    assert_eq!(texts(&refusal["details"]), blockers);
    assert_eq!(promoted, 409, "{denied}");
    assert_eq!(texts(&denied["details"]), blockers);
    assert!(
        bench
            .call(
                "GET",
                &format!("/v1/instances/{instance}/production"),
                FACTORY,
                &[]
            )
            .1
            .is_null()
    );

    // 팩토리가 키를 넣으면 같은 release 가 오른다
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    let (preview, (requested, _), (promoted, production)) = bench.try_ship(FACTORY, &instance);
    assert_eq!(preview["blockers"], json!([]));
    assert_eq!(requested, 200);
    assert_eq!(promoted, 200, "{production}");
}

#[test]
fn google_키를_넣지_않은_팩토리의_google_로그인은_운영에_오르지_못하고_까닭을_알린다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    let instance = bench.instance(FACTORY, "gcards");
    let (preview, (requested, refusal), (promoted, denied)) = bench.try_ship(FACTORY, &instance);
    let blockers = texts(&preview["blockers"]);
    assert_eq!(blockers.len(), 1, "{preview}");
    assert!(blockers[0].contains("Google 로그인 키"), "{}", blockers[0]);
    assert!(
        blockers[0].contains("에이전트가 고칠 수 없는"),
        "{}",
        blockers[0]
    );
    assert_eq!(requested, 409, "{refusal}");
    assert_eq!(texts(&refusal["details"]), blockers);
    assert_eq!(promoted, 409);
    assert_eq!(texts(&denied["details"]), blockers);

    // 키를 넣으면 오르고, 오른 뒤 키를 지우면 시작 주소는 404 가 되고 다음 승격은 막힌다
    bench.put_google(FACTORY);
    let (_, (requested, _), (promoted, production)) = bench.try_ship(FACTORY, &instance);
    assert_eq!((requested, promoted), (200, 200), "{production}");
    let live = production["services"][0]["url"]
        .as_str()
        .unwrap()
        .to_owned();
    Bench::google_start(&live, None);
    let (status, _) = bench.put_settings(FACTORY, &json!({ "google": null }));
    assert_eq!(status, 200);
    let gone = http(
        "GET",
        &live,
        "/_orbital/auth/google/start?next=%2Fcards",
        &[],
        "",
    );
    assert_eq!(gone.status, 404, "{}", gone.everything());
    let (preview, (requested, _), (promoted, _)) = bench.try_ship(FACTORY, &instance);
    assert_eq!(texts(&preview["blockers"]).len(), 1);
    assert_eq!((requested, promoted), (409, 409));
}

#[test]
fn 키가_없어도_미리보기는_서고_메일은_나가지_않는다() {
    let mut bench = bench!(false);
    let instance = bench.instance(FACTORY, "gcards");
    let token = bench.token(FACTORY, &instance);
    let preview = bench.preview(&instance, &token);
    let origin = preview["services"][0]["url"].as_str().unwrap().to_owned();
    assert_eq!(texts(&preview["blockers"]).len(), 2, "{preview}");
    // 미리보기의 씨앗 사용자로 들어가는 길은 그대로 있다
    let seeded = http(
        "POST",
        &origin,
        "/_orbital/preview/sign-in",
        &[("Origin", &origin), ("Content-Type", "application/json")],
        &json!({ "user": "u1", "next": "/cards" }).to_string(),
    );
    assert_eq!(seeded.status, 302, "{}", seeded.everything());

    // 키를 넣은 뒤에도 미리보기의 링크 요청은 같은 202 이고 메일은 나가지 않는다
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    for email in ["u1@example.test", "u2@example.test"] {
        let asked = Bench::ask_link(&origin, email, None);
        assert_eq!(asked.status, 202, "{}", asked.body);
    }
    assert!(bench.sent().is_empty(), "{:?}", bench.sent());
    assert!(!bench.home.join(OUTBOX).exists());
}

// ---- 키를 넣는 길과 봉인 ----

#[test]
fn 넣은_키의_값은_어떤_답과_로그와_오류에도_돌아오지_않는다() {
    let mut bench = bench!(false);
    let mut replies = Vec::new();
    let put = bench.put_settings(
        FACTORY,
        &json!({
            "mail": { "provider": "resend", "api_key": MAIL_KEY, "from": "login@factory.example", "from_name": "할 일 카드" },
            "google": { "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET },
        }),
    );
    assert_eq!(put.0, 200, "{}", put.1);
    replies.push(put.1.to_string());
    let shown = bench.settings(FACTORY);
    assert_eq!(
        shown,
        json!({
            "mail": { "configured": true, "provider": "resend", "from": "login@factory.example", "from_name": "할 일 카드" },
            "google": { "configured": true, "client_id": CLIENT_ID, "redirect_uri": "https://layer.example/v1/auth/google/callback" },
        })
    );
    replies.push(shown.to_string());
    // 틀린 설정의 오류에도 넣은 값이 실리지 않는다
    for wrong in [
        json!({ "mail": { "provider": "smtp", "api_key": MAIL_KEY, "from": "login@factory.example" } }),
        json!({ "mail": { "api_key": MAIL_KEY, "from": MAIL_KEY } }),
        json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example", MAIL_KEY: 1 } }),
        json!({ "mail": { "api_key": 7, "from": MAIL_KEY } }),
        json!({ "google": { "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "extra": CLIENT_SECRET } }),
        json!({ "google": CLIENT_SECRET }),
    ] {
        let (status, body) = bench.put_settings(FACTORY, &wrong);
        assert_eq!(status, 422, "{body}");
        replies.push(body.to_string());
    }
    let (status, body) = bench.call(
        "PUT",
        "/v1/settings/auth",
        FACTORY,
        format!("{{\"mail\": \"{MAIL_KEY}").as_bytes(),
    );
    assert_eq!(status, 422);
    replies.push(body.to_string());

    // 운영에 올리고, 메일이 거절되고, Google 이 code 를 거절하는 길을 지난다
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    *bench.resend.status.lock().unwrap() = 401;
    let asked = Bench::ask_link(&live, "kim@example.com", None);
    assert_eq!(asked.status, 202);
    replies.push(asked.everything());
    let (_, location) = Bench::google_start(&live, None);
    replies.push(location.clone());
    let refused = handle(
        &bench.layer,
        "GET",
        &format!(
            "/v1/auth/google/callback?code=unknown&state={}",
            enc(&param(&location, "state").unwrap())
        ),
        None,
        &[],
    );
    assert_eq!(refused.status, 302);
    assert_eq!(
        refused.location,
        Some(format!("{live}/login?error=unavailable"))
    );
    replies.push(format!(
        "{:?} {}",
        refused.location,
        String::from_utf8_lossy(&refused.body)
    ));
    // Google 에는 팩토리의 비밀이 갔다(값이 레이어 밖으로 나가는 곳은 Google 과 Resend 뿐이다)
    assert_eq!(
        bench.google.asked.lock().unwrap()[0]
            .get("client_secret")
            .map(String::as_str),
        Some(CLIENT_SECRET)
    );
    assert_eq!(bench.sent()[0].authorization, format!("Bearer {MAIL_KEY}"));

    let logs = bench.logs();
    assert!(logs.contains("MAIL rejected 401"), "{logs}");
    assert!(!logs.contains("kim@example.com"), "{logs}");
    let all = format!(
        "{}\n{logs}\n{}",
        replies.join("\n"),
        everything_under(&bench.home)
    );
    for secret in [MAIL_KEY, CLIENT_SECRET] {
        assert!(!all.contains(secret), "`{secret}` 가 새었습니다");
    }
}

#[test]
fn 키는_봉인된_글로만_기록에_있고_레이어의_열쇠_없이는_풀리지_않는다() {
    let bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let record = fs::read_to_string(bench.home.join(SETTINGS)).unwrap();
    assert!(record.contains("seal1."), "{record}");
    let everything = everything_under(&bench.home);
    for secret in [MAIL_KEY, CLIENT_SECRET] {
        assert!(!everything.contains(secret));
        assert!(!everything.contains(&hex(secret.as_bytes())));
    }
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(bench.home.join(SETTINGS))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // 다른 열쇠로 연 레이어에서는 풀리지 않는다. 넣은 것으로 보이지 않고 운영에 쓰이지 않는다
    let other = Bench::open(
        &bench.home,
        &bench.pg_url,
        Some(SealKey::from_bytes([8; 32])),
        false,
        &bench.endpoints,
    );
    let shown = handle(&other, "GET", "/v1/settings/auth", Some(FACTORY), &[]);
    let shown: Value = serde_json::from_slice(&shown.body).unwrap();
    assert_eq!(shown["mail"]["configured"], false, "{shown}");
    assert_eq!(shown["google"]["configured"], false, "{shown}");

    // 열쇠가 없는 레이어도 풀지 못하고, 키를 넣는 길은 409 로 까닭을 알린다
    let keyless = Bench::open(&bench.home, &bench.pg_url, None, false, &bench.endpoints);
    let shown: Value = serde_json::from_slice(
        &handle(&keyless, "GET", "/v1/settings/auth", Some(FACTORY), &[]).body,
    )
    .unwrap();
    assert_eq!(shown["mail"]["configured"], false);
    let refused = handle(
        &keyless,
        "PUT",
        "/v1/settings/auth",
        Some(FACTORY),
        json!({ "mail": { "api_key": MAIL_KEY, "from": "login@factory.example" } })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(refused.status, 409);
    let message = String::from_utf8_lossy(&refused.body).to_string();
    assert!(message.contains("ORBITAL_SEAL_KEY"), "{message}");
    assert!(!message.contains(MAIL_KEY));

    // 같은 열쇠의 레이어에서는 그대로 풀린다
    assert_eq!(bench.settings(FACTORY)["mail"]["configured"], true);
}

#[test]
fn 다른_팩토리의_줄에_옮겨_붙인_봉인은_풀리지_않는다() {
    let bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_mail(OTHER_FACTORY, OTHER_MAIL_KEY, "login@other.example");
    bench.put_google(FACTORY);
    let path = bench.home.join(SETTINGS);
    let mut record: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let organizations = &mut record["organizations"];
    organizations["other"]["mail"]["api_key"] = organizations["factory"]["mail"]["api_key"].clone();
    organizations["other"]["google"] = organizations["factory"]["google"].clone();
    fs::write(&path, record.to_string()).unwrap();

    let reopened = Bench::open(
        &bench.home,
        &bench.pg_url,
        Some(SealKey::from_bytes(SEAL)),
        false,
        &bench.endpoints,
    );
    let read = |key: &str| -> Value {
        serde_json::from_slice(&handle(&reopened, "GET", "/v1/settings/auth", Some(key), &[]).body)
            .unwrap()
    };
    let other = read(OTHER_FACTORY);
    assert_eq!(other["mail"]["configured"], false, "{other}");
    assert_eq!(other["google"]["configured"], false, "{other}");
    let ours = read(FACTORY);
    assert_eq!(ours["mail"]["configured"], true, "{ours}");
    assert_eq!(ours["google"]["configured"], true, "{ours}");
}

#[test]
fn 에이전트의_토큰으로는_팩토리의_설정을_읽거나_바꾸지_못한다() {
    let mut bench = bench!(false);
    let instance = bench.instance(FACTORY, "cards");
    let token = bench.token(FACTORY, &instance);
    let (status, _) = bench.call("GET", "/v1/settings/auth", &token, &[]);
    assert_eq!(status, 404);
    let (status, _) = bench.call(
        "PUT",
        "/v1/settings/auth",
        &token,
        json!({ "mail": { "api_key": MAIL_KEY, "from": "evil@attacker.example" } })
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 404);
    let (status, _) = bench.call(
        "PUT",
        "/v1/settings/auth",
        &token,
        json!({ "mail": null }).to_string().as_bytes(),
    );
    assert_eq!(status, 404);
    assert_eq!(bench.settings(FACTORY)["mail"]["configured"], false);
    // 열쇠 없이도 없다
    assert_eq!(
        handle(&bench.layer, "GET", "/v1/settings/auth", None, &[]).status,
        401
    );
}

// ---- 메일 ----

#[test]
fn 운영의_로그인_링크는_팩토리의_키와_보내는_주소로_나간다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    let (instance, live) = bench.ship(FACTORY, "cards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    let cookie = bench.sign_in_by_mail(&live, "kim@example.com");
    assert_eq!(me(&live, &cookie).json()["email"], "kim@example.com");

    let sent = bench.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let mail = &sent[0];
    assert_eq!(mail.authorization, format!("Bearer {MAIL_KEY}"));
    assert!(
        mail.user_agent
            .as_deref()
            .is_some_and(|agent| !agent.is_empty())
    );
    let idempotency = mail.idempotency.clone().unwrap();
    assert!(idempotency.len() <= 256);
    assert_eq!(mail.body["from"], "할 일 카드 <login@factory.example>");
    assert_eq!(mail.body["to"], json!(["kim@example.com"]));
    let subject = mail.body["subject"].as_str().unwrap();
    assert!(subject.contains("cards"), "{subject}");
    let text = mail.body["text"].as_str().unwrap();
    let link = text
        .split_whitespace()
        .find(|word| word.starts_with(&live))
        .unwrap();
    assert!(text.contains("15분"), "{text}");
    assert!(text.contains("니다"), "{text}");
    let html = mail.body["html"].as_str().unwrap();
    assert!(html.contains(link), "{html}");
    // 멱등 키는 링크의 토큰이 아니다
    let token = param(link, "token").unwrap();
    assert!(!idempotency.contains(&token));
    // 개발용 메일함은 켜지 않았다
    assert!(!bench.home.join(OUTBOX).exists());
}

#[test]
fn 다른_팩토리의_키로는_메일이_나가지_않는다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_mail(OTHER_FACTORY, OTHER_MAIL_KEY, "login@other.example");
    let (ours, ours_live) = bench.ship(FACTORY, "cards");
    let (theirs, theirs_live) = bench.ship(OTHER_FACTORY, "cards");
    bench.invite(FACTORY, &ours, "kim@example.com");
    bench.invite(OTHER_FACTORY, &theirs, "lee@example.com");
    assert_eq!(
        Bench::ask_link(&ours_live, "kim@example.com", None).status,
        202
    );
    assert_eq!(
        Bench::ask_link(&theirs_live, "lee@example.com", None).status,
        202
    );
    let kim = bench.sent_to("kim@example.com");
    let lee = bench.sent_to("lee@example.com");
    assert_eq!((kim.len(), lee.len()), (1, 1));
    assert_eq!(kim[0].authorization, format!("Bearer {MAIL_KEY}"));
    assert_eq!(kim[0].body["from"], "할 일 카드 <login@factory.example>");
    assert_eq!(lee[0].authorization, format!("Bearer {OTHER_MAIL_KEY}"));
    assert_eq!(lee[0].body["from"], "할 일 카드 <login@other.example>");

    // 그 팩토리가 키를 지우면 다른 팩토리의 키로 대신 보내지 않는다. 답은 같은 202 다
    let (status, _) = bench.put_settings(OTHER_FACTORY, &json!({ "mail": null }));
    assert_eq!(status, 200);
    bench
        .database(&theirs)
        .batch_execute(
            "UPDATE orbital_auth.email_link SET created_at = created_at - interval '2 minutes'",
        )
        .unwrap();
    let asked = Bench::ask_link(&theirs_live, "lee@example.com", None);
    assert_eq!(asked.status, 202);
    assert_eq!(bench.sent_to("lee@example.com").len(), 1);
    assert_eq!(bench.sent().len(), 2);
    assert!(bench.logs().contains("MAIL not_configured"));
}

#[test]
fn 메일을_보내지_못해도_링크_요청의_답은_같다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    let (instance, live) = bench.ship(FACTORY, "cards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    *bench.resend.status.lock().unwrap() = 500;
    let failed = Bench::ask_link(&live, "kim@example.com", None);
    let stranger = Bench::ask_link(&live, "stranger@example.com", None);
    for reply in [&failed, &stranger] {
        assert_eq!(reply.status, 202, "{}", reply.everything());
        assert_eq!(reply.body, "{}");
        assert!(reply.set_cookie("__Host-orbital-browser").is_some());
    }
    let names = |reply: &Reply| -> Vec<String> {
        reply
            .headers
            .iter()
            .map(|(key, _)| key.clone())
            .filter(|key| key != "date")
            .collect()
    };
    assert_eq!(names(&failed), names(&stranger));
    // Resend 는 한 번 불렸고 거절했다. 기록에는 갈래와 상태만 있다
    assert_eq!(bench.sent_to("kim@example.com").len(), 1);
    let logs = bench.logs();
    assert!(logs.contains("MAIL rejected 500"), "{logs}");
    assert!(!logs.contains("kim@example.com"));
    assert!(!logs.contains("token="));
    // 만들어 둔 링크는 그대로 있다
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.email_link WHERE email = 'kim@example.com' AND used_at IS NULL"),
        1
    );
}

// ---- Google 로그인 ----

#[test]
fn google_이_확인한_이메일의_초대받은_사용자가_google_로_들어와_자기_행만_본다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    bench.invite(FACTORY, &instance, "lee@example.com");

    // Google 로 가는 주소는 팩토리의 클라이언트와 레이어의 콜백 하나를 싣는다
    let (_, location) = Bench::google_start(&live, None);
    assert!(location.starts_with(&format!("{AUTHORIZE}?")), "{location}");
    assert_eq!(param(&location, "client_id").as_deref(), Some(CLIENT_ID));
    assert_eq!(
        param(&location, "redirect_uri").as_deref(),
        Some("https://layer.example/v1/auth/google/callback")
    );
    assert_eq!(param(&location, "response_type").as_deref(), Some("code"));
    assert_eq!(param(&location, "scope").as_deref(), Some("openid email"));
    assert!(param(&location, "nonce").is_some_and(|nonce| nonce.len() >= 32));

    let mut cookies = Vec::new();
    for (email, sub) in [("kim@example.com", "g-kim"), ("lee@example.com", "g-lee")] {
        let entered = bench.google_sign_in(&live, email, sub);
        assert_eq!(entered.status, 302, "{}", entered.everything());
        assert_eq!(entered.header("location"), Some("/cards"));
        cookies.push(entered.cookie("__Host-orbital-session"));
    }
    // 토큰 주소에는 팩토리의 키와 레이어의 콜백으로 code 를 바꿨다
    let asked = bench.google.asked.lock().unwrap().clone();
    assert_eq!(
        asked[0].get("client_id").map(String::as_str),
        Some(CLIENT_ID)
    );
    assert_eq!(
        asked[0].get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        asked[0].get("redirect_uri").map(String::as_str),
        Some("https://layer.example/v1/auth/google/callback")
    );

    assert_eq!(me(&live, &cookies[0]).json()["email"], "kim@example.com");
    assert_eq!(me(&live, &cookies[0]).json()["roles"], json!(["member"]));
    for (cookie, title) in [(&cookies[0], "김의 일"), (&cookies[1], "이의 일")] {
        let made = http("POST", &live, "/cards", &[("Cookie", cookie), JSON], title);
        assert_eq!(made.status, 201, "{}", made.everything());
    }
    assert_eq!(titles(&live, &cookies[0]), vec!["김의 일"]);
    assert_eq!(titles(&live, &cookies[1]), vec!["이의 일"]);
    assert_eq!(
        bench.count(
            &instance,
            "SELECT count(*) FROM orbital_auth.login WHERE provider = 'google'"
        ),
        2
    );
}

#[test]
fn google_이_확인하지_않은_이메일과_초대받지_않은_이메일은_들어오지_못한다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");

    // Google 이 확인하지 않은 이메일은 콜백에서 멈춘다. 표를 내지 않는다
    for unverified in [json!(false), json!("false"), Value::Null] {
        let (_, location) = Bench::google_start(&live, None);
        let back = bench.google_callback(&location, "kim@example.com", "g-kim", &|claims| {
            claims["email_verified"] = unverified.clone();
        });
        assert_eq!(
            back.location,
            Some(format!("{live}/login?error=unverified"))
        );
    }
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.google_ticket"),
        0
    );

    // 초대받지 않은 이메일은 표를 써도 들어오지 못한다
    let refused = bench.google_sign_in(&live, "stranger@example.com", "g-stranger");
    assert_eq!(refused.status, 302);
    assert_eq!(refused.header("location"), Some("/login?error=not_invited"));
    assert!(refused.set_cookie("__Host-orbital-session").is_none());
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.users"),
        0
    );
}

#[test]
fn 이메일_링크로_들어온_사용자가_google_로_들어와도_같은_사용자다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    let by_mail = bench.sign_in_by_mail(&live, "kim@example.com");
    let id = me(&live, &by_mail).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let entered = bench.google_sign_in(&live, "Kim@Example.com", "g-kim");
    assert_eq!(entered.status, 302, "{}", entered.everything());
    let by_google = entered.cookie("__Host-orbital-session");
    assert_eq!(me(&live, &by_google).json()["id"], id.as_str());
    assert_eq!(
        bench.count(
            &instance,
            &format!("SELECT count(*) FROM orbital_auth.login WHERE user_id = '{id}'")
        ),
        2
    );

    // Google 의 계정이 이미 묶여 있으면 이메일이 바뀌어도 그 사용자다
    let moved = bench.google_sign_in(&live, "kim.new@example.com", "g-kim");
    assert_eq!(moved.status, 302, "{}", moved.everything());
    assert_eq!(moved.header("location"), Some("/cards"));
    assert_eq!(
        me(&live, &moved.cookie("__Host-orbital-session")).json()["id"],
        id.as_str()
    );
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.users"),
        1
    );
}

#[test]
fn google_의_콜백이_낸_표는_한_번만_그_인스턴스에서만_요청한_브라우저에서만_쓰인다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    let (other, other_live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    bench.invite(FACTORY, &other, "kim@example.com");

    let (browser, location) = Bench::google_start(&live, None);
    let back = bench.google_callback(&location, "kim@example.com", "g-kim", &|_| {});
    let ticket = back.location.unwrap();
    let path = ticket.strip_prefix(&live).unwrap().to_owned();
    assert!(
        path.starts_with("/_orbital/auth/google/finish?ticket="),
        "{path}"
    );
    let ticket_value = param(&ticket, "ticket").unwrap();
    // 표는 해시로만 있다
    assert_eq!(
        bench.count(&instance, &format!("SELECT count(*) FROM orbital_auth.google_ticket WHERE token_hash::text LIKE '%{ticket_value}%'")),
        0
    );

    // 다른 브라우저
    let (stranger, _) = Bench::google_start(&live, None);
    let elsewhere = http("GET", &live, &path, &[("Cookie", &stranger)], "");
    assert_eq!(
        elsewhere.header("location"),
        Some("/login?error=other_browser")
    );
    let cookieless = http("GET", &live, &path, &[], "");
    assert_eq!(
        cookieless.header("location"),
        Some("/login?error=other_browser")
    );
    // 다른 인스턴스
    let there = http("GET", &other_live, &path, &[("Cookie", &browser)], "");
    assert_eq!(there.header("location"), Some("/login?error=invalid"));
    assert!(there.set_cookie("__Host-orbital-session").is_none());
    // 요청한 브라우저에서 한 번
    let entered = http("GET", &live, &path, &[("Cookie", &browser)], "");
    assert_eq!(
        entered.header("location"),
        Some("/cards"),
        "{}",
        entered.everything()
    );
    assert_eq!(entered.header("referrer-policy"), Some("no-referrer"));
    entered.cookie("__Host-orbital-session");
    let again = http("GET", &live, &path, &[("Cookie", &browser)], "");
    assert_eq!(again.header("location"), Some("/login?error=used"));
    assert!(again.set_cookie("__Host-orbital-session").is_none());

    // 60초가 지난 표는 쓰이지 않는다
    let (browser, location) = Bench::google_start(&live, None);
    let late = bench
        .google_callback(&location, "kim@example.com", "g-kim", &|_| {})
        .location
        .unwrap();
    bench
        .database(&instance)
        .batch_execute("UPDATE orbital_auth.google_ticket SET expires_at = now() - interval '1 second' WHERE used_at IS NULL")
        .unwrap();
    let expired = http(
        "GET",
        &live,
        late.strip_prefix(&live).unwrap(),
        &[("Cookie", &browser)],
        "",
    );
    assert_eq!(expired.header("location"), Some("/login?error=expired"));
}

#[test]
fn 다른_클라이언트용으로_낸_google_의_토큰은_받지_않는다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    let changes: [&dyn Fn(&mut Value); 4] = [
        &|claims| claims["aud"] = json!("other-client.apps.googleusercontent.com"),
        &|claims| {
            claims["aud"] = json!([CLIENT_ID, "other"]);
            claims["azp"] = json!("other");
        },
        &|claims| claims["iss"] = json!("https://evil.example"),
        &|claims| claims["nonce"] = json!("not-the-nonce-we-sent"),
    ];
    for change in changes {
        let (_, location) = Bench::google_start(&live, None);
        let back = bench.google_callback(&location, "kim@example.com", "g-kim", change);
        assert_eq!(back.status, 302);
        assert_eq!(back.location, Some(format!("{live}/login?error=invalid")));
    }
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.google_ticket"),
        0
    );
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.session"),
        0
    );
}

#[test]
fn 위조하거나_만료된_state_로는_콜백이_아무것도_하지_않는다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let (instance, live) = bench.ship(FACTORY, "gcards");
    bench.invite(FACTORY, &instance, "kim@example.com");
    let (_, location) = Bench::google_start(&live, None);
    let state = param(&location, "state").unwrap();
    let parts: Vec<&str> = state.split('.').collect();
    assert_eq!(parts.len(), 3, "{state}");
    let mut claims: StateClaims =
        serde_json::from_slice(&orbital_server::token::unhex(parts[1]).unwrap()).unwrap();

    let flipped = format!(
        "{}.{}.{}{}",
        parts[0],
        parts[1],
        &parts[2][..parts[2].len() - 1],
        if parts[2].ends_with('0') { '1' } else { '0' }
    );
    claims.next = "/elsewhere".to_owned();
    let rewritten = format!(
        "{}.{}.{}",
        parts[0],
        hex(serde_json::to_string(&claims).unwrap().as_bytes()),
        parts[2]
    );
    // 레이어의 열쇠로 서명했어도 만료된 것과 미리보기의 것은 받지 않는다
    let key = fs::read(bench.home.join("token.key")).unwrap();
    claims.next = "/cards".to_owned();
    let mut expired = claims.clone();
    expired.expires_at = now() - 1;
    let mut preview = claims.clone();
    preview.stage = Stage::Preview;
    let forged_by_other_key = sign_state(b"not-the-layer-key-not-the-layer-key", &claims);

    for bad in [
        flipped,
        rewritten,
        sign_state(&key, &expired),
        sign_state(&key, &preview),
        forged_by_other_key,
        "gs1.zz.zz".to_owned(),
        String::new(),
    ] {
        let code = "code-forged";
        bench
            .google
            .codes
            .lock()
            .unwrap()
            .insert(code.to_owned(), json!({}));
        let reply = handle(
            &bench.layer,
            "GET",
            &format!("/v1/auth/google/callback?code={code}&state={}", enc(&bad)),
            None,
            &[],
        );
        assert_eq!(
            reply.status,
            400,
            "{bad}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        assert_eq!(reply.location, None);
    }
    // Google 의 토큰 주소를 부르지 않았고 표도 적지 않았다
    assert!(bench.google.asked.lock().unwrap().is_empty());
    assert_eq!(
        bench.count(&instance, "SELECT count(*) FROM orbital_auth.google_ticket"),
        0
    );
    // 맞게 서명한 것은 지난다
    let fine = sign_state(&key, &claims);
    assert_eq!(fine.split('.').count(), 3);
}

#[test]
fn 미리보기에는_google_로그인이_없다() {
    let mut bench = bench!(false);
    bench.put_mail(FACTORY, MAIL_KEY, "login@factory.example");
    bench.put_google(FACTORY);
    let instance = bench.instance(FACTORY, "gcards");
    let token = bench.token(FACTORY, &instance);
    let preview = bench.preview(&instance, &token);
    assert_eq!(preview["blockers"], json!([]));
    let origin = preview["services"][0]["url"].as_str().unwrap().to_owned();
    let start = http(
        "GET",
        &origin,
        "/_orbital/auth/google/start?next=%2Fcards",
        &[("Accept", "text/html")],
        "",
    );
    assert_eq!(start.status, 404, "{}", start.everything());
    assert!(start.set_cookie("__Host-orbital-browser").is_none());
    let finish = http(
        "GET",
        &origin,
        &format!("/_orbital/auth/google/finish?ticket={}", "ab".repeat(32)),
        &[],
        "",
    );
    assert_eq!(finish.status, 404);
}

#[test]
fn 개발용_메일함은_명시해_켠_레이어에서만_키_없이_운영에_오른다() {
    // 켜지 않은 레이어(기본)
    let mut plain = bench!(false);
    let instance = plain.instance(FACTORY, "cards");
    let (_, (requested, _), (promoted, _)) = plain.try_ship(FACTORY, &instance);
    assert_eq!((requested, promoted), (409, 409));
    drop(plain);

    // 켠 레이어는 메일 키 없이 오르고 메일은 파일에 쌓인다. Google 의 키는 대신하지 않는다
    let mut dev = bench!(true);
    let (instance, live) = dev.ship(FACTORY, "cards");
    dev.invite(FACTORY, &instance, "kim@example.com");
    assert_eq!(Bench::ask_link(&live, "kim@example.com", None).status, 202);
    let mails = Outbox::read(&dev.home.join(OUTBOX));
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, "kim@example.com");
    assert!(dev.sent().is_empty());
    let google = dev.instance(FACTORY, "gcards");
    let (preview, (requested, _), (promoted, _)) = dev.try_ship(FACTORY, &google);
    assert_eq!(texts(&preview["blockers"]).len(), 1);
    assert!(texts(&preview["blockers"])[0].contains("Google"));
    assert_eq!((requested, promoted), (409, 409));
}
