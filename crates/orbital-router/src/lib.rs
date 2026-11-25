//! router. 인스턴스(미리보기나 운영)마다 하나가 포트 하나를 듣는다.
//!
//! 요청을 선언의 서비스 `path` 가운데 가장 길게 맞는 서비스로 가른다. 서버 서비스에는 HTTP/1.1 로 흘려보내고, 정적 서비스는
//! 빌드 결과의 폴더에서 파일을 내준다. `/_orbital/` 은 router 가 직접 답한다(로그인의 뒤쪽).
//!
//! 신원이 앱에 닿는 길은 하나다. 밖에서 온 `x-orbital-` 머리말은 언제나 지우고, router 가 세션 쿠키를 확인했을 때만
//! 60초짜리 서명된 신원을 `x-orbital-identity` 에 붙인다. 레이어의 쿠키(`__Host-orbital-*`)는 앱에 넘기지 않고, 앱이 그 이름으로
//! 쿠키를 심지도 못하게 한다.
//!
//! 판정(가르기 · 들여보내기 · 돌아갈 곳 · Origin · 정적 파일의 경로)은 core 의 `orbital_core::auth` 가 한다. 여기서는 그 답대로 움직인다.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use orbital_core::auth::{
    Admission, InvitationRefusal, LinkRefusal, SESSION_TTL, admit, route, safe_next, same_origin,
    static_file, wants_page,
};
use orbital_core::manifest::ValidManifest;
use orbital_core::plan::Names;
use orbital_pg::auth::{AuthError, AuthStore, Secret, SessionUser};
use orbital_pg::identity::{Claims, sign};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// 세션의 쿠키. `__Host-` 머리말이라 브라우저는 `Secure` 이고 `Path=/` 이고 `Domain` 이 없을 때만 받는다.
pub const SESSION_COOKIE: &str = "__Host-orbital-session";
/// 링크를 요청한 브라우저의 표식. 링크는 이 표식이 있는 브라우저에서만 열린다.
pub const BROWSER_COOKIE: &str = "__Host-orbital-browser";
/// 앱에 신원을 싣는 머리말. router 만 붙인다.
pub const IDENTITY_HEADER: &str = "x-orbital-identity";
const LAYER_COOKIE_PREFIX: &str = "__Host-orbital-";
const LAYER_HEADER_PREFIX: &str = "x-orbital-";
/// 앱에 싣는 신원이 읽히는 시간. 요청 하나를 처리하는 동안만 쓰면 된다.
const IDENTITY_TTL: u64 = 60;
const BROWSER_TTL: u64 = 365 * 24 * 60 * 60;
/// 인스턴스마다 인증 역할의 연결을 이만큼까지 연다.
const POOL_SIZE: usize = 4;
/// `/_orbital/` 이 받는 본문의 크기.
const BODY_LIMIT: usize = 16 * 1024;
/// 지나가는 머리말. 연결 하나에만 걸리므로 앱에 넘기지 않는다.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

type Body = BoxBody<Bytes, hyper::Error>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

// ---- 메일 ----

/// 로그인 링크 한 통.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub to: String,
    pub link: String,
}

/// 로그인 링크를 보내는 것. 실제 발송기는 아직 없고, 개발용은 보내는 대신 쌓는다.
pub trait Mailer: Send + Sync {
    fn send(&self, mail: Mail);
}

/// 메모리에 쌓는 메일함. 테스트가 꺼내 본다.
#[derive(Debug, Default)]
pub struct Mailbox {
    mails: Mutex<Vec<Mail>>,
}

impl Mailbox {
    pub fn mails(&self) -> Vec<Mail> {
        self.mails
            .lock()
            .map(|mails| mails.clone())
            .unwrap_or_default()
    }
}

impl Mailer for Mailbox {
    fn send(&self, mail: Mail) {
        if let Ok(mut mails) = self.mails.lock() {
            mails.push(mail);
        }
    }
}

/// 파일(JSON 한 줄에 한 통)에 쌓는 개발용 메일함. `orbitald` 를 따로 띄운 테스트가 읽는다. 파일은 주인만 읽는다(0600).
#[derive(Debug)]
pub struct Outbox {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Outbox {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// 쌓인 메일을 읽는다. 파일이 없으면 빈 목록이다.
    pub fn read(path: &Path) -> Vec<Mail> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|value| {
                Some(Mail {
                    to: value["to"].as_str()?.to_owned(),
                    link: value["link"].as_str()?.to_owned(),
                })
            })
            .collect()
    }
}

impl Mailer for Outbox {
    fn send(&self, mail: Mail) {
        let _guard = self.lock.lock();
        let line = json!({ "to": mail.to, "link": mail.link }).to_string();
        // 메일이 쌓이지 않아도 요청의 답은 같아야 한다. 실패는 삼킨다
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

// ---- 설정 ----

/// router 가 선 자리. 씨앗 사용자로 들어가는 길은 미리보기에만 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Preview,
    Production,
}

/// 서비스 하나가 요청을 받는 자리. 이 주소는 router 만 알고 밖에 알리지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Server { port: u16 },
    Static { folder: PathBuf },
}

/// 인증 역할의 연결을 새로 여는 것.
pub type Connect = Arc<dyn Fn() -> Result<AuthStore, AuthError> + Send + Sync>;

pub struct Config {
    /// router 의 바깥 주소(`http://127.0.0.1:4100`). 링크의 주소와 `Origin` 검사가 이것을 쓴다. 요청의 `Host` 는 믿지 않는다.
    pub origin: String,
    pub manifest: ValidManifest,
    pub names: Names,
    pub identity_key: Vec<u8>,
    /// 서비스의 이름마다 요청을 받는 자리.
    pub targets: BTreeMap<String, Target>,
    /// `[auth]` 를 선언했을 때만 있다.
    pub auth: Option<Connect>,
    pub mailer: Arc<dyn Mailer>,
    pub stage: Stage,
    /// 미리보기의 씨앗 사용자. 이 식별자로만 링크 없이 들어간다.
    pub seed_users: Vec<String>,
    /// 요청마다 한 줄(메서드, 질의를 뗀 경로, 상태)을 적는 파일.
    pub log: Option<PathBuf>,
}

// ---- 인증 역할의 연결 풀 ----

/// 인증 역할의 연결을 열지 못했다. 503 으로 답한다.
#[derive(Debug)]
struct Unavailable;

#[derive(Debug)]
enum StoreError {
    Refused(AuthError),
    Unavailable,
}

/// 인증 역할의 연결 몇 개. 필요할 때 열고, 깨지면 버리고 새로 연다. 동기 클라이언트라 `spawn_blocking` 에서만 부른다.
struct Pool {
    connect: Connect,
    idle: Mutex<Vec<AuthStore>>,
    permits: Semaphore,
}

impl Pool {
    async fn run<T, F>(self: &Arc<Self>, work: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: Fn(&mut AuthStore) -> Result<T, AuthError> + Send + 'static,
    {
        let Ok(_permit) = self.permits.acquire().await else {
            return Err(StoreError::Unavailable);
        };
        let pool = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            // 연결이 끊겼으면(운영 DB 의 문을 잠깐 닫는 예행연습 같은) 한 번만 새로 열어 다시 한다
            for _ in 0..2 {
                let idle = pool.idle.lock().ok().and_then(|mut idle| idle.pop());
                let mut store = match idle {
                    Some(store) => store,
                    None => match (pool.connect)() {
                        Ok(store) => store,
                        Err(_) => continue,
                    },
                };
                match work(&mut store) {
                    Err(AuthError::Db(_)) => {
                        // 같은 때에 연 연결들도 끊겼을 것이다. 모두 버린다
                        if let Ok(mut idle) = pool.idle.lock() {
                            idle.clear();
                        }
                    }
                    answer => {
                        if let Ok(mut idle) = pool.idle.lock() {
                            idle.push(store);
                        }
                        return answer.map_err(StoreError::Refused);
                    }
                }
            }
            Err(StoreError::Unavailable)
        })
        .await
        .unwrap_or(Err(StoreError::Unavailable))
    }
}

impl Drop for Pool {
    /// 동기 클라이언트는 닫을 때 제 런타임을 돌린다. router 를 내리면 이 값이 tokio 의 일꾼 위에서 떨어질 수 있어, 따로 된 스레드에서 닫는다.
    fn drop(&mut self) {
        let stores: Vec<AuthStore> = self.idle.get_mut().map(std::mem::take).unwrap_or_default();
        if !stores.is_empty() {
            std::thread::spawn(move || drop(stores));
        }
    }
}

// ---- 답 ----

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn json_reply(status: StatusCode, value: &Value) -> Response<Body> {
    let mut response = Response::new(full(value.to_string()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error(status: StatusCode, code: &str) -> Response<Body> {
    json_reply(status, &json!({ "error": code }))
}

fn redirect(location: &str) -> Response<Body> {
    let mut response = Response::new(empty());
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn set_cookie(response: &mut Response<Body>, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn session_cookie(session: &Secret) -> String {
    format!(
        "{SESSION_COOKIE}={}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Lax",
        session.to_text()
    )
}

fn cleared_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

fn browser_cookie(browser: &Secret) -> String {
    format!(
        "{BROWSER_COOKIE}={}; Path=/; Max-Age={BROWSER_TTL}; HttpOnly; Secure; SameSite=Lax",
        browser.to_text()
    )
}

// ---- 머리말과 쿠키 ----

/// 요청의 쿠키 가운데 이 이름의 값.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// `Cookie` 머리말의 값에서 레이어의 쿠키를 뺀다. 남는 것이 없으면 `None` 이다.
fn strip_layer_cookies(value: &str) -> Option<String> {
    let kept: Vec<&str> = value
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && !pair.starts_with(LAYER_COOKIE_PREFIX))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// 연결 하나에만 걸리는 머리말을 지운다. `Connection` 에 적힌 이름도 함께 지운다.
fn drop_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        headers.remove(name);
    }
}

/// 앱으로 넘기기 전에 요청의 머리말을 고른다. 밖에서 온 `x-orbital-` 머리말과 레이어의 쿠키를 지운다.
fn clean_request_headers(headers: &mut HeaderMap) {
    drop_hop_by_hop(headers);
    let layer: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(LAYER_HEADER_PREFIX))
        .cloned()
        .collect();
    for name in layer {
        headers.remove(name);
    }
    let cookies: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(strip_layer_cookies)
        .collect();
    headers.remove(header::COOKIE);
    if !cookies.is_empty()
        && let Ok(value) = HeaderValue::from_str(&cookies.join("; "))
    {
        headers.insert(header::COOKIE, value);
    }
}

/// 앱의 답에서 연결 하나에만 걸리는 머리말과, 레이어의 쿠키를 심으려는 `Set-Cookie` 를 지운다.
fn clean_response_headers(headers: &mut HeaderMap) {
    drop_hop_by_hop(headers);
    let kept: Vec<HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| {
            !value
                .to_str()
                .map(str::trim_start)
                .unwrap_or_default()
                .starts_with(LAYER_COOKIE_PREFIX)
        })
        .cloned()
        .collect();
    headers.remove(header::SET_COOKIE);
    for value in kept {
        headers.append(header::SET_COOKIE, value);
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// 질의에서 값 하나. 토큰은 hex 라 풀 것이 없다.
fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

// ---- router ----

struct State {
    config: Config,
    pool: Option<Arc<Pool>>,
    client: Client<HttpConnector, Body>,
    log: Mutex<()>,
}

/// 요청을 듣는다. 이 future 를 내리면(abort) 붙어 있던 연결도 모두 내린다.
pub async fn serve(listener: TcpListener, config: Config) -> std::io::Result<()> {
    let pool = config.auth.clone().map(|connect| {
        Arc::new(Pool {
            connect,
            idle: Mutex::new(Vec::new()),
            permits: Semaphore::new(POOL_SIZE),
        })
    });
    let state = Arc::new(State {
        config,
        pool,
        // 앱으로 가는 연결은 살려 두고 다시 쓴다
        client: Client::builder(TokioExecutor::new()).build_http(),
        log: Mutex::new(()),
    });
    let mut connections = JoinSet::new();
    loop {
        let (stream, _) = listener.accept().await?;
        while connections.try_join_next().is_some() {}
        let state = Arc::clone(&state);
        connections.spawn(async move {
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(state.handle(request).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

impl State {
    async fn handle(self: Arc<Self>, request: Request<Incoming>) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let response = self.answer(request).await;
        self.record(&method, &path, response.status());
        response
    }

    /// 요청마다 한 줄을 적는다. 질의(링크의 토큰이 있다)와 머리말(쿠키가 있다)은 적지 않는다.
    fn record(&self, method: &Method, path: &str, status: StatusCode) {
        let Some(log) = &self.config.log else {
            return;
        };
        let _guard = self.log.lock();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log) {
            let _ = writeln!(file, "{method} {path} {}", status.as_u16());
        }
    }

    async fn answer(&self, request: Request<Incoming>) -> Response<Body> {
        let path = request.uri().path().to_owned();
        if path == "/_orbital" || path.starts_with("/_orbital/") {
            return self.layer(request).await;
        }
        let manifest = &self.config.manifest;
        let Some(service) = route(manifest, &path) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let Some(target) = self.config.targets.get(service.name.as_str()) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let user = match self.signed_in(request.headers()).await {
            Ok(user) => user,
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or(path.clone(), |whole| whole.as_str().to_owned());
        let accept = request
            .headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok());
        let page = wants_page(request.method().as_str(), accept);
        match admit(manifest, service, &path_and_query, user.is_some(), page) {
            Admission::Pass => {}
            Admission::ToLogin { location } => return redirect(&location),
            Admission::Unauthorized => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        }
        match target {
            Target::Static { folder } => {
                Self::file(folder, &path, &service.path, request.method()).await
            }
            Target::Server { port } => self.forward(request, *port, user.as_ref()).await,
        }
    }

    /// 세션 쿠키의 사용자. 쿠키가 없거나 세션이 없는 것이면 `None` 이다. DB 에 닿지 못하면 `Err` 이다.
    async fn signed_in(&self, headers: &HeaderMap) -> Result<Option<SessionUser>, Unavailable> {
        let Some(pool) = &self.pool else {
            return Ok(None);
        };
        let Some(token) = cookie(headers, SESSION_COOKIE).and_then(|text| Secret::parse(&text))
        else {
            return Ok(None);
        };
        match pool.run(move |store| store.session(&token, now())).await {
            Ok(user) => Ok(user),
            Err(StoreError::Refused(_)) => Ok(None),
            Err(StoreError::Unavailable) => Err(Unavailable),
        }
    }

    async fn file(
        folder: &Path,
        path: &str,
        service_path: &str,
        method: &Method,
    ) -> Response<Body> {
        if method != Method::GET && method != Method::HEAD {
            return error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        }
        let Some(parts) = static_file(path, service_path) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let candidate = parts
            .iter()
            .fold(folder.to_path_buf(), |at, part| at.join(part));
        // 조각은 core 가 걸렀다. 심볼릭 링크가 폴더 밖을 가리킬 수 있으니 실제 경로가 폴더 안인지 다시 본다
        let (Ok(root), Ok(real)) = (fs::canonicalize(folder), fs::canonicalize(&candidate)) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        if !real.starts_with(&root) || !real.is_file() {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
        let Ok(bytes) = tokio::fs::read(&real).await else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let length = bytes.len();
        let mut response = Response::new(if method == Method::HEAD {
            empty()
        } else {
            full(bytes)
        });
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(&real)),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        response
    }

    /// 서버 서비스로 흘려보낸다. 본문은 버퍼에 담지 않는다.
    async fn forward(
        &self,
        request: Request<Incoming>,
        port: u16,
        user: Option<&SessionUser>,
    ) -> Response<Body> {
        let (mut parts, body) = request.into_parts();
        clean_request_headers(&mut parts.headers);
        if let Some(user) = user {
            let identity = sign(
                &self.config.identity_key,
                &self.config.names,
                &Claims {
                    subject: user.id.clone(),
                    expires_at: now() + IDENTITY_TTL,
                },
            );
            if let Ok(value) = HeaderValue::from_str(&identity) {
                parts.headers.insert(IDENTITY_HEADER, value);
            }
        }
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or("/", |whole| whole.as_str());
        let Ok(uri) = format!("http://127.0.0.1:{port}{path_and_query}").parse() else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        parts.uri = uri;
        let upstream = Request::from_parts(parts, body.boxed());
        match self.client.request(upstream).await {
            Ok(answer) => {
                let (mut parts, body) = answer.into_parts();
                clean_response_headers(&mut parts.headers);
                Response::from_parts(parts, body.boxed())
            }
            Err(_) => error(StatusCode::BAD_GATEWAY, "bad_gateway"),
        }
    }

    // ---- /_orbital/ ----

    async fn layer(&self, request: Request<Incoming>) -> Response<Body> {
        // [auth] 를 선언하지 않은 인스턴스에는 레이어의 길이 없다
        let Some(pool) = self.pool.clone() else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let preview = self.config.stage == Stage::Preview;
        let posting =
            matches!(
                (&method, path.as_str()),
                (
                    &Method::POST,
                    "/_orbital/auth/email-link" | "/_orbital/auth/logout"
                )
            ) || (preview && method == Method::POST && path == "/_orbital/preview/sign-in");
        if posting {
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok());
            if !same_origin(origin, &self.config.origin) {
                return error(StatusCode::FORBIDDEN, "forbidden");
            }
        }
        match (method, path.as_str()) {
            (Method::POST, "/_orbital/auth/email-link") => self.email_link(request, pool).await,
            (Method::GET, "/_orbital/auth/callback") => self.callback(&request, pool).await,
            (Method::GET, "/_orbital/auth/me") => self.me(request.headers()).await,
            (Method::POST, "/_orbital/auth/logout") => Self::logout(request.headers(), pool).await,
            (Method::POST, "/_orbital/preview/sign-in") if preview => {
                self.preview_sign_in(request, pool).await
            }
            _ => error(StatusCode::NOT_FOUND, "not_found"),
        }
    }

    fn login_path(&self) -> &str {
        self.config
            .manifest
            .get()
            .auth
            .as_ref()
            .map_or("/", |auth| auth.login_path.as_str())
    }

    async fn email_link(&self, request: Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let known = cookie(request.headers(), BROWSER_COOKIE).and_then(|text| Secret::parse(&text));
        let Some(body) = read_json(request).await else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        let Some(email) = body["email"].as_str().map(str::trim).map(str::to_owned) else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        let next = body["next"].as_str().unwrap_or("/").to_owned();
        // 표식이 없으면 심는다. 초대됐는지와 상관없이 같은 머리말이 나간다
        let (browser, planted) = match known {
            Some(browser) => (browser, None),
            None => match Secret::generate() {
                Ok(browser) => {
                    let cookie = browser_cookie(&browser);
                    (browser, Some(cookie))
                }
                Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            },
        };
        let asked = email.clone();
        let made = pool
            .run(move |store| store.request_link(&asked, &next, &browser, now()))
            .await;
        match made {
            Ok(Some(token)) => self.config.mailer.send(Mail {
                to: email,
                link: format!(
                    "{}/_orbital/auth/callback?token={}",
                    self.config.origin,
                    token.to_text()
                ),
            }),
            // 초대받지 않았거나, 막혔거나, 1분 안에 다시 왔다. 답은 같다
            Ok(None) | Err(StoreError::Refused(_)) => {}
            Err(StoreError::Unavailable) => {
                return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
        }
        let mut response = json_reply(StatusCode::ACCEPTED, &json!({}));
        if let Some(cookie) = planted {
            set_cookie(&mut response, &cookie);
        }
        response
    }

    async fn callback(&self, request: &Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let token = request
            .uri()
            .query()
            .and_then(|query| query_value(query, "token"))
            .and_then(Secret::parse);
        let browser =
            cookie(request.headers(), BROWSER_COOKIE).and_then(|text| Secret::parse(&text));
        let refused = |code: &str| {
            let mut response = redirect(&format!("{}?error={code}", self.login_path()));
            // 토큰이 든 주소가 다음 화면의 Referer 로 새지 않게 한다
            response.headers_mut().insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            response
        };
        let Some(token) = token else {
            return refused("invalid");
        };
        let Some(browser) = browser else {
            return refused("other_browser");
        };
        match pool
            .run(move |store| store.enter(&token, &browser, now()))
            .await
        {
            Ok(entered) => {
                let mut response = redirect(&entered.next);
                response.headers_mut().insert(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                );
                set_cookie(&mut response, &session_cookie(&entered.session));
                response
            }
            Err(StoreError::Refused(refusal)) => refused(match refusal {
                AuthError::Link(LinkRefusal::Expired)
                | AuthError::Invitation(InvitationRefusal::Expired) => "expired",
                AuthError::Link(LinkRefusal::Used) => "used",
                AuthError::Link(LinkRefusal::OtherBrowser) => "other_browser",
                AuthError::NotInvited => "not_invited",
                AuthError::UserDisabled => "disabled",
                _ => "invalid",
            }),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    async fn me(&self, headers: &HeaderMap) -> Response<Body> {
        match self.signed_in(headers).await {
            Ok(Some(user)) => json_reply(
                StatusCode::OK,
                &json!({ "id": user.id, "email": user.email, "name": user.name, "roles": user.roles }),
            ),
            Ok(None) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
            Err(Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    async fn logout(headers: &HeaderMap, pool: Arc<Pool>) -> Response<Body> {
        if let Some(token) = cookie(headers, SESSION_COOKIE).and_then(|text| Secret::parse(&text))
            && let Err(StoreError::Unavailable) =
                pool.run(move |store| store.revoke(&token, now())).await
        {
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        let mut response = Response::new(empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        set_cookie(&mut response, &cleared_session_cookie());
        response
    }

    async fn preview_sign_in(&self, request: Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let Some(body) = read_json(request).await else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        let Some(user) = body["user"].as_str().map(str::to_owned) else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        // 씨앗 사용자만 된다. 미리보기에서 초대받아 들어온 사람은 링크로 들어온다
        if !self.config.seed_users.contains(&user) {
            return error(StatusCode::NOT_FOUND, "no_such_user");
        }
        let next = safe_next(body["next"].as_str().unwrap_or("/"));
        match pool
            .run(move |store| store.start_session(&user, now()))
            .await
        {
            Ok((session, _)) => {
                let mut response = redirect(&next);
                set_cookie(&mut response, &session_cookie(&session));
                response
            }
            Err(StoreError::Refused(_)) => error(StatusCode::NOT_FOUND, "no_such_user"),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }
}

/// `/_orbital/` 이 받는 JSON 본문. 크기를 넘거나 JSON 이 아니면 `None` 이다.
async fn read_json(request: Request<Incoming>) -> Option<Value> {
    let bytes = Limited::new(request.into_body(), BODY_LIMIT)
        .collect()
        .await
        .ok()?
        .to_bytes();
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 앱에_넘기는_쿠키에서_레이어의_쿠키만_뺀다() {
        assert_eq!(
            strip_layer_cookies(
                "__Host-orbital-session=abc; theme=dark; __Host-orbital-browser=def"
            ),
            Some("theme=dark".to_owned())
        );
        assert_eq!(strip_layer_cookies("__Host-orbital-session=abc"), None);
        // 이름이 비슷해도 레이어의 것이 아니면 남긴다
        assert_eq!(
            strip_layer_cookies("orbital-session=x;__Host-orbitalx=y"),
            Some("orbital-session=x; __Host-orbitalx=y".to_owned())
        );
    }

    #[test]
    fn 앱에_넘기는_머리말에서_밖에서_온_x_orbital_과_연결의_머리말을_지운다() {
        let mut headers = HeaderMap::new();
        headers.insert("x-orbital-identity", HeaderValue::from_static("v1.aa.bb"));
        headers.insert("X-Orbital-Stage", HeaderValue::from_static("production"));
        headers.insert("x-request-id", HeaderValue::from_static("r1"));
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("s"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-orbital-session=abc; theme=dark"),
        );
        clean_request_headers(&mut headers);
        assert!(headers.get("x-orbital-identity").is_none());
        assert!(headers.get("x-orbital-stage").is_none());
        assert!(headers.get("x-secret").is_none());
        assert!(headers.get(header::CONNECTION).is_none());
        assert_eq!(headers["x-request-id"], "r1");
        assert_eq!(headers[header::COOKIE], "theme=dark");
    }

    #[test]
    fn 앱은_레이어의_쿠키를_심지_못한다() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("__Host-orbital-session=attacker; Path=/; Secure"),
        );
        headers.append(header::SET_COOKIE, HeaderValue::from_static("theme=dark"));
        clean_response_headers(&mut headers);
        let left: Vec<_> = headers.get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(left, vec!["theme=dark"]);
    }

    #[test]
    fn 질의에서_토큰을_꺼낸다() {
        assert_eq!(query_value("a=1&token=ff&b=2", "token"), Some("ff"));
        assert_eq!(query_value("xtoken=ff", "token"), None);
        assert_eq!(query_value("", "token"), None);
    }

    #[test]
    fn 파일에_쌓는_메일함은_주인만_읽는다() {
        use std::os::unix::fs::PermissionsExt as _;
        let path =
            std::env::temp_dir().join(format!("orbital-outbox-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let outbox = Outbox::new(&path);
        outbox.send(Mail {
            to: "kim@example.com".to_owned(),
            link: "http://127.0.0.1:1/_orbital/auth/callback?token=ab".to_owned(),
        });
        outbox.send(Mail {
            to: "lee@example.com".to_owned(),
            link: "x".to_owned(),
        });
        let mails = Outbox::read(&path);
        assert_eq!(mails.len(), 2);
        assert_eq!(mails[0].to, "kim@example.com");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_file(&path);
    }
}
