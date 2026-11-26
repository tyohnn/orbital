//! router. 인스턴스(프리뷰나 운영)마다 하나가 선다. 포트 하나를 듣거나([`serve`]), 레이어의 주소 하나를 하위 도메인으로 나눠 듣는다([`serve_hosts`]).
//! 서버 서비스는 요청이 없으면 자고 첫 요청에 깬다([`AppServer`]).
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
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use orbital_core::auth::{
    Admission, InvitationRefusal, LinkRefusal, SESSION_TTL, admit, fallback_file, is_public, route,
    safe_next, same_origin, schedule_path, static_file, wants_page,
};
use orbital_core::host::{BaseDomain, HostTarget, judge_host};
use orbital_core::manifest::{Auth, ValidManifest};
use orbital_core::name::Ident;
use orbital_core::oauth::is_mcp_path;
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
/// 레이어가 일정으로 부른 요청에 싣는 머리말. 값은 그 일정을 가리킨다(`Schedule::key`). 밖에서 온 것은 언제나 지우므로 router 만 붙인다.
pub const SCHEDULE_HEADER: &str = "x-orbital-schedule";
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

mod oauth;
mod wake;
pub use wake::{AppServer, Starter, WakeFailure, start_on_free_port};

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

/// 메일을 보내지 못한 까닭. router 의 기록에는 이 갈래와 상태만 적는다(키 · 받는 주소 · 링크는 적지 않는다).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailFailure {
    /// 팩토리가 메일 발송의 키를 넣지 않았다(넣었다가 지웠다).
    NotConfigured,
    /// 발송기에 닿지 못했거나 시간이 넘었다.
    Unreachable,
    /// 발송기가 거절했다. HTTP 상태다.
    Rejected { status: u16 },
}

impl std::fmt::Display for MailFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("not_configured"),
            Self::Unreachable => f.write_str("unreachable"),
            Self::Rejected { status } => write!(f, "rejected {status}"),
        }
    }
}

/// 로그인 링크를 보내는 것. 운영에서는 팩토리의 키로 보내고([`Resend`]), 개발용은 보내는 대신 쌓는다. 프리뷰의 router 는 부르지 않는다.
pub trait Mailer: Send + Sync {
    /// 한 통을 보낸다. 실패해도 링크 요청의 답은 같고, router 는 까닭의 갈래만 기록에 남긴다.
    fn send(&self, mail: Mail) -> Result<(), MailFailure>;
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
    fn send(&self, mail: Mail) -> Result<(), MailFailure> {
        if let Ok(mut mails) = self.mails.lock() {
            mails.push(mail);
        }
        Ok(())
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
    fn send(&self, mail: Mail) -> Result<(), MailFailure> {
        let _guard = self.lock.lock();
        let line = json!({ "to": mail.to, "link": mail.link }).to_string();
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| writeln!(file, "{line}"))
            .map_err(|_| MailFailure::Unreachable)
    }
}

mod resend;
pub use resend::{LoginMail, Resend, ResendKey, login_mail};

mod google;
pub use google::GoogleDoor;

// ---- Client ID Metadata Documents 받아 오기 ----

/// metadata 문서를 받아 오지 못한 까닭. 어느 것이든 그 클라이언트를 모르는 것으로 다룬다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// 주소가 사설망 · 이 기계 · 링크 로컬을 가리키거나 `https` 가 아니다.
    Refused,
    /// 닿지 못했거나 시간이 넘었다.
    Unreachable,
    /// 200 이 아니다(넘겨주기도 따라가지 않는다).
    NotOk,
    /// 상한(64KB)을 넘는다.
    TooLarge,
}

/// metadata 문서를 받아 오는 자리. 갈아 끼운다. 테스트는 가짜를, `orbitald` 는 [`HttpsFetcher`] 를 쓴다.
pub trait DocumentFetcher: Send + Sync {
    fn fetch(&self, url: &str) -> Result<Fetched, FetchError>;
}

/// 받아 온 문서와, 얼마나 기억해도 되는지 그 답이 말한 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub body: Vec<u8>,
    /// 답의 `Cache-Control`. 얼마나 기억할지는 core 의 `document_lifetime` 이 정한다.
    pub cache_control: Option<String>,
}

/// 실제로 받아 오는 것. `https` 만, 넘겨주기(redirect)를 따라가지 않고, 5초, 64KB 까지.
///
/// 주소의 모양은 core 의 `document_url` 이 먼저 본다. 이름이 실제로 가리키는 주소는 여기서 이름을 풀 때 다시 본다.
/// 사설망 · 이 기계 · 링크 로컬로 풀리는 주소는 버리고 남은 주소로만 붙는다(이름을 푼 뒤 바꿔치는 공격을 막는다).
#[derive(Debug, Default)]
pub struct HttpsFetcher;

/// 문서의 상한.
const DOCUMENT_LIMIT: u64 = 64 * 1024;

/// 공인 주소로만 풀어 준다.
struct PublicResolver;

/// 이 주소가 사설망 · 이 기계 · 링크 로컬 · 예약된 것인가.
pub fn private_address(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => orbital_core::oauth::private_ipv4(v4.octets()),
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| orbital_core::oauth::private_ipv4(v4.octets()))
        }
    }
}

impl ureq::Resolver for PublicResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs as _;
        let public: Vec<std::net::SocketAddr> = netloc
            .to_socket_addrs()?
            .filter(|address| !private_address(&address.ip()))
            .collect();
        if public.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "사설 주소로만 풀린다",
            ));
        }
        Ok(public)
    }
}

impl DocumentFetcher for HttpsFetcher {
    fn fetch(&self, url: &str) -> Result<Fetched, FetchError> {
        use std::io::Read as _;
        if orbital_core::oauth::document_url(url).is_err() {
            return Err(FetchError::Refused);
        }
        let agent = ureq::AgentBuilder::new()
            .https_only(true)
            .redirects(0)
            .timeout(std::time::Duration::from_secs(5))
            .resolver(PublicResolver)
            .build();
        let response = match agent.get(url).set("Accept", "application/json").call() {
            Ok(response) => response,
            Err(ureq::Error::Status(_, _)) => return Err(FetchError::NotOk),
            Err(ureq::Error::Transport(_)) => return Err(FetchError::Unreachable),
        };
        if response.status() != 200 {
            return Err(FetchError::NotOk);
        }
        let cache_control = response.header("cache-control").map(str::to_owned);
        let mut body = Vec::new();
        response
            .into_reader()
            .take(DOCUMENT_LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|_| FetchError::Unreachable)?;
        if body.len() as u64 > DOCUMENT_LIMIT {
            return Err(FetchError::TooLarge);
        }
        Ok(Fetched {
            body,
            cache_control,
        })
    }
}

// ---- 설정 ----

/// router 가 선 자리. 씨앗 사용자로 들어가는 길은 프리뷰에만 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Preview,
    Production,
}

/// 서비스 하나가 요청을 받는 자리. 서버의 포트는 router 만 알고 밖에 알리지 않는다.
#[derive(Clone)]
pub enum Target {
    /// 서버 서비스. 자고 있으면 첫 요청에 깨운다.
    Server(Arc<AppServer>),
    Static {
        folder: PathBuf,
    },
    /// 아직 빌드하는 중이다. 503 과 `Retry-After` 로 답한다(관리 서버가 빌드 폴더 없이 다시 떴을 때).
    Pending,
}

/// 일정으로 부른 결과. 숫자와 갈래만 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Called {
    /// 앱이 답했다. 상태 코드다.
    Answered(u16),
    /// 서비스를 깨우지 못했거나 앱에 닿지 못했다.
    Unreachable,
    /// 정한 시간 안에 답하지 않았다.
    TimedOut,
}

/// 인증 역할의 연결을 새로 여는 것.
pub type Connect = Arc<dyn Fn() -> Result<AuthStore, AuthError> + Send + Sync>;

pub struct Config {
    /// router 의 바깥 주소(`http://127.0.0.1:4100` 이거나 하위 도메인 `https://<인스턴스>.<기준 도메인>`).
    /// 링크의 주소 · `Origin` 검사 · OAuth 의 발급자가 이것을 쓴다. 요청의 `Host` 로 짓지 않는다.
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
    /// 프리뷰의 씨앗 사용자. 이 식별자로만 링크 없이 들어간다.
    pub seed_users: Vec<String>,
    /// 요청마다 한 줄(메서드, 질의를 뗀 경로, 상태)을 적는 파일.
    pub log: Option<PathBuf>,
    /// Client ID Metadata Documents 를 받아 오는 것.
    pub documents: Arc<dyn DocumentFetcher>,
    /// Google 로 들어가는 문. 운영에서 `google` 을 선언했을 때만 있다. 팩토리의 키는 문을 열 때마다 읽는다.
    pub google: Option<Arc<dyn GoogleDoor>>,
}

// ---- 인증 역할의 연결 풀 ----

/// 누구의 요청인지 확인한 것. 브라우저의 세션이면 세션의 이름(`sid`)이, MCP 의 토큰이면 클라이언트(`cid`)가 있다.
struct Signed {
    user: SessionUser,
    session: Option<String>,
    client: Option<String>,
}

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
            // 연결이 끊겼으면(운영 DB 의 문을 잠깐 닫는 리허설 같은) 한 번만 새로 열어 다시 한다
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

/// 다른 주소의 브라우저가 부를 수 있는 주소와 그 방법. 쿠키를 보지 않는 주소(메타데이터 · 토큰 · 동적 등록)뿐이다.
///
/// 로그인 · 동의 · 승인 목록처럼 세션 쿠키로 사람을 알아보는 주소는 여기에 넣지 않는다.
fn cross_origin_methods(path: &str) -> Option<&'static str> {
    if path.starts_with("/.well-known/oauth-") {
        return Some("GET, OPTIONS");
    }
    match path {
        "/_orbital/oauth/token" | "/_orbital/oauth/register" => Some("POST, OPTIONS"),
        _ => None,
    }
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
    log: Arc<Mutex<()>>,
}

/// 기록의 파일과 그 자물쇠. 요청 밖에서 도는 일이 들고 다닌다.
#[derive(Clone)]
struct Note {
    log: Option<PathBuf>,
    lock: Arc<Mutex<()>>,
}

impl Note {
    /// 한 줄을 적는다. 값(받는 주소 · 링크 · 키)을 싣지 않는 갈래와 이름만 넘긴다.
    fn line(&self, text: &str) {
        let Some(log) = &self.log else {
            return;
        };
        let _guard = self.lock.lock();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log) {
            let _ = writeln!(file, "{text}");
        }
    }
}

/// 인스턴스(프리뷰나 운영) 하나의 router. 포트 하나를 듣거나([`serve`]), 여러 인스턴스가 주소 하나를 나눠 듣는다([`serve_hosts`]).
#[derive(Clone)]
pub struct Router {
    state: Arc<State>,
}

impl Router {
    pub fn new(config: Config) -> Self {
        let pool = config.auth.clone().map(|connect| {
            Arc::new(Pool {
                connect,
                idle: Mutex::new(Vec::new()),
                permits: Semaphore::new(POOL_SIZE),
            })
        });
        let log = Arc::new(Mutex::new(()));
        let note = Note {
            log: config.log.clone(),
            lock: Arc::clone(&log),
        };
        for target in config.targets.values() {
            if let Target::Server(server) = target {
                server.attach(note.clone());
            }
        }
        Self {
            state: Arc::new(State { config, pool, log }),
        }
    }

    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// 선언의 일정 하나를 부른다. 그 서비스가 자고 있으면 깨워 `POST` 로 보내고, [`SCHEDULE_HEADER`] 에 `key` 를 싣는다.
    /// 사람의 신원과 쿠키는 싣지 않는다. `role` 이 있으면 사람 없이 그 업무 역할만 실린 서명된 신원을 싣고, 그 수명은 `limit` 이다.
    /// 밖에서 온 요청이 아니라 레이어가 부른 것이라 일정의 경로를 막지 않는다(밖에서는 그 경로도, 이 신원도 닿지 못한다).
    /// 다시 부르지 않는다. 결과는 router 의 기록에 `SCHEDULE <서비스> <경로> <갈래> <상태>` 로만 남긴다.
    pub async fn call_schedule(
        &self,
        service: &str,
        path: &str,
        key: &str,
        role: Option<&Ident>,
        limit: Duration,
    ) -> Called {
        let called = self
            .state
            .call_schedule(service, path, key, role, limit)
            .await;
        let (outcome, status) = match called {
            Called::Answered(status) if (200..300).contains(&status) => ("ok", status.to_string()),
            Called::Answered(status) => ("failed", status.to_string()),
            Called::Unreachable => ("unreachable", "-".to_owned()),
            Called::TimedOut => ("timed_out", "-".to_owned()),
        };
        self.state
            .note()
            .line(&format!("SCHEDULE {service} {path} {outcome} {status}"));
        called
    }
}

/// 받은 연결마다 요청을 듣는다. 요청마다 어느 router 가 답할지 `pick` 이 고른다. 이 future 를 내리면(abort) 붙어 있던 연결도 모두 내린다.
async fn accept<F>(listener: TcpListener, pick: Arc<F>) -> std::io::Result<()>
where
    F: Fn(&Request<Incoming>) -> Option<Router> + Send + Sync + 'static,
{
    let mut connections = JoinSet::new();
    loop {
        let (stream, _) = listener.accept().await?;
        while connections.try_join_next().is_some() {}
        let pick = Arc::clone(&pick);
        connections.spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let router = pick(&request);
                async move {
                    Ok::<_, Infallible>(match router {
                        Some(router) => router.state.handle(request).await,
                        None => error(StatusCode::NOT_FOUND, "not_found"),
                    })
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// 인스턴스 하나의 router 가 포트 하나를 듣는다(기준 도메인을 주지 않은 레이어).
pub async fn serve(listener: TcpListener, config: Config) -> std::io::Result<()> {
    serve_slot(listener, Arc::new(RwLock::new(Router::new(config)))).await
}

/// 자리(`slot`)에 든 router 가 포트 하나를 듣는다. 레이어는 듣기를 멈추지 않고 자리의 router 만 바꿔 넣는다
/// (빌드하는 동안 503 으로 답하던 router 를 빌드가 끝난 router 로). 요청마다 그때 든 router 가 답한다.
pub async fn serve_slot(listener: TcpListener, slot: Arc<RwLock<Router>>) -> std::io::Result<()> {
    accept(
        listener,
        Arc::new(move |_: &Request<Incoming>| slot.read().ok().map(|router| router.clone())),
    )
    .await
}

/// 인스턴스마다의 하위 도메인. 주소 하나에서 `Host` 로 router 를 고른다.
pub struct Hosts {
    base: BaseDomain,
    routers: RwLock<BTreeMap<HostTarget, Router>>,
}

impl Hosts {
    pub fn new(base: BaseDomain) -> Arc<Self> {
        Arc::new(Self {
            base,
            routers: RwLock::new(BTreeMap::new()),
        })
    }

    /// 그 곳의 router 를 세운다. 앞의 것은 바뀐다.
    pub fn insert(&self, target: HostTarget, router: &Router) {
        if let Ok(mut routers) = self.routers.write() {
            routers.insert(target, router.clone());
        }
    }

    /// 그 곳의 router 가 이것일 때만 걷는다. 뒤에 세운 것을 앞의 것이 걷지 않게 한다.
    pub fn remove(&self, target: &HostTarget, router: &Router) {
        if let Ok(mut routers) = self.routers.write()
            && routers.get(target).is_some_and(|known| known.same(router))
        {
            routers.remove(target);
        }
    }

    /// 요청이 가는 router. `Host` 머리말만 보고(`X-Forwarded-Host` 같은 것은 믿지 않는다), 판정(대소문자와 끝의 점을 접는 것까지)은 core 가 한다.
    /// 요청 줄에 주소를 적었으면(absolute-form) 그 주소가 `Host` 와 대소문자만 빼고 같아야 한다.
    fn pick(&self, request: &Request<Incoming>) -> Option<Router> {
        let host = request.headers().get(header::HOST)?.to_str().ok()?;
        if let Some(authority) = request.uri().authority()
            && !authority.as_str().eq_ignore_ascii_case(host)
        {
            return None;
        }
        let target = judge_host(host, &self.base)?;
        self.routers.read().ok()?.get(&target).cloned()
    }
}

/// 주소 하나에서 모든 인스턴스의 요청을 받고 `Host` 로 가른다. 모르는 호스트와 기준 도메인 자체는 404 다.
pub async fn serve_hosts(listener: TcpListener, hosts: Arc<Hosts>) -> std::io::Result<()> {
    accept(
        listener,
        Arc::new(move |request: &Request<Incoming>| hosts.pick(request)),
    )
    .await
}

/// 서비스에 들어가 있는 동안의 표를 쥔 답의 본문. 본문이 끝까지 나가 떨어질 때 처리 중인 수가 준다.
struct Held {
    inner: Body,
    _visit: wake::Visit,
}

impl hyper::body::Body for Held {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.inner).poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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

    /// 기록에 한 줄을 더하는 것. 요청과 따로 도는 일(뒤에서 보내는 메일)이 들고 간다.
    fn note(&self) -> Note {
        Note {
            log: self.config.log.clone(),
            lock: Arc::clone(&self.log),
        }
    }

    fn declares(&self, method: &str) -> bool {
        self.config
            .manifest
            .get()
            .auth
            .as_ref()
            .is_some_and(|auth| auth.uses(method))
    }

    async fn answer(&self, request: Request<Incoming>) -> Response<Body> {
        // 쿠키를 보지 않는 주소만 다른 주소의 브라우저에 연다. 자격 증명(credentials)은 열지 않으니 쿠키는 실리지 않는다
        let Some(methods) = cross_origin_methods(request.uri().path()) else {
            return self.dispatch(request).await;
        };
        let mut response = if request.method() == Method::OPTIONS {
            let mut preflight = Response::new(empty());
            *preflight.status_mut() = StatusCode::NO_CONTENT;
            let headers = preflight.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(methods),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type, mcp-protocol-version"),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
            preflight
        } else {
            self.dispatch(request).await
        };
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response
    }

    async fn dispatch(&self, request: Request<Incoming>) -> Response<Body> {
        let path = request.uri().path().to_owned();
        // 인가 서버와 자원 서버의 메타데이터는 서비스로 보내지 않고 router 가 답한다
        if path.starts_with("/.well-known/oauth-") {
            return self.well_known(&path);
        }
        if path == "/_orbital" || path.starts_with("/_orbital/") {
            return self.layer(request).await;
        }
        let manifest = &self.config.manifest;
        // 선언에 적은 일정의 경로는 레이어만 부른다. 밖에서 온 요청은 없는 것과 같이 답한다
        if schedule_path(manifest, &path) {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
        let Some(service) = route(manifest, &path) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let Some(target) = self.config.targets.get(service.name.as_str()) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        if let Target::Pending = target {
            let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "building");
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            return response;
        }
        // MCP 의 주소는 쿠키를 보지 않고 Bearer 토큰만 본다. 다른 사이트가 사용자의 쿠키로 MCP 를 부르지 못하게 한다
        if is_mcp_path(manifest, &path)
            && let Target::Server(server) = target
        {
            return self.mcp_request(request, server).await;
        }
        // 공개 경로는 세션을 보지 않는다. 신원을 싣지 않으니 읽을 까닭이 없다
        let user = if is_public(service, &path) {
            None
        } else {
            match self.signed_in(request.headers()).await {
                Ok(user) => user,
                Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            }
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
            // 공개 경로에는 세션이 있어도 신원을 싣지 않는다
            Admission::Public => {
                return match target {
                    Target::Static { folder } => {
                        Self::file(folder, &path, service, request.method(), page).await
                    }
                    Target::Server(server) => self.forward(request, server, None).await,
                    Target::Pending => error(StatusCode::SERVICE_UNAVAILABLE, "building"),
                };
            }
            Admission::ToLogin { location } => return redirect(&location),
            Admission::Unauthorized => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        }
        match target {
            Target::Static { folder } => {
                Self::file(folder, &path, service, request.method(), page).await
            }
            Target::Server(server) => self.forward(request, server, user.as_ref()).await,
            Target::Pending => error(StatusCode::SERVICE_UNAVAILABLE, "building"),
        }
    }

    /// 세션 쿠키의 사용자. 쿠키가 없거나 세션이 없는 것이면 `None` 이다. DB 에 닿지 못하면 `Err` 이다.
    async fn signed_in(&self, headers: &HeaderMap) -> Result<Option<Signed>, Unavailable> {
        let Some(pool) = &self.pool else {
            return Ok(None);
        };
        let Some(token) = cookie(headers, SESSION_COOKIE).and_then(|text| Secret::parse(&text))
        else {
            return Ok(None);
        };
        let session = token.session_id();
        match pool.run(move |store| store.session(&token, now())).await {
            Ok(user) => Ok(user.map(|user| Signed {
                user,
                session: Some(session),
                client: None,
            })),
            Err(StoreError::Refused(_)) => Ok(None),
            Err(StoreError::Unavailable) => Err(Unavailable),
        }
    }

    /// 폴더 안의 파일 하나. 조각은 core 가 걸렀다. 심볼릭 링크가 폴더 밖을 가리킬 수 있으니 실제 경로가 폴더 안인지 다시 본다.
    fn inside(folder: &Path, parts: &[String]) -> Option<PathBuf> {
        let candidate = parts
            .iter()
            .fold(folder.to_path_buf(), |at, part| at.join(part));
        let (Ok(root), Ok(real)) = (fs::canonicalize(folder), fs::canonicalize(&candidate)) else {
            return None;
        };
        (real.starts_with(&root) && real.is_file()).then_some(real)
    }

    /// 정적 서비스의 파일을 내준다. 없고 화면을 원하는 요청이면 선언의 `fallback` 을 내준다(core 의 `fallback_file`).
    async fn file(
        folder: &Path,
        path: &str,
        service: &orbital_core::manifest::Service,
        method: &Method,
        page: bool,
    ) -> Response<Body> {
        if method != Method::GET && method != Method::HEAD {
            return error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        }
        let Some(parts) = static_file(path, &service.path) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let found = Self::inside(folder, &parts).or_else(|| {
            fallback_file(service, path, page).and_then(|fallback| Self::inside(folder, &fallback))
        });
        let Some(real) = found else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
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

    /// 서버 서비스로 흘려보낸다. 본문은 버퍼에 담지 않는다. 서비스가 자고 있으면 깨운 뒤에 넘기고, 깨우지 못하면 503 이다.
    async fn forward(
        &self,
        request: Request<Incoming>,
        server: &Arc<AppServer>,
        signed: Option<&Signed>,
    ) -> Response<Body> {
        let visit = match server.enter().await {
            Ok(visit) => visit,
            Err(failure) => {
                let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "waking");
                let headers = response.headers_mut();
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
                if failure == WakeFailure::Overloaded {
                    // 넘친 요청의 연결은 붙잡지 않는다
                    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
                }
                return response;
            }
        };
        let port = visit.port;
        let (mut parts, body) = request.into_parts();
        clean_request_headers(&mut parts.headers);
        if let Some(Signed {
            user,
            session,
            client,
        }) = signed
        {
            // 업무 역할은 이번 요청에서 표로 읽은 것이다. 역할을 거두면 다음 요청의 신원에서 빠진다
            let identity = sign(
                &self.config.identity_key,
                &self.config.names,
                &Claims {
                    subject: Some(user.id.clone()),
                    roles: user.roles.clone(),
                    session: session.clone(),
                    client: client.clone(),
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
        match visit.client.clone().request(upstream).await {
            Ok(answer) => {
                let (mut parts, body) = answer.into_parts();
                clean_response_headers(&mut parts.headers);
                let held = Held {
                    inner: body.boxed(),
                    _visit: visit,
                };
                Response::from_parts(parts, held.boxed())
            }
            Err(_) => error(StatusCode::BAD_GATEWAY, "bad_gateway"),
        }
    }

    /// [`Router::call_schedule`] 의 몸. 기록은 부른 쪽이 남긴다.
    async fn call_schedule(
        &self,
        service: &str,
        path: &str,
        key: &str,
        role: Option<&Ident>,
        limit: Duration,
    ) -> Called {
        let Some(Target::Server(server)) = self.config.targets.get(service) else {
            return Called::Unreachable;
        };
        let call = async {
            let Ok(visit) = server.enter().await else {
                return Called::Unreachable;
            };
            let (Ok(uri), Ok(value)) = (
                format!("http://127.0.0.1:{}{path}", visit.port).parse::<hyper::Uri>(),
                HeaderValue::from_str(key),
            ) else {
                return Called::Unreachable;
            };
            let mut request = Request::new(empty());
            *request.method_mut() = Method::POST;
            *request.uri_mut() = uri;
            let headers = request.headers_mut();
            headers.insert(SCHEDULE_HEADER, value);
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            if let Some(role) = role {
                // 사람 없이 그 역할만 실린 신원. 일정이 답하기를 기다리는 만큼만 통한다
                let identity = sign(
                    &self.config.identity_key,
                    &self.config.names,
                    &Claims::for_role(role, now() + limit.as_secs().max(1)),
                );
                if let Ok(value) = HeaderValue::from_str(&identity) {
                    headers.insert(IDENTITY_HEADER, value);
                }
            }
            match visit.client.clone().request(request).await {
                Ok(answer) => {
                    let status = answer.status().as_u16();
                    // 본문은 읽어 버린다. 다 읽어야 연결과 처리 중의 수가 풀린다
                    let _ = answer.into_body().collect().await;
                    Called::Answered(status)
                }
                Err(_) => Called::Unreachable,
            }
        };
        tokio::time::timeout(limit, call)
            .await
            .unwrap_or(Called::TimedOut)
    }

    // ---- /_orbital/ ----

    async fn layer(&self, request: Request<Incoming>) -> Response<Body> {
        // [auth] 를 선언하지 않은 인스턴스에는 레이어의 길이 없다
        let Some(pool) = self.pool.clone() else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        if path.starts_with("/_orbital/oauth/") {
            return self.oauth(request, pool).await;
        }
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
            (Method::POST, "/_orbital/auth/email-link") if self.declares(Auth::EMAIL_LINK) => {
                self.email_link(request, pool).await
            }
            (Method::GET, "/_orbital/auth/callback") => self.callback(&request, pool).await,
            (Method::GET, "/_orbital/auth/google/start") if self.declares(Auth::GOOGLE) => {
                self.google_start(request.headers(), request.uri().query())
            }
            (Method::GET, "/_orbital/auth/google/finish") if self.declares(Auth::GOOGLE) => {
                self.google_finish(&request, pool).await
            }
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
        let Some((browser, planted)) = Self::browser(request.headers()) else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        };
        let Some(body) = read_json(request).await else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        let Some(email) = body["email"].as_str().map(str::trim).map(str::to_owned) else {
            return error(StatusCode::BAD_REQUEST, "bad_request");
        };
        let next = body["next"].as_str().unwrap_or("/").to_owned();
        // 표식이 없으면 심는다. 초대됐는지와 상관없이 같은 머리말이 나간다
        let asked = email.clone();
        let made = pool
            .run(move |store| store.request_link(&asked, &next, &browser, now()))
            .await;
        match made {
            // 프리뷰에서는 메일을 보내지 않는다. 프리뷰의 사람은 씨앗 사용자로 들어간다
            Ok(Some(_)) if self.config.stage == Stage::Preview => {}
            Ok(Some(token)) => {
                let mail = Mail {
                    to: email,
                    link: format!(
                        "{}/_orbital/auth/callback?token={}",
                        self.config.origin,
                        token.to_text()
                    ),
                };
                let mailer = Arc::clone(&self.config.mailer);
                let note = self.note();
                // 답을 먼저 보내고 메일은 뒤에서 보낸다. 발송을 기다리면 초대된 쪽만 늦어져 걸린 시간으로 초대 여부를 짐작할 수 있다.
                // 발송기는 동기 HTTP 라 일꾼을 막지 않게 따로 돌린다. 보내지 못해도 답은 같고, 기록에는 갈래와 상태만 남긴다
                tokio::task::spawn_blocking(move || {
                    if let Err(failure) = mailer.send(mail) {
                        note.line(&format!("MAIL {failure}"));
                    }
                });
            }
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
        let Some(token) = token else {
            return self.refused("invalid");
        };
        let Some(browser) = browser else {
            return self.refused("other_browser");
        };
        let entered = pool
            .run(move |store| store.enter(&token, &browser, now()))
            .await;
        self.entered(entered)
    }

    /// 브라우저의 표식. 없으면 새로 짓고 심을 쿠키를 함께 돌려준다.
    fn browser(headers: &HeaderMap) -> Option<(Secret, Option<String>)> {
        match cookie(headers, BROWSER_COOKIE).and_then(|text| Secret::parse(&text)) {
            Some(browser) => Some((browser, None)),
            None => {
                let browser = Secret::generate().ok()?;
                let cookie = browser_cookie(&browser);
                Some((browser, Some(cookie)))
            }
        }
    }

    /// Google 로 보낸다. 브라우저의 표식을 심고(이메일 링크와 같은 쿠키), 레이어가 서명한 `state` 를 실은 Google 의 주소로 302 한다.
    /// 팩토리가 Google 의 키를 넣지 않았거나 지웠으면 404 다.
    fn google_start(&self, headers: &HeaderMap, query: Option<&str>) -> Response<Body> {
        let Some(door) = &self.config.google else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let next = query
            .and_then(|query| orbital_core::auth::query_value(query, "next"))
            .map_or_else(|| "/".to_owned(), |next| safe_next(&next));
        let Some((browser, planted)) = Self::browser(headers) else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        };
        let Some(location) = door.authorize(&next, &browser) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let mut response = redirect(&location);
        if let Some(cookie) = planted {
            set_cookie(&mut response, &cookie);
        }
        response
    }

    /// 레이어의 콜백이 낸 한 번 쓰는 표로 들어온다. 그 표를 받은 브라우저에서, 60초 안에, 한 번만 된다.
    async fn google_finish(&self, request: &Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        if self.config.google.is_none() {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
        let ticket = request
            .uri()
            .query()
            .and_then(|query| query_value(query, "ticket"))
            .and_then(Secret::parse);
        let browser =
            cookie(request.headers(), BROWSER_COOKIE).and_then(|text| Secret::parse(&text));
        let Some(ticket) = ticket else {
            return self.refused("invalid");
        };
        let Some(browser) = browser else {
            return self.refused("other_browser");
        };
        let entered = pool
            .run(move |store| store.enter_google(&ticket, &browser, now()))
            .await;
        self.entered(entered)
    }

    /// 들어오지 못했다. 로그인 화면에 까닭의 코드를 실어 보낸다.
    fn refused(&self, code: &str) -> Response<Body> {
        let mut response = redirect(&format!("{}?error={code}", self.login_path()));
        // 토큰이 든 주소가 다음 화면의 Referer 로 새지 않게 한다
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        response
    }

    /// 링크나 표로 들어온 결과를 답으로 옮긴다. 들어왔으면 세션 쿠키를 심고 돌아갈 곳으로 보낸다.
    fn entered(&self, entered: Result<orbital_pg::auth::Entered, StoreError>) -> Response<Body> {
        match entered {
            Ok(entered) => {
                let mut response = redirect(&entered.next);
                response.headers_mut().insert(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                );
                set_cookie(&mut response, &session_cookie(&entered.session));
                response
            }
            Err(StoreError::Refused(refusal)) => self.refused(match refusal {
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
            Ok(Some(Signed { user, .. })) => json_reply(
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
        // 씨앗 사용자만 된다. 프리뷰에서 초대받아 들어온 사람은 링크로 들어온다
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
    fn metadata_문서를_받아_오는_실제_구현은_https_가_아니거나_사설_주소면_붙지도_않는다() {
        for refused in [
            "http://client.example/c.json",
            "https://127.0.0.1/c.json",
            "https://10.0.0.5/c.json",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost/c.json",
            "https://client.example/",
        ] {
            assert_eq!(
                HttpsFetcher.fetch(refused),
                Err(FetchError::Refused),
                "{refused}"
            );
        }
        // 이름이 이 기계로 풀리면 붙지 않는다(이름을 푼 뒤에도 본다)
        assert!(ureq::Resolver::resolve(&PublicResolver, "localhost:443").is_err());
        for (address, private) in [
            ("127.0.0.1", true),
            ("10.1.2.3", true),
            ("172.20.0.1", true),
            ("192.168.0.1", true),
            ("169.254.169.254", true),
            ("100.64.0.1", true),
            ("::1", true),
            ("fd12::1", true),
            ("fe80::1", true),
            ("::ffff:10.0.0.1", true),
            ("8.8.8.8", false),
            ("2001:4860:4860::8888", false),
        ] {
            assert_eq!(
                private_address(&address.parse().unwrap()),
                private,
                "{address}"
            );
        }
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
        outbox
            .send(Mail {
                to: "kim@example.com".to_owned(),
                link: "http://127.0.0.1:1/_orbital/auth/callback?token=ab".to_owned(),
            })
            .unwrap();
        outbox
            .send(Mail {
                to: "lee@example.com".to_owned(),
                link: "x".to_owned(),
            })
            .unwrap();
        let mails = Outbox::read(&path);
        assert_eq!(mails.len(), 2);
        assert_eq!(mails[0].to, "kim@example.com");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_file(&path);
    }
}
