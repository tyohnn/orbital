//! MCP 용 OAuth 2.1 의 판정. 인가 요청 · PKCE · redirect · 인가 코드 · 토큰 · Client ID Metadata Documents · 동적 등록.
//!
//! 인가 서버는 인스턴스마다 따로이고 발급자(`iss`)는 그 router 의 주소다. 저장과 무작위 값은 `orbital-pg` 가, 받아 오는 일은
//! router 가 맡고, 여기서는 읽어 온 상태와 받은 글자를 판정만 한다. 시각은 인자로 받는 유닉스 초이고 경계는 `now < expires_at` 이다.
//! PKCE 의 SHA-256 은 런타임 의존을 늘리지 않으려고 여기에 직접 둔다(FIPS 180-4).

use serde::{Deserialize, Serialize};

use crate::manifest::{Mcp, ValidManifest, trim_path, under};

/// 인가 코드가 읽히는 시간. 5분.
pub const CODE_TTL: u64 = 5 * 60;
/// access 토큰이 읽히는 시간. 1시간.
pub const ACCESS_TTL: u64 = 60 * 60;
/// refresh 토큰이 읽히는 시간. 30일.
pub const REFRESH_TTL: u64 = 30 * 24 * 60 * 60;
/// 동의를 기다리는 요청이 읽히는 시간. 10분.
pub const REQUEST_TTL: u64 = 10 * 60;
/// 받아 온 metadata 문서를 기억하는 시간. 24시간.
pub const DOCUMENT_TTL: u64 = 24 * 60 * 60;
/// 이 인가 서버가 내는 scope. 지금은 하나다.
pub const SCOPE: &str = "mcp";

// ---- 자원(MCP 주소) ----

/// 이 인스턴스의 MCP 선언. `[auth.mcp]` 가 없으면 없다.
pub fn mcp(manifest: &ValidManifest) -> Option<&Mcp> {
    manifest.get().auth.as_ref()?.mcp.as_ref()
}

/// 이 요청 경로가 MCP 의 주소(와 그 아래)인가. 그 경로는 쿠키를 보지 않고 `Authorization: Bearer` 만 본다.
pub fn is_mcp_path(manifest: &ValidManifest, path: &str) -> bool {
    mcp(manifest).is_some_and(|mcp| under(path, &mcp.path))
}

/// 토큰의 대상 자원(RFC 8707): router 의 주소 + MCP 경로.
pub fn resource_url(origin: &str, mcp: &Mcp) -> String {
    format!("{origin}{}", trim_path(&mcp.path))
}

/// 자원 서버의 메타데이터(RFC 9728)가 서는 경로. 맨 끝에 MCP 경로를 붙인 것과 붙이지 않은 것 둘이다.
pub fn is_resource_metadata_path(mcp: &Mcp, path: &str) -> bool {
    const BASE: &str = "/.well-known/oauth-protected-resource";
    path == BASE || path == format!("{BASE}{}", trim_path(&mcp.path))
}

// ---- 주소 ----

/// 판정에 쓰는 만큼만 나눈 주소. `scheme://host[:port]/path?query#fragment`.
struct Url<'a> {
    scheme: &'a str,
    host: &'a str,
    path: &'a str,
    fragment: bool,
}

fn parse_url(text: &str) -> Option<Url<'_>> {
    if text.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let (scheme, rest) = text.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // 사용자 정보(`user@`)가 든 주소는 받지 않는다. 사람이 읽는 주소와 실제로 가는 곳이 달라진다
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if authority.starts_with('[') {
        &authority[..=authority.find(']')?]
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        return None;
    }
    let tail = &rest[end..];
    let fragment = tail.contains('#');
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    Some(Url {
        scheme,
        host,
        path: &tail[..path_end],
        fragment,
    })
}

fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectProblem {
    NotUrl,
    Fragment,
    NotHttpsOrLocalhost,
}

/// 이 redirect 를 등록할 수 있는가. `https` 이거나, 이 기계(`localhost` · `127.0.0.1` · `[::1]`)의 `http` 여야 한다. 조각(`#`)은 받지 않는다.
pub fn registrable_redirect(uri: &str) -> Result<(), RedirectProblem> {
    let url = parse_url(uri).ok_or(RedirectProblem::NotUrl)?;
    if url.fragment {
        return Err(RedirectProblem::Fragment);
    }
    match url.scheme {
        "https" => Ok(()),
        "http" if is_local_host(url.host) => Ok(()),
        _ => Err(RedirectProblem::NotHttpsOrLocalhost),
    }
}

/// 동의 화면에 보일 redirect 의 자리(`host[:port]`). 사람이 어디로 돌아가는지 알아보게 한다.
pub fn redirect_host(uri: &str) -> Option<String> {
    let (_, rest) = uri.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty() && !authority.contains('@')).then(|| authority.to_owned())
}

/// 인가 요청의 redirect 가 등록된 것 가운데 하나와 글자 하나까지 같은가.
pub fn same_redirect(registered: &[String], given: &str) -> bool {
    registered.iter().any(|known| same_text(known, given))
}

// ---- PKCE ----

/// `BASE64URL(SHA256(verifier))`. 덧붙임(`=`)은 없다.
pub fn s256(verifier: &str) -> String {
    base64url(&sha256(verifier.as_bytes()))
}

/// verifier 가 challenge 에 맞는가. verifier 는 43~128자의 unreserved 글자여야 한다(RFC 7636).
pub fn pkce_matches(challenge: &str, verifier: &str) -> bool {
    valid_verifier(verifier) && same_text(&s256(verifier), challenge)
}

fn unreserved(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && unreserved(verifier)
}

/// S256 의 challenge 모양: SHA-256 을 덧붙임 없이 base64url 로 적은 43자.
fn valid_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn same_text(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..=chunk.len() {
            text.push(char::from(
                ALPHABET[((n >> (18 - 6 * index)) & 63) as usize],
            ));
        }
    }
    text
}

fn sha256(message: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = message.to_vec();
    let bits = (message.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bits.to_be_bytes());
    for block in padded.chunks(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// ---- 인가 요청 ----

/// `GET /_orbital/oauth/authorize` 의 질의.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
}

/// 인가 서버가 아는 클라이언트. 등록됐거나 metadata 문서로 받아 온 것이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownClient {
    pub id: String,
    pub redirect_uris: Vec<String>,
}

/// redirect 로 돌려보내지 않고 인가 서버에서 멈추는 까닭. 공격자가 고른 주소로 사용자를 보내지 않으려는 것이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stop {
    UnknownClient,
    BadRedirect,
}

/// 받아들인 인가 요청. 사용자의 동의를 기다린다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: String,
    pub scope: String,
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Authorize {
    /// 400 으로 여기서 멈춘다.
    Stop {
        reason: Stop,
    },
    /// 그 redirect 로 오류(`error` · `state` · `iss`)를 실어 돌려보낸다.
    Refuse {
        location: String,
    },
    Accept {
        request: Accepted,
    },
}

/// 인가 요청을 판정한다. `client` 는 `client_id` 로 찾은 클라이언트이고, `resource` 는 이 인스턴스의 MCP 주소, `issuer` 는 발급자다.
///
/// 클라이언트와 redirect 를 먼저 본다. 이 둘이 틀리면 그 redirect 로 보내지 않는다. 그 밖의 잘못은 redirect 로 오류를 돌려보낸다.
pub fn judge_authorize(
    query: &AuthorizeQuery,
    client: Option<&KnownClient>,
    resource: &str,
    issuer: &str,
) -> Authorize {
    // 1. 클라이언트와 redirect. 여기가 틀리면 어디로도 보내지 않는다
    let Some(client) = client.filter(|known| query.client_id.as_deref() == Some(known.id.as_str()))
    else {
        return Authorize::Stop {
            reason: Stop::UnknownClient,
        };
    };
    let Some(redirect) = query
        .redirect_uri
        .as_deref()
        .filter(|given| same_redirect(&client.redirect_uris, given))
    else {
        return Authorize::Stop {
            reason: Stop::BadRedirect,
        };
    };
    // 2. 그 밖의 잘못은 등록된 redirect 로 돌려보낸다
    let refuse = |error: &str| {
        let mut params = vec![("error", error)];
        if let Some(state) = &query.state {
            params.push(("state", state));
        }
        params.push(("iss", issuer));
        Authorize::Refuse {
            location: with_params(redirect, &params),
        }
    };
    if query.response_type.as_deref() != Some("code") {
        return refuse("unsupported_response_type");
    }
    let challenge = match (
        &query.code_challenge,
        query.code_challenge_method.as_deref(),
    ) {
        (Some(challenge), Some("S256")) if valid_challenge(challenge) => challenge.clone(),
        _ => return refuse("invalid_request"),
    };
    if query.resource.as_deref() != Some(resource) {
        return refuse("invalid_target");
    }
    let scope = match query.scope.as_deref() {
        None => SCOPE.to_owned(),
        Some(asked) if asked.split(' ').all(|one| one == SCOPE) && !asked.is_empty() => {
            SCOPE.to_owned()
        }
        Some(_) => return refuse("invalid_scope"),
    };
    Authorize::Accept {
        request: Accepted {
            client_id: client.id.clone(),
            redirect_uri: redirect.to_owned(),
            code_challenge: challenge,
            resource: resource.to_owned(),
            scope,
            state: query.state.clone(),
        },
    }
}

/// redirect 에 인가 응답의 값들을 붙인다. 이미 질의가 있으면 `&` 로 잇는다.
pub fn with_params(redirect: &str, params: &[(&str, &str)]) -> String {
    let mut location = redirect.to_owned();
    for (index, (key, value)) in params.iter().enumerate() {
        let joiner = if index == 0 && !redirect.contains('?') {
            '?'
        } else {
            '&'
        };
        location.push(joiner);
        location.push_str(key);
        location.push('=');
        location.push_str(&crate::auth::encode_component(value));
    }
    location
}

/// 승인했을 때 브라우저가 갈 곳: `code` · `state` · `iss`.
pub fn approved_location(request: &Accepted, code: &str, issuer: &str) -> String {
    let mut params = vec![("code", code)];
    if let Some(state) = &request.state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    with_params(&request.redirect_uri, &params)
}

/// 거절했을 때 브라우저가 갈 곳: `error=access_denied` · `state` · `iss`.
pub fn denied_location(request: &Accepted, issuer: &str) -> String {
    let mut params = vec![("error", "access_denied")];
    if let Some(state) = &request.state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    with_params(&request.redirect_uri, &params)
}

// ---- 코드 · 토큰 · 동의를 기다리는 요청 ----

pub fn code_expires_at(created_at: u64) -> u64 {
    created_at.saturating_add(CODE_TTL)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeState {
    pub expires_at: u64,
    pub used_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRefusal {
    Expired,
    /// 이미 썼다. 다시 쓰였으니 그 코드로 낸 토큰을 모두 거둔다.
    Used,
}

/// 이 코드로 지금 토큰을 낼 수 있는가.
pub fn judge_code(code: &CodeState, now: u64) -> Result<(), CodeRefusal> {
    if code.used_at.is_some() {
        return Err(CodeRefusal::Used);
    }
    if now >= code.expires_at {
        return Err(CodeRefusal::Expired);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenState {
    pub expires_at: u64,
    pub revoked: bool,
    /// refresh 토큰을 이미 썼다(갈았다).
    pub used: bool,
    pub grant_revoked: bool,
    pub user_disabled: bool,
    /// 이 토큰을 낸 대상 자원.
    pub resource: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRefusal {
    Expired,
    Revoked,
    /// 이미 쓴 refresh 토큰이 다시 왔다. 그 승인 전체를 거둔다.
    Used,
    UserDisabled,
    OtherResource,
}

/// 이 토큰이 지금 `resource` 에 쓰일 수 있는가. access 토큰과 refresh 토큰이 함께 쓴다.
pub fn judge_token(token: &TokenState, resource: &str, now: u64) -> Result<(), TokenRefusal> {
    if token.user_disabled {
        return Err(TokenRefusal::UserDisabled);
    }
    if token.revoked || token.grant_revoked {
        return Err(TokenRefusal::Revoked);
    }
    if token.used {
        return Err(TokenRefusal::Used);
    }
    if now >= token.expires_at {
        return Err(TokenRefusal::Expired);
    }
    if token.resource != resource {
        return Err(TokenRefusal::OtherResource);
    }
    Ok(())
}

/// 동의를 기다리는 요청을 지금 결정할 수 있는가. 만료 전이고, 아직 정하지 않았어야 한다.
pub fn request_open(expires_at: u64, decided: bool, now: u64) -> bool {
    !decided && now < expires_at
}

// ---- Client ID Metadata Documents ----

/// `client_id` 가 metadata 문서의 주소인가(`https://` 로 시작한다). 아니면 등록된 클라이언트의 식별자다.
pub fn is_document_id(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentUrlProblem {
    NotUrl,
    NotHttps,
    NoPath,
    Fragment,
    PrivateHost,
}

/// metadata 문서의 주소로 받을 수 있는가. `https` 이고, 경로가 있고, 조각이 없고, 이 기계나 사설망을 가리키지 않아야 한다.
///
/// 이름으로 적힌 주소가 실제로 어디로 가는지는 여기서 알 수 없다. 받아 오는 쪽이 이름을 푼 주소를 다시 본다.
pub fn document_url(client_id: &str) -> Result<(), DocumentUrlProblem> {
    let url = parse_url(client_id).ok_or(DocumentUrlProblem::NotUrl)?;
    if url.scheme != "https" {
        return Err(DocumentUrlProblem::NotHttps);
    }
    if url.fragment {
        return Err(DocumentUrlProblem::Fragment);
    }
    if url.path.is_empty() || url.path == "/" {
        return Err(DocumentUrlProblem::NoPath);
    }
    let host = url.host.to_ascii_lowercase();
    // IPv6 주소는 사설인지 가리는 규칙이 길어 모두 받지 않는다. 이름이나 공인 IPv4 로 적어야 한다
    let private = host == "localhost"
        || host.ends_with(".localhost")
        || host.starts_with('[')
        || ipv4_literal(&host).is_some_and(private_ipv4);
    if private {
        return Err(DocumentUrlProblem::PrivateHost);
    }
    Ok(())
}

/// 이 IPv4 주소가 사설망 · 이 기계 · 링크 로컬 · 공유 주소 · 예약된 것인가.
pub fn private_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, _, _] = octets;
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || a >= 224
}

fn ipv4_literal(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (slot, part) in octets.iter_mut().zip(parts) {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    Some(octets)
}

/// 받아 온 metadata 문서. 판정에 쓰는 칸만 읽고 나머지는 둔다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClientMetadata {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum DocumentProblem {
    IdMismatch,
    NoName,
    NoRedirect,
    BadRedirect { uri: String },
}

/// 받아 온 문서가 그 주소의 클라이언트를 밝히는가. 문서의 `client_id` 가 받아 온 주소와 글자까지 같아야 한다.
pub fn judge_document(url: &str, document: &ClientMetadata) -> Result<(), DocumentProblem> {
    if !same_text(&document.client_id, url) {
        return Err(DocumentProblem::IdMismatch);
    }
    if document
        .client_name
        .as_deref()
        .is_none_or(|name| name.trim().is_empty())
    {
        return Err(DocumentProblem::NoName);
    }
    if document.redirect_uris.is_empty() {
        return Err(DocumentProblem::NoRedirect);
    }
    for uri in &document.redirect_uris {
        if registrable_redirect(uri).is_err() {
            return Err(DocumentProblem::BadRedirect { uri: uri.clone() });
        }
    }
    Ok(())
}

/// 받아 온 문서를 아직 기억해도 되는가.
pub fn document_fresh(fetched_at: u64, now: u64) -> bool {
    now < fetched_at.saturating_add(DOCUMENT_TTL)
}

// ---- 동적 등록(RFC 7591) ----

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Registration {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum RegistrationProblem {
    NoRedirect,
    BadRedirect {
        uri: String,
    },
    /// 기밀 클라이언트(`client_secret`)는 받지 않는다.
    NotPublic,
    BadApplicationType,
    BadGrantType,
}

impl RegistrationProblem {
    /// RFC 7591 의 오류 코드.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRedirect | Self::BadRedirect { .. } => "invalid_redirect_uri",
            _ => "invalid_client_metadata",
        }
    }
}

/// 동적 등록의 요청을 받을 수 있는가. 공개 클라이언트만, 인가 코드와 refresh 토큰만, redirect 는 등록할 수 있는 것만.
pub fn judge_registration(request: &Registration) -> Result<(), RegistrationProblem> {
    if request.redirect_uris.is_empty() {
        return Err(RegistrationProblem::NoRedirect);
    }
    for uri in &request.redirect_uris {
        if registrable_redirect(uri).is_err() {
            return Err(RegistrationProblem::BadRedirect { uri: uri.clone() });
        }
    }
    if request
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method != "none")
    {
        return Err(RegistrationProblem::NotPublic);
    }
    if request
        .application_type
        .as_deref()
        .is_some_and(|kind| kind != "web" && kind != "native")
    {
        return Err(RegistrationProblem::BadApplicationType);
    }
    let grants_ok = request.grant_types.as_ref().is_none_or(|grants| {
        grants
            .iter()
            .all(|grant| grant == "authorization_code" || grant == "refresh_token")
    });
    let responses_ok = request
        .response_types
        .as_ref()
        .is_none_or(|responses| responses.iter().all(|response| response == "code"));
    if !grants_ok || !responses_ok {
        return Err(RegistrationProblem::BadGrantType);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "http://127.0.0.1:4100";
    const RESOURCE: &str = "http://127.0.0.1:4100/mcp";
    const REDIRECT: &str = "https://client.example/callback";
    /// verifier 와 그 challenge. challenge 는 Python 의 `hashlib.sha256` 과 `base64.urlsafe_b64encode` 로 따로 구한 값이다.
    const VERIFIER: &str = "dBjftJeZ4CVP-mJ92K1uX6s5wN5AtbcbN6p6pQs1bR8";
    const CHALLENGE: &str = "82hCCcUaX78_KHQ_-h_TNPnvb4uVcFODJnnPYx5vBUI";

    fn client() -> KnownClient {
        KnownClient {
            id: "c_1".to_owned(),
            redirect_uris: vec![REDIRECT.to_owned(), "http://localhost:7777/cb".to_owned()],
        }
    }

    fn query() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: Some("code".to_owned()),
            client_id: Some("c_1".to_owned()),
            redirect_uri: Some(REDIRECT.to_owned()),
            code_challenge: Some(CHALLENGE.to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            resource: Some(RESOURCE.to_owned()),
            scope: Some("mcp".to_owned()),
            state: Some("xyz".to_owned()),
        }
    }

    fn judge(query: &AuthorizeQuery) -> Authorize {
        judge_authorize(query, Some(&client()), RESOURCE, ISSUER)
    }

    fn refused_with(verdict: &Authorize) -> Option<String> {
        match verdict {
            Authorize::Refuse { location } => location
                .split(['?', '&'])
                .find_map(|pair| pair.strip_prefix("error="))
                .map(str::to_owned),
            _ => None,
        }
    }

    #[test]
    fn 인가_요청의_redirect_는_등록된_것과_글자_하나까지_같아야_받는다() {
        assert!(matches!(judge(&query()), Authorize::Accept { .. }));
        let local = AuthorizeQuery {
            redirect_uri: Some("http://localhost:7777/cb".to_owned()),
            ..query()
        };
        assert!(matches!(judge(&local), Authorize::Accept { .. }));
        for near in [
            "https://client.example/callback/",
            "https://client.example/Callback",
            "https://client.example/callback?x=1",
            "https://client.example:443/callback",
            "https://client.example/callback#",
            "http://client.example/callback",
            "http://localhost:7778/cb",
            "https://client.example.evil/callback",
        ] {
            let other = AuthorizeQuery {
                redirect_uri: Some(near.to_owned()),
                ..query()
            };
            assert_eq!(
                judge(&other),
                Authorize::Stop {
                    reason: Stop::BadRedirect
                },
                "{near}"
            );
        }
        assert!(same_redirect(&[REDIRECT.to_owned()], REDIRECT));
        assert!(!same_redirect(
            &[REDIRECT.to_owned()],
            "https://client.example/callbac"
        ));
    }

    #[test]
    fn pkce_가_없거나_s256_이_아니면_받지_않는다() {
        for (challenge, method) in [
            (None, Some("S256")),
            (Some(CHALLENGE), None),
            (Some(CHALLENGE), Some("plain")),
            (Some(CHALLENGE), Some("s256")),
            (Some("too-short"), Some("S256")),
        ] {
            let weak = AuthorizeQuery {
                code_challenge: challenge.map(str::to_owned),
                code_challenge_method: method.map(str::to_owned),
                ..query()
            };
            assert_eq!(
                refused_with(&judge(&weak)).as_deref(),
                Some("invalid_request"),
                "{challenge:?} {method:?}"
            );
        }
        // 오류도 등록된 redirect 로, 발급자와 state 를 실어 돌려보낸다
        let weak = AuthorizeQuery {
            code_challenge: None,
            ..query()
        };
        let Authorize::Refuse { location } = judge(&weak) else {
            panic!("redirect 로 돌려보내야 합니다");
        };
        assert!(location.starts_with("https://client.example/callback?error=invalid_request"));
        assert!(location.contains("&state=xyz"));
        assert!(location.contains("&iss=http%3A//127.0.0.1%3A4100"));
    }

    #[test]
    fn 대상_자원이_이_인스턴스의_mcp_주소가_아니면_받지_않는다() {
        for resource in [
            None,
            Some("http://127.0.0.1:4101/mcp"),
            Some("http://127.0.0.1:4100/mcp/"),
            Some("http://127.0.0.1:4100/"),
            Some("https://evil.example/mcp"),
        ] {
            let other = AuthorizeQuery {
                resource: resource.map(str::to_owned),
                ..query()
            };
            assert_eq!(
                refused_with(&judge(&other)).as_deref(),
                Some("invalid_target"),
                "{resource:?}"
            );
        }
        let wide = AuthorizeQuery {
            scope: Some("mcp admin".to_owned()),
            ..query()
        };
        assert_eq!(
            refused_with(&judge(&wide)).as_deref(),
            Some("invalid_scope")
        );
        let token = AuthorizeQuery {
            response_type: Some("token".to_owned()),
            ..query()
        };
        assert_eq!(
            refused_with(&judge(&token)).as_deref(),
            Some("unsupported_response_type")
        );
        // scope 를 적지 않으면 mcp 다
        let Authorize::Accept { request } = judge(&AuthorizeQuery {
            scope: None,
            ..query()
        }) else {
            panic!("받아야 합니다");
        };
        assert_eq!(request.scope, "mcp");
    }

    #[test]
    fn 클라이언트나_redirect_가_틀린_요청은_그_redirect_로_돌려보내지_않는다() {
        // 모르는 클라이언트: 다른 잘못이 함께 있어도 redirect 로 보내지 않는다
        let unknown = AuthorizeQuery {
            client_id: Some("c_404".to_owned()),
            code_challenge: None,
            ..query()
        };
        assert_eq!(
            judge_authorize(&unknown, None, RESOURCE, ISSUER),
            Authorize::Stop {
                reason: Stop::UnknownClient
            }
        );
        // 등록되지 않은 redirect 에 다른 잘못이 함께 있어도 마찬가지다
        let elsewhere = AuthorizeQuery {
            redirect_uri: Some("https://evil.example/steal".to_owned()),
            response_type: Some("token".to_owned()),
            resource: None,
            ..query()
        };
        assert_eq!(
            judge(&elsewhere),
            Authorize::Stop {
                reason: Stop::BadRedirect
            }
        );
        let missing = AuthorizeQuery {
            redirect_uri: None,
            ..query()
        };
        assert_eq!(
            judge(&missing),
            Authorize::Stop {
                reason: Stop::BadRedirect
            }
        );
        let no_client = AuthorizeQuery {
            client_id: None,
            ..query()
        };
        assert_eq!(
            judge_authorize(&no_client, None, RESOURCE, ISSUER),
            Authorize::Stop {
                reason: Stop::UnknownClient
            }
        );
    }

    #[test]
    fn verifier_가_challenge_와_맞지_않으면_토큰을_내지_않는다() {
        assert_eq!(s256(VERIFIER), CHALLENGE);
        assert!(pkce_matches(CHALLENGE, VERIFIER));
        let mut other = VERIFIER.to_owned();
        other.replace_range(0..1, "e");
        assert!(!pkce_matches(CHALLENGE, &other));
        assert!(!pkce_matches(CHALLENGE, ""));
        // verifier 자체를 challenge 로 내밀어도(plain) 맞지 않는다
        assert!(!pkce_matches(VERIFIER, VERIFIER));
        // 모양이 틀린 verifier 는 해시가 맞아도 받지 않는다(42자 · 허용되지 않는 글자)
        let short = &VERIFIER[..42];
        assert!(!pkce_matches(&s256(short), short));
        let odd = format!("{}!", &VERIFIER[..42]);
        assert!(!pkce_matches(&s256(&odd), &odd));
    }

    #[test]
    fn 인가_코드는_5분까지_읽히고_그_뒤로는_읽히지_않는다() {
        let made = 1_800_000_000;
        let code = CodeState {
            expires_at: code_expires_at(made),
            used_at: None,
        };
        assert_eq!(code.expires_at, made + 300);
        assert_eq!(judge_code(&code, made), Ok(()));
        assert_eq!(judge_code(&code, made + 299), Ok(()));
        assert_eq!(judge_code(&code, made + 300), Err(CodeRefusal::Expired));
        let used = CodeState {
            used_at: Some(made + 1),
            ..code
        };
        assert_eq!(judge_code(&used, made + 2), Err(CodeRefusal::Used));
    }

    #[test]
    fn redirect_는_https_이거나_localhost_여야_등록된다() {
        for good in [
            "https://client.example/callback",
            "https://client.example:8443/cb?app=1",
            "http://localhost:7777/cb",
            "http://127.0.0.1/cb",
            "http://[::1]:9000/cb",
        ] {
            assert_eq!(registrable_redirect(good), Ok(()), "{good}");
        }
        for (bad, problem) in [
            (
                "http://client.example/cb",
                RedirectProblem::NotHttpsOrLocalhost,
            ),
            (
                "http://localhost.evil.example/cb",
                RedirectProblem::NotHttpsOrLocalhost,
            ),
            ("javascript:alert(1)", RedirectProblem::NotUrl),
            ("myapp://callback", RedirectProblem::NotHttpsOrLocalhost),
            ("https://client.example/cb#top", RedirectProblem::Fragment),
            ("https://user@client.example/cb", RedirectProblem::NotUrl),
            ("https:///cb", RedirectProblem::NotUrl),
            ("/cb", RedirectProblem::NotUrl),
        ] {
            assert_eq!(registrable_redirect(bad), Err(problem), "{bad}");
        }
        assert_eq!(
            judge_registration(&Registration {
                redirect_uris: vec!["http://client.example/cb".to_owned()],
                ..Registration::default()
            }),
            Err(RegistrationProblem::BadRedirect {
                uri: "http://client.example/cb".to_owned()
            })
        );
        assert_eq!(
            judge_registration(&Registration {
                redirect_uris: vec![REDIRECT.to_owned()],
                token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
                ..Registration::default()
            }),
            Err(RegistrationProblem::NotPublic)
        );
        assert_eq!(
            judge_registration(&Registration {
                redirect_uris: vec![REDIRECT.to_owned()],
                application_type: Some("native".to_owned()),
                ..Registration::default()
            }),
            Ok(())
        );
    }

    #[test]
    fn metadata_문서의_주소는_https_이고_경로가_있어야_하며_사설_주소면_받지_않는다() {
        assert_eq!(
            document_url("https://client.example/oauth/client.json"),
            Ok(())
        );
        assert_eq!(document_url("https://8.8.8.8/client.json"), Ok(()));
        for (bad, problem) in [
            (
                "http://client.example/client.json",
                DocumentUrlProblem::NotHttps,
            ),
            ("https://client.example", DocumentUrlProblem::NoPath),
            ("https://client.example/", DocumentUrlProblem::NoPath),
            (
                "https://client.example/c.json#x",
                DocumentUrlProblem::Fragment,
            ),
            ("https://localhost/c.json", DocumentUrlProblem::PrivateHost),
            (
                "https://app.localhost/c.json",
                DocumentUrlProblem::PrivateHost,
            ),
            ("https://127.0.0.1/c.json", DocumentUrlProblem::PrivateHost),
            ("https://10.0.0.5/c.json", DocumentUrlProblem::PrivateHost),
            ("https://172.16.3.4/c.json", DocumentUrlProblem::PrivateHost),
            (
                "https://192.168.1.1/c.json",
                DocumentUrlProblem::PrivateHost,
            ),
            (
                "https://169.254.169.254/latest/meta-data",
                DocumentUrlProblem::PrivateHost,
            ),
            ("https://100.64.0.1/c.json", DocumentUrlProblem::PrivateHost),
            ("https://0.0.0.0/c.json", DocumentUrlProblem::PrivateHost),
            ("https://[::1]/c.json", DocumentUrlProblem::PrivateHost),
            ("https://[fd00::1]/c.json", DocumentUrlProblem::PrivateHost),
            (
                "https://user@client.example/c.json",
                DocumentUrlProblem::NotUrl,
            ),
        ] {
            assert_eq!(document_url(bad), Err(problem), "{bad}");
        }
        assert!(is_document_id("https://client.example/c.json"));
        assert!(!is_document_id("c_1"));
    }

    #[test]
    fn metadata_문서에_적힌_식별자가_받아_온_주소와_다르면_받지_않는다() {
        let url = "https://client.example/oauth/client.json";
        let document = ClientMetadata {
            client_id: url.to_owned(),
            client_name: Some("예시 클라이언트".to_owned()),
            redirect_uris: vec![REDIRECT.to_owned()],
        };
        assert_eq!(judge_document(url, &document), Ok(()));
        for other in [
            "https://client.example/oauth/client.json/",
            "https://CLIENT.example/oauth/client.json",
            "https://evil.example/oauth/client.json",
            "",
        ] {
            let lying = ClientMetadata {
                client_id: other.to_owned(),
                ..document.clone()
            };
            assert_eq!(
                judge_document(url, &lying),
                Err(DocumentProblem::IdMismatch),
                "{other}"
            );
        }
        let nameless = ClientMetadata {
            client_name: None,
            ..document.clone()
        };
        assert_eq!(judge_document(url, &nameless), Err(DocumentProblem::NoName));
        let nowhere = ClientMetadata {
            redirect_uris: Vec::new(),
            ..document.clone()
        };
        assert_eq!(
            judge_document(url, &nowhere),
            Err(DocumentProblem::NoRedirect)
        );
        let plain = ClientMetadata {
            redirect_uris: vec!["http://client.example/cb".to_owned()],
            ..document
        };
        assert_eq!(
            judge_document(url, &plain),
            Err(DocumentProblem::BadRedirect {
                uri: "http://client.example/cb".to_owned()
            })
        );
        assert!(document_fresh(100, 100 + DOCUMENT_TTL - 1));
        assert!(!document_fresh(100, 100 + DOCUMENT_TTL));
    }

    #[test]
    fn 동의_화면에는_redirect_의_자리만_보인다() {
        assert_eq!(redirect_host(REDIRECT).as_deref(), Some("client.example"));
        assert_eq!(
            redirect_host("http://localhost:7777/cb?x=1").as_deref(),
            Some("localhost:7777")
        );
        assert_eq!(redirect_host("https://user@evil.example/cb"), None);
        assert_eq!(redirect_host("/cb"), None);
    }

    #[test]
    fn 토큰은_만료됐거나_거뒀거나_다른_자원용이면_쓰이지_않는다() {
        let token = TokenState {
            expires_at: 200,
            revoked: false,
            used: false,
            grant_revoked: false,
            user_disabled: false,
            resource: RESOURCE.to_owned(),
        };
        assert_eq!(judge_token(&token, RESOURCE, 199), Ok(()));
        assert_eq!(
            judge_token(&token, RESOURCE, 200),
            Err(TokenRefusal::Expired)
        );
        assert_eq!(
            judge_token(&token, "http://127.0.0.1:4101/mcp", 100),
            Err(TokenRefusal::OtherResource)
        );
        for (changed, refusal) in [
            (
                TokenState {
                    revoked: true,
                    ..token.clone()
                },
                TokenRefusal::Revoked,
            ),
            (
                TokenState {
                    grant_revoked: true,
                    ..token.clone()
                },
                TokenRefusal::Revoked,
            ),
            (
                TokenState {
                    used: true,
                    ..token.clone()
                },
                TokenRefusal::Used,
            ),
            (
                TokenState {
                    user_disabled: true,
                    ..token.clone()
                },
                TokenRefusal::UserDisabled,
            ),
        ] {
            assert_eq!(judge_token(&changed, RESOURCE, 100), Err(refusal));
        }
        assert!(request_open(10, false, 9));
        assert!(!request_open(10, false, 10));
        assert!(!request_open(10, true, 9));
    }
}
