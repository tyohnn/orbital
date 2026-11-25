//! Orbital Auth 의 판정. 로그인 링크 · 초대 · 세션이 아직 읽히는지, 로그인 뒤에 돌아갈 곳, 요청을 받을 서비스를 가른다.
//!
//! 시각은 모두 인자로 받는 유닉스 초다. 경계는 하나로 맞춘다: `now < expires_at` 이면 읽힌다.
//! 저장과 무작위 값과 해시는 `orbital-pg` 가 맡고, 여기서는 읽어 온 상태를 판정만 한다.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::manifest::{LAYER_PATH, Service, ServiceAuth, ValidManifest, trim_path, under};
use crate::name::Ident;

/// 로그인 링크가 읽히는 시간. 15분.
pub const LINK_TTL: u64 = 15 * 60;
/// 초대가 받아들여지는 시간. 14일.
pub const INVITATION_TTL: u64 = 14 * 24 * 60 * 60;
/// 세션이 읽히는 시간. 30일.
pub const SESSION_TTL: u64 = 30 * 24 * 60 * 60;

pub fn link_expires_at(created_at: u64) -> u64 {
    created_at.saturating_add(LINK_TTL)
}

pub fn invitation_expires_at(created_at: u64) -> u64 {
    created_at.saturating_add(INVITATION_TTL)
}

pub fn session_expires_at(created_at: u64) -> u64 {
    created_at.saturating_add(SESSION_TTL)
}

/// 같은 이메일로 링크를 다시 만들 수 있기까지의 시간. 1분.
pub const LINK_INTERVAL: u64 = 60;
/// 세션을 본 시각을 다시 적기까지의 시간. 1분. 요청마다 쓰기가 생기지 않게 한다.
pub const SESSION_TOUCH_INTERVAL: u64 = 60;

/// 이 이메일로 지금 링크를 만들어도 되는가. `last_created_at` 은 그 이메일로 마지막에 만든 링크의 시각이다.
pub fn may_create_link(last_created_at: Option<u64>, now: u64) -> bool {
    last_created_at.is_none_or(|last| now >= last.saturating_add(LINK_INTERVAL))
}

/// 세션을 본 시각을 지금 다시 적을 때인가. 마지막으로 적은 지 1분이 지났으면 적는다.
pub fn needs_touch(last_seen_at: u64, now: u64) -> bool {
    now >= last_seen_at.saturating_add(SESSION_TOUCH_INTERVAL)
}

/// 로그인이 필요한 서비스에 요청을 들여보낼지.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum Admission {
    /// 들여보낸다.
    Pass,
    /// 화면을 여는 요청이다. 로그인 화면으로 보낸다. `location` 은 `login_path?next=<원래 경로와 질의>` 다.
    ToLogin { location: String },
    /// 화면이 아닌 요청이다. 401 로 답한다.
    Unauthorized,
}

/// 화면을 여는 요청인가. `GET` 이고 `Accept` 에 `text/html` 이 있다.
pub fn wants_page(method: &str, accept: Option<&str>) -> bool {
    method == "GET"
        && accept.is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"))
}

/// 질의의 값 하나로 싣도록 글자를 감싼다. 읽기 쉽게 `/` 는 그대로 둔다.
fn encode_component(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// `%` 로 감싼 글자를 푼다. 모양이 틀렸거나 UTF-8 이 아니면 `None` 이다.
fn decode_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = text.get(at + 1..at + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// 요청을 서비스에 들여보낼지 정한다. `path_and_query` 는 요청의 경로와 질의다.
///
/// 로그인을 요구하지 않는 서비스, 세션이 있는 요청, 로그인 화면(`login_path`)과 그 아래는 들여보낸다.
pub fn admit(
    manifest: &ValidManifest,
    service: &Service,
    path_and_query: &str,
    signed_in: bool,
    page: bool,
) -> Admission {
    if service.auth == ServiceAuth::Optional || signed_in {
        return Admission::Pass;
    }
    let Some(auth) = &manifest.get().auth else {
        // 선언의 검증이 막으므로 오지 않는다. 와도 들여보내지 않는다
        return Admission::Unauthorized;
    };
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    if under(path, &auth.login_path) {
        return Admission::Pass;
    }
    if page {
        Admission::ToLogin {
            location: format!(
                "{}?next={}",
                auth.login_path,
                encode_component(&safe_next(path_and_query))
            ),
        }
    } else {
        Admission::Unauthorized
    }
}

/// 상태를 바꾸는 레이어의 요청이 이 주소의 화면에서 왔는가. `Origin` 이 없거나 다르면 아니다.
pub fn same_origin(origin: Option<&str>, own: &str) -> bool {
    origin.is_some_and(|origin| !own.is_empty() && origin == own)
}

/// 정적 서비스의 요청 경로가 가리키는 파일. 빌드 결과의 폴더 안의 조각들로 돌려주고, 폴더 밖을 가리킬 수 있으면 `None` 이다.
///
/// 조각마다 `%` 를 풀어 본 뒤 `.` · `..` · `.` 으로 시작하는 것 · `/` · `\` · 제어 문자가 든 것을 받지 않는다. 비었거나 `/` 로 끝나면 `index.html` 이다.
/// 심볼릭 링크는 여기서 알 수 없으니, 파일을 여는 쪽이 실제 경로가 폴더 안인지 다시 본다.
pub fn static_file(path: &str, service_path: &str) -> Option<Vec<String>> {
    if !under(path, service_path) {
        return None;
    }
    let base = trim_path(service_path);
    let rest = if base == "/" {
        path
    } else {
        path.strip_prefix(base)?
    };
    let mut parts = Vec::new();
    for piece in rest.split('/').filter(|piece| !piece.is_empty()) {
        let part = decode_component(piece)?;
        let safe = !part.starts_with('.')
            && !part.contains(['/', '\\'])
            && !part.chars().any(char::is_control);
        if !safe {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() || rest.ends_with('/') {
        parts.push("index.html".to_owned());
    }
    Some(parts)
}

/// 미리보기의 씨앗 사용자(`db/seed/users.toml`). 미리보기에만 들어가고 운영에는 들어가지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedUsers {
    #[serde(default, rename = "user")]
    pub users: Vec<SeedUser>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedUser {
    /// 미리보기 전용이라 `u_` 모양이 아니어도 된다. 씨앗 데이터의 SQL 이 이 식별자로 행의 주인을 적는다.
    pub id: Ident,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub roles: Vec<Ident>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum SeedProblem {
    NoAuth,
    DuplicateId { id: Ident },
    DuplicateEmail { email: String },
    UndeclaredRole { id: Ident, role: Ident },
}

impl fmt::Display for SeedProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuth => write!(
                f,
                "씨앗 사용자를 적었지만 `orbital.toml` 에 `[auth]` 가 없습니다. `[auth]` 를 적거나 씨앗 사용자의 파일을 지워 주세요"
            ),
            Self::DuplicateId { id } => write!(
                f,
                "씨앗 사용자 `{id}` 가 두 번 적혀 있습니다. 식별자를 하나씩만 적어 주세요"
            ),
            Self::DuplicateEmail { email } => write!(
                f,
                "씨앗 사용자의 이메일 `{email}` 이 두 번 적혀 있습니다. 사람마다 다른 이메일을 적어 주세요"
            ),
            Self::UndeclaredRole { id, role } => write!(
                f,
                "씨앗 사용자 `{id}` 의 역할 `{role}` 이 `[database].roles` 에 없습니다. 선언한 업무 역할만 적어 주세요"
            ),
        }
    }
}

impl SeedUsers {
    /// 씨앗 사용자가 선언과 맞는지 본다. 문제를 모두 돌려준다.
    pub fn check(self, manifest: &ValidManifest) -> Result<Vec<SeedUser>, Vec<SeedProblem>> {
        if self.users.is_empty() {
            return Ok(Vec::new());
        }
        if manifest.get().auth.is_none() {
            return Err(vec![SeedProblem::NoAuth]);
        }
        let mut problems = Vec::new();
        let mut ids = BTreeSet::new();
        let mut emails = BTreeSet::new();
        for user in &self.users {
            for role in undeclared_roles(manifest, &user.roles) {
                problems.push(SeedProblem::UndeclaredRole {
                    id: user.id.clone(),
                    role,
                });
            }
            if !ids.insert(&user.id) {
                problems.push(SeedProblem::DuplicateId {
                    id: user.id.clone(),
                });
            }
            // 이메일은 대소문자를 가리지 않고 견준다. DB 도 그렇게 견준다
            if !emails.insert(user.email.to_lowercase()) {
                problems.push(SeedProblem::DuplicateEmail {
                    email: user.email.clone(),
                });
            }
        }
        if problems.is_empty() {
            Ok(self.users)
        } else {
            Err(problems)
        }
    }
}

/// 저장된 로그인 링크 하나의 상태. 토큰과 브라우저는 해시로만 갖는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkState {
    pub created_at: u64,
    pub expires_at: u64,
    pub used_at: Option<u64>,
    /// 링크를 요청한 브라우저의 표식의 해시.
    pub browser_hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkRefusal {
    Expired,
    Used,
    OtherBrowser,
}

/// 이 링크로 지금 들어올 수 있는가. `browser_hash` 는 링크를 연 브라우저의 표식의 해시다.
pub fn judge_link(link: &LinkState, browser_hash: &[u8], now: u64) -> Result<(), LinkRefusal> {
    if link.used_at.is_some() {
        return Err(LinkRefusal::Used);
    }
    if now >= link.expires_at {
        return Err(LinkRefusal::Expired);
    }
    if !same_bytes(&link.browser_hash, browser_hash) {
        return Err(LinkRefusal::OtherBrowser);
    }
    Ok(())
}

/// 두 값을 끝까지 견준다. 앞에서부터 견주다 멈추면 걸린 시간으로 값을 맞혀 갈 수 있다.
fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// 저장된 초대 하나의 상태.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationState {
    pub created_at: u64,
    pub expires_at: u64,
    pub accepted_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationRefusal {
    Expired,
    Accepted,
}

/// 이 초대를 지금 받아들일 수 있는가.
pub fn judge_invitation(invitation: &InvitationState, now: u64) -> Result<(), InvitationRefusal> {
    if invitation.accepted_at.is_some() {
        return Err(InvitationRefusal::Accepted);
    }
    if now >= invitation.expires_at {
        return Err(InvitationRefusal::Expired);
    }
    Ok(())
}

/// 저장된 세션 하나와 그 사용자의 상태.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub user_disabled_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRefusal {
    Expired,
    Revoked,
    UserDisabled,
}

/// 이 세션이 지금 있는 것인가. 거절되면 세션은 없는 것으로 다룬다.
pub fn judge_session(session: &SessionState, now: u64) -> Result<(), SessionRefusal> {
    if session.user_disabled_at.is_some() {
        return Err(SessionRefusal::UserDisabled);
    }
    if session.revoked_at.is_some() {
        return Err(SessionRefusal::Revoked);
    }
    if now >= session.expires_at {
        return Err(SessionRefusal::Expired);
    }
    Ok(())
}

/// 로그인 뒤에 돌아갈 곳. 이 주소 안의 경로만 받고, 그 밖의 것은 첫 화면(`/`)으로 바꾼다.
///
/// `/` 하나로 시작해야 한다. `//` 와 `/\` 는 브라우저가 다른 주소로 읽고, 브라우저는 `\` 를 `/` 처럼 읽으므로 `\` 는 어디에 있든 받지 않는다.
/// 제어 문자는 브라우저가 지우고 읽어서 `/\t/evil` 이 `//evil` 이 되므로 받지 않는다. 스킴이 있는 것은 `/` 로 시작하지 않아 걸린다.
pub fn safe_next(next: &str) -> String {
    let inside = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.chars().any(char::is_control);
    if inside {
        next.to_owned()
    } else {
        "/".to_owned()
    }
}

/// 요청을 받을 서비스. 경로가 가장 길게 맞는 서비스이고, 레이어의 경로(`/_orbital`)는 어느 서비스로도 가지 않는다.
///
/// `path` 는 질의(`?`)를 뗀 요청의 경로다. 맞는지는 조각의 경계로 본다(`/api` 는 `/apix` 에 맞지 않는다).
pub fn route<'a>(manifest: &'a ValidManifest, path: &str) -> Option<&'a Service> {
    if !path.starts_with('/') || under(path, LAYER_PATH) {
        return None;
    }
    manifest
        .get()
        .services
        .iter()
        .filter(|service| under(path, &service.path))
        .max_by_key(|service| trim_path(&service.path).len())
}

/// 선언에 없는 업무 역할. 초대하거나 역할을 바꿀 때 거절의 까닭이 된다.
pub fn undeclared_roles(manifest: &ValidManifest, roles: &[Ident]) -> Vec<Ident> {
    let declared = &manifest.get().database.roles;
    roles
        .iter()
        .filter(|role| !declared.contains(role))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    const MADE: u64 = 1_800_000_000;

    fn link(used_at: Option<u64>) -> LinkState {
        LinkState {
            created_at: MADE,
            expires_at: link_expires_at(MADE),
            used_at,
            browser_hash: vec![7; 32],
        }
    }

    #[test]
    fn 로그인_링크는_만든_지_15분까지_읽히고_그_뒤로는_읽히지_않는다() {
        let link = link(None);
        assert_eq!(link.expires_at, MADE + 900);
        assert_eq!(judge_link(&link, &[7; 32], MADE), Ok(()));
        assert_eq!(judge_link(&link, &[7; 32], MADE + 899), Ok(()));
        assert_eq!(
            judge_link(&link, &[7; 32], MADE + 900),
            Err(LinkRefusal::Expired)
        );
        assert_eq!(
            judge_link(&link, &[7; 32], MADE + 901),
            Err(LinkRefusal::Expired)
        );
    }

    #[test]
    fn 한_번_쓴_링크는_다시_읽히지_않는다() {
        assert_eq!(
            judge_link(&link(Some(MADE + 10)), &[7; 32], MADE + 20),
            Err(LinkRefusal::Used)
        );
        // 만료 전이어도, 같은 브라우저여도 쓴 것은 쓴 것이다
        assert_eq!(
            judge_link(&link(Some(MADE)), &[7; 32], MADE),
            Err(LinkRefusal::Used)
        );
    }

    #[test]
    fn 링크를_요청한_브라우저가_아니면_읽히지_않는다() {
        let link = link(None);
        assert_eq!(
            judge_link(&link, &[8; 32], MADE + 1),
            Err(LinkRefusal::OtherBrowser)
        );
        let mut one_off = [7; 32];
        one_off[31] = 6;
        assert_eq!(
            judge_link(&link, &one_off, MADE + 1),
            Err(LinkRefusal::OtherBrowser)
        );
        assert_eq!(
            judge_link(&link, &[7; 31], MADE + 1),
            Err(LinkRefusal::OtherBrowser)
        );
        assert_eq!(
            judge_link(&link, &[], MADE + 1),
            Err(LinkRefusal::OtherBrowser)
        );
    }

    #[test]
    fn next_는_이_주소_안의_경로만_받고_그_밖의_것은_첫_화면으로_바꾼다() {
        for kept in [
            "/",
            "/inbox",
            "/inbox?tab=2#top",
            "/a/b/../c",
            "/%2F%2Fevil.example",
            "/a//b",
        ] {
            assert_eq!(safe_next(kept), kept, "{kept}");
        }
        for moved in [
            "",
            "inbox",
            "//evil.example",
            "///evil.example",
            "/\\evil.example",
            "/a\\b",
            "\\\\evil.example",
            "https://evil.example/",
            "javascript:alert(1)",
            "/in\tbox",
            "/in\nbox",
            "/\r\n//evil.example",
            "/in\u{7f}box",
            "/in\u{85}box",
            " /inbox",
        ] {
            assert_eq!(safe_next(moved), "/", "{moved:?}");
        }
    }

    #[test]
    fn 세션은_만료됐거나_거뒀거나_사용자가_막혀_있으면_없는_것이다() {
        let live = SessionState {
            expires_at: session_expires_at(MADE),
            revoked_at: None,
            user_disabled_at: None,
        };
        assert_eq!(judge_session(&live, MADE), Ok(()));
        assert_eq!(judge_session(&live, live.expires_at - 1), Ok(()));
        assert_eq!(
            judge_session(&live, live.expires_at),
            Err(SessionRefusal::Expired)
        );
        let revoked = SessionState {
            revoked_at: Some(MADE + 5),
            ..live.clone()
        };
        assert_eq!(
            judge_session(&revoked, MADE + 6),
            Err(SessionRefusal::Revoked)
        );
        let disabled = SessionState {
            user_disabled_at: Some(MADE + 5),
            ..live
        };
        assert_eq!(
            judge_session(&disabled, MADE + 6),
            Err(SessionRefusal::UserDisabled)
        );
    }

    #[test]
    fn 초대는_열나흘째까지_받아들여지고_열다섯째_날부터는_받아들여지지_않는다() {
        let day = 24 * 60 * 60;
        let invitation = InvitationState {
            created_at: MADE,
            expires_at: invitation_expires_at(MADE),
            accepted_at: None,
        };
        assert_eq!(invitation.expires_at, MADE + 14 * day);
        // 열나흘째의 마지막 초
        assert_eq!(judge_invitation(&invitation, MADE + 14 * day - 1), Ok(()));
        // 열다섯째 날의 첫 초
        assert_eq!(
            judge_invitation(&invitation, MADE + 14 * day),
            Err(InvitationRefusal::Expired)
        );
        let accepted = InvitationState {
            accepted_at: Some(MADE + day),
            ..invitation
        };
        assert_eq!(
            judge_invitation(&accepted, MADE + 2 * day),
            Err(InvitationRefusal::Accepted)
        );
    }

    fn manifest(paths: &[(&str, &str)]) -> ValidManifest {
        let services: String = paths
            .iter()
            .map(|(name, path)| {
                format!(
                    "[[service]]\nname = \"{name}\"\nkind = \"server\"\nbuild = \"b\"\nstart = \"s\"\npath = \"{path}\"\n\n"
                )
            })
            .collect();
        toml::from_str::<Manifest>(&services)
            .unwrap()
            .check()
            .unwrap()
    }

    fn routed(manifest: &ValidManifest, path: &str) -> Option<String> {
        route(manifest, path).map(|service| service.name.to_string())
    }

    #[test]
    fn 요청은_path_가_가장_길게_맞는_서비스로_가고_orbital_은_어느_서비스로도_가지_않는다() {
        let manifest = manifest(&[("web", "/"), ("api", "/api"), ("admin", "/api/admin/")]);
        assert_eq!(routed(&manifest, "/"), Some("web".to_owned()));
        assert_eq!(routed(&manifest, "/inbox"), Some("web".to_owned()));
        assert_eq!(routed(&manifest, "/api"), Some("api".to_owned()));
        assert_eq!(routed(&manifest, "/api/"), Some("api".to_owned()));
        assert_eq!(routed(&manifest, "/api/users"), Some("api".to_owned()));
        assert_eq!(routed(&manifest, "/api/admin"), Some("admin".to_owned()));
        assert_eq!(routed(&manifest, "/api/admin/x"), Some("admin".to_owned()));
        // 조각의 경계에서만 맞는다
        assert_eq!(routed(&manifest, "/apix"), Some("web".to_owned()));
        assert_eq!(routed(&manifest, "/api/adminx"), Some("api".to_owned()));
        // 레이어의 경로
        assert_eq!(routed(&manifest, "/_orbital"), None);
        assert_eq!(routed(&manifest, "/_orbital/"), None);
        assert_eq!(routed(&manifest, "/_orbital/auth/callback"), None);
        // 경로가 아닌 것
        assert_eq!(routed(&manifest, ""), None);
        assert_eq!(routed(&manifest, "api"), None);

        // 첫 화면을 받는 서비스가 없으면 맞지 않는 경로는 어디로도 가지 않는다
        let narrow = self::manifest(&[("api", "/api")]);
        assert_eq!(routed(&narrow, "/"), None);
        assert_eq!(routed(&narrow, "/apix"), None);
        assert_eq!(routed(&narrow, "/api/x"), Some("api".to_owned()));
    }

    #[test]
    fn 선언에_없는_업무_역할을_가려낸다() {
        let text = "[[service]]\nname = \"api\"\nkind = \"server\"\nbuild = \"b\"\nstart = \"s\"\npath = \"/\"\n\n\
                    [database]\nschemas = [\"app\"]\nroles = [\"member\", \"manager\"]\n";
        let manifest = toml::from_str::<Manifest>(text).unwrap().check().unwrap();
        let ident = |text: &str| Ident::parse(text).unwrap();
        assert_eq!(
            undeclared_roles(&manifest, &[ident("member"), ident("auditor")]),
            vec![ident("auditor")]
        );
        assert_eq!(undeclared_roles(&manifest, &[ident("manager")]), vec![]);
    }

    #[test]
    fn 같은_이메일로는_1분_안에_링크를_다시_만들지_않는다() {
        assert!(may_create_link(None, MADE));
        assert!(!may_create_link(Some(MADE), MADE));
        assert!(!may_create_link(Some(MADE), MADE + 59));
        assert!(may_create_link(Some(MADE), MADE + 60));
        assert!(may_create_link(Some(MADE), MADE + 61));
        // 시계가 뒤로 가도 새로 만들지 않는다
        assert!(!may_create_link(Some(MADE), MADE - 10));
    }

    #[test]
    fn 세션을_본_시각은_1분이_지나야_다시_적는다() {
        assert!(!needs_touch(MADE, MADE));
        assert!(!needs_touch(MADE, MADE + 59));
        assert!(needs_touch(MADE, MADE + 60));
        assert!(!needs_touch(MADE, MADE - 10));
    }

    const GUARDED: &str = "[[service]]\nname = \"web\"\nkind = \"server\"\nbuild = \"b\"\nstart = \"s\"\npath = \"/\"\nroles = [\"member\"]\nauth = \"required\"\n\n\
        [[service]]\nname = \"site\"\nkind = \"static\"\nbuild = \"b\"\noutput = \"site\"\npath = \"/static\"\n\n\
        [database]\nschemas = [\"app\"]\nroles = [\"member\", \"manager\"]\n\n\
        [auth]\nmethods = [\"email_link\"]\nlogin_path = \"/login\"\n";

    #[test]
    fn 로그인이_필요한_서비스는_세션이_없으면_화면은_로그인_화면으로_보내고_그_밖은_401_이다() {
        let manifest = toml::from_str::<Manifest>(GUARDED)
            .unwrap()
            .check()
            .unwrap();
        let web = &manifest.get().services[0];
        let site = &manifest.get().services[1];
        assert_eq!(admit(&manifest, web, "/cards", true, true), Admission::Pass);
        assert_eq!(
            admit(&manifest, web, "/cards?tab=done&x=1", false, true),
            Admission::ToLogin {
                location: "/login?next=/cards%3Ftab%3Ddone%26x%3D1".to_owned()
            }
        );
        assert_eq!(
            admit(&manifest, web, "/cards", false, false),
            Admission::Unauthorized
        );
        // 로그인 화면과 그 아래는 세션 없이 열린다. 경계는 조각으로 본다
        for open in ["/login", "/login?error=used", "/login/", "/login/style.css"] {
            assert_eq!(
                admit(&manifest, web, open, false, true),
                Admission::Pass,
                "{open}"
            );
        }
        assert_eq!(
            admit(&manifest, web, "/loginx", false, false),
            Admission::Unauthorized
        );
        // 로그인을 요구하지 않는 서비스는 그대로 들여보낸다
        assert_eq!(
            admit(&manifest, site, "/static/a.css", false, false),
            Admission::Pass
        );
        // 돌아갈 곳이 이 주소 밖이면 첫 화면으로 바뀐다
        assert_eq!(
            admit(&manifest, web, "//evil.example/x", false, true),
            Admission::ToLogin {
                location: "/login?next=/".to_owned()
            }
        );
    }

    #[test]
    fn 화면을_여는_요청은_get_이고_html_을_받는_요청이다() {
        assert!(wants_page(
            "GET",
            Some("text/html,application/xhtml+xml;q=0.9")
        ));
        assert!(!wants_page("GET", Some("application/json")));
        assert!(!wants_page("GET", None));
        assert!(!wants_page("POST", Some("text/html")));
        assert!(!wants_page("HEAD", Some("text/html")));
    }

    #[test]
    fn 상태를_바꾸는_요청은_origin_이_이_주소일_때만_받는다() {
        let own = "http://127.0.0.1:4100";
        assert!(same_origin(Some("http://127.0.0.1:4100"), own));
        assert!(!same_origin(None, own));
        assert!(!same_origin(Some("null"), own));
        assert!(!same_origin(Some(""), own));
        assert!(!same_origin(Some("http://127.0.0.1:4101"), own));
        assert!(!same_origin(Some("https://127.0.0.1:4100"), own));
        assert!(!same_origin(
            Some("http://127.0.0.1:4100.evil.example"),
            own
        ));
        assert!(!same_origin(Some("http://127.0.0.1:4100/"), own));
    }

    #[test]
    fn 정적_서비스의_경로는_폴더_안의_파일만_가리킨다() {
        let file = |path: &str| static_file(path, "/static");
        let owned = |parts: &[&str]| {
            Some(
                parts
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(file("/static/app.js"), owned(&["app.js"]));
        assert_eq!(file("/static/css/site.css"), owned(&["css", "site.css"]));
        assert_eq!(file("/static"), owned(&["index.html"]));
        assert_eq!(file("/static/"), owned(&["index.html"]));
        assert_eq!(file("/static/docs/"), owned(&["docs", "index.html"]));
        assert_eq!(file("/static/%ED%95%9C.txt"), owned(&["한.txt"]));
        assert_eq!(file("/static//app.js"), owned(&["app.js"]));
        for outside in [
            "/static/../orbital.toml",
            "/static/a/../../orbital.toml",
            "/static/%2e%2e/orbital.toml",
            "/static/%2E%2E/orbital.toml",
            "/static/..%2forbital.toml",
            "/static/..%5corbital.toml",
            "/static/a%2f..%2f..%2forbital.toml",
            "/static/./app.js",
            "/static/.env",
            "/static/%00",
            "/static/a%0a",
            "/static/%zz",
            "/static/%ff",
            "/staticx/app.js",
            "/other/app.js",
        ] {
            assert_eq!(file(outside), None, "{outside}");
        }
        // 서비스가 첫 화면에 있으면 경로 전체가 폴더 안의 경로다
        assert_eq!(static_file("/a/b.html", "/"), owned(&["a", "b.html"]));
        assert_eq!(static_file("/", "/"), owned(&["index.html"]));
    }

    #[test]
    fn 씨앗_사용자는_선언의_업무_역할만_갖고_식별자와_이메일이_겹치지_않는다() {
        let manifest = toml::from_str::<Manifest>(GUARDED)
            .unwrap()
            .check()
            .unwrap();
        let read = |text: &str| toml::from_str::<SeedUsers>(text).unwrap();
        let fine =
            read("[[user]]\nid = \"u1\"\nemail = \"u1@example.test\"\nroles = [\"member\"]\n");
        assert_eq!(fine.clone().check(&manifest).unwrap().len(), 1);
        let bad = read(
            "[[user]]\nid = \"u1\"\nemail = \"a@example.test\"\nroles = [\"auditor\"]\n\n\
             [[user]]\nid = \"u1\"\nemail = \"A@example.test\"\n",
        );
        let ident = |text: &str| Ident::parse(text).unwrap();
        assert_eq!(
            bad.check(&manifest),
            Err(vec![
                SeedProblem::UndeclaredRole {
                    id: ident("u1"),
                    role: ident("auditor")
                },
                SeedProblem::DuplicateId { id: ident("u1") },
                SeedProblem::DuplicateEmail {
                    email: "A@example.test".to_owned()
                },
            ])
        );
        let plain = self::manifest(&[("api", "/")]);
        assert_eq!(fine.check(&plain), Err(vec![SeedProblem::NoAuth]));
        // 모르는 칸은 읽지 않는다
        assert!(
            toml::from_str::<SeedUsers>("[[user]]\nid = \"u1\"\nemail = \"x\"\npassword = \"p\"\n")
                .is_err()
        );
    }
}
