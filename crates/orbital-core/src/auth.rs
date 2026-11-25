//! Orbital Auth 의 판정. 로그인 링크 · 초대 · 세션이 아직 읽히는지, 로그인 뒤에 돌아갈 곳, 요청을 받을 서비스를 가른다.
//!
//! 시각은 모두 인자로 받는 유닉스 초다. 경계는 하나로 맞춘다: `now < expires_at` 이면 읽힌다.
//! 저장과 무작위 값과 해시는 `orbital-pg` 가 맡고, 여기서는 읽어 온 상태를 판정만 한다.

use serde::{Deserialize, Serialize};

use crate::manifest::{LAYER_PATH, Service, ValidManifest, trim_path, under};
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
}
