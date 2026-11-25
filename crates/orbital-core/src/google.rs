//! Google 로그인의 판정. `state` 가 아직 읽히는지, Google 이 준 `id_token` 을 받을지, Google 로 보낼 주소를 짓는다.
//!
//! 콜백은 레이어의 주소 하나로 받는다. 인스턴스마다의 주소를 팩토리가 Google 콘솔에 등록하지 않게 하려는 것이다.
//! 그래서 `state` 가 어느 인스턴스의 어느 브라우저에서 시작했는지를 싣고, 레이어가 서명한다. 서명과 해시와 무작위 값은 어댑터가 맡고,
//! 여기서는 풀린 값을 판정만 한다. 시각은 인자로 받는 유닉스 초이고 경계는 `now < expires_at` 이다.
//!
//! `id_token` 은 레이어가 Google 의 토큰 주소에서 TLS 로 직접 받은 것이라 서명 대신 그 통로를 믿는다(OpenID Connect Core 3.1.3.7 의 6).
//! 그 밖의 확인(`iss` · `aud` · `exp` · `nonce` · `email_verified`)은 모두 여기서 한다.

use serde::{Deserialize, Serialize};

use crate::oauth::with_params;

/// `state` 가 읽히는 시간. 사람이 Google 의 동의 화면을 지나는 동안이다.
pub const STATE_TTL: u64 = 10 * 60;
/// 레이어의 콜백이 낸 한 번 쓰는 표가 읽히는 시간. 브라우저가 router 로 넘어가는 동안만이다.
pub const TICKET_TTL: u64 = 60;
/// Google 에 묻는 것. 이메일과 그 이메일을 Google 이 확인했는지만 받는다.
pub const SCOPE: &str = "openid email";
/// Google 이 `iss` 에 적는 값. 둘 다 Google 의 문서가 적은 것이다.
pub const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
/// 레이어의 콜백 경로. 레이어의 바깥 주소 뒤에 붙는다. 팩토리가 Google 콘솔에 이 주소 하나를 등록한다.
pub const CALLBACK_PATH: &str = "/v1/auth/google/callback";

pub fn state_expires_at(created_at: u64) -> u64 {
    created_at + STATE_TTL
}

pub fn ticket_expires_at(created_at: u64) -> u64 {
    created_at + TICKET_TTL
}

/// 레이어의 콜백 주소. `public_url` 은 레이어의 바깥 주소다(`https://layer.example`).
pub fn callback_url(public_url: &str) -> String {
    format!("{}{CALLBACK_PATH}", public_url.trim_end_matches('/'))
}

/// router 가 선 자리. Google 로그인은 운영에만 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preview,
    Production,
}

/// `state` 에 싣는 것. 레이어가 서명해 Google 에 넘기고, Google 이 콜백에 그대로 돌려준다.
///
/// 브라우저의 표식과 `nonce` 는 해시(hex)로만 싣는다. `state` 는 주소에 실려 기록에 남을 수 있다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateClaims {
    /// 로그인을 시작한 인스턴스.
    pub instance: String,
    pub stage: Stage,
    /// 들어온 뒤 돌아갈 곳. 이 인스턴스 안의 경로다.
    pub next: String,
    /// 시작한 브라우저의 표식의 해시(hex).
    pub browser_hash: String,
    /// Google 에 보낸 `nonce` 의 해시(hex). `id_token` 의 `nonce` 를 이것과 견준다.
    pub nonce_hash: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateRefusal {
    Expired,
    /// 미리보기에서 시작했다. 미리보기에는 Google 로그인이 없다.
    NotProduction,
}

/// 서명을 확인한 `state` 를 지금 받을지. 서명이 틀린 것은 어댑터가 먼저 버린다.
pub fn judge_state(state: &StateClaims, now: u64) -> Result<(), StateRefusal> {
    if state.stage != Stage::Production {
        return Err(StateRefusal::NotProduction);
    }
    if now >= state.expires_at {
        return Err(StateRefusal::Expired);
    }
    Ok(())
}

/// Google 의 인가 주소로 보낼 곳. 질의의 값은 모두 감싼다.
pub fn authorize_location(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
) -> String {
    with_params(
        endpoint,
        &[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", SCOPE),
            ("state", state),
            ("nonce", nonce),
        ],
    )
}

/// `aud` 는 글자 하나이거나 목록이다(OpenID Connect Core 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

/// `email_verified`. 규격은 참거짓이지만 글자(`"true"`)로 오는 일이 있어 둘 다 읽는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Flag {
    Bool(bool),
    Text(String),
}

impl Flag {
    fn is_true(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Text(text) => text == "true",
        }
    }
}

/// `id_token` 의 몸(claims). 어댑터가 JWT 의 가운데 조각을 풀어 넘긴다. 모르는 칸은 읽지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdToken {
    pub iss: String,
    pub aud: Audience,
    #[serde(default)]
    pub azp: Option<String>,
    pub exp: u64,
    pub sub: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<Flag>,
}

/// `id_token` 을 받지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdTokenRefusal {
    /// Google 이 낸 것이 아니다.
    Issuer,
    /// 이 팩토리의 클라이언트용이 아니다.
    Audience,
    Expired,
    /// 이 로그인에서 보낸 `nonce` 가 아니다.
    Nonce,
    /// 이메일이 없거나 Google 이 확인하지 않았다.
    EmailNotVerified,
    /// 계정의 식별자(`sub`)가 비었다.
    NoSubject,
}

/// 확인을 지난 Google 계정.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleAccount {
    /// Google 이 확인한 이메일.
    pub email: String,
    /// Google 계정의 바뀌지 않는 식별자.
    pub subject: String,
}

/// `id_token` 을 받을지 판정한다.
///
/// `client_id` 는 그 인스턴스가 속한 팩토리의 것이다. `expected_nonce_hash` 는 `state` 에 실린 해시이고,
/// `computed_nonce_hash` 는 어댑터가 `id_token` 의 `nonce` 를 같은 방법으로 해시한 것이다(`nonce` 가 없으면 `None`).
pub fn judge_id_token(
    token: &IdToken,
    client_id: &str,
    expected_nonce_hash: &str,
    computed_nonce_hash: Option<&str>,
    now: u64,
) -> Result<GoogleAccount, IdTokenRefusal> {
    if !ISSUERS.contains(&token.iss.as_str()) {
        return Err(IdTokenRefusal::Issuer);
    }
    let ours = match &token.aud {
        Audience::One(audience) => audience == client_id,
        // 여럿이면 받는 쪽(azp)이 이 클라이언트여야 한다(OpenID Connect Core 3.1.3.7 의 4 · 5)
        Audience::Many(audiences) => {
            audiences.iter().any(|audience| audience == client_id)
                && (audiences.len() == 1 || token.azp.as_deref() == Some(client_id))
        }
    };
    if client_id.is_empty() || !ours {
        return Err(IdTokenRefusal::Audience);
    }
    if now >= token.exp {
        return Err(IdTokenRefusal::Expired);
    }
    let nonce_matches = computed_nonce_hash.is_some_and(|computed| {
        !expected_nonce_hash.is_empty()
            && crate::auth::same_bytes(computed.as_bytes(), expected_nonce_hash.as_bytes())
    });
    if !nonce_matches {
        return Err(IdTokenRefusal::Nonce);
    }
    let email = token
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty());
    let verified = token.email_verified.as_ref().is_some_and(Flag::is_true);
    let Some(email) = email.filter(|_| verified) else {
        return Err(IdTokenRefusal::EmailNotVerified);
    };
    if token.sub.trim().is_empty() {
        return Err(IdTokenRefusal::NoSubject);
    }
    Ok(GoogleAccount {
        email: email.to_owned(),
        subject: token.sub.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "factory-client.apps.googleusercontent.com";
    const NOW: u64 = 1_800_000_000;

    fn token() -> IdToken {
        IdToken {
            iss: "https://accounts.google.com".to_owned(),
            aud: Audience::One(CLIENT.to_owned()),
            azp: Some(CLIENT.to_owned()),
            exp: NOW + 3600,
            sub: "110169484474386276334".to_owned(),
            nonce: Some("n-raw".to_owned()),
            email: Some("kim@example.com".to_owned()),
            email_verified: Some(Flag::Bool(true)),
        }
    }

    fn judge(token: &IdToken) -> Result<GoogleAccount, IdTokenRefusal> {
        judge_id_token(token, CLIENT, "aa11", Some("aa11"), NOW)
    }

    fn state() -> StateClaims {
        StateClaims {
            instance: "i1".to_owned(),
            stage: Stage::Production,
            next: "/cards".to_owned(),
            browser_hash: "bb".to_owned(),
            nonce_hash: "aa11".to_owned(),
            expires_at: state_expires_at(NOW),
        }
    }

    #[test]
    fn google_이_이_클라이언트용으로_낸_확인된_이메일의_토큰은_받는다() {
        assert_eq!(
            judge(&token()),
            Ok(GoogleAccount {
                email: "kim@example.com".to_owned(),
                subject: "110169484474386276334".to_owned(),
            })
        );
        // 두 모양의 iss 를 모두 받는다
        let mut short = token();
        short.iss = "accounts.google.com".to_owned();
        assert!(judge(&short).is_ok());
        // 글자로 온 email_verified 도 읽는다
        let mut text = token();
        text.email_verified = Some(Flag::Text("true".to_owned()));
        assert!(judge(&text).is_ok());
    }

    #[test]
    fn 다른_발급자의_토큰은_받지_않는다() {
        for iss in [
            "https://accounts.google.com.evil.example",
            "https://evil.example",
            "http://accounts.google.com",
            "",
        ] {
            let mut other = token();
            other.iss = iss.to_owned();
            assert_eq!(judge(&other), Err(IdTokenRefusal::Issuer), "{iss}");
        }
    }

    #[test]
    fn 다른_클라이언트용으로_낸_토큰은_받지_않는다() {
        let mut other = token();
        other.aud = Audience::One("other-client.apps.googleusercontent.com".to_owned());
        assert_eq!(judge(&other), Err(IdTokenRefusal::Audience));
        // 목록에 들어 있어도 여럿이면 azp 가 이 클라이언트여야 한다
        let mut many = token();
        many.aud = Audience::Many(vec![CLIENT.to_owned(), "other".to_owned()]);
        many.azp = Some("other".to_owned());
        assert_eq!(judge(&many), Err(IdTokenRefusal::Audience));
        many.azp = Some(CLIENT.to_owned());
        assert!(judge(&many).is_ok());
        let mut missing = token();
        missing.aud = Audience::Many(vec!["other".to_owned()]);
        assert_eq!(judge(&missing), Err(IdTokenRefusal::Audience));
        // 글자의 일부만 같아도 받지 않는다
        let mut prefix = token();
        prefix.aud = Audience::One(format!("{CLIENT}x"));
        assert_eq!(judge(&prefix), Err(IdTokenRefusal::Audience));
    }

    #[test]
    fn 만료된_토큰은_만료_시각부터_받지_않는다() {
        let mut edge = token();
        edge.exp = NOW + 1;
        assert!(judge(&edge).is_ok());
        edge.exp = NOW;
        assert_eq!(judge(&edge), Err(IdTokenRefusal::Expired));
    }

    #[test]
    fn 이_로그인에서_보낸_nonce_가_아니면_받지_않는다() {
        assert_eq!(
            judge_id_token(&token(), CLIENT, "aa11", Some("aa12"), NOW),
            Err(IdTokenRefusal::Nonce)
        );
        assert_eq!(
            judge_id_token(&token(), CLIENT, "aa11", None, NOW),
            Err(IdTokenRefusal::Nonce)
        );
    }

    #[test]
    fn google_이_확인하지_않은_이메일은_받지_않는다() {
        for verified in [
            None,
            Some(Flag::Bool(false)),
            Some(Flag::Text("false".to_owned())),
            Some(Flag::Text("yes".to_owned())),
        ] {
            let mut unverified = token();
            unverified.email_verified = verified.clone();
            assert_eq!(
                judge(&unverified),
                Err(IdTokenRefusal::EmailNotVerified),
                "{verified:?}"
            );
        }
        let mut no_email = token();
        no_email.email = None;
        assert_eq!(judge(&no_email), Err(IdTokenRefusal::EmailNotVerified));
        let mut blank = token();
        blank.email = Some("  ".to_owned());
        assert_eq!(judge(&blank), Err(IdTokenRefusal::EmailNotVerified));
    }

    #[test]
    fn 계정의_식별자가_빈_토큰은_받지_않는다() {
        let mut empty = token();
        empty.sub = String::new();
        assert_eq!(judge(&empty), Err(IdTokenRefusal::NoSubject));
    }

    #[test]
    fn state_는_10분_뒤부터_읽히지_않고_미리보기의_것은_받지_않는다() {
        assert_eq!(judge_state(&state(), NOW + STATE_TTL - 1), Ok(()));
        assert_eq!(
            judge_state(&state(), NOW + STATE_TTL),
            Err(StateRefusal::Expired)
        );
        let mut preview = state();
        preview.stage = Stage::Preview;
        assert_eq!(judge_state(&preview, NOW), Err(StateRefusal::NotProduction));
    }

    #[test]
    fn state_는_모르는_칸이_있으면_읽지_않는다() {
        let mut value = serde_json::to_value(state()).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<StateClaims>(value).is_err());
    }

    #[test]
    fn google_로_보내는_주소는_코드_흐름과_이메일만_묻고_값을_감싼다() {
        let location = authorize_location(
            "https://accounts.google.com/o/oauth2/v2/auth",
            CLIENT,
            "https://layer.example/v1/auth/google/callback",
            "s.t&x",
            "n1",
        );
        assert_eq!(
            location,
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=factory-client.apps.googleusercontent.com\
             &redirect_uri=https%3A//layer.example/v1/auth/google/callback&response_type=code\
             &scope=openid%20email&state=s.t%26x&nonce=n1"
        );
    }

    #[test]
    fn 콜백_주소는_레이어의_바깥_주소_하나에_선다() {
        assert_eq!(
            callback_url("https://layer.example/"),
            "https://layer.example/v1/auth/google/callback"
        );
    }
}
