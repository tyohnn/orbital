//! 운영의 로그인이 팩토리의 키를 쓰는 자리. 메일은 팩토리의 Resend 키와 보내는 주소로, Google 은 팩토리의 클라이언트로.
//!
//! 키는 쓸 때마다 [`Settings`] 에서 읽는다. 운영에 오른 뒤 팩토리가 키를 지우면 다음 요청부터 메일이 나가지 않고(답은 같다)
//! Google 의 시작 주소는 404 가 된다. 판정(`state` · `id_token`)은 core 의 `orbital_core::google` 이 한다.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use orbital_core::google::{
    IdToken, Stage as GoogleStage, StateClaims, authorize_location, state_expires_at,
};
use orbital_pg::auth::Secret;
use orbital_router::{GoogleDoor, Mail, MailFailure, Mailer, Outbox, Resend, login_mail};
use sha2::{Digest, Sha256};

use crate::settings::{GoogleClient, Settings};
use crate::token::{self, hex};

/// 레이어가 부르는 바깥 주소. 테스트는 가짜 서버로 갈아 끼운다.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// Resend 의 API(`https://api.resend.com`).
    pub resend: String,
    /// Google 의 인가 주소.
    pub google_authorize: String,
    /// Google 의 토큰 주소.
    pub google_token: String,
}

impl Default for Endpoints {
    /// 실제 주소. Google 의 것은 `https://accounts.google.com/.well-known/openid-configuration` 이 적은 값이다.
    fn default() -> Self {
        Self {
            resend: "https://api.resend.com".to_owned(),
            google_authorize: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            google_token: "https://oauth2.googleapis.com/token".to_owned(),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// 글자의 sha256 을 hex 로.
pub(crate) fn sha256_hex(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// 인스턴스 하나의 운영이 메일을 보내는 것. 보낼 때마다 그 팩토리의 키를 읽는다.
pub(crate) struct FactoryMailer {
    pub settings: Arc<Settings>,
    pub organization: String,
    /// 메일의 글에 쓰는 앱의 이름.
    pub app: String,
    pub resend: Resend,
    /// 개발용 메일함. 레이어가 명시해 켰을 때만 있고, 팩토리의 키가 없을 때 대신 쌓는다.
    pub outbox: Option<Arc<Outbox>>,
}

impl Mailer for FactoryMailer {
    fn send(&self, mail: Mail) -> Result<(), MailFailure> {
        if let Some(key) = self.settings.mail(&self.organization) {
            // 같은 링크의 메일은 두 번 나가지 않는다. 링크의 토큰이 아니라 그 해시에서 짓는다
            let idempotency = format!("orbital-login-{}", &sha256_hex(&mail.link)[..40]);
            return self.resend.deliver(
                &key,
                &mail.to,
                &login_mail(&self.app, &mail.link),
                &idempotency,
            );
        }
        match &self.outbox {
            Some(outbox) => outbox.send(mail),
            None => Err(MailFailure::NotConfigured),
        }
    }
}

/// 인스턴스 하나의 운영이 Google 로 보내는 문.
pub(crate) struct FactoryGoogleDoor {
    pub settings: Arc<Settings>,
    pub organization: String,
    pub instance: String,
    /// `state` 를 서명하는 열쇠. 레이어의 열쇠다.
    pub state_key: Vec<u8>,
    /// 레이어의 콜백 주소.
    pub callback: String,
    pub authorize_endpoint: String,
}

impl GoogleDoor for FactoryGoogleDoor {
    fn authorize(&self, next: &str, browser: &Secret) -> Option<String> {
        let client = self.settings.google(&self.organization)?;
        let nonce = Secret::generate().ok()?.to_text();
        let state = token::sign_state(
            &self.state_key,
            &StateClaims {
                instance: self.instance.clone(),
                stage: GoogleStage::Production,
                next: next.to_owned(),
                browser_hash: hex(&browser.hash()),
                nonce_hash: sha256_hex(&nonce),
                expires_at: state_expires_at(now()),
            },
        );
        Some(authorize_location(
            &self.authorize_endpoint,
            &client.client_id,
            &self.callback,
            &state,
            &nonce,
        ))
    }
}

/// Google 의 토큰 주소에서 `code` 를 바꾸지 못한 까닭. 문구와 기록에 값을 싣지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exchange {
    Unreachable,
    Refused,
    Malformed,
}

/// `code` 를 팩토리의 키로 `id_token` 과 바꾼다. 받은 토큰의 몸만 풀어 돌려준다(서명 대신 TLS 로 직접 받은 통로를 믿는다).
pub(crate) fn exchange(
    endpoint: &str,
    client: &GoogleClient,
    code: &str,
    redirect_uri: &str,
) -> Result<IdToken, Exchange> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(10))
        .build();
    let response = match agent
        .post(endpoint)
        .set("Accept", "application/json")
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &client.client_id),
            ("client_secret", &client.client_secret),
            ("redirect_uri", redirect_uri),
        ]) {
        Ok(response) => response,
        Err(ureq::Error::Status(_, _)) => return Err(Exchange::Refused),
        Err(ureq::Error::Transport(_)) => return Err(Exchange::Unreachable),
    };
    let body: serde_json::Value = response.into_json().map_err(|_| Exchange::Malformed)?;
    let id_token = body["id_token"].as_str().ok_or(Exchange::Malformed)?;
    let payload = id_token.split('.').nth(1).ok_or(Exchange::Malformed)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| Exchange::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| Exchange::Malformed)
}
