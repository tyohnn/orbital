//! 실제 메일 발송기(Resend). 팩토리가 넣은 키와 보내는 주소로 보낸다. 레이어에는 공용 발송 도메인이 없다.
//!
//! 모양은 Resend 의 문서(<https://resend.com/docs/api-reference/emails/send-email>,
//! <https://resend.com/docs/api-reference/introduction>)를 따른다: `POST {base}/emails`, `Authorization: Bearer <키>`,
//! `User-Agent` 는 반드시 싣고(없으면 403), 같은 메일을 두 번 보내지 않게 `Idempotency-Key`(256자 이하, 24시간)를 싣는다.
//! 본문은 `from`(`이름 <주소>`) · `to` · `subject` · `text` · `html` 이고, 답은 `{ "id": … }` 다.
//! 실패하면 상태만 돌려준다. 답의 본문(받는 주소가 섞일 수 있다)과 키는 어디에도 싣지 않는다.

use std::fmt;
use std::time::Duration;

use serde_json::json;

use crate::MailFailure;

/// 팩토리의 메일 설정. 키는 찍지 않는다.
#[derive(Clone, PartialEq, Eq)]
pub struct ResendKey {
    pub api_key: String,
    /// 보내는 주소. 팩토리가 Resend 에서 확인한 도메인의 주소다.
    pub from: String,
    /// 보낸 사람의 이름. 없으면 주소만 보인다.
    pub from_name: Option<String>,
}

impl fmt::Debug for ResendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResendKey")
            .field("api_key", &"..")
            .field("from", &self.from)
            .field("from_name", &self.from_name)
            .finish()
    }
}

/// 로그인 링크 한 통의 글.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// 레이어의 기본 글. 앱의 이름과 링크, 15분 뒤 만료된다는 말을 싣는다.
pub fn login_mail(app: &str, link: &str) -> LoginMail {
    let subject = format!("{app} 로그인 링크");
    let text = format!(
        "{app}에 로그인하려면 아래 링크를 열어 주세요.\n\n{link}\n\n\
         링크는 15분 뒤에 만료되고 한 번만 쓸 수 있습니다. 링크를 요청한 브라우저에서 열어 주세요.\n\
         로그인을 요청하지 않았다면 이 메일은 지워도 됩니다.\n"
    );
    let (app, link) = (escape(app), escape(link));
    let html = format!(
        "<!doctype html><html lang=\"ko\"><body>\
         <p>{app}에 로그인하려면 아래 단추를 눌러 주세요.</p>\
         <p><a href=\"{link}\">{app}에 로그인</a></p>\
         <p>링크는 15분 뒤에 만료되고 한 번만 쓸 수 있습니다. 링크를 요청한 브라우저에서 열어 주세요.</p>\
         <p>로그인을 요청하지 않았다면 이 메일은 지워도 됩니다.</p>\
         </body></html>"
    );
    LoginMail {
        subject,
        text,
        html,
    }
}

/// Resend 의 API. 주소(base)는 갈아 끼운다. `orbitald` 는 `https://api.resend.com` 을, 테스트는 가짜 서버를 쓴다.
#[derive(Debug, Clone)]
pub struct Resend {
    base: String,
}

/// 한 통을 보내는 데 기다리는 시간.
const TIMEOUT: Duration = Duration::from_secs(10);

impl Resend {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_owned(),
        }
    }

    /// 한 통을 보낸다. `idempotency` 는 같은 링크의 메일을 두 번 보내지 않게 하는 열쇠다(링크의 토큰이 아니라 그 해시에서 짓는다).
    pub fn deliver(
        &self,
        key: &ResendKey,
        to: &str,
        mail: &LoginMail,
        idempotency: &str,
    ) -> Result<(), MailFailure> {
        let from = match &key.from_name {
            Some(name) if !name.trim().is_empty() => format!("{} <{}>", name.trim(), key.from),
            _ => key.from.clone(),
        };
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(TIMEOUT)
            .build();
        let sent = agent
            .post(&format!("{}/emails", self.base))
            .set("Authorization", &format!("Bearer {}", key.api_key))
            .set("User-Agent", "orbital-layer")
            .set("Idempotency-Key", idempotency)
            .send_json(json!({
                "from": from,
                "to": [to],
                "subject": mail.subject,
                "text": mail.text,
                "html": mail.html,
            }));
        match sent {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Ok(response) => Err(MailFailure::Rejected {
                status: response.status(),
            }),
            Err(ureq::Error::Status(status, _)) => Err(MailFailure::Rejected { status }),
            Err(ureq::Error::Transport(_)) => Err(MailFailure::Unreachable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 로그인_메일의_글은_앱의_이름과_링크와_만료를_싣고_html_은_값을_감싼다() {
        let mail = login_mail(
            "할 일 <카드>",
            "https://a.example/_orbital/auth/callback?token=ab&x=1",
        );
        assert_eq!(mail.subject, "할 일 <카드> 로그인 링크");
        assert!(
            mail.text
                .contains("https://a.example/_orbital/auth/callback?token=ab&x=1")
        );
        assert!(mail.text.contains("15분"));
        assert!(mail.html.contains("할 일 &lt;카드&gt;"));
        assert!(mail.html.contains("token=ab&amp;x=1"));
        assert!(!mail.html.contains("<카드>"));
    }

    #[test]
    fn 발송_설정은_찍어도_키가_보이지_않는다() {
        let key = ResendKey {
            api_key: "re_secret_value".to_owned(),
            from: "login@factory.example".to_owned(),
            from_name: None,
        };
        assert!(!format!("{key:?}").contains("re_secret_value"));
    }
}
