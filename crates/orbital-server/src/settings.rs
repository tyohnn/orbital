//! 팩토리의 설정. 팩토리(조직)마다 한 벌이고, 그 팩토리의 모든 인스턴스의 운영이 쓴다.
//!
//! 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않는다. 메일은 팩토리가 넣은 Resend 의 키와 보내는 주소로 나가고,
//! Google 로그인은 팩토리가 넣은 Google 클라이언트로 돈다. 비밀(`api_key` · `client_secret`)은 봉인한 글로만 파일에 두고([`crate::seal`]),
//! 어떤 답에도 돌려주지 않는다. 열쇠가 없는 레이어에서는 설정을 넣지 못한다.
//!
//! 파일(`settings.json`)은 레이어의 폴더 안에 있고 주인만 읽는다. 레이어의 큰 자물쇠와 따로 잠가, 운영의 router 가 메일을 보낼 때
//! 승격이 끝나기를 기다리지 않게 한다.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Mutex;

use orbital_core::release::Keys;
use orbital_router::ResendKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::seal::{SealKey, binding, open, seal};

/// 레이어가 아는 메일 발송기.
pub const RESEND: &str = "resend";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMail {
    provider: String,
    from: String,
    #[serde(default)]
    from_name: Option<String>,
    /// 봉인한 API 키.
    api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGoogle {
    client_id: String,
    /// 봉인한 클라이언트의 비밀.
    client_secret: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Organization {
    #[serde(default)]
    mail: Option<StoredMail>,
    #[serde(default)]
    google: Option<StoredGoogle>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    organizations: BTreeMap<String, Organization>,
}

/// 팩토리의 Google 클라이언트. 비밀은 찍지 않는다.
#[derive(Clone, PartialEq, Eq)]
pub struct GoogleClient {
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for GoogleClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleClient")
            .field("client_id", &self.client_id)
            .field("client_secret", &"..")
            .finish()
    }
}

/// 설정을 넣지 못한 까닭. 문구에 넣은 값은 싣지 않는다.
#[derive(Debug)]
pub enum SettingsError {
    /// 고칠 것이 있다.
    Problems(Vec<String>),
    /// 레이어에 봉인의 열쇠가 없다.
    NoSealKey,
    /// 적지 못했다.
    Internal(String),
}

pub struct Settings {
    path: PathBuf,
    seal: Option<SealKey>,
    stored: Mutex<Stored>,
}

const MAIL_KEY: &str = "mail.api_key";
const GOOGLE_SECRET: &str = "google.client_secret";

/// 칸 하나의 글자. 없거나 글자가 아니면 `None` 이다.
fn text<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// 보내는 주소의 모양. 줄바꿈 · 공백 · 꺾쇠가 없고 `@` 가 하나다. 받을 수 있는지는 Resend 가 본다.
fn mail_address(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && text.matches('@').count() == 1
        && !text
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "<>\"(),;:\\[]".contains(c))
}

/// 보낸 사람의 이름. `이름 <주소>` 의 모양을 깨는 글자를 받지 않는다.
fn display_name(text: &str) -> bool {
    !text.trim().is_empty()
        && text.chars().count() <= 64
        && !text
            .chars()
            .any(|c| c.is_control() || "<>\",;:@\\".contains(c))
}

impl Settings {
    /// 파일을 읽는다. 없으면 빈 설정이다.
    pub fn open(path: PathBuf, seal: Option<SealKey>) -> Result<Self, String> {
        let stored = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "팩토리의 설정을 읽지 못했습니다".to_owned())?,
            Err(_) => Stored::default(),
        };
        Ok(Self {
            path,
            seal,
            stored: Mutex::new(stored),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Stored> {
        self.stored
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save(&self, stored: &Stored) -> Result<(), SettingsError> {
        let failed = || SettingsError::Internal("팩토리의 설정을 적지 못했습니다".to_owned());
        let bytes = serde_json::to_vec_pretty(stored).map_err(|_| failed())?;
        let beside = self.path.with_extension("json.writing");
        fs::write(&beside, bytes).map_err(|_| failed())?;
        fs::set_permissions(&beside, fs::Permissions::from_mode(0o600)).map_err(|_| failed())?;
        fs::rename(&beside, &self.path).map_err(|_| failed())
    }

    fn unseal(&self, organization: &str, field: &str, sealed: &str) -> Option<String> {
        open(self.seal.as_ref()?, &binding(organization, field), sealed)
    }

    /// 그 팩토리의 메일 설정. 넣지 않았거나 봉인이 풀리지 않으면(열쇠가 다르거나 다른 조직의 줄에서 옮겨 왔으면) `None` 이다.
    pub fn mail(&self, organization: &str) -> Option<ResendKey> {
        let stored = self.lock().organizations.get(organization)?.mail.clone()?;
        Some(ResendKey {
            api_key: self.unseal(organization, MAIL_KEY, &stored.api_key)?,
            from: stored.from,
            from_name: stored.from_name,
        })
    }

    /// 그 팩토리의 Google 클라이언트. 넣지 않았거나 봉인이 풀리지 않으면 `None` 이다.
    pub fn google(&self, organization: &str) -> Option<GoogleClient> {
        let stored = self
            .lock()
            .organizations
            .get(organization)?
            .google
            .clone()?;
        Some(GoogleClient {
            client_secret: self.unseal(organization, GOOGLE_SECRET, &stored.client_secret)?,
            client_id: stored.client_id,
        })
    }

    /// 승격의 규칙에 넘길 것. 키가 있는지만 담는다.
    pub fn keys(&self, organization: &str, dev_mailbox: bool) -> Keys {
        Keys {
            mail: self.mail(organization).is_some(),
            google: self.google(organization).is_some(),
            dev_mailbox,
        }
    }

    /// 팩토리에게 보일 설정. 비밀은 싣지 않는다. `redirect_uri` 는 팩토리가 Google 콘솔에 등록할 레이어의 콜백이다.
    pub fn view(&self, organization: &str, redirect_uri: &str) -> Value {
        let stored = self
            .lock()
            .organizations
            .get(organization)
            .cloned()
            .unwrap_or_default();
        let mail = match &stored.mail {
            Some(mail) => json!({
                "configured": self.mail(organization).is_some(),
                "provider": mail.provider,
                "from": mail.from,
                "from_name": mail.from_name,
            }),
            None => json!({ "configured": false }),
        };
        let google = match &stored.google {
            Some(google) => json!({
                "configured": self.google(organization).is_some(),
                "client_id": google.client_id,
                "redirect_uri": redirect_uri,
            }),
            None => json!({ "configured": false, "redirect_uri": redirect_uri }),
        };
        json!({ "mail": mail, "google": google })
    }

    /// 설정을 바꾼다. `body` 의 칸이 없으면 그대로 두고, `null` 이면 지우고, 객체이면 통째로 바꾼다.
    pub fn update(&self, organization: &str, body: &[u8]) -> Result<(), SettingsError> {
        let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(body) else {
            return Err(SettingsError::Problems(vec![
                "요청의 본문은 `{ \"mail\": …, \"google\": … }` 모양의 JSON 이어야 합니다"
                    .to_owned(),
            ]));
        };
        // 모르는 칸의 이름은 되풀이하지 않는다. 키를 칸의 이름으로 잘못 넣었을 수 있다
        let mut problems: Vec<String> = Vec::new();
        if body
            .keys()
            .any(|key| !matches!(key.as_str(), "mail" | "google"))
        {
            problems.push("모르는 칸이 있습니다. `mail` 과 `google` 만 적어 주세요".to_owned());
        }
        let wants_secret = body.values().any(Value::is_object);
        if wants_secret && self.seal.is_none() {
            return Err(SettingsError::NoSealKey);
        }
        let key = self.seal.as_ref();
        let sealed = |field: &str, plain: &str| -> Result<String, SettingsError> {
            key.and_then(|key| seal(key, &binding(organization, field), plain))
                .ok_or(SettingsError::NoSealKey)
        };

        let mail = match body.get("mail") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Object(mail)) => {
                let provider = text(mail, "provider").unwrap_or(RESEND);
                if provider != RESEND {
                    problems.push(
                        "`mail.provider` 는 지금 `resend` 만 받습니다. `\"provider\": \"resend\"` 로 적어 주세요".to_owned(),
                    );
                }
                let api_key = text(mail, "api_key").map(str::trim).unwrap_or_default();
                if api_key.is_empty()
                    || api_key.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    problems.push(
                        "`mail.api_key` 가 비었거나 공백이 섞였습니다. Resend 에서 만든 API 키를 그대로 넣어 주세요".to_owned(),
                    );
                }
                let from = text(mail, "from").map(str::trim).unwrap_or_default();
                if !mail_address(from) {
                    problems.push(
                        "`mail.from` 은 `login@factory.example` 같은 메일 주소여야 합니다. Resend 에서 확인한 도메인의 주소를 적어 주세요".to_owned(),
                    );
                }
                let from_name = match mail.get("from_name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(name)) if display_name(name) => Some(name.trim().to_owned()),
                    Some(_) => {
                        problems.push(
                            "`mail.from_name` 은 64자 안의 글자여야 하고 줄바꿈과 `<>\",;:@\\` 를 쓸 수 없습니다. 앱이나 팩토리의 이름을 적어 주세요".to_owned(),
                        );
                        None
                    }
                };
                if mail.keys().any(|key| {
                    !matches!(key.as_str(), "provider" | "api_key" | "from" | "from_name")
                }) {
                    problems.push(
                        "`mail` 에 모르는 칸이 있습니다. `provider` · `api_key` · `from` · `from_name` 만 적어 주세요".to_owned(),
                    );
                }
                if problems.is_empty() {
                    Some(Some(StoredMail {
                        provider: RESEND.to_owned(),
                        from: from.to_owned(),
                        from_name,
                        api_key: sealed(MAIL_KEY, api_key)?,
                    }))
                } else {
                    None
                }
            }
            Some(_) => {
                problems.push("`mail` 은 객체이거나 `null` 이어야 합니다".to_owned());
                None
            }
        };

        let google = match body.get("google") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Object(google)) => {
                let client_id = text(google, "client_id").map(str::trim).unwrap_or_default();
                if client_id.is_empty()
                    || client_id
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                {
                    problems.push(
                        "`google.client_id` 가 비었거나 공백이 섞였습니다. Google 콘솔의 OAuth 클라이언트 ID 를 그대로 넣어 주세요".to_owned(),
                    );
                }
                let secret = text(google, "client_secret")
                    .map(str::trim)
                    .unwrap_or_default();
                if secret.is_empty() || secret.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    problems.push(
                        "`google.client_secret` 가 비었거나 공백이 섞였습니다. Google 콘솔의 클라이언트 보안 비밀을 그대로 넣어 주세요".to_owned(),
                    );
                }
                if google
                    .keys()
                    .any(|key| !matches!(key.as_str(), "client_id" | "client_secret"))
                {
                    problems.push(
                        "`google` 에 모르는 칸이 있습니다. `client_id` 와 `client_secret` 만 적어 주세요".to_owned(),
                    );
                }
                if problems.is_empty() {
                    Some(Some(StoredGoogle {
                        client_id: client_id.to_owned(),
                        client_secret: sealed(GOOGLE_SECRET, secret)?,
                    }))
                } else {
                    None
                }
            }
            Some(_) => {
                problems.push("`google` 은 객체이거나 `null` 이어야 합니다".to_owned());
                None
            }
        };

        if !problems.is_empty() {
            return Err(SettingsError::Problems(problems));
        }
        let mut stored = self.lock();
        let mut next = stored
            .organizations
            .get(organization)
            .cloned()
            .unwrap_or_default();
        if let Some(mail) = mail {
            next.mail = mail;
        }
        if let Some(google) = google {
            next.google = google;
        }
        let previous = stored.organizations.insert(organization.to_owned(), next);
        if let Err(error) = self.save(&stored) {
            // 적지 못했으면 메모리도 앞의 것으로 돌린다
            match previous {
                Some(previous) => stored
                    .organizations
                    .insert(organization.to_owned(), previous),
                None => stored.organizations.remove(organization),
            };
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 보내는_주소와_이름의_모양을_본다() {
        assert!(mail_address("login@factory.example"));
        for bad in [
            "",
            "login",
            "login@",
            "@factory.example",
            "a@b@factory.example",
            "login@factory",
            "Name <login@factory.example>",
            "login@factory.example\r\nBcc: x@y.z",
            "lo gin@factory.example",
        ] {
            assert!(!mail_address(bad), "{bad}");
        }
        assert!(display_name("할 일 카드"));
        for bad in ["", "  ", "a<b", "a\nb", "a,b", "\"q\""] {
            assert!(!display_name(bad), "{bad}");
        }
    }
}
