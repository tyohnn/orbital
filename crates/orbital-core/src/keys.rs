//! 팩토리(조직)와 service key 의 판정.
//!
//! 팩토리는 가입하면 조직 하나를 얻고, 그 조직의 service key 로 레이어를 부른다. 판정은 셋이다.
//! - 조직 이름이 바른가(`organization_name`).
//! - 키 하나를 폐기해도 되는가(`judge_revoke`). 조직의 마지막 살아 있는 키는 폐기하지 못해 조직이 잠기지 않는다.
//! - 운영자가 조직에 키를 내도 되는가(`judge_operator_issue`). 운영자는 살아 있는 키가 없는 조직에만 키를 낸다.
//!   그래서 운영자 키로는 살아 있는 팩토리의 인스턴스에 닿지 못한다.
//!
//! 환경 변수의 키(`ORBITAL_SERVICE_KEYS`)는 부트스트랩이다. 그 조직은 저장한 키가 없어도 잠기지 않은 것으로 본다.

use serde::{Deserialize, Serialize};

/// 조직 이름의 문제. 오류 문구는 레이어가 짓는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadOrganization;

impl std::fmt::Display for BadOrganization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "조직 이름은 소문자 · 숫자로 시작하고 소문자 · 숫자 · - · _ 로 64글자까지여야 합니다",
        )
    }
}

/// 조직 이름. 소문자 · 숫자로 시작하고 소문자 · 숫자 · `-` · `_` 로 64글자까지다(Higgs 의 조직 이름과 같은 규칙).
/// 조직 이름은 레이어의 기록과 API 에만 쓰이고 database 와 역할의 이름에는 들어가지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrganizationName(String);

impl TryFrom<String> for OrganizationName {
    type Error = BadOrganization;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        organization_name(&text)
    }
}

impl From<OrganizationName> for String {
    fn from(name: OrganizationName) -> Self {
        name.0
    }
}

impl OrganizationName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn organization_name(raw: &str) -> Result<OrganizationName, BadOrganization> {
    let mut chars = raw.chars();
    let valid = raw.len() <= 64
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        Ok(OrganizationName(raw.to_owned()))
    } else {
        Err(BadOrganization)
    }
}

/// 키 한 줄의 판정에 쓰는 모습. 비밀과 해시는 판정에 필요 없다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyState {
    pub id: String,
    pub revoked: bool,
}

/// 폐기 판정의 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revoke {
    /// 폐기한다.
    Revoke,
    /// 이미 폐기한 키다. 같은 답을 돌려주고 아무것도 바꾸지 않는다.
    AlreadyRevoked,
    /// 이 조직의 키가 아니다. 다른 조직의 키도 없는 키와 같다.
    NotFound,
    /// 조직의 마지막 살아 있는 키다. 폐기하면 조직이 잠긴다.
    LastLiveKey,
}

/// `keys` 는 그 조직의 키만 담는다. `bootstrap` 은 환경 변수의 키가 그 조직에 있는가다.
pub fn judge_revoke(keys: &[KeyState], id: &str, bootstrap: bool) -> Revoke {
    let Some(key) = keys.iter().find(|key| key.id == id) else {
        return Revoke::NotFound;
    };
    if key.revoked {
        return Revoke::AlreadyRevoked;
    }
    let others_live = keys.iter().any(|other| other.id != id && !other.revoked);
    if others_live || bootstrap {
        Revoke::Revoke
    } else {
        Revoke::LastLiveKey
    }
}

/// 운영자가 키를 내는 판정의 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorIssue {
    Issue,
    /// 없는 조직이다.
    NotFound,
    /// 살아 있는 키가 있다. 조직의 키로 만들어야 한다.
    HasLiveKey,
    /// 환경 변수의 키가 있는 조직이다.
    Bootstrap,
}

/// 운영자가 조직에 키를 하나 내어 되살려도 되는가. `keys` 는 그 조직이 있으면 `Some`.
pub fn judge_operator_issue(keys: Option<&[KeyState]>, bootstrap: bool) -> OperatorIssue {
    if bootstrap {
        return OperatorIssue::Bootstrap;
    }
    match keys {
        None => OperatorIssue::NotFound,
        Some(keys) if keys.iter().any(|key| !key.revoked) => OperatorIssue::HasLiveKey,
        Some(_) => OperatorIssue::Issue,
    }
}

/// 키의 이름(「배포 서버」 같은)은 100글자까지다.
pub fn label_fits(label: &str) -> bool {
    label.chars().count() <= 100
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, revoked: bool) -> KeyState {
        KeyState {
            id: id.to_owned(),
            revoked,
        }
    }

    #[test]
    fn 조직_이름은_소문자_숫자로_시작하고_소문자_숫자_하이픈_밑줄로_64글자까지다() {
        assert!(organization_name("acme").is_ok());
        assert!(organization_name("0-factory_co").is_ok());
        assert!(organization_name(&"a".repeat(64)).is_ok());
        for bad in ["", "-acme", "_acme", "Acme", "ac me", "acme.", "아크미"] {
            assert_eq!(organization_name(bad), Err(BadOrganization), "{bad}");
        }
        assert!(organization_name(&"a".repeat(65)).is_err());
        assert!(serde_json::from_str::<OrganizationName>("\"Acme\"").is_err());
    }

    #[test]
    fn 살아_있는_키가_하나뿐이면_폐기하지_못하고_다른_키가_있으면_폐기한다() {
        let keys = [key("a", false), key("b", true)];
        assert_eq!(judge_revoke(&keys, "a", false), Revoke::LastLiveKey);
        let keys = [key("a", false), key("b", false)];
        assert_eq!(judge_revoke(&keys, "a", false), Revoke::Revoke);
    }

    #[test]
    fn 환경_변수의_키가_있는_조직은_마지막_저장한_키도_폐기한다() {
        assert_eq!(judge_revoke(&[key("a", false)], "a", true), Revoke::Revoke);
    }

    #[test]
    fn 없는_키는_없다고_하고_이미_폐기한_키는_다시_폐기하지_않는다() {
        let keys = [key("a", false), key("b", true)];
        assert_eq!(judge_revoke(&keys, "c", false), Revoke::NotFound);
        assert_eq!(judge_revoke(&keys, "b", false), Revoke::AlreadyRevoked);
    }

    #[test]
    fn 운영자는_살아_있는_키가_없는_조직에만_키를_낸다() {
        assert_eq!(
            judge_operator_issue(Some(&[key("a", true)]), false),
            OperatorIssue::Issue
        );
        assert_eq!(judge_operator_issue(Some(&[]), false), OperatorIssue::Issue);
        assert_eq!(
            judge_operator_issue(Some(&[key("a", false)]), false),
            OperatorIssue::HasLiveKey
        );
        assert_eq!(judge_operator_issue(None, false), OperatorIssue::NotFound);
        assert_eq!(
            judge_operator_issue(Some(&[]), true),
            OperatorIssue::Bootstrap
        );
    }
}
