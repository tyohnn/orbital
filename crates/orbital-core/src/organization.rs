//! 조직(팩토리)과 service key 의 판정. 받을 열쇠인가, 그 열쇠를 거둘 수 있는가, 열쇠를 더 낼 수 있는가(조직 스스로 · 운영자),
//! 그 조직이 인스턴스를 더 세울 수 있는가, 조직을 닫을 수 있는가.
//!
//! 열쇠의 값을 읽고 sha256 을 셈하고 기록을 찾는 일은 관리 서버가 한다. 여기서는 찾은 사실(어디서 왔나 · 거뒀나 · 조직이 닫혔나 ·
//! 살아 있는 열쇠의 수 · 설정의 열쇠가 있나)을 받아 판정만 한다.
//! 시험용 조직(`test`)과 운영의 조직(`live`)이 갈리는 자리는 인스턴스의 상한 하나뿐이다. 열쇠는 종류와 상관없이 `orb_sk_` 로 시작한다.
//!
//! 설정의 열쇠(`ORBITAL_SERVICE_KEYS`)는 부트스트랩이다. 목록에 보이지 않고 API 로 거두지 못하며, 그 조직은 기록의 열쇠가 없어도 잠기지 않은 것으로 본다.

use serde::{Deserialize, Serialize};

use crate::scope::OrganizationId;

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
/// 조직 이름은 레이어의 기록과 API 에만 쓰이고 database 와 역할의 이름에는 들어가지 않는다. SQL 에는 매개변수로만 간다.
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

/// service key 가 시작하는 글자. 조직의 종류와 상관없이 같다(종류는 조직이 안다). 비밀 검사 도구가 찾기 쉽다.
pub const KEY_PREFIX: &str = "orb_sk_";

/// 조직의 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// 운영의 조직. 인스턴스의 상한이 없다.
    Live,
    /// 바로 쓰는 시험용 조직. 인스턴스의 수에 상한이 있고, 그 밖의 규칙은 `live` 와 같다.
    Test,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "live" => Some(Self::Live),
            "test" => Some(Self::Test),
            _ => None,
        }
    }
}

/// 시험용 조직이 세울 수 있는 인스턴스의 기본 상한(`ORBITAL_TEST_INSTANCE_LIMIT`).
pub const TEST_INSTANCE_LIMIT: u32 = 10;

/// 기록에 있는 조직의 모습.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationState {
    pub kind: Kind,
    /// 닫혔는가. 닫힌 조직의 열쇠는 어디서 왔든 받지 않는다.
    pub closed: bool,
}

/// 요청에 실려 온 열쇠를 찾아본 결과.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "found", rename_all = "snake_case")]
pub enum Presented {
    /// 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)에 있는 열쇠. 그 조직이 기록에 없으면 `state` 가 없다(운영의 조직으로 본다).
    Configured {
        organization: OrganizationId,
        state: Option<OrganizationState>,
    },
    /// 기록(control database)에 있는 열쇠. 기록의 열쇠는 언제나 기록의 조직에 딸린다.
    Recorded {
        key: String,
        organization: OrganizationId,
        revoked: bool,
        state: OrganizationState,
    },
    /// 어디에도 없다.
    Unknown,
}

/// 받아들인 열쇠의 주인.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    pub organization: OrganizationId,
    pub kind: Kind,
    /// 기록의 열쇠면 그 열쇠의 식별자. 설정의 열쇠면 없다.
    pub key: Option<String>,
}

/// 열쇠를 받지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRefusal {
    /// 모르는 열쇠다.
    Unknown,
    /// 거둔 열쇠다.
    Revoked,
    /// 열쇠의 조직이 닫혔다.
    Closed,
}

/// 실려 온 열쇠를 받을지 판정한다. 거둔 열쇠와 닫힌 조직의 열쇠는 어떤 일에도 받지 않는다.
pub fn judge_key(presented: &Presented) -> Result<Caller, KeyRefusal> {
    match presented {
        Presented::Unknown => Err(KeyRefusal::Unknown),
        Presented::Recorded { revoked: true, .. } => Err(KeyRefusal::Revoked),
        Presented::Recorded {
            state: OrganizationState { closed: true, .. },
            ..
        }
        | Presented::Configured {
            state: Some(OrganizationState { closed: true, .. }),
            ..
        } => Err(KeyRefusal::Closed),
        Presented::Recorded {
            key,
            organization,
            state,
            ..
        } => Ok(Caller {
            organization: organization.clone(),
            kind: state.kind,
            key: Some(key.clone()),
        }),
        Presented::Configured {
            organization,
            state,
        } => Ok(Caller {
            organization: organization.clone(),
            kind: state.map_or(Kind::Live, |state| state.kind),
            key: None,
        }),
    }
}

/// 열쇠를 거둘 때 보는 그 열쇠의 사실.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFacts {
    pub organization: OrganizationId,
    pub revoked: bool,
}

/// 거두기의 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revoking {
    /// 거둔다.
    Revoke,
    /// 이미 거둔 것이다. 아무것도 바꾸지 않는다.
    AlreadyRevoked,
}

/// 열쇠를 거두지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeRefusal {
    /// 없는 열쇠이거나 다른 조직의 것이다. 둘을 가르지 않는다.
    NotFound,
    /// 그 조직의 살아 있는 마지막 열쇠다. 거두면 조직이 잠긴다. 새 열쇠를 먼저 낸다.
    LastKey,
}

/// `caller` 의 조직이 열쇠 하나(`target`, 없으면 `None`)를 거둘 수 있는가. `alive` 는 그 조직의 기록에 살아 있는 열쇠의 수다(거둘 것을 포함).
/// `bootstrap` 은 그 조직에 설정의 열쇠가 있는가다. 있으면 기록의 마지막 열쇠를 거둬도 조직이 잠기지 않는다.
pub fn judge_revoke(
    caller: &OrganizationId,
    target: Option<&KeyFacts>,
    alive: u32,
    bootstrap: bool,
) -> Result<Revoking, RevokeRefusal> {
    let Some(target) = target.filter(|target| &target.organization == caller) else {
        return Err(RevokeRefusal::NotFound);
    };
    if target.revoked {
        return Ok(Revoking::AlreadyRevoked);
    }
    if alive <= 1 && !bootstrap {
        return Err(RevokeRefusal::LastKey);
    }
    Ok(Revoking::Revoke)
}

/// 조직이 제 열쇠로 열쇠를 더 내지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueRefusal {
    /// 기록에도 설정에도 없는 조직이다.
    NotFound,
    /// 닫힌 조직이다.
    Closed,
}

/// 조직이 제 열쇠로 열쇠를 하나 더 낼 수 있는가. `state` 는 기록의 조직이고, `bootstrap` 은 설정의 열쇠가 있는가다.
/// 설정의 열쇠만 있는 조직도 낸다(그 조직의 기록이 운영의 조직으로 생긴다).
pub fn judge_issue(state: Option<&OrganizationState>, bootstrap: bool) -> Result<(), IssueRefusal> {
    match state {
        None if bootstrap => Ok(()),
        None => Err(IssueRefusal::NotFound),
        Some(OrganizationState { closed: true, .. }) => Err(IssueRefusal::Closed),
        Some(_) => Ok(()),
    }
}

/// 운영자가 조직에 열쇠를 내는 모양.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorIssue {
    /// 살아 있는 열쇠가 없는 조직에 하나를 낸다(잠긴 조직을 되살린다).
    Issue,
    /// 그 조직의 살아 있는 열쇠를 모두 거두고 새 열쇠 하나를 낸다(열쇠가 새어 나갔거나 모두 잃었을 때).
    Reset,
}

/// 운영자가 열쇠를 내지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRefusal {
    /// 기록에 없는 조직이다.
    NotFound,
    /// 설정의 열쇠가 있는 조직이다. 운영자는 손대지 않는다.
    Bootstrap,
    /// 닫힌 조직이다.
    Closed,
    /// 살아 있는 열쇠가 있다. 조직의 열쇠로 새 열쇠를 내야 한다(`Issue` 만).
    HasLiveKey,
}

/// 운영자가 조직에 열쇠를 내도 되는가. 운영자는 살아 있는 열쇠가 있는 조직에 열쇠를 보태지 않는다.
/// 그래서 운영자 키로는 살아 있는 팩토리의 인스턴스에 몰래 닿지 못한다. `Reset` 은 살아 있는 열쇠를 모두 끊으므로 조직이 알아챈다.
pub fn judge_operator_issue(
    state: Option<&OrganizationState>,
    alive: u32,
    bootstrap: bool,
    how: OperatorIssue,
) -> Result<(), OperatorRefusal> {
    if bootstrap {
        return Err(OperatorRefusal::Bootstrap);
    }
    match state {
        None => Err(OperatorRefusal::NotFound),
        Some(OrganizationState { closed: true, .. }) => Err(OperatorRefusal::Closed),
        Some(_) if how == OperatorIssue::Issue && alive > 0 => Err(OperatorRefusal::HasLiveKey),
        Some(_) => Ok(()),
    }
}

/// 인스턴스를 더 세우지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstanceRefusal {
    /// 조직이 닫혔다.
    Closed,
    /// 시험용 조직의 인스턴스가 상한에 닿았다.
    TestLimit { limit: u32 },
}

/// 그 조직이 인스턴스를 하나 더 세울 수 있는가. `existing` 은 지금 그 조직의 인스턴스의 수다.
/// 기록에 없는 조직(설정의 열쇠만 있는 조직)은 운영의 조직으로 본다.
pub fn judge_new_instance(
    state: Option<&OrganizationState>,
    existing: u32,
    test_limit: u32,
) -> Result<(), InstanceRefusal> {
    match state {
        Some(OrganizationState { closed: true, .. }) => Err(InstanceRefusal::Closed),
        Some(OrganizationState {
            kind: Kind::Test, ..
        }) if existing >= test_limit => Err(InstanceRefusal::TestLimit { limit: test_limit }),
        _ => Ok(()),
    }
}

/// 조직을 닫지 않는 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloseRefusal {
    /// 기록에 없는 조직이다.
    NotFound,
    /// 인스턴스가 남아 있다. 먼저 지울 것의 식별자를 싣는다.
    InstancesRemain { instances: Vec<String> },
}

/// 조직을 닫을 수 있는가. 이미 닫힌 조직을 다시 닫는 것은 아무것도 바꾸지 않고 받는다.
pub fn judge_close(
    state: Option<&OrganizationState>,
    instances: &[String],
) -> Result<(), CloseRefusal> {
    if state.is_none() {
        return Err(CloseRefusal::NotFound);
    }
    if !instances.is_empty() {
        return Err(CloseRefusal::InstancesRemain {
            instances: instances.to_vec(),
        });
    }
    Ok(())
}

/// 사람이 붙이는 이름표의 문제.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelProblem {
    Empty,
    TooLong {
        max: usize,
    },
    /// 줄바꿈 같은 제어 문자가 들었다.
    Control,
}

/// 비울 수 없는 이름표(승인한 사람)의 최대 글자 수.
pub const LABEL_MAX: usize = 80;

/// 비울 수 없는 이름표를 본다. 앞뒤의 빈칸은 떼고 본다.
pub fn check_label(text: &str) -> Result<String, LabelProblem> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(LabelProblem::Empty);
    }
    if trimmed.chars().count() > LABEL_MAX {
        return Err(LabelProblem::TooLong { max: LABEL_MAX });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(LabelProblem::Control);
    }
    Ok(trimmed.to_owned())
}

/// 열쇠와 조직의 이름표(「배포 서버」 · 「Acme 팩토리」)의 최대 글자 수.
pub const KEY_LABEL_MAX: usize = 100;

/// 열쇠와 조직의 이름표를 본다. 비어도 된다(이름 없이 낸다). 앞뒤의 빈칸은 떼고 본다.
pub fn check_key_label(text: &str) -> Result<String, LabelProblem> {
    let trimmed = text.trim();
    if trimmed.chars().count() > KEY_LABEL_MAX {
        return Err(LabelProblem::TooLong { max: KEY_LABEL_MAX });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(LabelProblem::Control);
    }
    Ok(trimmed.to_owned())
}

/// 「마지막으로 쓴 때」를 적을 단위(초). 요청마다 적지 않도록 이 단위로 뭉친다.
pub const USED_AT_GRAIN: u64 = 60;

/// 지금(`now`) 열쇠를 썼을 때 적을 「마지막으로 쓴 때」. 이미 적힌 때(`recorded`)가 같은 단위 안이면 `None`(적지 않는다)이다.
pub fn used_at(recorded: Option<u64>, now: u64) -> Option<u64> {
    let grained = now - now % USED_AT_GRAIN;
    match recorded {
        Some(recorded) if recorded >= grained => None,
        _ => Some(grained),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(name: &str) -> OrganizationId {
        OrganizationId(name.to_owned())
    }

    const LIVE: OrganizationState = OrganizationState {
        kind: Kind::Live,
        closed: false,
    };
    const TEST: OrganizationState = OrganizationState {
        kind: Kind::Test,
        closed: false,
    };
    const CLOSED: OrganizationState = OrganizationState {
        kind: Kind::Live,
        closed: true,
    };

    #[test]
    fn 기록의_열쇠는_거뒀거나_조직이_닫혔으면_받지_않고_아니면_그_조직과_종류로_받는다() {
        let recorded = |revoked, state| Presented::Recorded {
            key: "key_1".to_owned(),
            organization: org("acme"),
            revoked,
            state,
        };
        assert_eq!(
            judge_key(&recorded(false, TEST)),
            Ok(Caller {
                organization: org("acme"),
                kind: Kind::Test,
                key: Some("key_1".to_owned())
            })
        );
        assert_eq!(judge_key(&recorded(true, TEST)), Err(KeyRefusal::Revoked));
        assert_eq!(judge_key(&recorded(false, CLOSED)), Err(KeyRefusal::Closed));
        assert_eq!(judge_key(&Presented::Unknown), Err(KeyRefusal::Unknown));
    }

    #[test]
    fn 설정의_열쇠는_기록에_조직이_없으면_운영의_조직이고_닫힌_조직이면_받지_않는다() {
        let configured = |state| Presented::Configured {
            organization: org("factory"),
            state,
        };
        assert_eq!(
            judge_key(&configured(None)).map(|caller| (caller.kind, caller.key)),
            Ok((Kind::Live, None))
        );
        assert_eq!(
            judge_key(&configured(Some(TEST))).map(|caller| caller.kind),
            Ok(Kind::Test)
        );
        assert_eq!(
            judge_key(&configured(Some(CLOSED))),
            Err(KeyRefusal::Closed)
        );
    }

    #[test]
    fn 살아_있는_마지막_열쇠는_거두지_못하고_둘이면_거둔다() {
        let mine = KeyFacts {
            organization: org("acme"),
            revoked: false,
        };
        assert_eq!(
            judge_revoke(&org("acme"), Some(&mine), 1, false),
            Err(RevokeRefusal::LastKey)
        );
        assert_eq!(
            judge_revoke(&org("acme"), Some(&mine), 2, false),
            Ok(Revoking::Revoke)
        );
    }

    #[test]
    fn 설정의_열쇠가_있는_조직은_기록의_마지막_열쇠도_거둔다() {
        let mine = KeyFacts {
            organization: org("acme"),
            revoked: false,
        };
        assert_eq!(
            judge_revoke(&org("acme"), Some(&mine), 1, true),
            Ok(Revoking::Revoke)
        );
    }

    #[test]
    fn 없는_열쇠와_다른_조직의_열쇠는_없다고_하고_이미_거둔_열쇠는_다시_거두지_않는다() {
        let mine = KeyFacts {
            organization: org("acme"),
            revoked: false,
        };
        let gone = KeyFacts {
            revoked: true,
            ..mine.clone()
        };
        assert_eq!(
            judge_revoke(&org("acme"), Some(&gone), 1, false),
            Ok(Revoking::AlreadyRevoked)
        );
        assert_eq!(
            judge_revoke(&org("other"), Some(&mine), 2, false),
            Err(RevokeRefusal::NotFound)
        );
        assert_eq!(
            judge_revoke(&org("acme"), None, 2, false),
            Err(RevokeRefusal::NotFound)
        );
    }

    #[test]
    fn 시험용_조직은_상한에_닿으면_더_세우지_못하고_상한_바로_아래에서는_세운다() {
        assert_eq!(judge_new_instance(Some(&TEST), 9, 10), Ok(()));
        assert_eq!(
            judge_new_instance(Some(&TEST), 10, 10),
            Err(InstanceRefusal::TestLimit { limit: 10 })
        );
        assert_eq!(judge_new_instance(Some(&LIVE), 10_000, 10), Ok(()));
        assert_eq!(judge_new_instance(None, 10_000, 10), Ok(()));
        assert_eq!(
            judge_new_instance(Some(&CLOSED), 0, 10),
            Err(InstanceRefusal::Closed)
        );
    }

    #[test]
    fn 조직은_열려_있으면_종류와_상관없이_열쇠를_더_내고_설정의_열쇠만_있는_조직도_낸다() {
        assert_eq!(judge_issue(Some(&TEST), false), Ok(()));
        assert_eq!(judge_issue(Some(&LIVE), false), Ok(()));
        assert_eq!(judge_issue(None, true), Ok(()));
        assert_eq!(judge_issue(Some(&CLOSED), true), Err(IssueRefusal::Closed));
        assert_eq!(judge_issue(None, false), Err(IssueRefusal::NotFound));
    }

    #[test]
    fn 운영자는_살아_있는_키가_없는_조직에만_키를_낸다() {
        let issue = |state, alive, bootstrap| {
            judge_operator_issue(state, alive, bootstrap, OperatorIssue::Issue)
        };
        assert_eq!(issue(Some(&LIVE), 0, false), Ok(()));
        assert_eq!(issue(Some(&TEST), 0, false), Ok(()));
        assert_eq!(
            issue(Some(&LIVE), 1, false),
            Err(OperatorRefusal::HasLiveKey)
        );
        assert_eq!(issue(None, 0, false), Err(OperatorRefusal::NotFound));
        assert_eq!(issue(Some(&CLOSED), 0, false), Err(OperatorRefusal::Closed));
        assert_eq!(issue(Some(&LIVE), 0, true), Err(OperatorRefusal::Bootstrap));
        assert_eq!(issue(None, 0, true), Err(OperatorRefusal::Bootstrap));
    }

    #[test]
    fn 운영자의_키_갈기는_살아_있는_키가_있어도_하되_설정의_조직과_닫힌_조직과_없는_조직에는_하지_않는다()
     {
        let reset = |state, alive, bootstrap| {
            judge_operator_issue(state, alive, bootstrap, OperatorIssue::Reset)
        };
        assert_eq!(reset(Some(&LIVE), 3, false), Ok(()));
        assert_eq!(reset(Some(&LIVE), 0, false), Ok(()));
        assert_eq!(reset(Some(&LIVE), 1, true), Err(OperatorRefusal::Bootstrap));
        assert_eq!(reset(Some(&CLOSED), 1, false), Err(OperatorRefusal::Closed));
        assert_eq!(reset(None, 0, false), Err(OperatorRefusal::NotFound));
    }

    #[test]
    fn 인스턴스가_남은_조직은_닫지_못하고_남은_것을_알린다() {
        assert_eq!(
            judge_close(Some(&LIVE), &["i1".to_owned()]),
            Err(CloseRefusal::InstancesRemain {
                instances: vec!["i1".to_owned()]
            })
        );
        assert_eq!(judge_close(Some(&LIVE), &[]), Ok(()));
        assert_eq!(judge_close(Some(&CLOSED), &[]), Ok(()));
        assert_eq!(judge_close(None, &[]), Err(CloseRefusal::NotFound));
    }

    #[test]
    fn 사람이_붙이는_이름은_비거나_길거나_제어_문자가_들면_받지_않는다() {
        assert_eq!(check_label("  배포 서버  "), Ok("배포 서버".to_owned()));
        assert_eq!(check_label("   "), Err(LabelProblem::Empty));
        assert_eq!(
            check_label(&"가".repeat(LABEL_MAX)),
            Ok("가".repeat(LABEL_MAX))
        );
        assert_eq!(
            check_label(&"가".repeat(LABEL_MAX + 1)),
            Err(LabelProblem::TooLong { max: LABEL_MAX })
        );
        assert_eq!(check_label("둘\n째 줄"), Err(LabelProblem::Control));
    }

    #[test]
    fn 열쇠와_조직의_이름표는_비어도_되고_100자를_넘거나_제어_문자가_들면_받지_않는다() {
        assert_eq!(check_key_label("  배포 서버  "), Ok("배포 서버".to_owned()));
        assert_eq!(check_key_label(""), Ok(String::new()));
        assert_eq!(
            check_key_label(&"가".repeat(KEY_LABEL_MAX)),
            Ok("가".repeat(KEY_LABEL_MAX))
        );
        assert_eq!(
            check_key_label(&"가".repeat(KEY_LABEL_MAX + 1)),
            Err(LabelProblem::TooLong { max: KEY_LABEL_MAX })
        );
        assert_eq!(check_key_label("둘\n째 줄"), Err(LabelProblem::Control));
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
    fn 마지막으로_쓴_때는_분_단위로_뭉쳐_같은_분_안에서는_다시_적지_않는다() {
        assert_eq!(used_at(None, 125), Some(120));
        assert_eq!(used_at(Some(120), 179), None);
        assert_eq!(used_at(Some(120), 180), Some(180));
        assert_eq!(used_at(Some(60), 125), Some(120));
    }
}
