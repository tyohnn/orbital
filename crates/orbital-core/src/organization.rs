//! 조직과 service key 의 판정. 받을 열쇠인가, 그 조직이 인스턴스를 더 세울 수 있는가, 그 열쇠를 거둘 수 있는가, 조직을 닫을 수 있는가.
//!
//! 열쇠의 값을 읽고 sha256 을 셈하고 기록을 찾는 일은 관리 서버가 한다. 여기서는 찾은 사실(어디서 왔나 · 거뒀나 · 조직이 닫혔나)을 받아
//! 판정만 한다. 시험용 조직(`test`)과 운영의 조직(`live`)이 갈리는 자리는 열쇠의 머리말과 인스턴스의 상한 둘뿐이다.
//! 그 밖의 관문(메일 · 복구 훈련 · 권한 · 승격)은 이 종류를 받지 않는다.

use serde::{Deserialize, Serialize};

use crate::scope::OrganizationId;

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
    /// 이 종류의 열쇠가 시작하는 글자. 열쇠만 보고 어느 종류의 조직인지 안다.
    pub const fn key_prefix(self) -> &'static str {
        match self {
            Self::Live => "sk_live_",
            Self::Test => "sk_test_",
        }
    }

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
pub fn judge_revoke(
    caller: &OrganizationId,
    target: Option<&KeyFacts>,
    alive: u32,
) -> Result<Revoking, RevokeRefusal> {
    let Some(target) = target.filter(|target| &target.organization == caller) else {
        return Err(RevokeRefusal::NotFound);
    };
    if target.revoked {
        return Ok(Revoking::AlreadyRevoked);
    }
    if alive <= 1 {
        return Err(RevokeRefusal::LastKey);
    }
    Ok(Revoking::Revoke)
}

/// 열쇠를 내지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueRefusal {
    /// 기록에 없는 조직이다(설정의 열쇠만 있는 조직 포함). 운영자가 조직을 먼저 만든다.
    NotFound,
    /// 닫힌 조직이다.
    Closed,
}

/// 그 조직에 열쇠를 더 낼 수 있는가. 내는 열쇠의 종류(머리말)를 돌려준다.
pub fn judge_issue(state: Option<&OrganizationState>) -> Result<Kind, IssueRefusal> {
    match state {
        None => Err(IssueRefusal::NotFound),
        Some(OrganizationState { closed: true, .. }) => Err(IssueRefusal::Closed),
        Some(state) => Ok(state.kind),
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

/// 사람이 붙이는 이름(조직의 이름 · 열쇠의 이름)의 문제.
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

/// 사람이 붙이는 이름의 최대 글자 수.
pub const LABEL_MAX: usize = 80;

/// 사람이 붙이는 이름을 본다. 앞뒤의 빈칸은 떼고 본다.
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
            judge_revoke(&org("acme"), Some(&mine), 1),
            Err(RevokeRefusal::LastKey)
        );
        assert_eq!(
            judge_revoke(&org("acme"), Some(&mine), 2),
            Ok(Revoking::Revoke)
        );
        let gone = KeyFacts {
            revoked: true,
            ..mine.clone()
        };
        assert_eq!(
            judge_revoke(&org("acme"), Some(&gone), 1),
            Ok(Revoking::AlreadyRevoked)
        );
        assert_eq!(
            judge_revoke(&org("other"), Some(&mine), 2),
            Err(RevokeRefusal::NotFound)
        );
        assert_eq!(
            judge_revoke(&org("acme"), None, 2),
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
    fn 열쇠는_기록에_있고_열린_조직에만_내고_머리말은_종류를_따른다() {
        assert_eq!(judge_issue(Some(&TEST)), Ok(Kind::Test));
        assert_eq!(judge_issue(Some(&LIVE)), Ok(Kind::Live));
        assert_eq!(judge_issue(Some(&CLOSED)), Err(IssueRefusal::Closed));
        assert_eq!(judge_issue(None), Err(IssueRefusal::NotFound));
        assert_eq!(Kind::Live.key_prefix(), "sk_live_");
        assert_eq!(Kind::Test.key_prefix(), "sk_test_");
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
    fn 마지막으로_쓴_때는_분_단위로_뭉쳐_같은_분_안에서는_다시_적지_않는다() {
        assert_eq!(used_at(None, 125), Some(120));
        assert_eq!(used_at(Some(120), 179), None);
        assert_eq!(used_at(Some(120), 180), Some(180));
        assert_eq!(used_at(Some(60), 125), Some(120));
    }
}
