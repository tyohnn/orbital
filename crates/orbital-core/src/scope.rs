//! 토큰 범위 판정.
//!
//! host(팩토리)가 「이 사람과 이 에이전트가 이 인스턴스를 고칠 수 있나」를 정해 토큰을 받으면, Orbital 은 요청마다 그 요청이
//! 토큰의 범위 안인지만 본다. 누가 고칠 수 있는지는 host 의 일이고 여기서는 다루지 않는다.
//!
//! 토큰에는 운영을 바꾸는 능력이 아예 없다. [`Capability`] 에 그런 값이 없어서, host 가 무엇을 적어 보내도 생기지 않는다.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::name::InstanceId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationId(pub String);

/// 토큰에 실을 수 있는 능력. 운영을 바꾸는 능력은 여기에 없다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// 코드를 받고 올린다.
    Source,
    /// 프리뷰를 세우고, 그 로그와 DB(씨앗 데이터)를 본다. 승격을 요청한다.
    Preview,
    /// 운영 사본에 마이그레이션을 리허설한다. 숫자만 돌아온다.
    Rehearse,
    /// 사람에게 비밀의 입력을 요청한다. 값은 보지 못한다.
    SecretsRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    SourceRead,
    SourceWrite,
    PreviewDeploy,
    PreviewLogs,
    PreviewDatabase,
    RequestPromotion,
    Rehearse,
    /// 사람에게 비밀의 입력을 요청한다.
    SecretsRequest,
    /// 비밀의 이름과 채워졌는지를 본다. 값은 싣지 않는다.
    SecretsList,
    /// 여기부터는 운영이다. service key 로만 한다.
    Promote,
    ProductionLogs,
    ProductionDatabase,
    /// 비밀의 값을 읽는다. 이 일을 하는 길은 레이어에 없다. 어떤 열쇠로도 값은 나가지 않는다.
    SecretsRead,
    /// 비밀의 값을 넣거나 지우고, 사람의 입력 표를 받는다.
    SecretsWrite,
    /// 자기 인스턴스가 든 rollout 의 진행(그 인스턴스의 상태 · 업데이트 commit · 멈췄는지)을 본다.
    RolloutView,
    /// rollout 을 만들고, 합치기를 부르고, 다시 열고, 거둔다. service key 로만 한다.
    RolloutManage,
}

impl Action {
    /// 이 일에 필요한 능력. `None` 이면 토큰으로는 할 수 없는 일이다.
    pub fn needs(&self) -> Option<Capability> {
        match self {
            // 업데이트를 받아 합치는 것이 코드의 일이다
            Self::SourceRead | Self::SourceWrite | Self::RolloutView => Some(Capability::Source),
            Self::PreviewDeploy
            | Self::PreviewLogs
            | Self::PreviewDatabase
            | Self::RequestPromotion => Some(Capability::Preview),
            Self::Rehearse => Some(Capability::Rehearse),
            Self::SecretsRequest | Self::SecretsList => Some(Capability::SecretsRequest),
            Self::Promote
            | Self::ProductionLogs
            | Self::ProductionDatabase
            | Self::SecretsRead
            | Self::SecretsWrite
            | Self::RolloutManage => None,
        }
    }
}

/// 토큰 하나가 허락하는 것. 에이전트의 작업 한 번 동안만 산다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub organization: OrganizationId,
    pub instance: InstanceId,
    pub can: BTreeSet<Capability>,
    /// 이 시각(유닉스 초)부터 거절한다.
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub organization: OrganizationId,
    pub instance: InstanceId,
    pub action: Action,
    /// 요청을 받은 시각(유닉스 초). 시계는 부르는 쪽이 읽어 넘긴다.
    pub at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// 다른 조직이나 다른 인스턴스다. 거부와 부재를 구분하지 않는다.
    NotFound,
    Expired,
    /// 토큰으로는 할 수 없는 일이다. service key 가 필요하다.
    ServiceKeyOnly,
    NotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", content = "reason", rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny(DenyReason),
}

/// 요청이 토큰의 범위 안인지 본다.
///
/// 범위 밖(다른 조직 · 다른 인스턴스)을 가장 먼저 가른다. 그래야 남의 인스턴스에 대해서는 만료되었는지조차 알려 주지 않는다.
pub fn judge(token: &Token, request: &Request) -> Verdict {
    if token.organization != request.organization || token.instance != request.instance {
        return Verdict::Deny(DenyReason::NotFound);
    }
    if request.at >= token.expires_at {
        return Verdict::Deny(DenyReason::Expired);
    }
    match request.action.needs() {
        None => Verdict::Deny(DenyReason::ServiceKeyOnly),
        Some(capability) if token.can.contains(&capability) => Verdict::Allow,
        Some(_) => Verdict::Deny(DenyReason::NotGranted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(can: &[Capability]) -> Token {
        Token {
            organization: OrganizationId("org_factory".to_owned()),
            instance: InstanceId::parse("k3f9x2ab").unwrap(),
            can: can.iter().copied().collect(),
            expires_at: 1_000,
        }
    }

    fn request(action: Action) -> Request {
        Request {
            organization: OrganizationId("org_factory".to_owned()),
            instance: InstanceId::parse("k3f9x2ab").unwrap(),
            action,
            at: 500,
        }
    }

    const ALL: [Capability; 4] = [
        Capability::Source,
        Capability::Preview,
        Capability::Rehearse,
        Capability::SecretsRequest,
    ];

    #[test]
    fn 능력이_있으면_그_일을_한다() {
        let token = token(&[Capability::Source, Capability::Preview]);
        assert_eq!(judge(&token, &request(Action::SourceWrite)), Verdict::Allow);
        assert_eq!(
            judge(&token, &request(Action::PreviewDeploy)),
            Verdict::Allow
        );
        assert_eq!(
            judge(&token, &request(Action::RequestPromotion)),
            Verdict::Allow
        );
    }

    #[test]
    fn 능력이_없으면_그_일을_하지_못한다() {
        let token = token(&[Capability::Source]);
        assert_eq!(
            judge(&token, &request(Action::PreviewDeploy)),
            Verdict::Deny(DenyReason::NotGranted)
        );
        assert_eq!(
            judge(&token, &request(Action::Rehearse)),
            Verdict::Deny(DenyReason::NotGranted)
        );
    }

    #[test]
    fn 능력을_모두_가진_토큰으로도_운영에_올리지_못한다() {
        let token = token(&ALL);
        for action in [
            Action::Promote,
            Action::ProductionLogs,
            Action::ProductionDatabase,
            Action::SecretsRead,
            Action::SecretsWrite,
        ] {
            assert_eq!(
                judge(&token, &request(action)),
                Verdict::Deny(DenyReason::ServiceKeyOnly),
                "{action:?}"
            );
        }
    }

    #[test]
    fn 운영을_바꾸는_능력은_적어_보내도_읽히지_않는다() {
        let text = r#"{"organization":"org_factory","instance":"k3f9x2ab","can":["source","promote"],"expires_at":1000}"#;
        assert!(serde_json::from_str::<Token>(text).is_err());
    }

    #[test]
    fn 다른_인스턴스와_다른_조직은_없는_것으로_답한다() {
        let token = token(&ALL);
        let mut other_instance = request(Action::SourceRead);
        other_instance.instance = InstanceId::parse("zzzzzzzz").unwrap();
        assert_eq!(
            judge(&token, &other_instance),
            Verdict::Deny(DenyReason::NotFound)
        );
        let mut other_organization = request(Action::SourceRead);
        other_organization.organization = OrganizationId("org_other".to_owned());
        assert_eq!(
            judge(&token, &other_organization),
            Verdict::Deny(DenyReason::NotFound)
        );
    }

    #[test]
    fn 만료_시각의_1초_앞까지_받고_만료_시각부터_거절한다() {
        let token = token(&ALL);
        let mut last = request(Action::SourceRead);
        last.at = 999;
        assert_eq!(judge(&token, &last), Verdict::Allow);
        let mut at_expiry = request(Action::SourceRead);
        at_expiry.at = 1_000;
        assert_eq!(
            judge(&token, &at_expiry),
            Verdict::Deny(DenyReason::Expired)
        );
    }

    #[test]
    fn 남의_인스턴스에_대해서는_만료되었는지도_알려_주지_않는다() {
        let token = token(&ALL);
        let mut request = request(Action::SourceRead);
        request.instance = InstanceId::parse("zzzzzzzz").unwrap();
        request.at = 5_000;
        assert_eq!(judge(&token, &request), Verdict::Deny(DenyReason::NotFound));
    }

    #[test]
    fn 판정은_json_으로_오간다() {
        assert_eq!(
            serde_json::to_string(&Verdict::Allow).unwrap(),
            r#"{"verdict":"allow"}"#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Deny(DenyReason::ServiceKeyOnly)).unwrap(),
            r#"{"verdict":"deny","reason":"service_key_only"}"#
        );
    }
}
