//! 조직과 service key. 운영자의 열쇠로 조직을 만들고 첫 열쇠를 내고, 조직은 자기 열쇠를 더 내고 보고 거둔다.
//!
//! 열쇠의 값은 낼 때의 답에 한 번만 실리고, 기록에는 sha256 만 남는다. 요청마다 기록을 보아, 한 관리 서버에서 거둔 열쇠는
//! 다른 관리 서버도 다음 요청부터 받지 않는다. 받을지 · 거둘지 · 세울지 · 닫을지의 판정은 core 의 `organization` 이 한다.
//! 운영자의 열쇠는 조직의 일(인스턴스 · 승격 · 비밀 · 사용자)을 하지 못하고, service key 와 작업의 토큰은 운영자의 길을 열지 못한다.

use orbital_core::name::Ident;
use orbital_core::organization::{
    Caller, CloseRefusal, InstanceRefusal, IssueRefusal, KeyRefusal, Kind, LabelProblem,
    OrganizationState, Presented, RevokeRefusal, check_label, judge_close, judge_issue, judge_key,
    judge_new_instance, judge_revoke, used_at,
};
use orbital_core::scope::OrganizationId;
use serde::Serialize;

use super::{Failure, Layer, Options, Outcome, digest, random};
use crate::records::{KeyRow, NewKey, OrganizationRow};
use crate::token::hex;

/// 운영자의 열쇠의 가장 짧은 길이(바이트).
const OPERATOR_KEY_MIN: usize = 32;

/// 낸 열쇠. 값(`key`)은 이 답 한 번에만 실리고 레이어는 다시 보여 주지 못한다.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedKey {
    pub id: String,
    pub label: String,
    pub key: String,
    pub created_at: u64,
}

/// 운영자가 보는 조직 하나. 이름과 숫자만 있다.
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationReport {
    #[serde(flatten)]
    pub organization: OrganizationRow,
    /// 지금 세워진 인스턴스의 수.
    pub instances: u32,
    /// 살아 있는(거두지 않은) 열쇠의 수.
    pub keys: u32,
}

/// 설정을 본다. 운영자의 열쇠는 길어야 하고 service key 나 작업의 토큰과 헷갈리지 않아야 한다.
pub(super) fn check_options(options: &Options) -> Result<(), String> {
    if let Some(operator) = &options.operator_key {
        if operator.len() < OPERATOR_KEY_MIN {
            return Err(format!(
                "`ORBITAL_OPERATOR_KEY` 는 {OPERATOR_KEY_MIN}자 이상이어야 합니다. `openssl rand -hex 32` 로 만들어 주세요"
            ));
        }
        if operator.starts_with("orb1.") || operator.starts_with("sk_") {
            return Err(
                "`ORBITAL_OPERATOR_KEY` 는 `orb1.` 이나 `sk_` 로 시작하지 않아야 합니다. 작업의 토큰이나 service key 와 헷갈립니다".to_owned(),
            );
        }
        if options.service_keys.iter().any(|(key, _)| key == operator) {
            return Err(
                "`ORBITAL_OPERATOR_KEY` 가 `ORBITAL_SERVICE_KEYS` 의 열쇠와 같습니다. 다른 값을 주세요".to_owned(),
            );
        }
    }
    if options.test_instance_limit == 0 {
        return Err("`ORBITAL_TEST_INSTANCE_LIMIT` 는 1 이상이어야 합니다".to_owned());
    }
    Ok(())
}

fn label_text(what: &str, problem: LabelProblem) -> Failure {
    Failure::Problems(vec![match problem {
        LabelProblem::Empty => format!("{what}을 적어 주세요"),
        LabelProblem::TooLong { max } => format!("{what}은 {max}자까지입니다"),
        LabelProblem::Control => format!("{what}에 줄바꿈 같은 제어 문자를 넣지 않습니다"),
    }])
}

/// 열쇠를 받지 않는 까닭의 글. 열쇠를 가진 쪽만 이 글을 본다.
pub fn key_refusal_text(refusal: KeyRefusal) -> &'static str {
    match refusal {
        KeyRefusal::Unknown => "열쇠가 없거나 맞지 않습니다",
        KeyRefusal::Revoked => {
            "거둔 service key 입니다. 살아 있는 다른 열쇠로 바꿔 주세요. 열쇠가 하나도 없으면 운영자에게 새 열쇠를 받아 주세요"
        }
        KeyRefusal::Closed => "닫힌 조직의 service key 입니다. 닫힌 조직의 열쇠는 받지 않습니다",
    }
}

fn new_key_parts(kind: Kind) -> Outcome<(String, String, String)> {
    let id = format!("key_{}", hex(&random(8)?));
    let value = format!("{}{}", kind.key_prefix(), hex(&random(32)?));
    let digest = hex(&digest(&value));
    Ok((id, value, digest))
}

impl Layer {
    /// 운영자의 길이 열려 있는가(`ORBITAL_OPERATOR_KEY` 를 줬는가).
    pub fn operator_enabled(&self) -> bool {
        self.operator_key.is_some()
    }

    /// 이 열쇠가 운영자의 열쇠인가. sha256 을 견준다(값의 앞 몇 글자가 맞는지 시간으로 알 수 없다).
    pub fn is_operator(&self, key: &str) -> bool {
        self.operator_key.is_some_and(|known| known == digest(key))
    }

    /// service key 의 주인. 설정의 열쇠면 그 조직이 기록에서 닫혔는지를, 기록의 열쇠면 거뒀는지와 조직이 닫혔는지를 요청마다 본다.
    /// 기록을 읽지 못하면 「없는 열쇠」(401)가 아니라 500 이다. 운영자의 열쇠는 조직의 일을 하지 못한다(403).
    pub fn caller(&self, key: &str) -> Outcome<Caller> {
        if self.is_operator(key) {
            return Err(Failure::Forbidden(
                "운영자의 열쇠는 조직을 만들고 보고 닫는 일과 열쇠를 내는 일(`/v1/operator/…`)만 합니다. 조직의 일은 그 조직의 service key 로 해 주세요".to_owned(),
            ));
        }
        let given = digest(key);
        let configured = self
            .service_keys
            .iter()
            .find(|(known, _)| known == &given)
            .map(|(_, organization)| organization.clone());
        let mut found_used_at = None;
        let presented = match configured {
            Some(organization) => Presented::Configured {
                state: self.records.organization_state(&organization)?,
                organization: OrganizationId(organization),
            },
            None => match self.records.find_key(&hex(&given))? {
                None => Presented::Unknown,
                Some(found) => {
                    found_used_at = Some(found.used_at);
                    Presented::Recorded {
                        key: found.id,
                        organization: found.organization,
                        revoked: found.revoked,
                        state: found.state,
                    }
                }
            },
        };
        let caller = judge_key(&presented).map_err(|refusal| match refusal {
            KeyRefusal::Unknown => Failure::Unauthorized,
            other => Failure::KeyRejected(other),
        })?;
        // 마지막으로 쓴 때는 분 단위로 뭉쳐 그 분에 한 번만 적는다. 적지 못해도 요청은 막지 않는다(읽기는 됐다)
        if let (Some(id), Some(recorded)) = (&caller.key, found_used_at)
            && let Some(at) = used_at(recorded, (self.clock)())
        {
            let _ = self.records.touch_key(id, at);
        }
        Ok(caller)
    }

    /// 열쇠를 하나 더 낸다. 값은 이 답에만 실린다. 기록에 없는 조직(설정의 열쇠만 있는 조직)은 열쇠를 내지 못한다(409).
    pub fn issue_key(&self, caller: &Caller, label: &str) -> Outcome<IssuedKey> {
        self.issue_for(&caller.organization.0, label, |refusal| match refusal {
            IssueRefusal::NotFound => Failure::Conflict(
                "이 조직은 레이어의 기록에 없어(관리 서버의 설정에만 있습니다) 열쇠를 내지 못합니다. 운영자가 같은 이름으로 조직을 만들어야 합니다".to_owned(),
            ),
            IssueRefusal::Closed => closed_failure(),
        })
    }

    fn issue_for(
        &self,
        organization: &str,
        label: &str,
        refused: impl Fn(IssueRefusal) -> Failure,
    ) -> Outcome<IssuedKey> {
        self.issue_with(organization, label, false, refused)
            .map(|(key, _)| key)
    }

    /// 열쇠를 낸다. `alone` 이면 같은 트랜잭션에서 그 조직의 다른 살아 있는 열쇠를 모두 거둔다. (낸 열쇠, 거둔 수).
    fn issue_with(
        &self,
        organization: &str,
        label: &str,
        alone: bool,
        refused: impl Fn(IssueRefusal) -> Failure,
    ) -> Outcome<(IssuedKey, u32)> {
        let label = check_label(label).map_err(|problem| label_text("열쇠의 이름", problem))?;
        let created_at = (self.clock)();
        // 머리말은 조직의 종류를 따른다. 종류는 바뀌지 않지만, 줄을 잠근 뒤에 다시 판정해 그사이 닫힌 조직에는 적지 않는다
        let kind = judge_issue(self.records.organization_state(organization)?.as_ref())
            .map_err(&refused)?;
        let (id, value, digest) = new_key_parts(kind)?;
        let new = NewKey {
            id: &id,
            digest: &digest,
            label: &label,
            created_at,
        };
        let judge =
            |state: Option<&OrganizationState>| match judge_issue(state).map_err(&refused)? {
                now if now == kind => Ok(()),
                _ => Err(Failure::Conflict(
                    "조직의 모습이 바뀌었습니다. 다시 보내 주세요".to_owned(),
                )),
            };
        let revoked = if alone {
            self.records.issue_key_alone(organization, &new, judge)?
        } else {
            self.records.issue_key(organization, &new, judge)?;
            0
        };
        Ok((
            IssuedKey {
                id,
                label,
                key: value,
                created_at,
            },
            revoked,
        ))
    }

    /// 조직의 열쇠 모두(거둔 것도). 값은 없다. 기록에 없는 조직이면 비어 있다.
    pub fn list_keys(&self, caller: &Caller) -> Outcome<Vec<KeyRow>> {
        Ok(self.records.keys(&caller.organization.0)?)
    }

    /// 열쇠를 거둔다. 다른 조직의 것은 없는 것과 같고, 살아 있는 마지막 열쇠는 거두지 못한다. 거둔 열쇠는 어느 관리 서버에서든 다음 요청부터 받지 않는다.
    pub fn revoke_key(&self, caller: &Caller, id: &str) -> Outcome<KeyRow> {
        let now = (self.clock)();
        self.records
            .revoke_key(&caller.organization.0, id, now, |target, alive| {
                judge_revoke(&caller.organization, target, alive).map_err(|refusal| match refusal {
                    RevokeRefusal::NotFound => Failure::NotFound,
                    RevokeRefusal::LastKey => Failure::Conflict(
                        "살아 있는 마지막 열쇠라 거두지 않았습니다. 거두면 이 조직이 잠깁니다. 새 열쇠를 먼저 내고(`POST /v1/keys`) 팩토리의 서버를 그 열쇠로 바꾼 뒤에 거둬 주세요".to_owned(),
                    ),
                })
            })
    }

    /// 인스턴스를 더 세울 수 있는가. 판정은 core 가 한다.
    pub(super) fn judge_new_instance(
        &self,
        state: Option<&OrganizationState>,
        existing: u32,
    ) -> Outcome<()> {
        judge_new_instance(state, existing, self.test_instance_limit).map_err(|refusal| match refusal {
            InstanceRefusal::Closed => Failure::Conflict(
                "닫힌 조직에는 인스턴스를 세우지 않습니다".to_owned(),
            ),
            InstanceRefusal::TestLimit { limit } => Failure::Conflict(format!(
                "시험용 조직은 인스턴스를 {limit}개까지 세웁니다. 쓰지 않는 인스턴스를 지우거나(`DELETE /v1/instances/{{id}}`) 운영의 조직(`live`)에서 세워 주세요"
            )),
        })
    }

    // ---- 운영자 ----

    /// 조직을 만들고 첫 열쇠를 낸다. 같은 이름의 조직이 있으면 409 다. 관리 서버의 설정에만 있는 조직의 이름도 받는다(그 조직의 기록이 생긴다).
    pub fn create_organization(
        &self,
        id: &str,
        name: &str,
        kind: Kind,
        label: &str,
    ) -> Outcome<(OrganizationRow, IssuedKey)> {
        let id = Ident::parse(id).map_err(|problem| {
            Failure::Problems(vec![format!(
                "조직의 식별자 `{id}` 는 영문 소문자로 시작하고 소문자 · 숫자 · 밑줄만 쓰는 24자 안의 이름이어야 합니다({problem})"
            )])
        })?;
        let name = check_label(name).map_err(|problem| label_text("조직의 이름", problem))?;
        let label = check_label(label).map_err(|problem| label_text("열쇠의 이름", problem))?;
        let created_at = (self.clock)();
        let organization = OrganizationRow {
            id: id.as_str().to_owned(),
            name,
            kind,
            created_at,
            closed_at: None,
        };
        let (key_id, value, digest) = new_key_parts(kind)?;
        let created = self.records.create_organization(
            &organization,
            &NewKey {
                id: &key_id,
                digest: &digest,
                label: &label,
                created_at,
            },
        )?;
        if !created {
            return Err(Failure::Conflict(format!(
                "조직 `{}` 은 이미 있습니다. 다른 식별자를 쓰거나, 그 조직에 열쇠를 더 내 주세요(`POST /v1/operator/organizations/{}/keys`)",
                id.as_str(),
                id.as_str()
            )));
        }
        Ok((
            organization,
            IssuedKey {
                id: key_id,
                label,
                key: value,
                created_at,
            },
        ))
    }

    /// 모든 조직. 이름과 숫자만 있다.
    pub fn organizations(&self) -> Outcome<Vec<OrganizationRow>> {
        Ok(self.records.organizations()?)
    }

    /// 조직 하나와 그 인스턴스 · 살아 있는 열쇠의 수. 없으면 404 다.
    pub fn organization_report(&self, id: &str) -> Outcome<OrganizationReport> {
        let organization = self.records.organization(id)?.ok_or(Failure::NotFound)?;
        let (instances, keys) = self.records.organization_counts(id)?;
        Ok(OrganizationReport {
            organization,
            instances,
            keys,
        })
    }

    /// 운영자가 조직에 열쇠를 낸다. 조직이 모든 열쇠를 잃었을 때 되찾는 길이다.
    ///
    /// `revoke_others` 면 그 조직의 다른 살아 있는 열쇠를 같은 트랜잭션에서 모두 거둔다. 열쇠가 새어 나갔을 때 쓴다.
    /// 새어 나간 열쇠를 쥔 쪽은 열쇠를 더 낼 수 있어, 하나씩 거두는 동안 새로 내며 버틸 수 있다. 한 번에 끊어야 끝난다.
    /// (낸 열쇠, 거둔 열쇠의 수).
    pub fn operator_issue_key(
        &self,
        id: &str,
        label: &str,
        revoke_others: bool,
    ) -> Outcome<(IssuedKey, u32)> {
        self.issue_with(id, label, revoke_others, |refusal| match refusal {
            IssueRefusal::NotFound => Failure::NotFound,
            IssueRefusal::Closed => closed_failure(),
        })
    }

    /// 조직을 닫는다. 인스턴스가 남아 있으면 닫지 않고 먼저 지울 것을 알린다. 닫으면 그 조직의 열쇠는 어디서 왔든 받지 않는다.
    pub fn close_organization(&self, id: &str) -> Outcome<OrganizationRow> {
        let now = (self.clock)();
        self.records
            .close_organization(id, now, |state, instances| {
                judge_close(state, instances).map_err(|refusal| match refusal {
                    CloseRefusal::NotFound => Failure::NotFound,
                    CloseRefusal::InstancesRemain { instances } => Failure::Conflict(format!(
                        "인스턴스 {}개가 남아 있어 닫지 않았습니다. 그 조직의 service key 로 먼저 지워 주세요(`DELETE /v1/instances/{{id}}`): {}",
                        instances.len(),
                        instances.join(", ")
                    )),
                })
            })?;
        self.records.organization(id)?.ok_or(Failure::NotFound)
    }
}

fn closed_failure() -> Failure {
    Failure::Conflict("닫힌 조직에는 열쇠를 내지 않습니다".to_owned())
}
