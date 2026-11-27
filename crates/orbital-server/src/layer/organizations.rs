//! 조직(팩토리)과 service key. 운영자 키(`ORBITAL_ADMIN_KEY`)로 조직을 만들고 첫 키를 내고, 조직은 제 키를 더 내고 보고 폐기한다.
//!
//! - 키의 비밀은 낼 때의 답에 한 번만 실리고, 기록(control database)에는 sha256 만 남는다. 요청마다 기록을 보아, 한 관리 서버에서 폐기한 키와
//!   닫힌 조직의 키는 다른 관리 서버도 다음 요청부터 받지 않는다.
//! - 운영자 키는 조직을 만들고 보고 닫는 일과, 살아 있는 키가 없는 조직에 키를 내는 일과, 키를 가는 일만 한다. 조직의 일(인스턴스 · 승격 ·
//!   비밀 · 사용자 · 키)은 하지 못하고(403), service key 와 작업의 토큰은 운영자의 길을 열지 못한다(401).
//! - 설정의 키(`ORBITAL_SERVICE_KEYS`)는 부트스트랩이다. 목록에 보이지 않고 API 로 폐기하지 못하며, 그 조직은 키를 더 낼 수 있다.
//!
//! 받을지 · 폐기할지 · 낼지 · 세울지 · 닫을지의 판정은 core 의 `organization` 이 한다.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbital_core::organization::{
    Caller, CloseRefusal, InstanceRefusal, IssueRefusal, KEY_PREFIX, KeyRefusal, Kind,
    LabelProblem, OperatorIssue, OperatorRefusal, OrganizationName, OrganizationState, Presented,
    RevokeRefusal, check_key_label, judge_close, judge_issue, judge_key, judge_new_instance,
    judge_operator_issue, judge_revoke, organization_name, used_at,
};
use orbital_core::scope::OrganizationId;
use serde::Serialize;

use super::{Failure, Layer, Options, Outcome, digest, random};
use crate::records::{KeyRow, NewKey, OrganizationRow};
use crate::token::hex;

/// 운영자 키의 가장 짧은 길이(바이트).
const ADMIN_KEY_MIN: usize = 32;

/// 막 낸 키. 비밀(`secret`)은 이 답에서 한 번만 보이고 레이어는 다시 보여 주지 못한다.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedKey {
    #[serde(flatten)]
    pub key: KeyRow,
    pub secret: String,
}

/// 운영자가 보는 조직 하나. 이름과 숫자만 있다.
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationReport {
    #[serde(flatten)]
    pub organization: OrganizationRow,
    /// 지금 세워진 인스턴스의 수.
    pub instances: u32,
    /// 살아 있는(폐기하지 않은) 기록의 키의 수.
    pub keys: u32,
}

/// 설정을 본다. 운영자 키는 길어야 하고 service key 나 작업의 토큰과 헷갈리지 않아야 한다.
pub(super) fn check_options(options: &Options) -> Result<(), String> {
    if let Some(admin) = &options.admin_key {
        if admin.len() < ADMIN_KEY_MIN {
            return Err(format!(
                "`ORBITAL_ADMIN_KEY` 는 {ADMIN_KEY_MIN}바이트 이상이어야 합니다. `openssl rand -hex 32` 로 만들어 주세요"
            ));
        }
        if ["orb1.", "sk_", KEY_PREFIX]
            .iter()
            .any(|prefix| admin.starts_with(prefix))
        {
            return Err(
                "`ORBITAL_ADMIN_KEY` 는 `orb1.` · `sk_` · `orb_sk_` 로 시작하지 않아야 합니다. 작업의 토큰이나 service key 와 헷갈립니다. `openssl rand -hex 32` 로 만들어 주세요".to_owned(),
            );
        }
        if options.service_keys.iter().any(|(key, _)| key == admin) {
            return Err(
                "`ORBITAL_ADMIN_KEY` 가 `ORBITAL_SERVICE_KEYS` 의 키와 같습니다. 다른 값을 주세요"
                    .to_owned(),
            );
        }
    }
    if options.test_instance_limit == 0 {
        return Err("`ORBITAL_TEST_INSTANCE_LIMIT` 는 1 이상이어야 합니다".to_owned());
    }
    Ok(())
}

fn label_failure(what: &str, problem: LabelProblem) -> Failure {
    Failure::Invalid(match problem {
        LabelProblem::Empty => format!("{what}을 적어 주세요"),
        LabelProblem::TooLong { max } => format!("{what}은 {max}글자까지여야 합니다"),
        LabelProblem::Control => format!("{what}에 줄바꿈 같은 제어 문자를 넣지 않습니다"),
    })
}

fn checked_label(what: &str, label: Option<&str>) -> Outcome<String> {
    check_key_label(label.unwrap_or_default()).map_err(|problem| label_failure(what, problem))
}

fn checked_name(raw: &str) -> Outcome<OrganizationName> {
    organization_name(raw).map_err(|problem| Failure::Invalid(problem.to_string()))
}

/// 키를 받지 않는 까닭의 글. 키를 가진 쪽만 이 글을 본다.
pub fn key_refusal_text(refusal: KeyRefusal) -> &'static str {
    match refusal {
        KeyRefusal::Unknown => "키가 없거나 맞지 않습니다",
        KeyRefusal::Revoked => {
            "폐기한 service key 입니다. 살아 있는 다른 키로 바꿔 주세요. 살아 있는 키가 하나도 없으면 운영자에게 새 키를 받아 주세요"
        }
        KeyRefusal::Closed => "닫힌 조직의 service key 입니다. 닫힌 조직의 키는 받지 않습니다",
    }
}

fn closed_failure() -> Failure {
    Failure::Conflict("닫힌 조직에는 키를 내지 않습니다".to_owned())
}

impl Layer {
    /// 새 키의 식별자 · 비밀 · sha256(hex). 비밀은 머리말로 무엇인지 알아보게 한다(비밀 검사 도구가 찾기 쉽다). 종류와 상관없이 같은 머리말이다.
    fn new_key_parts() -> Outcome<(String, String, String)> {
        let id = format!("key_{}", hex(&random(8)?));
        let secret = format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(random(32)?));
        let digest = hex(&digest(&secret));
        Ok((id, secret, digest))
    }

    /// 설정의 키(`ORBITAL_SERVICE_KEYS`)가 이 조직에 있는가.
    fn bootstrap(&self, organization: &str) -> bool {
        self.service_keys
            .iter()
            .any(|(_, known)| known == organization)
    }

    /// 운영자 키인가. sha256 을 견준다(값의 앞 몇 글자가 맞는지 시간으로 알 수 없다). 운영자 키를 두지 않은 레이어에서는 늘 거짓이다.
    pub fn is_admin(&self, key: &str) -> bool {
        self.admin_key.is_some_and(|known| known == digest(key))
    }

    /// service key 의 주인. 설정의 키면 그 조직이 기록에서 닫혔는지를, 기록의 키면 폐기했는지와 조직이 닫혔는지를 요청마다 본다.
    /// 기록을 읽지 못하면 「없는 키」(401)가 아니라 500 이다. 운영자 키는 조직의 일을 하지 못한다(403).
    pub fn caller(&self, key: &str) -> Outcome<Caller> {
        if self.is_admin(key) {
            return Err(Failure::Forbidden(
                "운영자 키는 조직을 만들고 보고 닫는 일과 키를 내고 가는 일(`/v1/admin/…`)만 합니다. 조직의 일은 그 조직의 service key 로 해 주세요".to_owned(),
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

    /// 키를 적는다. 판정은 `judge` 가 잠근 조직의 모습과 살아 있는 키의 수로 한다. (낸 키, 함께 폐기한 수).
    fn issue_with(
        &self,
        organization: &str,
        label: String,
        (bootstrap, revoke_others): (bool, bool),
        judge: impl FnOnce(Option<&OrganizationState>, u32) -> Outcome<()>,
    ) -> Outcome<(IssuedKey, u32)> {
        let created_at = (self.clock)();
        let (id, secret, digest) = Self::new_key_parts()?;
        let revoked = self.records.issue_key(
            organization,
            &NewKey {
                id: &id,
                digest: &digest,
                label: &label,
                created_at,
            },
            (bootstrap, revoke_others),
            judge,
        )?;
        Ok((
            IssuedKey {
                key: KeyRow {
                    id,
                    label,
                    created_at,
                    revoked_at: None,
                    used_at: None,
                },
                secret,
            },
            revoked,
        ))
    }

    /// 조직의 키로 키를 하나 더 낸다. 비밀은 이 답에만 실린다. 설정의 키만 있는 조직은 이때 기록에 운영의 조직으로 생긴다.
    pub fn issue_key(&self, caller: &Caller, label: Option<&str>) -> Outcome<IssuedKey> {
        let label = checked_label("키의 이름", label)?;
        let bootstrap = self.bootstrap(&caller.organization.0);
        self.issue_with(
            &caller.organization.0,
            label,
            (bootstrap, false),
            |state, _| {
                judge_issue(state, bootstrap).map_err(|refusal| match refusal {
                    IssueRefusal::NotFound => Failure::NotFound,
                    IssueRefusal::Closed => closed_failure(),
                })
            },
        )
        .map(|(key, _)| key)
    }

    /// 조직의 키 모두(폐기한 것도). 만든 차례다. 비밀은 없고, 설정의 키는 보이지 않는다.
    pub fn list_keys(&self, caller: &Caller) -> Outcome<Vec<KeyRow>> {
        Ok(self.records.keys(&caller.organization.0)?)
    }

    /// 키를 폐기한다. 다른 조직의 것은 없는 것과 같고, 살아 있는 마지막 키는 폐기하지 못한다(설정의 키가 있는 조직은 한다).
    /// 폐기한 키는 어느 관리 서버에서든 다음 요청부터 받지 않는다. 이미 폐기한 것이면 그대로 돌려준다.
    pub fn revoke_key(&self, caller: &Caller, id: &str) -> Outcome<KeyRow> {
        let now = (self.clock)();
        let bootstrap = self.bootstrap(&caller.organization.0);
        self.records
            .revoke_key(&caller.organization.0, id, now, |target, alive| {
                judge_revoke(&caller.organization, target, alive, bootstrap).map_err(|refusal| match refusal {
                    RevokeRefusal::NotFound => Failure::NotFound,
                    RevokeRefusal::LastKey => Failure::Conflict(
                        "조직의 마지막 살아 있는 키는 폐기하지 못합니다. 폐기하면 이 조직이 잠깁니다. 새 키를 만들고(`POST /v1/keys`) 팩토리의 서버를 그 키로 바꾼 뒤에 폐기해 주세요".to_owned(),
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

    /// 조직을 만들고 첫 키를 낸다. 이미 있거나 설정의 키의 조직이면 409 다(두 키가 같은 인스턴스를 나눠 갖게 된다).
    /// `label` 은 사람이 읽는 조직의 이름이고 비어도 된다. 첫 키에는 이름이 없다.
    pub fn create_organization(
        &self,
        id: &str,
        label: Option<&str>,
        kind: Kind,
    ) -> Outcome<(String, IssuedKey)> {
        let name = checked_name(id)?;
        let label = checked_label("조직의 이름", label)?;
        let exists =
            || Failure::Conflict("이미 있는 조직입니다. 다른 이름을 골라 주세요".to_owned());
        if self.bootstrap(name.as_str()) {
            return Err(exists());
        }
        let created_at = (self.clock)();
        let (key_id, secret, digest) = Self::new_key_parts()?;
        let created = self.records.create_organization(
            &OrganizationRow {
                id: name.as_str().to_owned(),
                name: label,
                kind,
                created_at,
                closed_at: None,
            },
            &NewKey {
                id: &key_id,
                digest: &digest,
                label: "",
                created_at,
            },
        )?;
        if !created {
            return Err(exists());
        }
        Ok((
            name.as_str().to_owned(),
            IssuedKey {
                key: KeyRow {
                    id: key_id,
                    label: String::new(),
                    created_at,
                    revoked_at: None,
                    used_at: None,
                },
                secret,
            },
        ))
    }

    /// 모든 기록의 조직. 이름과 숫자만 있다.
    pub fn organizations(&self) -> Outcome<Vec<OrganizationRow>> {
        Ok(self.records.organizations()?)
    }

    /// 조직 하나와 그 인스턴스 · 살아 있는 키의 수. 없으면 404 다.
    pub fn organization_report(&self, id: &str) -> Outcome<OrganizationReport> {
        let name = checked_name(id)?;
        let organization = self
            .records
            .organization(name.as_str())?
            .ok_or(Failure::NotFound)?;
        let (instances, keys) = self.records.organization_counts(name.as_str())?;
        Ok(OrganizationReport {
            organization,
            instances,
            keys,
        })
    }

    /// 운영자가 조직에 키를 낸다. `Issue` 는 살아 있는 키가 없는 조직에만 하나를 내어 되살린다.
    /// `Reset` 은 조직의 줄을 잠그고 한 트랜잭션에서 살아 있는 키를 모두 폐기하며 새 키 하나를 낸다. 키가 새어 나갔거나 모두 잃었을 때다.
    /// 새어 나간 키를 쥔 쪽은 키를 더 낼 수 있어 하나씩 폐기하는 동안 새로 내며 버틸 수 있으므로, 한 번에 끊는다.
    /// 설정의 키가 있는 조직과 없는 조직과 닫힌 조직에는 하지 않는다.
    pub fn operator_issue_key(
        &self,
        id: &str,
        label: Option<&str>,
        how: OperatorIssue,
    ) -> Outcome<IssuedKey> {
        let name = checked_name(id)?;
        let label = checked_label("키의 이름", label)?;
        let bootstrap = self.bootstrap(name.as_str());
        let (key, revoked) = self.issue_with(
            name.as_str(),
            label,
            (false, how == OperatorIssue::Reset),
            |state, alive| {
                judge_operator_issue(state, alive, bootstrap, how).map_err(|refusal| match refusal {
                    OperatorRefusal::NotFound => Failure::NotFound,
                    OperatorRefusal::Closed => closed_failure(),
                    OperatorRefusal::Bootstrap => Failure::Conflict(
                        "설정의 키(`ORBITAL_SERVICE_KEYS`)가 있는 조직에는 운영자가 키를 내거나 갈지 않습니다".to_owned(),
                    ),
                    OperatorRefusal::HasLiveKey => Failure::Conflict(
                        "살아 있는 키가 있는 조직에는 운영자가 키를 내지 않습니다. 조직의 키로 새 키를 만들어 주세요. 키가 새어 나갔으면 키를 갈아 주세요(`…/reset-keys`)".to_owned(),
                    ),
                })
            },
        )?;
        // 운영자가 조직의 키를 낸 일은 드물고 무겁다. 이름과 식별자와 수만 남긴다
        eprintln!(
            "orbitald: 운영자가 조직 {} 에 키 {} 를 냈습니다(함께 폐기한 키 {revoked}개)",
            name.as_str(),
            key.key.id
        );
        Ok(key)
    }

    /// 조직을 닫는다. 인스턴스가 남아 있으면 닫지 않고 먼저 지울 것을 알린다. 닫으면 그 조직의 키는 어디서 왔든 받지 않는다.
    pub fn close_organization(&self, id: &str) -> Outcome<OrganizationRow> {
        let name = checked_name(id)?;
        let now = (self.clock)();
        self.records
            .close_organization(name.as_str(), now, |state, instances| {
                judge_close(state, instances).map_err(|refusal| match refusal {
                    CloseRefusal::NotFound => Failure::NotFound,
                    CloseRefusal::InstancesRemain { instances } => Failure::Conflict(format!(
                        "인스턴스 {}개가 남아 있어 닫지 않았습니다. 그 조직의 service key 로 먼저 지워 주세요(`DELETE /v1/instances/{{id}}`): {}",
                        instances.len(),
                        instances.join(", ")
                    )),
                })
            })?;
        self.records
            .organization(name.as_str())?
            .ok_or(Failure::NotFound)
    }
}
