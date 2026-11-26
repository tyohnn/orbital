//! 팩토리(조직)와 service key 의 셀프서비스.
//!
//! - 운영자 키(`ORBITAL_ADMIN_KEY`)는 조직을 만들고 첫 키를 낸다. 그 뒤에는 살아 있는 키가 하나도 없는 조직에만 키를 낸다(되살리기).
//!   그래서 운영자 키로는 살아 있는 팩토리의 인스턴스에 닿지 못한다. 대시보드가 가입을 받으면 이 길로 조직을 만든다.
//! - 조직의 service key 는 제 조직의 키를 보고(비밀 없이) · 만들고 · 폐기한다. 다른 조직의 키는 없는 키와 같다.
//! - 키는 만들 때 한 번만 보여 주고, 기록에는 sha256 만 둔다.
//! - 환경 변수의 키(`ORBITAL_SERVICE_KEYS`)는 부트스트랩으로 계속 쓴다. 목록에 보이지 않고 API 로 폐기하지 못한다.
//!
//! 판정(이름 · 폐기 · 운영자의 키)은 core 의 `keys` 가 한다.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbital_core::keys::{
    KeyState, OperatorIssue, OrganizationName, Revoke, judge_operator_issue, judge_revoke,
    label_fits, organization_name,
};
use serde::Serialize;

use super::{Failure, Layer, Outcome, digest, random};
use crate::login::sha256_hex;
use crate::registry::{KeyRecord, OrganizationRecord};
use crate::token;

/// 목록의 한 줄. 비밀도 해시도 싣지 않는다.
#[derive(Debug, Clone, Serialize)]
pub struct KeyReport {
    pub id: String,
    pub label: String,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

/// 막 만든 키. 비밀은 이 답에서 한 번만 보인다.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedKey {
    #[serde(flatten)]
    pub key: KeyReport,
    pub secret: String,
}

impl From<&KeyRecord> for KeyReport {
    fn from(record: &KeyRecord) -> Self {
        Self {
            id: record.id.clone(),
            label: record.label.clone(),
            created_at: record.created_at,
            revoked_at: record.revoked_at,
        }
    }
}

fn states(keys: &[KeyRecord]) -> Vec<KeyState> {
    keys.iter()
        .map(|key| KeyState {
            id: key.id.clone(),
            revoked: key.revoked_at.is_some(),
        })
        .collect()
}

fn checked_label(label: Option<String>) -> Outcome<String> {
    let label = label.unwrap_or_default();
    if !label_fits(&label) {
        return Err(Failure::Invalid(
            "키의 이름은 100글자까지여야 합니다".to_owned(),
        ));
    }
    Ok(label)
}

fn checked_name(raw: &str) -> Outcome<OrganizationName> {
    organization_name(raw).map_err(|problem| Failure::Invalid(problem.to_string()))
}

/// 같은 길이의 두 바이트열을 걸린 시간으로 다른 자리가 새지 않게 견준다.
pub(super) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

impl Layer {
    /// 새 키 한 줄과 그 비밀. 비밀은 접두어로 무엇인지 알아보게 한다(비밀 검사 도구가 찾기 쉽다).
    fn new_key(&self, label: String) -> Outcome<(KeyRecord, String)> {
        let secret = format!("orb_sk_{}", URL_SAFE_NO_PAD.encode(random(32)?));
        let record = KeyRecord {
            id: format!("key_{}", token::hex(&random(8)?)),
            label,
            digest: sha256_hex(&secret),
            created_at: (self.clock)(),
            revoked_at: None,
        };
        Ok((record, secret))
    }

    /// 환경 변수의 키가 이 조직에 있는가.
    fn bootstrap(&self, organization: &str) -> bool {
        self.service_keys
            .iter()
            .any(|(_, known)| known == organization)
    }

    /// 운영자 키인가. 운영자 키를 두지 않은 레이어는 누구에게도 이 길을 열지 않는다.
    pub fn operator(&self, bearer: &str) -> Outcome<()> {
        match &self.admin_key {
            Some(known) if same(known, &digest(bearer)) => Ok(()),
            _ => Err(Failure::Unauthorized),
        }
    }

    /// 저장한 키의 조직. 폐기한 키는 없는 키와 같다.
    pub(super) fn stored_organization(&self, key: &str) -> Option<String> {
        let given = sha256_hex(key);
        let inner = self.lock();
        inner
            .registry
            .state
            .organizations
            .iter()
            .find(|(_, record)| {
                record.keys.iter().any(|stored| {
                    stored.revoked_at.is_none() && same(stored.digest.as_bytes(), given.as_bytes())
                })
            })
            .map(|(organization, _)| organization.clone())
    }

    /// 조직을 만들고 첫 키를 낸다. 이미 있거나 환경 변수의 조직이면 409 다.
    pub fn create_organization(
        &self,
        id: &str,
        label: Option<String>,
    ) -> Outcome<(String, IssuedKey)> {
        let name = checked_name(id)?;
        let label = checked_label(label)?;
        let exists =
            || Failure::Conflict("이미 있는 조직입니다. 다른 이름을 골라 주세요".to_owned());
        // 환경 변수의 조직과 이름이 같으면 두 열쇠가 같은 인스턴스를 나눠 갖게 된다
        if self.bootstrap(name.as_str()) {
            return Err(exists());
        }
        let (key, secret) = self.new_key(String::new())?;
        let mut inner = self.lock();
        if inner
            .registry
            .state
            .organizations
            .contains_key(name.as_str())
        {
            return Err(exists());
        }
        let report = KeyReport::from(&key);
        inner.registry.state.organizations.insert(
            name.as_str().to_owned(),
            OrganizationRecord {
                label,
                created_at: key.created_at,
                keys: vec![key],
            },
        );
        inner.registry.save().map_err(Failure::Internal)?;
        Ok((
            name.as_str().to_owned(),
            IssuedKey {
                key: report,
                secret,
            },
        ))
    }

    /// 조직의 키를 만든 차례대로. 폐기한 키도 보인다.
    pub fn keys(&self, organization: &str) -> Vec<KeyReport> {
        let inner = self.lock();
        inner
            .registry
            .state
            .organizations
            .get(organization)
            .map(|record| record.keys.iter().map(KeyReport::from).collect())
            .unwrap_or_default()
    }

    /// 조직의 키로 새 키를 만든다.
    pub fn create_key(&self, organization: &str, label: Option<String>) -> Outcome<IssuedKey> {
        let label = checked_label(label)?;
        let (key, secret) = self.new_key(label)?;
        let mut inner = self.lock();
        // 환경 변수의 조직은 처음 키를 만들 때 기록에 생긴다
        let record = inner
            .registry
            .state
            .organizations
            .entry(organization.to_owned())
            .or_insert_with(|| OrganizationRecord {
                label: String::new(),
                created_at: key.created_at,
                keys: Vec::new(),
            });
        let report = KeyReport::from(&key);
        record.keys.push(key);
        inner.registry.save().map_err(Failure::Internal)?;
        Ok(IssuedKey {
            key: report,
            secret,
        })
    }

    /// 조직의 키 하나를 폐기한다. 마지막 살아 있는 키는 폐기하지 못한다.
    pub fn revoke_key(&self, organization: &str, id: &str) -> Outcome<KeyReport> {
        let bootstrap = self.bootstrap(organization);
        let now = (self.clock)();
        let mut inner = self.lock();
        let Some(record) = inner.registry.state.organizations.get_mut(organization) else {
            return Err(Failure::NotFound);
        };
        match judge_revoke(&states(&record.keys), id, bootstrap) {
            Revoke::NotFound => Err(Failure::NotFound),
            Revoke::LastLiveKey => Err(Failure::Conflict(
                "조직의 마지막 살아 있는 키는 폐기하지 못합니다. 새 키를 만든 뒤에 폐기해 주세요"
                    .to_owned(),
            )),
            Revoke::AlreadyRevoked => record
                .keys
                .iter()
                .find(|key| key.id == id)
                .map(KeyReport::from)
                .ok_or(Failure::NotFound),
            Revoke::Revoke => {
                let key = record
                    .keys
                    .iter_mut()
                    .find(|key| key.id == id)
                    .ok_or(Failure::NotFound)?;
                key.revoked_at = Some(now);
                let report = KeyReport::from(&*key);
                inner.registry.save().map_err(Failure::Internal)?;
                Ok(report)
            }
        }
    }

    /// 운영자가 살아 있는 키가 없는 조직에 키를 내어 되살린다.
    pub fn operator_issue_key(&self, id: &str, label: Option<String>) -> Outcome<IssuedKey> {
        let name = checked_name(id)?;
        let label = checked_label(label)?;
        let bootstrap = self.bootstrap(name.as_str());
        let (key, secret) = self.new_key(label)?;
        let mut inner = self.lock();
        let record = inner.registry.state.organizations.get_mut(name.as_str());
        let keys = record.as_ref().map(|record| states(&record.keys));
        match judge_operator_issue(keys.as_deref(), bootstrap) {
            OperatorIssue::NotFound => Err(Failure::NotFound),
            OperatorIssue::Bootstrap => Err(Failure::Conflict(
                "환경 변수의 키가 있는 조직에는 운영자가 키를 내지 않습니다".to_owned(),
            )),
            OperatorIssue::HasLiveKey => Err(Failure::Conflict(
                "살아 있는 키가 있는 조직에는 운영자가 키를 내지 않습니다. 조직의 키로 새 키를 만들어 주세요".to_owned(),
            )),
            OperatorIssue::Issue => {
                let report = KeyReport::from(&key);
                if let Some(record) = record {
                    record.keys.push(key);
                }
                inner.registry.save().map_err(Failure::Internal)?;
                // 운영자가 조직의 키를 낸 일은 드물고 무겁다. 이름과 식별자만 남긴다
                eprintln!(
                    "orbitald: 운영자가 키가 없는 조직 {} 에 키 {} 를 냈습니다",
                    name.as_str(),
                    report.id
                );
                Ok(IssuedKey { key: report, secret })
            }
        }
    }

    /// 운영자가 조직의 키를 간다. 저장한 키를 모두 폐기하고 새 키 하나를 낸다.
    /// 키의 비밀을 모두 잃은 조직을 되살리는 길이다. 환경 변수의 조직과 없는 조직은 갈지 않는다.
    pub fn operator_reset_keys(&self, id: &str) -> Outcome<IssuedKey> {
        let name = checked_name(id)?;
        if self.bootstrap(name.as_str()) {
            return Err(Failure::Conflict(
                "환경 변수의 키가 있는 조직의 키는 갈지 않습니다".to_owned(),
            ));
        }
        let now = (self.clock)();
        let (key, secret) = self.new_key(String::new())?;
        let mut inner = self.lock();
        let Some(record) = inner.registry.state.organizations.get_mut(name.as_str()) else {
            return Err(Failure::NotFound);
        };
        for old in &mut record.keys {
            old.revoked_at.get_or_insert(now);
        }
        let report = KeyReport::from(&key);
        record.keys.push(key);
        inner.registry.save().map_err(Failure::Internal)?;
        eprintln!(
            "orbitald: 운영자가 조직 {} 의 키를 갈았습니다. 새 키는 {} 입니다",
            name.as_str(),
            report.id
        );
        Ok(IssuedKey {
            key: report,
            secret,
        })
    }
}
