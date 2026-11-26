//! 금고. 밖에서 넣는 비밀(`[secrets] external`)의 값을 인스턴스와 단계(프리뷰 · 운영)마다 봉인해 둔다.
//!
//! 값은 봉인한 글로만 control database 의 `vault_value` 표에 있다. 봉인에는 조직 · 인스턴스 · 단계 · 이름을 함께 묶어([`secret_binding`]),
//! 봉인된 글을 다른 자리에 옮겨 심으면 풀리지 않는다. 열쇠(`ORBITAL_SEAL_KEY`)는 기록 밖에 있고, 없는 레이어에서는 값을 넣지 못한다.
//!
//! 값이 들어오는 길은 둘이다(service key 로 바로 넣기, 사람의 입력 표). 나가는 길은 앱의 환경 변수 하나뿐이다. 값을 돌려주는 API 는 없다.
//! 에이전트의 요청(`secret_request`)과 입력 표(`secret_entry`, sha256 으로만)도 control database 에 적는다. 어느 관리 서버가 받아도
//! 다른 관리 서버가 곧 본다. 입력 표는 그 줄을 잠그고 써서 두 관리 서버에서 동시에 써도 한 번만 쓰인다.
//!
//! 판정(값의 한도, 빠진 이름, 입력 표를 받을지)은 core 의 `secrets` 가 한다. 여기서는 봉인하고 적고 읽는다.
//! 레이어의 큰 자물쇠는 쥐지 않아, 자는 서비스를 깨울 때(값을 읽을 때) 승격이 끝나기를 기다리지 않는다.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use orbital_core::name::{InstanceId, SecretName};
use orbital_core::secrets::{
    Entry, EntryRefusal, Place, Stage, ValueProblem, judge_entry, judge_value,
};
use orbital_core::sweep::LEFTOVER_RETENTION;
use postgres::Transaction;
use serde::{Deserialize, Serialize};

use crate::records::{RecordError, Records};
use crate::seal::{Rekeyed, SealKey, open, reseal, seal, secret_binding};

/// 비밀의 값. 찍어도(`Debug`) 값이 보이지 않고, 글(`Display`)이나 JSON 으로 내보내는 길이 없다.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// 앱의 환경 변수에 실을 때만 꺼낸다.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(..)")
    }
}

/// 옛 기록 파일(`vault.json`)의 한 칸.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sealed {
    /// 봉인한 값.
    sealed: String,
    set_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Slots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview: Option<Sealed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    production: Option<Sealed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    organization: String,
    entry: Entry,
}

/// 옛 기록 파일(`vault.json`)의 모양. 처음 뜰 때 한 번 control database 로 옮긴다.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct OldVault {
    /// 인스턴스 → 이름 → 단계마다의 봉인.
    #[serde(default)]
    values: BTreeMap<String, BTreeMap<String, Slots>>,
    /// 인스턴스 → 이름 → 마지막 요청.
    #[serde(default)]
    requests: BTreeMap<String, BTreeMap<String, Requested>>,
    /// 입력 표의 sha256(hex) → 표.
    #[serde(default)]
    entries: BTreeMap<String, StoredEntry>,
}

/// 옛 기록 파일을 읽는다. 읽지 못하면 `None` 이다.
pub(crate) fn parse_old(bytes: &[u8]) -> Option<OldVault> {
    serde_json::from_slice(bytes).ok()
}

fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn db(doing: &'static str) -> impl Fn(postgres::Error) -> RecordError {
    move |_| RecordError(format!("비밀의 금고를 {doing}지 못했습니다"))
}

/// 금고의 줄 하나. (이름, 단계, 봉인한 글, 넣은 때).
type SealedRow = (String, Stage, String, u64);

/// 옛 금고를 옮긴다. 봉인한 글은 그대로 옮긴다. 기록에 없는 인스턴스의 줄이 있으면 실패한다(외래 키).
pub(crate) fn import_old(
    transaction: &mut Transaction<'_>,
    old: &OldVault,
) -> Result<(), RecordError> {
    for (instance, names) in &old.values {
        for (name, slots) in names {
            for (stage, slot) in [
                ("preview", &slots.preview),
                ("production", &slots.production),
            ] {
                let Some(slot) = slot else {
                    continue;
                };
                transaction
                    .execute(
                        "INSERT INTO orbital.vault_value (instance, stage, name, sealed, set_at) VALUES ($1, $2, $3, $4, $5)",
                        &[instance, &stage, name, &slot.sealed, &signed(slot.set_at)],
                    )
                    .map_err(db("옮기"))?;
            }
        }
    }
    for (instance, names) in &old.requests {
        for (name, requested) in names {
            transaction
                .execute(
                    "INSERT INTO orbital.secret_request (instance, name, reason, at) VALUES ($1, $2, $3, $4)",
                    &[instance, name, &requested.reason, &signed(requested.at)],
                )
                .map_err(db("옮기"))?;
        }
    }
    for (digest, stored) in &old.entries {
        let place = &stored.entry.place;
        transaction
            .execute(
                "INSERT INTO orbital.secret_entry (digest, organization, instance, name, stage, expires_at, used) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    digest,
                    &stored.organization,
                    &place.instance.as_str(),
                    &place.name.as_str(),
                    &place.stage.as_str(),
                    &signed(stored.entry.expires_at),
                    &stored.entry.used,
                ],
            )
            .map_err(db("옮기"))?;
    }
    Ok(())
}

/// 에이전트의 요청 하나. 값이 아니라 까닭만 담는다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requested {
    pub reason: String,
    pub at: u64,
}

/// 금고가 하지 못한 까닭. 문구에 값을 싣지 않는다.
#[derive(Debug)]
pub enum VaultError {
    /// 레이어에 봉인의 열쇠가 없다.
    NoSealKey,
    Internal(String),
}

impl From<RecordError> for VaultError {
    fn from(error: RecordError) -> Self {
        Self::Internal(error.0)
    }
}

/// 입력 표로 값을 넣지 못한 까닭.
#[derive(Debug)]
pub enum RedeemError {
    /// 레이어가 낸 적 없는 표다(또는 지워졌다).
    Unknown,
    Refused(EntryRefusal),
    Value(Vec<ValueProblem>),
    Vault(VaultError),
}

/// 이름 하나의 모습. 값은 없고 채워졌는지와 그 때만 있다.
#[derive(Debug, Clone, Default)]
pub struct Filled {
    pub preview: Option<u64>,
    pub production: Option<u64>,
}

pub struct Vault {
    records: Arc<Records>,
    seal: Option<SealKey>,
}

impl Vault {
    pub fn new(records: Arc<Records>, seal: Option<SealKey>) -> Self {
        Self { records, seal }
    }

    /// 값을 넣을 수 있는가(봉인의 열쇠가 있는가).
    pub fn can_seal(&self) -> bool {
        self.seal.is_some()
    }

    /// 옛 열쇠로만 풀리는 값을 이 금고의 열쇠(새 열쇠)로 다시 봉인해 적는다. 봉인은 조직에 묶여 있어 인스턴스의 줄에서 조직을 읽는다.
    /// (바꾼 줄의 수, 풀리지 않는 줄의 이름). 모든 줄을 잠그고 한 트랜잭션으로 바꾼다.
    pub fn reseal(&self, previous: &SealKey) -> Result<(usize, Vec<String>), String> {
        let Some(new) = self.seal.as_ref() else {
            return Ok((0, Vec::new()));
        };
        let failed = || "비밀의 금고를 다시 봉인하지 못했습니다".to_owned();
        let mut client = self.records.client().map_err(|_| failed())?;
        let mut transaction = client.transaction().map_err(|_| failed())?;
        let rows = transaction
            .query(
                "SELECT v.instance, v.stage, v.name, v.sealed, i.organization FROM orbital.vault_value v
                 JOIN orbital.instance i ON i.id = v.instance FOR UPDATE OF v",
                &[],
            )
            .map_err(|_| failed())?;
        let mut changed = 0;
        let mut unopened = Vec::new();
        for row in rows {
            let (instance, stage, name, sealed, organization): (
                String,
                String,
                String,
                String,
                String,
            ) = (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4));
            match reseal(
                new,
                previous,
                &secret_binding(&organization, &instance, &stage, &name),
                &sealed,
            )
            .ok_or_else(failed)?
            {
                Rekeyed::Current => {}
                Rekeyed::Changed(again) => {
                    transaction
                        .execute(
                            "UPDATE orbital.vault_value SET sealed = $4 WHERE instance = $1 AND stage = $2 AND name = $3",
                            &[&instance, &stage, &name, &again],
                        )
                        .map_err(|_| failed())?;
                    changed += 1;
                }
                Rekeyed::Unopened => unopened.push(format!("vault {instance} {stage} {name}")),
            }
        }
        transaction.commit().map_err(|_| failed())?;
        Ok((changed, unopened))
    }

    fn binding(organization: &str, place: &Place) -> String {
        secret_binding(
            organization,
            place.instance.as_str(),
            place.stage.as_str(),
            place.name.as_str(),
        )
    }

    fn unseal(&self, organization: &str, place: &Place, sealed: &str) -> Option<SecretValue> {
        open(
            self.seal.as_ref()?,
            &Self::binding(organization, place),
            sealed,
        )
        .map(SecretValue)
    }

    fn sealed(
        &self,
        organization: &str,
        place: &Place,
        value: &SecretValue,
    ) -> Result<String, VaultError> {
        let key = self.seal.as_ref().ok_or(VaultError::NoSealKey)?;
        seal(key, &Self::binding(organization, place), &value.0)
            .ok_or_else(|| VaultError::Internal("난수를 읽지 못해 봉인하지 못했습니다".to_owned()))
    }

    fn put_in(
        transaction: &mut Transaction<'_>,
        place: &Place,
        sealed: &str,
        at: u64,
    ) -> Result<(), VaultError> {
        transaction
            .execute(
                "INSERT INTO orbital.vault_value (instance, stage, name, sealed, set_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (instance, stage, name) DO UPDATE SET sealed = excluded.sealed, set_at = excluded.set_at",
                &[
                    &place.instance.as_str(),
                    &place.stage.as_str(),
                    &place.name.as_str(),
                    &sealed,
                    &signed(at),
                ],
            )
            .map_err(db("적"))?;
        Ok(())
    }

    /// 값을 넣는다(service key 의 길).
    pub fn put(
        &self,
        organization: &str,
        place: &Place,
        value: &SecretValue,
        at: u64,
    ) -> Result<(), VaultError> {
        let sealed = self.sealed(organization, place, value)?;
        let mut client = self.records.client()?;
        let mut transaction = client.transaction().map_err(db("적"))?;
        Self::put_in(&mut transaction, place, &sealed, at)?;
        transaction.commit().map_err(db("적"))?;
        Ok(())
    }

    /// 값을 지운다. 없었으면 `false` 다.
    pub fn remove(&self, place: &Place) -> Result<bool, VaultError> {
        let removed = self
            .records
            .client()?
            .execute(
                "DELETE FROM orbital.vault_value WHERE instance = $1 AND stage = $2 AND name = $3",
                &[
                    &place.instance.as_str(),
                    &place.stage.as_str(),
                    &place.name.as_str(),
                ],
            )
            .map_err(db("지우"))?;
        Ok(removed > 0)
    }

    /// 인스턴스의 봉인한 값들. (이름, 단계, 봉인한 글, 넣은 때). 읽지 못한 것은 「없다」와 다르다.
    fn rows(&self, instance: &InstanceId) -> Result<Vec<SealedRow>, RecordError> {
        // 자는 서비스를 깨울 때(router 의 런타임 안에서) 부른다
        crate::records::off_runtime(|| self.rows_now(instance))
    }

    fn rows_now(&self, instance: &InstanceId) -> Result<Vec<SealedRow>, RecordError> {
        Ok(self
            .records
            .client()?
            .query(
                "SELECT name, stage, sealed, set_at FROM orbital.vault_value WHERE instance = $1",
                &[&instance.as_str()],
            )
            .map_err(db("읽"))?
            .iter()
            .filter_map(|row| {
                Some((
                    row.get::<_, String>(0),
                    Stage::parse(&row.get::<_, String>(1))?,
                    row.get::<_, String>(2),
                    unsigned(row.get::<_, i64>(3)),
                ))
            })
            .collect())
    }

    /// 이 레이어의 열쇠로 풀리는 값이 있는 이름. 다른 열쇠로 봉인했거나 다른 자리에서 옮겨 온 것은 채워지지 않은 것으로 본다.
    pub fn filled(
        &self,
        organization: &str,
        instance: &InstanceId,
        stage: Stage,
    ) -> BTreeSet<SecretName> {
        self.status(organization, instance)
            .into_iter()
            .filter(|(_, filled)| match stage {
                Stage::Preview => filled.preview.is_some(),
                Stage::Production => filled.production.is_some(),
            })
            .map(|(name, _)| name)
            .collect()
    }

    /// 이름마다 채워졌는지와 그 때. 풀리는 것만 채워진 것으로 본다.
    pub fn status(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> BTreeMap<SecretName, Filled> {
        let mut found: BTreeMap<SecretName, Filled> = BTreeMap::new();
        // 읽지 못하면 채워지지 않은 것으로 본다. 승격은 빠진 비밀로 막히고(닫힌 쪽), 앱에 싣는 길(`values`)은 따로 실패한다
        for (name, stage, sealed, set_at) in self.rows(instance).unwrap_or_default() {
            let Ok(name) = SecretName::parse(&name) else {
                continue;
            };
            let place = Place {
                instance: instance.clone(),
                name: name.clone(),
                stage,
            };
            let filled = found.entry(name).or_default();
            if self.unseal(organization, &place, &sealed).is_some() {
                match stage {
                    Stage::Preview => filled.preview = Some(set_at),
                    Stage::Production => filled.production = Some(set_at),
                }
            }
        }
        found
    }

    /// 앱의 환경에 실을 값. `names` 가운데 이 단계의 칸에 풀리는 값이 있는 것만 돌려준다. 다른 단계의 칸으로 대신하지 않는다.
    ///
    /// 금고를 읽지 못하면 빈 목록이 아니라 실패다. 빈 목록으로 답하면 앱이 비밀 없이 뜬다.
    pub fn values(
        &self,
        organization: &str,
        instance: &InstanceId,
        stage: Stage,
        names: &[SecretName],
    ) -> Result<Vec<(SecretName, SecretValue)>, VaultError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let rows = self.rows(instance)?;
        Ok(names
            .iter()
            .filter_map(|name| {
                let (_, _, sealed, _) = rows
                    .iter()
                    .find(|(found, at, _, _)| found == name.as_str() && *at == stage)?;
                let place = Place {
                    instance: instance.clone(),
                    name: name.clone(),
                    stage,
                };
                Some((name.clone(), self.unseal(organization, &place, sealed)?))
            })
            .collect())
    }

    /// 에이전트의 요청을 적는다. 같은 이름의 앞 요청은 새 것으로 바뀐다.
    pub fn request(
        &self,
        instance: &InstanceId,
        name: &SecretName,
        reason: &str,
        at: u64,
    ) -> Result<(), VaultError> {
        self.records
            .client()?
            .execute(
                "INSERT INTO orbital.secret_request (instance, name, reason, at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (instance, name) DO UPDATE SET reason = excluded.reason, at = excluded.at",
                &[&instance.as_str(), &name.as_str(), &reason, &signed(at)],
            )
            .map_err(db("적"))?;
        Ok(())
    }

    pub fn requests(&self, instance: &InstanceId) -> BTreeMap<String, Requested> {
        let Ok(mut client) = self.records.client() else {
            return BTreeMap::new();
        };
        client
            .query(
                "SELECT name, reason, at FROM orbital.secret_request WHERE instance = $1",
                &[&instance.as_str()],
            )
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        (
                            row.get::<_, String>(0),
                            Requested {
                                reason: row.get(1),
                                at: unsigned(row.get(2)),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 입력 표를 적는다. 표는 sha256(hex)으로만 둔다. 쓰고 남은 표(만료에서 하루가 지난 것)는 이때 함께 지운다.
    pub fn issue(
        &self,
        organization: &str,
        digest: &str,
        entry: Entry,
        now: u64,
    ) -> Result<(), VaultError> {
        let mut client = self.records.client()?;
        let mut transaction = client.transaction().map_err(db("적"))?;
        transaction
            .execute(
                "DELETE FROM orbital.secret_entry WHERE expires_at <= $1",
                &[&signed(now.saturating_sub(LEFTOVER_RETENTION))],
            )
            .map_err(db("걷"))?;
        let place = &entry.place;
        transaction
            .execute(
                "INSERT INTO orbital.secret_entry (digest, organization, instance, name, stage, expires_at, used) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &digest,
                    &organization,
                    &place.instance.as_str(),
                    &place.name.as_str(),
                    &place.stage.as_str(),
                    &signed(entry.expires_at),
                    &entry.used,
                ],
            )
            .map_err(db("적"))?;
        transaction.commit().map_err(db("적"))?;
        Ok(())
    }

    /// 입력 표로 값을 넣는다. 표의 줄을 잠그고 표의 판정 → 값의 판정 → 봉인해 넣고 표를 쓴 것으로 적기를 한 트랜잭션에서 한다.
    /// 두 관리 서버가 같은 표를 동시에 받아도 뒤의 것은 앞의 것이 끝나기를 기다렸다가 「이미 썼다」로 거절된다.
    ///
    /// `wanted` 의 이름과 단계는 본문이 적은 것이다. 적지 않았으면 표의 것이고, 다르면 core 가 거절한다.
    pub fn redeem(
        &self,
        digest: &str,
        wanted: (Option<SecretName>, Option<Stage>),
        value: &SecretValue,
        at: u64,
    ) -> Result<Place, RedeemError> {
        let internal = |error: RecordError| RedeemError::Vault(error.into());
        let mut client = self.records.client().map_err(internal)?;
        let mut transaction = client
            .transaction()
            .map_err(|error| internal(db("읽")(error)))?;
        let row = transaction
            .query_opt(
                "SELECT organization, instance, name, stage, expires_at, used FROM orbital.secret_entry WHERE digest = $1 FOR UPDATE",
                &[&digest],
            )
            .map_err(|error| internal(db("읽")(error)))?
            .ok_or(RedeemError::Unknown)?;
        let organization: String = row.get(0);
        let (Ok(instance), Ok(name), Some(stage)) = (
            InstanceId::parse(&row.get::<_, String>(1)),
            SecretName::parse(&row.get::<_, String>(2)),
            Stage::parse(&row.get::<_, String>(3)),
        ) else {
            return Err(RedeemError::Unknown);
        };
        let entry = Entry {
            place: Place {
                instance,
                name,
                stage,
            },
            expires_at: unsigned(row.get(4)),
            used: row.get(5),
        };
        let place = Place {
            instance: entry.place.instance.clone(),
            name: wanted.0.unwrap_or_else(|| entry.place.name.clone()),
            stage: wanted.1.unwrap_or(entry.place.stage),
        };
        judge_entry(&entry, &place, at).map_err(RedeemError::Refused)?;
        let problems = judge_value(&value.0);
        if !problems.is_empty() {
            return Err(RedeemError::Value(problems));
        }
        let sealed = self
            .sealed(&organization, &place, value)
            .map_err(RedeemError::Vault)?;
        Self::put_in(&mut transaction, &place, &sealed, at).map_err(RedeemError::Vault)?;
        transaction
            .execute(
                "UPDATE orbital.secret_entry SET used = true WHERE digest = $1",
                &[&digest],
            )
            .map_err(|error| internal(db("적")(error)))?;
        transaction
            .commit()
            .map_err(|error| internal(db("적")(error)))?;
        Ok(place)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 값을_찍어도_보이지_않는다() {
        let value = SecretValue::new("sk_live_bank".to_owned());
        assert_eq!(format!("{value:?}"), "SecretValue(..)");
        assert_eq!(
            format!("{:?}", RedeemError::Value(vec![ValueProblem::Nul])),
            "Value([Nul])"
        );
    }
}
