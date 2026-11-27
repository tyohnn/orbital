//! 조직과 service key 의 기록. 열쇠의 값은 두지 않고 sha256(hex)만 둔다.
//!
//! 판정은 core 의 `organization` 이 한다. 여기서는 줄을 잠그고 사실을 읽어 판정에 넘긴 뒤, 받아들인 것만 한 트랜잭션으로 적는다.
//! 같은 조직의 인스턴스 세우기와 조직 닫기는 그 조직의 advisory lock(트랜잭션 동안)으로 한 줄로 서서, 상한과 닫힘을 두 관리 서버가 함께 넘지 못한다.

use orbital_core::organization::{KeyFacts, Kind, OrganizationState, Revoking};
use orbital_core::scope::OrganizationId;
use postgres::Transaction;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{RecordError, Records, pg, signed};
use crate::registry::InstanceRecord;

/// 기록의 조직 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrganizationRow {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<u64>,
}

impl OrganizationRow {
    pub fn state(&self) -> OrganizationState {
        OrganizationState {
            kind: self.kind,
            closed: self.closed_at.is_some(),
        }
    }
}

/// 기록의 열쇠 하나. 값도 sha256 도 싣지 않는다. 끝 네 글자 같은 값의 조각도 싣지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyRow {
    pub id: String,
    pub label: String,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
    /// 마지막으로 쓴 때. 분 단위로 뭉친 것이다.
    pub used_at: Option<u64>,
}

/// 새로 적을 열쇠. 값 대신 sha256 을 싣는다.
pub struct NewKey<'a> {
    pub id: &'a str,
    pub digest: &'a str,
    pub label: &'a str,
    pub created_at: u64,
}

/// sha256 으로 찾은 기록의 열쇠.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKey {
    pub id: String,
    pub organization: OrganizationId,
    pub revoked: bool,
    pub state: OrganizationState,
    pub used_at: Option<u64>,
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn kind_of(text: &str) -> Result<Kind, RecordError> {
    Kind::parse(text).ok_or_else(|| {
        RecordError("레이어의 기록을 읽지 못했습니다(조직의 종류가 틀렸습니다)".to_owned())
    })
}

/// 조직마다의 advisory lock 번호. 이름의 sha256 앞 8바이트다.
fn organization_lock(organization: &str) -> i64 {
    let digest = Sha256::digest(format!("orbital/organization\n{organization}").as_bytes());
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(head)
}

/// 트랜잭션 동안 그 조직의 차례를 잡는다. 인스턴스 세우기와 조직 닫기가 한 줄로 선다.
fn hold_organization(
    transaction: &mut Transaction<'_>,
    organization: &str,
) -> Result<(), RecordError> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&organization_lock(organization)],
        )
        .map(drop)
        .map_err(pg("조직의 차례를 잡"))
}

const KEY_COLUMNS: &str = "id, label, created_at, revoked_at, used_at";

fn key_row(row: &postgres::Row) -> KeyRow {
    KeyRow {
        id: row.get(0),
        label: row.get(1),
        created_at: unsigned(row.get(2)),
        revoked_at: row.get::<_, Option<i64>>(3).map(unsigned),
        used_at: row.get::<_, Option<i64>>(4).map(unsigned),
    }
}

const ORGANIZATION_COLUMNS: &str = "id, name, kind, created_at, closed_at";

fn organization_row(row: &postgres::Row) -> Result<OrganizationRow, RecordError> {
    Ok(OrganizationRow {
        id: row.get(0),
        name: row.get(1),
        kind: kind_of(row.get(2))?,
        created_at: unsigned(row.get(3)),
        closed_at: row.get::<_, Option<i64>>(4).map(unsigned),
    })
}

fn state_in(
    transaction: &mut Transaction<'_>,
    organization: &str,
    lock: bool,
) -> Result<Option<OrganizationState>, RecordError> {
    let query = if lock {
        "SELECT kind, closed_at FROM orbital.organization WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT kind, closed_at FROM orbital.organization WHERE id = $1"
    };
    transaction
        .query_opt(query, &[&organization])
        .map_err(pg("조직을 읽"))?
        .map(|row| {
            Ok(OrganizationState {
                kind: kind_of(row.get(0))?,
                closed: row.get::<_, Option<i64>>(1).is_some(),
            })
        })
        .transpose()
}

/// 조직의 살아 있는(거두지 않은) 열쇠의 수.
fn alive_in(transaction: &mut Transaction<'_>, organization: &str) -> Result<u32, RecordError> {
    let alive: i64 = transaction
        .query_one(
            "SELECT count(*) FROM orbital.service_key WHERE organization = $1 AND revoked_at IS NULL",
            &[&organization],
        )
        .map_err(pg("열쇠를 세"))?
        .get(0);
    Ok(u32::try_from(alive).unwrap_or(u32::MAX))
}

fn insert_key(
    transaction: &mut Transaction<'_>,
    organization: &str,
    key: &NewKey<'_>,
) -> Result<(), RecordError> {
    transaction
        .execute(
            "INSERT INTO orbital.service_key (id, organization, digest, label, created_at) VALUES ($1, $2, $3, $4, $5)",
            &[&key.id, &organization, &key.digest, &key.label, &signed(key.created_at)],
        )
        .map(drop)
        .map_err(pg("열쇠를 적"))
}

impl Records {
    /// 조직과 그 첫 열쇠를 한 트랜잭션으로 적는다. 같은 이름의 조직이 이미 있으면 아무것도 적지 않고 거짓이다.
    pub fn create_organization(
        &self,
        organization: &OrganizationRow,
        key: &NewKey<'_>,
    ) -> Result<bool, RecordError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("조직을 적"))?;
        let inserted = transaction
            .execute(
                "INSERT INTO orbital.organization (id, name, kind, created_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &organization.id,
                    &organization.name,
                    &organization.kind.as_str(),
                    &signed(organization.created_at),
                ],
            )
            .map_err(pg("조직을 적"))?;
        if inserted == 0 {
            return Ok(false);
        }
        insert_key(&mut transaction, &organization.id, key)?;
        transaction.commit().map_err(pg("조직을 적"))?;
        Ok(true)
    }

    /// 조직 하나. 없으면 `None` 이다.
    pub fn organization(&self, id: &str) -> Result<Option<OrganizationRow>, RecordError> {
        self.client()?
            .query_opt(
                &format!("SELECT {ORGANIZATION_COLUMNS} FROM orbital.organization WHERE id = $1"),
                &[&id],
            )
            .map_err(pg("조직을 읽"))?
            .map(|row| organization_row(&row))
            .transpose()
    }

    /// 모든 조직. 이름 순이다.
    pub fn organizations(&self) -> Result<Vec<OrganizationRow>, RecordError> {
        self.client()?
            .query(
                &format!("SELECT {ORGANIZATION_COLUMNS} FROM orbital.organization ORDER BY id"),
                &[],
            )
            .map_err(pg("조직을 읽"))?
            .iter()
            .map(organization_row)
            .collect()
    }

    /// 조직의 인스턴스의 수와 살아 있는 열쇠의 수.
    pub fn organization_counts(&self, id: &str) -> Result<(u32, u32), RecordError> {
        let row = self
            .client()?
            .query_one(
                "SELECT (SELECT count(*) FROM orbital.instance WHERE organization = $1),
                        (SELECT count(*) FROM orbital.service_key WHERE organization = $1 AND revoked_at IS NULL)",
                &[&id],
            )
            .map_err(pg("조직을 세"))?;
        let count = |at: usize| u32::try_from(row.get::<_, i64>(at)).unwrap_or(u32::MAX);
        Ok((count(0), count(1)))
    }

    /// 조직의 모습(종류 · 닫혔는가). 기록에 없으면 `None` 이다. 설정의 열쇠를 받을 때 요청마다 본다.
    pub fn organization_state(&self, id: &str) -> Result<Option<OrganizationState>, RecordError> {
        self.client()?
            .query_opt(
                "SELECT kind, closed_at FROM orbital.organization WHERE id = $1",
                &[&id],
            )
            .map_err(pg("조직을 읽"))?
            .map(|row| {
                Ok(OrganizationState {
                    kind: kind_of(row.get(0))?,
                    closed: row.get::<_, Option<i64>>(1).is_some(),
                })
            })
            .transpose()
    }

    /// sha256 으로 기록의 열쇠를 찾는다. 요청마다 본다. 없으면 `None` 이다.
    ///
    /// 값이 아니라 sha256 을 견주므로, 견주는 데 걸린 시간은 보낸 값의 해시가 기록의 해시와 몇 글자 맞는지만 알려 준다. 해시의 앞을 맞혀도
    /// 그 해시가 될 값을 찾지 못하므로 시간으로 열쇠를 맞혀 가지 못한다.
    pub fn find_key(&self, digest: &str) -> Result<Option<FoundKey>, RecordError> {
        self.client()?
            .query_opt(
                "SELECT k.id, k.organization, k.revoked_at, k.used_at, o.kind, o.closed_at
                 FROM orbital.service_key k JOIN orbital.organization o ON o.id = k.organization
                 WHERE k.digest = $1",
                &[&digest],
            )
            .map_err(pg("열쇠를 읽"))?
            .map(|row| {
                Ok(FoundKey {
                    id: row.get(0),
                    organization: OrganizationId(row.get(1)),
                    revoked: row.get::<_, Option<i64>>(2).is_some(),
                    used_at: row.get::<_, Option<i64>>(3).map(unsigned),
                    state: OrganizationState {
                        kind: kind_of(row.get(4))?,
                        closed: row.get::<_, Option<i64>>(5).is_some(),
                    },
                })
            })
            .transpose()
    }

    /// 열쇠를 쓴 때를 적는다. 이미 그 때 뒤로 적혀 있으면 적지 않는다(두 관리 서버가 함께 적어도 뒤로 가지 않는다).
    pub fn touch_key(&self, id: &str, at: u64) -> Result<(), RecordError> {
        self.client()?
            .execute(
                "UPDATE orbital.service_key SET used_at = $2 WHERE id = $1 AND (used_at IS NULL OR used_at < $2)",
                &[&id, &signed(at)],
            )
            .map(drop)
            .map_err(pg("열쇠를 쓴 때를 적"))
    }

    /// 조직의 열쇠 모두. 만든 차례다. 값과 sha256 은 싣지 않는다.
    pub fn keys(&self, organization: &str) -> Result<Vec<KeyRow>, RecordError> {
        Ok(self
            .client()?
            .query(
                &format!(
                    "SELECT {KEY_COLUMNS} FROM orbital.service_key WHERE organization = $1 ORDER BY made"
                ),
                &[&organization],
            )
            .map_err(pg("열쇠를 읽"))?
            .iter()
            .map(key_row)
            .collect())
    }

    /// 조직에 열쇠를 하나 적는다. 조직의 줄을 잠그고 그 모습과 살아 있는 열쇠의 수를 `judge` 에 넘겨 받아들일 때만 적는다.
    ///
    /// `bootstrap` 이면(설정의 열쇠가 있는 조직) 기록에 없는 조직의 줄을 운영의 조직으로 먼저 만든다. 판정이 거절하면 그 줄도 남지 않는다.
    /// `revoke_others` 면 같은 트랜잭션에서 그 조직의 살아 있는 열쇠를 모두 거둔다(운영자의 키 갈기). 새어 나간 열쇠와 그것으로 낸 열쇠가
    /// 한 번에 끊기고, 조직의 줄을 잠그므로 그사이에 다른 관리 서버에서 낸 열쇠도 남지 않는다. 거둔 수를 돌려준다.
    pub fn issue_key<E: From<RecordError>>(
        &self,
        organization: &str,
        key: &NewKey<'_>,
        (bootstrap, revoke_others): (bool, bool),
        judge: impl FnOnce(Option<&OrganizationState>, u32) -> Result<(), E>,
    ) -> Result<u32, E> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("열쇠를 적"))?;
        if bootstrap {
            transaction
                .execute(
                    "INSERT INTO orbital.organization (id, name, kind, created_at) VALUES ($1, '', 'live', $2)
                     ON CONFLICT (id) DO NOTHING",
                    &[&organization, &signed(key.created_at)],
                )
                .map_err(pg("조직을 적"))?;
        }
        let state = state_in(&mut transaction, organization, true)?;
        let alive = alive_in(&mut transaction, organization)?;
        judge(state.as_ref(), alive)?;
        let revoked = if revoke_others {
            transaction
                .execute(
                    "UPDATE orbital.service_key SET revoked_at = $2 WHERE organization = $1 AND revoked_at IS NULL",
                    &[&organization, &signed(key.created_at)],
                )
                .map_err(pg("열쇠를 거두"))?
        } else {
            0
        };
        insert_key(&mut transaction, organization, key)?;
        transaction.commit().map_err(pg("열쇠를 적"))?;
        Ok(u32::try_from(revoked).unwrap_or(u32::MAX))
    }

    /// `caller` 의 조직이 열쇠 `id` 를 거둔다. 조직의 줄을 잠가 같은 조직의 거두기를 한 줄로 세우고, 살아 있는 열쇠의 수와 함께 `judge` 에 넘긴다.
    /// 거뒀으면(이미 거둔 것이었어도) 그 열쇠의 모습을 돌려준다.
    pub fn revoke_key<E: From<RecordError>>(
        &self,
        caller: &str,
        id: &str,
        now: u64,
        judge: impl FnOnce(Option<&KeyFacts>, u32) -> Result<Revoking, E>,
    ) -> Result<KeyRow, E> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("열쇠를 거두"))?;
        state_in(&mut transaction, caller, true)?;
        let target = transaction
            .query_opt(
                "SELECT organization, revoked_at FROM orbital.service_key WHERE id = $1",
                &[&id],
            )
            .map_err(pg("열쇠를 읽"))?
            .map(|row| KeyFacts {
                organization: OrganizationId(row.get(0)),
                revoked: row.get::<_, Option<i64>>(1).is_some(),
            });
        let alive = alive_in(&mut transaction, caller)?;
        let revoking = judge(target.as_ref(), alive)?;
        if revoking == Revoking::Revoke {
            transaction
                .execute(
                    "UPDATE orbital.service_key SET revoked_at = $3 WHERE id = $1 AND organization = $2 AND revoked_at IS NULL",
                    &[&id, &caller, &signed(now)],
                )
                .map_err(pg("열쇠를 거두"))?;
        }
        let row = transaction
            .query_one(
                &format!(
                    "SELECT {KEY_COLUMNS} FROM orbital.service_key WHERE id = $1 AND organization = $2"
                ),
                &[&id, &caller],
            )
            .map_err(pg("열쇠를 읽"))?;
        let key = key_row(&row);
        transaction.commit().map_err(pg("열쇠를 거두"))?;
        Ok(key)
    }

    /// 조직을 닫는다. 그 조직의 차례를 잡아 인스턴스 세우기와 한 줄로 서고, 남은 인스턴스와 함께 `judge` 에 넘긴다.
    /// 이미 닫힌 조직은 처음 닫은 때를 그대로 둔다.
    pub fn close_organization<E: From<RecordError>>(
        &self,
        id: &str,
        now: u64,
        judge: impl FnOnce(Option<&OrganizationState>, &[String]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("조직을 닫"))?;
        hold_organization(&mut transaction, id)?;
        let state = state_in(&mut transaction, id, true)?;
        let instances: Vec<String> = transaction
            .query(
                "SELECT id FROM orbital.instance WHERE organization = $1 ORDER BY id",
                &[&id],
            )
            .map_err(pg("인스턴스를 읽"))?
            .iter()
            .map(|row| row.get(0))
            .collect();
        judge(state.as_ref(), &instances)?;
        transaction
            .execute(
                "UPDATE orbital.organization SET closed_at = COALESCE(closed_at, $2) WHERE id = $1",
                &[&id, &signed(now)],
            )
            .map_err(pg("조직을 닫"))?;
        transaction.commit().map_err(pg("조직을 닫"))?;
        Ok(())
    }

    /// 새 인스턴스를 적는다(만든 때는 `now`). 그 조직의 차례를 잡고, 조직의 모습과 지금 인스턴스의 수를 `judge` 에 넘겨 받아들일 때만 적는다.
    pub fn insert_instance_checked<E: From<RecordError>>(
        &self,
        id: &str,
        record: &InstanceRecord,
        (now, notes): (u64, &[orbital_core::event::Note]),
        judge: impl FnOnce(Option<&OrganizationState>, u32) -> Result<(), E>,
    ) -> Result<(), E> {
        let body = self.encode(id, record)?;
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("적"))?;
        hold_organization(&mut transaction, &record.organization)?;
        let state = state_in(&mut transaction, &record.organization, false)?;
        let existing: i64 = transaction
            .query_one(
                "SELECT count(*) FROM orbital.instance WHERE organization = $1",
                &[&record.organization],
            )
            .map_err(pg("인스턴스를 세"))?
            .get(0);
        judge(state.as_ref(), u32::try_from(existing).unwrap_or(u32::MAX))?;
        transaction
            .execute(
                "INSERT INTO orbital.instance (id, organization, app, machine, body, created_at) VALUES ($1, $2, $3, $4, $5::text::jsonb, $6)",
                &[&id, &record.organization, &record.app, &record.machine, &body, &signed(now)],
            )
            .map_err(pg("적"))?;
        super::append_in(&mut transaction, &record.organization, now, notes)?;
        transaction.commit().map_err(pg("적"))?;
        Ok(())
    }
}
