//! 대시보드가 올라설 조회의 기록: 함대의 목록, release 의 이력, rollout 의 목록.
//!
//! 목록은 (만든 때, 식별자)의 차례로 SQL 에서 자르고(쪽의 판정은 core 의 `listing`), 질의는 언제나 조직으로 거른다. 다른 조직의 표식을 넣어도
//! 자기 조직의 그 자리 뒤가 나올 뿐이다. 함대의 한 줄은 인스턴스의 몸을 풀지 않고(봉인을 열지 않는다) 필요한 칸만 읽는다.
//!
//! 이력은 운영을 적는 트랜잭션에서 쌓는다([`append_history_in`]). 줄의 번호는 인스턴스마다 차례대로이고, 인스턴스의 줄을 잠근 트랜잭션에서 짓는다.

use orbital_core::event::Note;
use orbital_core::history::{Entry, KEEP, pruned_through};
use orbital_core::listing::{Cursor, Page};
use postgres::Transaction;
use serde::Serialize;
use serde_json::Value;

use super::{RecordError, Records, append_in, json as json_error, pg};
use crate::registry::RolloutRecord;

fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// 이력을 쌓는다. 부른 쪽의 트랜잭션 안에서, 인스턴스의 줄을 잠근 뒤에 부른다(번호가 겹치지 않는다).
/// 정한 수(`keep`)를 넘으면 같은 트랜잭션에서 오랜 것부터 걷는다.
pub(crate) fn append_history_in(
    transaction: &mut Transaction<'_>,
    instance: &str,
    now: u64,
    entries: &[Entry],
    keep: u64,
) -> Result<(), RecordError> {
    if entries.is_empty() {
        return Ok(());
    }
    let last: i64 = transaction
        .query_one(
            "SELECT coalesce(max(n), 0) FROM orbital.release_history WHERE instance = $1",
            &[&instance],
        )
        .map_err(pg("이력의 차례를 읽"))?
        .get(0);
    let mut newest = unsigned(last);
    for entry in entries {
        newest += 1;
        let body = serde_json::to_string(entry).map_err(json_error("이력을 적"))?;
        transaction
            .execute(
                "INSERT INTO orbital.release_history (instance, n, kind, at, body) VALUES ($1, $2, $3, $4, $5::text::jsonb)",
                &[&instance, &signed(newest), &entry.kind(), &signed(now), &body],
            )
            .map_err(pg("이력을 적"))?;
    }
    let through = pruned_through(newest, keep);
    if through > 0 {
        transaction
            .execute(
                "DELETE FROM orbital.release_history WHERE instance = $1 AND n <= $2",
                &[&instance, &signed(through)],
            )
            .map_err(pg("오랜 이력을 걷"))?;
    }
    Ok(())
}

/// 함대의 한 줄. 이름과 숫자만 있다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetRow {
    pub id: String,
    pub app: String,
    /// 갈라진 스캐폴드의 버전. 이 칸을 적기 전에 선 인스턴스는 `null` 이다.
    pub version: Option<String>,
    /// 놓인 기계.
    pub machine: String,
    pub created_at: Option<u64>,
    /// 운영에 오른 것. 아직 없으면 `null` 이다.
    pub production: Option<FleetProduction>,
    /// 사람의 승인을 기다리는 release.
    pub promotion_requested: Option<String>,
    /// 프리뷰의 database 가 기록에 있는가.
    pub preview: bool,
    /// 이력의 마지막 승격(올랐거나 되돌려졌다). 없으면 `null` 이다.
    pub last_promotion: Option<LastPromotion>,
    /// 이 줄의 쪽의 표식.
    #[serde(skip)]
    pub cursor: Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetProduction {
    pub release: String,
    /// 오른 때. 이 칸을 적기 전에 오른 운영은 `null` 이다.
    pub promoted_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastPromotion {
    pub release: String,
    pub at: u64,
    /// `promoted` · `rolled_back`.
    pub outcome: String,
}

const FLEET_SELECT: &str = "SELECT i.id, i.app, i.machine, i.created_at, coalesce(i.created_at, 0),
        i.body ->> 'version',
        i.body -> 'production' ->> 'release',
        (i.body -> 'production' ->> 'promoted_at')::bigint,
        i.body ->> 'promotion_requested',
        (i.body ->> 'preview') IS NOT NULL,
        h.kind, h.at, h.body ->> 'release'
    FROM orbital.instance i
    LEFT JOIN LATERAL (
        SELECT r.kind, r.at, r.body FROM orbital.release_history r
        WHERE r.instance = i.id AND r.kind IN ('promoted', 'rolled_back')
        ORDER BY r.n DESC LIMIT 1
    ) h ON true";

fn fleet_row(row: &postgres::Row) -> FleetRow {
    let id: String = row.get(0);
    let production = row
        .get::<_, Option<String>>(6)
        .map(|release| FleetProduction {
            release,
            promoted_at: row.get::<_, Option<i64>>(7).map(unsigned),
        });
    let last_promotion = match (
        row.get::<_, Option<String>>(10),
        row.get::<_, Option<i64>>(11),
        row.get::<_, Option<String>>(12),
    ) {
        (Some(outcome), Some(at), Some(release)) => Some(LastPromotion {
            release,
            at: unsigned(at),
            outcome,
        }),
        _ => None,
    };
    FleetRow {
        cursor: Cursor {
            created_at: unsigned(row.get(4)),
            id: id.clone(),
        },
        id,
        app: row.get(1),
        machine: row.get(2),
        created_at: row.get::<_, Option<i64>>(3).map(unsigned),
        version: row.get(5),
        production,
        promotion_requested: row.get(8),
        preview: row.get(9),
        last_promotion,
    }
}

/// 자른 쪽에서 뒤에 더 있는지를 가른다. 하나 더 읽어 본 것을 뗀다.
fn trimmed<T>(mut rows: Vec<T>, limit: u32) -> (Vec<T>, bool) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = rows.len() > limit;
    rows.truncate(limit);
    (rows, more)
}

/// 표식이 없으면 맨 앞(만든 때 0, 빈 식별자의 앞)부터다.
fn after_of(page: &Page) -> (i64, String) {
    page.after.as_ref().map_or((-1, String::new()), |cursor| {
        (signed(cursor.created_at), cursor.id.clone())
    })
}

/// 이력의 한 줄. 몸에 번호(`n`)와 때(`at`)를 더한 모양으로 내보낸다.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryRow {
    pub n: u64,
    pub at: u64,
    pub body: Value,
}

impl HistoryRow {
    /// 밖으로 나가는 모양(`{n, kind, at, …칸}`).
    pub fn envelope(&self) -> Value {
        let mut value = self.body.clone();
        if let Some(object) = value.as_object_mut() {
            object.insert("n".to_owned(), Value::from(self.n));
            object.insert("at".to_owned(), Value::from(self.at));
        }
        value
    }
}

impl Records {
    /// 조직의 인스턴스를 (만든 때, 식별자)의 차례로 한 쪽. 뒤에 더 있는지를 함께 돌려준다.
    pub fn fleet(
        &self,
        organization: &str,
        page: &Page,
    ) -> Result<(Vec<FleetRow>, bool), RecordError> {
        let (at, id) = after_of(page);
        let rows = self
            .client()?
            .query(
                &format!(
                    "{FLEET_SELECT}
                     WHERE i.organization = $1 AND (coalesce(i.created_at, 0), i.id) > ($2, $3)
                     ORDER BY coalesce(i.created_at, 0), i.id LIMIT $4"
                ),
                &[&organization, &at, &id, &(i64::from(page.limit) + 1)],
            )
            .map_err(pg("함대를 읽"))?;
        Ok(trimmed(rows.iter().map(fleet_row).collect(), page.limit))
    }

    /// 조직의 인스턴스 하나의 함대의 줄. 없거나 다른 조직의 것이면 `None` 이다.
    pub fn fleet_row(&self, organization: &str, id: &str) -> Result<Option<FleetRow>, RecordError> {
        Ok(self
            .client()?
            .query_opt(
                &format!("{FLEET_SELECT} WHERE i.organization = $1 AND i.id = $2"),
                &[&organization, &id],
            )
            .map_err(pg("함대를 읽"))?
            .as_ref()
            .map(fleet_row))
    }

    /// 인스턴스의 이력을 `after` 의 번호 뒤부터 차례대로. 뒤에 더 있는지를 함께 돌려준다.
    pub fn history(
        &self,
        instance: &str,
        after: u64,
        limit: u32,
    ) -> Result<(Vec<HistoryRow>, bool), RecordError> {
        let rows = self
            .client()?
            .query(
                "SELECT n, at, body::text FROM orbital.release_history WHERE instance = $1 AND n > $2 ORDER BY n LIMIT $3",
                &[&instance, &signed(after), &(i64::from(limit) + 1)],
            )
            .map_err(pg("이력을 읽"))?;
        let rows = rows
            .iter()
            .map(|row| {
                Ok(HistoryRow {
                    n: unsigned(row.get(0)),
                    at: unsigned(row.get(1)),
                    body: serde_json::from_str(&row.get::<_, String>(2))
                        .map_err(json_error("이력을 읽"))?,
                })
            })
            .collect::<Result<Vec<_>, RecordError>>()?;
        Ok(trimmed(rows, limit))
    }

    /// 되돌려진 승격의 이력과 이벤트를 한 트랜잭션에 쌓는다. 운영은 앞의 모습으로 돌렸으므로 인스턴스의 몸은 고치지 않는다.
    /// 인스턴스의 줄을 잠가 이력의 번호가 겹치지 않게 한다. 인스턴스가 그사이 지워졌으면 이벤트만 쌓는다.
    pub fn note_rolled_back(
        &self,
        organization: &str,
        instance: &str,
        now: u64,
        notes: &[Note],
        entry: &Entry,
    ) -> Result<(), RecordError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("이력을 적"))?;
        let present = transaction
            .query_opt(
                "SELECT 1 FROM orbital.instance WHERE id = $1 FOR UPDATE",
                &[&instance],
            )
            .map_err(pg("이력을 적으려고 읽"))?
            .is_some();
        if present {
            append_history_in(
                &mut transaction,
                instance,
                now,
                std::slice::from_ref(entry),
                KEEP,
            )?;
        }
        append_in(&mut transaction, organization, now, notes)?;
        transaction.commit().map_err(pg("이력을 적"))
    }

    /// 조직의 rollout 을 (만든 때, 식별자)의 차례로 한 쪽.
    pub fn rollout_page(
        &self,
        organization: &str,
        page: &Page,
    ) -> Result<(Vec<(Cursor, RolloutRecord)>, bool), RecordError> {
        let (at, id) = after_of(page);
        let rows = self
            .client()?
            .query(
                "SELECT id, coalesce(created_at, 0), body::text FROM orbital.rollout
                 WHERE organization = $1 AND (coalesce(created_at, 0), id) > ($2, $3)
                 ORDER BY coalesce(created_at, 0), id LIMIT $4",
                &[&organization, &at, &id, &(i64::from(page.limit) + 1)],
            )
            .map_err(pg("rollout 을 읽"))?;
        let rows = rows
            .iter()
            .map(|row| {
                let record: RolloutRecord = serde_json::from_str(&row.get::<_, String>(2))
                    .map_err(json_error("rollout 을 읽"))?;
                Ok((
                    Cursor {
                        created_at: unsigned(row.get(1)),
                        id: row.get(0),
                    },
                    record,
                ))
            })
            .collect::<Result<Vec<_>, RecordError>>()?;
        Ok(trimmed(rows, page.limit))
    }
}
