//! 이벤트와 웹훅의 기록.
//!
//! **쌓기.** 이벤트는 그 일을 적는 트랜잭션 안에서 쌓는다([`append_in`]). 한 조직의 이벤트는 그 조직의 advisory lock(트랜잭션 동안)을
//! 쥐고 쌓아, 조직 안에서는 id 의 차례가 commit 의 차례와 같다. 그래서 「`after` 뒤의 것」을 읽는 쪽이 나중에 앞의 id 가 끼어드는 것을 보지 않는다.
//!
//! **보내기.** 보낼 것이 있는 웹훅의 줄 하나를 `FOR UPDATE SKIP LOCKED` 로 잠그고, 그 조직의 다음 이벤트 하나를 보낸 뒤 결과를 적고 commit 한다.
//! 다른 관리 서버는 잠긴 줄을 건너뛰므로 같은 이벤트를 둘이 함께 보내지 않고, 앞의 이벤트가 끝나기(보냈거나 그만뒀다) 전에는 뒤의 것을 보내지 않는다.
//! 보낸 뒤 commit 하기 전에 관리 서버가 죽으면 잠금이 풀려 다른 관리 서버가 같은 이벤트를 다시 보낸다(적어도 한 번).

use orbital_core::event::{Note, Page, Retry, after_failure};
use postgres::Transaction;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{RecordError, Records, json as json_error, pg, signed};
use crate::seal::{Rekeyed, SealKey, open, reseal, seal, webhook_binding};

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// 조직마다 이벤트를 쌓는 차례(advisory lock)의 번호.
fn event_lock(organization: &str) -> i64 {
    let digest = Sha256::digest(format!("orbital/events\n{organization}").as_bytes());
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(head)
}

/// 이벤트를 쌓는다. 부른 쪽의 트랜잭션 안에서 쌓아, 그 일이 commit 될 때만 함께 남는다.
pub(crate) fn append_in(
    transaction: &mut Transaction<'_>,
    organization: &str,
    now: u64,
    notes: &[Note],
) -> Result<(), RecordError> {
    if notes.is_empty() {
        return Ok(());
    }
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&event_lock(organization)],
        )
        .map_err(pg("이벤트의 차례를 잡"))?;
    for note in notes {
        let whole = serde_json::to_value(&note.body).map_err(json_error("이벤트를 적"))?;
        let kind = note.body.kind();
        let data = whole.get("data").cloned().unwrap_or_else(|| json!({}));
        let data = data.to_string();
        let instance = note.instance.as_ref().map(|instance| instance.as_str());
        transaction
            .execute(
                "INSERT INTO orbital.event (organization, type, instance, data, created_at) VALUES ($1, $2, $3, $4::text::jsonb, $5)",
                &[&organization, &kind, &instance, &data, &signed(now)],
            )
            .map_err(pg("이벤트를 적"))?;
    }
    Ok(())
}

/// 쌓인 이벤트 하나.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    pub id: u64,
    pub kind: String,
    pub organization: String,
    pub instance: Option<String>,
    pub data: Value,
    pub created_at: u64,
}

impl EventRow {
    /// 밖으로 나가는 모양(`{id, type, created_at, organization, instance?, data}`). 목록과 웹훅의 본문이 같다.
    pub fn envelope(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "type": self.kind,
            "created_at": self.created_at,
            "organization": self.organization,
            "data": self.data,
        });
        if let Some(instance) = &self.instance {
            value["instance"] = json!(instance);
        }
        value
    }
}

const EVENT_COLUMNS: &str = "id, type, organization, instance, data::text, created_at";

fn event_row(row: &postgres::Row) -> Result<EventRow, RecordError> {
    let data: String = row.get(4);
    Ok(EventRow {
        id: unsigned(row.get(0)),
        kind: row.get(1),
        organization: row.get(2),
        instance: row.get(3),
        data: serde_json::from_str(&data).map_err(json_error("이벤트를 읽"))?,
        created_at: unsigned(row.get(5)),
    })
}

/// 보내지 못한 갈래. 이름만 적는다(받은 답의 본문 · Postgres 와 TLS 의 글은 적지 않는다).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Miss {
    /// 호스트가 바깥이 아닌 주소로 풀렸다. 붙지 않았다.
    RefusedAddress,
    /// 호스트를 풀지 못했다.
    Unresolved,
    /// 연결하지 못했거나 TLS 가 맞지 않았다.
    Unreachable,
    /// 정한 시간 안에 답이 없었다.
    TimedOut,
    /// 2xx 가 아닌 답(3xx 도. 리다이렉트는 따라가지 않는다).
    Status,
    /// 서명의 비밀이 풀리지 않았다(봉인의 열쇠가 바뀌었다). 보내지 않았다.
    Unsealed,
}

impl Miss {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RefusedAddress => "refused_address",
            Self::Unresolved => "unresolved",
            Self::Unreachable => "unreachable",
            Self::TimedOut => "timed_out",
            Self::Status => "status",
            Self::Unsealed => "unsealed",
        }
    }
}

/// 한 번 보낸 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    pub status: Option<u16>,
    pub miss: Option<Miss>,
}

/// 보낼 것. 서명의 비밀은 풀린 것이고, 풀리지 않았으면 `None` 이다.
pub struct Head {
    pub url: String,
    pub secret: Option<String>,
    pub event: EventRow,
}

/// 이벤트 하나를 보내 본 뒤의 모습.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    Sent,
    Retrying,
    /// 하루 동안 보내지 못해 그만뒀다.
    Abandoned,
}

/// 조직의 웹훅. 서명의 비밀은 싣지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebhookRow {
    pub url: String,
    pub created_at: u64,
    pub delivery: DeliveryRow,
}

/// 전달의 모습. 숫자와 갈래만 있다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryRow {
    /// 이 id 까지는 보냈거나 그만뒀다.
    pub delivered_through: u64,
    /// 아직 보내지 않은 이벤트의 수.
    pub pending: u64,
    /// 다음에 보낼 때. 보낼 것이 없으면 `null` 이다.
    pub next_at: Option<u64>,
    /// 지금 보내는 이벤트를 보내지 못한 횟수.
    pub failures: u32,
    pub last_attempt_at: Option<u64>,
    pub last_status: Option<u16>,
    pub last_error: Option<String>,
    /// 마지막으로 보낸(2xx 를 받은) 때.
    pub delivered_at: Option<u64>,
    /// 하루 동안 보내지 못해 그만둔 이벤트의 수와 마지막 것의 id.
    pub abandoned: u64,
    pub last_abandoned: Option<u64>,
}

impl Records {
    /// 이벤트를 따로 쌓는다. 그 일을 적는 트랜잭션에 넣을 수 없는 자리(되돌려진 승격)만 쓴다.
    pub fn append_events(
        &self,
        organization: &str,
        now: u64,
        notes: &[Note],
    ) -> Result<(), RecordError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("이벤트를 적"))?;
        append_in(&mut transaction, organization, now, notes)?;
        transaction.commit().map_err(pg("이벤트를 적"))
    }

    /// 조직의 이벤트를 `after` 뒤부터 차례대로. 뒤에 더 있는지를 함께 돌려준다.
    pub fn events(
        &self,
        organization: &str,
        page: Page,
    ) -> Result<(Vec<EventRow>, bool), RecordError> {
        let rows = self
            .client()?
            .query(
                &format!(
                    "SELECT {EVENT_COLUMNS} FROM orbital.event WHERE organization = $1 AND id > $2 ORDER BY id LIMIT $3"
                ),
                &[
                    &organization,
                    &signed(page.after),
                    &(i64::from(page.limit) + 1),
                ],
            )
            .map_err(pg("이벤트를 읽"))?;
        let mut events = rows.iter().map(event_row).collect::<Result<Vec<_>, _>>()?;
        let more = events.len() > usize::try_from(page.limit).unwrap_or(usize::MAX);
        events.truncate(usize::try_from(page.limit).unwrap_or(usize::MAX));
        Ok((events, more))
    }

    /// 보관 기간이 지난 이벤트를 걷는다. 걷은 수를 돌려준다.
    pub fn sweep_events(&self, before: u64) -> Result<u64, RecordError> {
        self.client()?
            .execute(
                "DELETE FROM orbital.event WHERE created_at < $1",
                &[&signed(before)],
            )
            .map_err(pg("지난 이벤트를 걷"))
    }

    /// 조직의 웹훅. 걸지 않았으면 `None` 이다.
    pub fn webhook(&self, organization: &str) -> Result<Option<WebhookRow>, RecordError> {
        let row = self
            .client()?
            .query_opt(
                "SELECT w.url, w.created_at, w.delivered, w.next_at, w.failures, w.last_attempt_at, w.last_status,
                        w.last_error, w.delivered_at, w.abandoned, w.last_abandoned,
                        (SELECT count(*) FROM orbital.event e WHERE e.organization = w.organization AND e.id > w.delivered)
                 FROM orbital.webhook w WHERE w.organization = $1",
                &[&organization],
            )
            .map_err(pg("웹훅을 읽"))?;
        Ok(row.map(|row| {
            let pending = unsigned(row.get(11));
            WebhookRow {
                url: row.get(0),
                created_at: unsigned(row.get(1)),
                delivery: DeliveryRow {
                    delivered_through: unsigned(row.get(2)),
                    pending,
                    next_at: (pending > 0).then(|| unsigned(row.get(3))),
                    failures: u32::try_from(row.get::<_, i32>(4)).unwrap_or(0),
                    last_attempt_at: row.get::<_, Option<i64>>(5).map(unsigned),
                    last_status: row
                        .get::<_, Option<i32>>(6)
                        .and_then(|status| u16::try_from(status).ok()),
                    last_error: row.get(7),
                    delivered_at: row.get::<_, Option<i64>>(8).map(unsigned),
                    abandoned: unsigned(row.get(9)),
                    last_abandoned: row.get::<_, Option<i64>>(10).map(unsigned),
                },
            }
        }))
    }

    /// 웹훅을 건다. 서명의 비밀은 조직에 묶어 봉인해 적는다. 이미 걸었으면 주소와 비밀을 바꾸고 보낸 자리는 그대로 둔다
    /// (밀린 것은 새 주소로 새 비밀의 서명과 함께 간다). 처음 걸면 그때까지 쌓인 것은 보내지 않는다(목록으로 받는다).
    pub fn set_webhook(
        &self,
        organization: &str,
        url: &str,
        secret: &str,
        now: u64,
    ) -> Result<(), RecordError> {
        let key = self.seal.as_ref().ok_or_else(|| {
            RecordError("봉인의 열쇠가 없어 웹훅의 비밀을 적지 못했습니다".to_owned())
        })?;
        let sealed = seal(key, &webhook_binding(organization), secret)
            .ok_or_else(|| RecordError("난수를 읽지 못해 봉인하지 못했습니다".to_owned()))?;
        self.client()?
            .execute(
                "INSERT INTO orbital.webhook (organization, url, secret, created_at, delivered, next_at)
                 VALUES ($1, $2, $3, $4, (SELECT coalesce(max(id), 0) FROM orbital.event WHERE organization = $1), $4)
                 ON CONFLICT (organization) DO UPDATE SET url = excluded.url, secret = excluded.secret,
                     created_at = excluded.created_at, next_at = excluded.next_at, failures = 0, failing_since = NULL",
                &[&organization, &url, &sealed, &signed(now)],
            )
            .map_err(pg("웹훅을 적"))?;
        Ok(())
    }

    /// 웹훅을 뗀다. 있었으면 참이다.
    pub fn remove_webhook(&self, organization: &str) -> Result<bool, RecordError> {
        Ok(self
            .client()?
            .execute(
                "DELETE FROM orbital.webhook WHERE organization = $1",
                &[&organization],
            )
            .map_err(pg("웹훅을 지우"))?
            > 0)
    }

    /// 보낼 때가 된 웹훅 하나를 잠그고 그 조직의 다음 이벤트 하나를 `send` 로 보낸 뒤 결과를 적는다. 보낼 것이 없거나
    /// 다른 관리 서버가 모두 쥐고 있으면 `None` 이다. 줄은 보내는 동안 잠겨 있어 다른 관리 서버는 건너뛴다.
    pub fn deliver_one(
        &self,
        now: u64,
        send: impl FnOnce(&Head) -> Attempt,
    ) -> Result<Option<Delivered>, RecordError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("보낼 웹훅을 잡"))?;
        let Some(row) = transaction
            .query_opt(
                "SELECT w.organization, w.url, w.secret, w.delivered, w.failures, w.failing_since
                 FROM orbital.webhook w
                 WHERE w.next_at <= $1
                   AND EXISTS (SELECT 1 FROM orbital.event e WHERE e.organization = w.organization AND e.id > w.delivered)
                 ORDER BY w.next_at
                 LIMIT 1
                 FOR UPDATE OF w SKIP LOCKED",
                &[&signed(now)],
            )
            .map_err(pg("보낼 웹훅을 잡"))?
        else {
            return Ok(None);
        };
        let (organization, url, sealed): (String, String, String) =
            (row.get(0), row.get(1), row.get(2));
        let delivered: i64 = row.get(3);
        let failures = u32::try_from(row.get::<_, i32>(4)).unwrap_or(0);
        let failing_since: Option<i64> = row.get(5);
        let event = transaction
            .query_one(
                &format!(
                    "SELECT {EVENT_COLUMNS} FROM orbital.event WHERE organization = $1 AND id > $2 ORDER BY id LIMIT 1"
                ),
                &[&organization, &delivered],
            )
            .map_err(pg("보낼 이벤트를 읽"))?;
        let event = event_row(&event)?;
        let secret = self
            .seal
            .as_ref()
            .and_then(|key| open(key, &webhook_binding(&organization), &sealed));
        let id = signed(event.id);
        let head = Head { url, secret, event };
        let attempt = if head.secret.is_some() {
            send(&head)
        } else {
            Attempt {
                status: None,
                miss: Some(Miss::Unsealed),
            }
        };
        let status = attempt.status.map(i32::from);
        let error = attempt.miss.map(Miss::as_str);
        let now_signed = signed(now);
        let outcome = if attempt.miss.is_none() {
            transaction
                .execute(
                    "UPDATE orbital.webhook SET delivered = $2, next_at = $3, failures = 0, failing_since = NULL,
                         last_attempt_at = $3, last_status = $4, last_error = NULL, delivered_at = $3
                     WHERE organization = $1",
                    &[&organization, &id, &now_signed, &status],
                )
                .map_err(pg("보낸 것을 적"))?;
            Delivered::Sent
        } else {
            let failures = failures.saturating_add(1);
            let since = failing_since.map_or(now, unsigned);
            match after_failure(failures, since, now) {
                Retry::At(next_at) => {
                    transaction
                        .execute(
                            "UPDATE orbital.webhook SET next_at = $2, failures = $3, failing_since = $4,
                                 last_attempt_at = $5, last_status = $6, last_error = $7
                             WHERE organization = $1",
                            &[
                                &organization,
                                &signed(next_at),
                                &i32::try_from(failures).unwrap_or(i32::MAX),
                                &signed(since),
                                &now_signed,
                                &status,
                                &error,
                            ],
                        )
                        .map_err(pg("보내지 못한 것을 적"))?;
                    Delivered::Retrying
                }
                Retry::GiveUp => {
                    transaction
                        .execute(
                            "UPDATE orbital.webhook SET delivered = $2, next_at = $3, failures = 0, failing_since = NULL,
                                 last_attempt_at = $3, last_status = $4, last_error = $5,
                                 abandoned = abandoned + 1, last_abandoned = $2
                             WHERE organization = $1",
                            &[&organization, &id, &now_signed, &status, &error],
                        )
                        .map_err(pg("그만둔 것을 적"))?;
                    Delivered::Abandoned
                }
            }
        };
        transaction.commit().map_err(pg("보낸 결과를 적"))?;
        Ok(Some(outcome))
    }

    /// 웹훅의 서명 비밀을 새 열쇠로 다시 봉인한다. (바꾼 줄의 수, 어느 열쇠로도 풀리지 않는 줄의 이름).
    pub fn reseal_webhooks(&self, previous: &SealKey) -> Result<(usize, Vec<String>), RecordError> {
        let Some(key) = &self.seal else {
            return Ok((0, Vec::new()));
        };
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("웹훅을 다시 봉인하"))?;
        let rows = transaction
            .query(
                "SELECT organization, secret FROM orbital.webhook FOR UPDATE",
                &[],
            )
            .map_err(pg("웹훅을 다시 봉인하려고 읽"))?;
        let (mut changed, mut unopened) = (0, Vec::new());
        for row in rows {
            let (organization, sealed): (String, String) = (row.get(0), row.get(1));
            match reseal(key, previous, &webhook_binding(&organization), &sealed)
                .ok_or_else(|| RecordError("난수를 읽지 못해 봉인하지 못했습니다".to_owned()))?
            {
                Rekeyed::Current => {}
                Rekeyed::Changed(again) => {
                    transaction
                        .execute(
                            "UPDATE orbital.webhook SET secret = $2 WHERE organization = $1",
                            &[&organization, &again],
                        )
                        .map_err(pg("웹훅을 다시 봉인해 적"))?;
                    changed += 1;
                }
                Rekeyed::Unopened => unopened.push(format!("webhook {organization}")),
            }
        }
        transaction.commit().map_err(pg("웹훅을 다시 봉인해 적"))?;
        Ok((changed, unopened))
    }
}
