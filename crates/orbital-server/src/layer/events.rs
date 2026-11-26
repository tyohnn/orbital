//! 이벤트를 물어보는 길과 웹훅. 기록에만 닿으므로 어느 관리 서버든 한다(`Errand::Events`).
//!
//! 웹훅은 조직마다 주소 하나다. 걸 때 레이어가 서명의 비밀을 만들어 그 답에 한 번만 싣고, 기록에는 조직에 묶어 봉인한 글로 둔다.
//! 봉인의 열쇠가 없는 레이어에서는 걸지 못한다(409). 보내는 일은 [`Layer::deliver_due`] 가 하고, 관리 서버는 뒤의 스레드에서 1초마다 부른다.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use orbital_core::event::{Note, RETENTION, page};
use orbital_core::webhook::{AddressRefusal, Allow, UrlProblem, judge_url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Failure, Layer, LayerCore, Outcome, random};
use crate::records::{Attempt, Delivered, Miss, WebhookRow};
use crate::token::hex;
use crate::webhook::{Resolve, Sending, resolve_judged, send, signature};

/// 한 번 부를 때 보내는 이벤트의 상한. 남은 것은 다음 부름이 보낸다.
const SEND_LIMIT: usize = 100;
/// 뒤에서 보내는 스레드의 수. 한 번에 이만큼의 조직에 함께 보낸다(스레드마다 보내는 동안 기록의 연결 하나를 쥔다).
const DELIVERY_WORKERS: usize = 4;
/// 지난 이벤트를 걷는 간격(초).
const SWEEP_EVERY: u64 = 60 * 60;

/// 웹훅을 보내는 설정.
pub(super) struct Webhooks {
    pub(super) allow: Allow,
    pub(super) resolver: Arc<dyn Resolve>,
    pub(super) timeout: Duration,
    /// 마지막으로 지난 이벤트를 걷은 때(레이어의 시계).
    pub(super) swept_at: Mutex<Option<u64>>,
}

/// 한 번 보낸 결과의 수.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DeliveryReport {
    pub sent: usize,
    pub retrying: usize,
    pub abandoned: usize,
}

/// 웹훅을 거는 요청.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewWebhook {
    url: String,
}

fn refusal_text(refusal: AddressRefusal) -> &'static str {
    match refusal {
        AddressRefusal::Unspecified => "`0.0.0.0/8` 이나 `::` 같은 지정되지 않은 주소",
        AddressRefusal::Loopback => "loopback 주소",
        AddressRefusal::Private => "사설 주소",
        AddressRefusal::SharedAddressSpace => "CGNAT(`100.64.0.0/10`) 주소",
        AddressRefusal::LinkLocal => "link-local 주소(클라우드의 메타데이터 주소를 포함)",
        AddressRefusal::Multicast => "멀티캐스트 주소",
        AddressRefusal::Broadcast => "브로드캐스트 주소",
        AddressRefusal::Documentation => "문서용 주소",
        AddressRefusal::Benchmarking => "장비 시험용 주소",
        AddressRefusal::Reserved => "남겨 둔 주소",
        AddressRefusal::Embedded => "IPv4 를 품은 IPv6 주소",
        AddressRefusal::UniqueLocal => "ULA(`fc00::/7`) 주소",
        AddressRefusal::NotGlobal => "전역 유니캐스트가 아닌 IPv6 주소",
    }
}

fn url_problem_text(problem: UrlProblem) -> String {
    match problem {
        UrlProblem::Scheme { http_allowed: false } => {
            "웹훅의 주소는 `https://` 로 시작해야 합니다".to_owned()
        }
        UrlProblem::Scheme { http_allowed: true } => {
            "웹훅의 주소는 `https://` 나 `http://` 로 시작해야 합니다".to_owned()
        }
        UrlProblem::Credentials => {
            "웹훅의 주소에 사용자 이름이나 비밀번호(`…@`)를 적지 않습니다. 받는 쪽은 서명(`orbital-signature`)으로 레이어를 확인해 주세요".to_owned()
        }
        UrlProblem::Fragment => "웹훅의 주소에 조각(`#…`)을 적지 않습니다".to_owned(),
        UrlProblem::Host => {
            "웹훅의 주소의 호스트를 DNS 의 이름(유니코드는 punycode)이나 IP 로 적어 주세요. 숫자뿐인 이름은 받지 않습니다".to_owned()
        }
        UrlProblem::Port => "포트는 1 에서 65535 사이의 수로 적어 주세요".to_owned(),
        UrlProblem::TooLong { max } => format!("웹훅의 주소는 {max}자 안으로 줄여 주세요"),
        UrlProblem::Characters => "웹훅의 주소에 빈칸이나 제어 문자를 넣지 않습니다".to_owned(),
        UrlProblem::Address { refusal } => format!(
            "웹훅의 주소가 {}입니다. 레이어는 바깥(공인)의 주소로만 보냅니다",
            refusal_text(refusal)
        ),
    }
}

impl Layer {
    /// 이 조직의 이벤트를 `after` 뒤부터 차례대로(`?after=<id>&limit=<n>`).
    pub fn list_events(&self, organization: &str, query: &str) -> Outcome<Value> {
        let after = orbital_core::auth::query_value(query, "after");
        let limit = orbital_core::auth::query_value(query, "limit");
        let page = page(after.as_deref(), limit.as_deref()).map_err(|problems| {
            Failure::Problems(
                problems
                    .iter()
                    .map(|problem| match problem {
                        orbital_core::event::PageProblem::After => {
                            "`after` 는 앞에서 받은 마지막 이벤트의 id(0 이상의 정수)로 적어 주세요"
                                .to_owned()
                        }
                        orbital_core::event::PageProblem::Limit { max } => {
                            format!("`limit` 은 1 에서 {max} 사이의 정수로 적어 주세요")
                        }
                    })
                    .collect(),
            )
        })?;
        let (events, more) = self.records.events(organization, page)?;
        let next = events.last().map_or(page.after, |event| event.id);
        Ok(json!({
            "events": events.iter().map(crate::records::EventRow::envelope).collect::<Vec<_>>(),
            "next": next,
            "has_more": more,
        }))
    }

    /// 이 조직의 웹훅. 걸지 않았으면 `null` 이다. 서명의 비밀은 싣지 않는다.
    pub fn webhook(&self, organization: &str) -> Outcome<Option<WebhookRow>> {
        Ok(self.records.webhook(organization)?)
    }

    /// 웹훅을 건다(`{url}`). 서명의 비밀을 새로 만들어 이 답에만 싣는다. 이미 걸었으면 주소와 비밀을 바꾼다.
    pub fn set_webhook(&self, organization: &str, body: &[u8]) -> Outcome<(WebhookRow, String)> {
        let request: NewWebhook = serde_json::from_slice(body).map_err(|_| {
            Failure::Problems(vec![
                "본문은 `{ \"url\": \"https://…\" }` 모양이어야 합니다".to_owned(),
            ])
        })?;
        if !self.records.sealing() {
            return Err(Failure::Conflict(
                "레이어에 봉인의 열쇠가 없어 웹훅을 걸지 못합니다. 레이어의 운영자가 `ORBITAL_SEAL_KEY` 를 넣고 다시 띄워야 합니다".to_owned(),
            ));
        }
        let target = judge_url(&request.url, self.webhooks.allow).map_err(|problems| {
            Failure::Problems(problems.into_iter().map(url_problem_text).collect())
        })?;
        // 걸 때도 풀어 본다. 무엇으로 풀렸는지는 알리지 않는다(레이어 안쪽의 이름을 알아내는 길이 되지 않게)
        resolve_judged(self.webhooks.resolver.as_ref(), &target, self.webhooks.allow).map_err(
            |_| {
                Failure::Problems(vec![
                    "웹훅의 주소의 호스트가 바깥(공인)의 주소로만 풀려야 합니다. 풀리지 않거나 사설 · loopback · link-local 같은 안쪽의 주소로 풀리는 호스트로는 보내지 않습니다".to_owned(),
                ])
            },
        )?;
        let secret = format!("whsec_{}", hex(&random(32)?));
        self.records
            .set_webhook(organization, &request.url, &secret, (self.clock)())?;
        let row = self
            .records
            .webhook(organization)?
            .ok_or_else(|| Failure::Internal("건 웹훅을 읽지 못했습니다".to_owned()))?;
        Ok((row, secret))
    }

    /// 웹훅을 뗀다. 있었으면 참이다. 쌓인 이벤트는 그대로 남아 목록으로 받는다.
    pub fn remove_webhook(&self, organization: &str) -> Outcome<bool> {
        Ok(self.records.remove_webhook(organization)?)
    }

    /// 보낼 때가 된 이벤트를 보낸다. 조직마다 차례대로 하나씩이고, 앞의 것이 끝나기 전에는 뒤의 것을 보내지 않는다.
    /// 관리 서버가 여럿이어도 같은 이벤트는 하나만 보낸다(웹훅의 줄을 잠근다). 테스트는 시계를 갈아 끼우고 이것을 바로 부른다.
    /// 보관 기간이 지난 이벤트도 여기서 한 시간에 한 번 걷는다.
    pub fn deliver_due(&self) -> DeliveryReport {
        let now = (self.clock)();
        self.sweep_events(now);
        let mut report = DeliveryReport::default();
        for _ in 0..SEND_LIMIT {
            let delivered = self
                .records
                .deliver_one(now, |head| self.send_one(head, now));
            match delivered {
                Ok(Some(Delivered::Sent)) => report.sent += 1,
                Ok(Some(Delivered::Retrying)) => report.retrying += 1,
                Ok(Some(Delivered::Abandoned)) => report.abandoned += 1,
                // 보낼 것이 없거나, 기록을 읽지 못했다(다음 부름에 다시 본다)
                Ok(None) | Err(_) => break,
            }
        }
        report
    }

    fn sweep_events(&self, now: u64) {
        let mut swept = self
            .webhooks
            .swept_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if swept.is_some_and(|at| now < at.saturating_add(SWEEP_EVERY)) {
            return;
        }
        if self
            .records
            .sweep_events(now.saturating_sub(RETENTION))
            .is_ok()
        {
            *swept = Some(now);
        }
    }

    fn send_one(&self, head: &crate::records::Head, now: u64) -> Attempt {
        let Some(secret) = &head.secret else {
            return Attempt {
                status: None,
                miss: Some(Miss::Unsealed),
            };
        };
        // 건 뒤에 레이어의 설정이 바뀌었을 수 있다. 주소의 글도 보낼 때마다 다시 판정한다
        let Ok(target) = judge_url(&head.url, self.webhooks.allow) else {
            return Attempt {
                status: None,
                miss: Some(Miss::RefusedAddress),
            };
        };
        let body = head.event.envelope().to_string();
        let signed = signature(secret, now, body.as_bytes());
        send(&Sending {
            url: &head.url,
            target: &target,
            allow: self.webhooks.allow,
            resolver: Arc::clone(&self.webhooks.resolver),
            timeout: self.webhooks.timeout,
            body: body.as_bytes(),
            signature: &signed,
            event_id: head.event.id,
            event_type: &head.event.kind,
        })
    }

    /// 이벤트를 쌓는다. 그 일을 적는 트랜잭션 밖에서 쌓는 자리만 쓴다. 쌓지 못하면 알리기만 하고 일을 되돌리지 않는다.
    pub(super) fn note_after(&self, organization: &str, notes: &[Note]) {
        if self
            .records
            .append_events(organization, (self.clock)(), notes)
            .is_err()
        {
            eprintln!("orbitald: 이벤트를 쌓지 못했습니다. 그 일은 됐고 이벤트만 빠졌습니다");
        }
    }

    /// 뒤의 스레드에서 `every` 마다 보낸다. 레이어가 내려가면 멈춘다(레이어를 쥐는 것은 보내는 동안뿐이다).
    pub(super) fn deliver_in_background(&self, every: Duration) {
        // 보내는 스레드를 여럿 둔다. 웹훅마다 줄을 잠그고 보내므로(`SKIP LOCKED`) 서로 다른 조직의 것을 함께 보내고,
        // 느리게 답하는 받는 쪽 하나가 다른 조직의 전달을 붙들지 못한다
        for worker in 0..DELIVERY_WORKERS {
            self.deliver_in_worker(every, worker);
        }
    }

    fn deliver_in_worker(&self, every: Duration, worker: usize) {
        let weak = Arc::downgrade(&self.0);
        let _ = std::thread::Builder::new()
            .name(format!("orbital-webhooks-{worker}"))
            .spawn(move || {
                loop {
                    // 기다리는 동안 레이어가 내려가면 바로 멈춘다
                    let mut waited = Duration::ZERO;
                    while waited < every {
                        let step = Duration::from_millis(100).min(every - waited);
                        std::thread::sleep(step);
                        waited += step;
                        if weak.strong_count() == 0 {
                            return;
                        }
                    }
                    let Some(core) = weak.upgrade() else {
                        return;
                    };
                    let layer = Layer(core);
                    let _ = layer.deliver_due();
                    drop(layer);
                }
            });
    }
}

impl LayerCore {
    /// 웹훅의 설정이 개발용(사설 주소와 `http://` 를 받는다)인가.
    pub fn dev_webhooks(&self) -> bool {
        self.webhooks.allow == Allow::Development
    }
}
