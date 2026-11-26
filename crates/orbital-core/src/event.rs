//! 이벤트. 레이어의 상태가 바뀐 것(승격의 요청 · 승격 · 되돌려진 승격 · rollout 의 진행 · 비밀의 요청 · 인스턴스의 생김과 지워짐)을
//! 조직마다 차례대로 쌓아, 팩토리가 묻지 않아도 알게 한다. 쌓는 일과 보내는 일은 관리 서버가 하고, 여기서는 무엇을 쌓을지와
//! 언제 다시 보낼지를 정한다.
//!
//! **몸에는 이름과 숫자만 싣는다.** 몸의 칸은 [`Body`] 의 갈래마다 타입으로 정해 두어, 비밀의 값 · 운영 데이터의 행 · 로그의 글 ·
//! 토큰 · 열쇠 · Postgres 의 오류 문구가 들어갈 칸이 없다. 에이전트가 적은 글(비밀을 요청한 까닭)도 싣지 않는다.

use serde::Serialize;

use crate::name::InstanceId;
use crate::release::{Approver, Change};
use crate::rollout::{FailReason, Progress, Rollout, Status};

/// 이벤트를 두는 기간(30일). 지난 것은 걷는다. 그때까지 보내지 못한 것도 함께 걷힌다.
pub const RETENTION: u64 = 30 * 24 * 60 * 60;
/// 목록 한 번에 돌려주는 수의 기본값과 상한.
pub const LIST_DEFAULT: u32 = 100;
pub const LIST_MAX: u32 = 500;
/// 보내지 못했을 때 다시 보내기까지 기다리는 시간(초). 실패가 이보다 많으면 마지막 것을 되풀이한다.
pub const RETRY_DELAYS: [u64; 5] = [30, 2 * 60, 10 * 60, 60 * 60, 6 * 60 * 60];
/// 한 이벤트를 처음 보내지 못한 때에서 이만큼이 지나면 그 이벤트는 그만 보낸다(하루).
pub const GIVE_UP_AFTER: u64 = 24 * 60 * 60;

/// rollout 의 인스턴스가 어디에 몇이 있는가. 숫자만 있다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub waiting: u32,
    pub applied: u32,
    pub previewed: u32,
    pub passed: u32,
    pub promoted: u32,
    pub failed: u32,
}

impl Tally {
    pub fn of(rollout: &Rollout) -> Self {
        let mut tally = Self::default();
        for state in rollout.progress.values() {
            let slot = match state {
                Progress::Waiting => &mut tally.waiting,
                Progress::Applied => &mut tally.applied,
                Progress::Previewed => &mut tally.previewed,
                Progress::Passed => &mut tally.passed,
                Progress::Promoted => &mut tally.promoted,
                Progress::Failed { .. } => &mut tally.failed,
            };
            *slot = slot.saturating_add(1);
        }
        tally
    }
}

/// 이벤트의 종류와 몸. JSON 으로는 `{ "type": "<종류>", "data": { … } }` 이다. 종류의 이름은 `무엇.어찌됨` 이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Body {
    /// 에이전트가 release 하나의 승격을 요청했다. 사람의 승인을 기다린다.
    #[serde(rename = "promotion.requested")]
    PromotionRequested { release: String, commit: String },
    /// release 가 운영에 올랐다.
    #[serde(rename = "promotion.succeeded")]
    PromotionSucceeded {
        release: String,
        commit: String,
        previous_release: Option<String>,
        change: Change,
        approved_by: Approver,
        /// 이번에 돈 마이그레이션의 수.
        migrations: u32,
        /// 이 release 가 담은 업데이트의 rollout. 없으면 `null` 이다.
        rollout: Option<String>,
    },
    /// 올리다가 깨져 앞의 모습으로 되돌렸다(되돌리지 못했으면 운영이 내려가 있다. 그 모습은 운영의 길이 답한다).
    #[serde(rename = "promotion.failed")]
    PromotionFailed {
        release: String,
        commit: String,
        previous_release: Option<String>,
        /// 마이그레이션이 돈 뒤에 깨졌는가.
        migrated: bool,
        rollout: Option<String>,
    },
    /// rollout 의 인스턴스 하나가 다음 자리로 갔다(실패와, 다시 열어 처음으로 돌아간 것도).
    #[serde(rename = "rollout.advanced")]
    RolloutAdvanced {
        rollout: String,
        app: String,
        update: String,
        instance: InstanceId,
        progress: Progress,
        tally: Tally,
    },
    /// 인스턴스가 실패해 rollout 이 멈췄다.
    #[serde(rename = "rollout.halted")]
    RolloutHalted {
        rollout: String,
        app: String,
        update: String,
        failed: Vec<Failed>,
        tally: Tally,
    },
    /// 팩토리가 멈춘 rollout 을 다시 열었다.
    #[serde(rename = "rollout.resumed")]
    RolloutResumed {
        rollout: String,
        app: String,
        update: String,
        tally: Tally,
    },
    /// 모든 인스턴스가 운영에 올라 rollout 이 끝났다.
    #[serde(rename = "rollout.completed")]
    RolloutCompleted {
        rollout: String,
        app: String,
        update: String,
        tally: Tally,
    },
    /// 팩토리가 rollout 을 거뒀다.
    #[serde(rename = "rollout.cancelled")]
    RolloutCancelled {
        rollout: String,
        app: String,
        update: String,
        tally: Tally,
    },
    /// 에이전트가 사람에게 비밀의 입력을 요청했다. 이름만 싣는다(까닭은 에이전트가 적은 글이라 싣지 않는다).
    #[serde(rename = "secret.requested")]
    SecretRequested { name: String },
    /// 인스턴스가 섰다.
    #[serde(rename = "instance.created")]
    InstanceCreated { app: String, version: String },
    /// 인스턴스가 지워졌다.
    #[serde(rename = "instance.deleted")]
    InstanceDeleted { app: String },
}

/// 멈춘 rollout 에서 실패한 인스턴스와 그 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failed {
    pub instance: InstanceId,
    pub reason: FailReason,
}

/// 이벤트의 종류. 받는 쪽은 모르는 종류를 건너뛰어야 한다(종류는 늘 수 있다).
pub const KINDS: [&str; 11] = [
    "promotion.requested",
    "promotion.succeeded",
    "promotion.failed",
    "rollout.advanced",
    "rollout.halted",
    "rollout.resumed",
    "rollout.completed",
    "rollout.cancelled",
    "secret.requested",
    "instance.created",
    "instance.deleted",
];

impl Body {
    /// 종류의 이름(`무엇.어찌됨`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PromotionRequested { .. } => KINDS[0],
            Self::PromotionSucceeded { .. } => KINDS[1],
            Self::PromotionFailed { .. } => KINDS[2],
            Self::RolloutAdvanced { .. } => KINDS[3],
            Self::RolloutHalted { .. } => KINDS[4],
            Self::RolloutResumed { .. } => KINDS[5],
            Self::RolloutCompleted { .. } => KINDS[6],
            Self::RolloutCancelled { .. } => KINDS[7],
            Self::SecretRequested { .. } => KINDS[8],
            Self::InstanceCreated { .. } => KINDS[9],
            Self::InstanceDeleted { .. } => KINDS[10],
        }
    }
}

/// 쌓을 이벤트 하나. 인스턴스 하나의 일이면 그 인스턴스를 함께 적는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Note {
    pub instance: Option<InstanceId>,
    pub body: Body,
}

/// rollout 하나가 `before` 에서 `after` 로 바뀐 것에서 나오는 이벤트. 인스턴스마다의 진행이 먼저이고 rollout 의 상태가 뒤다.
/// 바뀐 것이 없으면 아무것도 나오지 않는다.
pub fn rollout_notes(id: &str, before: &Rollout, after: &Rollout) -> Vec<Note> {
    let tally = Tally::of(after);
    let (rollout, app, update) = (id.to_owned(), after.app.clone(), after.update.clone());
    let mut notes = Vec::new();
    for (instance, progress) in &after.progress {
        if before.progress.get(instance) != Some(progress) {
            notes.push(Note {
                instance: Some(instance.clone()),
                body: Body::RolloutAdvanced {
                    rollout: rollout.clone(),
                    app: app.clone(),
                    update: update.clone(),
                    instance: instance.clone(),
                    progress: *progress,
                    tally,
                },
            });
        }
    }
    if before.status != after.status {
        let body = match after.status {
            Status::Halted => Some(Body::RolloutHalted {
                rollout,
                app,
                update,
                failed: after
                    .progress
                    .iter()
                    .filter_map(|(instance, progress)| match progress {
                        Progress::Failed { reason } => Some(Failed {
                            instance: instance.clone(),
                            reason: *reason,
                        }),
                        _ => None,
                    })
                    .collect(),
                tally,
            }),
            Status::Running if before.status == Status::Halted => Some(Body::RolloutResumed {
                rollout,
                app,
                update,
                tally,
            }),
            Status::Done => Some(Body::RolloutCompleted {
                rollout,
                app,
                update,
                tally,
            }),
            Status::Cancelled => Some(Body::RolloutCancelled {
                rollout,
                app,
                update,
                tally,
            }),
            Status::Running => None,
        };
        notes.extend(body.map(|body| Note {
            instance: None,
            body,
        }));
    }
    notes
}

// ---- 물어보는 길 ----

/// 목록 한 쪽. `after` 뒤의 것을 `limit` 개까지 차례대로.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Page {
    pub after: u64,
    pub limit: u32,
}

/// 목록의 질의가 틀린 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageProblem {
    /// `after` 가 0 이상의 정수가 아니다.
    After,
    /// `limit` 이 1 에서 [`LIST_MAX`] 사이의 정수가 아니다.
    Limit { max: u32 },
}

/// `after` 와 `limit` 을 읽는다. 없으면 처음부터 [`LIST_DEFAULT`] 개다.
pub fn page(after: Option<&str>, limit: Option<&str>) -> Result<Page, Vec<PageProblem>> {
    let mut problems = Vec::new();
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let after = match after {
        None => 0,
        Some(text) => match text.parse::<u64>() {
            Ok(value) if digits(text) => value,
            _ => {
                problems.push(PageProblem::After);
                0
            }
        },
    };
    let limit = match limit {
        None => LIST_DEFAULT,
        Some(text) => match text.parse::<u32>() {
            Ok(value) if digits(text) && (1..=LIST_MAX).contains(&value) => value,
            _ => {
                problems.push(PageProblem::Limit { max: LIST_MAX });
                LIST_DEFAULT
            }
        },
    };
    if problems.is_empty() {
        Ok(Page { after, limit })
    } else {
        Err(problems)
    }
}

// ---- 다시 보내기 ----

/// 보내지 못한 뒤에 할 일.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "next", content = "at")]
pub enum Retry {
    /// 이 때(유닉스 초)에 같은 이벤트를 다시 보낸다.
    At(u64),
    /// 처음 실패한 때에서 하루가 지났다. 이 이벤트는 그만 보내고 실패로 적는다. 뒤의 이벤트로 넘어간다.
    GiveUp,
}

/// 이벤트 하나를 `failures` 번째로 보내지 못했을 때 다음에 할 일. `failing_since` 는 그 이벤트를 처음 보내지 못한 때다.
///
/// 기다림은 30초 · 2분 · 10분 · 1시간 · 6시간이고 그 뒤로는 6시간마다다. 처음 실패에서 하루가 되는 때를 넘기지 않게
/// 마지막 시도를 그때로 당기고, 그때도 실패하면 그만둔다.
pub fn after_failure(failures: u32, failing_since: u64, now: u64) -> Retry {
    let deadline = failing_since.saturating_add(GIVE_UP_AFTER);
    if now >= deadline {
        return Retry::GiveUp;
    }
    let step = usize::try_from(failures.saturating_sub(1))
        .unwrap_or(usize::MAX)
        .min(RETRY_DELAYS.len() - 1);
    Retry::At(now.saturating_add(RETRY_DELAYS[step]).min(deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollout::Event;

    fn id(text: &str) -> InstanceId {
        InstanceId::parse(text).unwrap()
    }

    fn rollout() -> Rollout {
        Rollout::new(
            "todo".to_owned(),
            "a".repeat(40),
            Change::SecurityUpdate,
            vec![vec![id("k3f9x2ab")], vec![id("zzzzzzzz")]],
        )
        .unwrap()
    }

    #[test]
    fn 실패는_30초_2분_10분_1시간_6시간_뒤에_다시_보내고_처음_실패에서_하루가_되면_그만둔다() {
        let since = 1_000;
        let mut at = since;
        let mut seen = Vec::new();
        for failures in 1.. {
            match after_failure(failures, since, at) {
                Retry::At(next) => {
                    seen.push(next - at);
                    at = next;
                }
                Retry::GiveUp => break,
            }
        }
        assert_eq!(
            seen,
            vec![30, 120, 600, 3_600, 21_600, 21_600, 21_600, 17_250]
        );
        assert_eq!(at, since + GIVE_UP_AFTER);
        // 하루가 되기 1초 전의 실패는 아직 그만두지 않는다
        assert_eq!(
            after_failure(9, since, since + GIVE_UP_AFTER - 1),
            Retry::At(since + GIVE_UP_AFTER)
        );
    }

    #[test]
    fn rollout_의_진행은_바뀐_인스턴스마다_하나씩_나오고_멈춤은_실패한_것과_함께_뒤에_나온다() {
        let first = rollout();
        assert!(rollout_notes("r1", &first, &first).is_empty());
        let applied = first
            .step(&Event::Applied {
                instance: id("k3f9x2ab"),
            })
            .unwrap();
        let notes = rollout_notes("r1", &first, &applied);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].instance, Some(id("k3f9x2ab")));
        assert_eq!(notes[0].body.kind(), "rollout.advanced");
        let previewed = applied
            .step(&Event::Previewed {
                instance: id("k3f9x2ab"),
            })
            .unwrap();
        let halted = previewed
            .step(&Event::Checked {
                instance: id("k3f9x2ab"),
                access_passed: false,
                conformance_passed: true,
            })
            .unwrap();
        let notes = rollout_notes("r1", &previewed, &halted);
        let kinds: Vec<&str> = notes.iter().map(|note| note.body.kind()).collect();
        assert_eq!(kinds, ["rollout.advanced", "rollout.halted"]);
        let Body::RolloutHalted { failed, tally, .. } = &notes[1].body else {
            panic!("멈춤이 아닙니다");
        };
        assert_eq!(
            failed,
            &vec![Failed {
                instance: id("k3f9x2ab"),
                reason: FailReason::AccessCheckFailed
            }]
        );
        assert_eq!(tally.failed, 1);
        assert_eq!(tally.waiting, 1);
        // 다시 열면 실패한 곳이 처음으로 돌아가고 rollout 이 다시 열린다
        let resumed = halted.step(&Event::Resume).unwrap();
        let kinds: Vec<&'static str> = rollout_notes("r1", &halted, &resumed)
            .iter()
            .map(|note| note.body.kind())
            .collect();
        assert_eq!(kinds, ["rollout.advanced", "rollout.resumed"]);
        let cancelled = resumed.step(&Event::Cancel).unwrap();
        let kinds: Vec<&'static str> = rollout_notes("r1", &resumed, &cancelled)
            .iter()
            .map(|note| note.body.kind())
            .collect();
        assert_eq!(kinds, ["rollout.cancelled"]);
    }

    #[test]
    fn 몸은_종류와_이름과_숫자만_싣는다() {
        let body = Body::PromotionSucceeded {
            release: "r_abc".to_owned(),
            commit: "c".repeat(40),
            previous_release: None,
            change: Change::CustomerRequest,
            approved_by: Approver::Customer,
            migrations: 2,
            rollout: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "promotion.succeeded");
        assert_eq!(json["data"]["approved_by"], "customer");
        assert_eq!(json["data"]["migrations"], 2);
        let requested = serde_json::to_value(Body::SecretRequested {
            name: "BANK_API_KEY".to_owned(),
        })
        .unwrap();
        assert_eq!(
            requested,
            serde_json::json!({ "type": "secret.requested", "data": { "name": "BANK_API_KEY" } })
        );
        // 종류의 목록은 갈래마다 하나씩이고 겹치지 않는다
        let mut kinds = KINDS.to_vec();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), KINDS.len());
    }

    #[test]
    fn 목록의_질의는_after_가_정수이고_limit_이_1에서_500_사이일_때만_받는다() {
        assert_eq!(
            page(None, None),
            Ok(Page {
                after: 0,
                limit: LIST_DEFAULT
            })
        );
        assert_eq!(
            page(Some("41"), Some("500")),
            Ok(Page {
                after: 41,
                limit: 500
            })
        );
        assert_eq!(page(Some("0"), Some("1")), Ok(Page { after: 0, limit: 1 }));
        assert_eq!(
            page(Some("-1"), Some("501")),
            Err(vec![
                PageProblem::After,
                PageProblem::Limit { max: LIST_MAX }
            ])
        );
        assert_eq!(
            page(Some("+3"), Some("0")),
            Err(vec![
                PageProblem::After,
                PageProblem::Limit { max: LIST_MAX }
            ])
        );
        assert_eq!(page(Some(""), None), Err(vec![PageProblem::After]));
    }
}
