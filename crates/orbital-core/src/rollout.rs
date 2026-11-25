//! rollout. 앱(위쪽)의 업데이트 하나가 포크 셋에서 인스턴스마다 어디까지 갔는지를 갖고, 관문을 지키고, 실패하면 멈춘다.
//!
//! 레이어는 포크의 코드를 고치는 에이전트를 돌리지 않는다. 에이전트는 팩토리(밀기)나 고객(당기기)의 플랫폼에서 돌고, 레이어에는
//! 인스턴스 하나로 좁힌 토큰으로 들어온다. 여기서는 그 결과로 일어난 사건(적용 · 프리뷰 · 검사 · 승격 · 되돌려짐)을 받아
//! 다음 상태를 정하거나 거절한다.
//!
//! 「적용됐다」의 뜻은 하나다. release 의 commit 이 업데이트 commit 을 조상으로 담는다. 그 판정(git)은 어댑터가 하고,
//! 담은 release 에 대해서만 사건을 넘긴다. 담지 않은 release 는 rollout 과 무관하게 오르내린다.
//!
//! 멈춤은 넓게 건다. 인스턴스 하나가 실패하면 rollout 전체가 멈추고, 팩토리가 다시 열기 전에는 어느 인스턴스도 새로 오르지 못한다.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::name::InstanceId;
use crate::release::Change;

/// rollout 이 어디에 있는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// 이어지고 있다.
    Running,
    /// 인스턴스 하나가 실패해 멈췄다. 팩토리가 다시 열어야 이어진다.
    Halted,
    /// 팩토리가 거뒀다. 어떤 사건도 받지 않는다.
    Cancelled,
    /// 모든 인스턴스가 운영에 올랐다.
    Done,
}

impl Status {
    /// 아직 사건을 받는가. 열린 rollout 만 승격을 가로막는다.
    pub fn open(self) -> bool {
        matches!(self, Self::Running | Self::Halted)
    }
}

/// 인스턴스 하나가 이 업데이트를 어디까지 지났는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Progress {
    /// 아직 업데이트를 담은 commit 이 없다.
    Waiting,
    /// 업데이트를 담은 commit 이 포크에 섰다.
    Applied,
    /// 그 commit 의 프리뷰가 섰다.
    Previewed,
    /// 권한 검사와 적합성 테스트를 통과했다. 승격을 기다린다.
    Passed,
    /// 업데이트를 담은 release 가 운영에 올랐다. 끝이다.
    Promoted,
    /// 실패했다. rollout 이 멈춰 있고, 다시 열면 처음(`waiting`)부터 다시 지난다.
    Failed { reason: FailReason },
}

/// 인스턴스가 실패한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    /// 프리뷰의 권한 검사가 어긋남을 찾았다.
    AccessCheckFailed,
    /// 위쪽이 정한 적합성 테스트를 통과하지 못했다.
    ConformanceFailed,
    /// 운영에 올린 뒤 상태 확인에 실패해 앞의 release 로 되돌려졌다.
    RolledBack,
}

/// rollout 이 받는 사건. 인스턴스의 사건은 그 release 가 업데이트를 담았을 때만 온다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// 업데이트를 담은 commit 이 포크에 섰다(레이어가 합쳤거나 에이전트가 풀어 올렸다).
    Applied { instance: InstanceId },
    /// 업데이트를 담은 commit 의 프리뷰가 섰다.
    Previewed { instance: InstanceId },
    /// 그 프리뷰의 검사 결과.
    Checked {
        instance: InstanceId,
        access_passed: bool,
        conformance_passed: bool,
    },
    /// 업데이트를 담은 release 를 이 `change` 로 운영에 올렸다(올리려 한다).
    Promoted {
        instance: InstanceId,
        change: Change,
    },
    /// 올린 뒤 상태 확인에 실패해 앞의 release 로 되돌려졌다.
    RolledBack { instance: InstanceId },
    /// 팩토리가 다시 연다.
    Resume,
    /// 팩토리가 거둔다.
    Cancel,
}

/// 사건을 받지 않은 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refused", rename_all = "snake_case")]
pub enum Refusal {
    /// 거뒀거나 끝난 rollout 이다. 어떤 사건도 받지 않는다.
    Closed { status: Status },
    /// 이 rollout 에 든 인스턴스가 아니다.
    NotInRollout,
    /// 멈춰 있다. 팩토리가 다시 열기 전에는 오르지 못한다.
    Halted,
    /// 멈춰 있지 않아 다시 열 것이 없다.
    NotHalted,
    /// 이미 이 업데이트로 운영에 올랐다.
    AlreadyPromoted,
    /// 실패한 인스턴스다. 팩토리가 다시 연 뒤에 처음부터 다시 지난다.
    Failed,
    /// 업데이트를 담은 commit 이 아직 없다.
    NotApplied,
    /// 업데이트를 담은 commit 의 프리뷰가 아직 없다.
    NotPreviewed,
    /// 권한 검사와 적합성 테스트를 아직 통과하지 않았다.
    NotPassed,
    /// rollout 이 정한 것과 다른 `change` 로 올리려 한다.
    WrongChange { needs: Change },
    /// 앞 물결에 아직 오르지 않은 인스턴스가 있다.
    EarlierWave { waiting: Vec<InstanceId> },
}

/// 물결의 문제. 찾은 것을 모두 돌려준다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum WaveProblem {
    /// 물결이 하나도 없다.
    NoWave,
    /// 빈 물결이 있다(0 부터 센 자리).
    EmptyWave { wave: usize },
    /// 한 인스턴스가 두 번 적혔다.
    Duplicate { instance: InstanceId },
}

/// 업데이트 하나의 rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollout {
    /// 업데이트를 낸 앱(위쪽)의 이름.
    pub app: String,
    /// 업데이트 commit. 「적용됐다」는 release 의 commit 이 이것을 조상으로 담는다는 뜻이다.
    pub update: String,
    /// 이 업데이트를 담은 release 를 올릴 때 쓸 `change`. 누가 승인하는지(고객 · 팩토리)가 여기서 갈린다.
    pub change: Change,
    /// 순서 있는 물결. 앞 물결이 모두 오른 뒤에 뒤 물결이 오른다.
    pub waves: Vec<Vec<InstanceId>>,
    pub status: Status,
    pub progress: BTreeMap<InstanceId, Progress>,
}

impl Rollout {
    /// 새 rollout. 모든 인스턴스가 `waiting` 에서 시작한다.
    pub fn new(
        app: String,
        update: String,
        change: Change,
        waves: Vec<Vec<InstanceId>>,
    ) -> Result<Self, Vec<WaveProblem>> {
        let mut problems = Vec::new();
        if waves.is_empty() {
            problems.push(WaveProblem::NoWave);
        }
        let mut seen = BTreeSet::new();
        for (at, wave) in waves.iter().enumerate() {
            if wave.is_empty() {
                problems.push(WaveProblem::EmptyWave { wave: at });
            }
            for instance in wave {
                if !seen.insert(instance.clone()) {
                    problems.push(WaveProblem::Duplicate {
                        instance: instance.clone(),
                    });
                }
            }
        }
        if !problems.is_empty() {
            return Err(problems);
        }
        let progress = seen
            .into_iter()
            .map(|instance| (instance, Progress::Waiting))
            .collect();
        Ok(Self {
            app,
            update,
            change,
            waves,
            status: Status::Running,
            progress,
        })
    }

    /// 이 인스턴스가 든 rollout 인가.
    pub fn contains(&self, instance: &InstanceId) -> bool {
        self.progress.contains_key(instance)
    }

    /// 사건 하나를 받아 다음 모습을 돌려준다. 받지 않으면 까닭을 돌려주고 아무것도 바꾸지 않는다.
    pub fn step(&self, event: &Event) -> Result<Self, Refusal> {
        if !self.status.open() {
            return Err(Refusal::Closed {
                status: self.status,
            });
        }
        let mut next = self.clone();
        let (instance, state) = match event {
            Event::Resume => {
                if self.status != Status::Halted {
                    return Err(Refusal::NotHalted);
                }
                next.status = Status::Running;
                // 실패한 곳은 처음부터 다시 지난다. 고친 release 가 다시 적용 · 프리뷰 · 검사를 지나야 한다
                for state in next.progress.values_mut() {
                    if matches!(state, Progress::Failed { .. }) {
                        *state = Progress::Waiting;
                    }
                }
                return Ok(next);
            }
            Event::Cancel => {
                next.status = Status::Cancelled;
                return Ok(next);
            }
            Event::Applied { instance }
            | Event::Previewed { instance }
            | Event::Checked { instance, .. }
            | Event::Promoted { instance, .. }
            | Event::RolledBack { instance } => {
                let state = *self.progress.get(instance).ok_or(Refusal::NotInRollout)?;
                (instance, state)
            }
        };
        match state {
            Progress::Promoted => return Err(Refusal::AlreadyPromoted),
            Progress::Failed { .. } => return Err(Refusal::Failed),
            _ => {}
        }
        let after = match event {
            // 새 commit 이 서면 앞의 프리뷰와 검사는 그 commit 의 것이 아니다. 다시 지난다
            Event::Applied { .. } => Progress::Applied,
            Event::Previewed { .. } => match state {
                Progress::Waiting => return Err(Refusal::NotApplied),
                _ => Progress::Previewed,
            },
            Event::Checked {
                access_passed,
                conformance_passed,
                ..
            } => {
                if state != Progress::Previewed {
                    return Err(Refusal::NotPreviewed);
                }
                match (access_passed, conformance_passed) {
                    (true, true) => Progress::Passed,
                    (false, _) => Self::fail(&mut next, FailReason::AccessCheckFailed),
                    (true, false) => Self::fail(&mut next, FailReason::ConformanceFailed),
                }
            }
            Event::Promoted { change, .. } => {
                if self.status == Status::Halted {
                    return Err(Refusal::Halted);
                }
                if *change != self.change {
                    return Err(Refusal::WrongChange { needs: self.change });
                }
                if state != Progress::Passed {
                    return Err(Refusal::NotPassed);
                }
                let waiting = self.earlier_waiting(instance);
                if !waiting.is_empty() {
                    return Err(Refusal::EarlierWave { waiting });
                }
                Progress::Promoted
            }
            Event::RolledBack { .. } => {
                if state != Progress::Passed {
                    return Err(Refusal::NotPassed);
                }
                Self::fail(&mut next, FailReason::RolledBack)
            }
            Event::Resume | Event::Cancel => return Ok(next),
        };
        next.progress.insert(instance.clone(), after);
        if next
            .progress
            .values()
            .all(|state| *state == Progress::Promoted)
        {
            next.status = Status::Done;
        }
        Ok(next)
    }

    /// 인스턴스 하나의 실패는 rollout 전체를 멈춘다.
    fn fail(next: &mut Self, reason: FailReason) -> Progress {
        next.status = Status::Halted;
        Progress::Failed { reason }
    }

    /// 이 인스턴스보다 앞 물결에서 아직 오르지 않은 인스턴스.
    fn earlier_waiting(&self, instance: &InstanceId) -> Vec<InstanceId> {
        let Some(wave) = self
            .waves
            .iter()
            .position(|members| members.contains(instance))
        else {
            return Vec::new();
        };
        self.waves
            .iter()
            .take(wave)
            .flatten()
            .filter(|earlier| self.progress.get(*earlier) != Some(&Progress::Promoted))
            .cloned()
            .collect()
    }

    /// 이 인스턴스가 업데이트를 담은 release 를 이 `change` 로 올려도 되는가. 올리기 전에 묻는다.
    pub fn may_promote(&self, instance: &InstanceId, change: Change) -> Result<(), Refusal> {
        self.step(&Event::Promoted {
            instance: instance.clone(),
            change,
        })
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> InstanceId {
        InstanceId::parse(text).unwrap()
    }

    fn rollout(waves: &[&[&str]]) -> Rollout {
        Rollout::new(
            "todo".to_owned(),
            "a".repeat(40),
            Change::SecurityUpdate,
            waves
                .iter()
                .map(|wave| wave.iter().map(|text| id(text)).collect())
                .collect(),
        )
        .unwrap()
    }

    /// 인스턴스 하나를 적용 → 프리뷰 → 검사(통과)까지 보낸다.
    fn pass(rollout: Rollout, instance: &str) -> Rollout {
        let instance = id(instance);
        rollout
            .step(&Event::Applied {
                instance: instance.clone(),
            })
            .unwrap()
            .step(&Event::Previewed {
                instance: instance.clone(),
            })
            .unwrap()
            .step(&Event::Checked {
                instance,
                access_passed: true,
                conformance_passed: true,
            })
            .unwrap()
    }

    fn promoted(instance: &str) -> Event {
        Event::Promoted {
            instance: id(instance),
            change: Change::SecurityUpdate,
        }
    }

    #[test]
    fn 모든_인스턴스가_오르면_rollout_이_끝난다() {
        let mut rollout = rollout(&[&["aaaaaaaa"], &["bbbbbbbb", "cccccccc"]]);
        rollout = pass(rollout, "aaaaaaaa");
        rollout = rollout.step(&promoted("aaaaaaaa")).unwrap();
        assert_eq!(rollout.status, Status::Running);
        rollout = pass(pass(rollout, "bbbbbbbb"), "cccccccc");
        rollout = rollout.step(&promoted("bbbbbbbb")).unwrap();
        assert_eq!(rollout.status, Status::Running);
        rollout = rollout.step(&promoted("cccccccc")).unwrap();
        assert_eq!(rollout.status, Status::Done);
        assert!(
            rollout
                .progress
                .values()
                .all(|state| *state == Progress::Promoted)
        );
        // 끝난 rollout 은 더 받지 않는다
        assert_eq!(
            rollout.step(&Event::Resume),
            Err(Refusal::Closed {
                status: Status::Done
            })
        );
    }

    #[test]
    fn 거둔_rollout_은_어떤_사건도_받지_않는다() {
        let rollout = pass(rollout(&[&["aaaaaaaa", "bbbbbbbb"]]), "aaaaaaaa");
        let cancelled = rollout.step(&Event::Cancel).unwrap();
        assert_eq!(cancelled.status, Status::Cancelled);
        // 아직 오르지 않은 곳은 그 자리에 남는다
        assert_eq!(cancelled.progress[&id("aaaaaaaa")], Progress::Passed);
        assert_eq!(cancelled.progress[&id("bbbbbbbb")], Progress::Waiting);
        let closed = Err(Refusal::Closed {
            status: Status::Cancelled,
        });
        for event in [
            Event::Applied {
                instance: id("bbbbbbbb"),
            },
            Event::Previewed {
                instance: id("aaaaaaaa"),
            },
            Event::Checked {
                instance: id("aaaaaaaa"),
                access_passed: true,
                conformance_passed: true,
            },
            promoted("aaaaaaaa"),
            Event::RolledBack {
                instance: id("aaaaaaaa"),
            },
            Event::Resume,
            Event::Cancel,
        ] {
            assert_eq!(cancelled.step(&event), closed, "{event:?}");
        }
        assert!(!cancelled.status.open());
    }

    #[test]
    fn 실패한_인스턴스는_다시_연_뒤에_고친_release_로_다시_지난다() {
        let mut rollout = pass(rollout(&[&["aaaaaaaa", "bbbbbbbb"]]), "aaaaaaaa");
        let b = id("bbbbbbbb");
        rollout = rollout
            .step(&Event::Applied {
                instance: b.clone(),
            })
            .unwrap()
            .step(&Event::Previewed {
                instance: b.clone(),
            })
            .unwrap()
            .step(&Event::Checked {
                instance: b.clone(),
                access_passed: true,
                conformance_passed: false,
            })
            .unwrap();
        assert_eq!(rollout.status, Status::Halted);
        assert_eq!(
            rollout.progress[&b],
            Progress::Failed {
                reason: FailReason::ConformanceFailed
            }
        );
        // 멈춘 동안에는 통과한 곳도 오르지 못하고, 실패한 곳은 고쳐 올려도 다시 지나지 못한다
        assert_eq!(rollout.step(&promoted("aaaaaaaa")), Err(Refusal::Halted));
        assert_eq!(
            rollout.step(&Event::Applied {
                instance: b.clone()
            }),
            Err(Refusal::Failed)
        );
        // 다시 열면 실패한 곳은 처음부터 다시 지난다
        rollout = rollout.step(&Event::Resume).unwrap();
        assert_eq!(rollout.status, Status::Running);
        assert_eq!(rollout.progress[&b], Progress::Waiting);
        assert_eq!(rollout.step(&promoted("bbbbbbbb")), Err(Refusal::NotPassed));
        rollout = pass(rollout, "bbbbbbbb");
        rollout = rollout
            .step(&promoted("aaaaaaaa"))
            .unwrap()
            .step(&promoted("bbbbbbbb"))
            .unwrap();
        assert_eq!(rollout.status, Status::Done);
    }

    #[test]
    fn 정한_것과_다른_change_로는_올리지_못한다() {
        let rollout = pass(rollout(&[&["aaaaaaaa"]]), "aaaaaaaa");
        assert_eq!(
            rollout.may_promote(&id("aaaaaaaa"), Change::FeatureUpdate),
            Err(Refusal::WrongChange {
                needs: Change::SecurityUpdate
            })
        );
        assert_eq!(
            rollout.may_promote(&id("aaaaaaaa"), Change::SecurityUpdate),
            Ok(())
        );
    }

    #[test]
    fn 물결이_비었거나_한_인스턴스가_두_번_적히면_만들지_못한다() {
        let made = Rollout::new(
            "todo".to_owned(),
            "a".repeat(40),
            Change::FeatureUpdate,
            vec![vec![id("aaaaaaaa")], vec![], vec![id("aaaaaaaa")]],
        );
        assert_eq!(
            made,
            Err(vec![
                WaveProblem::EmptyWave { wave: 1 },
                WaveProblem::Duplicate {
                    instance: id("aaaaaaaa")
                }
            ])
        );
        assert_eq!(
            Rollout::new(
                "todo".to_owned(),
                "a".repeat(40),
                Change::FeatureUpdate,
                vec![]
            ),
            Err(vec![WaveProblem::NoWave])
        );
    }

    #[test]
    fn 판정은_json_으로_오간다() {
        assert_eq!(
            serde_json::to_string(&Progress::Failed {
                reason: FailReason::RolledBack
            })
            .unwrap(),
            r#"{"state":"failed","reason":"rolled_back"}"#
        );
        assert_eq!(
            serde_json::to_string(&Refusal::WrongChange {
                needs: Change::FeatureUpdate
            })
            .unwrap(),
            r#"{"refused":"wrong_change","needs":"feature_update"}"#
        );
    }
}
