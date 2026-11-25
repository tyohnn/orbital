//! rollout: 앱(위쪽)의 업데이트 하나를 포크 셋에 물결로 밀거나 당긴다.
//!
//! 레이어는 에이전트를 돌리지 않는다. 업데이트가 인스턴스마다 어디까지 갔는지를 적고, 관문(적합성 테스트 · 물결 · 멈춤)을 지킨다.
//! 판정은 core 의 `rollout` 이 하고, 여기서는 git 의 사실(release 가 업데이트를 조상으로 담는가)을 읽어 사건으로 넘긴다.

use std::fs;
use std::path::Path;
use std::time::Instant;

use orbital_core::name::{Ident, InstanceId};
use orbital_core::release::{Change, Conformed};
use orbital_core::rollout::{Event, Progress, Refusal, Rollout, Status, WaveProblem};
use orbital_run::{Job, RunError};
use orbital_source::assemble::Assembled;
use orbital_source::{Commit, Merged, app_commit};
use serde::{Deserialize, Serialize};

use super::{Failure, Inner, Layer, Outcome, fresh_id, internal};
use crate::registry::RolloutRecord;

/// rollout 을 만드는 요청. `commit` 이 없으면 앱의 `main` 의 끝이다.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRollout {
    #[serde(default)]
    pub commit: Option<String>,
    pub change: Change,
    pub waves: Vec<Vec<String>>,
}

/// 인스턴스 하나의 진행.
#[derive(Debug, Clone, Serialize)]
pub struct InstanceProgress {
    pub instance: String,
    #[serde(flatten)]
    pub progress: Progress,
}

/// 팩토리가 보는 rollout.
#[derive(Debug, Clone, Serialize)]
pub struct RolloutReport {
    pub id: String,
    pub app: String,
    /// 업데이트 commit.
    pub commit: String,
    pub change: Change,
    pub waves: Vec<Vec<String>>,
    pub status: Status,
    /// 물결의 차례대로.
    pub instances: Vec<InstanceProgress>,
}

/// 레이어가 업데이트를 합쳐 본 결과.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    /// 포크의 `main` 이 업데이트를 담게 됐는가(이미 담고 있었으면 그대로 `true`).
    pub applied: bool,
    /// 합친 뒤(또는 이미 담고 있던) `main` 의 commit. 충돌했으면 없다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// 충돌한 파일의 이름. 포크는 건드리지 않았다. 에이전트가 풀어 올린다.
    pub conflicts: Vec<String>,
}

/// 에이전트의 토큰이 보는 진행. 자기 인스턴스의 것만 있다. 다른 인스턴스의 이름과 상태는 싣지 않는다.
#[derive(Debug, Clone, Serialize)]
pub struct AgentRollout {
    pub rollout: String,
    /// 합칠 업데이트 commit. 받은 저장소에서는 `origin/update` 다.
    pub update: String,
    pub change: Change,
    /// 멈췄는가.
    pub halted: bool,
    #[serde(flatten)]
    pub progress: Progress,
}

/// 적합성 테스트의 결과. 통과 여부 · 걸린 시간 · 출력의 끝부분만 남긴다.
#[derive(Debug, Clone, Serialize)]
pub struct ConformanceReport {
    pub passed: bool,
    pub outcome: Conformed,
    pub millis: u64,
    /// 출력의 끝부분. 길이에 한도가 있다.
    pub output: String,
    /// 테스트를 가져온 위쪽 commit.
    pub upstream: String,
}

/// 적합성 테스트의 출력에서 남기는 끝부분의 길이(글자).
const OUTPUT_LIMIT: usize = 4000;

/// rollout 이 거절한 까닭을 에이전트와 사람이 읽는 문장으로 적는다.
pub(super) fn refusal_text(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Closed {
            status: Status::Done,
        } => "이 rollout 은 끝났습니다. 더 받지 않습니다".to_owned(),
        Refusal::Closed { .. } => "이 rollout 은 거뒀습니다. 더 받지 않습니다".to_owned(),
        Refusal::NotInRollout => "이 인스턴스는 이 rollout 에 들지 않았습니다".to_owned(),
        Refusal::Halted => "rollout 이 멈춰 있습니다. 실패한 인스턴스가 있어, 팩토리가 다시 열기(`POST /v1/rollouts/{id}/resume`) 전에는 어느 인스턴스도 이 업데이트를 담은 release 를 운영에 올리지 못합니다".to_owned(),
        Refusal::NotHalted => "rollout 이 멈춰 있지 않아 다시 열 것이 없습니다".to_owned(),
        Refusal::AlreadyPromoted => "이 인스턴스는 이미 이 업데이트로 운영에 올랐습니다".to_owned(),
        Refusal::Failed => "이 인스턴스는 실패로 적혀 있습니다. 팩토리가 rollout 을 다시 연 뒤에 고친 release 로 프리뷰부터 다시 지나야 합니다".to_owned(),
        Refusal::NotApplied | Refusal::NotPreviewed | Refusal::NotPassed => "이 인스턴스는 업데이트를 담은 release 의 프리뷰에서 권한 검사와 적합성 테스트를 아직 통과하지 않았습니다. 프리뷰를 세워 통과한 뒤 올려 주세요".to_owned(),
        Refusal::WrongChange { needs } => {
            let needs = change_name(*needs);
            format!("이 rollout 의 업데이트는 `{needs}` 로만 올립니다. change 를 `{needs}` 로 적어 주세요")
        }
        Refusal::EarlierWave { waiting } => {
            let names: Vec<String> = waiting
                .iter()
                .map(|instance| format!("`{}`", instance.as_str()))
                .collect();
            format!(
                "앞 물결의 인스턴스 {} 가 아직 오르지 않았습니다. 앞 물결이 모두 오른 뒤에 올려 주세요",
                names.join(", ")
            )
        }
    }
}

fn change_name(change: Change) -> String {
    serde_json::to_value(change)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn wave_text(problem: &WaveProblem) -> String {
    match problem {
        WaveProblem::NoWave => {
            "물결(`waves`)이 하나도 없습니다. `[[\"인스턴스\"]]` 처럼 하나 이상 적어 주세요"
                .to_owned()
        }
        WaveProblem::EmptyWave { wave } => {
            format!(
                "{}번째 물결이 비어 있습니다. 인스턴스를 적거나 그 물결을 빼 주세요",
                wave + 1
            )
        }
        WaveProblem::Duplicate { instance } => format!(
            "인스턴스 `{}` 가 두 번 적혀 있습니다. 한 인스턴스는 한 물결에 한 번만 적어 주세요",
            instance.as_str()
        ),
    }
}

/// 출력의 끝부분. 글자의 경계에서 자른다.
fn output_tail(log: &Path) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    let count = text.chars().count();
    text.chars()
        .skip(count.saturating_sub(OUTPUT_LIMIT))
        .collect()
}

/// 적합성 테스트 한 번을 돌릴 자리.
#[derive(Clone, Copy)]
struct Trial<'a> {
    /// 위쪽이 선언한 명령.
    run: &'a str,
    /// 위쪽이 선언한 테스트의 폴더.
    files: &'a str,
    /// 위쪽의 폴더만 놓을 빈 자리.
    folder: &'a Path,
    log: &'a Path,
    /// 프리뷰의 주소. 테스트에 건네는 유일한 값이다.
    origin: &'a str,
}

fn report(id: &str, rollout: &Rollout) -> RolloutReport {
    RolloutReport {
        id: id.to_owned(),
        app: rollout.app.clone(),
        commit: rollout.update.clone(),
        change: rollout.change,
        waves: rollout
            .waves
            .iter()
            .map(|wave| {
                wave.iter()
                    .map(|instance| instance.as_str().to_owned())
                    .collect()
            })
            .collect(),
        status: rollout.status,
        instances: rollout
            .waves
            .iter()
            .flatten()
            .map(|instance| InstanceProgress {
                instance: instance.as_str().to_owned(),
                progress: rollout
                    .progress
                    .get(instance)
                    .copied()
                    .unwrap_or(Progress::Waiting),
            })
            .collect(),
    }
}

impl Layer {
    /// 위쪽이 정한 적합성 테스트를 프리뷰에 대해 돌린다. 위쪽이 선언하지 않았으면 `None` 이다.
    ///
    /// 명령과 폴더는 포크가 아니라 위쪽(release 가 담은 가장 새 앱의 commit)에서 가져온다. 빈 자리에 그 폴더만 놓고
    /// 빌드와 같은 실행기로 환경을 비워 돌린다. 포크의 트리는 놓지 않고, 프리뷰의 주소 말고는 아무것도 건네지 않는다.
    pub(super) fn conform(
        &self,
        instance: &InstanceId,
        assembled: &Assembled,
        origin: &str,
    ) -> Option<ConformanceReport> {
        let upstream = self
            .sources
            .newest_upstream(instance, &assembled.commit)
            .ok()??;
        let declared = self.assembled(instance, &upstream).ok()?;
        let (run, files) = declared.manifest.get().conformance.as_ref()?.parts()?;
        let started = Instant::now();
        let folder = self
            .home
            .join("conformance")
            .join(instance.as_str())
            .join(&assembled.release.0);
        let log = self.log(instance, &assembled.release, "conformance");
        let _ = fs::remove_dir_all(&folder);
        let _ = fs::remove_file(&log);
        if let Some(parent) = log.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let trial = Trial {
            run,
            files,
            folder: &folder,
            log: &log,
            origin,
        };
        let outcome = self.run_conformance(instance, &upstream, &trial);
        let _ = fs::remove_dir_all(&folder);
        Some(ConformanceReport {
            passed: outcome == Conformed::Passed,
            outcome,
            millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            output: output_tail(&log),
            upstream: upstream.to_string(),
        })
    }

    fn run_conformance(
        &self,
        instance: &InstanceId,
        upstream: &Commit,
        trial: &Trial<'_>,
    ) -> Conformed {
        let Trial {
            run,
            files,
            folder,
            log,
            origin,
        } = *trial;
        // 빈 자리에 위쪽의 폴더만 놓는다. 포크의 트리는 놓지 않는다: 포크가 고쳤든 지웠든 끼워 넣었든 위쪽의 테스트만 돌고,
        // 테스트의 프로세스가 포크의 코드(옆에 둔 모듈 · 설정)를 읽어 들일 길이 없다. 포크는 프리뷰의 주소로만 잰다
        if fs::create_dir_all(folder).is_err() {
            return Conformed::NotRun;
        }
        match self
            .sources
            .export_folder(instance, upstream, files, folder)
        {
            Ok(true) => {}
            _ => return Conformed::NotRun,
        }
        let env = [("ORBITAL_PREVIEW_URL".to_owned(), origin.to_owned())];
        let job = Job {
            folder,
            command: run,
            env: &env,
            log,
        };
        match self.runner.check(&job, self.conformance_timeout) {
            Ok(()) => Conformed::Passed,
            Err(RunError::TimedOut) => Conformed::TimedOut,
            Err(RunError::Failed { .. }) => Conformed::Failed,
            Err(RunError::Spawn) => Conformed::NotRun,
        }
    }

    /// 이 인스턴스가 든 열린 rollout 가운데, 그 업데이트를 `commit` 이 조상으로 담는 것.
    pub(super) fn governing(
        &self,
        inner: &Inner,
        instance: &InstanceId,
        commit: &Commit,
    ) -> Option<String> {
        inner
            .registry
            .state
            .rollouts
            .iter()
            .filter(|(_, record)| record.rollout.status.open() && record.rollout.contains(instance))
            .find(|(_, record)| {
                Commit::parse(&record.rollout.update).is_some_and(|update| {
                    self.sources
                        .descends(instance, commit, &update)
                        .unwrap_or(false)
                })
            })
            .map(|(id, _)| id.clone())
    }

    /// 사건을 차례로 넘긴다. 받지 않은 사건은 버린다(그 까닭은 승격할 때 다시 판정한다).
    pub(super) fn record(inner: &mut Inner, id: &str, events: &[Event]) -> Outcome<()> {
        if let Some(record) = inner.registry.state.rollouts.get_mut(id) {
            for event in events {
                if let Ok(next) = record.rollout.step(event) {
                    record.rollout = next;
                }
            }
        }
        inner.registry.save().map_err(Failure::Internal)
    }

    /// `commit` 이 업데이트를 담았으면 그 rollout 에 사건을 넘긴다.
    pub(super) fn track(
        &self,
        inner: &mut Inner,
        instance: &InstanceId,
        commit: &Commit,
        events: &[Event],
    ) -> Outcome<()> {
        match self.governing(inner, instance, commit) {
            Some(id) => Self::record(inner, &id, events),
            None => Ok(()),
        }
    }

    fn owned_rollout<'a>(
        inner: &'a mut Inner,
        organization: &str,
        id: &str,
    ) -> Outcome<&'a mut RolloutRecord> {
        inner
            .registry
            .state
            .rollouts
            .get_mut(id)
            .filter(|record| record.organization == organization)
            .ok_or(Failure::NotFound)
    }

    /// rollout 을 만든다(service key).
    pub fn create_rollout(
        &self,
        organization: &str,
        app: &str,
        request: NewRollout,
    ) -> Outcome<RolloutReport> {
        let app_name = Ident::parse(app).map_err(|_| Failure::NotFound)?;
        let repository = self.app_path(organization, &app_name)?;
        if !repository.join("HEAD").is_file() {
            return Err(Failure::NotFound);
        }
        let update = app_commit(&repository, request.commit.as_deref()).map_err(|_| {
            Failure::Problems(vec![format!(
                "앱 `{app}` 의 버전에 그 commit 이 없습니다. 앱을 먼저 올리고(`PUT /v1/apps/{app}`) 그 commit 의 40자 식별자를 적거나, 적지 않아 앱의 `main` 의 끝을 쓰세요"
            )])
        })?;
        let missing = |text: &str| {
            format!("인스턴스 `{text}` 가 없습니다. 이 팩토리의 인스턴스 식별자를 적어 주세요")
        };
        let mut problems = Vec::new();
        let mut waves = Vec::new();
        for wave in &request.waves {
            let mut members = Vec::new();
            for text in wave {
                match InstanceId::parse(text) {
                    Ok(instance) => members.push(instance),
                    Err(_) => problems.push(missing(text)),
                }
            }
            waves.push(members);
        }
        let mut inner = self.lock();
        for instance in waves.iter().flatten() {
            match inner.registry.state.instances.get(instance.as_str()) {
                Some(record) if record.organization == organization => {
                    if record.app != app {
                        problems.push(format!(
                            "인스턴스 `{}` 는 앱 `{}` 의 포크라 앱 `{app}` 의 rollout 에 넣지 못합니다. 앱 `{app}` 에서 갈라진 인스턴스만 적어 주세요",
                            instance.as_str(),
                            record.app
                        ));
                    }
                }
                // 다른 팩토리의 인스턴스는 없는 것과 같은 답이다
                _ => problems.push(missing(instance.as_str())),
            }
        }
        let rollout = match Rollout::new(app.to_owned(), update.to_string(), request.change, waves)
        {
            Ok(rollout) if problems.is_empty() => rollout,
            Ok(_) => return Err(Failure::Problems(problems)),
            Err(found) => {
                problems.extend(found.iter().map(wave_text));
                return Err(Failure::Problems(problems));
            }
        };
        // 한 인스턴스는 같은 앱의 열린 rollout 하나에만 든다
        for (id, record) in &inner.registry.state.rollouts {
            if record.organization != organization
                || record.rollout.app != app
                || !record.rollout.status.open()
            {
                continue;
            }
            if let Some(busy) = rollout
                .progress
                .keys()
                .find(|instance| record.rollout.contains(instance))
            {
                return Err(Failure::Conflict(format!(
                    "인스턴스 `{}` 는 이미 열린 rollout `{id}` 에 들어 있습니다. 한 인스턴스는 같은 앱의 열린 rollout 하나에만 듭니다. 그 rollout 이 끝나거나 거둔 뒤에 넣어 주세요",
                    busy.as_str()
                )));
            }
        }
        for instance in rollout.progress.keys() {
            self.sources
                .fetch_upstream(instance, &repository, &update)
                .map_err(internal)?;
        }
        let id = fresh_id('r')?.as_str().to_owned();
        let made = report(&id, &rollout);
        inner.registry.state.rollouts.insert(
            id,
            RolloutRecord {
                organization: organization.to_owned(),
                rollout,
            },
        );
        inner.registry.save().map_err(Failure::Internal)?;
        Ok(made)
    }

    /// rollout 하나(service key). 다른 팩토리의 것은 없는 것으로 답한다.
    pub fn rollout(&self, organization: &str, id: &str) -> Outcome<RolloutReport> {
        let mut inner = self.lock();
        let record = Self::owned_rollout(&mut inner, organization, id)?;
        Ok(report(id, &record.rollout))
    }

    /// 포크의 머리에 업데이트를 기계적으로 합친다(service key). 충돌하면 포크를 건드리지 않고 충돌한 파일의 이름만 돌려준다.
    pub fn apply_update(
        &self,
        organization: &str,
        id: &str,
        instance: &InstanceId,
    ) -> Outcome<ApplyReport> {
        let mut inner = self.lock();
        let rollout = Self::owned_rollout(&mut inner, organization, id)?
            .rollout
            .clone();
        if !rollout.status.open() {
            return Err(Failure::Conflict(refusal_text(&Refusal::Closed {
                status: rollout.status,
            })));
        }
        if !rollout.contains(instance) {
            return Err(Failure::NotFound);
        }
        let update = Commit::parse(&rollout.update)
            .ok_or_else(|| internal("업데이트 commit 을 읽지 못했습니다"))?;
        let merged = self.sources.merge(instance, &update).map_err(internal)?;
        let applied = Event::Applied {
            instance: instance.clone(),
        };
        Ok(match merged {
            Merged::Merged(commit) => {
                Self::record(&mut inner, id, &[applied])?;
                ApplyReport {
                    applied: true,
                    commit: Some(commit.to_string()),
                    conflicts: Vec::new(),
                }
            }
            Merged::Already(commit) => {
                // 이미 담고 있다. 아직 적히지 않았을 때만 적는다(앞의 프리뷰와 검사를 지우지 않는다)
                if rollout.progress.get(instance) == Some(&Progress::Waiting) {
                    Self::record(&mut inner, id, &[applied])?;
                }
                ApplyReport {
                    applied: true,
                    commit: Some(commit.to_string()),
                    conflicts: Vec::new(),
                }
            }
            Merged::Conflicts(files) => ApplyReport {
                applied: false,
                commit: None,
                conflicts: files,
            },
        })
    }

    /// 멈춘 rollout 을 다시 연다(service key). 실패한 인스턴스는 처음부터 다시 지난다.
    pub fn resume_rollout(&self, organization: &str, id: &str) -> Outcome<RolloutReport> {
        self.decide(organization, id, &Event::Resume)
    }

    /// rollout 을 거둔다(service key). 아직 오르지 않은 곳은 그대로 남는다.
    pub fn cancel_rollout(&self, organization: &str, id: &str) -> Outcome<RolloutReport> {
        let made = self.decide(organization, id, &Event::Cancel)?;
        for instance in made.instances.iter() {
            if let Ok(instance) = InstanceId::parse(&instance.instance) {
                // 묶음에 담던 업데이트를 뺀다. 합친 코드는 그대로다
                let _ = self.sources.clear_update(&instance);
            }
        }
        Ok(made)
    }

    fn decide(&self, organization: &str, id: &str, event: &Event) -> Outcome<RolloutReport> {
        let mut inner = self.lock();
        let record = Self::owned_rollout(&mut inner, organization, id)?;
        let next = record
            .rollout
            .step(event)
            .map_err(|refusal| Failure::Conflict(refusal_text(&refusal)))?;
        record.rollout = next;
        let made = report(id, &record.rollout);
        inner.registry.save().map_err(Failure::Internal)?;
        Ok(made)
    }

    /// 이 인스턴스가 든 열린 rollout 의 진행(토큰). 없으면 `None` 이다. 다른 인스턴스는 싣지 않는다.
    pub fn instance_rollout(&self, instance: &InstanceId) -> Outcome<Option<AgentRollout>> {
        let inner = self.lock();
        Ok(inner
            .registry
            .state
            .rollouts
            .iter()
            .find(|(_, record)| record.rollout.status.open() && record.rollout.contains(instance))
            .map(|(id, record)| AgentRollout {
                rollout: id.clone(),
                update: record.rollout.update.clone(),
                change: record.rollout.change,
                halted: record.rollout.status == Status::Halted,
                progress: record
                    .rollout
                    .progress
                    .get(instance)
                    .copied()
                    .unwrap_or(Progress::Waiting),
            }))
    }
}
