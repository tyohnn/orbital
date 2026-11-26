//! 레이어가 기억하는 것의 모양. 어느 인스턴스가 어느 조직의 것이고 어느 기계에 놓였는지, release 마다 검사가 어떻게 끝났는지,
//! 운영에 무엇이 올라 있는지, rollout 이 어디까지 갔는지.
//!
//! 적고 읽는 일은 [`crate::records`] 가 control database 에 한다. 여기의 타입은 그 줄의 몸(jsonb)이고, [`State`] 는 옛 기록 파일
//! (`registry.json`)의 모양이다. 옛 파일은 처음 뜰 때 한 번 옮긴다.

use std::collections::BTreeMap;

use orbital_core::history::Rehearsal;
use orbital_core::manifest::Manifest;
use orbital_core::release::{Conformed, Rehearsed};
use orbital_core::rollout::Rollout;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub commit: String,
    /// 프리뷰 DB 에서 권한 검사가 찾은 어긋남의 수.
    pub access_findings: usize,
    pub rehearsal: Rehearsed,
    /// 선언이 밖에서 넣는다고 적은 비밀의 이름(`[secrets] external`). 에이전트가 요청할 수 있는 이름을 가른다.
    #[serde(default)]
    pub external: Vec<String>,
    /// 위쪽의 적합성 테스트가 이 release 의 프리뷰에서 어떻게 끝났는가.
    #[serde(default)]
    pub conformance: Conformed,
    /// 리허설의 숫자(걸린 시간 · 멈춘 자리 · 표마다의 행 수). 리허설을 돌려 마이그레이션이 있었을 때만 있다. 이력의 승격 줄에 옮긴다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsed: Option<Rehearsal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionRecord {
    pub release: String,
    pub previous: Option<String>,
    /// 이 release 를 올리기 직전의 DB 를 떠 둔 것.
    pub restore_point: Option<String>,
    /// 서명된 신원의 열쇠(hex). control database 에는 봉인한 글로 적는다(열쇠가 없는 개발용 레이어만 평문).
    pub identity_key: String,
    /// 레이어가 만든 비밀. 승격해도 바뀌지 않아야 로그인이 풀리지 않는다. control database 에는 봉인한 글로 적는다.
    #[serde(default)]
    pub generated: BTreeMap<String, String>,
    /// 마지막으로 되살리기가 남긴 되돌릴 지점(database 의 이름). 이것이 `restore_point` 와 같을 때만 되살리기를 무른다.
    /// 승격하면 `restore_point` 가 그 승격의 것으로 바뀌어 무르지 못한다(이 칸은 까닭을 알리려고 남긴다).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<String>,
    /// 하위 도메인을 쓰지 않는 레이어에서 운영의 router 가 듣던 포트. 다시 뜰 때 먼저 잡아 주소가 바뀌지 않게 한다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// 운영의 router 의 바깥 주소. 다른 기계의 관리 서버가 운영의 모습과 Google 의 콜백을 답할 때 쓴다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// 운영의 선언. 다른 기계의 관리 서버가 코드 저장소 없이 사용자 · 비밀 · 운영의 모습을 다룰 때 쓴다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    /// 이 release 가 운영에 오른 때(유닉스 초). 이 칸을 적기 전에 오른 운영은 모른다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_at: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub organization: String,
    pub app: String,
    /// 인스턴스가 놓인 기계. 코드 저장소 · 빌드 폴더 · 프로세스가 그 기계에 있다. control database 의 열에서 읽는다.
    #[serde(skip)]
    pub machine: String,
    #[serde(default)]
    pub releases: BTreeMap<String, ReleaseRecord>,
    #[serde(default)]
    pub production: Option<ProductionRecord>,
    /// 에이전트가 승격을 요청한 release. 사람의 승인을 기다린다.
    #[serde(default)]
    pub promotion_requested: Option<String>,
    /// 승격을 요청한 때와 그 작업의 식별자(토큰의 sha256 앞 16바이트). 이력의 승격 줄에 옮긴다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_requested_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_requested_by: Option<String>,
    /// 인스턴스가 갈라진 스캐폴드의 버전(태그). 이 칸을 적기 전에 선 인스턴스는 모른다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 프리뷰가 쓰는 database 의 식별자. 관리 서버가 다시 뜨면 프리뷰는 되살리지 않고 이것으로 남은 database 를 걷는다.
    #[serde(default)]
    pub preview: Option<String>,
    /// 운영의 일정마다(`Schedule::key`) 다음 때와 마지막 실행. 옛 기록 파일에서 옮길 때만 읽는다.
    /// control database 에서는 `schedule` 표에 따로 있다([`crate::records::Records::schedules`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schedules: BTreeMap<String, ScheduleRecord>,
}

/// 일정 하나의 기록.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRecord {
    /// 다음에 부를 때(유닉스 초).
    pub next_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<ScheduleRun>,
}

/// 일정을 한 번 부른 것. 숫자와 갈래만 있다(앱의 답의 본문은 적지 않는다).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleRun {
    /// 이번에 맞춘 때. 레이어가 내려가 있어 놓쳤으면 놓친 때 가운데 마지막 것이다.
    pub due_at: u64,
    /// 실제로 부른 때.
    pub started_at: u64,
    /// `running` · `ok`(2xx) · `failed`(그 밖의 답) · `unreachable`(깨우지 못함 · 닿지 못함) · `timed_out`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub millis: Option<u64>,
}

/// rollout 하나. 어느 팩토리의 것인지와 core 가 판정하는 진행.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutRecord {
    pub organization: String,
    pub rollout: Rollout,
}

/// 옛 기록 파일(`registry.json`)의 모양.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub instances: BTreeMap<String, InstanceRecord>,
    /// rollout 의 식별자마다. 끝났거나 거둔 것도 남긴다.
    #[serde(default)]
    pub rollouts: BTreeMap<String, RolloutRecord>,
}
