//! 레이어가 기억하는 것. 어느 인스턴스가 어느 조직의 것인지, release 마다 검사가 어떻게 끝났는지, 운영에 무엇이 올라 있는지.
//!
//! 지금은 파일 하나(JSON)에 적는다. 서버가 하나일 때의 모양이고, 서버가 여럿이 되기 전에 DB 로 옮긴다.
//! 파일은 레이어의 폴더 안에 있고 주인만 읽는다. 인스턴스마다의 서명 열쇠가 여기에 있다.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionRecord {
    pub release: String,
    pub previous: Option<String>,
    /// 이 release 를 올리기 직전의 DB 를 떠 둔 것.
    pub restore_point: Option<String>,
    /// 서명된 신원의 열쇠(hex).
    pub identity_key: String,
    /// 레이어가 만든 비밀. 승격해도 바뀌지 않아야 로그인이 풀리지 않는다.
    #[serde(default)]
    pub generated: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub organization: String,
    pub app: String,
    #[serde(default)]
    pub releases: BTreeMap<String, ReleaseRecord>,
    #[serde(default)]
    pub production: Option<ProductionRecord>,
    /// 에이전트가 승격을 요청한 release. 사람의 승인을 기다린다.
    #[serde(default)]
    pub promotion_requested: Option<String>,
    /// 프리뷰가 쓰는 database 의 식별자. 관리 서버가 다시 뜨면 프리뷰는 되살리지 않고 이것으로 남은 database 를 걷는다.
    #[serde(default)]
    pub preview: Option<String>,
}

/// rollout 하나. 어느 팩토리의 것인지와 core 가 판정하는 진행.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutRecord {
    pub organization: String,
    pub rollout: Rollout,
}

/// service key 한 줄. 비밀은 두지 않고 sha256 만 둔다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    /// 사람이 붙인 이름(「배포 서버」 같은).
    pub label: String,
    /// 비밀의 sha256(hex).
    pub digest: String,
    pub created_at: u64,
    /// 폐기한 시각. 폐기한 키는 다음 요청부터 거절된다.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

/// 팩토리 하나. 운영자 키로 만들고, 그 뒤로는 제 service key 로 키를 다룬다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationRecord {
    pub label: String,
    pub created_at: u64,
    /// 만든 차례대로. 폐기한 키도 남긴다.
    #[serde(default)]
    pub keys: Vec<KeyRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// API 로 만든 팩토리. 환경 변수(`ORBITAL_SERVICE_KEYS`)의 조직은 여기에 없다.
    #[serde(default)]
    pub organizations: BTreeMap<String, OrganizationRecord>,
    #[serde(default)]
    pub instances: BTreeMap<String, InstanceRecord>,
    /// rollout 의 식별자마다. 끝났거나 거둔 것도 남긴다.
    #[serde(default)]
    pub rollouts: BTreeMap<String, RolloutRecord>,
}

pub struct Registry {
    path: PathBuf,
    pub state: State,
}

impl Registry {
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "레이어의 기록을 읽지 못했습니다".to_owned())?,
            Err(_) => State::default(),
        };
        Ok(Self { path, state })
    }

    /// 기록을 파일에 적는다. 옆에 쓰고 이름을 바꿔서, 쓰다가 멈춰도 앞의 기록이 남는다.
    pub fn save(&self) -> Result<(), String> {
        let failed = || "레이어의 기록을 적지 못했습니다".to_owned();
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| failed())?;
        let beside = self.path.with_extension("json.writing");
        fs::write(&beside, bytes).map_err(|_| failed())?;
        fs::set_permissions(&beside, fs::Permissions::from_mode(0o600)).map_err(|_| failed())?;
        fs::rename(&beside, &self.path).map_err(|_| failed())
    }
}
