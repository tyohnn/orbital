//! 금고. 밖에서 넣는 비밀(`[secrets] external`)의 값을 인스턴스와 단계(프리뷰 · 운영)마다 봉인해 둔다.
//!
//! 값은 봉인한 글로만 파일(`vault.json`, 주인만 읽음)에 있다. 봉인에는 조직 · 인스턴스 · 단계 · 이름을 함께 묶어([`secret_binding`]),
//! 봉인된 글을 다른 자리에 옮겨 심으면 풀리지 않는다. 열쇠(`ORBITAL_SEAL_KEY`)가 없는 레이어에서는 값을 넣지 못한다.
//!
//! 값이 들어오는 길은 둘이다(service key 로 바로 넣기, 사람의 입력 표). 나가는 길은 앱의 환경 변수 하나뿐이다. 값을 돌려주는 API 는 없다.
//! 에이전트의 요청과 입력 표도 여기에 적는다. 입력 표는 sha256 으로만 둔다.
//!
//! 판정(값의 한도, 빠진 이름, 입력 표를 받을지)은 core 의 `secrets` 가 한다. 여기서는 봉인하고 적고 읽는다.
//! 레이어의 큰 자물쇠와 따로 잠가, 자는 서비스를 깨울 때(값을 읽을 때) 승격이 끝나기를 기다리지 않게 한다.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Mutex;

use orbital_core::name::{InstanceId, SecretName};
use orbital_core::secrets::{
    Entry, EntryRefusal, Place, Stage, ValueProblem, judge_entry, judge_value,
};
use orbital_core::sweep::LEFTOVER_RETENTION;
use serde::{Deserialize, Serialize};

use crate::seal::{SealKey, open, seal, secret_binding};

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

impl Slots {
    fn slot(&mut self, stage: Stage) -> &mut Option<Sealed> {
        match stage {
            Stage::Preview => &mut self.preview,
            Stage::Production => &mut self.production,
        }
    }

    fn get(&self, stage: Stage) -> Option<&Sealed> {
        match stage {
            Stage::Preview => self.preview.as_ref(),
            Stage::Production => self.production.as_ref(),
        }
    }
}

/// 에이전트의 요청 하나. 값이 아니라 까닭만 담는다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requested {
    pub reason: String,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    organization: String,
    entry: Entry,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
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

/// 금고가 하지 못한 까닭. 문구에 값을 싣지 않는다.
#[derive(Debug)]
pub enum VaultError {
    /// 레이어에 봉인의 열쇠가 없다.
    NoSealKey,
    Internal(String),
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
    path: PathBuf,
    seal: Option<SealKey>,
    stored: Mutex<Stored>,
}

impl Vault {
    /// 파일을 읽는다. 없으면 빈 금고다.
    pub fn open(path: PathBuf, seal: Option<SealKey>) -> Result<Self, String> {
        // 없는 파일만 빈 금고로 본다. 읽지 못한 금고를 빈 것으로 보면 다음에 적을 때 있던 값을 덮어쓴다
        let stored = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "비밀의 금고를 읽지 못했습니다".to_owned())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Stored::default(),
            Err(_) => return Err("비밀의 금고를 읽지 못했습니다".to_owned()),
        };
        Ok(Self {
            path,
            seal,
            stored: Mutex::new(stored),
        })
    }

    /// 값을 넣을 수 있는가(봉인의 열쇠가 있는가).
    pub fn can_seal(&self) -> bool {
        self.seal.is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Stored> {
        self.stored
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save(&self, stored: &Stored) -> Result<(), VaultError> {
        let failed = || VaultError::Internal("비밀의 금고를 적지 못했습니다".to_owned());
        let bytes = serde_json::to_vec_pretty(stored).map_err(|_| failed())?;
        let beside = self.path.with_extension("json.writing");
        // 처음부터 주인만 읽게 만든다. 먼저 쓰고 권한을 좁히면 그 사이에 남이 읽을 수 있다
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&beside)
            .map_err(|_| failed())?;
        file.write_all(&bytes).map_err(|_| failed())?;
        // 앞서 남은 임시 파일이 넓은 권한으로 있었을 수 있다
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| failed())?;
        drop(file);
        fs::rename(&beside, &self.path).map_err(|_| failed())
    }

    fn binding(organization: &str, place: &Place) -> String {
        secret_binding(
            organization,
            place.instance.as_str(),
            place.stage.as_str(),
            place.name.as_str(),
        )
    }

    fn unseal(&self, organization: &str, place: &Place, sealed: &Sealed) -> Option<SecretValue> {
        open(
            self.seal.as_ref()?,
            &Self::binding(organization, place),
            &sealed.sealed,
        )
        .map(SecretValue)
    }

    /// 봉인해 자리에 둔다. 적지 못하면 메모리도 그대로 둔다.
    fn put_in(
        &self,
        stored: &mut Stored,
        organization: &str,
        place: &Place,
        value: &SecretValue,
        at: u64,
    ) -> Result<(), VaultError> {
        let key = self.seal.as_ref().ok_or(VaultError::NoSealKey)?;
        let sealed = seal(key, &Self::binding(organization, place), &value.0).ok_or_else(|| {
            VaultError::Internal("난수를 읽지 못해 봉인하지 못했습니다".to_owned())
        })?;
        let slots = stored
            .values
            .entry(place.instance.as_str().to_owned())
            .or_default()
            .entry(place.name.as_str().to_owned())
            .or_default();
        *slots.slot(place.stage) = Some(Sealed { sealed, set_at: at });
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
        let mut stored = self.lock();
        let before = stored.values.get(place.instance.as_str()).cloned();
        self.put_in(&mut stored, organization, place, value, at)?;
        if let Err(error) = self.save(&stored) {
            Self::restore(&mut stored, &place.instance, before);
            return Err(error);
        }
        Ok(())
    }

    fn restore(
        stored: &mut Stored,
        instance: &InstanceId,
        before: Option<BTreeMap<String, Slots>>,
    ) {
        match before {
            Some(before) => stored.values.insert(instance.as_str().to_owned(), before),
            None => stored.values.remove(instance.as_str()),
        };
    }

    /// 값을 지운다. 없었으면 `false` 다.
    pub fn remove(&self, place: &Place) -> Result<bool, VaultError> {
        let mut stored = self.lock();
        let before = stored.values.get(place.instance.as_str()).cloned();
        let removed = stored
            .values
            .get_mut(place.instance.as_str())
            .and_then(|names| names.get_mut(place.name.as_str()))
            .and_then(|slots| slots.slot(place.stage).take())
            .is_some();
        if !removed {
            return Ok(false);
        }
        if let Err(error) = self.save(&stored) {
            Self::restore(&mut stored, &place.instance, before);
            return Err(error);
        }
        Ok(true)
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
        let stored = self.lock();
        let Some(names) = stored.values.get(instance.as_str()) else {
            return BTreeMap::new();
        };
        let mut found = BTreeMap::new();
        for (name, slots) in names {
            let Ok(name) = SecretName::parse(name) else {
                continue;
            };
            let mut filled = Filled::default();
            for stage in Stage::ALL {
                let place = Place {
                    instance: instance.clone(),
                    name: name.clone(),
                    stage,
                };
                let at = slots
                    .get(stage)
                    .filter(|sealed| self.unseal(organization, &place, sealed).is_some())
                    .map(|sealed| sealed.set_at);
                match stage {
                    Stage::Preview => filled.preview = at,
                    Stage::Production => filled.production = at,
                }
            }
            found.insert(name, filled);
        }
        found
    }

    /// 앱의 환경에 실을 값. `names` 가운데 이 단계의 칸에 풀리는 값이 있는 것만 돌려준다. 다른 단계의 칸으로 대신하지 않는다.
    pub fn values(
        &self,
        organization: &str,
        instance: &InstanceId,
        stage: Stage,
        names: &[SecretName],
    ) -> Vec<(SecretName, SecretValue)> {
        let stored = self.lock();
        let Some(slots) = stored.values.get(instance.as_str()) else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|name| {
                let sealed = slots.get(name.as_str())?.get(stage)?;
                let place = Place {
                    instance: instance.clone(),
                    name: name.clone(),
                    stage,
                };
                Some((name.clone(), self.unseal(organization, &place, sealed)?))
            })
            .collect()
    }

    /// 에이전트의 요청을 적는다. 같은 이름의 앞 요청은 새 것으로 바뀐다.
    pub fn request(
        &self,
        instance: &InstanceId,
        name: &SecretName,
        reason: &str,
        at: u64,
    ) -> Result<(), VaultError> {
        let mut stored = self.lock();
        let before = stored.requests.get(instance.as_str()).cloned();
        stored
            .requests
            .entry(instance.as_str().to_owned())
            .or_default()
            .insert(
                name.as_str().to_owned(),
                Requested {
                    reason: reason.to_owned(),
                    at,
                },
            );
        if let Err(error) = self.save(&stored) {
            match before {
                Some(before) => stored.requests.insert(instance.as_str().to_owned(), before),
                None => stored.requests.remove(instance.as_str()),
            };
            return Err(error);
        }
        Ok(())
    }

    pub fn requests(&self, instance: &InstanceId) -> BTreeMap<String, Requested> {
        self.lock()
            .requests
            .get(instance.as_str())
            .cloned()
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
        let mut stored = self.lock();
        stored
            .entries
            .retain(|_, kept| now < kept.entry.expires_at.saturating_add(LEFTOVER_RETENTION));
        stored.entries.insert(
            digest.to_owned(),
            StoredEntry {
                organization: organization.to_owned(),
                entry,
            },
        );
        self.save(&stored)
    }

    /// 입력 표로 값을 넣는다. 표의 판정 → 값의 판정 → 봉인해 넣고 표를 쓴 것으로 적기를 한 자물쇠 안에서 한다.
    ///
    /// `wanted` 의 이름과 단계는 본문이 적은 것이다. 적지 않았으면 표의 것이고, 다르면 core 가 거절한다.
    pub fn redeem(
        &self,
        digest: &str,
        wanted: (Option<SecretName>, Option<Stage>),
        value: &SecretValue,
        at: u64,
    ) -> Result<Place, RedeemError> {
        let mut stored = self.lock();
        let found = stored
            .entries
            .get(digest)
            .cloned()
            .ok_or(RedeemError::Unknown)?;
        let place = Place {
            instance: found.entry.place.instance.clone(),
            name: wanted.0.unwrap_or_else(|| found.entry.place.name.clone()),
            stage: wanted.1.unwrap_or(found.entry.place.stage),
        };
        judge_entry(&found.entry, &place, at).map_err(RedeemError::Refused)?;
        let problems = judge_value(&value.0);
        if !problems.is_empty() {
            return Err(RedeemError::Value(problems));
        }
        let before = stored.values.get(place.instance.as_str()).cloned();
        self.put_in(&mut stored, &found.organization, &place, value, at)
            .map_err(RedeemError::Vault)?;
        if let Some(kept) = stored.entries.get_mut(digest) {
            kept.entry.used = true;
        }
        if let Err(error) = self.save(&stored) {
            Self::restore(&mut stored, &place.instance, before);
            if let Some(kept) = stored.entries.get_mut(digest) {
                kept.entry.used = false;
            }
            return Err(RedeemError::Vault(error));
        }
        Ok(place)
    }

    /// 인스턴스의 값 · 요청 · 입력 표를 모두 지운다.
    pub fn forget(&self, instance: &InstanceId) -> Result<(), VaultError> {
        let mut stored = self.lock();
        stored.values.remove(instance.as_str());
        stored.requests.remove(instance.as_str());
        stored
            .entries
            .retain(|_, kept| &kept.entry.place.instance != instance);
        self.save(&stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 읽지_못한_금고를_빈_금고로_보지_않는다() {
        // 폴더는 파일처럼 읽히지 않는다. 없는 파일만 빈 금고다
        let folder = std::env::temp_dir().join(format!("orbital-vault-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        assert!(Vault::open(folder.clone(), None).is_err());
        assert!(Vault::open(folder.join("vault.json"), None).is_ok());
        fs::remove_dir_all(&folder).unwrap();
    }

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
