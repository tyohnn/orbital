//! 거둔 작업의 장부. 작업의 토큰은 서명만으로 확인하므로, 만료 전에 거둔 것은 여기에 적어 두고 요청마다 본다.
//!
//! 장부는 (인스턴스, 작업의 식별자)마다 「언제까지 기억할지」만 둔다. 토큰의 글자는 두지 않는다. 토큰은 길어야 12시간 살므로
//! 거둔 때부터 그만큼 기억하고, 지난 것은 새 줄을 적을 때 걷는다. 파일(`revoked.json`, 주인만 읽음)에 적어 관리 서버가 다시 떠도 거둔 채다.
//! 적을 때는 임시 파일에 쓰고 옮겨 한 번에 바꾼다. 레이어의 기록을 DB 로 옮길 때 이 파일 하나를 표 하나로 옮기면 된다.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Mutex;

use orbital_core::name::InstanceId;

/// 장부의 파일. `ORBITAL_HOME` 아래에 둔다.
pub const REVOKED: &str = "revoked.json";

pub struct Revoked {
    path: PathBuf,
    /// `<인스턴스>/<작업>` → 이 시각(유닉스 초)까지 기억한다.
    entries: Mutex<BTreeMap<String, u64>>,
}

fn key(instance: &InstanceId, session: &str) -> String {
    format!("{}/{session}", instance.as_str())
}

impl Revoked {
    /// 파일을 읽는다. 없으면 빈 장부다. 읽지 못한 장부를 빈 것으로 보지 않는다(거둔 토큰이 되살아난다).
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let entries = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "거둔 작업의 장부를 읽지 못했습니다".to_owned())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err("거둔 작업의 장부를 읽지 못했습니다".to_owned()),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, u64>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 거둔 작업인가.
    pub fn contains(&self, instance: &InstanceId, session: &str) -> bool {
        self.lock().contains_key(&key(instance, session))
    }

    /// 작업을 거둔다. `until` 까지 기억한다. 지난 줄은 함께 걷는다. 적지 못하면 메모리도 그대로 둔다.
    pub fn revoke(
        &self,
        instance: &InstanceId,
        session: &str,
        until: u64,
        now: u64,
    ) -> Result<(), String> {
        let mut entries = self.lock();
        let mut next = entries.clone();
        next.retain(|_, kept| *kept > now);
        next.insert(key(instance, session), until);
        self.save(&next)?;
        *entries = next;
        Ok(())
    }

    /// 인스턴스를 지우면 그 줄을 걷는다.
    pub fn forget(&self, instance: &InstanceId) -> Result<(), String> {
        let mut entries = self.lock();
        let prefix = format!("{}/", instance.as_str());
        let mut next = entries.clone();
        next.retain(|known, _| !known.starts_with(&prefix));
        if next.len() != entries.len() {
            self.save(&next)?;
            *entries = next;
        }
        Ok(())
    }

    fn save(&self, entries: &BTreeMap<String, u64>) -> Result<(), String> {
        let failed = || "거둔 작업의 장부를 적지 못했습니다".to_owned();
        let bytes = serde_json::to_vec_pretty(entries).map_err(|_| failed())?;
        let beside = self.path.with_extension("json.writing");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&beside)
            .map_err(|_| failed())?;
        file.write_all(&bytes).map_err(|_| failed())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| failed())?;
        drop(file);
        fs::rename(&beside, &self.path).map_err(|_| failed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let folder =
            std::env::temp_dir().join(format!("orbital-revoked-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder).unwrap();
        folder
    }

    #[test]
    fn 거둔_작업은_다시_열어도_거둔_채이고_기억할_때가_지난_줄은_새_줄을_적을_때_걷는다() {
        let folder = scratch("ledger");
        let path = folder.join(REVOKED);
        let instance = InstanceId::parse("k3f9x2ab").unwrap();
        let other = InstanceId::parse("k3f9x2abc").unwrap();
        let ledger = Revoked::open(path.clone()).unwrap();
        ledger.revoke(&instance, "s1", 100, 10).unwrap();
        assert!(ledger.contains(&instance, "s1"));
        // 같은 작업의 식별자라도 다른 인스턴스의 것은 아니다
        assert!(!ledger.contains(&other, "s1"));
        let again = Revoked::open(path.clone()).unwrap();
        assert!(again.contains(&instance, "s1"));
        again.revoke(&instance, "s2", 300, 150).unwrap();
        assert!(!again.contains(&instance, "s1"));
        assert!(again.contains(&instance, "s2"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!folder.join("revoked.json.writing").exists());
        again.forget(&instance).unwrap();
        assert!(!Revoked::open(path).unwrap().contains(&instance, "s2"));
        let _ = fs::remove_dir_all(folder);
    }

    #[test]
    fn 읽지_못한_장부를_빈_장부로_보지_않는다() {
        let folder = scratch("broken");
        let path = folder.join(REVOKED);
        fs::write(&path, b"{").unwrap();
        assert!(Revoked::open(path).is_err());
        let _ = fs::remove_dir_all(folder);
    }
}
