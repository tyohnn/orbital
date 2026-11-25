//! 백업과 복구의 판정. 시점을 덮는 기반 백업 고르기, 되살릴 수 있는 시점인지, 복구 훈련의 판정, 훈련이 낡았는지, 지울 백업 고르기.
//!
//! 기반 백업을 뜨고 WAL 을 보관하고 클러스터를 되살리는 일은 `orbital-backup` 이 한다. 여기서는 그 결과(시각 · WAL 의 이름)를 받아 판정만 한다.
//! 백업의 시각은 DB 의 시계로 잰 유닉스 밀리초다. 시점 복구가 견주는 것이 DB 가 적은 commit 의 시각이기 때문이다.
//! 훈련의 기록과 「낡았는가」는 레이어의 시계(유닉스 초)로 잰다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 마지막으로 통과한 훈련이 이만큼(초)을 넘기면 낡은 것이다. 여드레. 매주 도는 훈련이 한 번 늦어도 하루의 틈이 있다.
pub const DRILL_FRESH_FOR: u64 = 8 * 24 * 60 * 60;

/// 기반 백업을 두는 기본 기간(초). 14일.
pub const KEEP_FOR: u64 = 14 * 24 * 60 * 60;

/// 보관한 WAL 조각 하나의 자리. 이름(`TTTTTTTTXXXXXXXXYYYYYYYY`)에서 읽는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WalSegment {
    pub timeline: u32,
    /// 타임라인 안에서 몇 번째 조각인가. 조각의 크기에 따라 이름의 가운데와 끝을 이어 센다.
    pub number: u64,
}

impl WalSegment {
    /// WAL 조각의 이름을 읽는다. 대문자 hex 24자가 아니면(`.history` · `.backup` · `.partial`) 조각이 아니다.
    /// `segment_bytes` 는 클러스터의 `wal_segment_size` 다.
    pub fn parse(name: &str, segment_bytes: u64) -> Option<Self> {
        let per_log = Self::per_log(segment_bytes)?;
        if name.len() != 24
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        {
            return None;
        }
        let field = |range: std::ops::Range<usize>| u64::from_str_radix(&name[range], 16).ok();
        let timeline = u32::try_from(field(0..8)?).ok()?;
        let (log, segment) = (field(8..16)?, field(16..24)?);
        if segment >= per_log {
            return None;
        }
        Some(Self {
            timeline,
            number: log.checked_mul(per_log)?.checked_add(segment)?,
        })
    }

    /// 이름의 가운데 하나가 몇 조각인가. 4GB 를 조각의 크기로 나눈 것이다.
    fn per_log(segment_bytes: u64) -> Option<u64> {
        (segment_bytes > 0 && segment_bytes.is_power_of_two())
            .then(|| 0x1_0000_0000u64 / segment_bytes)
            .filter(|per_log| *per_log > 0)
    }

    /// 조각의 이름. [`WalSegment::parse`] 의 반대다.
    pub fn name(&self, segment_bytes: u64) -> String {
        let per_log = Self::per_log(segment_bytes).unwrap_or(1);
        format!(
            "{:08X}{:08X}{:08X}",
            self.timeline,
            self.number / per_log,
            self.number % per_log
        )
    }
}

/// 기반 백업 하나. 이 백업으로 되살리면 `finished_at` 뒤의 어느 시점으로든 갈 수 있다(WAL 이 닿는 데까지).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseBackup {
    pub id: String,
    /// 뜨기 시작한 때(유닉스 밀리초, DB 의 시계).
    pub started_at: u64,
    /// 다 뜬 때. 이 앞의 시점으로는 이 백업에서 되살리지 못한다.
    pub finished_at: u64,
    /// 이 백업이 되살리기 시작하는 WAL 조각의 이름.
    pub start_wal: String,
    /// 클러스터의 WAL 조각 크기(바이트).
    pub segment_bytes: u64,
}

/// 「이 시각까지 쓴 것은 보관한 WAL 에 들었다」는 표시. 레이어가 commit 하나를 적고 WAL 을 넘겨 보관을 확인한 뒤에 적는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    /// 유닉스 밀리초(DB 의 시계). 이 시각 뒤에 commit 이 하나 있고, 그것까지 보관됐다.
    pub at: u64,
    /// 그 commit 이 든 WAL 조각의 이름.
    pub wal: String,
}

/// 보관한 WAL 의 모습.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archive {
    /// 보관 폴더에 있는 파일의 이름. 조각이 아닌 것(`.history` 같은)이 섞여 있어도 된다.
    pub files: Vec<String>,
    /// 마지막으로 보관을 확인한 표시. 없으면 어디까지 보관됐는지 모른다.
    pub sealed: Option<Seal>,
}

/// 그 시점으로 되살리지 못하는 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RestoreRefusal {
    /// 기반 백업이 하나도 없다.
    NoBackup,
    /// 가장 오랜 기반 백업이 다 뜬 때보다 앞선 시점이다.
    BeforeOldestBackup { oldest: u64 },
    /// 보관을 확인한 WAL 이 그 시점에 닿지 않는다.
    BeyondArchive { archived_until: Option<u64> },
    /// 기반 백업에서 그 시점까지 이어져야 할 WAL 조각이 보관 폴더에 없다.
    MissingWal { segment: String },
}

/// 그 시점을 덮는 가장 새 기반 백업. 다 뜬 때가 그 시점과 같거나 앞서야 한다.
pub fn cover(backups: &[BaseBackup], at: u64) -> Option<&BaseBackup> {
    backups
        .iter()
        .filter(|backup| backup.finished_at <= at)
        .max_by_key(|backup| backup.finished_at)
}

/// 그 시점(유닉스 밀리초)으로 되살릴 수 있는지 본다. 되살릴 수 있으면 쓸 기반 백업을 돌려준다.
pub fn judge_restore<'a>(
    backups: &'a [BaseBackup],
    archive: &Archive,
    at: u64,
) -> Result<&'a BaseBackup, RestoreRefusal> {
    let oldest = backups
        .iter()
        .map(|backup| backup.finished_at)
        .min()
        .ok_or(RestoreRefusal::NoBackup)?;
    let backup = cover(backups, at).ok_or(RestoreRefusal::BeforeOldestBackup { oldest })?;
    let sealed = archive
        .sealed
        .as_ref()
        .filter(|sealed| at <= sealed.at)
        .ok_or_else(|| RestoreRefusal::BeyondArchive {
            archived_until: archive.sealed.as_ref().map(|sealed| sealed.at),
        })?;
    // 기반 백업이 시작하는 조각부터 표시의 조각까지 하나도 빠지지 않아야 한다
    let size = backup.segment_bytes;
    let missing = |segment: String| RestoreRefusal::MissingWal { segment };
    let start = WalSegment::parse(&backup.start_wal, size)
        .ok_or_else(|| missing(backup.start_wal.clone()))?;
    let end = WalSegment::parse(&sealed.wal, size).ok_or_else(|| missing(sealed.wal.clone()))?;
    let present: std::collections::BTreeSet<WalSegment> = archive
        .files
        .iter()
        .filter_map(|name| WalSegment::parse(name, size))
        .collect();
    if end.timeline != start.timeline || end.number < start.number {
        return Err(missing(sealed.wal.clone()));
    }
    for number in start.number..=end.number {
        let segment = WalSegment {
            timeline: start.timeline,
            number,
        };
        if !present.contains(&segment) {
            return Err(missing(segment.name(size)));
        }
    }
    Ok(backup)
}

/// 데이터베이스 하나의 지문. 이름과 숫자만 있고 행의 값은 없다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// 스키마(표 · 열 · 제약 · 색인 · 정책 · 함수)의 모양을 이어 붙인 것의 sha256(hex).
    pub schema: String,
    /// `스키마.표` 마다의 행 수.
    pub tables: BTreeMap<String, i64>,
}

/// 복구 훈련의 확인 하나.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum Check {
    /// 옆에 되살린 클러스터가 떠서 접속을 받는다.
    ClusterStarted,
    /// 그 시점 앞에 적은 훈련의 표식이 있다.
    MarkBeforeKept,
    /// 그 시점 뒤에 적은 훈련의 표식이 없다.
    MarkAfterGone,
    /// 인스턴스의 database 가 있다.
    Database { instance: String },
    /// 인스턴스의 database 의 지문이 그 시점에 떠 둔 것과 같다.
    Fingerprint { instance: String },
    /// 인스턴스의 역할이 모두 있다.
    Roles { instance: String },
    /// database 하나를 운영 클러스터의 임시 database 로 옮겼고 지문이 같다.
    Moved { database: String },
    /// 기반 백업에 묶은 레이어의 기록이 풀리고 읽힌다.
    Records,
}

/// 확인 하나의 결과.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checked {
    #[serde(flatten)]
    pub check: Check,
    pub passed: bool,
}

/// 훈련의 판정.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum DrillVerdict {
    Passed,
    /// 어긋난 확인. 확인이 하나도 없었으면 비어 있다(본 것이 없으니 통과가 아니다).
    Failed {
        failed: Vec<Check>,
    },
}

/// 훈련을 판정한다. 확인이 모두 통과해야 통과다. 확인이 하나도 없으면 통과가 아니다.
pub fn judge_drill(checks: &[Checked]) -> DrillVerdict {
    let failed: Vec<Check> = checks
        .iter()
        .filter(|checked| !checked.passed)
        .map(|checked| checked.check.clone())
        .collect();
    if checks.is_empty() || !failed.is_empty() {
        DrillVerdict::Failed { failed }
    } else {
        DrillVerdict::Passed
    }
}

/// 훈련이 확인까지 가지 못하고 멈춘 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStep {
    /// 기반 백업을 뜬다(하나도 없을 때).
    BaseBackup,
    /// 훈련의 표식을 적고 지문을 뜬다.
    Mark,
    /// WAL 을 넘겨 보관을 확인한다.
    Seal,
    /// 옆에 클러스터를 되살린다.
    Recover,
    /// 옆의 클러스터와 파일을 지운다.
    Clean,
}

/// 되살린 클러스터가 서지 못한 까닭. Postgres 의 기록에서 갈래만 읽는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFailure {
    /// WAL 을 끝까지 돌렸는데 그 시점에 닿지 못했다.
    TargetNotReached,
    /// 이어질 WAL 조각을 읽지 못했다.
    WalMissing,
    /// 그 밖의 까닭으로 뜨지 않았다.
    DidNotStart,
}

/// 훈련이 실패한 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DrillFailure {
    /// 확인이 어긋났다.
    Checks { failed: Vec<Check> },
    /// 되살릴 수 없는 시점이라고 판정했다(백업이 없거나 WAL 이 빠졌다).
    Refused { refusal: RestoreRefusal },
    /// 옆의 클러스터가 서지 못했다.
    Recovery { failure: RecoveryFailure },
    /// 그 단계에서 깨졌다. 갈래만 적는다.
    Step { step: DrillStep },
}

/// 훈련 한 번의 기록. 이름과 숫자만 있다(행의 값 · 표식의 난수 · 경로는 없다).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillRecord {
    /// 훈련을 시작한 때(유닉스 초, 레이어의 시계).
    pub at: u64,
    pub passed: bool,
    pub checks: Vec<Checked>,
    /// 옆에 클러스터를 되살리는 데 걸린 시간(복구 시간).
    pub recovery_millis: u64,
    /// 훈련 전체에 걸린 시간.
    pub drill_millis: u64,
    /// 잃을 수 있는 구간(초). 훈련을 시작한 때 − 마지막으로 보관된 WAL 의 시각. 보관된 것이 없었으면 `null` 이다.
    pub exposure_seconds: Option<u64>,
    /// 견준 인스턴스의 수.
    pub instances: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<DrillFailure>,
}

/// 훈련이 낡았는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "freshness", rename_all = "snake_case")]
pub enum Freshness {
    Fresh,
    /// 한 번도 통과하지 않았다.
    NeverPassed,
    /// 마지막으로 통과한 때에서 [`DRILL_FRESH_FOR`] 를 넘겼다.
    Overdue {
        last_passed_at: u64,
    },
}

impl Freshness {
    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// 마지막으로 통과한 훈련의 시각(유닉스 초)과 지금으로 낡았는지 본다.
pub fn freshness(last_passed_at: Option<u64>, now: u64) -> Freshness {
    match last_passed_at {
        None => Freshness::NeverPassed,
        Some(at) if now.saturating_sub(at) > DRILL_FRESH_FOR => {
            Freshness::Overdue { last_passed_at: at }
        }
        Some(_) => Freshness::Fresh,
    }
}

/// 기록에서 마지막으로 통과한 훈련의 시각.
pub fn last_passed(records: &[DrillRecord]) -> Option<u64> {
    records
        .iter()
        .filter(|record| record.passed)
        .map(|record| record.at)
        .max()
}

/// 지울 것.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pruning {
    /// 지울 기반 백업의 식별자.
    pub backups: Vec<String>,
    /// 이 이름보다 앞선(같은 타임라인의) WAL 조각을 지운다. 남는 가장 오랜 기반 백업이 시작하는 조각이다.
    pub wal_before: Option<String>,
}

/// 보관 기간(밀리초)이 지난 기반 백업과 그것에만 딸린 WAL 을 고른다. 마지막(가장 새) 기반 백업은 언제나 남긴다.
pub fn prune(backups: &[BaseBackup], now: u64, keep_for: u64) -> Pruning {
    let newest = backups
        .iter()
        .enumerate()
        .max_by_key(|(index, backup)| (backup.finished_at, usize::MAX - index))
        .map(|(index, _)| index);
    let mut pruning = Pruning::default();
    let mut oldest_kept: Option<&str> = None;
    for (index, backup) in backups.iter().enumerate() {
        let expired = backup.finished_at.saturating_add(keep_for) < now;
        if expired && Some(index) != newest {
            pruning.backups.push(backup.id.clone());
        } else if oldest_kept.is_none_or(|kept| backup.start_wal.as_str() < kept) {
            oldest_kept = Some(&backup.start_wal);
        }
    }
    pruning.wal_before = oldest_kept.map(str::to_owned);
    pruning
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;

    fn backup(id: &str, finished_at: u64, start_wal: &str) -> BaseBackup {
        BaseBackup {
            id: id.to_owned(),
            started_at: finished_at.saturating_sub(10),
            finished_at,
            start_wal: start_wal.to_owned(),
            segment_bytes: MB,
        }
    }

    fn archive(files: &[&str], sealed_at: u64, wal: &str) -> Archive {
        Archive {
            files: files.iter().map(|name| (*name).to_owned()).collect(),
            sealed: Some(Seal {
                at: sealed_at,
                wal: wal.to_owned(),
            }),
        }
    }

    const W2: &str = "000000010000000000000002";
    const W3: &str = "000000010000000000000003";
    const W4: &str = "000000010000000000000004";
    const W5: &str = "000000010000000000000005";

    #[test]
    fn wal_조각의_이름은_조각의_크기에_따라_이어_센다() {
        // 1MB 조각이면 이름의 가운데 하나가 4096 조각이다
        let last = WalSegment::parse("000000010000000000000FFF", MB).unwrap();
        let next = WalSegment::parse("000000010000000100000000", MB).unwrap();
        assert_eq!(next.number, last.number + 1);
        assert_eq!(
            WalSegment::parse("000000010000000000001000", MB),
            None,
            "1MB 조각에서 끝자리는 0x1000 보다 작다"
        );
        let wrap = WalSegment::parse("000000010000000100000000", 16 * MB).unwrap();
        let before = WalSegment::parse("0000000100000000000000FF", 16 * MB).unwrap();
        assert_eq!(wrap.number, before.number + 1);
        assert_eq!(wrap.name(16 * MB), "000000010000000100000000");
        for name in [
            "00000001.history",
            "000000010000000000000002.00000028.backup",
            "000000010000000000000002.partial",
            "00000001000000000000000g",
        ] {
            assert_eq!(WalSegment::parse(name, MB), None, "{name}");
        }
    }

    #[test]
    fn 복구할_시점을_덮는_가장_새_기반_백업을_고른다() {
        let backups = [
            backup("b1", 1_000, W2),
            backup("b3", 3_000, W4),
            backup("b2", 2_000, W3),
        ];
        assert_eq!(cover(&backups, 2_500).map(|b| b.id.as_str()), Some("b2"));
        // 다 뜬 때와 같은 시점은 그 백업이 덮는다
        assert_eq!(cover(&backups, 3_000).map(|b| b.id.as_str()), Some("b3"));
        assert_eq!(cover(&backups, 2_999).map(|b| b.id.as_str()), Some("b2"));
        assert_eq!(cover(&backups, 999), None);
        let archive = archive(&[W2, W3, W4, W5], 5_000, W5);
        assert_eq!(
            judge_restore(&backups, &archive, 2_500).map(|b| b.id.as_str()),
            Ok("b2")
        );
    }

    #[test]
    fn 가장_오랜_기반_백업보다_앞선_시점으로는_되살리지_못한다() {
        let backups = [backup("b1", 1_000, W2), backup("b2", 2_000, W3)];
        let archive = archive(&[W2, W3, W4], 5_000, W4);
        assert_eq!(
            judge_restore(&backups, &archive, 999),
            Err(RestoreRefusal::BeforeOldestBackup { oldest: 1_000 })
        );
        assert_eq!(
            judge_restore(&backups, &archive, 1_000).map(|b| b.id.as_str()),
            Ok("b1")
        );
        assert_eq!(
            judge_restore(&[], &archive, 1_000),
            Err(RestoreRefusal::NoBackup)
        );
    }

    #[test]
    fn 보관한_wal_이_닿지_않는_시점으로는_되살리지_못한다() {
        let backups = [backup("b1", 1_000, W2)];
        let sealed = archive(&[W2, W3, W4], 4_000, W4);
        assert_eq!(
            judge_restore(&backups, &sealed, 4_001),
            Err(RestoreRefusal::BeyondArchive {
                archived_until: Some(4_000)
            })
        );
        assert!(judge_restore(&backups, &sealed, 4_000).is_ok());
        // 어디까지 보관됐는지 모르면 되살리지 않는다
        let unsealed = Archive {
            files: vec![W2.to_owned()],
            sealed: None,
        };
        assert_eq!(
            judge_restore(&backups, &unsealed, 1_500),
            Err(RestoreRefusal::BeyondArchive {
                archived_until: None
            })
        );
        // 기반 백업에서 표시까지 이어지는 조각이 하나라도 빠지면 되살리지 않는다
        let gap = archive(&[W2, W4, "00000001.history"], 4_000, W4);
        assert_eq!(
            judge_restore(&backups, &gap, 1_500),
            Err(RestoreRefusal::MissingWal {
                segment: W3.to_owned()
            })
        );
    }

    #[test]
    fn 훈련은_확인이_모두_통과해야_통과하고_확인이_없으면_통과가_아니다() {
        let ok = |check| Checked {
            check,
            passed: true,
        };
        assert_eq!(
            judge_drill(&[ok(Check::ClusterStarted), ok(Check::Records)]),
            DrillVerdict::Passed
        );
        assert_eq!(
            judge_drill(&[]),
            DrillVerdict::Failed { failed: Vec::new() }
        );
        let bad = Checked {
            check: Check::Fingerprint {
                instance: "k3f9x2ab".to_owned(),
            },
            passed: false,
        };
        assert_eq!(
            judge_drill(&[ok(Check::ClusterStarted), bad.clone()]),
            DrillVerdict::Failed {
                failed: vec![bad.check]
            }
        );
    }

    #[test]
    fn 마지막으로_통과한_훈련이_여드레를_넘기면_낡은_것이다() {
        let passed = 1_000_000;
        assert_eq!(
            freshness(Some(passed), passed + DRILL_FRESH_FOR),
            Freshness::Fresh
        );
        assert_eq!(
            freshness(Some(passed), passed + DRILL_FRESH_FOR + 1),
            Freshness::Overdue {
                last_passed_at: passed
            }
        );
        assert_eq!(DRILL_FRESH_FOR, 8 * 86_400);
    }

    #[test]
    fn 한_번도_통과하지_않은_레이어는_낡은_것이다() {
        assert_eq!(freshness(None, 0), Freshness::NeverPassed);
        let failed = DrillRecord {
            at: 10,
            passed: false,
            checks: Vec::new(),
            recovery_millis: 0,
            drill_millis: 0,
            exposure_seconds: None,
            instances: 0,
            failure: None,
        };
        assert_eq!(last_passed(&[failed]), None);
        assert_eq!(freshness(last_passed(&[]), 10), Freshness::NeverPassed);
    }

    #[test]
    fn 지문과_훈련의_기록은_json_으로_오간다() {
        let checked = Checked {
            check: Check::Database {
                instance: "k3f9x2ab".to_owned(),
            },
            passed: true,
        };
        assert_eq!(
            serde_json::to_string(&checked).unwrap(),
            r#"{"check":"database","instance":"k3f9x2ab","passed":true}"#
        );
        assert_eq!(
            serde_json::to_string(&Freshness::Overdue { last_passed_at: 7 }).unwrap(),
            r#"{"freshness":"overdue","last_passed_at":7}"#
        );
    }
}
