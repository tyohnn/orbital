//! release 의 이력. 운영이 어떻게 지금이 되었는지(오른 것 · 되돌려진 것 · 되살린 것 · 무른 것)를 인스턴스마다 한 줄씩 남긴다.
//!
//! 이벤트(`event`)는 일어난 것을 알리고 30일 뒤에 걷는다. 이력은 「누가 요청하고 누가 승인했는지 · 권한이 어떻게 바뀌었는지 ·
//! 리허설의 숫자」를 오래 둔다. 줄의 칸은 [`Entry`] 의 갈래마다 타입으로 정해 두어, 값(비밀 · 행 · 로그의 글 · Postgres 의 문구)이
//! 들어갈 칸이 없다. 권한 변화의 문장(`describe`)과 사람이 붙인 이름표만 글이다.

use serde::{Deserialize, Serialize};

use crate::organization::{LabelProblem, check_label};
use crate::release::{Approver, Change, Conformed, Rehearsed};

/// 인스턴스마다 남기는 이력의 줄 수. 넘으면 오랜 것부터 걷는다.
pub const KEEP: u64 = 500;
/// 한 쪽에 돌려주는 수의 기본값과 상한.
pub const LIST_DEFAULT: u32 = 100;
pub const LIST_MAX: u32 = 500;

/// 리허설의 숫자. 행의 내용은 없다.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Rehearsal {
    pub millis: u64,
    /// 멈춘 마이그레이션의 이름. 통과했으면 없다.
    #[serde(default)]
    pub failed_at: Option<String>,
    /// 멈춘 자리의 SQLSTATE(다섯 글자의 코드). 오류의 문구는 싣지 않는다.
    #[serde(default)]
    pub sqlstate: Option<String>,
    /// 표마다의 행 수(앞, 뒤).
    #[serde(default)]
    pub tables: Vec<TableRows>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRows {
    pub table: String,
    pub before: Option<i64>,
    pub after: Option<i64>,
}

/// 승격 한 번(올랐거나 되돌려졌다).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Promotion {
    pub release: String,
    pub commit: String,
    pub previous_release: Option<String>,
    pub change: Change,
    pub approved_by: Approver,
    /// 팩토리가 붙인 승인한 사람의 이름표. 레이어는 뜻을 모른다.
    #[serde(default)]
    pub approver: Option<String>,
    /// 에이전트가 이 release 의 승격을 요청한 때와 그 작업의 식별자. 요청 없이 올렸으면 없다.
    #[serde(default)]
    pub requested_at: Option<u64>,
    #[serde(default)]
    pub requested_by: Option<String>,
    /// 프리뷰에서 권한 검사가 찾은 어긋남의 수.
    pub access_findings: usize,
    pub rehearsal: Rehearsed,
    /// 리허설의 숫자. 돌리지 않았거나 필요 없었으면 없다.
    #[serde(default)]
    pub rehearsed: Option<Rehearsal>,
    pub conformance: Conformed,
    /// 돈 마이그레이션의 수.
    pub migrations: u32,
    /// 앞의 운영과 견준 권한의 변화(승인 카드에 보이던 문장).
    pub changes: Vec<String>,
    pub rollout: Option<String>,
}

/// 이력의 한 줄의 몸. JSON 으로는 `{ "kind": "<갈래>", …칸 }` 이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// release 가 운영에 올랐다.
    Promoted(Promotion),
    /// 올리다가 깨져 앞의 모습으로 되돌렸다.
    RolledBack {
        #[serde(flatten)]
        promotion: Promotion,
        /// 마이그레이션이 돈 뒤에 깨졌는가.
        migrated: bool,
    },
    /// 운영 DB 를 지난 시점으로 되살렸다. 코드는 그대로다.
    Restored {
        release: String,
        /// 되살린 시점(유닉스 초).
        to: u64,
    },
    /// 마지막 되살리기를 물렀다.
    RestoreUndone { release: String },
}

impl Entry {
    /// 갈래의 이름. 기록의 `kind` 열에 적는다.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Promoted(_) => "promoted",
            Self::RolledBack { .. } => "rolled_back",
            Self::Restored { .. } => "restored",
            Self::RestoreUndone { .. } => "restore_undone",
        }
    }
}

/// 승인한 사람의 이름표를 본다. 비지 않고 · 80자 안 · 제어 문자 없음이다.
pub fn check_approver(text: &str) -> Result<String, LabelProblem> {
    check_label(text)
}

/// 번호 `newest` 의 줄을 쌓은 뒤 걷을 줄: 번호가 이 값 이하인 것. 걷을 것이 없으면 0 이다.
pub fn pruned_through(newest: u64, keep: u64) -> u64 {
    newest.saturating_sub(keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn promotion() -> Promotion {
        Promotion {
            release: "r_1".to_owned(),
            commit: "c".repeat(40),
            previous_release: None,
            change: Change::CustomerRequest,
            approved_by: Approver::Customer,
            approver: Some("고객의 담당자".to_owned()),
            requested_at: Some(10),
            requested_by: Some("0".repeat(32)),
            access_findings: 0,
            rehearsal: Rehearsed::Passed,
            rehearsed: Some(Rehearsal {
                millis: 12,
                failed_at: None,
                sqlstate: None,
                tables: vec![TableRows {
                    table: "ledger.note".to_owned(),
                    before: Some(3),
                    after: Some(3),
                }],
            }),
            conformance: Conformed::NotDeclared,
            migrations: 1,
            changes: vec!["`member` 는 `ledger.note` 를 읽을 수 있게 됩니다".to_owned()],
            rollout: None,
        }
    }

    #[test]
    fn 이력의_한_줄은_이름과_숫자와_권한_변화의_문장만_싣는다() {
        let promoted = serde_json::to_value(Entry::Promoted(promotion())).unwrap();
        let keys: Vec<&str> = promoted
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "access_findings",
                "approved_by",
                "approver",
                "change",
                "changes",
                "commit",
                "conformance",
                "kind",
                "migrations",
                "previous_release",
                "rehearsal",
                "rehearsed",
                "release",
                "requested_at",
                "requested_by",
                "rollout",
            ]
        );
        assert_eq!(promoted["kind"], "promoted");
        let rolled = Entry::RolledBack {
            promotion: promotion(),
            migrated: true,
        };
        let value = serde_json::to_value(&rolled).unwrap();
        assert_eq!(value["kind"], "rolled_back");
        assert_eq!(value["migrated"], true);
        assert_eq!(value["release"], "r_1");
        // 기록에서 다시 읽힌다
        assert_eq!(serde_json::from_value::<Entry>(value).unwrap(), rolled);
        let restored = serde_json::to_value(Entry::Restored {
            release: "r_1".to_owned(),
            to: 99,
        })
        .unwrap();
        assert_eq!(
            restored,
            serde_json::json!({ "kind": "restored", "release": "r_1", "to": 99 })
        );
        assert_eq!(
            serde_json::to_value(Entry::RestoreUndone {
                release: "r_1".to_owned()
            })
            .unwrap(),
            serde_json::json!({ "kind": "restore_undone", "release": "r_1" })
        );
        for entry in [
            Entry::Promoted(promotion()),
            rolled,
            Entry::RestoreUndone {
                release: String::new(),
            },
        ] {
            assert_eq!(serde_json::to_value(&entry).unwrap()["kind"], entry.kind());
        }
    }

    #[test]
    fn 보관의_상한을_넘은_줄은_오랜_것부터_걷는다() {
        // 상한 안이면 걷지 않는다
        assert_eq!(pruned_through(1, KEEP), 0);
        assert_eq!(pruned_through(KEEP, KEEP), 0);
        // 하나 넘으면 가장 오랜 하나를 걷는다
        assert_eq!(pruned_through(KEEP + 1, KEEP), 1);
        assert_eq!(pruned_through(7, 3), 4);
    }

    #[test]
    fn 승인한_사람의_이름표는_비거나_길거나_제어_문자가_들면_받지_않는다() {
        assert_eq!(check_approver("  김 팀장 "), Ok("김 팀장".to_owned()));
        assert_eq!(check_approver(" "), Err(LabelProblem::Empty));
        assert!(matches!(
            check_approver(&"가".repeat(81)),
            Err(LabelProblem::TooLong { .. })
        ));
        assert_eq!(check_approver("김\n팀장"), Err(LabelProblem::Control));
    }
}
