//! 권한의 변화를 문장으로 적는다. 승인 카드에 서는 글이다.
//!
//! 고객은 권한을 설정하지 않고 뜻을 승인한다. 그래서 「무엇이 달라지는지」를 권한 표의 차이가 아니라 문장으로 보인다.
//! 넓어지는 변화를 먼저 적는다. 사람이 먼저 봐야 하는 것이 그쪽이다.

use serde::{Deserialize, Serialize};

use crate::access::{Access, Grant, Reach};
use crate::name::{Ident, TableRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// 전보다 더 많이 닿는다.
    Widened,
    /// 넓어진 것과 좁아진 것이 섞였다.
    Mixed,
    /// 전보다 덜 닿는다.
    Narrowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub role: Ident,
    pub table: TableRef,
    pub before: Grant,
    pub after: Grant,
    pub direction: Direction,
    pub sentence: String,
}

fn clause(before: Reach, after: Reach, verb: &str, verb_past: &str) -> Option<String> {
    let text = match (before, after) {
        (Reach::None, Reach::All) => format!("{verb} 수 있게 됩니다"),
        (Reach::None, Reach::Own) => format!("자기 행을 {verb} 수 있게 됩니다"),
        (Reach::Own, Reach::All) => {
            format!("자기 행만 {verb_past}다가 모든 행을 {verb} 수 있게 됩니다")
        }
        (Reach::All, Reach::Own) => {
            format!("모든 행을 {verb_past}다가 자기 행만 {verb} 수 있게 됩니다")
        }
        (Reach::Own | Reach::All, Reach::None) => format!("더는 {verb_past}지 못합니다"),
        _ => return None,
    };
    Some(text)
}

fn direction(before: Grant, after: Grant) -> Direction {
    let wider = after.read > before.read || after.write > before.write;
    let narrower = after.read < before.read || after.write < before.write;
    match (wider, narrower) {
        (true, false) => Direction::Widened,
        (false, true) => Direction::Narrowed,
        _ => Direction::Mixed,
    }
}

/// 앞의 권한 표와 새 권한 표의 차이를 문장으로 돌려준다. 달라진 것이 없으면 비어 있다.
///
/// 처음 배포라면 `before` 에 빈 표를 넘긴다. 그러면 새로 주는 모든 권한이 「~할 수 있게 됩니다」로 선다.
pub fn changes(before: &Access, after: &Access) -> Vec<Change> {
    let mut pairs: Vec<(&TableRef, &Ident)> = Vec::new();
    for (table, access) in before.tables.iter().chain(&after.tables) {
        for role in access.roles.keys() {
            if !pairs.contains(&(table, role)) {
                pairs.push((table, role));
            }
        }
    }

    let mut found = Vec::new();
    for (table, role) in pairs {
        let (was, now) = (before.grant(table, role), after.grant(table, role));
        if was == now {
            continue;
        }
        let clauses: Vec<String> = [
            clause(was.read, now.read, "읽을", "읽"),
            clause(was.write, now.write, "고칠", "고치"),
        ]
        .into_iter()
        .flatten()
        .collect();
        found.push(Change {
            role: role.clone(),
            table: table.clone(),
            before: was,
            after: now,
            direction: direction(was, now),
            sentence: format!(
                "`{role}` 역할이 `{table}` 표를 {}",
                clauses.join(" 그리고 ")
            ),
        });
    }
    found.sort_by(|a, b| (a.direction, &a.table, &a.role).cmp(&(b.direction, &b.table, &b.role)));
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::tests::{ACCESS, access};

    fn sentences(before: &str, after: &str) -> Vec<String> {
        changes(&access(before).unwrap(), &access(after).unwrap())
            .into_iter()
            .map(|change| change.sentence)
            .collect()
    }

    #[test]
    fn 달라진_것이_없으면_문장도_없다() {
        assert_eq!(sentences(ACCESS, ACCESS), Vec::<String>::new());
    }

    #[test]
    fn 못_읽던_역할이_읽게_되면_문장으로_선다() {
        let after = ACCESS.replace("manager = \"none\"", "manager = \"read\"");
        assert_eq!(
            sentences(ACCESS, &after),
            vec!["`manager` 역할이 `payroll.payslip` 표를 읽을 수 있게 됩니다"]
        );
    }

    #[test]
    fn 자기_행만_읽다가_모든_행을_읽게_되면_그렇게_적는다() {
        let after = ACCESS.replace("employee = \"read own\"", "employee = \"read\"");
        assert_eq!(
            sentences(ACCESS, &after),
            vec![
                "`employee` 역할이 `payroll.payslip` 표를 자기 행만 읽다가 모든 행을 읽을 수 있게 됩니다"
            ]
        );
    }

    #[test]
    fn 권한을_걷으면_더는_못_한다고_적는다() {
        let after = ACCESS.replace(
            "payroll_admin = \"read write\"\n\n",
            "payroll_admin = \"none\"\n\n",
        );
        assert_eq!(
            sentences(ACCESS, &after),
            vec![
                "`payroll_admin` 역할이 `payroll.payslip` 표를 더는 읽지 못합니다 그리고 더는 고치지 못합니다"
            ]
        );
    }

    #[test]
    fn 넓어지는_변화를_좁아지는_변화보다_먼저_적는다() {
        let after = ACCESS
            .replace(
                "payroll_admin = \"read write\"\n\n",
                "payroll_admin = \"read\"\n\n",
            )
            .replace("manager = \"none\"", "manager = \"read write\"");
        let found = changes(&access(ACCESS).unwrap(), &access(&after).unwrap());
        assert_eq!(
            found
                .iter()
                .map(|change| change.direction)
                .collect::<Vec<_>>(),
            vec![Direction::Widened, Direction::Narrowed]
        );
        assert_eq!(
            found[0].sentence,
            "`manager` 역할이 `payroll.payslip` 표를 읽을 수 있게 됩니다 그리고 고칠 수 있게 됩니다"
        );
        assert_eq!(
            found[1].sentence,
            "`payroll_admin` 역할이 `payroll.payslip` 표를 더는 고치지 못합니다"
        );
    }

    #[test]
    fn 처음_배포는_빈_표와_견주어_주는_권한을_모두_적는다() {
        let found = changes(&Access::default(), &access(ACCESS).unwrap());
        // payslip 의 manager 는 none 이라 문장이 없다. 나머지 다섯이 선다
        assert_eq!(found.len(), 5);
        assert!(
            found
                .iter()
                .all(|change| change.direction == Direction::Widened)
        );
    }

    #[test]
    fn 표를_권한_표에서_빼면_그_표의_권한이_사라진다고_적는다() {
        let after = ACCESS.split("[hr.department]").next().unwrap();
        let found = sentences(ACCESS, after);
        assert_eq!(found.len(), 3);
        assert!(
            found.contains(&"`employee` 역할이 `hr.department` 표를 더는 읽지 못합니다".to_owned())
        );
    }
}
