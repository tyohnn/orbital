//! 권한의 변화를 문장으로 적는다. 승인 카드에 서는 글이다.
//!
//! 고객은 권한을 설정하지 않고 뜻을 승인한다. 그래서 「무엇이 달라지는지」를 권한 표의 차이가 아니라 문장으로 보인다.
//! 넓어지는 변화를 먼저 적는다. 사람이 먼저 봐야 하는 것이 그쪽이다.

use serde::{Deserialize, Serialize};

use crate::access::{Access, Grant, Reach};
use crate::manifest::Schedule;
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

/// 일정이 도는 업무 역할의 변화를 문장으로 돌려준다. 승인 카드에 권한의 변화와 함께 선다.
///
/// 일정이 새로 생기거나 그 역할이 바뀌어 어떤 역할로 돌게 되면 「이번 변경으로 일정 … 이 `역할` 역할로 돕니다」가 선다(넓어지는 것이라 먼저).
/// 역할을 빼거나 일정을 지우면 「… 은 더는 `역할` 역할로 돌지 않습니다」가 선다. 일정은 서비스 · cron · 경로(`Schedule::key`)로 가른다.
/// 처음 배포라면 `before` 에 빈 목록을 넘긴다.
pub fn schedule_changes(before: &[Schedule], after: &[Schedule]) -> Vec<String> {
    let named = |schedule: &Schedule| {
        format!(
            "`{}`(`{}`, UTC)",
            schedule.path,
            schedule
                .cron
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let role_of = |list: &[Schedule], key: &str| {
        list.iter()
            .find(|schedule| schedule.key() == key)
            .and_then(|schedule| schedule.role.clone())
    };
    let mut widened = Vec::new();
    let mut narrowed = Vec::new();
    for schedule in after {
        let was = role_of(before, &schedule.key());
        if let Some(role) = &schedule.role
            && was.as_ref() != Some(role)
        {
            widened.push(format!(
                "이번 변경으로 일정 {}이 `{role}` 역할로 돕니다. 그 역할의 모든 행 권한으로 읽고 씁니다",
                named(schedule)
            ));
        }
    }
    for schedule in before {
        let now = role_of(after, &schedule.key());
        if let Some(role) = &schedule.role
            && now.as_ref() != Some(role)
        {
            narrowed.push(format!(
                "일정 {}은 더는 `{role}` 역할로 돌지 않습니다",
                named(schedule)
            ));
        }
    }
    widened.extend(narrowed);
    widened
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

    fn schedule(path: &str, role: Option<&str>) -> Schedule {
        Schedule {
            service: Ident::parse("api").unwrap(),
            cron: "0 9 25 * *".to_owned(),
            path: path.to_owned(),
            role: role.map(|role| Ident::parse(role).unwrap()),
        }
    }

    #[test]
    fn 일정이_새로_생기거나_역할이_바뀌어_어떤_역할로_돌게_되면_그_문장이_먼저_선다() {
        let payroll = schedule("/api/jobs/payroll", Some("payroll_admin"));
        assert_eq!(
            schedule_changes(&[], std::slice::from_ref(&payroll)),
            vec![
                "이번 변경으로 일정 `/api/jobs/payroll`(`0 9 25 * *`, UTC)이 `payroll_admin` 역할로 돕니다. 그 역할의 모든 행 권한으로 읽고 씁니다"
                    .to_owned()
            ]
        );
        // 같은 역할로 그대로면 문장이 없다. 역할이 없던 일정에 역할이 붙어도 선다
        assert_eq!(
            schedule_changes(
                std::slice::from_ref(&payroll),
                std::slice::from_ref(&payroll)
            ),
            Vec::<String>::new()
        );
        let bare = schedule("/api/jobs/payroll", None);
        assert_eq!(
            schedule_changes(std::slice::from_ref(&bare), std::slice::from_ref(&payroll)).len(),
            1
        );
        // 역할이 바뀌면 새 역할의 문장(먼저)과 앞 역할의 문장이 함께 선다
        let manager = schedule("/api/jobs/payroll", Some("manager"));
        assert_eq!(
            schedule_changes(std::slice::from_ref(&manager), std::slice::from_ref(&payroll)),
            vec![
                "이번 변경으로 일정 `/api/jobs/payroll`(`0 9 25 * *`, UTC)이 `payroll_admin` 역할로 돕니다. 그 역할의 모든 행 권한으로 읽고 씁니다"
                    .to_owned(),
                "일정 `/api/jobs/payroll`(`0 9 25 * *`, UTC)은 더는 `manager` 역할로 돌지 않습니다"
                    .to_owned(),
            ]
        );
        // 역할 없는 일정은 문장이 없다
        assert_eq!(schedule_changes(&[], &[bare]), Vec::<String>::new());
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
