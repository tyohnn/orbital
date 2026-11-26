//! control database 의 마이그레이션을 어떻게 적용하는가. 번호의 차례대로, 적용하지 않은 것만, 적용한 것의 내용은 바뀌지 않았을 때만.
//!
//! 해시를 셈하고 SQL 을 돌리는 일은 관리 서버가 한다. 여기서는 저장소에 든 것과 이미 적용한 것을 견주어 무엇을 돌릴지만 판정한다.

use serde::{Deserialize, Serialize};

/// 마이그레이션 하나의 번호와 내용의 해시.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    pub number: u32,
    pub sha256: String,
}

/// 적용하지 못하는 까닭. 하나라도 있으면 관리 서버는 뜨지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MigrationRefusal {
    /// 저장소의 번호가 1 부터 빠짐없이 이어지지 않는다.
    Gap { missing: u32 },
    /// 같은 번호가 둘이다.
    Duplicate { number: u32 },
    /// 적용한 것의 내용이 저장소의 것과 다르다(적용한 뒤 파일을 고쳤다).
    Changed { number: u32 },
    /// 이 관리 서버가 모르는 번호가 적용돼 있다(더 새 관리 서버가 적용했다).
    Unknown { number: u32 },
}

/// 적용할 번호를 차례대로 돌려준다. 저장소(`known`)는 1 부터 빠짐없이 이어져야 하고, 적용한 것(`applied`)은 저장소의 것과 같아야 한다.
pub fn pending(known: &[Known], applied: &[Known]) -> Result<Vec<u32>, Vec<MigrationRefusal>> {
    let mut refusals = Vec::new();
    let mut sorted: Vec<&Known> = known.iter().collect();
    sorted.sort_by_key(|migration| migration.number);
    for pair in sorted.windows(2) {
        if pair[0].number == pair[1].number {
            refusals.push(MigrationRefusal::Duplicate {
                number: pair[0].number,
            });
        }
    }
    let mut expected = 1;
    for migration in &sorted {
        if migration.number > expected {
            refusals.push(MigrationRefusal::Gap { missing: expected });
        }
        expected = migration.number.saturating_add(1);
    }
    for done in applied {
        match sorted
            .iter()
            .find(|migration| migration.number == done.number)
        {
            None => refusals.push(MigrationRefusal::Unknown {
                number: done.number,
            }),
            Some(migration) if migration.sha256 != done.sha256 => {
                refusals.push(MigrationRefusal::Changed {
                    number: done.number,
                });
            }
            Some(_) => {}
        }
    }
    if !refusals.is_empty() {
        return Err(refusals);
    }
    let mut next: Vec<u32> = sorted
        .iter()
        .map(|migration| migration.number)
        .filter(|number| !applied.iter().any(|done| done.number == *number))
        .collect();
    next.dedup();
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(number: u32, sha256: &str) -> Known {
        Known {
            number,
            sha256: sha256.to_owned(),
        }
    }

    #[test]
    fn 적용할_마이그레이션은_번호의_차례이고_빠진_번호가_있으면_거절한다() {
        // 저장소의 차례와 상관없이 번호의 차례로 돌린다
        let all = [known(3, "c"), known(1, "a"), known(2, "b")];
        assert_eq!(pending(&all, &[]), Ok(vec![1, 2, 3]));
        // 적용한 것은 빼고 남은 것만
        assert_eq!(pending(&all, &[known(1, "a"), known(2, "b")]), Ok(vec![3]));
        assert_eq!(pending(&all, &all), Ok(Vec::new()));
        // 빠진 번호
        assert_eq!(
            pending(&[known(1, "a"), known(3, "c")], &[]),
            Err(vec![MigrationRefusal::Gap { missing: 2 }])
        );
        assert_eq!(
            pending(&[known(2, "b")], &[]),
            Err(vec![MigrationRefusal::Gap { missing: 1 }])
        );
        // 같은 번호가 둘
        assert_eq!(
            pending(&[known(1, "a"), known(1, "x")], &[]),
            Err(vec![MigrationRefusal::Duplicate { number: 1 }])
        );
        // 적용한 것의 내용이 바뀌었다
        assert_eq!(
            pending(&all, &[known(1, "z")]),
            Err(vec![MigrationRefusal::Changed { number: 1 }])
        );
        // 모르는 번호가 적용돼 있다
        assert_eq!(
            pending(&all, &[known(4, "d")]),
            Err(vec![MigrationRefusal::Unknown { number: 4 }])
        );
    }
}
