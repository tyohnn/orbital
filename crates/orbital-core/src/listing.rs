//! 목록의 쪽. 함대(인스턴스)와 rollout 의 목록을 (만든 때, 식별자)의 차례로 쪽을 나눠 준다.
//!
//! 쪽의 표식은 앞 쪽의 마지막 줄의 `<만든 때>.<식별자>` 다. 전역의 차례 번호를 표식으로 쓰지 않는다. 번호의 틈으로 다른 조직이
//! 그사이 몇을 만들었는지가 새기 때문이다. 표식은 자기 조직의 줄에서만 지어지고, 질의는 언제나 조직으로 거른다(어댑터의 일).
//! 만든 때를 모르는 줄(만든 때를 적기 전에 선 것)은 0 으로 본다.

use serde::Serialize;

/// 한 쪽에 돌려주는 수의 기본값과 상한.
pub const LIST_DEFAULT: u32 = 100;
pub const LIST_MAX: u32 = 500;
/// 표식의 식별자가 가질 수 있는 가장 긴 길이.
pub const ID_MAX: usize = 64;

/// 쪽의 표식. 이 줄의 뒤부터 준다.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Cursor {
    /// 만든 때(유닉스 초). 모르면 0 이다.
    pub created_at: u64,
    pub id: String,
}

impl Cursor {
    /// `<만든 때>.<식별자>` 를 읽는다. 만든 때는 0 이상의 정수, 식별자는 영문 소문자 · 숫자 · 밑줄 1–64 자다.
    pub fn parse(text: &str) -> Option<Self> {
        let (at, id) = text.split_once('.')?;
        let digits = !at.is_empty() && at.bytes().all(|byte| byte.is_ascii_digit());
        let shaped = !id.is_empty()
            && id.len() <= ID_MAX
            && id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !digits || !shaped {
            return None;
        }
        Some(Self {
            created_at: at.parse().ok()?,
            id: id.to_owned(),
        })
    }

    /// 글로 적는다. [`Cursor::parse`] 로 다시 읽힌다.
    pub fn text(&self) -> String {
        format!("{}.{}", self.created_at, self.id)
    }
}

/// 목록 한 쪽. `after` 의 뒤(없으면 처음)부터 `limit` 개까지.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page {
    pub after: Option<Cursor>,
    pub limit: u32,
}

/// 목록의 질의가 틀린 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageProblem {
    /// `after` 가 앞에서 받은 표식(`next`)의 모양이 아니다.
    After,
    /// `limit` 이 1 에서 [`LIST_MAX`] 사이의 정수가 아니다.
    Limit { max: u32 },
}

/// `after` 와 `limit` 을 읽는다. 없으면 처음부터 [`LIST_DEFAULT`] 개다. 찾은 문제는 모두 돌려준다.
pub fn page(after: Option<&str>, limit: Option<&str>) -> Result<Page, Vec<PageProblem>> {
    let mut problems = Vec::new();
    let after = match after {
        None => None,
        Some(text) => {
            let parsed = Cursor::parse(text);
            if parsed.is_none() {
                problems.push(PageProblem::After);
            }
            parsed
        }
    };
    let limit = match limit {
        None => LIST_DEFAULT,
        Some(text) => match text.parse::<u32>() {
            Ok(value)
                if text.bytes().all(|byte| byte.is_ascii_digit())
                    && (1..=LIST_MAX).contains(&value) =>
            {
                value
            }
            _ => {
                problems.push(PageProblem::Limit { max: LIST_MAX });
                LIST_DEFAULT
            }
        },
    };
    if problems.is_empty() {
        Ok(Page { after, limit })
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 쪽의_표식은_만든_때와_식별자로_적고_다시_읽으면_같다() {
        let cursor = Cursor {
            created_at: 1_900_000_000,
            id: "i3k9x2ab0q".to_owned(),
        };
        assert_eq!(cursor.text(), "1900000000.i3k9x2ab0q");
        assert_eq!(Cursor::parse(&cursor.text()), Some(cursor));
        // 만든 때를 모르는 줄은 0 이다
        assert_eq!(
            Cursor::parse("0.r00000000"),
            Some(Cursor {
                created_at: 0,
                id: "r00000000".to_owned()
            })
        );
        // 식별자의 길이의 경계
        assert!(Cursor::parse(&format!("1.{}", "a".repeat(ID_MAX))).is_some());
        assert!(Cursor::parse(&format!("1.{}", "a".repeat(ID_MAX + 1))).is_none());
        for wrong in [
            "", ".", "1.", ".abc", "abc", "-1.abc", "1.ABC", "1.a-b", "1.a.b", "x1.abc", "1 .abc",
            "１.abc",
        ] {
            assert_eq!(Cursor::parse(wrong), None, "{wrong}");
        }
        // 만든 때가 u64 를 넘으면 받지 않는다
        assert_eq!(Cursor::parse("99999999999999999999.abc"), None);
    }

    #[test]
    fn 쪽의_질의는_표식의_모양이_맞고_limit_이_1에서_500_사이일_때만_받는다() {
        assert_eq!(
            page(None, None),
            Ok(Page {
                after: None,
                limit: LIST_DEFAULT
            })
        );
        assert_eq!(page(None, Some("1")).map(|page| page.limit), Ok(1));
        assert_eq!(page(None, Some("500")).map(|page| page.limit), Ok(500));
        for wrong in ["0", "501", "-1", "+5", "1.5", "", "abc"] {
            assert_eq!(
                page(None, Some(wrong)),
                Err(vec![PageProblem::Limit { max: LIST_MAX }]),
                "{wrong}"
            );
        }
        assert_eq!(
            page(Some("12.i3k9x2ab"), Some("2")),
            Ok(Page {
                after: Some(Cursor {
                    created_at: 12,
                    id: "i3k9x2ab".to_owned()
                }),
                limit: 2
            })
        );
        // 문제는 모두 돌려준다
        assert_eq!(
            page(Some("12"), Some("0")),
            Err(vec![
                PageProblem::After,
                PageProblem::Limit { max: LIST_MAX }
            ])
        );
    }
}
