//! 일정(`[[schedule]]`)의 cron 식과 그 다음 때.
//!
//! 다섯 칸(분 시 일 월 요일)의 평범한 cron 식만 받는다. 칸마다 `*`, 수, 범위(`1-5`), 간격(`*/15` · `1-30/5` · `5/10`), 쉼표의 목록을 쓴다.
//! 요일의 0 과 7 은 일요일이다. 이름(`mon` · `jan`)과 `@daily` 같은 줄임은 받지 않는다.
//! **시각은 UTC 다.** 레이어는 시간대를 모르고, 한국 시각으로 아침 9시라면 `0 0 * * *` 처럼 UTC 로 적는다.
//!
//! 일과 요일을 둘 다 좁히면(둘 다 `*` 로 시작하지 않으면) 둘 가운데 하나만 맞아도 맞는다. 여느 cron 과 같다.
//! 시각은 모두 인자로 받는 유닉스 초이고, 시계를 읽지 않는다.

use std::fmt;

use serde::{Deserialize, Serialize};

/// 읽은 cron 식. 칸마다 맞는 값의 집합을 비트로 갖는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cron {
    minutes: u64,
    hours: u32,
    /// 1 부터 31 까지.
    days: u32,
    /// 1 부터 12 까지.
    months: u16,
    /// 0(일) 부터 6(토) 까지.
    weekdays: u8,
    /// 일과 요일을 둘 다 좁혔는가. 그러면 둘 가운데 하나만 맞아도 된다.
    either_day: bool,
}

/// 읽지 못한 까닭.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum CronProblem {
    /// 칸이 다섯이 아니다.
    Fields { count: usize },
    /// 한 칸을 읽지 못했다(모르는 글자 · 범위 밖의 수 · 거꾸로 된 범위 · 0 간격).
    Field { field: String },
    /// 맞는 때가 한 번도 오지 않는다(`0 0 31 2 *`).
    Never,
}

impl fmt::Display for CronProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fields { count } => write!(
                f,
                "칸이 {count}개입니다. 분 시 일 월 요일의 다섯 칸이어야 합니다"
            ),
            Self::Field { field } => write!(
                f,
                "칸 `{field}` 를 읽지 못했습니다. 수 · `*` · 범위(`1-5`) · 간격(`*/15`) · 쉼표의 목록만 씁니다"
            ),
            Self::Never => write!(f, "맞는 때가 한 번도 오지 않습니다"),
        }
    }
}

/// 한 칸이 받는 값의 범위.
const MINUTE: (u32, u32) = (0, 59);
const HOUR: (u32, u32) = (0, 23);
const DAY: (u32, u32) = (1, 31);
const MONTH: (u32, u32) = (1, 12);
/// 요일은 7 까지 받고 7 을 0(일요일)으로 읽는다.
const WEEKDAY: (u32, u32) = (0, 7);

/// 한 칸을 읽어 맞는 값의 비트를 돌려준다.
fn field(text: &str, (low, high): (u32, u32)) -> Result<u64, CronProblem> {
    let bad = || CronProblem::Field {
        field: text.to_owned(),
    };
    let number = |part: &str| -> Result<u32, CronProblem> {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) || part.len() > 2 {
            return Err(bad());
        }
        let value: u32 = part.parse().map_err(|_| bad())?;
        if value < low || value > high {
            return Err(bad());
        }
        Ok(value)
    };
    let mut bits = 0u64;
    for item in text.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((range, step)) => {
                if step.is_empty()
                    || step.len() > 2
                    || !step.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(bad());
                }
                let step: u32 = step.parse().map_err(|_| bad())?;
                if step == 0 {
                    return Err(bad());
                }
                (range, Some(step))
            }
            None => (item, None),
        };
        let (from, to) = if range == "*" {
            (low, high)
        } else if let Some((from, to)) = range.split_once('-') {
            let (from, to) = (number(from)?, number(to)?);
            if from > to {
                return Err(bad());
            }
            (from, to)
        } else {
            let from = number(range)?;
            // `5/10` 은 5 부터 끝까지 10 씩이다. 간격이 없으면 그 수 하나다
            (from, if step.is_some() { high } else { from })
        };
        let step = step.unwrap_or(1);
        let mut value = from;
        while value <= to {
            bits |= 1 << value;
            value += step;
        }
    }
    Ok(bits)
}

impl Cron {
    /// cron 식을 읽는다. 맞는 때가 한 번도 오지 않는 식도 받지 않는다.
    pub fn parse(text: &str) -> Result<Self, CronProblem> {
        let fields: Vec<&str> = text.split_whitespace().collect();
        let [minute, hour, day, month, weekday] = fields[..] else {
            return Err(CronProblem::Fields {
                count: fields.len(),
            });
        };
        let mut weekdays = field(weekday, WEEKDAY)?;
        if weekdays & (1 << 7) != 0 {
            weekdays = (weekdays | 1) & !(1 << 7);
        }
        let cron = Self {
            minutes: field(minute, MINUTE)?,
            hours: u32::try_from(field(hour, HOUR)?).unwrap_or(u32::MAX),
            days: u32::try_from(field(day, DAY)?).unwrap_or(u32::MAX),
            months: u16::try_from(field(month, MONTH)?).unwrap_or(u16::MAX),
            weekdays: u8::try_from(weekdays).unwrap_or(u8::MAX),
            either_day: !day.starts_with('*') && !weekday.starts_with('*'),
        };
        if cron.next_after(0).is_none() {
            return Err(CronProblem::Never);
        }
        Ok(cron)
    }

    fn day_matches(&self, date: Date) -> bool {
        if self.months & (1 << date.month) == 0 {
            return false;
        }
        let day = self.days & (1 << date.day) != 0;
        let weekday = self.weekdays & (1 << date.weekday) != 0;
        if self.either_day {
            day || weekday
        } else {
            day && weekday
        }
    }

    /// 이 시각(유닉스 초)의 분이 식에 맞는가. 초는 보지 않는다.
    pub fn matches(&self, at: u64) -> bool {
        let date = Date::of_day(at / DAY_SECONDS);
        let minute_of_day = (at % DAY_SECONDS) / 60;
        self.day_matches(date)
            && self.hours & (1 << (minute_of_day / 60)) != 0
            && self.minutes & (1 << (minute_of_day % 60)) != 0
    }

    /// `now` 보다 뒤에 오는 첫 맞는 때(분의 첫 초). 400년 안에 없으면 `None` 이다.
    pub fn next_after(&self, now: u64) -> Option<u64> {
        let start = (now / 60 + 1) * 60;
        let first_day = start / DAY_SECONDS;
        let first_minute = (start % DAY_SECONDS) / 60;
        // 그레고리력은 400년(146097일)마다 되풀이된다
        for offset in 0..=146_097u64 {
            let day = first_day + offset;
            if !self.day_matches(Date::of_day(day)) {
                continue;
            }
            let from = if offset == 0 { first_minute } else { 0 };
            for minute_of_day in from..24 * 60 {
                if self.hours & (1 << (minute_of_day / 60)) != 0
                    && self.minutes & (1 << (minute_of_day % 60)) != 0
                {
                    return Some(day * DAY_SECONDS + minute_of_day * 60);
                }
            }
        }
        None
    }
}

const DAY_SECONDS: u64 = 24 * 60 * 60;

/// 1970-01-01 부터 센 날 하나의 달력.
#[derive(Debug, Clone, Copy)]
struct Date {
    month: u32,
    day: u32,
    /// 0 이 일요일이다.
    weekday: u32,
}

impl Date {
    /// 날의 수에서 달력의 날을 짓는다(H. Hinnant 의 `civil_from_days`).
    fn of_day(days: u64) -> Self {
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        Self {
            month: u32::try_from(month).unwrap_or(0),
            day: u32::try_from(day).unwrap_or(0),
            // 1970-01-01 은 목요일(4)이다
            weekday: u32::try_from((days + 4) % 7).unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-25 수요일 00:00 UTC.
    const WEDNESDAY: u64 = 1_795_564_800;

    fn next(text: &str, now: u64) -> u64 {
        Cron::parse(text).unwrap().next_after(now).unwrap()
    }

    #[test]
    fn 다섯_칸의_평범한_식을_읽는다() {
        for text in [
            "* * * * *",
            "0 9 25 * *",
            "*/15 0-6 1,15 * 1-5",
            "5/10 * * 1-12/2 0,7",
            "59 23 31 12 6",
        ] {
            assert!(Cron::parse(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn 칸의_수가_틀리거나_읽지_못하는_칸이면_받지_않는다() {
        assert_eq!(
            Cron::parse("0 9 25 *"),
            Err(CronProblem::Fields { count: 4 })
        );
        assert_eq!(
            Cron::parse("0 0 9 25 * *"),
            Err(CronProblem::Fields { count: 6 })
        );
        for text in [
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * 32 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "a * * * *",
            "* * * jan *",
            "-1 * * * *",
            "1,,2 * * * *",
            "*/+5 * * * *",
            "@daily * * * *",
        ] {
            assert!(
                matches!(Cron::parse(text), Err(CronProblem::Field { .. })),
                "{text}"
            );
        }
    }

    #[test]
    fn 한_번도_오지_않는_식은_받지_않는다() {
        assert_eq!(Cron::parse("0 0 31 2 *"), Err(CronProblem::Never));
        assert_eq!(Cron::parse("0 0 30 2 *"), Err(CronProblem::Never));
        // 2월 29일은 네 해에 한 번 온다
        assert!(Cron::parse("0 0 29 2 *").is_ok());
    }

    #[test]
    fn 다음_때는_지금보다_뒤의_첫_맞는_분이다() {
        // 매분: 지금이 분의 첫 초여도 다음 분이다
        assert_eq!(next("* * * * *", WEDNESDAY), WEDNESDAY + 60);
        assert_eq!(next("* * * * *", WEDNESDAY + 59), WEDNESDAY + 60);
        // 매일 9시: 오늘의 9시가 지나지 않았으면 오늘, 지났으면 내일
        assert_eq!(next("0 9 * * *", WEDNESDAY), WEDNESDAY + 9 * 3600);
        assert_eq!(
            next("0 9 * * *", WEDNESDAY + 9 * 3600),
            WEDNESDAY + DAY_SECONDS + 9 * 3600
        );
        // 매달 25일 9시: 2026-11-25 9시, 그다음은 2026-12-25
        assert_eq!(next("0 9 25 * *", WEDNESDAY), WEDNESDAY + 9 * 3600);
        assert_eq!(
            next("0 9 25 * *", WEDNESDAY + 9 * 3600),
            WEDNESDAY + 30 * DAY_SECONDS + 9 * 3600
        );
        // 일요일(0 과 7) 자정: 수요일에서 나흘 뒤
        assert_eq!(next("0 0 * * 0", WEDNESDAY), WEDNESDAY + 4 * DAY_SECONDS);
        assert_eq!(next("0 0 * * 7", WEDNESDAY), WEDNESDAY + 4 * DAY_SECONDS);
        // 2월 29일: 2028 년
        assert_eq!(next("0 0 29 2 *", WEDNESDAY), 1_835_395_200);
    }

    #[test]
    fn 일과_요일을_둘_다_좁히면_하나만_맞아도_맞는다() {
        // 매달 1일이거나 금요일. 수요일 다음의 금요일(27일)이 12월 1일보다 먼저다
        assert_eq!(next("0 0 1 * 5", WEDNESDAY), WEDNESDAY + 2 * DAY_SECONDS);
        // 요일이 `*` 면 일만 본다
        assert_eq!(next("0 0 1 * *", WEDNESDAY), WEDNESDAY + 6 * DAY_SECONDS);
        // 일이 `*/1` 처럼 `*` 로 시작하면 좁히지 않은 것으로 보고 둘 다 맞아야 한다
        assert_eq!(next("0 0 */1 * 5", WEDNESDAY), WEDNESDAY + 2 * DAY_SECONDS);
    }
}
