//! 함대: 팩토리가 인스턴스들을 한눈에 보는 것. 서비스마다의 상태와 운영의 로그의 한도를 정한다.
//!
//! 상태와 로그는 놓인 기계의 메모리와 파일에 있어 놓인 기계가 답한다. 여기서는 그 사실(떠 있는가 · 빌드 중인가 · 깨어 있는가)에서
//! 상태를 고르고, 로그를 얼마나 내줄지를 정한다. 운영의 로그는 앱이 찍은 글이라 고객의 데이터가 섞일 수 있으므로 양을 묶는다.

use serde::Serialize;

use crate::manifest::ServiceKind;

/// 운영의 로그에서 서비스마다 내주는 줄 수의 기본값과 상한.
pub const LOG_LINES_DEFAULT: u32 = 200;
pub const LOG_LINES_MAX: u32 = 1000;
/// 한 줄에서 내주는 가장 긴 글자 수. 넘는 줄은 여기서 자른다.
pub const LOG_LINE_MAX: usize = 2000;
/// 자른 줄의 끝에 붙이는 표시.
pub const CLIPPED_MARK: &str = " …(잘림)";

/// 서비스 하나가 지금 어떤가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// 프로세스가 떠 있다.
    Awake,
    /// 요청이 없어 프로세스를 내렸다. 첫 요청에 깬다.
    Asleep,
    /// 빌드가 끝나기를 기다린다(관리 서버가 빌드 폴더 없이 다시 떴다). 요청에 503 으로 답한다.
    Building,
    /// 정적 서비스. 프로세스가 없고 router 가 파일을 내준다.
    Static,
    /// 기록에는 운영이 있는데 이 기계에 떠 있지 않다(되돌리지 못한 승격 같은 것).
    Stopped,
}

/// 놓인 기계의 메모리에서 읽은 것. 운영이 이 기계에 떠 있지 않으면 `None` 이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Live {
    /// 운영 전체가 빌드를 기다리는 중인가.
    pub building: bool,
    /// 그 서비스의 프로세스가 떠 있는가. 정적 서비스는 거짓이다.
    pub awake: bool,
}

/// 서비스의 상태를 고른다.
pub fn service_state(kind: ServiceKind, live: Option<Live>) -> ServiceState {
    match (live, kind) {
        (None, _) => ServiceState::Stopped,
        (Some(live), _) if live.building => ServiceState::Building,
        (Some(_), ServiceKind::Static) => ServiceState::Static,
        (Some(live), ServiceKind::Server) if live.awake => ServiceState::Awake,
        (Some(_), ServiceKind::Server) => ServiceState::Asleep,
    }
}

/// 로그의 질의가 틀린 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinesProblem {
    /// `lines` 가 1 에서 [`LOG_LINES_MAX`] 사이의 정수가 아니다.
    Lines { max: u32 },
}

/// 서비스마다 내줄 줄 수(`?lines=`). 없으면 [`LOG_LINES_DEFAULT`] 다.
pub fn log_lines(given: Option<&str>) -> Result<u32, LinesProblem> {
    let Some(text) = given else {
        return Ok(LOG_LINES_DEFAULT);
    };
    match text.parse::<u32>() {
        Ok(value)
            if text.bytes().all(|byte| byte.is_ascii_digit())
                && (1..=LOG_LINES_MAX).contains(&value) =>
        {
            Ok(value)
        }
        _ => Err(LinesProblem::Lines { max: LOG_LINES_MAX }),
    }
}

/// 줄 하나를 [`LOG_LINE_MAX`] 글자에서 자른다(글자의 경계에서). 잘랐으면 끝에 [`CLIPPED_MARK`] 를 붙이고 참을 함께 돌려준다.
pub fn clip_line(line: &str) -> (String, bool) {
    match line.char_indices().nth(LOG_LINE_MAX) {
        None => (line.to_owned(), false),
        Some((at, _)) => (format!("{}{CLIPPED_MARK}", &line[..at]), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 서비스의_상태는_정적이면_static_빌드_중이면_building_깨어_있으면_awake_아니면_asleep_이고_떠_있지_않으면_stopped_이다()
     {
        let live = |building, awake| Some(Live { building, awake });
        assert_eq!(
            service_state(ServiceKind::Server, live(false, true)),
            ServiceState::Awake
        );
        assert_eq!(
            service_state(ServiceKind::Server, live(false, false)),
            ServiceState::Asleep
        );
        assert_eq!(
            service_state(ServiceKind::Static, live(false, false)),
            ServiceState::Static
        );
        // 빌드를 기다리는 동안은 어느 서비스든 building 이다
        assert_eq!(
            service_state(ServiceKind::Server, live(true, false)),
            ServiceState::Building
        );
        assert_eq!(
            service_state(ServiceKind::Static, live(true, false)),
            ServiceState::Building
        );
        assert_eq!(
            service_state(ServiceKind::Server, None),
            ServiceState::Stopped
        );
        assert_eq!(
            service_state(ServiceKind::Static, None),
            ServiceState::Stopped
        );
    }

    #[test]
    fn 로그의_줄_수는_1에서_1000_사이만_받고_적지_않으면_200줄이다() {
        assert_eq!(log_lines(None), Ok(200));
        assert_eq!(log_lines(Some("1")), Ok(1));
        assert_eq!(log_lines(Some("1000")), Ok(1000));
        for wrong in ["0", "1001", "-1", "+3", "", "ten", "2.5"] {
            assert_eq!(
                log_lines(Some(wrong)),
                Err(LinesProblem::Lines { max: 1000 }),
                "{wrong}"
            );
        }
    }

    #[test]
    fn 긴_줄은_상한에서_글자의_경계로_자르고_자른_것을_알린다() {
        let exact = "가".repeat(LOG_LINE_MAX);
        assert_eq!(clip_line(&exact), (exact.clone(), false));
        let (clipped, cut) = clip_line(&format!("{exact}나다"));
        assert!(cut);
        assert_eq!(clipped, format!("{exact}{CLIPPED_MARK}"));
        assert_eq!(clip_line(""), (String::new(), false));
    }
}
