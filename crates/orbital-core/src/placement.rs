//! 놓인 자리. 인스턴스는 그것을 세운 관리 서버의 기계에 놓인다. 코드 저장소 · 빌드 폴더 · 떠 있는 프로세스가 그 기계에만 있어서다.
//!
//! 관리 서버의 일 가운데 그 파일과 프로세스에 닿는 일은 놓인 기계만 하고, 기록(control database)과 인스턴스의 DB 에만 닿는 일은
//! 어느 기계든 한다. 어느 일이 어느 쪽인지를 여기 한곳에 적는다. 다른 기계는 일을 하지 않고, 놓인 기계의 주소를 알면 요청을 그 기계로
//! 넘기고 모르면 「다른 기계에 놓여 있다」고 답한다(`route`). 넘겨받은 요청은 다시 넘기지 않는다.

use serde::{Deserialize, Serialize};

/// 관리 서버가 하는 일. 인스턴스 하나에 닿는 것만 적는다(레이어 전체의 일인 백업과 훈련은 따로 하나만 돌린다).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Errand {
    /// 코드를 묶음으로 내주기.
    SourceBundle,
    /// 묶음이나 git 으로 코드를 받기.
    Push,
    /// git 의 광고와 주고받기.
    Git,
    /// 프리뷰를 세우기 · 걷기 · 그 로그와 세션.
    Preview,
    /// 운영 DB 의 사본에 마이그레이션을 미리 돌리기. commit 에서 마이그레이션을 읽는다.
    Rehearse,
    /// 승격의 요청과 그 요청의 모습. commit 에서 선언을 읽는다.
    PromotionRequest,
    /// 운영에 올리기.
    Promote,
    /// 인스턴스의 DB 를 지난 시점으로 되살리기와 무르기. 서버를 재운다.
    Restore,
    /// 업데이트를 인스턴스의 `main` 에 합치기.
    ApplyUpdate,
    /// rollout 을 만들기. 인스턴스의 저장소에 업데이트를 가져다 둔다.
    CreateRollout,
    /// 인스턴스를 걷기. 프로세스 · 저장소 · 빌드 폴더를 지운다.
    Destroy,
    /// 작업(토큰)을 열고 닫기.
    Work,
    /// 운영의 모습(release · 주소 · 일정)을 보기.
    ProductionView,
    /// 운영의 사용자 · 초대 · 역할 · MCP 클라이언트. 인스턴스의 DB 에만 닿는다.
    Users,
    /// 비밀의 목록 · 요청 · 값 넣기와 지우기 · 입력 표. 서비스를 재우는 일은 놓인 기계에 DB 로 알린다.
    Secrets,
    /// rollout 을 보기 · 다시 열기 · 거두기.
    Rollout,
    /// 앱의 스캐폴드를 받기와 그 앱에서 인스턴스를 세우기. 앱의 코드 저장소는 처음 받은 기계에 있다.
    App,
    /// 고객의 요청(인스턴스의 하위 도메인으로 앱에 가는 것). 그 인스턴스의 router 와 앱의 프로세스는 놓인 기계에만 떠 있다.
    Traffic,
    /// 조직과 그 service key 를 보기 · 내기 · 거두기와, 운영자가 조직을 만들고 닫기. 기록에만 닿는다.
    Organization,
}

impl Errand {
    pub const ALL: [Self; 19] = [
        Self::SourceBundle,
        Self::Push,
        Self::Git,
        Self::Preview,
        Self::Rehearse,
        Self::PromotionRequest,
        Self::Promote,
        Self::Restore,
        Self::ApplyUpdate,
        Self::CreateRollout,
        Self::Destroy,
        Self::Work,
        Self::ProductionView,
        Self::Users,
        Self::Secrets,
        Self::Rollout,
        Self::App,
        Self::Traffic,
        Self::Organization,
    ];
}

/// 일이 어디서 되는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// 인스턴스가 놓인 기계만 한다. 코드 저장소 · 빌드 폴더 · 프로세스에 닿는다.
    Placed,
    /// 어느 기계든 한다. 기록과 인스턴스의 DB 에만 닿는다.
    Anywhere,
}

/// 일이 어디서 되는가.
pub fn reach(errand: Errand) -> Reach {
    match errand {
        Errand::SourceBundle
        | Errand::Push
        | Errand::Git
        | Errand::Preview
        | Errand::Rehearse
        | Errand::PromotionRequest
        | Errand::Promote
        | Errand::Restore
        | Errand::ApplyUpdate
        | Errand::CreateRollout
        | Errand::Destroy
        | Errand::App
        | Errand::Traffic => Reach::Placed,
        Errand::Work
        | Errand::ProductionView
        | Errand::Users
        | Errand::Secrets
        | Errand::Rollout
        | Errand::Organization => Reach::Anywhere,
    }
}

/// 이 기계가 하지 않는 일. 인스턴스가 놓인 기계의 이름을 싣는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Misplaced {
    pub machine: String,
}

/// 이 기계(`here`)가 `placed_on` 에 놓인 인스턴스의 일을 해도 되는가.
pub fn judge(errand: Errand, placed_on: &str, here: &str) -> Result<(), Misplaced> {
    match reach(errand) {
        Reach::Anywhere => Ok(()),
        Reach::Placed if placed_on == here => Ok(()),
        Reach::Placed => Err(Misplaced {
            machine: placed_on.to_owned(),
        }),
    }
}

/// 받은 요청을 어디서 처리하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "route")]
pub enum Route {
    /// 이 기계가 한다.
    Here,
    /// 놓인 기계로 요청을 그대로 넘긴다. 이 기계는 아무것도 하지 않는다.
    Forward { machine: String },
    /// 넘기지도 하지도 않고 놓인 기계의 이름으로 답한다(HTTP 의 421).
    Refuse { machine: String, why: Unforwarded },
}

/// 놓인 기계로 넘기지 않은 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unforwarded {
    /// 다른 기계에서 넘겨받은 요청이다. 다시 넘기면 기록이 엇갈렸을 때 기계 사이를 돌고 돈다.
    AlreadyForwarded,
    /// 놓인 기계가 자신의 주소를 기록에 적지 않았다.
    NoAddress,
}

/// 이 기계(`here`)가 받은 요청을 어디서 처리하나.
///
/// `forwarded` 는 요청이 다른 기계에서 넘겨받은 것인지, `address_known` 은 놓인 기계의 주소가 기록에 있는지다.
/// 어느 기계나 하는 일과 이 기계에 놓인 것의 일은 여기서 한다. 넘겨받은 요청은 어떤 일이든 다시 넘기지 않는다.
pub fn route(
    errand: Errand,
    placed_on: &str,
    here: &str,
    forwarded: bool,
    address_known: bool,
) -> Route {
    match judge(errand, placed_on, here) {
        Ok(()) => Route::Here,
        Err(Misplaced { machine }) if forwarded => Route::Refuse {
            machine,
            why: Unforwarded::AlreadyForwarded,
        },
        Err(Misplaced { machine }) if !address_known => Route::Refuse {
            machine,
            why: Unforwarded::NoAddress,
        },
        Err(Misplaced { machine }) => Route::Forward { machine },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 놓인_기계가_해야_하는_일과_어느_기계나_할_수_있는_일을_가른다() {
        let placed = [
            Errand::SourceBundle,
            Errand::Push,
            Errand::Git,
            Errand::Preview,
            Errand::Rehearse,
            Errand::PromotionRequest,
            Errand::Promote,
            Errand::Restore,
            Errand::ApplyUpdate,
            Errand::CreateRollout,
            Errand::Destroy,
            Errand::App,
            Errand::Traffic,
        ];
        let anywhere = [
            Errand::Work,
            Errand::ProductionView,
            Errand::Users,
            Errand::Secrets,
            Errand::Rollout,
            Errand::Organization,
        ];
        // 모든 일이 두 갈래 가운데 하나에 든다
        assert_eq!(placed.len() + anywhere.len(), Errand::ALL.len());
        for errand in placed {
            assert_eq!(judge(errand, "m1", "m1"), Ok(()), "{errand:?}");
            assert_eq!(
                judge(errand, "m1", "m2"),
                Err(Misplaced {
                    machine: "m1".to_owned()
                }),
                "{errand:?}"
            );
        }
        for errand in anywhere {
            assert_eq!(judge(errand, "m1", "m1"), Ok(()), "{errand:?}");
            assert_eq!(judge(errand, "m1", "m2"), Ok(()), "{errand:?}");
        }
    }

    #[test]
    fn 다른_기계에_놓인_것의_일은_주소를_알면_넘기고_모르거나_넘겨받은_것이면_421_이다() {
        // 넘기는 끝: 놓인 기계가 다르고, 주소를 알고, 처음 받은 요청
        assert_eq!(
            route(Errand::Preview, "a", "b", false, true),
            Route::Forward {
                machine: "a".to_owned()
            }
        );
        // 넘기지 않는 끝: 주소를 모른다
        assert_eq!(
            route(Errand::Preview, "a", "b", false, false),
            Route::Refuse {
                machine: "a".to_owned(),
                why: Unforwarded::NoAddress
            }
        );
        // 넘기지 않는 끝: 이미 넘겨받은 요청
        assert_eq!(
            route(Errand::Preview, "a", "b", true, true),
            Route::Refuse {
                machine: "a".to_owned(),
                why: Unforwarded::AlreadyForwarded
            }
        );
        // 놓인 기계가 받은 요청은 넘겨받은 것이든 아니든 여기서 한다
        assert_eq!(route(Errand::Preview, "a", "a", true, true), Route::Here);
        assert_eq!(route(Errand::Preview, "a", "a", false, false), Route::Here);
        // 어느 기계나 하는 일은 주소를 알아도 넘기지 않는다
        assert_eq!(route(Errand::Users, "a", "b", false, true), Route::Here);
    }
}
