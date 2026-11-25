//! Google 로 들어가는 문. router 는 브라우저의 표식과 돌아갈 곳만 건네고, 무엇을 서명해 어디로 보낼지는 레이어가 정한다.
//!
//! 콜백은 레이어의 주소 하나로 받으므로 `state` 의 서명 · 팩토리의 키 · Google 의 주소는 모두 레이어(관리 서버)에 있다.
//! router 에는 그 레이어가 낸 한 번 쓰는 표를 받아 들여보내는 일(`/_orbital/auth/google/finish`)만 있다.

use orbital_pg::auth::Secret;

/// Google 로 보낼 주소를 짓는 것. 레이어가 인스턴스마다 하나를 router 에 건넨다.
pub trait GoogleDoor: Send + Sync {
    /// Google 의 인가 주소. 팩토리가 Google 의 키를 넣지 않았거나 지웠으면 `None` 이고, router 는 404 로 답한다.
    ///
    /// `next` 는 이미 이 주소 안의 경로로 거른 것이다. `browser` 는 시작한 브라우저의 표식이고, 해시만 `state` 에 싣는다.
    fn authorize(&self, next: &str, browser: &Secret) -> Option<String>;
}
