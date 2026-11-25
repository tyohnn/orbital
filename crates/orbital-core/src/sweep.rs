//! 쓰고 남은 줄을 언제 지우는가. 로그인 링크 · Google 로그인의 표 · 인가 요청 · 인가 코드 · 세션 · OAuth 토큰.
//!
//! 지우는 일은 `orbital-pg` 가 새 줄을 적을 때 함께 한다. 여기서는 어느 줄이 지울 때가 됐는지만 판정한다.
//! 만료된 줄을 곧바로 지우지 않고 하루를 더 둔다. 그동안은 다시 온 링크에 「이미 썼다」 · 「만료됐다」를 바르게 답하고,
//! 다시 쓰인 코드와 refresh 토큰을 알아보고 그 줄기를 거둘 수 있다.

use serde::{Deserialize, Serialize};

/// 만료되거나 거둔 뒤에도 줄을 남겨 두는 시간. 하루.
pub const LEFTOVER_RETENTION: u64 = 24 * 60 * 60;

/// 쓰고 남는 줄이 생기는 표.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leftover {
    EmailLink,
    GoogleTicket,
    OauthRequest,
    OauthCode,
    Session,
    OauthToken,
}

impl Leftover {
    pub const ALL: [Self; 6] = [
        Self::EmailLink,
        Self::GoogleTicket,
        Self::OauthRequest,
        Self::OauthCode,
        Self::Session,
        Self::OauthToken,
    ];

    /// 거둔 시각부터도 세는가. 세션은 거두면(로그아웃) 다시 읽히지 않으니 거둔 뒤 하루면 지운다.
    /// OAuth 토큰은 만료까지 둔다. 거둔 refresh 토큰이 다시 오면 그 승인을 거두는 근거가 되기 때문이다.
    pub fn counts_revocation(self) -> bool {
        matches!(self, Self::Session)
    }
}

/// 한 줄의 시각들.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverState {
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

/// 이 줄을 지금 지워도 되는가. 만료(또는 세션이면 거둔 때)에서 하루가 지났으면 지운다.
pub fn stale(kind: Leftover, row: &LeftoverState, now: u64) -> bool {
    let after = |at: u64| now >= at.saturating_add(LEFTOVER_RETENTION);
    after(row.expires_at) || (kind.counts_revocation() && row.revoked_at.is_some_and(after))
}

/// 이 시각 이하에 만료(또는 거둔) 줄을 지운다. DB 의 조건이 [`stale`] 과 같은 경계를 쓰게 하려고 둔다.
pub fn sweep_before(now: u64) -> u64 {
    now.saturating_sub(LEFTOVER_RETENTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn row(expires_at: u64, revoked_at: Option<u64>) -> LeftoverState {
        LeftoverState {
            expires_at,
            revoked_at,
        }
    }

    #[test]
    fn 만료되고_하루가_지난_줄은_지우고_하루가_되지_않은_줄은_남긴다() {
        for kind in Leftover::ALL {
            assert!(stale(kind, &row(NOW - LEFTOVER_RETENTION, None), NOW));
            assert!(!stale(kind, &row(NOW - LEFTOVER_RETENTION + 1, None), NOW));
            // 아직 만료되지 않은 줄은 남긴다
            assert!(!stale(kind, &row(NOW + 60, None), NOW));
        }
    }

    #[test]
    fn 거둔_세션은_만료_전이라도_거둔_지_하루가_지나면_지운다() {
        let revoked = row(
            NOW + 10 * LEFTOVER_RETENTION,
            Some(NOW - LEFTOVER_RETENTION),
        );
        assert!(stale(Leftover::Session, &revoked, NOW));
        let fresh = row(NOW + 10 * LEFTOVER_RETENTION, Some(NOW - 60));
        assert!(!stale(Leftover::Session, &fresh, NOW));
    }

    #[test]
    fn 거둔_oauth_토큰은_만료될_때까지_남긴다() {
        let revoked = row(NOW + 60, Some(NOW - 10 * LEFTOVER_RETENTION));
        assert!(!stale(Leftover::OauthToken, &revoked, NOW));
    }

    #[test]
    fn 지우는_경계의_시각은_판정과_같다() {
        let cutoff = sweep_before(NOW);
        assert!(stale(Leftover::EmailLink, &row(cutoff, None), NOW));
        assert!(!stale(Leftover::EmailLink, &row(cutoff + 1, None), NOW));
    }
}
