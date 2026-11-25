//! Orbital 의 도메인.
//!
//! 여기의 함수는 모두 순수하다. 파일 · 네트워크 · 시계 · 난수에 닿지 않고, 필요한 값(지금 시각, 실제 DB 의 모습)은 인자로 받는다.
//! 실제 Postgres 에 닿는 일은 `orbital-pg` 가, 연결을 잇는 일은 `orbital-proxy` 가 한다.

pub mod access;
pub mod auth;
pub mod backup;
pub mod check;
pub mod describe;
pub mod git;
pub mod google;
pub mod host;
pub mod manifest;
pub mod name;
pub mod oauth;
pub mod plan;
pub mod release;
pub mod rollout;
pub mod scope;
pub mod secrets;
pub mod sweep;
