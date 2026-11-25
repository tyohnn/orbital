//! 관리 서버.
//!
//! 토큰을 발급하고 확인하며, 코드를 받아 그 commit 에서 직접 빌드하고, 프리뷰를 세우고, 승인받은 release 를 운영에 올린다.

pub mod http;
pub mod layer;
pub mod login;
pub mod registry;
pub mod seal;
pub mod settings;
pub mod token;
pub mod vault;
