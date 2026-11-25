//! 봉인. 팩토리가 넣은 키(Resend 의 API 키, Google 클라이언트의 비밀)는 레이어의 기록에 봉인한 글로만 둔다.
//!
//! XChaCha20-Poly1305(AEAD, `chacha20poly1305` crate)로 봉인한다. 일회값은 봉인할 때마다 무작위 24바이트라 겹칠 걱정이 없다.
//! 봉인에는 무엇의 봉인인지(조직의 이름과 칸)를 함께 묶어(associated data), 다른 조직의 줄이나 다른 칸에 옮겨 붙이면 풀리지 않는다.
//! 열쇠는 기록 밖에서 온다(`ORBITAL_SEAL_KEY`). 기록을 통째로 가져가도 열쇠가 없으면 풀리지 않는다.
//!
//! 모양은 `seal1.<일회값과 봉인한 글의 hex>` 다.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::token::{hex, unhex};

const PREFIX: &str = "seal1.";
const NONCE: usize = 24;

/// 봉인의 열쇠(32바이트). 값은 찍지 않는다.
#[derive(Clone)]
pub struct SealKey([u8; 32]);

impl SealKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 64자의 hex 를 읽는다. 모양이 다르면 `None` 이다.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = unhex(text.trim())?;
        Some(Self(bytes.try_into().ok()?))
    }
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKey(..)")
    }
}

/// 무엇의 봉인인지. 조직과 칸이 다르면 같은 열쇠로도 풀리지 않는다.
pub fn binding(organization: &str, field: &str) -> String {
    format!("orbital/settings/v1\n{organization}\n{field}")
}

/// 봉인한다. 운영체제의 무작위 값을 얻지 못하면 `None` 이다.
pub fn seal(key: &SealKey, bound_to: &str, plain: &str) -> Option<String> {
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut nonce).ok()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain.as_bytes(),
                aad: bound_to.as_bytes(),
            },
        )
        .ok()?;
    let mut whole = nonce.to_vec();
    whole.extend(sealed);
    Some(format!("{PREFIX}{}", hex(&whole)))
}

/// 푼다. 열쇠가 다르거나, 다른 조직 · 다른 칸의 봉인이거나, 한 글자라도 바뀌었으면 `None` 이다.
pub fn open(key: &SealKey, bound_to: &str, sealed: &str) -> Option<String> {
    let whole = unhex(sealed.strip_prefix(PREFIX)?)?;
    if whole.len() <= NONCE {
        return None;
    }
    let (nonce, body) = whole.split_at(NONCE);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: bound_to.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SealKey {
        SealKey::from_bytes([byte; 32])
    }

    #[test]
    fn 봉인한_글에는_값이_보이지_않고_같은_열쇠와_같은_자리에서만_풀린다() {
        let bound = binding("factory", "mail.api_key");
        let sealed = seal(&key(1), &bound, "re_secret_value").unwrap();
        assert!(!sealed.contains("re_secret_value"));
        assert!(!sealed.contains(&hex(b"re_secret_value")));
        assert_eq!(
            open(&key(1), &bound, &sealed).as_deref(),
            Some("re_secret_value")
        );
        // 다른 열쇠
        assert_eq!(open(&key(2), &bound, &sealed), None);
        // 다른 조직의 줄
        assert_eq!(
            open(&key(1), &binding("other", "mail.api_key"), &sealed),
            None
        );
        // 다른 칸
        assert_eq!(
            open(
                &key(1),
                &binding("factory", "google.client_secret"),
                &sealed
            ),
            None
        );
    }

    #[test]
    fn 한_글자라도_바뀐_봉인은_풀리지_않는다() {
        let bound = binding("factory", "mail.api_key");
        let sealed = seal(&key(1), &bound, "re_secret_value").unwrap();
        let last = sealed.chars().last().unwrap();
        let flipped = format!(
            "{}{}",
            &sealed[..sealed.len() - 1],
            if last == '0' { '1' } else { '0' }
        );
        assert_eq!(open(&key(1), &bound, &flipped), None);
        assert_eq!(open(&key(1), &bound, "seal1."), None);
        assert_eq!(open(&key(1), &bound, "re_secret_value"), None);
    }

    #[test]
    fn 같은_값도_봉인할_때마다_글이_다르다() {
        let bound = binding("factory", "mail.api_key");
        assert_ne!(
            seal(&key(1), &bound, "same").unwrap(),
            seal(&key(1), &bound, "same").unwrap()
        );
    }

    #[test]
    fn 열쇠는_64자의_hex_만_받고_찍어도_값이_보이지_않는다() {
        assert!(SealKey::from_hex(&"ab".repeat(32)).is_some());
        assert!(SealKey::from_hex(&"ab".repeat(31)).is_none());
        assert!(SealKey::from_hex(&"zz".repeat(32)).is_none());
        assert_eq!(format!("{:?}", key(7)), "SealKey(..)");
    }
}
