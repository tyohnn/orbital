//! 토큰의 서명과 확인.
//!
//! 토큰의 내용은 core 의 [`Token`] 이다(조직 · 인스턴스 · 능력 · 만료). 서버가 자기 열쇠로 서명해 내주고, 요청마다 서명을 확인한 뒤
//! core 의 `scope::judge` 에 넘긴다. 무엇이 허락되는지는 여기서 정하지 않는다.
//!
//! 모양은 `orb1.<내용의 hex>.<HMAC-SHA256 의 hex>` 다.

use hmac::{Hmac, Mac};
use orbital_core::scope::Token;
use sha2::Sha256;

const PREFIX: &str = "orb1";
/// Google 로그인의 `state`. 같은 열쇠로 서명하되 머리말이 달라 토큰과 서로 바꿔 쓰이지 않는다.
const STATE_PREFIX: &str = "gs1";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn mac(key: &[u8], signed: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC 은 어떤 길이의 열쇠도 받는다");
    mac.update(signed.as_bytes());
    mac
}

pub fn sign(key: &[u8], token: &Token) -> String {
    let body = serde_json::to_string(token).expect("토큰은 JSON 이 된다");
    let signed = format!("{PREFIX}.{}", hex(body.as_bytes()));
    let signature = hex(&mac(key, &signed).finalize().into_bytes());
    format!("{signed}.{signature}")
}

/// 서명이 맞으면 토큰의 내용을 돌려준다. 만료와 범위는 보지 않는다. 그것은 `scope::judge` 의 일이다.
pub fn verify(key: &[u8], text: &str) -> Option<Token> {
    let mut parts = text.split('.');
    let (prefix, body, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if prefix != PREFIX || parts.next().is_some() {
        return None;
    }
    // 서명을 견주는 데 걸린 시간으로 서명을 맞혀 가지 못하게, 라이브러리의 견주기를 쓴다
    mac(key, &format!("{PREFIX}.{body}"))
        .verify_slice(&unhex(signature)?)
        .ok()?;
    serde_json::from_slice(&unhex(body)?).ok()
}

/// Google 로그인의 `state` 에 서명한다. 모양은 `gs1.<내용의 hex>.<HMAC-SHA256 의 hex>` 다.
pub fn sign_state(key: &[u8], state: &orbital_core::google::StateClaims) -> String {
    let body = serde_json::to_string(state).expect("state 는 JSON 이 된다");
    let signed = format!("{STATE_PREFIX}.{}", hex(body.as_bytes()));
    let signature = hex(&mac(key, &signed).finalize().into_bytes());
    format!("{signed}.{signature}")
}

/// 서명이 맞으면 `state` 의 내용을 돌려준다. 만료는 보지 않는다. 그것은 core 의 `google::judge_state` 의 일이다.
pub fn verify_state(key: &[u8], text: &str) -> Option<orbital_core::google::StateClaims> {
    let mut parts = text.split('.');
    let (prefix, body, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if prefix != STATE_PREFIX || parts.next().is_some() {
        return None;
    }
    mac(key, &format!("{STATE_PREFIX}.{body}"))
        .verify_slice(&unhex(signature)?)
        .ok()?;
    serde_json::from_slice(&unhex(body)?).ok()
}

#[cfg(test)]
mod tests {
    use orbital_core::name::InstanceId;
    use orbital_core::scope::{Capability, OrganizationId};

    use super::*;

    fn token() -> Token {
        Token {
            organization: OrganizationId("org_factory".to_owned()),
            instance: InstanceId::parse("k3f9x2ab").unwrap(),
            can: [Capability::Source, Capability::Preview].into(),
            expires_at: 2_000_000_000,
        }
    }

    #[test]
    fn 서명한_토큰은_같은_열쇠로_확인하면_내용이_그대로_나온다() {
        assert_eq!(verify(b"key", &sign(b"key", &token())), Some(token()));
    }

    #[test]
    fn 다른_열쇠로_서명한_토큰은_읽히지_않는다() {
        assert_eq!(verify(b"key", &sign(b"other", &token())), None);
    }

    #[test]
    fn 내용을_고친_토큰은_읽히지_않는다() {
        let signed = sign(b"key", &token());
        let mut wider = token();
        wider.can.insert(Capability::Rehearse);
        let forged_body = hex(serde_json::to_string(&wider).unwrap().as_bytes());
        let signature = signed.rsplit('.').next().unwrap();
        assert_eq!(
            verify(b"key", &format!("orb1.{forged_body}.{signature}")),
            None
        );
    }

    #[test]
    fn 모양이_다른_글자열은_읽히지_않는다() {
        for bad in [
            "",
            "orb1",
            "orb1..",
            "orb2.00.00",
            "orb1.zz.zz",
            "orb1.00.00.00",
            "sk_live_123",
        ] {
            assert_eq!(verify(b"key", bad), None, "{bad}");
        }
    }

    #[test]
    fn 운영을_바꾸는_능력을_적어_서명해도_토큰으로_읽히지_않는다() {
        // 서버의 열쇠를 가진 쪽이 잘못 서명했더라도 core 의 타입에 없는 능력은 읽히지 않는다
        let body = r#"{"organization":"org_factory","instance":"k3f9x2ab","can":["promote"],"expires_at":2000000000}"#;
        let signed = format!("orb1.{}", hex(body.as_bytes()));
        let signature = hex(&mac(b"key", &signed).finalize().into_bytes());
        assert_eq!(verify(b"key", &format!("{signed}.{signature}")), None);
    }
}
