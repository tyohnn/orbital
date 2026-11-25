//! PKCE(S256)를 속성 테스트로 잰다(사다리 2단계). 해시는 이 crate 가 `sha2` 로 계산하고, core 는 계산된 값을 견주기만 한다.
//!
//! 오라클은 구현을 다시 부르지 않는다. `sha2` 의 값을 비트 글자열로 풀어 따로 적은 base64url 로 challenge 를 만든다.

use orbital_pg::oauth::verifier_matches;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn challenge_of(verifier: &str) -> String {
    let table: Vec<char> = ('A'..='Z')
        .chain('a'..='z')
        .chain('0'..='9')
        .chain(['-', '_'])
        .collect();
    let bits: String = Sha256::digest(verifier.as_bytes())
        .iter()
        .map(|byte| format!("{byte:08b}"))
        .collect();
    bits.as_bytes()
        .chunks(6)
        .map(|chunk| {
            let mut six = String::from_utf8(chunk.to_vec()).unwrap();
            while six.len() < 6 {
                six.push('0');
            }
            table[usize::from_str_radix(&six, 2).unwrap()]
        })
        .collect()
}

proptest! {
    #[test]
    fn 어떤_verifier_든_제_challenge_에만_맞는다(
        mine in "[A-Za-z0-9._~-]{43,128}",
        other in "[A-Za-z0-9._~-]{43,128}",
    ) {
        let challenge = challenge_of(&mine);
        prop_assert!(verifier_matches(&challenge, &mine));
        prop_assert_eq!(verifier_matches(&challenge, &other), other == mine);
    }
}
