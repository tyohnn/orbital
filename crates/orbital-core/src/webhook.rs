//! 웹훅의 주소. 팩토리가 준 주소로 레이어가 요청을 보내므로, 그 요청이 레이어의 안쪽(loopback · 사설망 · 클라우드의 메타데이터
//! 주소)에 닿지 못하게 가둔다.
//!
//! 판정은 둘이다. 주소의 글([`judge_url`])은 걸 때 보고, 호스트를 풀어 나온 IP([`judge_resolved`])는 걸 때와 **보낼 때마다** 본다.
//! 풀어 나온 주소가 **모두** 바깥의 것이어야 하고, 관리 서버는 판정한 그 주소에 붙는다(이름을 다시 풀지 않는다).
//!
//! IP 는 바이트(`[u8; 4]` · `[u16; 8]`)로 받는다. 글을 IP 로 읽을 때만 `core::net` 의 읽기를 쓰고, 네트워크에는 닿지 않는다.

use core::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// 주소의 길이 상한.
pub const URL_MAX: usize = 2048;

/// 어떤 주소까지 받는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Allow {
    /// 기본. `https://` 와 바깥(공인)의 주소만.
    Public,
    /// 명시해 켠 개발용 레이어(`ORBITAL_DEV_WEBHOOK=private`). `http://` 와 loopback · 사설 · CGNAT · ULA 도 받는다.
    /// link-local(메타데이터 주소) · 멀티캐스트 · 사상된 주소 같은 것은 여기서도 받지 않는다.
    Development,
}

/// IP 하나.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Address {
    V4([u8; 4]),
    V6([u16; 8]),
}

/// 주소의 호스트.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    /// 풀어야 하는 이름(소문자로 맞춘 것).
    Name(String),
    /// 주소에 바로 적은 IP.
    Ip(Address),
}

/// 판정을 지난 주소.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// `https://` 인가.
    pub secure: bool,
    pub host: Host,
    pub port: u16,
}

/// 주소의 글이 틀린 까닭. 찾은 것을 모두 돌려준다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "problem")]
pub enum UrlProblem {
    /// `https://` 로 시작하지 않는다(개발용 레이어는 `http://` 도 받는다).
    Scheme { http_allowed: bool },
    /// 사용자 이름이나 비밀번호(`…@`)를 적었다.
    Credentials,
    /// 조각(`#…`)을 적었다.
    Fragment,
    /// 호스트가 없거나 이름 · IP 로 읽히지 않는다(유니코드 이름은 punycode 로 적는다).
    Host,
    /// 포트가 1 에서 65535 사이의 수가 아니다.
    Port,
    /// 길다([`URL_MAX`]자).
    TooLong { max: usize },
    /// 빈칸이나 제어 문자가 있다.
    Characters,
    /// 주소에 적은 IP 가 바깥의 것이 아니다.
    Address { refusal: AddressRefusal },
}

/// 바깥의 주소가 아닌 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressRefusal {
    /// `0.0.0.0/8` · `::`.
    Unspecified,
    /// `127.0.0.0/8` · `::1`.
    Loopback,
    /// `10/8` · `172.16/12` · `192.168/16`.
    Private,
    /// CGNAT `100.64/10`.
    SharedAddressSpace,
    /// `169.254/16`(클라우드의 메타데이터 주소가 여기 있다) · `fe80::/10`.
    LinkLocal,
    /// `224/4` · `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// 문서에 쓰라고 남긴 주소(`192.0.2/24` · `198.51.100/24` · `203.0.113/24` · `2001:db8::/32` · `3fff::/20`).
    Documentation,
    /// 장비 시험용 `198.18/15`.
    Benchmarking,
    /// 그 밖에 남겨 둔 주소(`192.0.0/24` · `192.88.99/24` · `240/4` · `2001::/23` · `fec0::/10`).
    Reserved,
    /// IPv4 를 품은 IPv6(사상 `::ffff:0:0/96` · 6to4 `2002::/16` · Teredo `2001::/32`). 안쪽의 IPv4 로 닿을 수 있다.
    Embedded,
    /// ULA `fc00::/7`.
    UniqueLocal,
    /// 전역 유니캐스트(`2000::/3`) 밖의 IPv6(NAT64 · 옛 IPv4 호환 주소 같은 것).
    NotGlobal,
}

/// 풀어 나온 주소를 받지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "refused")]
pub enum ResolveRefusal {
    /// 풀어 나온 주소가 없다.
    Empty,
    /// 바깥의 것이 아닌 주소가 하나라도 있다.
    Inside { refusal: AddressRefusal },
}

fn v4_refusal([a, b, c, _]: [u8; 4]) -> Option<AddressRefusal> {
    use AddressRefusal as R;
    Some(match (a, b, c) {
        (0, _, _) => R::Unspecified,
        (10, _, _) => R::Private,
        (100, 64..=127, _) => R::SharedAddressSpace,
        (127, _, _) => R::Loopback,
        (169, 254, _) => R::LinkLocal,
        (172, 16..=31, _) => R::Private,
        (192, 0, 0) | (192, 88, 99) => R::Reserved,
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => R::Documentation,
        (192, 168, _) => R::Private,
        (198, 18..=19, _) => R::Benchmarking,
        (224..=239, _, _) => R::Multicast,
        (255, 255, 255) => R::Broadcast,
        (240..=255, _, _) => R::Reserved,
        _ => return None,
    })
}

fn v6_refusal(segments: [u16; 8]) -> Option<AddressRefusal> {
    use AddressRefusal as R;
    let [first, second, ..] = segments;
    if segments == [0; 8] {
        return Some(R::Unspecified);
    }
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return Some(R::Loopback);
    }
    if segments[..5] == [0; 5] && segments[5] == 0xffff {
        return Some(R::Embedded);
    }
    Some(match first {
        0xff00..=0xffff => R::Multicast,
        0xfe80..=0xfebf => R::LinkLocal,
        0xfec0..=0xfeff => R::Reserved,
        0xfc00..=0xfdff => R::UniqueLocal,
        0x2002 => R::Embedded,
        0x2001 if second == 0 => R::Embedded,
        0x2001 if second == 0x0db8 => R::Documentation,
        0x2001 if second < 0x0200 => R::Reserved,
        0x3fff if second < 0x1000 => R::Documentation,
        0x2000..=0x3fff => return None,
        _ => R::NotGlobal,
    })
}

/// IP 하나가 보내도 되는 곳인가. 개발용 레이어는 loopback · 사설 · CGNAT · ULA 도 받는다.
pub fn judge_address(address: Address, allow: Allow) -> Result<(), AddressRefusal> {
    let refusal = match address {
        Address::V4(octets) => v4_refusal(octets),
        Address::V6(segments) => v6_refusal(segments),
    };
    match (refusal, allow) {
        (None, _) => Ok(()),
        (
            Some(
                AddressRefusal::Loopback
                | AddressRefusal::Private
                | AddressRefusal::SharedAddressSpace
                | AddressRefusal::UniqueLocal,
            ),
            Allow::Development,
        ) => Ok(()),
        (Some(refusal), _) => Err(refusal),
    }
}

/// 호스트를 풀어 나온 주소 모두가 보내도 되는 곳인가. 하나라도 아니면 받지 않는다(그중 하나로 붙을 수 있어서다).
pub fn judge_resolved(addresses: &[Address], allow: Allow) -> Result<(), ResolveRefusal> {
    if addresses.is_empty() {
        return Err(ResolveRefusal::Empty);
    }
    for address in addresses {
        judge_address(*address, allow).map_err(|refusal| ResolveRefusal::Inside { refusal })?;
    }
    Ok(())
}

/// 이름 하나가 DNS 의 이름으로 맞는가. 소문자 · 숫자 · `-` 의 조각을 `.` 로 잇는다. 마지막 조각이 숫자뿐이면 이름이 아니다
/// (`127.1` · `2130706433` 같은 IP 의 다른 표기를 이름으로 받지 않는다).
fn name_shaped(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let shaped = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
    shaped
        && labels
            .last()
            .is_some_and(|last| !last.bytes().all(|byte| byte.is_ascii_digit()))
}

fn host_of(text: &str) -> Option<Host> {
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| Host::Ip(Address::V6(address.segments())));
    }
    if let Ok(address) = text.parse::<Ipv4Addr>() {
        return Some(Host::Ip(Address::V4(address.octets())));
    }
    let lowered = text.to_ascii_lowercase();
    name_shaped(&lowered).then_some(Host::Name(lowered))
}

/// 웹훅의 주소를 읽는다. `https://` 만(개발용 레이어는 `http://` 도), 사용자 이름 · 조각 없이, 호스트는 DNS 의 이름이나 IP.
/// 주소에 IP 를 바로 적었으면 그 IP 도 여기서 판정한다.
pub fn judge_url(text: &str, allow: Allow) -> Result<Target, Vec<UrlProblem>> {
    let mut problems = Vec::new();
    if text.len() > URL_MAX {
        problems.push(UrlProblem::TooLong { max: URL_MAX });
    }
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        problems.push(UrlProblem::Characters);
    }
    let lowered = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    let (secure, rest) = if lowered.starts_with("https://") {
        (true, &text[8..])
    } else if lowered.starts_with("http://") && allow == Allow::Development {
        (false, &text[7..])
    } else {
        problems.push(UrlProblem::Scheme {
            http_allowed: allow == Allow::Development,
        });
        return Err(problems);
    };
    if rest.contains('#') {
        problems.push(UrlProblem::Fragment);
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        problems.push(UrlProblem::Credentials);
        return Err(problems);
    }
    // 호스트와 포트를 가른다. IPv6 는 `[…]` 안에 있다
    let (host_text, port_text) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(close) => {
                let (host, tail) = authority.split_at(close + 1);
                match tail.strip_prefix(':') {
                    Some(port) => (host, Some(port)),
                    None if tail.is_empty() => (host, None),
                    None => ("", None),
                }
            }
            None => ("", None),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port_text {
        None => Some(if secure { 443 } else { 80 }),
        Some(digits) if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) => {
            digits.parse::<u16>().ok().filter(|port| *port > 0)
        }
        Some(_) => None,
    };
    if port.is_none() {
        problems.push(UrlProblem::Port);
    }
    let host = host_of(host_text);
    match &host {
        None => problems.push(UrlProblem::Host),
        Some(Host::Ip(address)) => {
            if let Err(refusal) = judge_address(*address, allow) {
                problems.push(UrlProblem::Address { refusal });
            }
        }
        Some(Host::Name(_)) => {}
    }
    match (host, port) {
        (Some(host), Some(port)) if problems.is_empty() => Ok(Target { secure, host, port }),
        _ => Err(problems),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(text: &str) -> Vec<UrlProblem> {
        judge_url(text, Allow::Public).expect_err(text)
    }

    #[test]
    fn 주소는_https_만_받고_사용자_이름과_조각은_받지_않는다() {
        assert_eq!(
            judge_url("https://Hooks.Example.com:8443/orbital?x=1", Allow::Public),
            Ok(Target {
                secure: true,
                host: Host::Name("hooks.example.com".to_owned()),
                port: 8443,
            })
        );
        assert_eq!(
            refused("http://hooks.example.com/"),
            vec![UrlProblem::Scheme {
                http_allowed: false
            }]
        );
        assert_eq!(
            refused("ftp://hooks.example.com/"),
            vec![UrlProblem::Scheme {
                http_allowed: false
            }]
        );
        assert_eq!(
            refused("https://user:pw@hooks.example.com/"),
            vec![UrlProblem::Credentials]
        );
        assert_eq!(
            refused("https://hooks.example.com/a#b"),
            vec![UrlProblem::Fragment]
        );
        assert_eq!(
            refused("https://hooks.example.com:0/"),
            vec![UrlProblem::Port]
        );
        assert_eq!(
            refused("https://hooks.example.com:65536/"),
            vec![UrlProblem::Port]
        );
        assert_eq!(
            refused("https://hooks.example.com/ a"),
            vec![UrlProblem::Characters]
        );
        assert_eq!(refused("https:///path"), vec![UrlProblem::Host]);
        assert!(
            refused(&format!("https://a.example/{}", "x".repeat(URL_MAX)))
                .contains(&UrlProblem::TooLong { max: URL_MAX })
        );
        // 개발용 레이어는 http 와 loopback 을 받는다
        assert_eq!(
            judge_url("http://127.0.0.1:9000/hook", Allow::Development),
            Ok(Target {
                secure: false,
                host: Host::Ip(Address::V4([127, 0, 0, 1])),
                port: 9000,
            })
        );
    }

    #[test]
    fn 주소에_적은_ip_와_ip_의_다른_표기는_걸_때_거절한다() {
        assert_eq!(
            refused("https://127.0.0.1/"),
            vec![UrlProblem::Address {
                refusal: AddressRefusal::Loopback
            }]
        );
        assert_eq!(
            refused("https://169.254.169.254/latest/meta-data"),
            vec![UrlProblem::Address {
                refusal: AddressRefusal::LinkLocal
            }]
        );
        assert_eq!(
            refused("https://[::ffff:127.0.0.1]/"),
            vec![UrlProblem::Address {
                refusal: AddressRefusal::Embedded
            }]
        );
        assert_eq!(
            refused("https://[fd00::1]:8443/"),
            vec![UrlProblem::Address {
                refusal: AddressRefusal::UniqueLocal
            }]
        );
        // 숫자뿐인 이름과 8 · 16 진수의 표기는 이름으로도 IP 로도 받지 않는다
        for text in [
            "https://2130706433/",
            "https://127.1/",
            "https://0x7f.0.0.1/",
            "https://017700000001/",
        ] {
            assert_eq!(refused(text), vec![UrlProblem::Host], "{text}");
        }
        // 공인 주소는 받는다
        assert!(judge_url("https://8.8.8.8/", Allow::Public).is_ok());
        assert!(judge_url("https://[2606:4700::1111]/", Allow::Public).is_ok());
        // 메타데이터 주소는 개발용 레이어에서도 받지 않는다
        assert_eq!(
            judge_url("http://169.254.169.254/", Allow::Development),
            Err(vec![UrlProblem::Address {
                refusal: AddressRefusal::LinkLocal
            }])
        );
    }

    #[test]
    fn 바깥이_아닌_주소의_경계는_양쪽을_가른다() {
        let v4 = |octets| judge_address(Address::V4(octets), Allow::Public);
        assert_eq!(v4([172, 15, 255, 255]), Ok(()));
        assert_eq!(v4([172, 16, 0, 0]), Err(AddressRefusal::Private));
        assert_eq!(v4([172, 31, 255, 255]), Err(AddressRefusal::Private));
        assert_eq!(v4([172, 32, 0, 0]), Ok(()));
        assert_eq!(v4([100, 63, 255, 255]), Ok(()));
        assert_eq!(v4([100, 64, 0, 0]), Err(AddressRefusal::SharedAddressSpace));
        assert_eq!(
            v4([100, 127, 255, 255]),
            Err(AddressRefusal::SharedAddressSpace)
        );
        assert_eq!(v4([100, 128, 0, 0]), Ok(()));
        assert_eq!(v4([223, 255, 255, 255]), Ok(()));
        assert_eq!(v4([224, 0, 0, 0]), Err(AddressRefusal::Multicast));
        assert_eq!(v4([255, 255, 255, 255]), Err(AddressRefusal::Broadcast));
        let v6 = |segments| judge_address(Address::V6(segments), Allow::Public);
        assert_eq!(
            v6([0x1fff, 0xffff, 0, 0, 0, 0, 0, 1]),
            Err(AddressRefusal::NotGlobal)
        );
        assert_eq!(v6([0x2000, 0, 0, 0, 0, 0, 0, 1]), Ok(()));
        assert_eq!(v6([0x3fff, 0x1000, 0, 0, 0, 0, 0, 1]), Ok(()));
        assert_eq!(
            v6([0x4000, 0, 0, 0, 0, 0, 0, 1]),
            Err(AddressRefusal::NotGlobal)
        );
        assert_eq!(
            v6([0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1]),
            Err(AddressRefusal::NotGlobal)
        );
        assert_eq!(
            v6([0xfebf, 0, 0, 0, 0, 0, 0, 1]),
            Err(AddressRefusal::LinkLocal)
        );
        // 풀어 나온 주소는 모두 바깥이어야 한다
        assert_eq!(
            judge_resolved(
                &[Address::V4([8, 8, 8, 8]), Address::V4([10, 0, 0, 1])],
                Allow::Public
            ),
            Err(ResolveRefusal::Inside {
                refusal: AddressRefusal::Private
            })
        );
        assert_eq!(
            judge_resolved(&[], Allow::Public),
            Err(ResolveRefusal::Empty)
        );
        assert_eq!(
            judge_resolved(&[Address::V4([8, 8, 8, 8])], Allow::Public),
            Ok(())
        );
    }
}
