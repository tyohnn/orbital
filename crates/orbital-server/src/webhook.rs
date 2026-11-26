//! 웹훅을 보낸다. 팩토리가 준 주소로 레이어가 밖에 요청을 보내는 자리라, 그 요청이 안쪽에 닿지 못하게 가둔다.
//!
//! - 호스트를 풀어 나온 주소 **모두**를 core 의 `webhook::judge_resolved` 로 판정하고, 판정한 그 주소에만 붙는다. 이름을 다시 풀지 않아
//!   판정과 연결 사이에 DNS 가 다른 주소를 내미는 일(rebinding)이 통하지 않는다. TLS 의 이름과 `Host` 는 원래 호스트다.
//! - 걸 때 한 번이 아니라 보낼 때마다 푼다.
//! - 리다이렉트는 따라가지 않고(3xx 는 실패), 프록시를 쓰지 않으며, 연결과 답을 기다리는 시간에 상한을 두고, 답의 본문은 읽지 않고 버린다.
//!
//! 이름을 푸는 일은 [`Resolve`] 로 갈아 끼운다. 테스트가 「사설 주소로 풀리는 이름」을 실제로 만들어 본다.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac};
use orbital_core::webhook::{Address, Allow, Host, Target, judge_resolved};
use sha2::Sha256;

use crate::records::{Attempt, Miss};
use crate::token::hex;

/// 서명을 싣는 머리말.
pub const SIGNATURE_HEADER: &str = "orbital-signature";

/// 이름을 IP 로 푼다. 관리 서버는 운영체제의 것을 쓰고, 테스트가 갈아 끼운다.
pub trait Resolve: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// 운영체제의 풀이(`getaddrinfo`).
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        Ok((host, port)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect())
    }
}

pub fn address_of(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(v4) => Address::V4(v4.octets()),
        IpAddr::V6(v6) => Address::V6(v6.segments()),
    }
}

/// 호스트를 풀어 판정한다. 받으면 붙을 주소들이다.
pub fn resolve_judged(
    resolver: &dyn Resolve,
    target: &Target,
    allow: Allow,
) -> Result<Vec<SocketAddr>, Miss> {
    let ips = match &target.host {
        Host::Ip(Address::V4(octets)) => vec![IpAddr::from(*octets)],
        Host::Ip(Address::V6(segments)) => vec![IpAddr::from(*segments)],
        Host::Name(name) => resolver
            .resolve(name, target.port)
            .map_err(|_| Miss::Unresolved)?,
    };
    let addresses: Vec<Address> = ips.iter().copied().map(address_of).collect();
    match judge_resolved(&addresses, allow) {
        Ok(()) => Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, target.port))
            .collect()),
        Err(orbital_core::webhook::ResolveRefusal::Empty) => Err(Miss::Unresolved),
        Err(orbital_core::webhook::ResolveRefusal::Inside { .. }) => Err(Miss::RefusedAddress),
    }
}

/// 서명의 머리말 값: `t=<유닉스 초>,v1=<hex(HMAC-SHA256(비밀, "<t>.<본문>"))>`.
pub fn signature(secret: &str, at: u64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC 은 어떤 길이의 열쇠도 받는다");
    mac.update(format!("{at}.").as_bytes());
    mac.update(body);
    format!("t={at},v1={}", hex(&mac.finalize().into_bytes()))
}

/// 보내는 데 필요한 것.
pub struct Sending<'a> {
    pub url: &'a str,
    pub target: &'a Target,
    pub allow: Allow,
    pub resolver: Arc<dyn Resolve>,
    pub timeout: Duration,
    pub body: &'a [u8],
    pub signature: &'a str,
    pub event_id: u64,
    pub event_type: &'a str,
}

/// 이벤트 하나를 보낸다. 2xx 면 보낸 것이다.
pub fn send(sending: &Sending<'_>) -> Attempt {
    // 판정은 ureq 가 이름을 풀 자리에서 한다. 판정한 주소만 돌려주고, ureq 는 그 주소로 붙는다
    let refused: Arc<Mutex<Option<Miss>>> = Arc::new(Mutex::new(None));
    let resolver = {
        let refused = Arc::clone(&refused);
        let target = sending.target.clone();
        let allow = sending.allow;
        let inner = Arc::clone(&sending.resolver);
        // ureq 가 넘기는 이름(`_netloc`)은 보지 않고 늘 판정한 주소의 호스트를 푼다. 무엇이 와도 그 주소 밖으로는 붙지 않는다
        move |_netloc: &str| -> io::Result<Vec<SocketAddr>> {
            match resolve_judged(inner.as_ref(), &target, allow) {
                Ok(addresses) => Ok(addresses),
                Err(miss) => {
                    *refused
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(miss);
                    Err(io::Error::other("받지 않는 주소"))
                }
            }
        }
    };
    let agent = ureq::AgentBuilder::new()
        .resolver(resolver)
        .redirects(0)
        .timeout_connect(sending.timeout.min(Duration::from_secs(5)))
        .timeout(sending.timeout)
        .user_agent("orbital-webhook/1")
        .try_proxy_from_env(false)
        .build();
    let answer = agent
        .post(sending.url)
        .set("content-type", "application/json")
        .set(SIGNATURE_HEADER, sending.signature)
        .set("orbital-event-id", &sending.event_id.to_string())
        .set("orbital-event-type", sending.event_type)
        .send_bytes(sending.body);
    let refused = *refused
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match answer {
        // 답의 본문은 읽지 않고 버린다
        Ok(response) => {
            let status = response.status();
            drop(response);
            Attempt {
                status: Some(status),
                miss: (!(200..300).contains(&status)).then_some(Miss::Status),
            }
        }
        Err(ureq::Error::Status(status, response)) => {
            drop(response);
            Attempt {
                status: Some(status),
                miss: Some(Miss::Status),
            }
        }
        Err(ureq::Error::Transport(transport)) => {
            let miss = refused.unwrap_or_else(|| match transport.kind() {
                ureq::ErrorKind::Dns => Miss::Unresolved,
                ureq::ErrorKind::Io if timed_out(&transport) => Miss::TimedOut,
                _ => Miss::Unreachable,
            });
            Attempt {
                status: None,
                miss: Some(miss),
            }
        }
    }
}

fn timed_out(transport: &ureq::Transport) -> bool {
    use std::error::Error as _;
    let mut source = transport.source();
    while let Some(error) = source {
        if let Some(io) = error.downcast_ref::<io::Error>()
            && matches!(
                io.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        {
            return true;
        }
        source = error.source();
    }
    false
}
