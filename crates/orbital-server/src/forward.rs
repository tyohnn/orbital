//! 넘겨 주기. 다른 기계에 놓인 인스턴스의 요청을 받은 관리 서버가 그 요청을 놓인 기계로 그대로 넘기고 답을 그대로 돌려준다.
//!
//! 넘길지는 core 의 `placement::route` 가 판정한다. 여기서는 그 답대로 보낸다.
//! 넘기는 요청에는 [`FORWARDED_BY`] 를 붙인다. 받는 쪽은 이 머리말이 있는 요청을 다시 넘기지 않는다(고리 막기).
//! 이 머리말은 아무 권한도 주지 않는다. 받는 쪽은 토큰과 service key 를 처음 받은 요청과 똑같이 다시 판정한다.
//!
//! 관리 API 는 연결을 맺는 시간만 짧게 둔다. 프리뷰와 승격은 분 단위로 걸리므로 답을 기다리는 시간은 끊지 않는다.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 넘긴 요청에 붙이는 머리말. 값은 넘긴 기계의 이름이다. 권한을 주지 않고 「다시 넘기지 말라」는 뜻만 있다.
pub const FORWARDED_BY: &str = "x-orbital-forwarded-by";

/// 놓인 기계에 연결을 맺기를 기다리는 시간. 넘으면 닿지 못한 것이다.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// 답에서 그대로 돌려줄 머리말. 본문의 종류는 따로 옮긴다. 연결 하나에만 걸리는 것과 길이는 이 서버가 다시 적는다.
const KEPT: [&str; 9] = [
    "www-authenticate",
    "cache-control",
    "location",
    "referrer-policy",
    "retry-after",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
];

/// 넘길 요청. 받은 그대로다.
pub struct Outgoing<'a> {
    pub method: &'a str,
    /// 경로와 질의.
    pub path: &'a str,
    /// 받은 `Authorization` 머리말 그대로(`Bearer` 든 git 의 `Basic` 이든).
    pub authorization: Option<&'a str>,
    pub content_type: Option<&'a str>,
    /// git 이 줄여 보낸 본문(`gzip`)은 줄인 그대로 넘기므로 함께 넘긴다.
    pub content_encoding: Option<&'a str>,
    pub body: &'a [u8],
}

/// 놓인 기계의 답.
pub struct Answered {
    pub status: u16,
    pub content_type: String,
    /// 그대로 돌려줄 머리말([`KEPT`] 가운데 온 것).
    pub headers: Vec<(String, String)>,
    /// 본문. 다 받기 전에 흘려 보낸다(git 의 받기는 pack 을 흘려 보낸다).
    pub body: Box<dyn Read + Send>,
}

/// 넘긴 결과.
pub enum Relayed {
    Answered(Answered),
    /// 연결을 맺지 못했다. 놓인 기계는 요청을 받지 못했다.
    Unreachable,
    /// 연결은 맺었지만 답을 받기 전에 끊겼다. 놓인 기계가 일을 했는지는 모른다.
    Interrupted,
}

/// `base`(놓인 기계의 관리 API 주소)로 요청을 넘긴다. `here` 는 이 기계의 이름이다.
pub fn relay(base: &str, here: &str, outgoing: &Outgoing<'_>) -> Relayed {
    // 경로는 `/` 로 시작해야 한다. 그러지 않은 것을 주소 뒤에 붙이면 `http://기계@다른곳/…` 처럼 다른 호스트를 가리키는 주소가 되어
    // 받은 열쇠(`Authorization`)가 그리로 간다. 관리 API 의 길은 모두 `/v1/` 로 시작하므로 여기 닿으면 안 되는 모양이다
    if !sound_path(outgoing.path) {
        return Relayed::Unreachable;
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        // 답의 `Location` 은 따라가지 않고 그대로 돌려준다
        .redirects(0)
        .build();
    let mut request = agent
        .request(outgoing.method, &format!("{base}{}", outgoing.path))
        .set(FORWARDED_BY, here);
    for (name, value) in [
        ("Authorization", outgoing.authorization),
        ("Content-Type", outgoing.content_type),
        ("Content-Encoding", outgoing.content_encoding),
    ] {
        if let Some(value) = value {
            request = request.set(name, value);
        }
    }
    let response = match request.send_bytes(outgoing.body) {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(transport)) => {
            return match transport.kind() {
                ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed => Relayed::Unreachable,
                _ => Relayed::Interrupted,
            };
        }
    };
    let headers = KEPT
        .iter()
        .filter_map(|name| {
            response
                .header(name)
                .map(|value| ((*name).to_owned(), value.to_owned()))
        })
        .collect();
    Relayed::Answered(Answered {
        status: response.status(),
        content_type: response
            .header("content-type")
            .unwrap_or("application/octet-stream")
            .to_owned(),
        headers,
        body: Box::new(response.into_reader()),
    })
}

/// 주소 뒤에 그대로 붙여도 호스트가 바뀌지 않는 경로인가. `/` 로 시작하고 공백 · 제어 글자가 없어야 한다.
fn sound_path(path: &str) -> bool {
    path.starts_with('/')
        && !path
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
}

/// 넘길 곳을 찾은 결과를 잠깐 기억하는 것. 하위 도메인으로 온 고객의 요청마다 기록(control database)을 읽지 않게 한다.
///
/// 기억에 없는 곳은 한 번에 하나씩만 찾는다. 모르는 하위 도메인으로 요청을 쏟아부어도 기록에 붙는 연결이 늘지 않는다.
/// 기억은 `keep` 동안만 믿는다. 그사이 인스턴스가 지워졌거나 기계의 주소가 바뀌었으면 그만큼 늦게 따라간다.
pub struct Remembered {
    keep: Duration,
    limit: usize,
    found: Mutex<HashMap<String, (Instant, Option<String>)>>,
    /// 기록을 읽는 차례. 기억에 없는 곳을 찾는 일을 한 줄로 세운다.
    turn: Mutex<()>,
}

impl Remembered {
    /// `keep` 동안 기억하고, `limit` 곳을 넘으면 모두 잊는다.
    pub fn new(keep: Duration, limit: usize) -> Self {
        Self {
            keep,
            limit,
            found: Mutex::new(HashMap::new()),
            turn: Mutex::new(()),
        }
    }

    fn recall(&self, place: &str, now: Instant) -> Option<Option<String>> {
        let found = self
            .found
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        found
            .get(place)
            .filter(|(at, _)| now.saturating_duration_since(*at) < self.keep)
            .map(|(_, address)| address.clone())
    }

    /// `place` 를 넘길 곳. 기억에 있으면 그것을, 없으면 `find` 로 찾아 기억한다. 넘기지 않을 곳(`None`)도 기억한다.
    pub fn address(
        &self,
        place: &str,
        now: Instant,
        find: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        if let Some(known) = self.recall(place, now) {
            return known;
        }
        let _turn = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 차례를 기다리는 사이에 앞의 요청이 찾아 두었을 수 있다
        if let Some(known) = self.recall(place, now) {
            return known;
        }
        let address = find();
        let mut found = self
            .found
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if found.len() >= self.limit {
            found.clear();
        }
        found.insert(place.to_owned(), (now, address.clone()));
        address
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn 주소_뒤에_붙여도_호스트가_바뀌지_않는_경로만_넘긴다() {
        assert!(sound_path("/v1/instances/k3f9x2ab/previews"));
        assert!(sound_path(
            "/v1/instances/k3f9x2ab/git/info/refs?service=git-upload-pack"
        ));
        // `/` 로 시작하지 않으면 주소의 호스트 자리에 이어 붙는다
        assert!(!sound_path(
            "@attacker.example/v1/instances/k3f9x2ab/previews"
        ));
        assert!(!sound_path("v1/instances/k3f9x2ab/previews"));
        assert!(!sound_path(""));
        assert!(!sound_path(
            "/v1/instances/k3f9x2ab/previews\r\nHost: attacker.example"
        ));
        assert!(!sound_path("/v1/a b"));
        // 그런 경로는 어디에도 보내지 않는다. `@` 뒤의 주소에서 듣고 있어도 연결이 오지 않는다.
        // 듣는 쪽은 온 연결을 세고 바로 닫는다(방어가 빠졌을 때 이 테스트가 멈추지 않고 실패하게)
        let elsewhere = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        elsewhere.set_nonblocking(true).unwrap();
        let path = format!(
            "@{}/v1/instances/k3f9x2ab/previews",
            elsewhere.local_addr().unwrap()
        );
        let reached = AtomicUsize::new(0);
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    if let Ok((stream, _)) = elsewhere.accept() {
                        reached.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let outgoing = Outgoing {
                method: "POST",
                path: &path,
                authorization: Some("Bearer sk_test_never_sent"),
                content_type: None,
                content_encoding: None,
                body: &[],
            };
            let relayed = relay("http://127.0.0.1:9", "a", &outgoing);
            std::thread::sleep(Duration::from_millis(50));
            done.store(true, Ordering::SeqCst);
            assert!(matches!(relayed, Relayed::Unreachable));
        });
        assert_eq!(
            reached.load(Ordering::SeqCst),
            0,
            "열쇠를 실은 요청이 다른 호스트로 갔습니다"
        );
    }

    #[test]
    fn 넘길_곳은_정한_동안만_기억하고_그동안은_다시_찾지_않는다() {
        let remembered = Remembered::new(Duration::from_secs(5), 8);
        let asked = AtomicUsize::new(0);
        let find = |address: Option<&str>| {
            asked.fetch_add(1, Ordering::SeqCst);
            address.map(str::to_owned)
        };
        let start = Instant::now();
        // 처음에는 찾는다
        assert_eq!(
            remembered.address("k3f9x2ab", start, || find(Some("http://10.0.0.2:8080"))),
            Some("http://10.0.0.2:8080".to_owned())
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // 기억하는 동안(끝 바로 앞까지)은 다시 찾지 않는다. 그사이 답이 달라졌어도 기억한 것을 준다
        let almost = start + Duration::from_millis(4_999);
        assert_eq!(
            remembered.address("k3f9x2ab", almost, || find(None)),
            Some("http://10.0.0.2:8080".to_owned())
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // 정한 동안이 지나면 다시 찾는다
        let after = start + Duration::from_secs(5);
        assert_eq!(remembered.address("k3f9x2ab", after, || find(None)), None);
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        // 넘기지 않을 곳도 기억한다. 모르는 하위 도메인을 되풀이해 물어도 기록을 다시 읽지 않는다
        assert_eq!(
            remembered.address("k3f9x2ab", after, || find(Some("http://10.0.0.9:1"))),
            None
        );
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        // 다른 곳은 따로 찾는다
        assert_eq!(
            remembered.address("k3f9x2abc", after, || find(Some("http://10.0.0.3:8080"))),
            Some("http://10.0.0.3:8080".to_owned())
        );
        assert_eq!(asked.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn 기억은_상한을_넘으면_비워_끝없이_자라지_않는다() {
        let remembered = Remembered::new(Duration::from_secs(60), 4);
        let now = Instant::now();
        for place in 0..100 {
            remembered.address(&format!("p{place}"), now, || None);
            let held = remembered.found.lock().unwrap().len();
            assert!(held <= 4, "{held}");
        }
    }

    #[test]
    fn 기억에_없는_곳을_여럿이_한꺼번에_물어도_한_번에_하나씩만_찾는다() {
        let remembered = Remembered::new(Duration::from_secs(60), 1024);
        let finding = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let asked = AtomicUsize::new(0);
        let now = Instant::now();
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let (remembered, finding, most, asked) = (&remembered, &finding, &most, &asked);
                scope.spawn(move || {
                    for round in 0..4 {
                        // 반은 같은 곳을, 반은 저마다 다른 곳을 묻는다
                        let place = if round % 2 == 0 {
                            "same".to_owned()
                        } else {
                            format!("p{thread}x{round}")
                        };
                        remembered.address(&place, now, || {
                            let together = finding.fetch_add(1, Ordering::SeqCst) + 1;
                            most.fetch_max(together, Ordering::SeqCst);
                            asked.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(2));
                            finding.fetch_sub(1, Ordering::SeqCst);
                            None
                        });
                    }
                });
            }
        });
        assert_eq!(most.load(Ordering::SeqCst), 1);
        // 같은 곳은 한 번만, 다른 곳 16개는 한 번씩 찾았다
        assert_eq!(asked.load(Ordering::SeqCst), 17);
    }
}
