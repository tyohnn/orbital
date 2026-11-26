//! 인스턴스마다의 하위 도메인. 레이어가 주소 하나에서 모든 인스턴스의 요청을 받고 `Host` 로 가른다.
//!
//! `<인스턴스>.<기준 도메인>` 은 그 인스턴스의 운영, `<인스턴스>-preview.<기준 도메인>` 은 프리뷰다.
//! 인스턴스의 식별자에는 `-` 가 없어 둘이 겹치지 않는다. 호스트 이름은 대소문자를 가리지 않으므로(RFC 4343) `Host` 를 소문자로 접고,
//! 이름 끝의 `.` 하나(완전한 이름의 표시)를 뗀 뒤에 견준다. 그 밖에는 글자 그대로 본다(포트는 기준 도메인의 것과 글자까지 같아야 한다).
//! 기준 도메인은 바깥에서 보이는 그대로 적는다. 포트가 붙는 자리(로컬)면 `orbital.test:7480` 처럼 포트까지 적는다.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::name::InstanceId;

/// 프리뷰의 하위 도메인에 붙는 꼬리.
pub const PREVIEW_SUFFIX: &str = "-preview";

/// 기준 도메인. 소문자 이름 조각을 `.` 으로 이은 것이고, 바깥 포트가 있으면 `:포트` 가 붙는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BaseDomain(String);

/// 기준 도메인으로 쓸 수 없는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseDomainProblem {
    Empty,
    /// 소문자 · 숫자 · `-` 가 아닌 글자가 있다(대문자 · 밑줄 · 스킴 · 경로 같은).
    BadCharacter,
    /// 비었거나 63자를 넘거나 `-` 로 시작하거나 끝나는 조각이 있다.
    BadLabel,
    /// 포트가 1에서 65535 사이의 숫자가 아니다.
    BadPort,
}

impl fmt::Display for BaseDomainProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "기준 도메인이 비었습니다. `orbital.example` 처럼 적어 주세요",
            Self::BadCharacter => {
                "기준 도메인에는 소문자 · 숫자 · `-` · `.` 만 씁니다. 스킴(`https://`)과 경로를 빼고 소문자로 적어 주세요"
            }
            Self::BadLabel => {
                "기준 도메인의 조각은 1자에서 63자이고 `-` 로 시작하거나 끝나지 않아야 합니다. 이름을 고쳐 주세요"
            }
            Self::BadPort => {
                "기준 도메인의 포트는 1에서 65535 사이의 숫자여야 합니다. 포트가 바깥에서 보이지 않으면 빼 주세요"
            }
        })
    }
}

impl BaseDomain {
    pub fn parse(text: &str) -> Result<Self, BaseDomainProblem> {
        if text.is_empty() {
            return Err(BaseDomainProblem::Empty);
        }
        let allowed = |byte: u8| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b':')
        };
        if !text.bytes().all(allowed) || text.matches(':').count() > 1 {
            return Err(BaseDomainProblem::BadCharacter);
        }
        let (name, port) = match text.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (text, None),
        };
        if let Some(port) = port {
            let valid = !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && !port.starts_with('0')
                && port
                    .parse::<u32>()
                    .is_ok_and(|port| (1..=65_535).contains(&port));
            if !valid {
                return Err(BaseDomainProblem::BadPort);
            }
        }
        if name.is_empty() {
            return Err(BaseDomainProblem::Empty);
        }
        if !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        }) {
            return Err(BaseDomainProblem::BadCharacter);
        }
        let labels_ok = name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
        if !labels_ok {
            return Err(BaseDomainProblem::BadLabel);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BaseDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for BaseDomain {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).map_err(|problem| problem.to_string())
    }
}

impl From<BaseDomain> for String {
    fn from(base: BaseDomain) -> Self {
        base.0
    }
}

/// 바깥에서 쓰는 스킴. TLS 는 레이어 앞에서 끝난다고 보고 운영은 `https`, 로컬은 `http` 다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// 요청이 가는 곳. 인스턴스 하나의 운영이거나 프리뷰다.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "stage", content = "instance", rename_all = "snake_case")]
pub enum HostTarget {
    Production(InstanceId),
    Preview(InstanceId),
}

impl HostTarget {
    pub fn instance(&self) -> &InstanceId {
        match self {
            Self::Production(instance) | Self::Preview(instance) => instance,
        }
    }

    /// 이 곳의 하위 도메인 조각(`<인스턴스>` 이거나 `<인스턴스>-preview`).
    fn label(&self) -> String {
        match self {
            Self::Production(instance) => instance.as_str().to_owned(),
            Self::Preview(instance) => format!("{}{PREVIEW_SUFFIX}", instance.as_str()),
        }
    }
}

/// `Host` 머리말의 값이 가리키는 곳. 기준 도메인 바로 아래의 한 조각이고 그 조각이 인스턴스(또는 그 프리뷰)일 때만 있다.
///
/// 대소문자를 접고 이름 끝의 `.` 하나를 뗀 뒤에 본다. 기준 도메인 자체, 두 조각 아래, 다른 도메인, 끝의 `.` 둘,
/// 기준 도메인과 다른 포트는 모두 `None` 이다.
pub fn judge_host(host: &str, base: &BaseDomain) -> Option<HostTarget> {
    let host = fold_host(host);
    let label = host.strip_suffix(base.as_str())?.strip_suffix('.')?;
    let (id, preview) = match label.strip_suffix(PREVIEW_SUFFIX) {
        Some(id) => (id, true),
        None => (label, false),
    };
    let instance = InstanceId::parse(id).ok()?;
    Some(if preview {
        HostTarget::Preview(instance)
    } else {
        HostTarget::Production(instance)
    })
}

/// 호스트를 견줄 모양으로 접는다. ASCII 소문자로 바꾸고, 포트 앞의 이름 끝에 `.` 이 하나 있으면 뗀다.
fn fold_host(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    let (name, port) = match lower.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (lower.as_str(), None),
    };
    let name = name.strip_suffix('.').unwrap_or(name);
    match port {
        Some(port) => format!("{name}:{port}"),
        None => name.to_owned(),
    }
}

/// 그 곳의 origin(`https://<조각>.<기준 도메인>`). 쿠키 · 로그인 링크 · `Origin` 검사 · OAuth 의 발급자가 이것을 쓴다.
pub fn origin(scheme: Scheme, base: &BaseDomain, target: &HostTarget) -> String {
    format!("{}://{}.{base}", scheme.as_str(), target.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(text: &str) -> BaseDomain {
        BaseDomain::parse(text).unwrap()
    }

    fn id(text: &str) -> InstanceId {
        InstanceId::parse(text).unwrap()
    }

    #[test]
    fn 기준_도메인은_소문자_이름과_바깥_포트만_받는다() {
        for good in [
            "orbital.test",
            "apps.factory.example",
            "localhost",
            "orbital.test:7480",
        ] {
            assert!(BaseDomain::parse(good).is_ok(), "{good}");
        }
        for (bad, problem) in [
            ("", BaseDomainProblem::Empty),
            (":80", BaseDomainProblem::Empty),
            ("Orbital.test", BaseDomainProblem::BadCharacter),
            ("https://orbital.test", BaseDomainProblem::BadCharacter),
            ("orbital.test/", BaseDomainProblem::BadCharacter),
            ("orbital_test", BaseDomainProblem::BadCharacter),
            (".orbital.test", BaseDomainProblem::BadLabel),
            ("orbital..test", BaseDomainProblem::BadLabel),
            ("orbital.test.", BaseDomainProblem::BadLabel),
            ("-orbital.test", BaseDomainProblem::BadLabel),
            ("orbital.test:", BaseDomainProblem::BadPort),
            ("orbital.test:0", BaseDomainProblem::BadPort),
            ("orbital.test:65536", BaseDomainProblem::BadPort),
            ("orbital.test:08", BaseDomainProblem::BadPort),
        ] {
            assert_eq!(BaseDomain::parse(bad), Err(problem), "{bad}");
        }
    }

    #[test]
    fn 인스턴스의_조각은_운영으로_preview_가_붙은_조각은_프리뷰로_간다() {
        let base = base("orbital.test");
        assert_eq!(
            judge_host("k3f9x2ab.orbital.test", &base),
            Some(HostTarget::Production(id("k3f9x2ab")))
        );
        assert_eq!(
            judge_host("k3f9x2ab-preview.orbital.test", &base),
            Some(HostTarget::Preview(id("k3f9x2ab")))
        );
        for unknown in [
            "orbital.test",
            ".orbital.test",
            "x.k3f9x2ab.orbital.test",
            "k3f9x2ab.orbital.test..",
            "k3f9x2ab..orbital.test",
            "k3f9x2ab.orbital.test:80",
            "k3f9x2ab.evilorbital.test",
            "k3f9x2aborbital.test",
            "k3f9x2ab-preview-preview.orbital.test",
            "-preview.orbital.test",
            "short.orbital.test",
            "k3f9x2ab.other.test",
        ] {
            assert_eq!(judge_host(unknown, &base), None, "{unknown}");
        }
    }

    #[test]
    fn 호스트는_대소문자를_가리지_않고_이름_끝의_점_하나를_떼고_견준다() {
        let base = base("orbital.test");
        for host in [
            "K3F9X2AB.orbital.test",
            "k3f9x2ab.ORBITAL.TEST",
            "k3f9x2ab.orbital.test.",
            "K3f9x2Ab.Orbital.Test.",
        ] {
            assert_eq!(
                judge_host(host, &base),
                Some(HostTarget::Production(id("k3f9x2ab"))),
                "{host}"
            );
        }
        assert_eq!(
            judge_host("K3F9X2AB-PREVIEW.orbital.test", &base),
            Some(HostTarget::Preview(id("k3f9x2ab")))
        );
        let with_port = self::base("orbital.test:7480");
        assert_eq!(
            judge_host("K3F9X2AB.orbital.test.:7480", &with_port),
            Some(HostTarget::Production(id("k3f9x2ab")))
        );
        assert_eq!(judge_host("k3f9x2ab.orbital.test:7480.", &with_port), None);
    }

    #[test]
    fn 포트가_붙은_기준_도메인은_그_포트까지_같아야_한다() {
        let base = base("orbital.test:7480");
        assert_eq!(
            judge_host("k3f9x2ab.orbital.test:7480", &base),
            Some(HostTarget::Production(id("k3f9x2ab")))
        );
        assert_eq!(judge_host("k3f9x2ab.orbital.test", &base), None);
        assert_eq!(judge_host("k3f9x2ab.orbital.test:7481", &base), None);
        assert_eq!(
            origin(Scheme::Http, &base, &HostTarget::Preview(id("k3f9x2ab"))),
            "http://k3f9x2ab-preview.orbital.test:7480"
        );
    }

    #[test]
    fn origin_은_스킴과_조각과_기준_도메인으로_선다() {
        let base = base("apps.factory.example");
        assert_eq!(
            origin(
                Scheme::Https,
                &base,
                &HostTarget::Production(id("k3f9x2ab"))
            ),
            "https://k3f9x2ab.apps.factory.example"
        );
    }
}
