//! 밖에서 넣는 비밀(`[secrets] external`)의 판정. 값이 어디에 들어가고, 무엇이 빠졌고, 입력 표를 받을지를 정한다.
//!
//! 값은 인스턴스와 단계(프리뷰 · 운영)마다 따로다. 프리뷰의 앱은 에이전트가 쓴 코드이고 에이전트가 그 로그와 답을 읽으므로,
//! 프리뷰의 값은 에이전트가 볼 수 있다고 본다. 그래서 두 칸은 서로 넘어가지 않고, 한쪽이 없다고 다른 쪽으로 대신하지 않는다.
//!
//! 값을 봉인하고 파일에 두는 일, 입력 표의 난수와 해시, 시계는 어댑터(관리 서버)가 맡는다. 여기서는 풀린 값과 시각을 받아 판정만 한다.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::manifest::ValidManifest;
use crate::name::{InstanceId, SecretName};

/// 값의 상한. 64 KiB.
pub const VALUE_MAX: usize = 64 * 1024;
/// 입력 표가 읽히는 시간. 사람이 카드에서 값을 붙여 넣는 동안이다.
pub const ENTRY_TTL: u64 = 10 * 60;
/// 요청의 까닭의 상한(글자 수).
pub const REASON_MAX: usize = 500;

/// 값이 들어가는 단계. 프리뷰의 값은 에이전트가 볼 수 있다고 본다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preview,
    Production,
}

impl Stage {
    pub const ALL: [Self; 2] = [Self::Preview, Self::Production];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Production => "production",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "preview" => Some(Self::Preview),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

/// 값을 받지 않는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ValueProblem {
    Empty,
    TooLarge {
        max: usize,
    },
    /// NUL(`\0`)이 들었다. 환경 변수에 실을 수 없다.
    Nul,
}

/// 값을 받을지 본다. 비어 있지 않고, 64 KiB 이하이고, NUL 이 없어야 한다. 찾은 문제를 모두 돌려준다.
pub fn judge_value(value: &str) -> Vec<ValueProblem> {
    let mut problems = Vec::new();
    if value.is_empty() {
        problems.push(ValueProblem::Empty);
    }
    if value.len() > VALUE_MAX {
        problems.push(ValueProblem::TooLarge { max: VALUE_MAX });
    }
    if value.contains('\0') {
        problems.push(ValueProblem::Nul);
    }
    problems
}

/// 선언에서 밖에서 넣는다고 적은 비밀 가운데 `filled` 에 없는 것. 선언에 적힌 차례다.
pub fn missing_secrets(manifest: &ValidManifest, filled: &BTreeSet<SecretName>) -> Vec<SecretName> {
    manifest
        .get()
        .secrets
        .external
        .iter()
        .filter(|name| !filled.contains(*name))
        .cloned()
        .collect()
}

/// `after` 가 선언했는데 `before` 가 선언하지 않은 이름. 이번 변경으로 앱이 새로 받게 되는 비밀이다. 승인 카드에 선다.
pub fn newly_received(before: &[SecretName], after: &[SecretName]) -> Vec<SecretName> {
    after
        .iter()
        .filter(|name| !before.contains(name))
        .cloned()
        .collect()
}

/// 비밀의 입력을 요청하지 못하는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum RequestProblem {
    /// 그 인스턴스의 어느 release 도 `[secrets] external` 에 적지 않은 이름이다.
    Undeclared,
    ReasonEmpty,
    ReasonTooLong {
        max: usize,
    },
}

/// 요청을 받을지 본다. `declared` 는 그 인스턴스의 release(프리뷰로 세운 것과 운영의 것)가 밖에서 넣는다고 적은 이름이다.
pub fn judge_request(
    declared: &BTreeSet<SecretName>,
    name: &SecretName,
    reason: &str,
) -> Vec<RequestProblem> {
    let mut problems = Vec::new();
    if !declared.contains(name) {
        problems.push(RequestProblem::Undeclared);
    }
    if reason.trim().is_empty() {
        problems.push(RequestProblem::ReasonEmpty);
    }
    if reason.chars().count() > REASON_MAX {
        problems.push(RequestProblem::ReasonTooLong { max: REASON_MAX });
    }
    problems
}

/// 값이 들어갈 자리 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    pub instance: InstanceId,
    pub name: SecretName,
    pub stage: Stage,
}

/// 입력 표 하나. 자리 하나에 묶이고 한 번만 쓴다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub place: Place,
    /// 이 시각(유닉스 초)부터 쓰지 못한다.
    pub expires_at: u64,
    pub used: bool,
}

pub fn entry_expires_at(issued_at: u64) -> u64 {
    issued_at + ENTRY_TTL
}

/// 입력 표를 쓰지 못하는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryRefusal {
    Used,
    Expired,
    /// 표가 묶인 자리(인스턴스 · 이름 · 단계)가 아닌 곳에 넣으려 했다.
    OtherPlace,
}

/// 입력 표로 `wanted` 자리에 값을 넣어도 되는지 본다. 경계는 `at < expires_at` 이다.
pub fn judge_entry(entry: &Entry, wanted: &Place, at: u64) -> Result<(), EntryRefusal> {
    if entry.used {
        return Err(EntryRefusal::Used);
    }
    if at >= entry.expires_at {
        return Err(EntryRefusal::Expired);
    }
    if &entry.place != wanted {
        return Err(EntryRefusal::OtherPlace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> SecretName {
        SecretName::parse(text).unwrap()
    }

    fn manifest(external: &str) -> ValidManifest {
        let text = format!(
            r#"
[[service]]
name = "web"
kind = "server"
build = "true"
start = "true"
path = "/"

[secrets]
generated = ["SESSION_KEY"]
external = [{external}]
"#
        );
        toml::from_str::<crate::manifest::Manifest>(&text)
            .unwrap()
            .check()
            .unwrap()
    }

    fn place(instance: &str, secret: &str, stage: Stage) -> Place {
        Place {
            instance: InstanceId::parse(instance).unwrap(),
            name: name(secret),
            stage,
        }
    }

    fn entry() -> Entry {
        Entry {
            place: place("k3f9x2ab", "BANK_API_KEY", Stage::Production),
            expires_at: entry_expires_at(1_000),
            used: false,
        }
    }

    #[test]
    fn 선언한_비밀이_모두_채워지면_비밀_때문에_막히지_않는다() {
        let manifest = manifest(r#""BANK_API_KEY", "MAP_KEY""#);
        let filled: BTreeSet<SecretName> = [name("MAP_KEY"), name("BANK_API_KEY")].into();
        assert_eq!(missing_secrets(&manifest, &filled), vec![]);
        // 하나가 빠지면 그 이름만 돌려준다. 만드는 비밀(`generated`)은 묻지 않는다
        let partly: BTreeSet<SecretName> = [name("MAP_KEY")].into();
        assert_eq!(
            missing_secrets(&manifest, &partly),
            vec![name("BANK_API_KEY")]
        );
        let release = crate::release::Release {
            id: crate::release::ReleaseId("r1".to_owned()),
            built_by: crate::release::BuiltBy::Layer,
            access_findings: 0,
            rehearsal: crate::release::Rehearsed::Passed,
            missing_keys: Vec::new(),
            missing_secrets: missing_secrets(&manifest, &filled),
            conformance: crate::release::Conformed::NotDeclared,
        };
        assert_eq!(crate::release::blockers(&release), vec![]);
    }

    #[test]
    fn 선언하지_않은_이름은_요청하지_못한다() {
        let declared: BTreeSet<SecretName> = [name("BANK_API_KEY")].into();
        assert_eq!(
            judge_request(
                &declared,
                &name("BANK_API_KEY"),
                "송금을 하려면 은행의 키가 필요합니다"
            ),
            vec![]
        );
        assert_eq!(
            judge_request(&declared, &name("MAP_KEY"), "지도"),
            vec![RequestProblem::Undeclared]
        );
        assert_eq!(
            judge_request(&BTreeSet::new(), &name("BANK_API_KEY"), "까닭"),
            vec![RequestProblem::Undeclared]
        );
        // 까닭은 비어 있지 않고 500자 이하여야 한다. 경계의 양쪽을 본다
        assert_eq!(
            judge_request(&declared, &name("BANK_API_KEY"), "  "),
            vec![RequestProblem::ReasonEmpty]
        );
        assert_eq!(
            judge_request(&declared, &name("BANK_API_KEY"), &"가".repeat(REASON_MAX)),
            vec![]
        );
        assert_eq!(
            judge_request(&declared, &name("MAP_KEY"), &"가".repeat(REASON_MAX + 1)),
            vec![
                RequestProblem::Undeclared,
                RequestProblem::ReasonTooLong { max: REASON_MAX }
            ]
        );
    }

    #[test]
    fn 입력_표는_묶인_이름과_단계에만_쓰인다() {
        let entry = entry();
        assert_eq!(judge_entry(&entry, &entry.place, 1_000), Ok(()));
        for wanted in [
            place("k3f9x2ab", "BANK_API_KEY", Stage::Preview),
            place("k3f9x2ab", "MAP_KEY", Stage::Production),
            place("k3f9x2abc", "BANK_API_KEY", Stage::Production),
        ] {
            assert_eq!(
                judge_entry(&entry, &wanted, 1_000),
                Err(EntryRefusal::OtherPlace),
                "{wanted:?}"
            );
        }
    }

    #[test]
    fn 입력_표는_십_분이_지나면_쓰지_못한다() {
        let entry = entry();
        assert_eq!(entry.expires_at, 1_000 + 600);
        assert_eq!(judge_entry(&entry, &entry.place, 1_599), Ok(()));
        assert_eq!(
            judge_entry(&entry, &entry.place, 1_600),
            Err(EntryRefusal::Expired)
        );
    }

    #[test]
    fn 이미_쓴_입력_표는_다시_쓰지_못한다() {
        let mut entry = entry();
        entry.used = true;
        assert_eq!(
            judge_entry(&entry, &entry.place, 1_000),
            Err(EntryRefusal::Used)
        );
    }

    #[test]
    fn 빈_값과_너무_큰_값과_nul_이_든_값은_받지_않는다() {
        assert_eq!(judge_value("sk_live_value"), vec![]);
        assert_eq!(judge_value(""), vec![ValueProblem::Empty]);
        // 크기는 바이트로 센다. 경계의 양쪽을 본다
        assert_eq!(judge_value(&"a".repeat(VALUE_MAX)), vec![]);
        assert_eq!(
            judge_value(&"a".repeat(VALUE_MAX + 1)),
            vec![ValueProblem::TooLarge { max: VALUE_MAX }]
        );
        assert_eq!(
            judge_value(&"가".repeat(VALUE_MAX / 3 + 1)),
            vec![ValueProblem::TooLarge { max: VALUE_MAX }]
        );
        assert_eq!(judge_value("ab\0cd"), vec![ValueProblem::Nul]);
        assert_eq!(
            judge_value(&format!("{}\0", "a".repeat(VALUE_MAX))),
            vec![ValueProblem::TooLarge { max: VALUE_MAX }, ValueProblem::Nul]
        );
    }

    #[test]
    fn 새로_받게_되는_비밀은_운영의_release_에_없던_이름이다() {
        let before = [name("MAP_KEY")];
        let after = [name("MAP_KEY"), name("BANK_API_KEY")];
        assert_eq!(newly_received(&before, &after), vec![name("BANK_API_KEY")]);
        assert_eq!(newly_received(&after, &before), vec![]);
        assert_eq!(newly_received(&[], &after), after.to_vec());
    }

    #[test]
    fn 단계는_json_으로_preview_와_production_이다() {
        assert_eq!(
            serde_json::to_string(&Stage::Preview).unwrap(),
            r#""preview""#
        );
        assert_eq!(Stage::parse("production"), Some(Stage::Production));
        assert_eq!(Stage::parse("prod"), None);
    }
}
