//! 승격의 규칙. 무엇이 운영에 오를 수 있고, 누가 승인해야 하며, 올린 뒤 깨지면 어디로 돌아가는가.
//!
//! 승인한 것이 도는 것이다. release 는 commit · 선언 · 권한 표 · 마이그레이션에서 지은 식별자를 갖고, 승인은 그 식별자 하나에 묶인다.
//! 승인한 뒤에 commit 이 하나라도 더해지면 식별자가 달라지므로, 앞의 승인으로는 올리지 못한다.
//!
//! 식별자를 짓는 일(해시)과 실제로 올리는 일은 여기에 없다. 여기서는 올려도 되는지만 본다.

use serde::{Deserialize, Serialize};

use crate::manifest::{Auth, ValidManifest};

/// release 의 식별자. 레이어가 commit · 선언 · 권한 표 · 마이그레이션의 내용에서 짓는다. 넷 중 하나라도 바뀌면 달라진다.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReleaseId(pub String);

/// 빌드를 누가 했는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltBy {
    /// 레이어가 그 commit 에서 직접 빌드했다.
    Layer,
    /// 밖에서 빌드한 결과를 올려 받았다. 미리보기에는 쓰지만 운영에는 올리지 않는다.
    Uploaded,
}

/// 마이그레이션의 예행연습이 어떻게 끝났는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rehearsed {
    /// 돌릴 마이그레이션이 없다.
    NotNeeded,
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub id: ReleaseId,
    pub built_by: BuiltBy,
    /// 권한 검사가 찾은 어긋남의 수. 0 이어야 통과다.
    pub access_findings: usize,
    pub rehearsal: Rehearsed,
    /// 선언의 로그인 방법이 쓰는데 팩토리가 넣지 않은 키. [`missing_keys`] 가 셈한다.
    #[serde(default)]
    pub missing_keys: Vec<FactoryKey>,
}

/// 운영의 로그인이 쓰는 팩토리의 키. 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryKey {
    /// 메일 발송(Resend)의 키와 보내는 주소. 이메일 링크가 쓴다.
    Mail,
    /// Google 클라이언트의 키. Google 로그인이 쓴다.
    Google,
}

/// 팩토리가 지금 넣어 둔 키. 값이 아니라 있는지만 담는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Keys {
    pub mail: bool,
    pub google: bool,
    /// 레이어의 운영자가 개발용 메일함을 명시해 켰다. 메일은 파일에 쌓이고, 메일의 키가 없어도 운영에 오른다.
    pub dev_mailbox: bool,
}

/// 선언의 로그인 방법이 쓰는데 팩토리가 넣지 않은 키. 비어 있어야 운영에 오른다. 미리보기는 키 없이 선다.
pub fn missing_keys(manifest: &ValidManifest, keys: &Keys) -> Vec<FactoryKey> {
    let Some(auth) = &manifest.get().auth else {
        return Vec::new();
    };
    let mut missing = Vec::new();
    if auth.uses(Auth::EMAIL_LINK) && !keys.mail && !keys.dev_mailbox {
        missing.push(FactoryKey::Mail);
    }
    if auth.uses(Auth::GOOGLE) && !keys.google {
        missing.push(FactoryKey::Google);
    }
    missing
}

/// 승격을 막는 것.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", rename_all = "snake_case")]
pub enum Blocker {
    NotBuiltByLayer,
    AccessCheckFailed {
        findings: usize,
    },
    RehearsalNotRun,
    RehearsalFailed,
    /// 팩토리가 키를 넣지 않았다. 에이전트가 고칠 수 없고 팩토리의 관리자가 설정에 넣어야 한다.
    KeyMissing {
        key: FactoryKey,
    },
}

/// 이 release 의 승격을 막는 것을 모두 돌려준다. 비어 있어야 승격을 요청할 수 있다.
pub fn blockers(release: &Release) -> Vec<Blocker> {
    let mut found = Vec::new();
    if release.built_by != BuiltBy::Layer {
        found.push(Blocker::NotBuiltByLayer);
    }
    if release.access_findings > 0 {
        found.push(Blocker::AccessCheckFailed {
            findings: release.access_findings,
        });
    }
    match release.rehearsal {
        Rehearsed::NotNeeded | Rehearsed::Passed => {}
        Rehearsed::NotRun => found.push(Blocker::RehearsalNotRun),
        Rehearsed::Failed => found.push(Blocker::RehearsalFailed),
    }
    found.extend(
        release
            .missing_keys
            .iter()
            .map(|&key| Blocker::KeyMissing { key }),
    );
    found
}

/// 무엇 때문에 올리는가. 누가 승인해야 하는지가 여기서 갈린다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// 고객이 요청한 수정.
    CustomerRequest,
    /// 팩토리가 낸 기능 업데이트. 고객의 에이전트가 적용한다(당기기).
    FeatureUpdate,
    /// 법이 바뀌어 팩토리가 낸 코드 변경(밀기).
    LegalUpdate,
    /// 보안 때문에 팩토리가 낸 코드 변경(밀기).
    SecurityUpdate,
    /// 포크하지 않는 핵심 패키지의 버전 올리기(밀기).
    CorePackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approver {
    /// 고객사의 사람.
    Customer,
    /// 팩토리의 사람.
    Factory,
}

impl Change {
    /// 이 변경을 승인해야 하는 쪽. 화면이나 절차가 달라지는 것은 고객이, 급하게 모두에게 올려야 하는 것은 팩토리가 승인한다.
    pub fn approver(&self) -> Approver {
        match self {
            Self::CustomerRequest | Self::FeatureUpdate => Approver::Customer,
            Self::LegalUpdate | Self::SecurityUpdate | Self::CorePackage => Approver::Factory,
        }
    }
}

/// 사람의 승인. host 가 사람에게 받아 넘긴다. 누가 승인할 자격이 있는지는 host 가 정한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub release: ReleaseId,
    pub by: Approver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denied", rename_all = "snake_case")]
pub enum PromoteDenied {
    Blocked {
        blockers: Vec<Blocker>,
    },
    NoApproval,
    /// 승인이 다른 release 의 것이다. 승인한 뒤에 무언가 바뀌었다.
    ApprovalForOtherRelease,
    WrongApprover {
        needs: Approver,
    },
}

/// 이 release 를 운영에 올려도 되는가.
///
/// 막는 것이 하나라도 있으면 승인이 있어도 올리지 못한다. 승인은 사람이 뜻을 본 것이고, 검사는 기계가 사실을 본 것이라 서로를 대신하지 못한다.
pub fn promote(
    release: &Release,
    change: Change,
    approval: Option<&Approval>,
) -> Result<(), PromoteDenied> {
    let blockers = blockers(release);
    if !blockers.is_empty() {
        return Err(PromoteDenied::Blocked { blockers });
    }
    let approval = approval.ok_or(PromoteDenied::NoApproval)?;
    if approval.release != release.id {
        return Err(PromoteDenied::ApprovalForOtherRelease);
    }
    let needs = change.approver();
    if approval.by != needs {
        return Err(PromoteDenied::WrongApprover { needs });
    }
    Ok(())
}

/// 올린 마이그레이션이 앞의 코드와도 맞는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Migrations {
    None,
    /// 더하기만 했다(열 · 표 · 색인). 앞의 코드가 그대로 돈다.
    Additive,
    /// 지우거나 바꿨다. 앞의 코드로 돌아가려면 DB 도 되돌려야 하고, 그러면 승격 뒤에 쓴 데이터를 잃는다.
    Destructive,
}

/// 승격한 뒤 상태를 확인한 결과에 따라 할 일.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Aftermath {
    Keep,
    /// 코드만 앞의 release 로 돌린다. DB 는 그대로 둔다.
    RollBackCode,
    /// 코드를 앞의 release 로 돌릴 수 없다. DB 를 되돌릴 지점으로 돌리면 데이터를 잃으므로 사람에게 묻는다.
    AskHuman,
}

/// 승격 뒤의 상태 확인에 실패하면 어디로 돌아가는가. 데이터를 잃는 되돌리기는 기계가 정하지 않는다.
pub fn after_promotion(healthy: bool, migrations: Migrations) -> Aftermath {
    match (healthy, migrations) {
        (true, _) => Aftermath::Keep,
        (false, Migrations::None | Migrations::Additive) => Aftermath::RollBackCode,
        (false, Migrations::Destructive) => Aftermath::AskHuman,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(id: &str) -> Release {
        Release {
            id: ReleaseId(id.to_owned()),
            built_by: BuiltBy::Layer,
            access_findings: 0,
            rehearsal: Rehearsed::Passed,
            missing_keys: Vec::new(),
        }
    }

    fn manifest(methods: &str) -> ValidManifest {
        let text = format!(
            r#"
[[service]]
name = "web"
kind = "server"
build = "true"
start = "true"
path = "/"
roles = ["member"]

[database]
schemas = ["app"]
migrations = "db/migrations"
roles = ["member"]

[auth]
methods = [{methods}]
login_path = "/login"
"#
        );
        toml::from_str::<crate::manifest::Manifest>(&text)
            .unwrap()
            .check()
            .unwrap()
    }

    #[test]
    fn 메일_키가_없으면_이메일_링크를_선언한_release_는_운영에_오르지_못한다() {
        let none = Keys::default();
        assert_eq!(
            missing_keys(&manifest(r#""email_link""#), &none),
            vec![FactoryKey::Mail]
        );
        let mail = Keys {
            mail: true,
            ..Keys::default()
        };
        assert_eq!(missing_keys(&manifest(r#""email_link""#), &mail), vec![]);
        let mut release = release("r1");
        release.missing_keys = vec![FactoryKey::Mail];
        assert_eq!(
            blockers(&release),
            vec![Blocker::KeyMissing {
                key: FactoryKey::Mail
            }]
        );
    }

    #[test]
    fn google_키가_없으면_google_을_선언한_release_는_운영에_오르지_못한다() {
        let mail = Keys {
            mail: true,
            ..Keys::default()
        };
        assert_eq!(
            missing_keys(&manifest(r#""email_link", "google""#), &mail),
            vec![FactoryKey::Google]
        );
        let both = Keys {
            mail: true,
            google: true,
            dev_mailbox: false,
        };
        assert_eq!(
            missing_keys(&manifest(r#""email_link", "google""#), &both),
            vec![]
        );
        // Google 만 선언했으면 메일의 키는 묻지 않는다
        assert_eq!(
            missing_keys(&manifest(r#""google""#), &Keys::default()),
            vec![FactoryKey::Google]
        );
    }

    #[test]
    fn 개발용_메일함은_메일_키를_대신하지만_google_키는_대신하지_않는다() {
        let dev = Keys {
            dev_mailbox: true,
            ..Keys::default()
        };
        assert_eq!(missing_keys(&manifest(r#""email_link""#), &dev), vec![]);
        assert_eq!(
            missing_keys(&manifest(r#""email_link", "google""#), &dev),
            vec![FactoryKey::Google]
        );
    }

    #[test]
    fn 로그인을_맡기지_않은_앱은_키를_묻지_않는다() {
        let text = r#"
[[service]]
name = "web"
kind = "server"
build = "true"
start = "true"
path = "/"
"#;
        let manifest = toml::from_str::<crate::manifest::Manifest>(text)
            .unwrap()
            .check()
            .unwrap();
        assert_eq!(missing_keys(&manifest, &Keys::default()), vec![]);
    }

    fn approval(id: &str, by: Approver) -> Approval {
        Approval {
            release: ReleaseId(id.to_owned()),
            by,
        }
    }

    #[test]
    fn 검사를_통과하고_승인받은_release_는_운영에_오른다() {
        let approval = approval("r1", Approver::Customer);
        assert_eq!(
            promote(&release("r1"), Change::CustomerRequest, Some(&approval)),
            Ok(())
        );
    }

    #[test]
    fn 승인_없이는_올리지_못한다() {
        assert_eq!(
            promote(&release("r1"), Change::CustomerRequest, None),
            Err(PromoteDenied::NoApproval)
        );
    }

    #[test]
    fn 승인은_release_하나에_묶인다_승인한_뒤_commit_이_더해지면_그_승인으로는_올리지_못한다() {
        // r1 을 승인한 뒤 commit 이 더해져 식별자가 r2 가 되었다
        let approval = approval("r1", Approver::Customer);
        assert_eq!(
            promote(&release("r2"), Change::CustomerRequest, Some(&approval)),
            Err(PromoteDenied::ApprovalForOtherRelease)
        );
    }

    #[test]
    fn 권한_검사를_통과하지_못한_release_는_승인이_있어도_올리지_못한다() {
        let mut release = release("r1");
        release.access_findings = 2;
        assert_eq!(
            blockers(&release),
            vec![Blocker::AccessCheckFailed { findings: 2 }]
        );
        let approval = approval("r1", Approver::Customer);
        assert_eq!(
            promote(&release, Change::CustomerRequest, Some(&approval)),
            Err(PromoteDenied::Blocked {
                blockers: vec![Blocker::AccessCheckFailed { findings: 2 }]
            })
        );
    }

    #[test]
    fn 예행연습이_실패했거나_돌지_않은_마이그레이션은_승격하지_못한다() {
        let mut release = release("r1");
        release.rehearsal = Rehearsed::Failed;
        assert_eq!(blockers(&release), vec![Blocker::RehearsalFailed]);
        release.rehearsal = Rehearsed::NotRun;
        assert_eq!(blockers(&release), vec![Blocker::RehearsalNotRun]);
    }

    #[test]
    fn 마이그레이션이_없는_release_는_예행연습_없이_올린다() {
        let mut release = release("r1");
        release.rehearsal = Rehearsed::NotNeeded;
        assert_eq!(blockers(&release), vec![]);
    }

    #[test]
    fn 운영에_오르는_빌드는_레이어가_그_commit_에서_만든_것이다_올려_받은_빌드는_받지_않는다() {
        let mut release = release("r1");
        release.built_by = BuiltBy::Uploaded;
        assert_eq!(blockers(&release), vec![Blocker::NotBuiltByLayer]);
    }

    #[test]
    fn 막는_것은_하나만이_아니라_모두_돌려준다() {
        let release = Release {
            id: ReleaseId("r1".to_owned()),
            built_by: BuiltBy::Uploaded,
            access_findings: 1,
            rehearsal: Rehearsed::Failed,
            missing_keys: vec![FactoryKey::Mail, FactoryKey::Google],
        };
        assert_eq!(blockers(&release).len(), 5);
    }

    #[test]
    fn 고객의_요청과_기능_업데이트는_고객이_승인한다() {
        for change in [Change::CustomerRequest, Change::FeatureUpdate] {
            assert_eq!(change.approver(), Approver::Customer);
            let by_factory = approval("r1", Approver::Factory);
            assert_eq!(
                promote(&release("r1"), change, Some(&by_factory)),
                Err(PromoteDenied::WrongApprover {
                    needs: Approver::Customer
                })
            );
        }
    }

    #[test]
    fn 보안과_법과_핵심_패키지의_변경은_팩토리가_승인한다() {
        for change in [
            Change::SecurityUpdate,
            Change::LegalUpdate,
            Change::CorePackage,
        ] {
            assert_eq!(change.approver(), Approver::Factory);
            assert_eq!(
                promote(
                    &release("r1"),
                    change,
                    Some(&approval("r1", Approver::Factory))
                ),
                Ok(())
            );
            let by_customer = approval("r1", Approver::Customer);
            assert_eq!(
                promote(&release("r1"), change, Some(&by_customer)),
                Err(PromoteDenied::WrongApprover {
                    needs: Approver::Factory
                })
            );
        }
    }

    #[test]
    fn 승격_뒤_상태_확인에_실패하면_앞의_release_로_돌아간다() {
        assert_eq!(
            after_promotion(true, Migrations::Destructive),
            Aftermath::Keep
        );
        assert_eq!(
            after_promotion(false, Migrations::None),
            Aftermath::RollBackCode
        );
    }

    #[test]
    fn 더하기만_한_마이그레이션이면_코드만_돌리고_db_는_그대로_둔다() {
        assert_eq!(
            after_promotion(false, Migrations::Additive),
            Aftermath::RollBackCode
        );
    }

    #[test]
    fn 되돌리면_데이터를_잃는_마이그레이션이면_기계가_정하지_않고_사람에게_묻는다() {
        assert_eq!(
            after_promotion(false, Migrations::Destructive),
            Aftermath::AskHuman
        );
    }

    #[test]
    fn 키가_없어_막힌_까닭은_json_으로_어느_키인지_알린다() {
        assert_eq!(
            serde_json::to_string(&Blocker::KeyMissing {
                key: FactoryKey::Google
            })
            .unwrap(),
            r#"{"blocker":"key_missing","key":"google"}"#
        );
    }

    #[test]
    fn 판정은_json_으로_오간다() {
        let denied = PromoteDenied::WrongApprover {
            needs: Approver::Factory,
        };
        assert_eq!(
            serde_json::to_string(&denied).unwrap(),
            r#"{"denied":"wrong_approver","needs":"factory"}"#
        );
    }
}
