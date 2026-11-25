//! 「어떤 ~이든」, 「하나라도」가 든 규칙을 속성 테스트로 잰다(사다리 2단계).
//!
//! 기대값은 구현을 다시 부르지 않고 다른 방법으로 만든다. 생성기는 경계가 자주 나오게 좁힌다(역할 셋, 표 넷, 인스턴스 둘).

use std::collections::{BTreeMap, BTreeSet};

use orbital_core::access::{Access, Grant, Privilege, RawAccess, Reach};
use orbital_core::check::{
    Finding, Membership, RoleState, Snapshot, TableState, judge as judge_database,
};
use orbital_core::manifest::{
    Database, Manifest, Service, ServiceAuth, ServiceKind, ValidManifest,
};
use orbital_core::name::{Ident, InstanceId, TableRef};
use orbital_core::plan::{Names, Step, grants, provision};
use orbital_core::scope::{
    Action, Capability, DenyReason, OrganizationId, Request, Token, Verdict, judge,
};
use proptest::prelude::*;

const ROLES: [&str; 3] = ["employee", "manager", "payroll_admin"];
const TABLES: [(&str, &str); 4] = [
    ("hr", "person"),
    ("hr", "department"),
    ("payroll", "payslip"),
    ("payroll", "bonus"),
];
const WORDS: [&str; 5] = ["none", "read", "read own", "read write", "read write own"];

fn ident(text: &str) -> Ident {
    Ident::parse(text).unwrap()
}

fn names() -> Names {
    Names::new(InstanceId::parse("k3f9x2ab").unwrap())
}

/// 서비스 둘이 역할의 부분집합을 쓰는 선언.
fn manifest(api: &[bool; 3], worker: &[bool; 3]) -> ValidManifest {
    let pick = |mask: &[bool; 3]| {
        ROLES
            .iter()
            .zip(mask)
            .filter(|(_, on)| **on)
            .map(|(role, _)| ident(role))
            .collect()
    };
    let service = |name: &str, path: &str, mask: &[bool; 3]| Service {
        name: ident(name),
        kind: ServiceKind::Server,
        build: "npm run build".to_owned(),
        start: Some("npm run start".to_owned()),
        output: None,
        path: path.to_owned(),
        roles: pick(mask),
        auth: ServiceAuth::Optional,
    };
    Manifest {
        services: vec![
            service("api", "/api", api),
            service("worker", "/worker", worker),
        ],
        database: Database {
            schemas: vec![ident("hr"), ident("payroll")],
            roles: ROLES.iter().map(|role| ident(role)).collect(),
            ..Database::default()
        },
        ..Manifest::default()
    }
    .check()
    .unwrap()
}

/// 표마다 역할마다 다섯 말 가운데 하나를 고른 권한 표. 행 단위 규칙은 모두 켠다.
fn access(words: &[[usize; 3]; 4], manifest: &ValidManifest) -> Access {
    let mut raw = RawAccess::new();
    for ((schema, table), row) in TABLES.iter().zip(words) {
        let by_role: BTreeMap<String, String> = ROLES
            .iter()
            .zip(row)
            .map(|(role, word)| ((*role).to_owned(), WORDS[*word].to_owned()))
            .collect();
        raw.entry((*schema).to_owned())
            .or_default()
            .insert((*table).to_owned(), by_role);
    }
    Access::parse(&raw, manifest).unwrap()
}

fn tables() -> Vec<TableRef> {
    TABLES
        .iter()
        .map(|(schema, table)| TableRef {
            schema: ident(schema),
            table: ident(table),
        })
        .collect()
}

/// 계획의 단계를 그대로 실행한 DB 의 모습. 실제 DB 대신 단계를 읽어 흉내 낸다.
fn applied(names: &Names, manifest: &ValidManifest, access: &Access) -> Snapshot {
    let mut snapshot = Snapshot {
        schemas: vec!["public".to_owned()],
        ..Snapshot::default()
    };
    for step in provision(names, manifest) {
        match step {
            Step::CreateRole { name, login } => snapshot.roles.push(RoleState {
                name,
                login,
                superuser: false,
                create_db: false,
                create_role: false,
                replication: false,
                bypass_rls: false,
            }),
            Step::GrantMembership {
                group,
                member,
                inherit,
                set,
            } => {
                snapshot.memberships.push(Membership {
                    group,
                    member,
                    inherit,
                    set,
                });
            }
            Step::CreateSchema { schema, .. } => snapshot.schemas.push(schema.to_string()),
            _ => {}
        }
    }
    for table in tables() {
        snapshot.tables.push(TableState {
            schema: table.schema.to_string(),
            table: table.table.to_string(),
            owner: names.owner(),
            rls: true,
            privileges: BTreeMap::new(),
        });
    }
    for step in grants(names, manifest, access, &tables()) {
        match step {
            Step::RevokeTable { table, role } => {
                let state = snapshot
                    .tables
                    .iter_mut()
                    .find(|state| state.table == table.table.as_str())
                    .unwrap();
                state.privileges.remove(&role);
            }
            Step::GrantTable {
                table,
                role,
                privileges,
            } => {
                let state = snapshot
                    .tables
                    .iter_mut()
                    .find(|state| state.table == table.table.as_str())
                    .unwrap();
                state.privileges.entry(role).or_default().extend(privileges);
            }
            _ => {}
        }
    }
    snapshot
}

fn mask() -> impl Strategy<Value = [bool; 3]> {
    proptest::array::uniform3(any::<bool>())
}

fn words() -> impl Strategy<Value = [[usize; 3]; 4]> {
    proptest::array::uniform4(proptest::array::uniform3(0usize..5))
}

fn privilege() -> impl Strategy<Value = Privilege> {
    (0usize..8).prop_map(|index| Privilege::ALL[index])
}

proptest! {
    #[test]
    fn 어떤_선언이든_계획대로_세운_db_는_검사를_통과한다(api in mask(), worker in mask(), words in words()) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        let access = access(&words, &manifest);
        prop_assert_eq!(judge_database(&names, &manifest, &access, &applied(&names, &manifest, &access)), vec![]);
    }

    #[test]
    fn 어떤_선언이든_권한_표가_none_인_역할에게는_그_표의_권한을_주지_않는다(api in mask(), worker in mask(), words in words()) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        let access = access(&words, &manifest);
        for step in grants(&names, &manifest, &access, &tables()) {
            if let Step::GrantTable { table, role, privileges } = step {
                // 구현의 `Access::grant` 를 부르지 않고 생성기의 입력에서 바로 찾는다
                let row = TABLES.iter().position(|(_, name)| *name == table.table.as_str()).unwrap();
                let column = ROLES.iter().position(|name| names.group(&ident(name)) == role).unwrap();
                let word = WORDS[words[row][column]];
                prop_assert_ne!(word, "none");
                prop_assert_eq!(privileges.contains(&Privilege::Insert), word.contains("write"));
                prop_assert!(!privileges.contains(&Privilege::Truncate));
            }
        }
    }

    #[test]
    fn 어떤_선언이든_역할을_바꿔_탈_수_있는_것은_마이그레이션_역할뿐이다(api in mask(), worker in mask()) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        for step in provision(&names, &manifest) {
            if let Step::GrantMembership { group, member, set, .. } = step {
                prop_assert_eq!(set, member == names.migrator() && group == names.owner());
            }
        }
    }

    #[test]
    fn 어떤_선언이든_서비스에_적지_않은_역할의_로그인은_만들지_않는다(api in mask(), worker in mask()) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        let created: BTreeSet<String> = provision(&names, &manifest)
            .into_iter()
            .filter_map(|step| match step {
                Step::CreateRole { name, login: true } => Some(name),
                _ => None,
            })
            .collect();
        for (service, mask) in [("api", &api), ("worker", &worker)] {
            for (role, on) in ROLES.iter().zip(mask) {
                let login = format!("i_k3f9x2ab_s_{service}_{role}");
                prop_assert_eq!(created.contains(&login), *on, "{}", login);
            }
        }
    }

    #[test]
    fn 통과한_db_에_권한을_하나라도_더하면_검사가_실패한다(
        api in mask(), worker in mask(), words in words(), table in 0usize..4, role in 0usize..3, extra in privilege(),
    ) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        let access = access(&words, &manifest);
        let mut snapshot = applied(&names, &manifest, &access);
        let group = names.group(&ident(ROLES[role]));
        let added = snapshot.tables[table].privileges.entry(group).or_default().insert(extra);
        let findings = judge_database(&names, &manifest, &access, &snapshot);
        prop_assert_eq!(findings.iter().any(|finding| matches!(finding, Finding::PrivilegeExtra { .. })), added);
    }

    #[test]
    fn 통과한_db_에서_행_단위_규칙을_하나라도_끄면_검사가_실패한다(api in mask(), worker in mask(), words in words(), table in 0usize..4) {
        let (names, manifest) = (names(), manifest(&api, &worker));
        let access = access(&words, &manifest);
        let mut snapshot = applied(&names, &manifest, &access);
        snapshot.tables[table].rls = false;
        prop_assert_eq!(judge_database(&names, &manifest, &access, &snapshot).len(), 1);
    }
}

fn capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        Just(Capability::Source),
        Just(Capability::Preview),
        Just(Capability::Rehearse),
        Just(Capability::SecretsRequest)
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::SourceRead),
        Just(Action::SourceWrite),
        Just(Action::PreviewDeploy),
        Just(Action::PreviewLogs),
        Just(Action::PreviewDatabase),
        Just(Action::RequestPromotion),
        Just(Action::Rehearse),
        Just(Action::SecretsRequest),
        Just(Action::Promote),
        Just(Action::ProductionLogs),
        Just(Action::ProductionDatabase),
        Just(Action::SecretsRead),
    ]
}

fn instance() -> impl Strategy<Value = InstanceId> {
    prop_oneof![Just("k3f9x2ab"), Just("k3f9x2abc")]
        .prop_map(|text| InstanceId::parse(text).unwrap())
}

fn organization() -> impl Strategy<Value = OrganizationId> {
    prop_oneof![Just("org_a"), Just("org_b")].prop_map(|text| OrganizationId(text.to_owned()))
}

fn token() -> impl Strategy<Value = Token> {
    (
        organization(),
        instance(),
        proptest::collection::btree_set(capability(), 0..=4),
        0u64..6,
    )
        .prop_map(|(organization, instance, can, expires_at)| Token {
            organization,
            instance,
            can,
            expires_at,
        })
}

fn request() -> impl Strategy<Value = Request> {
    (organization(), instance(), action(), 0u64..6).prop_map(
        |(organization, instance, action, at)| Request {
            organization,
            instance,
            action,
            at,
        },
    )
}

/// 운영을 바꾸는 일. 구현의 `Action::needs` 와 따로 적는다.
fn touches_production(action: Action) -> bool {
    matches!(
        action,
        Action::Promote | Action::ProductionLogs | Action::ProductionDatabase | Action::SecretsRead
    )
}

proptest! {
    #[test]
    fn 어떤_토큰도_발급받은_인스턴스_밖의_요청을_허락하지_않는다(token in token(), request in request()) {
        if token.instance != request.instance || token.organization != request.organization {
            prop_assert_eq!(judge(&token, &request), Verdict::Deny(DenyReason::NotFound));
        }
    }

    #[test]
    fn 어떤_토큰도_운영을_바꾸는_일을_허락하지_않는다(token in token(), request in request()) {
        if touches_production(request.action) {
            prop_assert_ne!(judge(&token, &request), Verdict::Allow);
        }
    }

    #[test]
    fn 어떤_토큰도_만료_시각부터는_아무것도_허락하지_않는다(token in token(), request in request()) {
        if request.at >= token.expires_at {
            prop_assert_ne!(judge(&token, &request), Verdict::Allow);
        }
    }

    #[test]
    fn 능력을_더한다고_전에_되던_일이_안_되지는_않는다(token in token(), request in request(), extra in capability()) {
        let mut wider = token.clone();
        wider.can.insert(extra);
        if judge(&token, &request) == Verdict::Allow {
            prop_assert_eq!(judge(&wider, &request), Verdict::Allow);
        }
    }
}

/// 로그인 뒤에 돌아갈 곳의 후보. 브라우저가 주소를 다르게 읽게 만드는 글자(`/` · `\` · `:` · 제어 문자 · 공백)가 자주 나오게 좁힌다.
fn next() -> impl Strategy<Value = String> {
    const PIECES: [&str; 22] = [
        "/",
        "/",
        "//",
        "\\",
        ":",
        ".",
        "..",
        "@",
        "a",
        "evil.example",
        "https:",
        "javascript:",
        "?",
        "#",
        "%2F",
        "\t",
        "\n",
        "\r",
        "\u{0}",
        " ",
        "\u{7f}",
        "\u{3000}",
    ];
    proptest::collection::vec(0usize..PIECES.len(), 0..8)
        .prop_map(|picks| picks.into_iter().map(|index| PIECES[index]).collect())
}

proptest! {
    #[test]
    fn 어떤_next_를_넣어도_돌아갈_곳은_이_주소_안이다(next in next()) {
        // 오라클은 브라우저와 같은 규칙(WHATWG URL)으로 읽는 `url` 이다. 이 주소에서 돌아갈 곳을 읽었을 때 주소가 바뀌지 않아야 한다
        let here = url::Url::parse("https://app.example/inbox/").unwrap();
        let safe = orbital_core::auth::safe_next(&next);
        let resolved = here.join(&safe).unwrap();
        prop_assert_eq!(resolved.origin(), here.origin(), "{:?} → {:?}", next, safe);
        // 바꾼다면 첫 화면으로만 바꾼다. 받은 것은 고치지 않고 그대로 돌려준다
        prop_assert!(safe == "/" || safe == next, "{:?} → {:?}", next, safe);
    }
}

#[test]
fn 권한의_말은_닿는_범위로_읽힌다() {
    // 생성기가 쓰는 다섯 말이 구현이 받는 말과 같은지 붙잡아 둔다
    let reaches: Vec<(Reach, Reach)> = WORDS
        .iter()
        .map(|word| Grant::parse(word).unwrap())
        .map(|grant| (grant.read, grant.write))
        .collect();
    assert_eq!(
        reaches,
        vec![
            (Reach::None, Reach::None),
            (Reach::All, Reach::None),
            (Reach::Own, Reach::None),
            (Reach::All, Reach::All),
            (Reach::Own, Reach::Own)
        ]
    );
}

mod release {
    use orbital_core::release::{
        Approval, Approver, BuiltBy, Change, Rehearsed, Release, ReleaseId, promote,
    };
    use proptest::prelude::*;

    fn release() -> impl Strategy<Value = Release> {
        (
            prop_oneof![Just("r1"), Just("r2")],
            any::<bool>(),
            0usize..3,
            prop_oneof![
                Just(Rehearsed::NotNeeded),
                Just(Rehearsed::NotRun),
                Just(Rehearsed::Passed),
                Just(Rehearsed::Failed)
            ],
        )
            .prop_map(|(id, by_layer, access_findings, rehearsal)| Release {
                id: ReleaseId(id.to_owned()),
                built_by: if by_layer {
                    BuiltBy::Layer
                } else {
                    BuiltBy::Uploaded
                },
                access_findings,
                rehearsal,
            })
    }

    fn change() -> impl Strategy<Value = Change> {
        prop_oneof![
            Just(Change::CustomerRequest),
            Just(Change::FeatureUpdate),
            Just(Change::LegalUpdate),
            Just(Change::SecurityUpdate),
            Just(Change::CorePackage)
        ]
    }

    fn approval() -> impl Strategy<Value = Option<Approval>> {
        proptest::option::of(
            (prop_oneof![Just("r1"), Just("r2")], any::<bool>()).prop_map(|(id, customer)| {
                Approval {
                    release: ReleaseId(id.to_owned()),
                    by: if customer {
                        Approver::Customer
                    } else {
                        Approver::Factory
                    },
                }
            }),
        )
    }

    proptest! {
        #[test]
        fn 어떤_release_든_운영에_오르려면_검사_셋을_통과하고_제_승인을_받아야_한다(
            release in release(), change in change(), approval in approval(),
        ) {
            // 구현의 `blockers` 를 부르지 않고 조건을 따로 적는다
            let checks_pass = release.built_by == BuiltBy::Layer
                && release.access_findings == 0
                && matches!(release.rehearsal, Rehearsed::NotNeeded | Rehearsed::Passed);
            let needs_customer = matches!(change, Change::CustomerRequest | Change::FeatureUpdate);
            let approved = approval.as_ref().is_some_and(|approval| {
                approval.release == release.id && (approval.by == Approver::Customer) == needs_customer
            });
            prop_assert_eq!(promote(&release, change, approval.as_ref()).is_ok(), checks_pass && approved);
        }
    }
}
