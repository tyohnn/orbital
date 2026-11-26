//! 「어떤 ~이든」, 「하나라도」가 든 규칙을 속성 테스트로 잰다(사다리 2단계).
//!
//! 기대값은 구현을 다시 부르지 않고 다른 방법으로 만든다. 생성기는 경계가 자주 나오게 좁힌다(역할 셋, 표 넷, 인스턴스 둘).

use std::collections::{BTreeMap, BTreeSet};

use orbital_core::access::{Access, Grant, Privilege, RawAccess, Reach};
use orbital_core::check::{
    Finding, Membership, RolePolicy, RoleState, Snapshot, TableState, judge as judge_database,
};
use orbital_core::manifest::{
    Auth, Database, Manifest, Service, ServiceAuth, ServiceKind, Signup, ValidManifest,
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
    manifest_with(api, worker, false)
}

/// `auth` 이면 로그인을 레이어에 맡긴다(`[auth]`).
fn manifest_with(api: &[bool; 3], worker: &[bool; 3], auth: bool) -> ValidManifest {
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
        public: Vec::new(),
        fallback: None,
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
        auth: auth.then(|| Auth {
            methods: vec!["email_link".to_owned()],
            login_path: "/api/login".to_owned(),
            signup: Signup::Invite,
            default_roles: Vec::new(),
            directory: Vec::new(),
            mcp: None,
        }),
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
    // `[auth]` 를 선언했으면 레이어가 `orbital_auth` 를 둔다(`Admin::install_auth`)
    if manifest.get().auth.is_some() {
        snapshot.schemas.push("orbital_auth".to_owned());
    }
    for table in tables() {
        snapshot.tables.push(TableState {
            schema: table.schema.to_string(),
            table: table.table.to_string(),
            owner: names.owner(),
            rls: true,
            privileges: BTreeMap::new(),
            role_policy: None,
        });
    }
    for step in grants(names, manifest, access, &tables()) {
        match step {
            // Postgres 가 정책을 읽어 줄 때의 모양이다(`pg_get_expr`). 구현의 상수를 부르지 않고 그대로 적는다
            Step::SetRolePolicy { table } => {
                let state = snapshot
                    .tables
                    .iter_mut()
                    .find(|state| state.table == table.table.as_str())
                    .unwrap();
                state.role_policy = Some(RolePolicy {
                    restrictive: true,
                    command: "*".to_owned(),
                    roles: vec!["public".to_owned()],
                    using: Some("( SELECT orbital.granted() AS granted)".to_owned()),
                    check: Some("( SELECT orbital.granted() AS granted)".to_owned()),
                });
            }
            Step::DropRolePolicy { table } => {
                let state = snapshot
                    .tables
                    .iter_mut()
                    .find(|state| state.table == table.table.as_str())
                    .unwrap();
                state.role_policy = None;
            }
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

    #[test]
    fn 어떤_선언이든_계획대로_세운_db_는_역할_제한_정책까지_넣어_권한_검사를_통과한다(
        api in mask(), worker in mask(), words in words(), auth in any::<bool>()
    ) {
        let (names, manifest) = (names(), manifest_with(&api, &worker, auth));
        let access = access(&words, &manifest);
        let snapshot = applied(&names, &manifest, &access);
        prop_assert_eq!(judge_database(&names, &manifest, &access, &snapshot), vec![]);
        // 정책은 auth 를 선언했을 때만, 권한 표의 표마다 있다(생성기의 권한 표는 모든 표의 행 단위 규칙을 켠다)
        let guarded = snapshot.tables.iter().filter(|state| state.role_policy.is_some()).count();
        prop_assert_eq!(guarded, if auth { TABLES.len() } else { 0 });
    }

    #[test]
    fn 통과한_db_에서_역할_제한_정책을_하나라도_지우면_검사가_실패한다(
        api in mask(), worker in mask(), words in words(), table in 0usize..4
    ) {
        let (names, manifest) = (names(), manifest_with(&api, &worker, true));
        let access = access(&words, &manifest);
        let mut snapshot = applied(&names, &manifest, &access);
        snapshot.tables[table].role_policy = None;
        let (schema, name) = TABLES[table];
        prop_assert_eq!(
            judge_database(&names, &manifest, &access, &snapshot),
            vec![Finding::RolePolicyMissing { table: TableRef { schema: ident(schema), table: ident(name) } }]
        );
    }
}

fn capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        Just(Capability::Source),
        Just(Capability::SourceRead),
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
        Just(Action::SecretsList),
        Just(Action::Promote),
        Just(Action::ProductionLogs),
        Just(Action::ProductionDatabase),
        Just(Action::SecretsRead),
        Just(Action::SecretsWrite),
        Just(Action::RolloutView),
        Just(Action::RolloutManage),
        Just(Action::RestoreInstance),
        Just(Action::Events),
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
        proptest::collection::btree_set(capability(), 0..=5),
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

/// 토큰으로 하지 못하는 일: 운영을 바꾸는 일과 조직 전체의 일(이벤트 · 웹훅). 구현의 `Action::needs` 와 따로 적는다.
fn touches_production(action: Action) -> bool {
    matches!(
        action,
        Action::Promote
            | Action::ProductionLogs
            | Action::ProductionDatabase
            | Action::SecretsRead
            | Action::SecretsWrite
            | Action::RolloutManage
            | Action::RestoreInstance
            | Action::Events
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

/// git 의 길 넷. 받기와 올리기마다 광고와 주고받기가 있다.
fn git_route() -> impl Strategy<Value = (&'static str, &'static [&'static str], &'static str)> {
    prop_oneof![
        Just(("GET", &["info", "refs"][..], "service=git-upload-pack")),
        Just(("GET", &["info", "refs"][..], "service=git-receive-pack")),
        Just(("POST", &["git-upload-pack"][..], "")),
        Just(("POST", &["git-receive-pack"][..], "")),
    ]
}

proptest! {
    #[test]
    fn 어떤_토큰도_다른_인스턴스의_git_에_닿지_못한다(
        token in token(),
        organization in organization(),
        instance in instance(),
        (method, tail, query) in git_route(),
        at in 0u64..6,
    ) {
        let route = orbital_core::git::route(method, tail, query).expect("정해진 길이다");
        let request = Request { organization: organization.clone(), instance: instance.clone(), action: route.service().action(), at };
        let verdict = judge(&token, &request);
        if token.instance != instance || token.organization != organization {
            // 다른 인스턴스는 만료됐는지도, 능력이 있는지도 알려 주지 않고 없는 것으로 답한다
            prop_assert_eq!(verdict, Verdict::Deny(DenyReason::NotFound));
        }
        // 올리기는 받기만 하는 능력으로 열리지 않는다
        if method == "POST" && tail == ["git-receive-pack"] && !token.can.contains(&Capability::Source) {
            prop_assert_ne!(verdict, Verdict::Allow);
        }
    }
}

/// 비밀의 값에 닿는 일. 구현의 `Action::needs` 와 따로 적는다.
fn touches_secret_values(action: Action) -> bool {
    matches!(action, Action::SecretsRead | Action::SecretsWrite)
}

/// 토큰에 적어 보낼 능력의 이름. 값을 읽거나 넣는 능력의 이름을 섞는다.
fn capability_word() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("source"),
        Just("preview"),
        Just("rehearse"),
        Just("secrets_request"),
        Just("secrets_read"),
        Just("secrets_write"),
        Just("secrets"),
    ]
}

proptest! {
    #[test]
    fn 어떤_토큰으로도_값을_읽거나_넣는_능력을_얻지_못한다(
        token in token(),
        request in request(),
        words in proptest::collection::vec(capability_word(), 0..5),
    ) {
        // 받은 토큰이 무엇을 할 수 있든 값을 읽거나 넣는 일은 허락되지 않는다
        if touches_secret_values(request.action) {
            prop_assert_ne!(judge(&token, &request), Verdict::Allow);
        }
        // 값에 닿는 능력의 이름을 적어 보낸 토큰은 읽히지 않는다
        let text = serde_json::json!({
            "organization": "org_a",
            "instance": "k3f9x2ab",
            "can": words,
            "expires_at": 5,
        })
        .to_string();
        let reaches_values = words
            .iter()
            .any(|word| matches!(*word, "secrets_read" | "secrets_write" | "secrets"));
        let parsed = serde_json::from_str::<Token>(&text);
        prop_assert_eq!(parsed.is_ok(), !reaches_values);
        if let Ok(parsed) = parsed {
            for action in [Action::SecretsRead, Action::SecretsWrite] {
                let request = Request {
                    organization: parsed.organization.clone(),
                    instance: parsed.instance.clone(),
                    action,
                    at: 0,
                };
                prop_assert_eq!(judge(&parsed, &request), Verdict::Deny(DenyReason::ServiceKeyOnly));
            }
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

mod oauth {
    use orbital_core::oauth::{
        Authorize, AuthorizeQuery, KnownClient, Stop, judge_authorize, same_redirect,
    };
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    const RESOURCE: &str = "http://127.0.0.1:4100/mcp";

    /// 모양이 맞는 challenge 를 만든다(S256 의 43자). redirect 의 판정에만 쓴다.
    fn challenge_of(verifier: &str) -> String {
        let digest = Sha256::digest(verifier.as_bytes());
        let table: Vec<char> = ('A'..='Z')
            .chain('a'..='z')
            .chain('0'..='9')
            .chain(['-', '_'])
            .collect();
        let mut bits = String::new();
        for byte in digest {
            bits.push_str(&format!("{byte:08b}"));
        }
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

    fn redirect() -> impl Strategy<Value = String> {
        "https://[a-z]{1,6}\\.example(:[0-9]{2,4})?/[a-z/]{0,10}(\\?[a-z]=[0-9])?"
    }

    /// 등록된 redirect 를 한 글자 고친다: 넣기 · 빼기 · 바꾸기. 바꾼 글자가 같으면 그대로일 수도 있다.
    fn edit() -> impl Strategy<Value = (usize, u8, char)> {
        (
            0usize..64,
            0u8..3,
            prop::sample::select(vec!['a', 'A', '/', ':', '.', '%', '?', '#', ' ', '0']),
        )
    }

    fn apply(text: &str, (at, op, c): (usize, u8, char)) -> String {
        let mut chars: Vec<char> = text.chars().collect();
        let at = at % (chars.len() + 1);
        match op {
            0 => chars.insert(at, c),
            1 if at < chars.len() => {
                chars.remove(at);
            }
            _ if at < chars.len() => chars[at] = c,
            _ => chars.push(c),
        }
        chars.into_iter().collect()
    }

    proptest! {
        #[test]
        fn 어떤_redirect_든_등록된_것과_한_글자라도_다르면_받지_않는다(registered in redirect(), change in edit()) {
            let given = apply(&registered, change);
            let client = KnownClient { id: "c_1".to_owned(), redirect_uris: vec![registered.clone()] };
            let query = AuthorizeQuery {
                response_type: Some("code".to_owned()),
                client_id: Some("c_1".to_owned()),
                redirect_uri: Some(given.clone()),
                code_challenge: Some(challenge_of(&"v".repeat(43))),
                code_challenge_method: Some("S256".to_owned()),
                resource: Some(RESOURCE.to_owned()),
                scope: None,
                state: None,
            };
            let verdict = judge_authorize(&query, Some(&client), RESOURCE, "http://127.0.0.1:4100");
            prop_assert_eq!(same_redirect(&client.redirect_uris, &given), given == registered);
            if given == registered {
                prop_assert!(matches!(verdict, Authorize::Accept { .. }), "{:?}", verdict);
            } else {
                prop_assert_eq!(verdict, Authorize::Stop { reason: Stop::BadRedirect });
            }
        }
    }
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
                missing_keys: Vec::new(),
                missing_secrets: Vec::new(),
                conformance: orbital_core::release::Conformed::NotDeclared,
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

// ---- 밖에서 넣는 비밀 ----

mod secrets {
    use std::collections::BTreeSet;

    use orbital_core::manifest::{Manifest, Secrets, Service, ServiceAuth, ServiceKind};
    use orbital_core::name::{Ident, SecretName};
    use orbital_core::release::{
        Approval, Approver, Blocker, BuiltBy, Change, Rehearsed, Release, ReleaseId, blockers,
        promote,
    };
    use orbital_core::secrets::missing_secrets;
    use proptest::prelude::*;

    const NAMES: [&str; 3] = ["BANK_API_KEY", "MAP_KEY", "MAIL_TOKEN"];

    proptest! {
        #[test]
        fn 넣지_않은_비밀이_하나라도_있으면_승격하지_못한다(
            declared in proptest::array::uniform3(any::<bool>()),
            filled in proptest::array::uniform3(any::<bool>()),
        ) {
            let pick = |mask: &[bool; 3]| -> Vec<SecretName> {
                NAMES
                    .iter()
                    .zip(mask)
                    .filter(|(_, on)| **on)
                    .map(|(name, _)| SecretName::parse(name).unwrap())
                    .collect()
            };
            let manifest = Manifest {
                services: vec![Service {
                    name: Ident::parse("web").unwrap(),
                    kind: ServiceKind::Server,
                    build: "true".to_owned(),
                    start: Some("true".to_owned()),
                    output: None,
                    path: "/".to_owned(),
                    roles: Vec::new(),
                    auth: ServiceAuth::Optional,
                    public: Vec::new(),
                    fallback: None,
                }],
                secrets: Secrets {
                    generated: Vec::new(),
                    external: pick(&declared),
                },
                ..Manifest::default()
            }
            .check()
            .unwrap();
            let filled: BTreeSet<SecretName> = pick(&filled).into_iter().collect();
            let release = Release {
                id: ReleaseId("r1".to_owned()),
                built_by: BuiltBy::Layer,
                access_findings: 0,
                rehearsal: Rehearsed::Passed,
                missing_keys: Vec::new(),
                missing_secrets: missing_secrets(&manifest, &filled),
                conformance: orbital_core::release::Conformed::NotDeclared,
            };
            // 구현을 부르지 않고 마스크에서 바로 기대값을 찾는다
            let expected: Vec<Blocker> = NAMES
                .iter()
                .enumerate()
                .filter(|(at, name)| declared[*at] && !filled.contains(&SecretName::parse(name).unwrap()))
                .map(|(_, name)| Blocker::SecretMissing { secret: SecretName::parse(name).unwrap() })
                .collect();
            prop_assert_eq!(blockers(&release), expected.clone());
            let approval = Approval { release: ReleaseId("r1".to_owned()), by: Approver::Customer };
            prop_assert_eq!(
                promote(&release, Change::CustomerRequest, Some(&approval)).is_ok(),
                expected.is_empty()
            );
        }
    }
}

// ---- 하위 도메인 ----

mod hosts {
    use orbital_core::host::{BaseDomain, HostTarget, judge_host};
    use orbital_core::name::InstanceId;
    use proptest::prelude::*;

    /// 하위 도메인 자리에 올 조각. 머리말이 겹치는 식별자 둘을 두고, 모양이 틀린 것과 대문자를 섞는다.
    const LABELS: [&str; 13] = [
        "k3f9x2ab",
        "k3f9x2abc",
        "k3f9x2ab-preview",
        "k3f9x2abc-preview",
        "K3F9X2AB",
        "",
        "x.k3f9x2ab",
        "k3f9x2ab-preview-preview",
        "short",
        "-preview",
        "k3f9x2ab.",
        "k3f9x2ab-Preview",
        "K3f9X2aBc-PREVIEW",
    ];
    /// 대소문자를 접은 머리 가운데 인스턴스로 가는 것. 이 넷 말고는 어디로도 가지 않는다.
    const HEADS: [(&str, &str, bool); 4] = [
        ("k3f9x2ab.", "k3f9x2ab", false),
        ("k3f9x2abc.", "k3f9x2abc", false),
        ("k3f9x2ab-preview.", "k3f9x2ab", true),
        ("k3f9x2abc-preview.", "k3f9x2abc", true),
    ];
    const SEPARATORS: [&str; 3] = [".", "", ".."];
    const BASES: [&str; 2] = ["orbital.test", "orbital.test:7480"];
    /// 꼬리. 대소문자만 다른 것, 끝에 점이 하나 · 둘 붙은 것(포트 앞의 점 포함)을 섞는다.
    const SUFFIXES: [&str; 14] = [
        "orbital.test",
        "orbital.test:7480",
        "orbital.test:7481",
        "evilorbital.test",
        "orbital.test.",
        "orbital.test..",
        "orbital.test.:7480",
        "ORBITAL.Test",
        "Orbital.TEST.:7480",
        "test",
        "orbital.test.other",
        "orbital.test:07480",
        "orbital.test:",
        "",
    ];

    /// 오라클이 아는, 기준 도메인과 같은 곳을 가리키는 꼬리. 대소문자를 접고 이름 끝의 점 하나를 떼면 기준 도메인과 글자까지 같은 것만 적었다.
    fn same_base(suffix: &str, base: &str) -> bool {
        match base {
            "orbital.test" => matches!(suffix, "orbital.test" | "orbital.test." | "ORBITAL.Test"),
            "orbital.test:7480" => {
                matches!(
                    suffix,
                    "orbital.test:7480" | "orbital.test.:7480" | "Orbital.TEST.:7480"
                )
            }
            _ => false,
        }
    }

    proptest! {
        #[test]
        fn 어떤_호스트든_대소문자와_끝의_점을_접어_기준_도메인_아래의_한_조각이_아니면_어느_인스턴스로도_가지_않는다(
            label in 0..LABELS.len(),
            separator in 0..SEPARATORS.len(),
            suffix in 0..SUFFIXES.len(),
            base in 0..BASES.len(),
        ) {
            let head = format!("{}{}", LABELS[label], SEPARATORS[separator]);
            let host = format!("{head}{}", SUFFIXES[suffix]);
            let base_text = BASES[base];
            // 오라클: 꼬리가 기준 도메인과 같은 곳(위의 목록)이고, 소문자로 접은 머리가 인스턴스 하나의 머리와 한 글자도 다르지 않을 때만 간다
            let folded = head.to_ascii_lowercase();
            let expected = HEADS
                .iter()
                .find(|(known, _, _)| same_base(SUFFIXES[suffix], base_text) && folded == *known)
                .map(|(_, id, preview)| {
                    let instance = InstanceId::parse(id).unwrap();
                    if *preview { HostTarget::Preview(instance) } else { HostTarget::Production(instance) }
                });
            let base = BaseDomain::parse(base_text).unwrap();
            prop_assert_eq!(judge_host(&host, &base), expected, "{}", host);
        }

        #[test]
        fn 어떤_호스트든_인스턴스로_간다면_대소문자와_이름_끝의_점_하나를_접은_호스트는_그_인스턴스의_하위_도메인_그대로다(
            host in "[a-zA-Z0-9.:-]{0,32}",
            base in 0..BASES.len(),
        ) {
            let base = BaseDomain::parse(BASES[base]).unwrap();
            if let Some(target) = judge_host(&host, &base) {
                let canonical = match &target {
                    HostTarget::Production(instance) => format!("{}.{base}", instance.as_str()),
                    HostTarget::Preview(instance) => format!("{}-preview.{base}", instance.as_str()),
                };
                let lower = host.to_ascii_lowercase();
                let (name, port) = match lower.split_once(':') {
                    Some((name, port)) => (name.to_owned(), format!(":{port}")),
                    None => (lower.clone(), String::new()),
                };
                let name = name.strip_suffix('.').unwrap_or(&name);
                prop_assert_eq!(format!("{name}{port}"), canonical);
            }
        }
    }
}

// ---- rollout ----

mod rollout {
    use orbital_core::name::InstanceId;
    use orbital_core::release::Change;
    use orbital_core::rollout::{Event, Progress, Rollout, Status};
    use orbital_core::scope::{Action, Capability, OrganizationId, Request, Token, Verdict, judge};
    use proptest::prelude::*;

    /// 머리말이 겹치는 식별자를 섞는다. 마지막 것은 rollout 에 들지 않는 인스턴스로 쓴다.
    const POOL: [&str; 5] = ["k3f9x2ab", "k3f9x2abc", "zzzzzzzz", "aaaaaaaa", "outsider"];

    fn id(text: &str) -> InstanceId {
        InstanceId::parse(text).unwrap()
    }

    /// 인스턴스 둘에서 넷까지를 물결 셋 가운데 하나에 넣는다. 빈 물결은 걷는다.
    fn waves() -> impl Strategy<Value = Vec<Vec<InstanceId>>> {
        proptest::collection::vec(0usize..3, 2..=4).prop_map(|places| {
            let mut waves: Vec<Vec<InstanceId>> = vec![Vec::new(); 3];
            for (at, wave) in places.iter().enumerate() {
                waves[*wave].push(id(POOL[at]));
            }
            waves.retain(|wave| !wave.is_empty());
            waves
        })
    }

    /// 사건 하나의 재료: (갈래, 인스턴스의 자리, 권한 검사가 통과했나, 다른 change 인가).
    type Raw = (u8, usize, bool, bool);

    fn raw() -> impl Strategy<Value = Raw> {
        // 갈래: 0..=2 적용 · 프리뷰 · 검사, 3..=4 승격, 5 되돌려짐, 6 다시 열기, 7 거두기(드물게)
        (
            prop_oneof![
                6 => 0u8..=2,
                3 => 3u8..=4,
                1 => Just(5u8),
                1 => Just(6u8),
                1 => Just(7u8),
            ],
            0usize..5,
            any::<bool>(),
            prop_oneof![4 => Just(false), 1 => Just(true)],
        )
    }

    /// 재료를 사건으로 옮긴다. 검사의 적합성 테스트 결과는 인스턴스마다 정한 `conforms` 를 따른다.
    fn event(raw: Raw, conforms: &[bool; 5], cancel: bool) -> Event {
        let (kind, at, access, other) = raw;
        let instance = id(POOL[at]);
        match kind {
            0 => Event::Applied { instance },
            1 => Event::Previewed { instance },
            2 => Event::Checked {
                instance,
                access_passed: access,
                conformance_passed: conforms[at],
            },
            3 | 4 => Event::Promoted {
                instance,
                change: if other {
                    Change::FeatureUpdate
                } else {
                    Change::SecurityUpdate
                },
            },
            5 => Event::RolledBack { instance },
            7 if cancel => Event::Cancel,
            _ => Event::Resume,
        }
    }

    fn start(waves: Vec<Vec<InstanceId>>) -> Rollout {
        Rollout::new(
            "todo".to_owned(),
            "a".repeat(40),
            Change::SecurityUpdate,
            waves,
        )
        .unwrap()
    }

    fn promoted_count(rollout: &Rollout) -> usize {
        rollout
            .progress
            .values()
            .filter(|state| **state == Progress::Promoted)
            .count()
    }

    proptest! {
        #[test]
        fn 멈춘_rollout_에서는_사건이_어떤_순서로_와도_새_승격이_없다(
            waves in waves(),
            raws in proptest::collection::vec(raw(), 0..60),
            conforms in proptest::array::uniform5(prop_oneof![3 => Just(true), 1 => Just(false)]),
        ) {
            let mut rollout = start(waves);
            for raw in raws {
                let event = event(raw, &conforms, false);
                let before = promoted_count(&rollout);
                let halted = rollout.status == Status::Halted;
                if let Ok(next) = rollout.step(&event) {
                    if halted {
                        prop_assert!(promoted_count(&next) <= before, "{:?}", event);
                    }
                    rollout = next;
                }
            }
        }

        #[test]
        fn 적합성_테스트를_통과하지_않은_인스턴스는_사건이_어떤_순서로_와도_승격에_닿지_못한다(
            waves in waves(),
            raws in proptest::collection::vec(raw(), 0..60),
            conforms in proptest::array::uniform5(any::<bool>()),
        ) {
            let mut rollout = start(waves);
            for raw in raws {
                if let Ok(next) = rollout.step(&event(raw, &conforms, true)) {
                    rollout = next;
                }
                // 오라클: 적합성 테스트를 한 번도 통과하지 못하는 인스턴스는 `promoted` 가 아니다
                for (at, name) in POOL.iter().enumerate() {
                    if !conforms[at] {
                        prop_assert_ne!(rollout.progress.get(&id(name)), Some(&Progress::Promoted));
                    }
                }
            }
        }

        #[test]
        fn 뒤_물결은_앞_물결이_모두_오른_뒤에만_오른다(
            waves in waves(),
            raws in proptest::collection::vec(raw(), 0..80),
            conforms in proptest::array::uniform5(prop_oneof![5 => Just(true), 1 => Just(false)]),
        ) {
            let mut rollout = start(waves.clone());
            for raw in raws {
                let Ok(next) = rollout.step(&event(raw, &conforms, false)) else {
                    continue;
                };
                // 새로 오른 인스턴스가 있으면, 그 앞 물결은 모두 이미 올라 있었다
                for (wave, members) in waves.iter().enumerate() {
                    for instance in members {
                        let newly = next.progress.get(instance) == Some(&Progress::Promoted)
                            && rollout.progress.get(instance) != Some(&Progress::Promoted);
                        if newly {
                            for earlier in waves.iter().take(wave).flatten() {
                                prop_assert_eq!(rollout.progress.get(earlier), Some(&Progress::Promoted));
                            }
                        }
                    }
                }
                rollout = next;
            }
        }
    }

    fn capability() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::Source),
            Just(Capability::SourceRead),
            Just(Capability::Preview),
            Just(Capability::Rehearse),
            Just(Capability::SecretsRequest)
        ]
    }

    /// 토큰에 적어 보낼 능력의 이름. rollout 을 다루는 능력처럼 보이는 이름을 섞는다.
    fn word() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("source"),
            Just("preview"),
            Just("rehearse"),
            Just("secrets_request"),
            Just("rollout"),
            Just("rollout_manage"),
            Just("rollouts"),
            Just("resume"),
        ]
    }

    proptest! {
        #[test]
        fn 어떤_토큰으로도_rollout_을_만들거나_다시_여는_능력을_얻지_못한다(
            can in proptest::collection::btree_set(capability(), 0..=4),
            token_instance in 0usize..2,
            request_instance in 0usize..2,
            at in 0u64..6,
            words in proptest::collection::vec(word(), 0..5),
        ) {
            let token = Token {
                organization: OrganizationId("org_a".to_owned()),
                instance: id(POOL[token_instance]),
                can,
                expires_at: 5,
            };
            let request = Request {
                organization: OrganizationId("org_a".to_owned()),
                instance: id(POOL[request_instance]),
                action: Action::RolloutManage,
                at,
            };
            prop_assert_ne!(judge(&token, &request), Verdict::Allow);
            // rollout 을 다루는 능력의 이름을 적어 보낸 토큰은 읽히지 않는다
            let text = serde_json::json!({
                "organization": "org_a",
                "instance": "k3f9x2ab",
                "can": words,
                "expires_at": 5,
            })
            .to_string();
            let known = words
                .iter()
                .all(|word| matches!(*word, "source" | "preview" | "rehearse" | "secrets_request"));
            let parsed = serde_json::from_str::<Token>(&text);
            prop_assert_eq!(parsed.is_ok(), known);
            if let Ok(parsed) = parsed {
                let request = Request {
                    organization: parsed.organization.clone(),
                    instance: parsed.instance.clone(),
                    action: Action::RolloutManage,
                    at: 0,
                };
                prop_assert_ne!(judge(&parsed, &request), Verdict::Allow);
            }
        }
    }
}

/// 백업과 복구 훈련의 판정.
mod backup {
    use orbital_core::backup::{BaseBackup, Check, Checked, DrillVerdict, judge_drill, prune};
    use orbital_core::name::InstanceId;
    use orbital_core::scope::{
        Action, Capability, DenyReason, OrganizationId, Request, Token, Verdict, judge,
    };
    use proptest::prelude::*;

    fn check() -> impl Strategy<Value = Check> {
        prop_oneof![
            Just(Check::ClusterStarted),
            Just(Check::MarkBeforeKept),
            Just(Check::MarkAfterGone),
            Just(Check::Records),
            prop_oneof![Just("k3f9x2ab"), Just("k3f9x2abc")].prop_flat_map(|instance| {
                prop_oneof![
                    Just(Check::Database {
                        instance: instance.to_owned()
                    }),
                    Just(Check::Fingerprint {
                        instance: instance.to_owned()
                    }),
                    Just(Check::Roles {
                        instance: instance.to_owned()
                    }),
                ]
            }),
            Just(Check::Moved {
                database: "i_k3f9x2ab".to_owned()
            }),
        ]
    }

    /// 통과한 확인이 훨씬 자주 나오게 해서 「하나만 어긋난」 경우가 자주 나온다.
    fn checked() -> impl Strategy<Value = Checked> {
        (check(), prop::bool::weighted(0.9)).prop_map(|(check, passed)| Checked { check, passed })
    }

    proptest! {
        #[test]
        fn 훈련은_확인이_하나라도_어긋나면_통과하지_못한다(checks in proptest::collection::vec(checked(), 0..12)) {
            let failed: Vec<Check> = checks
                .iter()
                .filter(|checked| !checked.passed)
                .map(|checked| checked.check.clone())
                .collect();
            let verdict = judge_drill(&checks);
            if checks.is_empty() || !failed.is_empty() {
                prop_assert_eq!(verdict, DrillVerdict::Failed { failed });
            } else {
                prop_assert_eq!(verdict, DrillVerdict::Passed);
            }
        }
    }

    const DAY: u64 = 86_400_000;

    /// 기반 백업의 목록. 다 뜬 때가 보관 기간의 경계 근처에 자주 오게 좁힌다.
    fn backups() -> impl Strategy<Value = Vec<BaseBackup>> {
        proptest::collection::vec(
            prop_oneof![
                0u64..40 * DAY,
                Just(16 * DAY),
                Just(16 * DAY + 1),
                Just(16 * DAY - 1)
            ],
            0..8,
        )
        .prop_map(|times| {
            times
                .into_iter()
                .enumerate()
                .map(|(index, finished_at)| BaseBackup {
                    id: format!("b{index}"),
                    started_at: finished_at.saturating_sub(5),
                    finished_at,
                    // 조각은 다 뜬 때를 따라 커진다(하루에 한 조각)
                    start_wal: format!("00000001000000000000{:04X}", finished_at / DAY),
                    segment_bytes: 1024 * 1024,
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn 보관_기간이_지난_백업만_지우고_마지막_기반_백업은_언제나_남긴다(backups in backups()) {
            // 지금은 30일, 보관 기간은 14일이다. 16일보다 앞에 다 뜬 것이 지난 것이다
            let now = 30 * DAY;
            let keep_for = 14 * DAY;
            let pruning = prune(&backups, now, keep_for);
            let newest = backups.iter().map(|backup| backup.finished_at).max();
            let mut newest_kept = false;
            for backup in &backups {
                let gone = pruning.backups.contains(&backup.id);
                let expired = backup.finished_at + keep_for < now;
                if Some(backup.finished_at) == newest {
                    // 가장 새 것과 같은 때에 뜬 것 가운데 하나는 반드시 남는다
                    newest_kept |= !gone;
                } else {
                    prop_assert_eq!(gone, expired, "{:?}", backup);
                }
            }
            prop_assert!(backups.is_empty() || newest_kept);
            // WAL 은 남는 가장 오랜 기반 백업이 시작하는 조각 앞까지만 지운다
            let oldest_kept = backups
                .iter()
                .filter(|backup| !pruning.backups.contains(&backup.id))
                .map(|backup| backup.start_wal.clone())
                .min();
            prop_assert_eq!(pruning.wal_before, oldest_kept);
        }
    }

    const POOL: [&str; 2] = ["k3f9x2ab", "k3f9x2abc"];

    fn capability() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::Source),
            Just(Capability::SourceRead),
            Just(Capability::Preview),
            Just(Capability::Rehearse),
            Just(Capability::SecretsRequest)
        ]
    }

    /// 토큰에 적어 보낼 능력의 이름. 되살리기를 다루는 능력처럼 보이는 이름을 섞는다.
    fn word() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("source"),
            Just("preview"),
            Just("rehearse"),
            Just("secrets_request"),
            Just("restore"),
            Just("restore_instance"),
            Just("backup"),
            Just("drill"),
        ]
    }

    proptest! {
        #[test]
        fn 어떤_토큰으로도_인스턴스를_되살리는_능력을_얻지_못한다(
            can in proptest::collection::btree_set(capability(), 0..=4),
            token_instance in 0usize..2,
            request_instance in 0usize..2,
            at in 0u64..6,
            words in proptest::collection::vec(word(), 0..5),
        ) {
            let token = Token {
                organization: OrganizationId("org_a".to_owned()),
                instance: InstanceId::parse(POOL[token_instance]).unwrap(),
                can,
                expires_at: 5,
            };
            let request = Request {
                organization: OrganizationId("org_a".to_owned()),
                instance: InstanceId::parse(POOL[request_instance]).unwrap(),
                action: Action::RestoreInstance,
                at,
            };
            prop_assert_ne!(judge(&token, &request), Verdict::Allow);
            // 되살리기를 다루는 능력의 이름을 적어 보낸 토큰은 읽히지 않는다
            let text = serde_json::json!({
                "organization": "org_a",
                "instance": "k3f9x2ab",
                "can": words,
                "expires_at": 5,
            })
            .to_string();
            let known = words
                .iter()
                .all(|word| matches!(*word, "source" | "preview" | "rehearse" | "secrets_request"));
            let parsed = serde_json::from_str::<Token>(&text);
            prop_assert_eq!(parsed.is_ok(), known);
            if let Ok(parsed) = parsed {
                let request = Request {
                    organization: parsed.organization.clone(),
                    instance: parsed.instance.clone(),
                    action: Action::RestoreInstance,
                    at: 0,
                };
                prop_assert_eq!(judge(&parsed, &request), Verdict::Deny(DenyReason::ServiceKeyOnly));
            }
        }
    }
}

// ---- 일정의 cron 식 ----

mod cron {
    use orbital_core::cron::Cron;
    use proptest::prelude::*;

    /// 칸 하나: 식에 적을 글과, 생성기가 아는 맞는 값의 집합(구현을 부르지 않고 만든다).
    fn field(low: u32, high: u32) -> impl Strategy<Value = (String, Vec<u32>)> {
        prop_oneof![
            Just(("*".to_owned(), (low..=high).collect())),
            (low..=high).prop_map(|value| (value.to_string(), vec![value])),
            (low..=high, low..=high).prop_map(|(a, b)| {
                let (from, to) = (a.min(b), a.max(b));
                (format!("{from}-{to}"), (from..=to).collect())
            }),
            (1u32..=7).prop_map(move |step| (
                format!("*/{step}"),
                (low..=high).step_by(step as usize).collect()
            )),
            proptest::collection::btree_set(low..=high, 1..4).prop_map(|values| (
                values
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                values.into_iter().collect()
            )),
        ]
    }

    /// 유닉스 초를 (월, 일, 시, 분, 요일)로. 구현과 다른 길로 센다: 해와 달을 앞에서부터 빼 나간다.
    fn calendar(at: u64) -> (u32, u32, u32, u32, u32) {
        let mut days = at / 86_400;
        let weekday = ((days + 4) % 7) as u32;
        let leap = |year: u64| {
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
        };
        let mut year = 1970;
        loop {
            let length = if leap(year) { 366 } else { 365 };
            if days < length {
                break;
            }
            days -= length;
            year += 1;
        }
        let lengths = [
            31,
            if leap(year) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut month = 0;
        while days >= lengths[month] {
            days -= lengths[month];
            month += 1;
        }
        let minute_of_day = (at % 86_400) / 60;
        (
            month as u32 + 1,
            days as u32 + 1,
            (minute_of_day / 60) as u32,
            (minute_of_day % 60) as u32,
            weekday,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        #[test]
        fn 다음_때는_언제나_지금보다_뒤이고_식에_맞으며_그_사이에_맞는_분이_없다(
            minute in field(0, 59),
            hour in field(0, 23),
            day in field(1, 31),
            month in field(1, 12),
            weekday in field(0, 6),
            // 2020 년부터 2040 년 사이의 아무 초
            now in 1_577_836_800u64..2_208_988_800u64,
        ) {
            let text = format!("{} {} {} {} {}", minute.0, hour.0, day.0, month.0, weekday.0);
            let either = !day.0.starts_with('*') && !weekday.0.starts_with('*');
            let fits = |at: u64| {
                let (m, d, h, min, w) = calendar(at);
                let on_day = if either {
                    day.1.contains(&d) || weekday.1.contains(&w)
                } else {
                    day.1.contains(&d) && weekday.1.contains(&w)
                };
                month.1.contains(&m) && on_day && hour.1.contains(&h) && minute.1.contains(&min)
            };
            match Cron::parse(&text) {
                // 오지 않는 식(2월 30일)만 받지 않는다. 그 식은 400년 안에 맞는 날이 정말로 없다
                Err(_) => {
                    let months_with_day = |d: u32| match d { 31 => vec![1, 3, 5, 7, 8, 10, 12], 30 => vec![1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], _ => (1..=12).collect() };
                    prop_assert!(!either && !day.1.iter().any(|d| months_with_day(*d).iter().any(|m| month.1.contains(m))), "{text}");
                }
                Ok(cron) => {
                    let next = cron.next_after(now).expect("받은 식은 언젠가 온다");
                    prop_assert!(next > now, "{text}: {next} <= {now}");
                    prop_assert_eq!(next % 60, 0);
                    prop_assert!(fits(next), "{}: {} 은 식에 맞지 않습니다 {:?}", text, next, calendar(next));
                    prop_assert!(cron.matches(next));
                    // 사이의 분은 맞지 않는다. 사흘까지 분마다 본다
                    let mut at = (now / 60 + 1) * 60;
                    while at < next && at < now + 3 * 86_400 {
                        prop_assert!(!fits(at), "{}: 사이의 {} 이 맞습니다", text, at);
                        at += 60;
                    }
                }
            }
        }
    }
}

// ---- 놓인 자리와 넘겨 주기 ----

mod placement {
    use orbital_core::placement::{Errand, Route, Unforwarded, route};
    use proptest::prelude::*;

    /// 어느 기계나 하는 일. 구현의 `reach` 를 부르지 않고 따로 적는다(기록과 인스턴스의 DB 에만 닿는 일).
    const ANYWHERE: [Errand; 7] = [
        Errand::Work,
        Errand::ProductionView,
        Errand::Users,
        Errand::Secrets,
        Errand::Rollout,
        Errand::Organization,
        Errand::Events,
    ];

    fn errand() -> impl Strategy<Value = Errand> {
        proptest::sample::select(Errand::ALL.to_vec())
    }

    /// 기계의 이름은 셋뿐이라 같은 기계와 다른 기계가 자주 나온다. `a` 와 `ab` 는 머리가 겹친다.
    fn machine() -> impl Strategy<Value = &'static str> {
        proptest::sample::select(vec!["a", "ab", "b"])
    }

    proptest! {
        #[test]
        fn 어떤_일이든_넘겨받은_요청은_다시_넘기지_않는다(
            errand in errand(), placed in machine(), here in machine(), known in any::<bool>()
        ) {
            let routed = route(errand, placed, here, true, known);
            prop_assert!(!matches!(routed, Route::Forward { .. }), "{:?}", routed);
            // 넘기지 않는 대신 하지 않을 일은 「넘겨받았다」는 까닭으로 놓인 기계의 이름과 함께 거절한다
            if placed != here && !ANYWHERE.contains(&errand) {
                prop_assert_eq!(routed, Route::Refuse { machine: placed.to_owned(), why: Unforwarded::AlreadyForwarded });
            }
        }

        #[test]
        fn 어느_기계나_하는_일은_넘기지_않고_받은_기계가_한다(
            errand in proptest::sample::select(ANYWHERE.to_vec()),
            placed in machine(), here in machine(), forwarded in any::<bool>(), known in any::<bool>()
        ) {
            prop_assert_eq!(route(errand, placed, here, forwarded, known), Route::Here);
        }

        #[test]
        fn 놓인_기계가_아닌_곳이_처음_받은_놓인_기계의_일은_주소를_알_때만_넘긴다(
            errand in errand(), placed in machine(), here in machine(), known in any::<bool>()
        ) {
            let expected = if placed == here || ANYWHERE.contains(&errand) {
                Route::Here
            } else if known {
                Route::Forward { machine: placed.to_owned() }
            } else {
                Route::Refuse { machine: placed.to_owned(), why: Unforwarded::NoAddress }
            };
            prop_assert_eq!(route(errand, placed, here, false, known), expected);
        }
    }
}

// ---- 조직과 service key ----

mod organization {
    use orbital_core::organization::{
        Caller, KeyFacts, Kind, OrganizationState, Presented, RevokeRefusal, judge_key,
        judge_new_instance, judge_revoke,
    };
    use orbital_core::scope::OrganizationId;
    use proptest::prelude::*;

    /// 조직은 둘뿐이라 같은 조직과 다른 조직이 자주 나온다. `acme` 와 `acme2` 는 머리가 겹친다.
    fn organization() -> impl Strategy<Value = OrganizationId> {
        proptest::sample::select(vec!["acme", "acme2"])
            .prop_map(|name| OrganizationId(name.to_owned()))
    }

    fn kind() -> impl Strategy<Value = Kind> {
        proptest::sample::select(vec![Kind::Live, Kind::Test])
    }

    fn state() -> impl Strategy<Value = OrganizationState> {
        (kind(), any::<bool>()).prop_map(|(kind, closed)| OrganizationState { kind, closed })
    }

    /// (실려 온 열쇠, 그 열쇠가 가리키는 조직, 거둔 것인가, 그 조직의 모습). 어디서 왔든 고르게 나온다.
    fn presented() -> impl Strategy<Value = Presented> {
        prop_oneof![
            (organization(), proptest::option::of(state())).prop_map(|(organization, state)| {
                Presented::Configured {
                    organization,
                    state,
                }
            }),
            (
                organization(),
                any::<bool>(),
                state(),
                proptest::sample::select(vec!["key_a", "key_b"])
            )
                .prop_map(|(organization, revoked, state, key)| Presented::Recorded {
                    key: key.to_owned(),
                    organization,
                    revoked,
                    state,
                }),
            Just(Presented::Unknown),
        ]
    }

    proptest! {
        #[test]
        fn 거둔_열쇠는_어떤_조직의_어떤_모습에서도_받지_않는다(organization in organization(), state in state()) {
            let presented = Presented::Recorded { key: "key_a".to_owned(), organization, revoked: true, state };
            prop_assert!(judge_key(&presented).is_err());
        }

        #[test]
        fn 닫힌_조직의_열쇠는_어디서_왔든_받지_않는다(presented in presented()) {
            let closed = match &presented {
                Presented::Configured { state, .. } => state.is_some_and(|state| state.closed),
                Presented::Recorded { state, .. } => state.closed,
                Presented::Unknown => false,
            };
            if closed {
                prop_assert!(judge_key(&presented).is_err());
            }
        }

        #[test]
        fn 받아들인_열쇠의_주인은_언제나_그_열쇠가_가리키는_조직이다(presented in presented()) {
            // 기대값은 생성한 입력에서 바로 읽는다
            let expected = match &presented {
                Presented::Configured { organization, state: Some(state) } if !state.closed => {
                    Some(Caller { organization: organization.clone(), kind: state.kind, key: None })
                }
                Presented::Configured { organization, state: None } => {
                    Some(Caller { organization: organization.clone(), kind: Kind::Live, key: None })
                }
                Presented::Recorded { key, organization, revoked: false, state } if !state.closed => {
                    Some(Caller { organization: organization.clone(), kind: state.kind, key: Some(key.clone()) })
                }
                _ => None,
            };
            prop_assert_eq!(judge_key(&presented).ok(), expected);
        }

        #[test]
        fn 어떤_조직의_열쇠도_다른_조직의_열쇠를_거두지_못하고_없는_것과_같다(
            caller in organization(), owner in organization(), revoked in any::<bool>(), alive in 0u32..4
        ) {
            let target = KeyFacts { organization: owner.clone(), revoked };
            let judged = judge_revoke(&caller, Some(&target), alive);
            if caller != owner {
                prop_assert_eq!(judged, Err(RevokeRefusal::NotFound));
            }
        }

        #[test]
        fn 살아_있는_열쇠가_하나뿐인_조직은_그_열쇠를_거두지_못한다(organization in organization(), alive in 0u32..2) {
            let target = KeyFacts { organization: organization.clone(), revoked: false };
            prop_assert_eq!(judge_revoke(&organization, Some(&target), alive), Err(RevokeRefusal::LastKey));
        }

        #[test]
        fn 시험용_조직은_어떤_상한에서도_상한보다_많이_세우지_못하고_운영의_조직은_상한을_받지_않는다(
            state in proptest::option::of(state()), existing in 0u32..14, limit in 0u32..12
        ) {
            let open = state.is_none_or(|state| !state.closed);
            let capped = state.is_some_and(|state| state.kind == Kind::Test);
            let expected = open && (!capped || existing < limit);
            prop_assert_eq!(judge_new_instance(state.as_ref(), existing, limit).is_ok(), expected);
        }

        #[test]
        fn 상한_밖의_판정은_조직의_종류에_따라_달라지지_않는다(
            closed in any::<bool>(), existing in 0u32..5, organization in organization(), revoked in any::<bool>()
        ) {
            // 상한(10) 아래에서 인스턴스를 세우는 판정과, 열쇠를 받는 판정은 시험용이든 운영이든 같다
            let of = |kind| OrganizationState { kind, closed };
            prop_assert_eq!(
                judge_new_instance(Some(&of(Kind::Test)), existing, 10),
                judge_new_instance(Some(&of(Kind::Live)), existing, 10)
            );
            let key = |kind| Presented::Recorded { key: "key_a".to_owned(), organization: organization.clone(), revoked, state: of(kind) };
            prop_assert_eq!(
                judge_key(&key(Kind::Test)).map(|caller| caller.organization),
                judge_key(&key(Kind::Live)).map(|caller| caller.organization)
            );
        }
    }
}

mod webhook {
    use orbital_core::webhook::{
        Address, Allow, ResolveRefusal, UrlProblem, judge_address, judge_resolved, judge_url,
    };
    use proptest::prelude::*;

    /// 안쪽의 IPv4 대역(앞 바이트, 고정된 비트 수). 구현을 부르지 않고 따로 적는다.
    const INSIDE_V4: [([u8; 2], u32); 7] = [
        ([10, 0], 8),
        ([172, 16], 12),
        ([192, 168], 16),
        ([127, 0], 8),
        ([169, 254], 16),
        ([100, 64], 10),
        ([0, 0], 8),
    ];

    /// 대역 안의 아무 주소. 고정된 비트는 대역의 것을, 나머지는 무작위를 쓴다.
    fn inside_v4() -> impl Strategy<Value = [u8; 4]> {
        (0usize..INSIDE_V4.len(), any::<u32>()).prop_map(|(at, noise)| {
            let ([a, b], bits) = INSIDE_V4[at];
            let base = u32::from_be_bytes([a, b, 0, 0]);
            let mask = u32::MAX << (32 - bits);
            ((base & mask) | (noise & !mask)).to_be_bytes()
        })
    }

    /// 안쪽의 IPv6: loopback · link-local(fe80::/10) · ULA(fc00::/7).
    fn inside_v6() -> impl Strategy<Value = [u16; 8]> {
        (0u8..3, any::<[u16; 8]>()).prop_map(|(kind, mut segments)| {
            match kind {
                0 => segments = [0, 0, 0, 0, 0, 0, 0, 1],
                1 => segments[0] = 0xfe80 | (segments[0] & 0x003f),
                _ => segments[0] = 0xfc00 | (segments[0] & 0x01ff),
            }
            segments
        })
    }

    /// 공인 대역의 앞 바이트. 이 /8 안에는 남겨 둔 대역이 없다.
    fn public_v4() -> impl Strategy<Value = [u8; 4]> {
        let firsts: Vec<u8> = (1u8..=223)
            .filter(|first| !matches!(first, 10 | 100 | 127 | 169 | 172 | 192 | 198 | 203))
            .collect();
        (proptest::sample::select(firsts), any::<[u8; 3]>())
            .prop_map(|(first, [b, c, d])| [first, b, c, d])
    }

    fn allow() -> impl Strategy<Value = Allow> {
        prop_oneof![Just(Allow::Public), Just(Allow::Development)]
    }

    proptest! {
        #[test]
        fn 어떤_사설_loopback_link_local_주소도_받지_않는다(v4 in inside_v4(), v6 in inside_v6()) {
            prop_assert!(judge_address(Address::V4(v4), Allow::Public).is_err(), "{:?}", v4);
            prop_assert!(judge_address(Address::V6(v6), Allow::Public).is_err(), "{:?}", v6);
        }

        #[test]
        fn link_local_은_메타데이터_주소를_품어_개발용_레이어에서도_받지_않는다(
            noise in any::<u16>(), segments in any::<[u16; 7]>()
        ) {
            let [c, d] = noise.to_be_bytes();
            prop_assert!(judge_address(Address::V4([169, 254, c, d]), Allow::Development).is_err());
            let mut v6 = [0xfe80 | (noise & 0x003f), 0, 0, 0, 0, 0, 0, 0];
            v6[1..].copy_from_slice(&segments);
            prop_assert!(judge_address(Address::V6(v6), Allow::Development).is_err());
        }

        #[test]
        fn ipv4_로_사상된_ipv6_는_안의_주소가_무엇이든_받지_않는다(v4 in any::<[u8; 4]>(), allow in allow()) {
            let [a, b, c, d] = v4;
            let mapped = [0, 0, 0, 0, 0, 0xffff, u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d])];
            prop_assert!(judge_address(Address::V6(mapped), allow).is_err());
        }

        #[test]
        fn 공인_대역의_주소는_받는다(v4 in public_v4()) {
            prop_assert_eq!(judge_address(Address::V4(v4), Allow::Public), Ok(()));
        }

        #[test]
        fn 풀어_나온_주소_가운데_하나라도_안쪽이면_받지_않는다(
            outside in proptest::collection::vec(public_v4(), 0..5), inside in inside_v4(), at in 0usize..6
        ) {
            let mut addresses: Vec<Address> = outside.iter().copied().map(Address::V4).collect();
            let at = at.min(addresses.len());
            addresses.insert(at, Address::V4(inside));
            let judged = judge_resolved(&addresses, Allow::Public);
            prop_assert!(matches!(judged, Err(ResolveRefusal::Inside { .. })), "{:?}", judged);
            addresses.remove(at);
            let expected = if addresses.is_empty() { Err(ResolveRefusal::Empty) } else { Ok(()) };
            prop_assert_eq!(judge_resolved(&addresses, Allow::Public), expected);
        }

        #[test]
        fn 사용자_이름을_적은_주소는_어떤_호스트든_받지_않는다(
            user in "[a-z0-9:]{0,12}", host in "[a-z0-9.]{1,20}", allow in allow()
        ) {
            let problems = judge_url(&format!("https://{user}@{host}/hook"), allow).unwrap_err();
            prop_assert!(problems.contains(&UrlProblem::Credentials));
        }
    }
}

mod event {
    use orbital_core::event::{GIVE_UP_AFTER, Retry, after_failure, rollout_notes};
    use orbital_core::name::InstanceId;
    use orbital_core::release::Change;
    use orbital_core::rollout::{Event, Rollout};
    use proptest::prelude::*;

    const POOL: [&str; 3] = ["k3f9x2ab", "k3f9x2abc", "zzzzzzzz"];

    fn id(text: &str) -> InstanceId {
        InstanceId::parse(text).unwrap()
    }

    fn event(kind: u8, at: usize, pass: bool) -> Event {
        let instance = id(POOL[at]);
        match kind {
            0 => Event::Applied { instance },
            1 => Event::Previewed { instance },
            2 => Event::Checked {
                instance,
                access_passed: pass,
                conformance_passed: true,
            },
            3 => Event::Promoted {
                instance,
                change: Change::SecurityUpdate,
            },
            4 => Event::RolledBack { instance },
            5 => Event::Resume,
            _ => Event::Cancel,
        }
    }

    proptest! {
        #[test]
        fn 다시_보내는_때는_언제나_지금보다_뒤이고_처음_실패에서_하루를_넘지_않는다(
            failures in 1u32..64, since in 0u64..1_000_000_000, elapsed in 0u64..GIVE_UP_AFTER
        ) {
            let now = since + elapsed;
            match after_failure(failures, since, now) {
                Retry::At(next) => {
                    prop_assert!(next > now);
                    prop_assert!(next <= since + GIVE_UP_AFTER);
                }
                Retry::GiveUp => prop_assert!(false, "하루 안에서 그만뒀습니다"),
            }
        }

        #[test]
        fn 처음_실패에서_하루가_지난_뒤의_실패는_언제나_그만둔다(
            failures in 1u32..64, since in 0u64..1_000_000_000, late in 0u64..10_000_000
        ) {
            prop_assert_eq!(after_failure(failures, since, since + GIVE_UP_AFTER + late), Retry::GiveUp);
        }

        #[test]
        fn rollout_의_사건이_어떤_순서로_와도_바뀐_인스턴스마다_하나_상태가_바뀌면_하나가_나온다(
            raws in proptest::collection::vec((0u8..7, 0usize..3, any::<bool>()), 0..40)
        ) {
            let mut rollout = Rollout::new(
                "todo".to_owned(),
                "a".repeat(40),
                Change::SecurityUpdate,
                vec![vec![id(POOL[0]), id(POOL[1])], vec![id(POOL[2])]],
            ).unwrap();
            for (kind, at, pass) in raws {
                let before = rollout.clone();
                let after = before.step(&event(kind, at, pass)).unwrap_or_else(|_| before.clone());
                let notes = rollout_notes("r1", &before, &after);
                let moved = after.progress.iter().filter(|(instance, state)| before.progress.get(*instance) != Some(*state)).count();
                let advanced = notes.iter().filter(|note| note.body.kind() == "rollout.advanced").count();
                prop_assert_eq!(advanced, moved);
                let status = notes.len() - advanced;
                prop_assert_eq!(status, usize::from(before.status != after.status));
                // 진행이 먼저이고 상태가 뒤다
                if status == 1 {
                    prop_assert_ne!(notes.last().map(|note| note.body.kind()), Some("rollout.advanced"));
                }
                rollout = after;
            }
        }
    }
}

// ---- 목록의 쪽 ----

mod listing {
    use orbital_core::listing::Cursor;
    use proptest::prelude::*;

    /// 식별자의 글자. 경계가 자주 나오게 허락하는 글자 몇과 허락하지 않는 글자 몇만 쓴다.
    fn allowed() -> impl Strategy<Value = char> {
        proptest::sample::select(vec!['a', 'z', '0', '9', '_'])
    }

    /// 표식의 식별자 자리에 올 글자. 대부분 허락하는 글자이고, 가끔 허락하지 않는 글자(대문자 · 기호 · 빈칸 · 한글)가 섞인다.
    fn id_char() -> impl Strategy<Value = char> {
        prop_oneof![
            8 => allowed(),
            1 => proptest::sample::select(vec!['A', 'Z', '-', '.', ' ', '가', '/']),
        ]
    }

    /// 표식의 때 자리에 올 글. 대부분 숫자이고, 가끔 숫자가 아닌 것이 섞인다.
    fn at_text() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => proptest::collection::vec(proptest::sample::select(vec!['0', '1', '9']), 0..5)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
            1 => proptest::collection::vec(proptest::sample::select(vec!['1', '-', '+', 'x', ' ']), 0..4)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
        ]
    }

    proptest! {
        #[test]
        fn 어떤_표식이든_글로_적었다_읽으면_같다(
            created_at in prop_oneof![Just(0_u64), Just(u64::MAX), any::<u64>()],
            id in proptest::collection::vec(allowed(), 1..=64)
        ) {
            let cursor = Cursor { created_at, id: id.into_iter().collect() };
            prop_assert_eq!(Cursor::parse(&cursor.text()), Some(cursor));
        }

        #[test]
        fn 점이_없거나_때가_수가_아니거나_식별자에_없는_글자가_든_표식은_받지_않는다(
            at in at_text(),
            id in proptest::collection::vec(id_char(), 0..70)
        ) {
            let id: String = id.into_iter().collect();
            let text = format!("{at}.{id}");
            // 오라클: 표식의 규칙을 구현과 따로 적는다
            let at_ok = !at.is_empty() && at.chars().all(|c| c.is_ascii_digit());
            let id_ok = !id.is_empty() && id.chars().count() <= 64
                && id.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'));
            prop_assert_eq!(Cursor::parse(&text).is_some(), at_ok && id_ok, "{}", text);
            // 점이 없는 글은 무엇이든 받지 않는다
            let joined = format!("{at}{id}");
            if !joined.contains('.') {
                prop_assert_eq!(Cursor::parse(&joined), None);
            }
        }
    }
}

// ---- 운영의 로그 ----

mod fleet {
    use orbital_core::fleet::{CLIPPED_MARK, LOG_LINE_MAX, clip_line};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn 어떤_줄이든_자른_줄은_상한의_글자_수를_넘지_않고_원래_줄의_머리다(
            pieces in proptest::collection::vec(proptest::sample::select(vec!["a", "가", "😀", " ", "\t"]), 0..2100)
        ) {
            let line: String = pieces.concat();
            let (clipped, cut) = clip_line(&line);
            let count = line.chars().count();
            // 오라클: 글자 수로만 가른다
            prop_assert_eq!(cut, count > LOG_LINE_MAX);
            let body = clipped.strip_suffix(CLIPPED_MARK).filter(|_| cut).unwrap_or(&clipped);
            prop_assert!(body.chars().count() <= LOG_LINE_MAX);
            prop_assert!(line.starts_with(body));
            if !cut {
                prop_assert_eq!(&clipped, &line);
            }
        }
    }
}
