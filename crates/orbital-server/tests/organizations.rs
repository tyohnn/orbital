//! 팩토리(조직)와 service key 의 셀프서비스를 관리 서버의 HTTP 처리(`handle`)로 잰다.
//!
//! 대시보드가 가입을 받으면 운영자 키로 조직을 만들고 첫 키를 받아 한 번만 보여 준다. 팩토리는 그 키로 키를 더 만들고 폐기한다.
//! 레이어를 여는 데 DB 의 관리 주소가 있어야 해서 `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use orbital_run::LocalRunner;
use orbital_server::http::handle;
use orbital_server::layer::{Layer, Options};
use serde_json::{Value, json};

const ADMIN: &str = "admin_key_for_tests_0123456789abcdef";
const BOOTSTRAP: &str = "sk_test_bootstrap";

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Bench {
    home: std::path::PathBuf,
    pg_url: String,
    layer: Option<Arc<Layer>>,
}

impl Bench {
    fn new() -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let home = std::env::temp_dir().join(format!(
            "orbital-organizations-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&home).unwrap();
        let mut bench = Self {
            home,
            pg_url,
            layer: None,
        };
        bench.open();
        Some(bench)
    }

    fn open(&mut self) {
        self.layer = None;
        self.layer = Some(Arc::new(
            Layer::open(Options {
                admin_key: Some(ADMIN.to_owned()),
                ..Options::new(
                    self.home.clone(),
                    self.pg_url.clone(),
                    vec![(BOOTSTRAP.to_owned(), "boot".to_owned())],
                    Box::new(LocalRunner::default()),
                )
            })
            .expect("레이어를 열지 못했습니다"),
        ));
    }

    fn call(&self, method: &str, path: &str, bearer: Option<&str>, body: Value) -> (u16, Value) {
        let body = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        let reply = handle(self.layer.as_ref().unwrap(), method, path, bearer, &body);
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
        )
    }

    /// 운영자 키로 조직을 만들고 첫 키의 비밀을 돌려준다.
    fn organization(&self, id: &str) -> String {
        let (status, body) = self.call(
            "POST",
            "/v1/admin/organizations",
            Some(ADMIN),
            json!({ "id": id }),
        );
        assert_eq!(status, 201, "{body}");
        body["key"]["secret"].as_str().unwrap().to_owned()
    }

    fn new_key(&self, key: &str, label: &str) -> Value {
        let (status, body) = self.call("POST", "/v1/keys", Some(key), json!({ "label": label }));
        assert_eq!(status, 201, "{body}");
        body
    }

    fn list(&self, key: &str) -> (u16, Value) {
        self.call("GET", "/v1/keys", Some(key), Value::Null)
    }

    fn revoke(&self, key: &str, id: &str) -> (u16, Value) {
        self.call(
            "POST",
            &format!("/v1/keys/{id}/revoke"),
            Some(key),
            Value::Null,
        )
    }

    /// service key 로만 되는 길 하나. 키가 살아 있는지 본다.
    fn backup_status(&self, key: &str) -> u16 {
        self.call("GET", "/v1/backup", Some(key), Value::Null).0
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        self.layer = None;
        let _ = fs::remove_dir_all(&self.home);
    }
}

macro_rules! bench {
    () => {
        match Bench::new() {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
}

fn ids(list: &Value) -> Vec<String> {
    list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn 운영자_키로_조직을_만들면_첫_service_key_를_한_번만_보여_주고_그_키로_부른다() {
    let bench = bench!();
    let (status, body) = bench.call(
        "POST",
        "/v1/admin/organizations",
        Some(ADMIN),
        json!({ "id": "acme", "label": "Acme 팩토리" }),
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["organization"], "acme");
    let secret = body["key"]["secret"].as_str().unwrap();
    assert!(secret.starts_with("orb_sk_"), "{secret}");
    assert!(body["key"]["id"].as_str().unwrap().starts_with("key_"));
    assert_eq!(bench.backup_status(secret), 200);
    // 목록에는 그 키가 있되 비밀은 다시 보이지 않는다
    let (status, list) = bench.list(secret);
    assert_eq!(status, 200);
    assert_eq!(ids(&list), vec![body["key"]["id"].as_str().unwrap()]);
    assert!(!list.to_string().contains(secret));
    assert!(list["keys"][0].get("secret").is_none());
}

#[test]
fn 운영자_키가_없거나_틀리거나_service_key_면_조직을_만들지_못한다() {
    let bench = bench!();
    let body = json!({ "id": "acme" });
    for bearer in [
        None,
        Some("wrong_admin_key_0123456789abcdef0123"),
        Some(BOOTSTRAP),
    ] {
        let (status, _) = bench.call("POST", "/v1/admin/organizations", bearer, body.clone());
        assert_eq!(status, 401, "{bearer:?}");
    }
    let acme = bench.organization("acme");
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations",
        Some(&acme),
        json!({ "id": "other" }),
    );
    assert_eq!(status, 401);
    // 운영자 키를 두지 않은 레이어는 누구에게도 열지 않는다
    let home = bench.home.join("keyless");
    let keyless = Layer::open(Options::new(
        home,
        bench.pg_url.clone(),
        vec![(BOOTSTRAP.to_owned(), "boot".to_owned())],
        Box::new(LocalRunner::default()),
    ))
    .unwrap();
    let reply = handle(
        &keyless,
        "POST",
        "/v1/admin/organizations",
        Some(ADMIN),
        body.to_string().as_bytes(),
    );
    assert_eq!(reply.status, 401);
}

#[test]
fn 이미_있는_조직이나_환경_변수의_조직은_다시_만들지_못하고_이름이_틀리면_400_이다() {
    let bench = bench!();
    bench.organization("acme");
    for id in ["acme", "boot"] {
        let (status, _) = bench.call(
            "POST",
            "/v1/admin/organizations",
            Some(ADMIN),
            json!({ "id": id }),
        );
        assert_eq!(status, 409, "{id}");
    }
    for id in ["", "Acme", "-acme", "ac me", "아크미"] {
        let (status, _) = bench.call(
            "POST",
            "/v1/admin/organizations",
            Some(ADMIN),
            json!({ "id": id }),
        );
        assert_eq!(status, 400, "{id}");
    }
}

#[test]
fn 조직의_키로_새_키를_만들고_목록에는_만든_차례로_비밀_없이_보인다() {
    let bench = bench!();
    let first = bench.organization("acme");
    let deploy = bench.new_key(&first, "배포 서버");
    let laptop = bench.new_key(&first, "노트북");
    assert_eq!(deploy["label"], "배포 서버");
    let deploy_secret = deploy["secret"].as_str().unwrap();
    assert_eq!(bench.backup_status(deploy_secret), 200);
    let (_, list) = bench.list(deploy_secret);
    let listed = ids(&list);
    assert_eq!(listed.len(), 3);
    assert_eq!(listed[1], deploy["id"].as_str().unwrap());
    assert_eq!(listed[2], laptop["id"].as_str().unwrap());
    for secret in [&first, deploy_secret, laptop["secret"].as_str().unwrap()] {
        assert!(!list.to_string().contains(secret));
    }
    // 이름 없이 불러도 되고, 이름은 100글자까지다
    let (status, _) = bench.call("POST", "/v1/keys", Some(&first), Value::Null);
    assert_eq!(status, 201);
    let (status, _) = bench.call(
        "POST",
        "/v1/keys",
        Some(&first),
        json!({ "label": "가".repeat(101) }),
    );
    assert_eq!(status, 400);
}

#[test]
fn 폐기한_키는_다음_요청부터_거절된다() {
    let bench = bench!();
    let first = bench.organization("acme");
    let second = bench.new_key(&first, "두 번째");
    let (status, revoked) = bench.revoke(&first, second["id"].as_str().unwrap());
    assert_eq!(status, 200, "{revoked}");
    assert!(revoked["revoked_at"].is_u64());
    assert_eq!(bench.backup_status(second["secret"].as_str().unwrap()), 401);
    assert_eq!(bench.backup_status(&first), 200);
    // 다시 폐기해도 같은 답이고 아무것도 바뀌지 않는다
    let (status, again) = bench.revoke(&first, second["id"].as_str().unwrap());
    assert_eq!(status, 200);
    assert_eq!(again["revoked_at"], revoked["revoked_at"]);
}

#[test]
fn 조직의_마지막_살아_있는_키는_폐기하지_못한다() {
    let bench = bench!();
    let first = bench.organization("acme");
    let (_, list) = bench.list(&first);
    let first_id = ids(&list)[0].clone();
    let (status, _) = bench.revoke(&first, &first_id);
    assert_eq!(status, 409);
    assert_eq!(bench.backup_status(&first), 200);
    // 새 키를 만든 뒤에는 앞의 키를 폐기하고, 그러면 새 키가 마지막 키다
    let second = bench.new_key(&first, "새 키");
    let second_secret = second["secret"].as_str().unwrap();
    assert_eq!(bench.revoke(second_secret, &first_id).0, 200);
    assert_eq!(
        bench
            .revoke(second_secret, second["id"].as_str().unwrap())
            .0,
        409
    );
}

#[test]
fn 한_조직의_키는_다른_조직의_키를_보지도_폐기하지도_못한다() {
    let bench = bench!();
    let acme = bench.organization("acme");
    let globex = bench.organization("globex");
    let globex_extra = bench.new_key(&globex, "여분");
    let (_, acme_list) = bench.list(&acme);
    assert!(
        !acme_list
            .to_string()
            .contains(globex_extra["id"].as_str().unwrap())
    );
    // 다른 조직의 키는 없는 키와 같은 답이다
    let (status, _) = bench.revoke(&acme, globex_extra["id"].as_str().unwrap());
    assert_eq!(status, 404);
    let (status, _) = bench.revoke(&acme, "key_0000000000000000");
    assert_eq!(status, 404);
    assert_eq!(
        bench.backup_status(globex_extra["secret"].as_str().unwrap()),
        200
    );
}

#[test]
fn 에이전트의_토큰은_키의_길에_닿지_못한다() {
    let bench = bench!();
    bench.organization("acme");
    // 토큰은 `orb1.` 로 시작한다. 서명이 맞든 틀리든 키의 길과 운영자의 길은 토큰 쪽에 없다
    let token = "orb1.eyJ9.forged";
    assert_eq!(bench.list(token).0, 404);
    assert_eq!(
        bench.call("POST", "/v1/keys", Some(token), Value::Null).0,
        404
    );
    assert_eq!(bench.revoke(token, "key_0000000000000000").0, 404);
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations",
        Some(token),
        json!({ "id": "x" }),
    );
    assert_eq!(status, 401);
}

#[test]
fn 키는_해시로만_기록에_두고_관리_서버가_다시_떠도_남는다() {
    let mut bench = bench!();
    let first = bench.organization("acme");
    let second = bench.new_key(&first, "배포 서버");
    let second_secret = second["secret"].as_str().unwrap().to_owned();
    bench.revoke(&first, second["id"].as_str().unwrap());
    let mut written = String::new();
    for entry in fs::read_dir(&bench.home).unwrap().flatten() {
        if entry.path().is_file() {
            written.push_str(&String::from_utf8_lossy(&fs::read(entry.path()).unwrap()));
        }
    }
    assert!(written.contains("acme"));
    assert!(!written.contains(&first));
    assert!(!written.contains(&second_secret));
    bench.open();
    assert_eq!(bench.backup_status(&first), 200);
    assert_eq!(bench.backup_status(&second_secret), 401);
    assert_eq!(ids(&bench.list(&first).1).len(), 2);
}

#[test]
fn 환경_변수의_키는_부트스트랩으로_계속_쓰이고_그_조직의_키를_만든다() {
    let bench = bench!();
    assert_eq!(bench.backup_status(BOOTSTRAP), 200);
    let made = bench.new_key(BOOTSTRAP, "API 로 만든 키");
    let (_, list) = bench.list(BOOTSTRAP);
    // 환경 변수의 키는 목록에 보이지 않는다
    assert_eq!(ids(&list), vec![made["id"].as_str().unwrap()]);
    // 환경 변수의 키가 있으니 마지막 저장한 키도 폐기한다
    assert_eq!(bench.revoke(BOOTSTRAP, made["id"].as_str().unwrap()).0, 200);
    assert_eq!(bench.backup_status(BOOTSTRAP), 200);
}

#[test]
fn 운영자는_살아_있는_키가_없는_조직에만_키를_내어_되살린다() {
    let bench = bench!();
    let first = bench.organization("acme");
    // 살아 있는 키가 있으면 운영자는 키를 내지 않는다
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/acme/keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 409);
    // 환경 변수의 조직에도, 없는 조직에도 내지 않고, service key 로는 부르지 못한다
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/boot/keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 409);
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/nobody/keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 404);
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/acme/keys",
        Some(&first),
        Value::Null,
    );
    assert_eq!(status, 401);
}

#[test]
fn 운영자가_키를_갈면_조직의_키는_모두_폐기되고_새_키_하나로만_부른다() {
    let bench = bench!();
    let first = bench.organization("acme");
    let second = bench.new_key(&first, "배포 서버");
    let (status, fresh) = bench.call(
        "POST",
        "/v1/admin/organizations/acme/reset-keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 201, "{fresh}");
    let fresh_secret = fresh["secret"].as_str().unwrap();
    assert_eq!(bench.backup_status(&first), 401);
    assert_eq!(bench.backup_status(second["secret"].as_str().unwrap()), 401);
    assert_eq!(bench.backup_status(fresh_secret), 200);
    let (_, list) = bench.list(fresh_secret);
    let live: Vec<&Value> = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["revoked_at"].is_null())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0]["id"], fresh["id"]);
    // 환경 변수의 조직과 없는 조직의 키는 갈지 않고, 운영자 키가 아니면 부르지 못한다
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/boot/reset-keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 409);
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/nobody/reset-keys",
        Some(ADMIN),
        Value::Null,
    );
    assert_eq!(status, 404);
    let (status, _) = bench.call(
        "POST",
        "/v1/admin/organizations/acme/reset-keys",
        Some(fresh_secret),
        Value::Null,
    );
    assert_eq!(status, 401);
}
