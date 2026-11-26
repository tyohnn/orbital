//! git 이 레이어에 바로 붙는 길(smart HTTP)을 실제로 돈다.
//!
//! 레이어를 실제 HTTP 로 띄우고, 에이전트가 하듯이 실제 `git` 실행 파일로 `clone` · `fetch` · `push` 한다. 자격은 작업에 한정된
//! 토큰이고, git 이 보내는 두 모양(한 번 쓰는 머리말의 Bearer, 자격 도우미가 건네는 Basic 의 비밀번호)을 모두 쓴다.
//! 실제 PostgreSQL 에 붙는다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use orbital_run::LocalRunner;
use orbital_server::http::serve;
use orbital_server::layer::{Layer, Options};
use serde_json::{Value, json};

/// 레이어마다 다른 control database 의 이름. 같은 `home` 으로 다시 열면 같은 이름이라 다시 뜬 레이어가 같은 기록을 본다.
fn control_of(home: &std::path::Path) -> orbital_core::name::Ident {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    home.hash(&mut hasher);
    orbital_core::name::Ident::parse(&format!("ctl_{:016x}", hasher.finish())).unwrap()
}

/// 테스트가 세운 control database 를 걷는다.
fn forget_control(home: &std::path::Path) {
    if let Ok(pg_url) = std::env::var("ORBITAL_PG") {
        let _ = orbital_server::records::drop_database(&pg_url, &control_of(home));
    }
}

const FACTORY: &str = "sk_test_factory";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// 사람의 git 설정이 섞이지 않는 git. 실패해도 결과를 돌려준다.
fn run_git(folder: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(folder)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=agent",
            "-c",
            "user.email=agent@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .unwrap()
}

fn git(folder: &Path, args: &[&str]) -> String {
    let output = run_git(folder, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// 한 번 쓰는 머리말로 토큰을 건네는 git. 토큰은 저장소의 설정이나 원격의 주소에 남지 않는다.
fn bearer_git(folder: &Path, token: &str, args: &[&str]) -> Output {
    let header = format!("http.extraHeader=Authorization: Bearer {token}");
    let mut all = vec!["-c", header.as_str()];
    all.extend_from_slice(args);
    run_git(folder, &all)
}

/// 자격 도우미로 토큰을 건네는 git. git 은 401 을 받은 뒤 Basic 으로 다시 보낸다. 사용자 이름은 아무것이나 된다.
fn helper_git(folder: &Path, token: &str, args: &[&str]) -> Output {
    let helper = format!(
        "credential.helper=!f() {{ test \"$1\" = get && echo username=agent && echo password={token}; }}; f"
    );
    let mut all = vec!["-c", "credential.helper=", "-c", helper.as_str()];
    all.extend_from_slice(args);
    run_git(folder, &all)
}

fn ok(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn refused(output: Output) -> String {
    assert!(!output.status.success(), "git 이 성공했습니다");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// 실제 HTTP 의 답 하나.
struct Answer {
    status: u16,
    content_type: String,
    challenge: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// 실제 HTTP 로 부른다. `authorization` 은 머리말의 값 그대로다.
fn raw(method: &str, url: &str, authorization: Option<&str>, body: &[u8]) -> Answer {
    let mut request = ureq::request(method, url);
    if let Some(value) = authorization {
        request = request.set("Authorization", value);
    }
    // git 이 싣는 것처럼 객체를 주고받는 요청에는 그 길의 `Content-Type` 을 싣는다
    for service in ["git-upload-pack", "git-receive-pack"] {
        if method == "POST" && url.ends_with(service) {
            request = request.set("Content-Type", &format!("application/x-{service}-request"));
        }
    }
    let response = if method == "GET" {
        request.call()
    } else {
        request.send_bytes(body)
    };
    let response = match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("{url}: {error}"),
    };
    let status = response.status();
    let content_type = response.content_type().to_owned();
    let challenge = response.header("www-authenticate").map(str::to_owned);
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body).unwrap();
    Answer {
        status,
        content_type,
        challenge,
        body,
    }
}

fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

/// git 의 줄(pkt-line) 하나.
fn pkt(line: &str) -> Vec<u8> {
    let mut out = format!("{:04x}", line.len() + 4).into_bytes();
    out.extend_from_slice(line.as_bytes());
    out
}

/// 레이어 하나를 실제 HTTP 로 띄우고 팩토리가 스캐폴드를 올린 자리.
struct Bench {
    scratch: PathBuf,
    url: String,
    /// 토큰을 판정하는 시계를 이만큼 앞으로 돌린다.
    ahead: Arc<AtomicU64>,
    instances: Vec<String>,
}

impl Bench {
    fn new(upload_limit: Option<usize>) -> Option<Self> {
        let pg_url = std::env::var("ORBITAL_PG").ok()?;
        let scratch = std::env::temp_dir().join(format!(
            "orbital-git-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let ahead = Arc::new(AtomicU64::new(0));
        let clock = Arc::clone(&ahead);
        let defaults = Options::new(
            scratch.join("home"),
            pg_url,
            vec![(FACTORY.to_owned(), "factory".to_owned())],
            Box::new(LocalRunner::default()),
        );
        let layer = Layer::open(Options {
            dev_mailbox: true,
            control_database: control_of(&scratch.join("home")),
            token_clock: Arc::new(move || now() + clock.load(Ordering::SeqCst)),
            upload_limit: upload_limit.unwrap_or(defaults.upload_limit),
            ..defaults
        })
        .expect("레이어를 열지 못했습니다");
        let layer = Arc::new(layer);
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        // 레이어는 받는 고리가 갖는다. 세운 인스턴스는 걷을 때 HTTP 로 걷는다
        std::thread::spawn(move || serve(layer, server));

        // 팩토리가 스캐폴드를 만들어 v1 을 달고 올린다. 팩토리만 아는 브랜치(`draft`)도 함께 있다
        let scaffold = scratch.join("scaffold");
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/todo"),
            &scaffold,
        );
        git(&scaffold, &["init", "--quiet", "--initial-branch", "main"]);
        git(&scaffold, &["add", "-A"]);
        git(&scaffold, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
        git(&scaffold, &["tag", "v1"]);
        git(&scaffold, &["checkout", "--quiet", "-b", "draft"]);
        fs::write(scaffold.join("DRAFT.md"), "팩토리만 보는 초안\n").unwrap();
        git(&scaffold, &["add", "-A"]);
        git(&scaffold, &["commit", "--quiet", "-m", "초안"]);
        git(&scaffold, &["checkout", "--quiet", "main"]);
        let bench = Self {
            scratch,
            url,
            ahead,
            instances: Vec::new(),
        };
        bench.publish();
        Some(bench)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.scratch.join(name)
    }

    fn publish(&self) {
        let bundle = self.path(&format!(
            "scaffold-{}.bundle",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        git(
            &self.path("scaffold"),
            &[
                "bundle",
                "create",
                "--quiet",
                bundle.to_str().unwrap(),
                "--all",
            ],
        );
        let answer = raw(
            "PUT",
            &format!("{}/v1/apps/todo", self.url),
            Some(&format!("Bearer {FACTORY}")),
            &fs::read(bundle).unwrap(),
        );
        assert_eq!(answer.status, 200, "{}", answer.text());
    }

    fn factory(&self, method: &str, path: &str, body: Value) -> Value {
        let answer = raw(
            method,
            &format!("{}{path}", self.url),
            Some(&format!("Bearer {FACTORY}")),
            body.to_string().as_bytes(),
        );
        assert_eq!(answer.status, 200, "{path}: {}", answer.text());
        answer.json()
    }

    fn agent(&self, method: &str, path: &str, token: &str, body: Value) -> Answer {
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        raw(
            method,
            &format!("{}{path}", self.url),
            Some(&format!("Bearer {token}")),
            &bytes,
        )
    }

    fn instance(&mut self) -> String {
        let created = self.factory(
            "POST",
            "/v1/instances",
            json!({ "app": "todo", "version": "v1" }),
        );
        let instance = created["instance"].as_str().unwrap().to_owned();
        self.instances.push(instance.clone());
        instance
    }

    fn token(&self, instance: &str, can: &[&str]) -> String {
        let session = self.factory(
            "POST",
            &format!("/v1/instances/{instance}/sessions"),
            json!({ "can": can }),
        );
        session["token"].as_str().unwrap().to_owned()
    }

    fn remote(&self, instance: &str) -> String {
        format!("{}/v1/instances/{instance}/git", self.url)
    }

    /// 레이어 안의 인스턴스 저장소.
    fn repository(&self, instance: &str) -> PathBuf {
        self.path("home")
            .join("sources")
            .join(format!("{instance}.git"))
    }

    /// 레이어 안의 `main` 의 끝.
    fn head(&self, instance: &str) -> String {
        git(
            &self.repository(instance),
            &["rev-parse", "refs/heads/main"],
        )
    }

    /// 토큰으로 받아 작업 폴더를 만든다.
    fn clone(&self, instance: &str, token: &str, name: &str) -> PathBuf {
        let work = self.path(name);
        ok(bearer_git(
            &self.scratch,
            token,
            &[
                "clone",
                "--quiet",
                &self.remote(instance),
                work.to_str().unwrap(),
            ],
        ));
        work
    }

    /// 작업 폴더의 `main` 을 묶음으로 만든다.
    fn bundle_of(&self, work: &Path, refs: &[&str]) -> Vec<u8> {
        let file = self.path(&format!(
            "push-{}.bundle",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut args = vec!["bundle", "create", "--quiet", file.to_str().unwrap()];
        args.extend_from_slice(refs);
        git(work, &args);
        fs::read(file).unwrap()
    }

    fn post_bundle(&self, instance: &str, token: &str, bundle: &[u8]) -> Answer {
        raw(
            "POST",
            &format!("{}/v1/instances/{instance}/source", self.url),
            Some(&format!("Bearer {token}")),
            bundle,
        )
    }

    /// 레이어 저장소의 객체 파일들. 받지 않은 것이 아무것도 남기지 않았는지 견준다.
    fn objects(&self, instance: &str) -> Vec<String> {
        let mut found = Vec::new();
        let repository = self.repository(instance);
        let mut stack = vec![repository.clone()];
        while let Some(folder) = stack.pop() {
            for entry in fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                let relative = path
                    .strip_prefix(&repository)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                if path.is_dir() {
                    stack.push(path);
                } else if relative.starts_with("objects") || relative.starts_with("orbital-") {
                    found.push(relative);
                }
            }
        }
        found.sort();
        found
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for instance in &self.instances {
            let _ = raw(
                "DELETE",
                &format!("{}/v1/instances/{instance}", self.url),
                Some(&format!("Bearer {FACTORY}")),
                &[],
            );
        }
        forget_control(&self.scratch.join("home"));
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    ($limit:expr) => {
        match Bench::new($limit) {
            Some(bench) => bench,
            None => {
                eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
                return;
            }
        }
    };
    () => {
        bench!(None)
    };
}

const WORK: [&str; 3] = ["source", "preview", "rehearse"];

fn edit(work: &Path, file: &str, text: &str, message: &str) -> String {
    fs::write(work.join(file), text).unwrap();
    git(work, &["add", "-A"]);
    git(work, &["commit", "--quiet", "-m", message]);
    git(work, &["rev-parse", "HEAD"])
}

#[test]
fn 토큰으로_git_clone_하면_이력째_받는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);

    // 자격 도우미로 건넨다. git 은 처음에 401 과 Basic 의 요청을 받고, 비밀번호 자리에 토큰을 실어 다시 보낸다
    let work = bench.path("work");
    ok(helper_git(
        &bench.scratch,
        &token,
        &[
            "clone",
            "--quiet",
            &bench.remote(&instance),
            work.to_str().unwrap(),
        ],
    ));
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), bench.head(&instance));
    assert_eq!(git(&work, &["log", "--format=%s"]), "스캐폴드 v1");
    assert!(work.join("server.js").is_file());
    // 원격의 주소에 토큰이 남지 않았다
    let config = fs::read_to_string(work.join(".git/config")).unwrap();
    assert!(!config.contains(&token), "{config}");

    // 다른 작업 폴더가 올린 것을 fetch 로 이어 받는다
    let other = bench.clone(&instance, &token, "other");
    let pushed = edit(&other, "NOTES.md", "메모\n", "메모를 더한다");
    ok(bearer_git(
        &other,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    ok(bearer_git(&work, &token, &["pull", "--quiet", "--ff-only"]));
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), pushed);
    assert_eq!(
        git(&work, &["log", "--format=%s"]),
        "메모를 더한다\n스캐폴드 v1"
    );
}

#[test]
fn 토큰으로_git_push_하면_프리뷰가_그_commit_으로_선다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let work = bench.clone(&instance, &token, "work");
    let source = fs::read_to_string(work.join("server.js")).unwrap();
    let pushed = edit(
        &work,
        "server.js",
        &source.replace("version: 1", "version: 2"),
        "버전을 올린다",
    );
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    assert_eq!(bench.head(&instance), pushed);

    // 프리뷰는 레이어의 main 에서 선다
    let preview = bench.agent(
        "POST",
        &format!("/v1/instances/{instance}/previews"),
        &token,
        Value::Null,
    );
    assert_eq!(preview.status, 200, "{}", preview.text());
    let report = preview.json();
    assert_eq!(report["commit"], json!(pushed));
    assert_eq!(report["blockers"], json!([]));
    assert!(
        report["changes"][0]
            .as_str()
            .unwrap()
            .contains("자기 행을 읽을 수 있게 됩니다")
    );
    let address = report["services"][0]["url"].as_str().unwrap().to_owned();
    let health: Value = ureq::get(&format!("{address}/health"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(health["version"], 2);

    // 씨앗 사용자로 들어가 본다. 받은 값을 Cookie 머리말에 그대로 붙인다
    let identity = bench.agent(
        "POST",
        &format!("/v1/instances/{instance}/previews/identities"),
        &token,
        json!({ "user": "u1" }),
    );
    assert_eq!(identity.status, 200, "{}", identity.text());
    let cards: Value = ureq::get(&format!("{address}/cards"))
        .set("Cookie", identity.json()["cookie"].as_str().unwrap())
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(cards.as_array().unwrap().len(), 2);

    // 프리뷰의 로그를 본다. 빌드와 서버의 것이다
    let logs = bench.agent(
        "GET",
        &format!("/v1/instances/{instance}/previews/logs"),
        &token,
        Value::Null,
    );
    assert_eq!(logs.status, 200, "{}", logs.text());
    let logs = logs.json();
    assert_eq!(logs["release"], report["release"]);
    let names: Vec<&str> = logs["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| log["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["build-web", "preview-web"]);

    // 리허설과 승격의 요청까지가 토큰의 일이다
    let release = report["release"].as_str().unwrap();
    let rehearsal = bench.agent(
        "POST",
        &format!("/v1/instances/{instance}/rehearsals"),
        &token,
        json!({ "release": release }),
    );
    assert_eq!(rehearsal.status, 200, "{}", rehearsal.text());
    assert_eq!(rehearsal.json()["needed"], json!(false));
    let requested = bench.agent(
        "POST",
        &format!("/v1/instances/{instance}/promotion-requests"),
        &token,
        json!({ "release": release }),
    );
    assert_eq!(requested.status, 200, "{}", requested.text());
    let pending = bench.factory(
        "GET",
        &format!("/v1/instances/{instance}/promotion-request"),
        Value::Null,
    );
    assert_eq!(pending["commit"], json!(pushed));
}

#[test]
fn git_으로_올린_것과_묶음으로_올린_것은_같은_규칙을_지난다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let work = bench.clone(&instance, &token, "work");
    let other = bench.clone(&instance, &token, "other");

    // 받는 것: git 으로 올린 뒤 묶음으로 잇고, 다시 git 으로 잇는다
    let first = edit(&work, "A.md", "가\n", "가");
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    let second = edit(&work, "B.md", "나\n", "나");
    let answer = bench.post_bundle(&instance, &token, &bench.bundle_of(&work, &["main"]));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.json()["commit"], json!(second));
    let third = edit(&work, "C.md", "다\n", "다");
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    assert_eq!(bench.head(&instance), third);
    assert_ne!(first, third);

    // 받지 않는 것: 이력을 잇지 않는 commit. 두 길이 같은 문장으로 거절한다
    edit(&other, "D.md", "라\n", "받지 않고 고쳤다");
    let by_git = refused(bearer_git(
        &other,
        &token,
        &["push", "--force", "origin", "main"],
    ));
    let by_bundle = bench.post_bundle(&instance, &token, &bench.bundle_of(&other, &["main"]));
    assert_eq!(by_bundle.status, 422);
    let sentence = by_bundle.json()["details"][0].as_str().unwrap().to_owned();
    assert!(sentence.contains("받아 합친 뒤"), "{sentence}");
    assert!(by_git.contains(&sentence), "{by_git}");

    // 받지 않는 것: main 이 아닌 ref
    git(&other, &["checkout", "--quiet", "-b", "feature"]);
    let by_git = refused(bearer_git(&other, &token, &["push", "origin", "feature"]));
    let by_bundle = bench.post_bundle(&instance, &token, &bench.bundle_of(&other, &["feature"]));
    assert_eq!(by_bundle.status, 422);
    let sentence = by_bundle.json()["details"][0].as_str().unwrap().to_owned();
    assert!(sentence.contains("`main` 브랜치 하나만"), "{sentence}");
    assert!(by_git.contains(&sentence), "{by_git}");

    assert_eq!(bench.head(&instance), third);
}

#[test]
fn main_이_아닌_ref_와_뒤로_가는_올리기는_받지_않고_무엇을_고칠지_알려_준다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let work = bench.clone(&instance, &token, "work");
    let pushed = edit(&work, "A.md", "가\n", "가");
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    let before = bench.objects(&instance);

    // 다른 브랜치와 태그
    let stderr = refused(bearer_git(
        &work,
        &token,
        &["push", "origin", "main:refs/heads/feature"],
    ));
    assert!(stderr.contains("`main` 브랜치 하나만"), "{stderr}");
    git(&work, &["tag", "v9"]);
    let stderr = refused(bearer_git(&work, &token, &["push", "origin", "v9"]));
    assert!(stderr.contains("`main` 브랜치 하나만"), "{stderr}");
    // main 을 지우기. 레이어가 지우기를 알리지 않으므로 git 이 보내기 전에 멈춘다(문장은 core 의 판정에 있다)
    let stderr = refused(bearer_git(&work, &token, &["push", "origin", ":main"]));
    assert!(stderr.contains("rejected"), "{stderr}");
    // 뒤로 가기(앞의 commit 으로 되감아 억지로 올린다)
    git(&work, &["reset", "--quiet", "--hard", "HEAD~1"]);
    let stderr = refused(bearer_git(
        &work,
        &token,
        &["push", "--force", "origin", "main"],
    ));
    assert!(stderr.contains("받아 합친 뒤"), "{stderr}");
    assert_eq!(bench.head(&instance), pushed);
    assert_eq!(bench.objects(&instance), before);

    // 받아 합친 뒤에는 오른다
    edit(&work, "B.md", "나\n", "나");
    let stderr = refused(bearer_git(&work, &token, &["push", "origin", "main"]));
    assert!(stderr.contains("rejected"), "{stderr}");
    ok(bearer_git(
        &work,
        &token,
        &[
            "pull",
            "--quiet",
            "--no-rebase",
            "--no-edit",
            "origin",
            "main",
        ],
    ));
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    assert_eq!(bench.head(&instance), git(&work, &["rev-parse", "HEAD"]));
}

#[test]
fn 토큰_없이는_git_이_닿지_못하고_다른_인스턴스의_토큰도_닿지_못한다() {
    let mut bench = bench!();
    let mine = bench.instance();
    let theirs = bench.instance();
    let token = bench.token(&mine, &WORK);

    for service in ["git-upload-pack", "git-receive-pack"] {
        let refs = format!("{}/info/refs?service={service}", bench.remote(&mine));
        // 자격이 없으면 401 과 Basic 의 요청. git 은 이것을 보고 자격 도우미를 부른다
        let answer = raw("GET", &refs, None, &[]);
        assert_eq!(answer.status, 401, "{}", answer.text());
        assert!(
            answer
                .challenge
                .as_deref()
                .unwrap_or_default()
                .starts_with("Basic"),
            "{:?}",
            answer.challenge
        );
        // 지어낸 토큰도 같다
        assert_eq!(
            raw("GET", &refs, Some("Bearer orb1.made.up"), &[]).status,
            401
        );
        assert_eq!(
            raw("GET", &refs, Some(&basic("x", "orb1.made.up")), &[]).status,
            401
        );
        // 다른 인스턴스는 없는 것과 같은 답이다
        let elsewhere = format!("{}/info/refs?service={service}", bench.remote(&theirs));
        for authorization in [format!("Bearer {token}"), basic("agent", &token)] {
            let answer = raw("GET", &elsewhere, Some(&authorization), &[]);
            assert_eq!(answer.status, 404, "{}", answer.text());
            assert_eq!(answer.json()["error"], json!("not_found"));
        }
        let nowhere = format!(
            "{}/info/refs?service={service}",
            bench.remote("i0000000000")
        );
        assert_eq!(
            raw("GET", &nowhere, Some(&format!("Bearer {token}")), &[]).status,
            404
        );
        // 주고받는 길도 같다
        let exchange = format!("{}/{service}", bench.remote(&theirs));
        assert_eq!(
            raw("POST", &exchange, Some(&format!("Bearer {token}")), b"0000").status,
            404
        );
        assert_eq!(
            raw(
                "POST",
                &format!("{}/{service}", bench.remote(&mine)),
                None,
                b"0000"
            )
            .status,
            401
        );
    }

    // 실제 git 으로도 닿지 못한다
    let stderr = refused(run_git(
        &bench.scratch,
        &["clone", "--quiet", &bench.remote(&mine), "bare"],
    ));
    assert!(
        stderr.contains("Authentication failed") || stderr.contains("could not read Username"),
        "{stderr}"
    );
    refused(bearer_git(
        &bench.scratch,
        &token,
        &["clone", "--quiet", &bench.remote(&theirs), "into-theirs"],
    ));
    assert!(!bench.path("into-theirs").exists());
}

#[test]
fn 읽기만_되는_토큰으로는_올리지_못한다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let reader = bench.token(&instance, &["source_read"]);
    let work = bench.clone(&instance, &reader, "work");
    let before = bench.head(&instance);
    edit(&work, "A.md", "가\n", "가");

    let stderr = refused(bearer_git(&work, &reader, &["push", "origin", "main"]));
    assert!(stderr.contains("403"), "{stderr}");
    let answer = raw(
        "GET",
        &format!(
            "{}/info/refs?service=git-receive-pack",
            bench.remote(&instance)
        ),
        Some(&format!("Bearer {reader}")),
        &[],
    );
    assert_eq!(answer.status, 403);
    assert!(answer.json()["message"].as_str().unwrap().contains("능력"));
    // 묶음의 길도 같다
    let answer = bench.post_bundle(&instance, &reader, &bench.bundle_of(&work, &["main"]));
    assert_eq!(answer.status, 403);
    assert_eq!(bench.head(&instance), before);

    // 코드의 능력이 없는 토큰은 받지도 못한다
    let previewer = bench.token(&instance, &["preview"]);
    let stderr = refused(bearer_git(
        &bench.scratch,
        &previewer,
        &["clone", "--quiet", &bench.remote(&instance), "previewer"],
    ));
    assert!(stderr.contains("403"), "{stderr}");
}

#[test]
fn service_key_로는_git_의_길을_열지_못한다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let remote = bench.remote(&instance);
    for authorization in [format!("Bearer {FACTORY}"), basic("factory", FACTORY)] {
        for (method, path, body) in [
            ("GET", "info/refs?service=git-upload-pack", &b""[..]),
            ("GET", "info/refs?service=git-receive-pack", &b""[..]),
            ("POST", "git-upload-pack", &b"0000"[..]),
            ("POST", "git-receive-pack", &b"0000"[..]),
        ] {
            let answer = raw(
                method,
                &format!("{remote}/{path}"),
                Some(&authorization),
                body,
            );
            assert_eq!(answer.status, 403, "{path}: {}", answer.text());
            assert!(
                answer.json()["message"].as_str().unwrap().contains("작업"),
                "{}",
                answer.text()
            );
        }
    }
    refused(bearer_git(
        &bench.scratch,
        FACTORY,
        &["clone", "--quiet", &remote, "by-key"],
    ));
}

#[test]
fn 만료된_토큰은_진행_중인_git_요청도_거절한다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let remote = bench.remote(&instance);
    let bearer = format!("Bearer {token}");

    // 받기를 시작한다: 광고를 받는다
    let advertised = raw(
        "GET",
        &format!("{remote}/info/refs?service=git-upload-pack"),
        Some(&bearer),
        &[],
    );
    assert_eq!(advertised.status, 200);
    assert_eq!(
        advertised.content_type,
        "application/x-git-upload-pack-advertisement"
    );
    let head = bench.head(&instance);
    assert!(advertised.text().contains(&head));
    let mut want = pkt(&format!("want {head} ofs-delta\n"));
    want.extend_from_slice(b"0000");
    want.extend(pkt("done\n"));
    let fetched = raw(
        "POST",
        &format!("{remote}/git-upload-pack"),
        Some(&bearer),
        &want,
    );
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.content_type, "application/x-git-upload-pack-result");

    // 그사이 토큰이 만료된다. 이어지는 요청은 처음부터 다시 받지 않는다
    bench.ahead.store(2 * 60 * 60, Ordering::SeqCst);
    let fetched = raw(
        "POST",
        &format!("{remote}/git-upload-pack"),
        Some(&bearer),
        &want,
    );
    assert_eq!(fetched.status, 401, "{}", fetched.text());
    let advertised = raw(
        "GET",
        &format!("{remote}/info/refs?service=git-upload-pack"),
        Some(&bearer),
        &[],
    );
    assert_eq!(advertised.status, 401);
    refused(bearer_git(
        &bench.scratch,
        &token,
        &["clone", "--quiet", &remote, "late"],
    ));
    // 만료 직전까지는 받는다
    bench.ahead.store(2 * 60 * 60 - 120, Ordering::SeqCst);
    assert_eq!(
        raw(
            "POST",
            &format!("{remote}/git-upload-pack"),
            Some(&bearer),
            &want
        )
        .status,
        200
    );
}

#[test]
fn 받기의_답은_다_만들기_전에_흘려_보내고_git_의_것이_아닌_content_type_의_요청은_받지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let remote = bench.remote(&instance);
    let head = bench.head(&instance);
    let mut want = pkt(&format!("want {head}\n"));
    want.extend_from_slice(b"0000");
    want.extend(pkt("done\n"));
    let post = |service: &str, content_type: Option<&str>, body: &[u8]| {
        let mut request = ureq::post(&format!("{remote}/{service}"))
            .set("Authorization", &format!("Bearer {token}"));
        if let Some(content_type) = content_type {
            request = request.set("Content-Type", content_type);
        }
        match request.send_bytes(body) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("{error}"),
        }
    };

    // pack 은 길이를 미리 적지 않고 조각으로 흘려 보낸다
    let streamed = post(
        "git-upload-pack",
        Some("application/x-git-upload-pack-request"),
        &want,
    );
    assert_eq!(streamed.status(), 200);
    assert_eq!(streamed.header("transfer-encoding"), Some("chunked"));
    assert_eq!(streamed.header("content-length"), None);
    let mut body = Vec::new();
    streamed.into_reader().read_to_end(&mut body).unwrap();
    assert!(body.windows(4).any(|window| window == b"PACK"));

    // 틀린 받기 요청은 흘려 보내기 전에 거절한다
    let broken = post(
        "git-upload-pack",
        Some("application/x-git-upload-pack-request"),
        b"0032want 0000000000000000000000000000000000000000\n0000",
    );
    assert_eq!(broken.status(), 422);

    // 브라우저의 폼이 보낼 수 있는 것을 포함해 git 의 것이 아닌 `Content-Type` 은 받지 않는다
    for (service, content_type) in [
        ("git-upload-pack", None),
        ("git-upload-pack", Some("text/plain")),
        ("git-upload-pack", Some("application/x-www-form-urlencoded")),
        (
            "git-upload-pack",
            Some("application/x-git-receive-pack-request"),
        ),
        ("git-receive-pack", Some("multipart/form-data; boundary=x")),
        (
            "git-receive-pack",
            Some("application/x-git-upload-pack-request"),
        ),
    ] {
        let refused = post(service, content_type, &want);
        assert_eq!(refused.status(), 415, "{service} {content_type:?}");
    }
    assert_eq!(bench.head(&instance), head);
}

#[test]
fn 작업을_닫으면_그_토큰으로_도는_다음_요청부터_진행_중인_git_의_다음_왕복까지_받지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let opened = bench.factory(
        "POST",
        &format!("/v1/instances/{instance}/sessions"),
        json!({ "can": WORK }),
    );
    let token = opened["token"].as_str().unwrap().to_owned();
    let session = opened["session"].as_str().unwrap().to_owned();
    assert_eq!(session.len(), 32, "{opened}");
    assert!(!token.contains(&session));
    let other = bench.token(&instance, &WORK);
    let remote = bench.remote(&instance);
    let bearer = format!("Bearer {token}");

    // 받기를 시작한다: 광고를 받는다
    let advertised = raw(
        "GET",
        &format!("{remote}/info/refs?service=git-upload-pack"),
        Some(&bearer),
        &[],
    );
    assert_eq!(advertised.status, 200);
    let head = bench.head(&instance);
    let mut want = pkt(&format!("want {head}\n"));
    want.extend_from_slice(b"0000");
    want.extend(pkt("done\n"));

    // 그사이 팩토리가 작업을 닫는다. 이어지는 왕복과 다른 길이 모두 거절된다
    let closed = bench.factory(
        "DELETE",
        &format!("/v1/instances/{instance}/sessions/{session}"),
        Value::Null,
    );
    assert_eq!(closed, json!({ "closed": true }));
    let fetched = raw(
        "POST",
        &format!("{remote}/git-upload-pack"),
        Some(&bearer),
        &want,
    );
    assert_eq!(fetched.status, 401, "{}", fetched.text());
    let rollout = bench.agent(
        "GET",
        &format!("/v1/instances/{instance}/rollout"),
        &token,
        Value::Null,
    );
    assert_eq!(rollout.status, 401, "{}", rollout.text());
    refused(bearer_git(
        &bench.scratch,
        &token,
        &["clone", "--quiet", &remote, "closed"],
    ));
    // 같은 인스턴스의 다른 작업은 그대로 돈다
    assert_eq!(
        raw(
            "POST",
            &format!("{remote}/git-upload-pack"),
            Some(&format!("Bearer {other}")),
            &want,
        )
        .status,
        200
    );
    // 작업의 식별자 모양이 아니면 없는 것이다. 작업의 토큰으로는 닫지 못한다
    let not_found = raw(
        "DELETE",
        &format!("{}/v1/instances/{instance}/sessions/zz", bench.url),
        Some(&format!("Bearer {FACTORY}")),
        &[],
    );
    assert_eq!(not_found.status, 404);
    let by_token = bench.agent(
        "DELETE",
        &format!("/v1/instances/{instance}/sessions/{}", "ab".repeat(16)),
        &other,
        Value::Null,
    );
    assert_ne!(by_token.status, 200);
    assert_eq!(
        raw(
            "POST",
            &format!("{remote}/git-upload-pack"),
            Some(&format!("Bearer {other}")),
            &want,
        )
        .status,
        200
    );
}

#[test]
fn 레이어가_안에서_쓰는_ref_는_git_에_보이지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    // 업데이트를 받아 두면 레이어의 저장소에 팩토리의 브랜치들이 안쪽 ref 로 들어온다
    let draft = git(&bench.path("scaffold"), &["rev-parse", "draft"]);
    let rollout = bench.factory(
        "POST",
        "/v1/apps/todo/rollouts",
        json!({ "commit": git(&bench.path("scaffold"), &["rev-parse", "main"]), "change": "feature_update", "waves": [[instance]] }),
    );
    bench.factory(
        "POST",
        &format!("/v1/rollouts/{}/cancel", rollout["id"].as_str().unwrap()),
        Value::Null,
    );
    let inside = git(
        &bench.repository(&instance),
        &["for-each-ref", "--format=%(refname)"],
    );
    assert!(inside.contains("refs/orbital/base"), "{inside}");
    assert!(inside.contains("refs/orbital/app/heads/draft"), "{inside}");

    let listed = ok(bearer_git(
        &bench.scratch,
        &token,
        &["ls-remote", &bench.remote(&instance)],
    ));
    let names: Vec<&str> = listed
        .lines()
        .map(|line| line.split('\t').nth(1).unwrap())
        .collect();
    assert_eq!(names, ["HEAD", "refs/heads/main"], "{listed}");

    // 이름으로도 식별자로도 받지 못한다
    let work = bench.clone(&instance, &token, "work");
    refused(bearer_git(
        &work,
        &token,
        &["fetch", "origin", "refs/orbital/base"],
    ));
    refused(bearer_git(&work, &token, &["fetch", "origin", &draft]));
    assert!(!run_git(&work, &["cat-file", "-e", &draft]).status.success());
}

#[test]
fn 열린_rollout_의_업데이트는_git_에서_update_로_보인다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    // 팩토리가 업데이트를 올리고 rollout 을 연다
    let scaffold = bench.path("scaffold");
    let update = edit(&scaffold, "UPDATE.md", "업데이트\n", "업데이트 v2");
    bench.publish();
    let rollout = bench.factory(
        "POST",
        "/v1/apps/todo/rollouts",
        json!({ "change": "feature_update", "waves": [[instance]] }),
    );
    let id = rollout["id"].as_str().unwrap().to_owned();

    let listed = ok(bearer_git(
        &bench.scratch,
        &token,
        &["ls-remote", &bench.remote(&instance)],
    ));
    assert!(
        listed.contains(&format!("{update}\trefs/heads/update")),
        "{listed}"
    );

    // 에이전트가 받아 합쳐 git 으로 올리면 그 인스턴스는 업데이트를 적용한 것이다
    let work = bench.clone(&instance, &token, "work");
    assert_eq!(git(&work, &["rev-parse", "origin/update"]), update);
    git(&work, &["merge", "--quiet", "--no-edit", "origin/update"]);
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    let now = bench.factory("GET", &format!("/v1/rollouts/{id}"), Value::Null);
    assert_eq!(now["instances"][0]["state"], json!("applied"), "{now}");
    // 토큰으로도 자기 인스턴스의 진행을 본다
    let seen = bench.agent(
        "GET",
        &format!("/v1/instances/{instance}/rollout"),
        &token,
        Value::Null,
    );
    assert_eq!(seen.json()["state"], json!("applied"), "{}", seen.text());

    // 거두면 더는 보이지 않는다
    bench.factory("POST", &format!("/v1/rollouts/{id}/cancel"), Value::Null);
    let listed = ok(bearer_git(
        &bench.scratch,
        &token,
        &["ls-remote", &bench.remote(&instance)],
    ));
    assert!(!listed.contains("refs/heads/update"), "{listed}");
}

#[test]
fn 올리는_쪽의_훅과_설정은_레이어에서_돌지_않는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let marker = bench.path("ran");
    let script = format!("#!/bin/sh\necho \"$0\" >> {}\n", marker.display());

    // 레이어의 저장소에 훅과 설정이 놓여 있다고 해 본다
    let repository = bench.repository(&instance);
    for hook in [
        "pre-receive",
        "update",
        "post-receive",
        "post-update",
        "reference-transaction",
        "push-to-checkout",
        "pre-upload-pack",
    ] {
        let path = repository.join("hooks").join(hook);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &script).unwrap();
        Command::new("chmod").arg("+x").arg(&path).status().unwrap();
    }
    let mut config = fs::read_to_string(repository.join("config")).unwrap();
    config.push_str(&format!(
        "[core]\n\tfsmonitor = {0}\n[uploadpack]\n\tallowAnySHA1InWant = true\n\tpackObjectsHook = {0}\n",
        repository.join("hooks/post-update").display()
    ));
    fs::write(repository.join("config"), config).unwrap();

    // 올리는 쪽은 훅 · 설정 · 걸러 내는 규칙을 담은 나무를 올린다
    let work = bench.clone(&instance, &token, "work");
    for (file, text) in [
        ("hooks/post-receive", script.as_str()),
        ("hooks/pre-receive", script.as_str()),
        ("config", "[core]\n\thooksPath = hooks\n"),
        (".gitattributes", "* filter=evil\n"),
        (
            ".gitmodules",
            "[submodule \"x\"]\n\tpath = x\n\turl = ../x\n",
        ),
    ] {
        let path = work.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "훅과 설정을 담는다"]);
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    assert_eq!(bench.head(&instance), git(&work, &["rev-parse", "HEAD"]));
    // 받는 쪽에서도 돌지 않는다
    bench.clone(&instance, &token, "again");
    ok(bearer_git(&work, &token, &["fetch", "--quiet", "origin"]));
    // 올리는 쪽의 선택지(push option)는 받지 않는다
    edit(&work, "A.md", "가\n", "가");
    refused(bearer_git(
        &work,
        &token,
        &["push", "--push-option=run=1", "origin", "main"],
    ));

    assert!(
        !marker.exists(),
        "레이어에서 훅이 돌았습니다: {}",
        fs::read_to_string(&marker).unwrap_or_default()
    );
}

#[test]
fn 너무_큰_올리기와_깨진_pack_은_받지_않고_저장소는_그대로다() {
    let mut bench = bench!(Some(256 * 1024));
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let work = bench.clone(&instance, &token, "work");
    let before_head = bench.head(&instance);
    let before = bench.objects(&instance);

    // 너무 큰 올리기: 줄어들지 않는 1MB
    let mut noise = Vec::new();
    fs::File::open("/dev/urandom")
        .unwrap()
        .take(1024 * 1024)
        .read_to_end(&mut noise)
        .unwrap();
    fs::write(work.join("noise.bin"), noise).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "큰 파일"]);
    refused(bearer_git(&work, &token, &["push", "origin", "main"]));
    let bundle = bench.bundle_of(&work, &["main"]);
    assert_eq!(bench.post_bundle(&instance, &token, &bundle).status, 413);
    assert_eq!(bench.head(&instance), before_head);
    assert_eq!(bench.objects(&instance), before);

    // 깨진 pack: 진짜 pack 을 반으로 자른 것과 지어낸 것
    git(&work, &["reset", "--quiet", "--hard", "HEAD~1"]);
    let new = edit(&work, "A.md", "가\n", "가");
    let pack = Command::new("git")
        .current_dir(&work)
        .args(["pack-objects", "--stdout", "--revs", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{new}\n^{before_head}\n").as_bytes())?;
            child.wait_with_output()
        })
        .unwrap()
        .stdout;
    let commands = || {
        let mut body = pkt(&format!(
            "{before_head} {new} refs/heads/main\0report-status\n"
        ));
        body.extend_from_slice(b"0000");
        body
    };
    let url = format!("{}/git-receive-pack", bench.remote(&instance));
    let bearer = format!("Bearer {token}");
    for broken in [
        pack[..pack.len() / 2].to_vec(),
        b"PACK\0\0\0\x02\0\0\0\x09not a pack at all".to_vec(),
        Vec::new(),
    ] {
        let mut body = commands();
        body.extend(broken);
        let answer = raw("POST", &url, Some(&bearer), &body);
        assert_eq!(answer.status, 200);
        assert_eq!(answer.content_type, "application/x-git-receive-pack-result");
        let text = answer.text();
        assert!(text.contains("ng refs/heads/main"), "{text}");
        assert!(text.contains("읽지 못했습니다"), "{text}");
        assert_eq!(bench.head(&instance), before_head);
        assert_eq!(bench.objects(&instance), before);
    }

    // 온전한 pack 은 받는다
    let mut body = commands();
    body.extend(pack);
    let answer = raw("POST", &url, Some(&bearer), &body);
    assert!(
        answer.text().contains("ok refs/heads/main"),
        "{}",
        answer.text()
    );
    assert_eq!(bench.head(&instance), new);
}

// ---- 줄인(gzip) 요청 ----

/// 명령 한 번의 머리말로 토큰을 건네고, git 이 HTTP 로 주고받은 머리를 표준 오류에 찍게 한다(`GIT_TRACE_CURL`).
fn traced_git(folder: &Path, token: &str, args: &[&str]) -> Output {
    let header = format!("http.extraHeader=Authorization: Bearer {token}");
    Command::new("git")
        .current_dir(folder)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_TRACE_CURL", "1")
        .env("GIT_TRACE_CURL_NO_DATA", "1")
        .args(["-c", header.as_str()])
        .args(args)
        .output()
        .unwrap()
}

/// `gzip` 실행 파일로 줄인다.
fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut child = Command::new("gzip")
        .args(["-c", "-9"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = bytes.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    output.stdout
}

#[test]
fn git_이_줄여_보낸_받기_요청을_풀어_받는다() {
    let mut bench = bench!();
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    // 받는 쪽에 올리지 않은 commit 이 많으면 have 가 많아져 git 이 요청을 줄여(gzip) 보낸다
    let work = bench.clone(&instance, &token, "many-haves");
    for at in 0..200 {
        edit(
            &work,
            "LOCAL.md",
            &format!("{at}\n"),
            &format!("올리지 않은 {at}"),
        );
    }
    let other = bench.clone(&instance, &token, "other");
    let pushed = edit(&other, "NEW.md", "새것\n", "새것");
    ok(bearer_git(
        &other,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));

    let fetched = traced_git(&work, &token, &["fetch", "origin"]);
    let trace = String::from_utf8_lossy(&fetched.stderr);
    assert!(fetched.status.success(), "{trace}");
    assert!(
        trace
            .to_ascii_lowercase()
            .contains("content-encoding: gzip"),
        "git 이 요청을 줄이지 않았습니다. 이 테스트는 줄인 요청을 재야 합니다"
    );
    assert_eq!(git(&work, &["rev-parse", "origin/main"]), pushed);
}

#[test]
fn 직접_줄인_받기_요청도_받고_풀린_크기가_한도를_넘는_요청은_받지_않는다() {
    let limit = 256 * 1024;
    let mut bench = bench!(Some(limit));
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let head = bench.head(&instance);
    let url = format!("{}/git-upload-pack", bench.remote(&instance));
    let post = |body: &[u8]| {
        let response = ureq::post(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Content-Type", "application/x-git-upload-pack-request")
            .set("Content-Encoding", "gzip")
            .send_bytes(body);
        let response = match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("{error}"),
        };
        let status = response.status();
        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body).unwrap();
        (status, body)
    };

    // 손으로 짠 받기 요청(want 하나, done)을 줄여 보낸다. pack 이 돌아온다
    let mut request = pkt(&format!("want {head}\n"));
    request.extend_from_slice(b"0000");
    request.extend(pkt("done\n"));
    let (status, body) = post(&gzip(&request));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(body.windows(4).any(|window| window == b"PACK"));

    // 풀면 한도(256KiB)를 넘는 요청(4MiB 의 0 을 줄인 4KiB 남짓): 끝까지 풀지 않고 거절한다
    let bomb = gzip(&vec![0u8; 4 * 1024 * 1024]);
    assert!(bomb.len() < limit / 10);
    let started = std::time::Instant::now();
    let (status, body) = post(&bomb);
    assert_eq!(status, 422, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("줄인(gzip) 요청을 풀지 못했습니다"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // 한도에 꼭 맞게 풀리는 요청은 푼다(받기 요청으로는 틀렸으니 git 의 거절이 돌아온다)
    let (_, body) = post(&gzip(&vec![b'0'; limit]));
    assert!(
        !String::from_utf8_lossy(&body).contains("줄인(gzip) 요청을 풀지 못했습니다"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    // 줄인 것이 아닌데 줄였다고 하면 받지 않는다
    let (status, _) = post(b"not gzip at all");
    assert_eq!(status, 422);
}

#[test]
fn 요청_본문은_한도까지_받고_한_바이트라도_넘으면_413_이다() {
    let limit = 256 * 1024;
    let mut bench = bench!(Some(limit));
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let url = format!("{}/v1/instances/{instance}/source", bench.url);
    let bearer = format!("Bearer {token}");
    let at_limit = raw("POST", &url, Some(&bearer), &vec![b'x'; limit]);
    assert_ne!(at_limit.status, 413, "{}", at_limit.text());
    let over = raw("POST", &url, Some(&bearer), &vec![b'x'; limit + 1]);
    assert_eq!(over.status, 413, "{}", over.text());
    assert!(over.text().contains("너무 큽니다"), "{}", over.text());
}

// ---- 큰 저장소(무거운 묶음) ----

/// 이 프로세스가 쓴 메모리의 꼭대기(KiB). 레이어가 같은 프로세스에서 돈다. git 의 하위 프로세스는 들지 않는다.
fn peak_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// 줄어들지 않는 바이트.
fn noise(bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    fs::File::open("/dev/urandom")
        .unwrap()
        .take(bytes as u64)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[test]
fn 큰_저장소를_git_으로_올리고_받으며_한도를_넘는_올리기는_까닭과_함께_거절한다() {
    if std::env::var("ORBITAL_FRAMEWORKS").is_err() {
        eprintln!(
            "무거운 묶음입니다. ORBITAL_FRAMEWORKS=1 로 돕니다(npm run test:frameworks). 건너뜁니다"
        );
        return;
    }
    let limit = 48 * 1024 * 1024;
    let mut bench = bench!(Some(limit));
    let instance = bench.instance();
    let token = bench.token(&instance, &WORK);
    let work = bench.clone(&instance, &token, "big");
    // 파일 3000 개(작은 글) + 이진 파일 20 개(1MiB 씩)를 commit 셋에 나눠 쌓는다: 이력 약 20MiB 의 줄어들지 않는 것
    for round in 0..3 {
        for at in 0..1000 {
            let folder = work.join(format!("src/{round}/{}", at % 50));
            fs::create_dir_all(&folder).unwrap();
            fs::write(
                folder.join(format!("file-{at}.txt")),
                format!("{round}-{at}\n").repeat(40),
            )
            .unwrap();
        }
        for at in 0..7 {
            fs::write(
                work.join(format!("blob-{round}-{at}.bin")),
                noise(1024 * 1024),
            )
            .unwrap();
        }
        git(&work, &["add", "-A"]);
        git(
            &work,
            &["commit", "--quiet", "-m", &format!("큰 commit {round}")],
        );
    }
    let size = Command::new("git")
        .current_dir(&work)
        .args(["count-objects", "-vH"])
        .output()
        .unwrap();
    eprintln!(
        "잰 것: 큰 저장소 {}",
        String::from_utf8_lossy(&size.stdout).replace('\n', " ")
    );
    let before = peak_kib();
    let started = std::time::Instant::now();
    ok(bearer_git(
        &work,
        &token,
        &["push", "--quiet", "origin", "main"],
    ));
    let pushed = started.elapsed();
    let after_push = peak_kib();
    let started = std::time::Instant::now();
    let copy = bench.clone(&instance, &token, "big-copy");
    let cloned = started.elapsed();
    let after_clone = peak_kib();
    assert_eq!(
        git(&copy, &["rev-parse", "HEAD"]),
        git(&work, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git(&copy, &["ls-files"]).lines().count(),
        git(&work, &["ls-files"]).lines().count()
    );
    eprintln!(
        "잰 것: 큰 저장소 올리기 {:.1}초 · 받기 {:.1}초, 이 프로세스(레이어)의 메모리 꼭대기 {} → {}(올린 뒤) → {}(받은 뒤) MiB",
        pushed.as_secs_f64(),
        cloned.as_secs_f64(),
        before / 1024,
        after_push / 1024,
        after_clone / 1024
    );

    // 한도(48MiB)를 넘는 올리기: 줄어들지 않는 60MiB. git 이 무엇을 보는지 적는다
    let head = bench.head(&instance);
    fs::write(work.join("huge.bin"), noise(60 * 1024 * 1024)).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "한도를 넘는 것"]);
    let started = std::time::Instant::now();
    let refused = refused(bearer_git(&work, &token, &["push", "origin", "main"]));
    eprintln!(
        "잰 것: 한도를 넘는 올리기는 {:.1}초 만에 거절, git 이 보인 것: {}",
        started.elapsed().as_secs_f64(),
        refused.trim().replace('\n', " / ")
    );
    assert!(refused.contains("413"), "{refused}");
    assert_eq!(bench.head(&instance), head);
}
