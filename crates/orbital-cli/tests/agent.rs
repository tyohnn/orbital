//! 에이전트가 sandbox 에서 하듯이 `orbital` 을 돌린다. 실제 실행 파일을, 실제 HTTP 로 듣는 관리 서버에 붙인다.
//!
//! `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. `scripts/pg-local.sh` 가 띄우고 주소를 찍는다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use orbital_run::LocalRunner;
use orbital_server::http::serve;
use orbital_server::layer::{Layer, Options};
use serde_json::{Value, json};

const FACTORY: &str = "sk_test_factory";

fn git(folder: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(folder)
        .args([
            "-c",
            "user.name=agent",
            "-c",
            "user.email=agent@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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

/// 팩토리의 서버가 하듯이 service key 로 부른다.
fn factory(url: &str, method: &str, path: &str, body: &[u8]) -> Value {
    let request = ureq::request(method, &format!("{url}{path}"))
        .set("Authorization", &format!("Bearer {FACTORY}"));
    let response = if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(body)
    };
    response
        .unwrap_or_else(|error| panic!("{method} {path}: {error}"))
        .into_json()
        .unwrap()
}

struct Agent {
    url: String,
    instance: String,
    token: String,
}

impl Agent {
    /// `orbital` 을 돌린다. 에이전트의 sandbox 에는 주소 · 인스턴스 · 토큰만 있다.
    fn orbital(&self, folder: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_orbital"))
            .current_dir(folder)
            .env("ORBITAL_URL", &self.url)
            .env("ORBITAL_INSTANCE", &self.instance)
            .env("ORBITAL_TOKEN", &self.token)
            .args(args)
            .output()
            .unwrap()
    }

    fn ok(&self, folder: &Path, args: &[&str]) -> String {
        let output = self.orbital(folder, args);
        let (out, err) = (
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            output.status.success(),
            "orbital {args:?} 가 실패했습니다:\n{out}{err}"
        );
        out.into_owned()
    }

    fn fails(&self, folder: &Path, args: &[&str]) -> String {
        let output = self.orbital(folder, args);
        assert!(!output.status.success(), "orbital {args:?} 가 성공했습니다");
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
}

fn word_after<'a>(text: &'a str, marker: &str) -> &'a str {
    text.split(marker)
        .nth(1)
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
}

#[test]
fn 에이전트가_코드를_받아_고쳐_올리고_미리보기의_주소를_받는다() {
    let Ok(pg_url) = std::env::var("ORBITAL_PG") else {
        eprintln!("ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요");
        return;
    };
    let scratch = std::env::temp_dir().join(format!("orbital-agent-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).unwrap();

    // 관리 서버를 실제 HTTP 로 띄운다
    let layer = Layer::open(Options {
        home: scratch.join("home"),
        pg_url,
        service_keys: vec![(FACTORY.to_owned(), "factory".to_owned())],
        runner: Box::new(LocalRunner::default()),
    })
    .unwrap();
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || serve(Arc::new(layer), server));

    // 팩토리가 스캐폴드를 올리고, 고객의 인스턴스를 세우고, 에이전트의 토큰을 받는다
    let scaffold = scratch.join("scaffold");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../orbital-server/tests/fixtures/todo"),
        &scaffold,
    );
    git(&scaffold, &["init", "--quiet", "--initial-branch", "main"]);
    git(&scaffold, &["add", "-A"]);
    git(&scaffold, &["commit", "--quiet", "-m", "스캐폴드 v1"]);
    git(&scaffold, &["tag", "v1"]);
    let bundle: PathBuf = scratch.join("scaffold.bundle");
    git(
        &scaffold,
        &[
            "bundle",
            "create",
            "--quiet",
            bundle.to_str().unwrap(),
            "--all",
        ],
    );
    factory(&url, "PUT", "/v1/apps/todo", &fs::read(&bundle).unwrap());
    let created = factory(
        &url,
        "POST",
        "/v1/instances",
        json!({ "app": "todo", "version": "v1" })
            .to_string()
            .as_bytes(),
    );
    let instance = created["instance"].as_str().unwrap().to_owned();
    let session = factory(
        &url,
        "POST",
        &format!("/v1/instances/{instance}/sessions"),
        json!({ "can": ["source", "preview", "rehearse"] })
            .to_string()
            .as_bytes(),
    );
    let agent = Agent {
        url: url.clone(),
        instance: instance.clone(),
        token: session["token"].as_str().unwrap().to_owned(),
    };

    // ---- 받기 → 고치기 → 올리기 ----
    assert!(
        agent
            .ok(&scratch, &["clone", "work"])
            .contains("코드를 받았습니다")
    );
    let work = scratch.join("work");
    let server_js = fs::read_to_string(work.join("server.js")).unwrap();
    fs::write(
        work.join("server.js"),
        server_js.replace("version: 1", "version: 2"),
    )
    .unwrap();
    git(&work, &["commit", "--quiet", "-am", "버전을 올린다"]);
    let pushed = agent.ok(&work, &["push"]);
    assert!(pushed.contains("올렸습니다"));
    assert_eq!(
        word_after(&pushed, "commit "),
        git(&work, &["rev-parse", "HEAD"])
    );

    // ---- 미리보기: 명령 한 번으로 주소가 돌아온다 ----
    let preview = agent.ok(&work, &["preview"]);
    assert!(preview.contains("미리보기가 섰습니다"), "{preview}");
    assert!(
        preview.contains("자기 행을 읽을 수 있게 됩니다"),
        "{preview}"
    );
    assert!(preview.contains("막는 것이 없습니다"), "{preview}");
    let address = word_after(&preview, "web → ");
    let health: Value = ureq::get(&format!("{address}/health"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(health["version"], 2);

    // 씨앗 데이터의 사람으로 요청해 본다
    let identity = agent.ok(&work, &["identity", "u1"]);
    let cards: Value = ureq::get(&format!("{address}/cards"))
        .set("x-orbital-identity", identity.trim())
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(cards.as_array().unwrap().len(), 2);

    // ---- 승격은 요청까지만 ----
    let release = word_after(&preview, "release ");
    assert!(
        agent
            .ok(&work, &["request-promotion", release])
            .contains("승격을 요청했습니다")
    );
    assert!(
        agent
            .ok(&work, &["rehearse", release])
            .contains("예행연습이 필요 없습니다")
    );

    // ---- 다른 작업 폴더가 먼저 올렸을 때: 받아 합친 뒤에 올린다 ----
    agent.ok(&scratch, &["clone", "other"]);
    let other = scratch.join("other");
    fs::write(other.join("NOTES.md"), "먼저 올린 메모\n").unwrap();
    git(&other, &["add", "-A"]);
    git(&other, &["commit", "--quiet", "-m", "메모를 더한다"]);
    agent.ok(&other, &["push"]);
    fs::write(work.join("README.md"), "받지 않고 고쳤다\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "읽어 보기를 더한다"]);
    assert!(agent.fails(&work, &["push"]).contains("orbital pull"));
    let pulling = Command::new(env!("CARGO_BIN_EXE_orbital"))
        .current_dir(&work)
        .env("ORBITAL_URL", &agent.url)
        .env("ORBITAL_INSTANCE", &agent.instance)
        .env("ORBITAL_TOKEN", &agent.token)
        .envs([
            ("GIT_AUTHOR_NAME", "agent"),
            ("GIT_AUTHOR_EMAIL", "agent@example.invalid"),
        ])
        .envs([
            ("GIT_COMMITTER_NAME", "agent"),
            ("GIT_COMMITTER_EMAIL", "agent@example.invalid"),
        ])
        .arg("pull")
        .output()
        .unwrap();
    assert!(
        pulling.status.success(),
        "{}",
        String::from_utf8_lossy(&pulling.stderr)
    );
    assert!(work.join("NOTES.md").is_file());
    assert!(agent.ok(&work, &["push"]).contains("올렸습니다"));

    // ---- 범위 밖 ----
    // 다른 인스턴스는 없는 것으로 보인다
    let stranger = Agent {
        url: url.clone(),
        instance: "i0000000000".to_owned(),
        token: agent.token.clone(),
    };
    assert!(stranger.fails(&work, &["preview"]).contains("없습니다"));
    // 토큰이 없으면 무엇이 필요한지 알려 준다
    let bare = Command::new(env!("CARGO_BIN_EXE_orbital"))
        .current_dir(&work)
        .env_remove("ORBITAL_TOKEN")
        .arg("push")
        .output()
        .unwrap();
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("환경 변수"));

    let _ = ureq::delete(&format!("{url}/v1/instances/{instance}"))
        .set("Authorization", &format!("Bearer {FACTORY}"))
        .call();
    let _ = fs::remove_dir_all(&scratch);
}
