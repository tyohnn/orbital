//! 코드 저장소를 실제 git 으로 재는 테스트.
//!
//! 스캐폴드와 에이전트의 작업 폴더를 임시 폴더에 만들고, 묶음으로 받아 가서 고쳐 묶음으로 올린다. git 으로 주고받는 길은
//! `orbital-server` 의 `tests/git.rs` 가 실제 HTTP 로 잰다.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use orbital_core::name::InstanceId;
use orbital_source::assemble::{AssembleError, assemble, release_id};
use orbital_source::{Commit, Error, Merged, SourceStore};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 테스트 하나가 쓰는 임시 폴더. 끝나면 지운다.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orbital-source-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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

fn write(folder: &Path, file: &str, text: &str) {
    let path = folder.join(file);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn commit_all(folder: &Path, message: &str) -> Commit {
    git(folder, &["add", "-A"]);
    git(folder, &["commit", "--quiet", "-m", message]);
    Commit::parse(&git(folder, &["rev-parse", "HEAD"])).unwrap()
}

const MANIFEST: &str = r#"
[[service]]
name = "web"
kind = "server"
build = "true"
start = "node server.js"
path = "/"
roles = ["member"]

[database]
schemas = ["todo"]
migrations = "db/migrations"
roles = ["member"]
seed = "db/seed"
"#;

const ACCESS: &str = "[todo.card]\nmember = \"read write own\"\n";

/// 스캐폴드 저장소를 만들고 `v1` 태그를 단다.
fn scaffold(scratch: &Scratch) -> (PathBuf, Commit) {
    let folder = scratch.path("scaffold");
    fs::create_dir_all(&folder).unwrap();
    git(&folder, &["init", "--quiet", "--initial-branch", "main"]);
    write(&folder, "orbital.toml", MANIFEST);
    write(&folder, "db/access.toml", ACCESS);
    write(
        &folder,
        "db/migrations/001_card.sql",
        "CREATE TABLE todo.card (id int, owner text, title text);\n",
    );
    write(
        &folder,
        "db/migrations/README.md",
        "마이그레이션은 이름 순서로 돈다\n",
    );
    write(
        &folder,
        "db/seed/001_cards.sql",
        "INSERT INTO todo.card VALUES (1, 'u1', '첫 카드');\n",
    );
    write(&folder, "server.js", "// 서버\n");
    let commit = commit_all(&folder, "스캐폴드 v1");
    git(&folder, &["tag", "v1"]);
    (folder, commit)
}

fn instance(text: &str) -> InstanceId {
    InstanceId::parse(text).unwrap()
}

/// 인스턴스를 세우고, 에이전트가 하듯이 묶음으로 받아 작업 폴더를 만든다.
fn setup(scratch: &Scratch) -> (SourceStore, InstanceId, PathBuf, Commit) {
    let (scaffold, base) = scaffold(scratch);
    let store = SourceStore::new(scratch.path("sources"));
    let id = instance("k3f9x2ab");
    store.create(&id, &scaffold, "v1").unwrap();
    let work = clone(scratch, &store, &id, "work");
    (store, id, work, base)
}

fn clone(scratch: &Scratch, store: &SourceStore, id: &InstanceId, name: &str) -> PathBuf {
    let bundle = scratch.path(&format!("{name}.bundle"));
    fs::write(&bundle, store.bundle(id).unwrap()).unwrap();
    let work = scratch.path(name);
    git(
        &scratch.0,
        &[
            "clone",
            "--quiet",
            bundle.to_str().unwrap(),
            work.to_str().unwrap(),
        ],
    );
    work
}

/// 작업 폴더의 `main` 을 묶음으로 만든다.
fn bundle_of(scratch: &Scratch, work: &Path) -> Vec<u8> {
    let file = scratch.path(&format!(
        "push-{}.bundle",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    git(
        work,
        &[
            "bundle",
            "create",
            "--quiet",
            file.to_str().unwrap(),
            "main",
        ],
    );
    fs::read(file).unwrap()
}

#[test]
fn 인스턴스의_저장소는_스캐폴드의_한_버전에서_갈라지고_그_기준점을_기억한다() {
    let scratch = Scratch::new();
    let (store, id, _, base) = setup(&scratch);
    assert_eq!(store.head(&id).unwrap(), base);
    assert_eq!(store.base(&id).unwrap(), base);
}

#[test]
fn 스캐폴드에_없는_버전에서는_세우지_못하고_저장소도_남지_않는다() {
    let scratch = Scratch::new();
    let (scaffold, _) = scaffold(&scratch);
    let store = SourceStore::new(scratch.path("sources"));
    let id = instance("k3f9x2ab");
    assert!(matches!(
        store.create(&id, &scaffold, "v99"),
        Err(Error::NoSuchVersion)
    ));
    assert!(matches!(store.head(&id), Err(Error::NoSuchInstance)));
    // 같은 식별자로 다시 세울 수 있다
    assert!(store.create(&id, &scaffold, "v1").is_ok());
}

#[test]
fn 같은_인스턴스의_저장소를_두_번_세우지_못한다() {
    let scratch = Scratch::new();
    let (store, id, _, _) = setup(&scratch);
    let (scaffold, _) = (scratch.path("scaffold"), ());
    assert!(matches!(
        store.create(&id, &scaffold, "v1"),
        Err(Error::AlreadyExists)
    ));
}

#[test]
fn 묶음으로_받아_고친_commit_을_올리면_main_이_그_commit_이_된다() {
    let scratch = Scratch::new();
    let (store, id, work, base) = setup(&scratch);
    write(&work, "server.js", "// 반차를 더했다\n");
    let pushed = commit_all(&work, "연차 신청에 반차를 넣는다");
    assert_eq!(
        store.receive(&id, &bundle_of(&scratch, &work)).unwrap(),
        pushed
    );
    assert_eq!(store.head(&id).unwrap(), pushed);
    // 갈라진 기준점은 그대로다
    assert_eq!(store.base(&id).unwrap(), base);
}

#[test]
fn main_의_이력을_잇지_않는_묶음은_받지_않고_main_은_그대로다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    // 다른 작업 폴더가 먼저 올린다
    let other = clone(&scratch, &store, &id, "other");
    write(&other, "server.js", "// 먼저 올린 변경\n");
    let first = commit_all(&other, "먼저 올린 변경");
    store.receive(&id, &bundle_of(&scratch, &other)).unwrap();
    // 받지 않고 고친 쪽이 올린다
    write(&work, "server.js", "// 받지 않고 고친 변경\n");
    commit_all(&work, "받지 않고 고친 변경");
    assert!(matches!(
        store.receive(&id, &bundle_of(&scratch, &work)),
        Err(Error::NotFastForward)
    ));
    assert_eq!(store.head(&id).unwrap(), first);
}

#[test]
fn 깨진_묶음은_받지_않고_main_은_그대로다() {
    let scratch = Scratch::new();
    let (store, id, work, base) = setup(&scratch);
    write(&work, "server.js", "// 변경\n");
    commit_all(&work, "변경");
    let mut bundle = bundle_of(&scratch, &work);
    let middle = bundle.len() / 2;
    bundle.truncate(middle);
    assert!(matches!(store.receive(&id, &bundle), Err(Error::BadBundle)));
    assert!(matches!(
        store.receive(&id, b"this is not a bundle"),
        Err(Error::BadBundle)
    ));
    assert_eq!(store.head(&id).unwrap(), base);
}

#[test]
fn commit_하나의_파일을_읽고_없는_파일은_없다고_답한다() {
    let scratch = Scratch::new();
    let (store, id, work, base) = setup(&scratch);
    write(&work, "server.js", "// 새 내용\n");
    let pushed = commit_all(&work, "변경");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    assert_eq!(
        store.read(&id, &pushed, "server.js").unwrap().unwrap(),
        "// 새 내용\n".as_bytes()
    );
    // 앞의 commit 은 앞의 내용을 그대로 갖는다
    assert_eq!(
        store.read(&id, &base, "server.js").unwrap().unwrap(),
        "// 서버\n".as_bytes()
    );
    assert_eq!(store.read(&id, &pushed, "missing.txt").unwrap(), None);
    assert!(matches!(
        store.read(&id, &pushed, "../etc/passwd"),
        Err(Error::BadPath)
    ));
}

#[test]
fn 이_저장소의_main_에_없는_commit_으로는_읽지_못한다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    // 올리지 않은 commit
    write(&work, "server.js", "// 올리지 않았다\n");
    let local = commit_all(&work, "올리지 않은 변경");
    assert!(!store.contains(&id, &local).unwrap());
    assert!(matches!(
        store.read(&id, &local, "server.js"),
        Err(Error::NoSuchCommit)
    ));
    assert!(matches!(
        store.export(&id, &local, &scratch.path("out")),
        Err(Error::NoSuchCommit)
    ));
}

#[test]
fn 폴더의_파일_이름을_순서대로_돌려주고_없는_폴더는_비어_있다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    write(
        &work,
        "db/migrations/010_due.sql",
        "ALTER TABLE todo.card ADD COLUMN due date;\n",
    );
    write(
        &work,
        "db/migrations/002_done.sql",
        "ALTER TABLE todo.card ADD COLUMN done boolean;\n",
    );
    let pushed = commit_all(&work, "마이그레이션 둘");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    assert_eq!(
        store.list(&id, &pushed, "db/migrations").unwrap(),
        vec!["001_card.sql", "002_done.sql", "010_due.sql", "README.md"]
    );
    assert_eq!(
        store.list(&id, &pushed, "db/nothing").unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn commit_의_나무를_폴더로_꺼낸다() {
    let scratch = Scratch::new();
    let (store, id, _, base) = setup(&scratch);
    let out = scratch.path("out");
    store.export(&id, &base, &out).unwrap();
    assert_eq!(
        fs::read_to_string(out.join("orbital.toml")).unwrap(),
        MANIFEST
    );
    assert!(out.join("db/migrations/001_card.sql").is_file());
    // 이력은 꺼내지 않는다
    assert!(!out.join(".git").exists());
}

#[test]
fn 인스턴스마다_저장소가_따로이고_남의_commit_은_제_것이_아니다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    let other = instance("zzzzzzzz");
    store
        .create(&other, &scratch.path("scaffold"), "v1")
        .unwrap();
    write(&work, "server.js", "// 이 고객만의 변경\n");
    let pushed = commit_all(&work, "이 고객만의 변경");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    assert!(store.contains(&id, &pushed).unwrap());
    assert!(!store.contains(&other, &pushed).unwrap());
    assert_ne!(store.head(&other).unwrap(), pushed);
}

#[test]
fn 저장소를_지우면_없는_인스턴스가_된다() {
    let scratch = Scratch::new();
    let (store, id, _, _) = setup(&scratch);
    store.destroy(&id).unwrap();
    assert!(matches!(store.head(&id), Err(Error::NoSuchInstance)));
    assert!(matches!(store.bundle(&id), Err(Error::NoSuchInstance)));
}

// ---- commit 에서 release 의 재료 읽기 ----

#[test]
fn commit_하나에서_선언과_권한_표와_마이그레이션과_씨앗을_읽는다() {
    let scratch = Scratch::new();
    let (store, id, _, base) = setup(&scratch);
    let assembled = assemble(&store, &id, &base).unwrap();
    assert_eq!(assembled.manifest.get().services.len(), 1);
    assert_eq!(assembled.access.tables.len(), 1);
    // .sql 이 아닌 파일은 마이그레이션이 아니다
    assert_eq!(
        assembled
            .migrations
            .iter()
            .map(|script| script.name.as_str())
            .collect::<Vec<_>>(),
        vec!["001_card.sql"]
    );
    assert!(
        assembled.migrations[0]
            .sql
            .starts_with("CREATE TABLE todo.card")
    );
    assert_eq!(assembled.seed.len(), 1);
    assert_eq!(assembled.commit, base);
}

#[test]
fn 마이그레이션은_이름_순서로_읽는다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    write(
        &work,
        "db/migrations/010_due.sql",
        "ALTER TABLE todo.card ADD COLUMN due date;\n",
    );
    write(
        &work,
        "db/migrations/002_done.sql",
        "ALTER TABLE todo.card ADD COLUMN done boolean;\n",
    );
    let pushed = commit_all(&work, "마이그레이션 둘");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let names: Vec<String> = assemble(&store, &id, &pushed)
        .unwrap()
        .migrations
        .into_iter()
        .map(|script| script.name)
        .collect();
    assert_eq!(names, vec!["001_card.sql", "002_done.sql", "010_due.sql"]);
}

#[test]
fn release_의_식별자는_commit_이_같으면_같고_하나라도_더해지면_달라진다() {
    let scratch = Scratch::new();
    let (store, id, work, base) = setup(&scratch);
    let first = assemble(&store, &id, &base).unwrap().release;
    assert_eq!(first, assemble(&store, &id, &base).unwrap().release);
    write(&work, "README.md", "글자 하나\n");
    let pushed = commit_all(&work, "글자 하나");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    assert_ne!(first, assemble(&store, &id, &pushed).unwrap().release);
    // 같은 commit 이라도 인스턴스가 다르면 다르다
    assert_ne!(
        release_id(&id, &base),
        release_id(&instance("zzzzzzzz"), &base)
    );
}

#[test]
fn 선언에_고칠_것이_있으면_파일_이름과_함께_모두_돌려준다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    write(
        &work,
        "orbital.toml",
        &MANIFEST
            .replace("start = \"node server.js\"\n", "")
            .replace(
                "roles = [\"member\"]\nseed",
                "roles = [\"member\", \"member\"]\nseed",
            ),
    );
    let pushed = commit_all(&work, "선언을 깨뜨린다");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let Err(AssembleError::Problems(problems)) = assemble(&store, &id, &pushed) else {
        panic!("문제가 있어야 합니다");
    };
    assert_eq!(problems.len(), 2);
    assert!(
        problems
            .iter()
            .all(|problem| problem.starts_with("`orbital.toml`: "))
    );
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("실행 명령(`start`)이 없습니다"))
    );
}

#[test]
fn 권한_표에_고칠_것이_있거나_권한_표가_없으면_어떻게_고칠지_돌려준다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    write(
        &work,
        "db/access.toml",
        "[todo.card]\nmember = \"everything\"\n",
    );
    let bad = commit_all(&work, "권한 표를 깨뜨린다");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let Err(AssembleError::Problems(problems)) = assemble(&store, &id, &bad) else {
        panic!("문제가 있어야 합니다");
    };
    assert!(
        problems[0].starts_with("`db/access.toml`: "),
        "{}",
        problems[0]
    );
    assert!(problems[0].contains("read write own"));

    fs::remove_file(work.join("db/access.toml")).unwrap();
    let missing = commit_all(&work, "권한 표를 지운다");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let Err(AssembleError::Problems(problems)) = assemble(&store, &id, &missing) else {
        panic!("문제가 있어야 합니다");
    };
    assert!(problems[0].contains("`db/access.toml` 이 없습니다"));
}

#[test]
fn 선언_파일이_없거나_읽히지_않으면_그렇다고_돌려준다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    write(&work, "orbital.toml", "this is = not [valid toml\n");
    let broken = commit_all(&work, "선언을 깨뜨린다");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let Err(AssembleError::Problems(problems)) = assemble(&store, &id, &broken) else {
        panic!("문제가 있어야 합니다");
    };
    assert!(problems[0].starts_with("`orbital.toml` 을 읽지 못했습니다"));

    fs::remove_file(work.join("orbital.toml")).unwrap();
    let gone = commit_all(&work, "선언을 지운다");
    store.receive(&id, &bundle_of(&scratch, &work)).unwrap();
    let Err(AssembleError::Problems(problems)) = assemble(&store, &id, &gone) else {
        panic!("문제가 있어야 합니다");
    };
    assert!(problems[0].contains("`orbital.toml` 이 없습니다"));
}

// ---- 줄인(gzip) 요청 풀기 ----

fn gzipped(bytes: &[u8]) -> Vec<u8> {
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
fn 줄인_요청은_풀린_크기가_한도와_같으면_풀고_한_바이트라도_넘으면_받지_않는다() {
    let limit = 64 * 1024;
    for size in [0, 1, limit - 1, limit] {
        let plain = vec![b'0'; size];
        assert_eq!(
            orbital_source::gunzip(&gzipped(&plain), limit)
                .map(|out| out.len())
                .ok(),
            Some(size),
            "{size}"
        );
    }
    assert!(matches!(
        orbital_source::gunzip(&gzipped(&vec![b'0'; limit + 1]), limit),
        Err(Error::BadBundle)
    ));
    assert!(matches!(
        orbital_source::gunzip(b"not gzip", limit),
        Err(Error::BadBundle)
    ));
}

/// 이 프로세스가 쓴 메모리의 꼭대기(KiB).
fn peak_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

#[test]
fn 풀면_커지는_요청은_한도까지만_풀고_멈춰_메모리를_한도만큼만_쓴다() {
    // gzip 은 이어 붙인 조각을 모두 푼다. 1MiB 의 0 을 줄인 조각(1KiB 남짓) 512 개 = 보내는 것 0.5MiB, 풀면 512MiB
    let piece = gzipped(&vec![0u8; 1024 * 1024]);
    let bomb: Vec<u8> = piece.repeat(512);
    assert!(bomb.len() < 1024 * 1024);
    let before = peak_kib();
    let started = std::time::Instant::now();
    assert!(matches!(
        orbital_source::gunzip(&bomb, 1024 * 1024),
        Err(Error::BadBundle)
    ));
    let grew = peak_kib().saturating_sub(before);
    assert!(grew < 64 * 1024, "풀면서 {grew} KiB 를 더 썼습니다");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

// ---- 업데이트: 받아 두기 · 합치기 · 담았는지 ----

/// 앱(위쪽)에 업데이트 commit 을 하나 더한다. `file` 을 `text` 로 쓴다.
fn upstream_commit(scaffold: &Path, file: &str, text: &str, message: &str) -> Commit {
    write(scaffold, file, text);
    commit_all(scaffold, message)
}

/// 에이전트가 하듯이 작업 폴더에서 고쳐 묶음으로 올린다.
fn push_change(
    scratch: &Scratch,
    store: &SourceStore,
    id: &InstanceId,
    work: &Path,
    file: &str,
    text: &str,
) -> Commit {
    write(work, file, text);
    let commit = commit_all(work, "포크를 고친다");
    assert_eq!(
        store.receive(id, &bundle_of(scratch, work)).unwrap(),
        commit
    );
    commit
}

#[test]
fn 받아_둔_업데이트는_묶음에_update_로_담기고_앱에_없는_commit_은_받지_않는다() {
    let scratch = Scratch::new();
    let (store, id, _, _) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    let update = upstream_commit(&scaffold, "server.js", "// 서버 v2\n", "업데이트 v2");
    // 앱에 없는 commit 은 받지 않고 묶음에도 담기지 않는다
    let stray = Commit::parse(&"ab".repeat(20)).unwrap();
    assert!(matches!(
        store.fetch_upstream(&id, &scaffold, &stray),
        Err(Error::NoSuchCommit)
    ));
    let before = clone(&scratch, &store, &id, "before");
    assert_eq!(
        git(&before, &["branch", "-r", "--list", "origin/update"]),
        ""
    );

    store.fetch_upstream(&id, &scaffold, &update).unwrap();
    let after = clone(&scratch, &store, &id, "after");
    assert_eq!(
        git(&after, &["rev-parse", "origin/update"]),
        update.as_str()
    );
    // 거두면 묶음에서 빠진다
    store.clear_update(&id).unwrap();
    let cleared = clone(&scratch, &store, &id, "cleared");
    assert_eq!(
        git(&cleared, &["branch", "-r", "--list", "origin/update"]),
        ""
    );
}

#[test]
fn 충돌_없는_업데이트는_main_위에_합쳐지고_합친_commit_의_부모는_main_과_업데이트다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    let fork = push_change(
        &scratch,
        &store,
        &id,
        &work,
        "custom.json",
        "{\"greeting\": \"A\"}\n",
    );
    let update = upstream_commit(&scaffold, "server.js", "// 서버 v2\n", "업데이트 v2");
    store.fetch_upstream(&id, &scaffold, &update).unwrap();

    let Merged::Merged(merged) = store.merge(&id, &update).unwrap() else {
        panic!("합치지 않았습니다");
    };
    assert_eq!(store.head(&id).unwrap(), merged);
    let merged_work = clone(&scratch, &store, &id, "merged");
    assert_eq!(
        git(&merged_work, &["rev-parse", "HEAD^1", "HEAD^2"]),
        format!("{fork}\n{update}")
    );
    // 포크의 손과 업데이트가 함께 있다
    assert_eq!(
        fs::read_to_string(merged_work.join("server.js")).unwrap(),
        "// 서버 v2\n"
    );
    assert_eq!(
        fs::read_to_string(merged_work.join("custom.json")).unwrap(),
        "{\"greeting\": \"A\"}\n"
    );
    assert!(store.descends(&id, &merged, &update).unwrap());
    assert!(!store.descends(&id, &fork, &update).unwrap());
}

#[test]
fn 충돌하면_main_을_건드리지_않고_충돌한_파일의_이름만_돌려준다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    let fork = push_change(
        &scratch,
        &store,
        &id,
        &work,
        "server.js",
        "// 포크의 서버\n",
    );
    let update = upstream_commit(&scaffold, "server.js", "// 서버 v2\n", "업데이트 v2");
    store.fetch_upstream(&id, &scaffold, &update).unwrap();

    assert_eq!(
        store.merge(&id, &update).unwrap(),
        Merged::Conflicts(vec!["server.js".to_owned()])
    );
    assert_eq!(store.head(&id).unwrap(), fork);
    assert!(!store.descends(&id, &fork, &update).unwrap());
}

#[test]
fn main_이_이미_업데이트를_담으면_합치지_않고_그대로_둔다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    push_change(
        &scratch,
        &store,
        &id,
        &work,
        "custom.json",
        "{\"greeting\": \"A\"}\n",
    );
    let update = upstream_commit(&scaffold, "server.js", "// 서버 v2\n", "업데이트 v2");
    store.fetch_upstream(&id, &scaffold, &update).unwrap();
    // 에이전트가 받은 저장소의 `origin/update` 를 손으로 합쳐 올렸다(앞으로 감기가 아닌 합친 commit)
    let fresh = clone(&scratch, &store, &id, "fresh");
    git(&fresh, &["merge", "--quiet", "--no-edit", "origin/update"]);
    let head = Commit::parse(&git(&fresh, &["rev-parse", "HEAD"])).unwrap();
    assert_eq!(
        store.receive(&id, &bundle_of(&scratch, &fresh)).unwrap(),
        head
    );

    assert_eq!(
        store.merge(&id, &update).unwrap(),
        Merged::Already(head.clone())
    );
    assert_eq!(store.head(&id).unwrap(), head);
    // 받지 않은 commit 으로는 합치지 않는다
    let stray = Commit::parse(&"cd".repeat(20)).unwrap();
    assert!(matches!(store.merge(&id, &stray), Err(Error::NoSuchCommit)));
}

#[test]
fn 업데이트를_받은_뒤_main_이_옮겨져도_옮겨진_main_위에_합쳐_그_commit_을_잃지_않는다() {
    let scratch = Scratch::new();
    let (store, id, work, _) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    let update = upstream_commit(&scaffold, "server.js", "// 서버 v2\n", "업데이트 v2");
    store.fetch_upstream(&id, &scaffold, &update).unwrap();
    // 받아 둔 뒤, 합치기 전에 에이전트가 main 을 옮겼다
    let moved = push_change(
        &scratch,
        &store,
        &id,
        &work,
        "custom.json",
        "{\"greeting\": \"B\"}\n",
    );

    let Merged::Merged(merged) = store.merge(&id, &update).unwrap() else {
        panic!("합치지 않았습니다");
    };
    assert!(store.descends(&id, &merged, &moved).unwrap());
    assert!(store.descends(&id, &merged, &update).unwrap());
    // 합친 뒤 에이전트가 앞의 main 에서 고친 것을 올리면 앞으로 가지 않아 받지 않는다
    write(&work, "custom.json", "{\"greeting\": \"C\"}\n");
    commit_all(&work, "합치기 전의 main 에서 고친다");
    assert!(matches!(
        store.receive(&id, &bundle_of(&scratch, &work)),
        Err(Error::NotFastForward)
    ));
    assert_eq!(store.head(&id).unwrap(), merged);
}

#[test]
fn 위쪽_commit_이_여럿이면_commit_이_담은_것_가운데_가장_새_것을_고른다() {
    let scratch = Scratch::new();
    let (store, id, work, base) = setup(&scratch);
    let scaffold = scratch.path("scaffold");
    let fork = push_change(
        &scratch,
        &store,
        &id,
        &work,
        "custom.json",
        "{\"greeting\": \"A\"}\n",
    );
    // 아무 업데이트도 담지 않은 commit 의 가장 새 위쪽은 갈라진 기준점이다
    assert_eq!(
        store.newest_upstream(&id, &fork).unwrap(),
        Some(base.clone())
    );

    // 업데이트 넷을 받아 둔다. 받아 두기만 하고 담지 않았으면 여전히 기준점이다
    let updates: Vec<Commit> = (2..6)
        .map(|version| {
            let update = upstream_commit(
                &scaffold,
                "server.js",
                &format!("// 서버 v{version}\n"),
                &format!("업데이트 v{version}"),
            );
            store.fetch_upstream(&id, &scaffold, &update).unwrap();
            update
        })
        .collect();
    assert_eq!(store.newest_upstream(&id, &fork).unwrap(), Some(base));
    // 하나씩 합칠 때마다 그 commit 이 담은 것 가운데 가장 새 것(방금 합친 것)을 고른다. 받아 둔 차례나 이름의 차례가 아니다
    let mut merged = Vec::new();
    for update in &updates {
        let Merged::Merged(commit) = store.merge(&id, update).unwrap() else {
            panic!("합치지 않았습니다");
        };
        assert_eq!(
            store.newest_upstream(&id, &commit).unwrap(),
            Some(update.clone())
        );
        merged.push(commit);
    }
    // 앞의 commit 은 여전히 그때의 위쪽을 가리킨다
    assert_eq!(
        store.newest_upstream(&id, &merged[0]).unwrap(),
        Some(updates[0].clone())
    );
    // 이 저장소에 없는 commit 은 무엇도 담지 않는다
    let stray = Commit::parse(&"ef".repeat(20)).unwrap();
    assert_eq!(store.newest_upstream(&id, &stray).unwrap(), None);
}
