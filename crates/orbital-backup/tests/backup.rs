//! 기반 백업 · WAL 보관 · 옆에 세운 클러스터로의 시점 복구 · database 하나 옮기기를 실제 PostgreSQL 로 잰다.
//!
//! 테스트마다 자기 클러스터를 따로 세운다(`initdb`, 임시 폴더, 빈 포트, WAL 보관을 켠 설정). 다른 테스트가 함께 쓰는
//! `ORBITAL_PG` 의 클러스터는 건드리지 않는다. 이 기계에 PostgreSQL 의 도구가 없을 때만 건너뛰었다고 찍고 통과한다.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use orbital_backup::{
    Cluster, DatabaseName, Load, LocalStore, RECORDS, Store, Tools, databases, dump_database,
    fingerprint, load_database, roles,
};
use orbital_core::backup::{BaseBackup, RecoveryFailure, RestoreRefusal, judge_restore, prune};
use postgres::{Client, NoTls};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 어디에 새어도 찾을 수 있게 드문 글자로 지은 행의 값.
const ROW_VALUE: &str = "row_value_Kq83vZ";

struct Bench {
    scratch: PathBuf,
    store: LocalStore,
    cluster: Option<Cluster>,
}

impl Bench {
    fn new() -> Option<Self> {
        let Ok(tools) = Tools::find() else {
            return None;
        };
        let scratch = std::env::temp_dir().join(format!(
            "obk-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = LocalStore::open(tools.clone(), scratch.join("store")).unwrap();
        let cluster = Cluster::init(&tools, &scratch.join("pg"), Some(&store.archive_command()))
            .expect("클러스터를 세우지 못했습니다");
        Some(Self {
            scratch,
            store,
            cluster: Some(cluster),
        })
    }

    fn url(&self) -> String {
        self.cluster.as_ref().unwrap().url().unwrap()
    }

    fn client(&self, database: &str) -> Client {
        let url = self.url();
        let url = format!("{}/{database}", url.rsplit_once('/').unwrap().0);
        Client::connect(&url, NoTls).unwrap()
    }

    fn run(&self, database: &str, sql: &str) {
        self.client(database).batch_execute(sql).unwrap();
    }

    /// DB 의 시계로 지금(유닉스 밀리초).
    fn now(&self) -> u64 {
        let millis: i64 = self
            .client("postgres")
            .query_one(
                "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
                &[],
            )
            .unwrap()
            .get(0);
        u64::try_from(millis).unwrap()
    }

    /// 앞의 commit 과 겹치지 않는 시점을 잡는다. 앞뒤로 조금씩 둔다.
    fn moment(&self) -> u64 {
        std::thread::sleep(Duration::from_millis(20));
        let at = self.now();
        std::thread::sleep(Duration::from_millis(20));
        at
    }

    fn home(&self) -> PathBuf {
        let home = self.scratch.join("home");
        fs::create_dir_all(&home).unwrap();
        home
    }

    fn base_backup(&self) -> BaseBackup {
        self.store.base_backup(&self.url(), &self.home()).unwrap()
    }

    /// 보관을 확인하고 그 시점으로 옆에 되살린다.
    fn recover(&self, at: u64) -> Cluster {
        self.store.seal(&self.url()).unwrap();
        let backups = self.store.backups().unwrap();
        let archive = self.store.archive().unwrap();
        let backup = judge_restore(&backups, &archive, at).unwrap().clone();
        self.store.recover(&backup, at).unwrap()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        drop(self.cluster.take());
        let _ = self.store.tools().remove(&self.scratch.join("store"));
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

macro_rules! bench {
    () => {
        match Bench::new() {
            Some(bench) => bench,
            // CI 에서는 건너뛰지 않는다. 도구가 없으면 워크플로가 PostgreSQL 을 깔지 못한 것이다
            None if std::env::var_os("CI").is_some() => {
                panic!("CI 에 PostgreSQL 의 도구(/usr/lib/postgresql/<버전>/bin)가 없습니다")
            }
            None => {
                eprintln!(
                    "PostgreSQL 의 도구(/usr/lib/postgresql/<버전>/bin)가 없어 건너뜁니다"
                );
                return;
            }
        }
    };
}

fn count(client: &mut Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).unwrap().get(0)
}

fn name(text: &str) -> DatabaseName {
    DatabaseName::parse(text).unwrap()
}

#[test]
fn 기반_백업과_보관한_wal_로_클러스터를_정한_시점으로_되살린다() {
    let bench = bench!();
    bench.run("postgres", "CREATE DATABASE shop");
    bench.run("shop", "CREATE TABLE item (name text)");
    let backup = bench.base_backup();
    // 기반 백업 뒤에 쓴 것은 보관한 WAL 로만 되살아난다
    bench.run("shop", "INSERT INTO item VALUES ('a'), ('b')");
    let at = bench.moment();
    assert!(backup.finished_at <= at);

    let side = bench.recover(at);
    let mut client = side.connect("shop").unwrap();
    assert_eq!(count(&mut client, "SELECT count(*) FROM item"), 2);
    let recovering: bool = client
        .query_one("SELECT pg_is_in_recovery()", &[])
        .unwrap()
        .get(0);
    assert!(
        !recovering,
        "되살린 클러스터는 복구를 마치고 승격해 있어야 합니다"
    );
    // 운영 클러스터는 그대로다
    assert_eq!(
        count(&mut bench.client("shop"), "SELECT count(*) FROM item"),
        2
    );
    let root = side.root().to_owned();
    drop(side);
    assert!(
        !root.exists(),
        "옆의 클러스터는 내리면 폴더째 지워져야 합니다"
    );
    assert_eq!(bench.store.restores_left(), 0);
}

#[test]
fn 되살린_클러스터에는_그_시점_뒤에_쓴_행이_없다() {
    let bench = bench!();
    bench.run("postgres", "CREATE DATABASE shop");
    bench.run("shop", "CREATE TABLE item (name text)");
    bench.base_backup();
    bench.run("shop", "INSERT INTO item VALUES ('before')");
    let at = bench.moment();
    bench.run("shop", "INSERT INTO item VALUES ('after')");
    bench.run("postgres", "CREATE DATABASE late");

    let side = bench.recover(at);
    let mut client = side.connect("shop").unwrap();
    let names: Vec<String> = client
        .query("SELECT name FROM item ORDER BY name", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(names, vec!["before".to_owned()]);
    let all = databases(&mut side.connect("postgres").unwrap()).unwrap();
    assert!(all.contains(&"shop".to_owned()));
    assert!(
        !all.contains(&"late".to_owned()),
        "그 시점 뒤에 만든 database 가 있습니다: {all:?}"
    );
}

#[test]
fn 역할과_권한도_함께_되살아난다() {
    let bench = bench!();
    bench.run("postgres", "CREATE DATABASE shop");
    bench.run(
        "postgres",
        "CREATE ROLE i_k1_owner NOLOGIN; CREATE ROLE i_k1_reader LOGIN; GRANT CONNECT ON DATABASE shop TO i_k1_reader",
    );
    bench.run(
        "shop",
        "CREATE TABLE item (name text); ALTER TABLE item OWNER TO i_k1_owner; GRANT SELECT ON item TO i_k1_reader; INSERT INTO item VALUES ('a')",
    );
    bench.base_backup();
    let at = bench.moment();
    // 그 시점 뒤의 역할과 권한은 되살아나지 않는다
    bench.run(
        "postgres",
        "CREATE ROLE i_k1_late LOGIN; GRANT CONNECT ON DATABASE shop TO i_k1_late",
    );
    bench.run("shop", "GRANT INSERT ON item TO i_k1_reader");

    let side = bench.recover(at);
    let mut admin = side.connect("shop").unwrap();
    assert_eq!(
        roles(&mut admin, "i_k1_").unwrap(),
        vec!["i_k1_owner".to_owned(), "i_k1_reader".to_owned()]
    );
    let owner: String = admin
        .query_one(
            "SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE relname = 'item'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(owner, "i_k1_owner");
    // 그 역할로 접속해 해 본다. 읽기는 되고 쓰기는 거절된다
    let mut reader = postgres::Config::new()
        .host_path(side.socket())
        .port(5432)
        .user("i_k1_reader")
        .dbname("shop")
        .connect(NoTls)
        .unwrap();
    assert_eq!(count(&mut reader, "SELECT count(*) FROM item"), 1);
    let denied = reader
        .batch_execute("INSERT INTO item VALUES ('x')")
        .unwrap_err();
    assert_eq!(
        denied.code(),
        Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
    );
}

#[test]
fn 옆에_세운_클러스터는_tcp_를_듣지_않는다() {
    let bench = bench!();
    bench.base_backup();
    let at = bench.moment();
    let side = bench.recover(at);
    assert_eq!(side.url(), None);
    assert_eq!(side.listen_addresses().unwrap(), "");
    let mut client = side.connect("postgres").unwrap();
    let archive_mode: String = client.query_one("SHOW archive_mode", &[]).unwrap().get(0);
    assert_eq!(
        archive_mode, "off",
        "옆의 클러스터가 운영의 보관 폴더에 WAL 을 섞으면 안 됩니다"
    );
    // 소켓의 폴더는 Postgres 의 사용자만 들어간다
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(side.socket()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn wal_이_빠져_있으면_되살리지_못하고_까닭을_알려_준다() {
    let bench = bench!();
    bench.run("postgres", "CREATE DATABASE shop");
    bench.run("shop", "CREATE TABLE item (name text)");
    let backup = bench.base_backup();
    // 조각을 여럿 넘긴다
    for round in 0..3 {
        bench.run(
            "shop",
            &format!("INSERT INTO item VALUES ('{round}'); SELECT pg_switch_wal()"),
        );
    }
    let at = bench.moment();
    bench.store.seal(&bench.url()).unwrap();

    let archive = bench.store.archive().unwrap();
    let start = archive
        .files
        .iter()
        .position(|file| *file == backup.start_wal)
        .unwrap();
    let missing = archive.files[start + 2].clone();
    assert_eq!(missing.len(), 24, "{:?}", archive.files);
    fs::remove_file(bench.store.root().join("wal").join(&missing)).unwrap();

    let backups = bench.store.backups().unwrap();
    let archive = bench.store.archive().unwrap();
    assert_eq!(
        judge_restore(&backups, &archive, at),
        Err(RestoreRefusal::MissingWal { segment: missing })
    );
    // 판정을 건너뛰고 되살려 봐도 서지 못하고 까닭을 알려 준다. 옆의 폴더는 남지 않는다
    let failed = bench.store.recover(&backup, at).unwrap_err();
    assert_eq!(
        failed,
        orbital_backup::Error::Recovery(RecoveryFailure::TargetNotReached)
    );
    assert!(failed.to_string().contains("WAL"));
    assert_eq!(bench.store.restores_left(), 0);
}

/// 운영 클러스터에 인스턴스 둘의 database 를 세운다. 표 · 색인 · 행 단위 규칙 · 함수 · 권한을 함께 둔다.
/// `i_ka` 는 레이어가 세우는 모양(주인 역할의 스키마, 마이그레이션 역할)이다.
fn two_databases(bench: &Bench) {
    bench.run("postgres", "CREATE DATABASE i_ka");
    bench.run("postgres", "CREATE DATABASE i_kb");
    bench.run(
        "postgres",
        "CREATE ROLE i_ka_owner NOLOGIN; CREATE ROLE i_ka_login LOGIN; CREATE ROLE i_ka_migrator LOGIN; \
         GRANT i_ka_owner TO i_ka_migrator WITH INHERIT TRUE, SET TRUE",
    );
    bench.run("i_ka", "CREATE SCHEMA app AUTHORIZATION i_ka_owner");
    bench.run("i_kb", "CREATE SCHEMA app");
    for database in ["i_ka", "i_kb"] {
        bench.run(
            database,
            &format!(
                "CREATE TABLE app.note (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body text NOT NULL); \
                 CREATE INDEX note_body ON app.note (body); ALTER TABLE app.note ENABLE ROW LEVEL SECURITY; \
                 CREATE POLICY mine ON app.note USING (body <> 'hidden'); \
                 CREATE FUNCTION app.twice(x int) RETURNS int LANGUAGE sql AS 'SELECT x * 2'; \
                 INSERT INTO app.note (body) VALUES ('{ROW_VALUE}')"
            ),
        );
    }
    bench.run(
        "i_ka",
        "ALTER TABLE app.note OWNER TO i_ka_owner; ALTER FUNCTION app.twice(int) OWNER TO i_ka_owner; \
         GRANT SELECT ON app.note TO i_ka_login",
    );
    // 기본값과 같은 권한을 풀어 적은 표. 옮기면 `NULL` 로 돌아오지만 실제 권한은 같다
    bench.run(
        "i_ka",
        "CREATE TABLE app.quiet (x int); ALTER TABLE app.quiet OWNER TO i_ka_owner; REVOKE ALL ON app.quiet FROM PUBLIC",
    );
}

/// 레이어가 자기 계획으로 세우는 것처럼 옮겨 넣을 database 를 세운다. 앱의 스키마는 비어 있고 주인 역할의 것이다.
fn prepare(bench: &Bench, target: &str) {
    bench.run(
        "postgres",
        &format!("CREATE DATABASE {target} TEMPLATE template0"),
    );
    bench.run(
        "postgres",
        &format!(
            "REVOKE ALL ON DATABASE {target} FROM PUBLIC; GRANT CONNECT ON DATABASE {target} TO i_ka_migrator"
        ),
    );
    bench.run(
        target,
        "REVOKE ALL ON SCHEMA public FROM PUBLIC; CREATE SCHEMA app AUTHORIZATION i_ka_owner",
    );
}

fn load<'a>(url: &'a str, target: &'a DatabaseName, schemas: &'a [String]) -> Load<'a> {
    Load {
        admin_url: url,
        database: target,
        schemas,
        owner: "i_ka_owner",
        migrator: "i_ka_migrator",
        auth: None,
    }
}

#[test]
fn database_하나만_운영_클러스터로_옮기고_다른_database_는_건드리지_않는다() {
    let bench = bench!();
    two_databases(&bench);
    bench.base_backup();
    let at = bench.moment();
    for database in ["i_ka", "i_kb"] {
        bench.run(database, "INSERT INTO app.note (body) VALUES ('after')");
    }
    let before: Vec<String> = databases(&mut bench.client("postgres")).unwrap();

    let side = bench.recover(at);
    prepare(&bench, "i_ka_rs_1");
    let url = bench.url();
    let schemas = vec!["app".to_owned()];
    let target = name("i_ka_rs_1");
    load_database(&side, &name("i_ka"), &load(&url, &target, &schemas)).unwrap();

    let after: Vec<String> = databases(&mut bench.client("postgres")).unwrap();
    let mut expected = before.clone();
    expected.push("i_ka_rs_1".to_owned());
    expected.sort();
    assert_eq!(after, expected);
    // 옮긴 것은 그 시점의 것이고, 운영의 두 database 는 그대로다
    assert_eq!(
        count(
            &mut bench.client("i_ka_rs_1"),
            "SELECT count(*) FROM app.note"
        ),
        1
    );
    for database in ["i_ka", "i_kb"] {
        assert_eq!(
            count(&mut bench.client(database), "SELECT count(*) FROM app.note"),
            2,
            "{database}"
        );
    }
    // 정의는 마이그레이션처럼 주인 역할이 만든 것이다. 덤프의 소유와 권한은 되풀이하지 않는다
    let owner: String = bench
        .client("i_ka_rs_1")
        .query_one(
            "SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE oid = 'app.note'::regclass",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(owner, "i_ka_owner");
    let granted: bool = bench
        .client("i_ka_rs_1")
        .query_one(
            "SELECT has_table_privilege('i_ka_login', 'app.note', 'SELECT')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!granted, "권한은 레이어가 권한 표대로 다시 세운다");
    // 이미 정의가 있는 database 에는 넣지 못하고, 그 database 는 그대로다
    bench.run(
        "postgres",
        "GRANT CONNECT ON DATABASE i_kb TO i_ka_migrator",
    );
    let existing = name("i_kb");
    assert!(load_database(&side, &name("i_ka"), &load(&url, &existing, &schemas)).is_err());
    assert_eq!(
        count(&mut bench.client("i_kb"), "SELECT count(*) FROM app.note"),
        2
    );
}

#[test]
fn 옮긴_database_의_지문이_그_시점의_것과_같다() {
    let bench = bench!();
    two_databases(&bench);
    bench.base_backup();
    let then = fingerprint(&mut bench.client("i_ka")).unwrap();
    let at = bench.moment();
    bench.run(
        "i_ka",
        "INSERT INTO app.note (body) VALUES ('after'); CREATE TABLE app.extra (x int)",
    );
    let now = fingerprint(&mut bench.client("i_ka")).unwrap();
    assert_ne!(now, then, "바뀐 database 는 지문이 달라야 합니다");

    let side = bench.recover(at);
    assert_eq!(
        fingerprint(&mut side.connect("i_ka").unwrap()).unwrap(),
        then
    );
    prepare(&bench, "i_ka_rs_1");
    let url = bench.url();
    let schemas = vec!["app".to_owned()];
    let target = name("i_ka_rs_1");
    load_database(&side, &name("i_ka"), &load(&url, &target, &schemas)).unwrap();
    // 레이어가 권한 표대로 권한을 다시 세운다
    bench.run("i_ka_rs_1", "GRANT SELECT ON app.note TO i_ka_login");
    let moved = fingerprint(&mut bench.client("i_ka_rs_1")).unwrap();
    assert_eq!(moved, then);
    assert_eq!(moved.tables.get("app.note"), Some(&1));
}

#[test]
fn 지문에는_이름과_숫자만_있고_행의_값이_없다() {
    let bench = bench!();
    two_databases(&bench);
    let print = fingerprint(&mut bench.client("i_ka")).unwrap();
    let text = serde_json::to_string(&print).unwrap();
    assert!(!text.contains(ROW_VALUE), "{text}");
    assert!(
        !text.contains("hidden"),
        "정책의 글도 해시로만 들어가야 합니다: {text}"
    );
    assert_eq!(print.tables.len(), 2);
    assert_eq!(print.tables.get("app.note"), Some(&1));
    assert_eq!(print.tables.get("app.quiet"), Some(&0));
    assert_eq!(print.schema.len(), 64);
    assert!(print.schema.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn 백업의_묶음에는_봉인의_열쇠와_service_key_가_들어가지_않는다() {
    let bench = bench!();
    let home = bench.home();
    let seal_key = "seal_key_Zt71pQ0xv";
    let service_key = "sk_live_service_Rm40aC9w";
    let token_key = "token_key_Lj29dE8u";
    fs::write(home.join("registry.json"), r#"{"instances":{}}"#).unwrap();
    fs::write(home.join("settings.json"), r#"{"sealed":"AAAA"}"#).unwrap();
    fs::write(home.join("vault.json"), r#"{"sealed":"BBBB"}"#).unwrap();
    fs::create_dir_all(home.join("sources/i1.git")).unwrap();
    fs::write(home.join("sources/i1.git/HEAD"), "ref: refs/heads/main\n").unwrap();
    // 기록 밖에 있어야 하는 것이 실수로 폴더에 놓였어도 묶이지 않는다
    fs::write(home.join("token.key"), token_key).unwrap();
    fs::write(
        home.join(".env"),
        format!("ORBITAL_SEAL_KEY={seal_key}\nORBITAL_SERVICE_KEYS=factory={service_key}\n"),
    )
    .unwrap();
    fs::write(home.join("outbox.jsonl"), "{}\n").unwrap();

    let backup = bench.base_backup();
    let tar = bench
        .store
        .root()
        .join("base")
        .join(&backup.id)
        .join("records.tar");
    let bytes = String::from_utf8_lossy(&fs::read(&tar).unwrap()).into_owned();
    for secret in [seal_key, service_key, token_key] {
        assert!(!bytes.contains(secret), "{secret} 가 묶였습니다");
    }
    let into = bench.scratch.join("unpacked");
    bench.store.records(&backup, &into).unwrap();
    let mut names: Vec<String> = fs::read_dir(&into)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["registry.json", "settings.json", "sources", "vault.json"]
    );
    assert!(RECORDS.iter().all(|record| !record.contains("key")));
    assert_eq!(
        fs::read_to_string(into.join("vault.json")).unwrap(),
        r#"{"sealed":"BBBB"}"#,
        "금고는 봉인한 글 그대로 묶입니다"
    );
}

#[test]
fn 보관_기간이_지난_기반_백업과_거기에만_딸린_wal_을_지운다() {
    let bench = bench!();
    bench.run("postgres", "CREATE DATABASE shop");
    bench.run("shop", "CREATE TABLE item (name text)");
    let old = bench.base_backup();
    for round in 0..3 {
        bench.run(
            "shop",
            &format!("INSERT INTO item VALUES ('{round}'); SELECT pg_switch_wal()"),
        );
    }
    let new = bench.base_backup();
    bench.run("shop", "INSERT INTO item VALUES ('last')");
    let at = bench.moment();
    bench.store.seal(&bench.url()).unwrap();

    // 옛 백업은 보관 기간이 지났고 새 백업은 아직이다. 두 백업 사이가 얼마나 걸렸든 성립하게 그 사이를 보관 기간으로 잡는다
    // (고정한 숫자로 잡으면 기계가 빨라 두 백업이 그보다 가까이 끝났을 때 앞의 조건이 깨진다)
    let keep_for = new.finished_at - old.finished_at;
    assert!(
        keep_for >= 2,
        "두 백업이 같은 때에 끝났습니다: {keep_for}ms"
    );
    let now = new.finished_at + 1;
    assert!(old.finished_at + keep_for < now);
    assert!(new.finished_at + keep_for > now);
    let pruning = prune(&bench.store.backups().unwrap(), now, keep_for);
    assert_eq!(pruning.backups, vec![old.id.clone()]);
    bench.store.prune(&pruning).unwrap();

    let left = bench.store.backups().unwrap();
    assert_eq!(left, vec![new.clone()]);
    assert!(!bench.store.root().join("base").join(&old.id).exists());
    let archive = bench.store.archive().unwrap();
    let segments: Vec<&String> = archive
        .files
        .iter()
        .filter(|file| file.len() == 24)
        .collect();
    assert!(
        segments.iter().all(|file| **file >= new.start_wal),
        "{segments:?}"
    );
    assert!(!archive.files.contains(&old.start_wal));
    // 남은 백업과 WAL 로 여전히 되살린다
    let backup = judge_restore(&left, &archive, at).unwrap().clone();
    let side = bench.store.recover(&backup, at).unwrap();
    assert_eq!(
        count(
            &mut side.connect("shop").unwrap(),
            "SELECT count(*) FROM item"
        ),
        4
    );
    // 마지막 기반 백업은 보관 기간이 지나도 남는다
    let pruning = prune(&left, now + 10 * keep_for, keep_for);
    assert!(pruning.backups.is_empty());
}

#[test]
fn 따옴표가_든_폴더에는_백업을_두지_않는다() {
    let Ok(tools) = Tools::find() else {
        return;
    };
    // 폴더의 이름은 `archive_command` 와 `restore_command` 에 따옴표로 감싸 들어간다. 깨는 글자가 있으면 열지 않는다
    let root = std::env::temp_dir().join(format!("obk-{}-it's", std::process::id()));
    assert!(LocalStore::open(tools, root.clone()).is_err());
    assert!(!root.exists());
}

#[test]
fn 덤프_파일은_주인만_읽고_옮기다_깨져도_남지_않는다() {
    let bench = bench!();
    two_databases(&bench);
    bench.base_backup();
    let at = bench.moment();
    let side = bench.recover(at);

    let dump = side.root().join("probe.dump");
    dump_database(&side, &name("i_ka"), &dump).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(&dump).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(&dump).unwrap();

    // 옮겨 넣을 database 가 없어 깨져도 덤프는 지운다
    let url = bench.url();
    let schemas = vec!["app".to_owned()];
    let missing = name("i_ka_rs_missing");
    assert!(load_database(&side, &name("i_ka"), &load(&url, &missing, &schemas)).is_err());
    let left: Vec<String> = fs::read_dir(side.root())
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|file| file.ends_with(".dump"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}
