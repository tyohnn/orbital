//! database 하나의 지문, 역할의 목록, database 하나를 옆의 클러스터에서 운영 클러스터로 옮기기.
//!
//! 지문에는 이름과 숫자만 든다. 스키마의 모양은 해시 하나로, 표는 행의 수로만 적는다.

use std::collections::BTreeMap;
use std::path::Path;

use orbital_core::backup::Fingerprint;
use postgres::Client;
use sha2::{Digest, Sha256};

use crate::{Cluster, Error, Tools, pg};

/// SQL 에 넣는 database 의 이름. 소문자 · 숫자 · 밑줄로만 지어져 따옴표를 깨지 못한다.
/// 레이어는 인스턴스의 이름(`Names`, 검증된 식별자)에 정한 꼬리를 붙여 짓는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseName(String);

impl DatabaseName {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let fine = !text.is_empty()
            && text.len() <= 63
            && text.starts_with(|c: char| c.is_ascii_lowercase())
            && text
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        fine.then(|| Self(text.to_owned())).ok_or(Error::BadName)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 사용자 스키마의 조건. Postgres 의 것과 `information_schema` 는 뺀다.
const USER_SCHEMA: &str = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'";

/// database 의 지문을 뜬다. 한 트랜잭션(REPEATABLE READ)에서 읽어 스키마와 행 수가 한 시점의 것이다.
pub fn fingerprint(client: &mut Client) -> Result<Fingerprint, Error> {
    let reading = "지문을 뜨";
    let mut transaction = client
        .build_transaction()
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(pg(reading))?;
    // 모양을 이루는 것마다 한 줄씩. 순서를 정해 두어 같은 모양이면 같은 해시가 나온다.
    // 권한은 실제로 갖는 것(기본값을 풀어 쓴 것)으로 견준다. 옮기면 기본값과 같은 권한은 `NULL` 로 돌아오기 때문이다
    let shapes = [
        format!(
            "SELECT format('rel %s.%s %s', n.nspname, c.relname, c.relkind) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE {USER_SCHEMA} AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') ORDER BY 1"
        ),
        format!(
            "SELECT format('col %s.%s.%s %s %s', n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull) \
             FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE {USER_SCHEMA} AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped ORDER BY 1"
        ),
        format!(
            "SELECT format('con %s.%s %s %s', n.nspname, c.relname, k.conname, pg_get_constraintdef(k.oid)) \
             FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE {USER_SCHEMA} ORDER BY 1"
        ),
        "SELECT format('idx %s', indexdef) FROM pg_indexes \
         WHERE schemaname !~ '^pg_' AND schemaname <> 'information_schema' ORDER BY 1"
            .to_owned(),
        "SELECT format('pol %s.%s %s %s %s %s %s %s', schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check) \
         FROM pg_policies ORDER BY 1"
            .to_owned(),
        format!(
            "SELECT format('fn %s.%s(%s) %s', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), md5(coalesce(p.prosrc, ''))) \
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE {USER_SCHEMA} ORDER BY 1"
        ),
        format!(
            "SELECT format('acl %s.%s %s %s', n.nspname, c.relname, coalesce(r.rolname, 'public'), a.privilege_type) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::\"char\", c.relowner))) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE {USER_SCHEMA} ORDER BY 1"
        ),
        format!(
            "SELECT format('nsp %s %s', n.nspname, pg_get_userbyid(n.nspowner)) FROM pg_namespace n WHERE {USER_SCHEMA} ORDER BY 1"
        ),
    ];
    let mut hasher = Sha256::new();
    for shape in &shapes {
        for row in transaction.query(shape, &[]).map_err(pg(reading))? {
            let line: String = row.get(0);
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        hasher.update(b"--\n");
    }
    let schema = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let mut tables = BTreeMap::new();
    let rows = transaction
        .query(
            &format!(
                "SELECT n.nspname || '.' || c.relname, format('%I.%I', n.nspname, c.relname) \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE {USER_SCHEMA} AND c.relkind IN ('r', 'p') ORDER BY 1"
            ),
            &[],
        )
        .map_err(pg(reading))?;
    for row in rows {
        let (label, quoted): (String, String) = (row.get(0), row.get(1));
        let count: i64 = transaction
            .query_one(&format!("SELECT count(*) FROM {quoted}"), &[])
            .map_err(pg("행의 수를 세"))?
            .get(0);
        tables.insert(label, count);
    }
    transaction.commit().map_err(pg(reading))?;
    Ok(Fingerprint { schema, tables })
}

/// 이 머리말을 가진 역할의 이름.
pub fn roles(client: &mut Client, prefix: &str) -> Result<Vec<String>, Error> {
    Ok(client
        .query(
            "SELECT rolname FROM pg_roles WHERE left(rolname, length($1)) = $1 ORDER BY 1",
            &[&prefix],
        )
        .map_err(pg("역할의 목록을 읽"))?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// 클러스터의 database 이름.
pub fn databases(client: &mut Client) -> Result<Vec<String>, Error> {
    Ok(client
        .query(
            "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1",
            &[],
        )
        .map_err(pg("database 의 목록을 읽"))?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// 운영 클러스터에 붙을 자리. 주소에서 읽어 명령에는 환경 변수(`PGHOST` · `PGPORT` · `PGUSER` · `PGPASSWORD` · `PGDATABASE`)로 건넨다.
/// 명령줄에 실으면 비밀번호가 프로세스 목록에 보이기 때문이다.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    database: String,
}

impl Endpoint {
    pub(crate) fn parse(url: &str) -> Result<Self, Error> {
        let bad = || Error::Io {
            doing: "DB 의 관리 주소를 읽",
        };
        let parsed = url::Url::parse(url).map_err(|_| bad())?;
        let decode = |text: &str| {
            url::form_urlencoded::parse(format!("x={text}").as_bytes())
                .next()
                .map(|(_, value)| value.into_owned())
        };
        Ok(Self {
            host: parsed.host_str().ok_or_else(bad)?.to_owned(),
            port: parsed.port().unwrap_or(5432),
            user: decode(parsed.username())
                .filter(|user| !user.is_empty())
                .ok_or_else(bad)?,
            password: parsed.password().and_then(decode),
            database: parsed.path().trim_start_matches('/').to_owned(),
        })
    }

    /// 같은 자리에 다른 역할과 database 로. 인스턴스의 역할에는 비밀번호가 없다.
    fn as_role(&self, user: &str, database: &DatabaseName) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            user: user.to_owned(),
            password: None,
            database: database.as_str().to_owned(),
        }
    }

    pub(crate) fn apply(&self, command: &mut std::process::Command) {
        command
            .env("PGHOST", &self.host)
            .env("PGPORT", self.port.to_string())
            .env("PGUSER", &self.user)
            .env("PGDATABASE", &self.database);
        if let Some(password) = &self.password {
            command.env("PGPASSWORD", password);
        }
    }
}

/// 옆의 클러스터의 database 하나를 덤프로 뜬다. 파일은 주인만 읽는다(운영의 행이 평문으로 들어 있다).
pub fn dump_database(side: &Cluster, source: &DatabaseName, into: &Path) -> Result<(), Error> {
    let mut command = side.tools().tool_private("pg_dump");
    command
        .arg("-h")
        .arg(side.socket())
        .arg("-p")
        .arg(side.socket_port().to_string())
        .arg("-U")
        .arg(side.user())
        .args(["-Fc", "--no-password", "-f"])
        .arg(into)
        .arg(source.as_str());
    let dumped = Tools::run(command, "옆의 클러스터에서 database 를 뜨");
    if dumped.is_err() {
        let _ = std::fs::remove_file(into);
    }
    dumped
}

/// 옮겨 넣을 자리. 레이어가 자기 계획으로 이미 세운 database 와, 그 안에 넣을 때 쓰는 인스턴스의 역할.
#[derive(Debug, Clone, Copy)]
pub struct Load<'a> {
    /// 운영 클러스터의 관리 주소. 호스트와 포트만 쓴다. 관리 역할로는 아무것도 풀지 않는다.
    pub admin_url: &'a str,
    /// 레이어가 세운 새 database(스키마 · `orbital` · `orbital_auth` 가 이미 있다).
    pub database: &'a DatabaseName,
    /// 앱이 선언한 스키마. 이 스키마의 정의와 행만 덤프에서 푼다.
    pub schemas: &'a [String],
    /// 표의 주인. 마이그레이션처럼 이 역할이 되어 정의를 만든다.
    pub owner: &'a str,
    /// 인스턴스의 마이그레이션 역할. 이 역할로 붙는다.
    pub migrator: &'a str,
    /// `orbital_auth` 의 행을 넣는 인증 역할. `[auth]` 가 없으면 없다.
    pub auth: Option<&'a str>,
}

/// 옆의 클러스터의 database 하나를 운영 클러스터의, 레이어가 미리 세운 database 로 옮긴다.
///
/// **덤프의 SQL 을 관리 역할로 되풀이하지 않는다.** 앱이 정의한 함수는 CHECK 제약 · 인덱스의 식 · 생성 열에 걸려 행을 넣는 동안 돈다.
/// 그래서 이렇게 나눈다.
/// - `orbital_auth` 는 **행만** 인증 역할로 넣는다. 정의는 레이어가 세운 것이다. 덤프로는 외래 키의 차례대로 넣지 못해
///   (그 차례를 무시하는 길은 관리 권한에만 있다) 옆의 클러스터에서 표마다 `COPY` 로 옮긴다.
/// - 앱의 스키마는 마이그레이션 역할로 붙어 소유자가 되어(`--role`) 정의와 행을 푼다. 마이그레이션이 도는 것과 같은 권한이다.
///   덤프의 소유와 권한은 되풀이하지 않는다(`--no-owner --no-acl`). 권한은 부른 쪽이 권한 표대로 다시 세운다.
/// - 레이어의 마이그레이션 기록(`orbital.migration`)은 행만 소유자로 넣는다.
///
/// 덤프 파일은 주인만 읽고, 어떻게 끝나든 지운다.
pub fn load_database(side: &Cluster, source: &DatabaseName, into: &Load<'_>) -> Result<(), Error> {
    let dump = side.root().join(format!("{}.dump", into.database.as_str()));
    let loaded = load_from(side, source, into, &dump);
    let _ = std::fs::remove_file(&dump);
    loaded
}

fn load_from(
    side: &Cluster,
    source: &DatabaseName,
    into: &Load<'_>,
    dump: &Path,
) -> Result<(), Error> {
    dump_database(side, source, dump)?;
    let tools = side.tools();
    let admin = Endpoint::parse(into.admin_url)?;
    if let Some(auth) = into.auth {
        copy_auth_rows(side, source, &admin.as_role(auth, into.database))?;
    }
    if !into.schemas.is_empty() {
        let mut args = vec![
            "--no-owner".to_owned(),
            "--no-acl".to_owned(),
            format!("--role={}", into.owner),
        ];
        args.extend(
            into.schemas
                .iter()
                .map(|schema| format!("--schema={schema}")),
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        restore(
            tools,
            dump,
            &admin.as_role(into.migrator, into.database),
            &args,
            "앱의 스키마를 풀",
        )?;
    }
    restore(
        tools,
        dump,
        &admin.as_role(into.migrator, into.database),
        &[
            "--data-only",
            "--schema=orbital",
            "--table=migration",
            &format!("--role={}", into.owner),
        ],
        "마이그레이션의 기록을 넣",
    )
}

/// `orbital_auth` 의 행을 옆의 클러스터에서 옮겨 넣는다. 넣는 쪽은 인증 역할로 붙고, 표는 외래 키가 가리키는 것부터 넣는다.
/// 열은 넣는 쪽(레이어가 세운 것)의 열 이름으로 맞춘다. 읽는 쪽은 레이어가 정의한 표만 읽는다(앱의 함수를 부르지 않는다).
fn copy_auth_rows(side: &Cluster, source: &DatabaseName, into: &Endpoint) -> Result<(), Error> {
    let mut from = side.connect(source.as_str())?;
    let mut target = postgres::Config::new()
        .host(&into.host)
        .port(into.port)
        .user(&into.user)
        .dbname(&into.database)
        .connect(postgres::NoTls)
        .map_err(pg("인증 역할로 붙"))?;
    // 표마다 (따옴표를 씌운 이름, 그 표가 가리키는 같은 스키마의 표, 열의 목록)
    let rows = target
        .query(
            "SELECT c.relname::text, format('orbital_auth.%I', c.relname), \
             ARRAY(SELECT DISTINCT r.relname::text FROM pg_constraint k JOIN pg_class r ON r.oid = k.confrelid \
                   WHERE k.conrelid = c.oid AND k.contype = 'f' AND r.oid <> c.oid AND r.relnamespace = c.relnamespace), \
             (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) FROM pg_attribute a \
              WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'orbital_auth' AND c.relkind = 'r' ORDER BY 1",
            &[],
        )
        .map_err(pg("로그인의 표를 읽"))?;
    let mut tables: Vec<(String, String, Vec<String>, String)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    // 가리키는 표가 모두 앞에 놓인 것부터 차례로 꺼낸다
    let mut ordered: Vec<(String, String, Vec<String>, String)> = Vec::new();
    while !tables.is_empty() {
        let placed: Vec<String> = ordered
            .iter()
            .map(|(name, ..)| String::clone(name))
            .collect();
        let Some(next) = tables
            .iter()
            .position(|(_, _, refers, _)| refers.iter().all(|name| placed.contains(name)))
        else {
            return Err(Error::Io {
                doing: "로그인의 표의 차례를 정하",
            });
        };
        ordered.push(tables.remove(next));
    }
    let mut transaction = target
        .transaction()
        .map_err(pg("로그인의 행 넣기를 시작"))?;
    for (_, table, _, columns) in &ordered {
        let mut reader = from
            .copy_out(&format!(
                "COPY {table} ({columns}) TO STDOUT (FORMAT binary)"
            ))
            .map_err(pg("로그인의 행을 읽"))?;
        let mut writer = transaction
            .copy_in(&format!(
                "COPY {table} ({columns}) FROM STDIN (FORMAT binary)"
            ))
            .map_err(pg("로그인의 행을 넣"))?;
        std::io::copy(&mut reader, &mut writer).map_err(crate::io("로그인의 행을 옮기"))?;
        writer.finish().map_err(pg("로그인의 행을 넣"))?;
    }
    transaction
        .commit()
        .map_err(pg("로그인의 행 넣기를 마무리"))
}

fn restore(
    tools: &Tools,
    dump: &Path,
    endpoint: &Endpoint,
    args: &[&str],
    doing: &'static str,
) -> Result<(), Error> {
    let mut command = tools.tool("pg_restore");
    command
        .args(["--exit-on-error", "--single-transaction", "--no-password"])
        .args(args)
        .arg("--dbname")
        .arg(&endpoint.database)
        .arg(dump);
    endpoint.apply(&mut command);
    Tools::run(command, doing)
}
