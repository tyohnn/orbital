//! 레이어의 기록. 관리 연결(`ORBITAL_PG`)의 클러스터 안에 레이어 전용 database(control database) 하나를 두고 그 안의 `orbital` 스키마에 둔다.
//!
//! 관리 서버는 기록을 자기 디스크에 두지 않는다. 그래서 같은 control database 를 보는 관리 서버가 여럿 떠도 같은 기록을 본다.
//! 따로 고쳐지는 것마다 줄을 두고(인스턴스 · 일정 · rollout · 팩토리의 설정 · 금고의 값 · 비밀의 요청 · 입력 표 · 닫은 작업 · 훈련 · 기계 · 앱 · 조직 · service key),
//! 줄을 고칠 때는 그 줄을 잠그고(`FOR UPDATE`) 읽어 고친 뒤 한 트랜잭션으로 적는다. 두 관리 서버가 같은 줄을 동시에 고쳐도 한쪽의 변경을 잃지 않는다.
//!
//! 인스턴스의 database 와 섞지 않고, `PUBLIC` 의 접속을 걷어 인스턴스의 어떤 역할도 이 database 에 붙지 못한다.
//! 마이그레이션은 번호 붙은 SQL 파일(`migrations/`)을 실행 파일에 넣어 두고, 뜰 때 적용하지 않은 것만 차례로 적용한다.
//! 무엇을 적용할지는 core 의 `control::pending` 이 판정한다.
//!
//! 운영의 신원 열쇠와 레이어가 만든 비밀은 봉인의 열쇠가 있는 레이어에서 봉인한 글로만 적는다(조직 · 인스턴스 · 칸에 묶는다).
//! 열쇠가 없는 레이어는 개발용 모양으로 평문을 적고, 열쇠를 준 뒤 처음 뜰 때 평문이던 줄을 봉인으로 바꾼다.
//! 값과 SQL 의 글자는 섞지 않는다. 값은 매개변수로만 넘기고, 오류 문구에는 Postgres 의 글을 싣지 않는다.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use orbital_core::backup::DrillRecord;
use orbital_core::control::{Known, MigrationRefusal, pending};
use orbital_core::event::{Note, rollout_notes};
use orbital_core::name::Ident;
use postgres::{Client, Config, NoTls, Transaction};
use sha2::{Digest, Sha256};

use crate::registry::{InstanceRecord, RolloutRecord, ScheduleRecord, ScheduleRun, State};
use crate::seal::{Rekeyed, SealKey, open, production_binding, reseal, seal};
use crate::token::hex;

mod dashboard;
mod events;
mod organizations;

pub use dashboard::{FleetProduction, FleetRow, HistoryRow, LastPromotion};
pub(crate) use events::append_in;
pub use events::{Attempt, Delivered, DeliveryRow, EventRow, Head, Miss, WebhookRow};
pub use organizations::{FoundKey, KeyRow, NewKey, OrganizationRow};

/// control database 의 기본 이름(`ORBITAL_CONTROL_DB`).
pub const CONTROL_DATABASE: &str = "orbital_control";
/// 기계의 기본 이름(`ORBITAL_MACHINE`). 관리 서버가 한 대일 때의 이름이다.
pub const DEFAULT_MACHINE: &str = "local";
/// 놓인 기계에게 서비스를 재우라고 알리는 길(`LISTEN`/`NOTIFY`). 실리는 것은 기계 · 인스턴스 · 단계의 이름뿐이다.
pub const REFRESH_CHANNEL: &str = "orbital_refresh";

/// 저장소에 둔 control database 의 마이그레이션(파일 이름, 내용). 번호는 이름의 앞 네 자리다.
pub const MIGRATIONS: [(&str, &str); 6] = [
    (
        "0001_records.sql",
        include_str!("../migrations/0001_records.sql"),
    ),
    (
        "0002_machine_address.sql",
        include_str!("../migrations/0002_machine_address.sql"),
    ),
    (
        "0003_organizations.sql",
        include_str!("../migrations/0003_organizations.sql"),
    ),
    (
        "0004_events.sql",
        include_str!("../migrations/0004_events.sql"),
    ),
    (
        "0005_dashboard.sql",
        include_str!("../migrations/0005_dashboard.sql"),
    ),
    (
        "0006_service_key_order.sql",
        include_str!("../migrations/0006_service_key_order.sql"),
    ),
];

/// 기록의 bigint 칸에 적을 값. 넘치면 가장 큰 값이다.
fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// 옛 기록 파일. 처음 뜰 때 한 번 옮기고 `<이름>.imported` 로 바꾼다.
pub const OLD_FILES: [&str; 5] = [
    "registry.json",
    "settings.json",
    "vault.json",
    "revoked.json",
    "drills.jsonl",
];

/// 마이그레이션을 한 줄로 세우는 advisory lock 의 번호. control database 안에서만 쓴다.
const MIGRATE_LOCK: i64 = 0x6f72_6200_0001;
/// 기반 백업과 복구 훈련을 여러 관리 서버 가운데 하나만 돌리게 하는 advisory lock 의 번호.
const BACKUP_LOCK: i64 = 0x6f72_6200_0002;

/// 기록을 읽거나 적지 못한 까닭. Postgres 의 글(행의 값이 섞일 수 있다)은 싣지 않고 무엇을 하다 깨졌는지와 SQLSTATE 만 싣는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(pub String);

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecordError {}

/// Postgres 의 오류를 기록의 오류로 옮긴다. SQLSTATE 만 남긴다.
fn pg(doing: &'static str) -> impl Fn(postgres::Error) -> RecordError {
    move |error| {
        let code = error
            .code()
            .map(|code| format!(" (SQLSTATE {})", code.code()))
            .unwrap_or_default();
        RecordError(format!("레이어의 기록을 {doing}지 못했습니다{code}"))
    }
}

fn json(doing: &'static str) -> impl Fn(serde_json::Error) -> RecordError {
    move |_| {
        RecordError(format!(
            "레이어의 기록을 {doing}지 못했습니다(모양이 틀렸습니다)"
        ))
    }
}

// ---- 연결 ----

/// 동기 연결은 안에서 tokio 의 런타임을 돌린다. router 처럼 런타임 안에서 부르는 쪽은 그 일을 따로 된 스레드에서 돌린다.
pub fn off_runtime<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    if tokio::runtime::Handle::try_current().is_err() {
        return work();
    }
    std::thread::scope(|scope| match scope.spawn(work).join() {
        Ok(done) => done,
        Err(panic) => std::panic::resume_unwind(panic),
    })
}

/// control database 에 붙은 연결 몇 개. 쓰고 나면 돌려놓는다.
struct Pool {
    config: Config,
    idle: Mutex<Vec<Client>>,
}

/// 빌려 쓰는 연결. 떨어지면 돌려놓는다(끊긴 것은 버린다).
pub struct Pooled<'a> {
    pool: &'a Pool,
    client: Option<Client>,
}

impl std::ops::Deref for Pooled<'_> {
    type Target = Client;

    fn deref(&self) -> &Client {
        self.client.as_ref().expect("빌린 연결")
    }
}

impl std::ops::DerefMut for Pooled<'_> {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().expect("빌린 연결")
    }
}

impl Drop for Pooled<'_> {
    fn drop(&mut self) {
        if let Some(client) = self.client.take()
            && !client.is_closed()
        {
            let mut idle = self
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if idle.len() < 4 {
                idle.push(client);
            }
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // 마지막 손잡이가 router 의 런타임 안에서 떨어질 수 있다. 연결을 닫는 일은 런타임 밖에서 한다
        let idle = std::mem::take(
            &mut *self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        off_runtime(move || drop(idle));
    }
}

impl Pool {
    fn get(&self) -> Result<Pooled<'_>, RecordError> {
        let kept = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();
        let client = match kept {
            Some(client) if !client.is_closed() => client,
            _ => self
                .config
                .connect(NoTls)
                .map_err(pg("읽으려고 control database 에 붙"))?,
        };
        Ok(Pooled {
            pool: self,
            client: Some(client),
        })
    }
}

/// 관리 주소에서 database 만 바꾼 설정.
fn config_for(pg_url: &str, database: &str) -> Result<Config, String> {
    let mut config: Config = pg_url
        .parse()
        .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
    config.dbname(database);
    Ok(config)
}

/// control database 를 세운다(없으면). 있든 없든 `PUBLIC` 의 접속을 걷는다. 두 관리 서버가 동시에 세워도 하나만 선다.
pub fn ensure_database(pg_url: &str, name: &Ident) -> Result<(), String> {
    let config: Config = pg_url
        .parse()
        .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
    let mut admin = config
        .connect(NoTls)
        .map_err(|_| "운영 클러스터에 관리 연결로 붙지 못했습니다".to_owned())?;
    let quoted = format!("\"{}\"", name.as_str());
    for attempt in 0..20 {
        let exists = admin
            .query_opt(
                "SELECT 1 FROM pg_database WHERE datname = $1",
                &[&name.as_str()],
            )
            .map_err(|_| "control database 를 찾지 못했습니다".to_owned())?
            .is_some();
        if exists {
            break;
        }
        match admin.batch_execute(&format!("CREATE DATABASE {quoted}")) {
            Ok(()) => break,
            // 다른 관리 서버가 먼저 세웠다(42P04), 또는 그쪽이 본뜨는 중이라 본이 바쁘다(55006)
            Err(error)
                if attempt < 19
                    && error
                        .code()
                        .is_some_and(|code| matches!(code.code(), "42P04" | "55006" | "23505")) =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err("control database 를 세우지 못했습니다".to_owned()),
        }
    }
    admin
        .batch_execute(&format!("REVOKE ALL ON DATABASE {quoted} FROM PUBLIC"))
        .map_err(|_| "control database 의 접속을 걷지 못했습니다".to_owned())
}

/// control database 를 지운다. 테스트가 끝날 때 쓴다(붙은 연결은 끊는다).
pub fn drop_database(pg_url: &str, name: &Ident) -> Result<(), String> {
    let config: Config = pg_url
        .parse()
        .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
    let mut admin = config
        .connect(NoTls)
        .map_err(|_| "운영 클러스터에 관리 연결로 붙지 못했습니다".to_owned())?;
    admin
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            name.as_str()
        ))
        .map_err(|_| "control database 를 지우지 못했습니다".to_owned())
}

// ---- 마이그레이션 ----

/// 마이그레이션 하나.
#[derive(Debug, Clone)]
pub struct Migration {
    pub number: u32,
    pub name: String,
    pub sql: String,
}

impl Migration {
    /// 파일 이름의 앞 네 자리를 번호로 읽는다.
    pub fn named(name: &str, sql: &str) -> Result<Self, String> {
        let number = name
            .get(..4)
            .and_then(|digits| digits.parse::<u32>().ok())
            .filter(|_| name.as_bytes().get(4) == Some(&b'_'))
            .ok_or_else(|| {
                format!("마이그레이션 `{name}` 의 이름은 `0001_무엇.sql` 처럼 네 자리 번호로 시작해야 합니다")
            })?;
        Ok(Self {
            number,
            name: name.to_owned(),
            sql: sql.to_owned(),
        })
    }

    fn sha256(&self) -> String {
        hex(&Sha256::digest(self.sql.as_bytes()))
    }
}

/// 저장소의 마이그레이션.
pub fn bundled() -> Vec<Migration> {
    MIGRATIONS
        .iter()
        .filter_map(|(name, sql)| Migration::named(name, sql).ok())
        .collect()
}

fn refusal_text(refusal: &MigrationRefusal) -> String {
    match refusal {
        MigrationRefusal::Gap { missing } => format!(
            "control database 의 마이그레이션 {missing:04} 가 저장소에 없습니다. 번호는 1 부터 빠짐없이 이어져야 합니다"
        ),
        MigrationRefusal::Duplicate { number } => {
            format!(
                "control database 의 마이그레이션 {number:04} 가 둘입니다. 번호를 하나씩만 써 주세요"
            )
        }
        MigrationRefusal::Changed { number } => format!(
            "control database 에 적용한 마이그레이션 {number:04} 의 내용이 이 관리 서버의 것과 다릅니다. 적용한 마이그레이션은 고치지 않습니다. 파일을 적용한 때의 모양으로 되돌리고, 바꿀 것은 새 번호의 마이그레이션으로 더해 주세요"
        ),
        MigrationRefusal::Unknown { number } => format!(
            "control database 에 이 관리 서버가 모르는 마이그레이션 {number:04} 가 적용돼 있습니다. 더 새 관리 서버가 적용한 것입니다. 그 판의 관리 서버로 띄워 주세요"
        ),
    }
}

/// 적용하지 않은 마이그레이션을 번호의 차례로 적용하고, 적용한 번호를 돌려준다. 두 관리 서버가 동시에 불러도 advisory lock 으로
/// 한 줄로 서서 한 번만 돈다. 적용한 것의 내용이 바뀌었으면 아무것도 돌리지 않고 까닭을 돌려준다.
pub fn migrate(client: &mut Client, migrations: &[Migration]) -> Result<Vec<u32>, String> {
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATE_LOCK])
        .map_err(|_| "마이그레이션의 차례를 잡지 못했습니다".to_owned())?;
    let result = migrate_locked(client, migrations);
    let unlocked = client.query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATE_LOCK]);
    let applied = result?;
    unlocked.map_err(|_| "마이그레이션의 차례를 놓지 못했습니다".to_owned())?;
    Ok(applied)
}

fn migrate_locked(client: &mut Client, migrations: &[Migration]) -> Result<Vec<u32>, String> {
    client
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS orbital;
             CREATE TABLE IF NOT EXISTS orbital.migration (
                 number integer PRIMARY KEY,
                 name text NOT NULL,
                 sha256 text NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .map_err(|_| "control database 의 마이그레이션 표를 세우지 못했습니다".to_owned())?;
    let applied: Vec<Known> = client
        .query("SELECT number, sha256 FROM orbital.migration", &[])
        .map_err(|_| "적용한 마이그레이션을 읽지 못했습니다".to_owned())?
        .iter()
        .map(|row| Known {
            number: u32::try_from(row.get::<_, i32>(0)).unwrap_or(0),
            sha256: row.get(1),
        })
        .collect();
    let known: Vec<Known> = migrations
        .iter()
        .map(|migration| Known {
            number: migration.number,
            sha256: migration.sha256(),
        })
        .collect();
    let next = pending(&known, &applied).map_err(|refusals| {
        refusals
            .iter()
            .map(refusal_text)
            .collect::<Vec<_>>()
            .join(" / ")
    })?;
    for number in &next {
        let Some(migration) = migrations.iter().find(|found| found.number == *number) else {
            continue;
        };
        let failed = || {
            format!(
                "control database 의 마이그레이션 {:04} 를 적용하지 못했습니다",
                migration.number
            )
        };
        let mut transaction = client.transaction().map_err(|_| failed())?;
        transaction
            .batch_execute(&migration.sql)
            .map_err(|_| failed())?;
        let number = i32::try_from(migration.number).map_err(|_| failed())?;
        transaction
            .execute(
                "INSERT INTO orbital.migration (number, name, sha256) VALUES ($1, $2, $3)",
                &[&number, &migration.name, &migration.sha256()],
            )
            .map_err(|_| failed())?;
        transaction.commit().map_err(|_| failed())?;
    }
    Ok(next)
}

// ---- 기록 ----

/// 레이어의 기록. control database 에 붙은 연결 몇 개와, 이 관리 서버의 기계 이름.
pub struct Records {
    pool: Pool,
    seal: Option<SealKey>,
    machine: Ident,
    database: Ident,
    pg_url: String,
}

/// 기계의 주소. 다른 관리 서버에서 닿는 것이다. 끝의 `/` 는 없다.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineAddresses {
    /// 관리 API(`ORBITAL_MACHINE_URL`).
    pub api: Option<String>,
    /// 하위 도메인으로 고객의 요청을 받는 공용 listener(`ORBITAL_MACHINE_ROUTER_URL`).
    pub router: Option<String>,
}

/// 봉인을 다시 한 결과(운영의 신원 열쇠와 레이어가 만든 비밀).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProductionSealed {
    /// 옛 열쇠로만 풀리던 것을 새 열쇠로 옮긴 칸의 수.
    pub resealed: usize,
    /// 평문이던 것을 봉인한 칸의 수.
    pub sealed: usize,
    /// 어느 열쇠로도 풀리지 않아 그대로 둔 칸의 이름.
    pub unopened: Vec<String>,
}

/// 여러 관리 서버 가운데 하나만 하는 일을 쥔 것. 떨어지면 연결이 닫혀 놓는다.
pub struct Exclusive {
    _client: Client,
}

/// 기계의 이름을 쥔 것. 쥐고 있는 동안 다른 관리 서버는 같은 이름으로 뜨지 못한다. 떨어지면(또는 프로세스가 죽으면) 연결이 닫혀 놓는다.
pub struct MachineHold {
    /// 연결은 쓰지 않고 쥐고만 있다. 레이어를 스레드 사이에서 나눠 쓰도록 자물쇠 안에 둔다.
    client: Mutex<Option<Client>>,
}

impl Drop for MachineHold {
    fn drop(&mut self) {
        // 레이어의 마지막 손잡이가 router 의 런타임 안에서 떨어질 수 있다. 연결을 닫는 일은 런타임 밖에서 한다
        let client = self
            .client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        off_runtime(move || drop(client));
    }
}

/// 기계의 이름마다의 advisory lock 번호. 이름의 sha256 앞 8바이트라 다른 이름과 겹치지 않는다.
fn machine_lock(machine: &str) -> i64 {
    let digest = Sha256::digest(format!("orbital/machine\n{machine}").as_bytes());
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(head)
}

const IDENTITY_KEY: &str = "identity_key";

fn generated_field(name: &str) -> String {
    format!("generated.{name}")
}

fn is_sealed(text: &str) -> bool {
    text.starts_with("seal1.")
}

impl Records {
    /// control database 를 세우고(없으면) 마이그레이션을 적용한 뒤 이 관리 서버의 기계를 적는다.
    pub fn open(
        pg_url: &str,
        database: &Ident,
        machine: &Ident,
        seal: Option<SealKey>,
        now: u64,
    ) -> Result<Self, String> {
        ensure_database(pg_url, database)?;
        let config = config_for(pg_url, database.as_str())?;
        let mut client = config
            .connect(NoTls)
            .map_err(|_| "control database 에 붙지 못했습니다".to_owned())?;
        migrate(&mut client, &bundled())?;
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        client
            .execute(
                "INSERT INTO orbital.machine (name, started_at, seen_at) VALUES ($1, $2, $2)
                 ON CONFLICT (name) DO UPDATE SET started_at = excluded.started_at, seen_at = excluded.seen_at",
                &[&machine.as_str(), &now],
            )
            .map_err(|_| "이 관리 서버의 기계를 기록에 적지 못했습니다".to_owned())?;
        Ok(Self {
            pool: Pool {
                config,
                idle: Mutex::new(vec![client]),
            },
            seal,
            machine: machine.clone(),
            database: database.clone(),
            pg_url: pg_url.to_owned(),
        })
    }

    /// 봉인의 열쇠가 있는가.
    pub fn sealing(&self) -> bool {
        self.seal.is_some()
    }

    /// 이 관리 서버의 기계.
    pub fn machine(&self) -> &str {
        self.machine.as_str()
    }

    /// 이 기계의 주소를 적는다. 주지 않은 주소는 비운다(앞에 띄운 관리 서버가 적은 낡은 주소로 넘기지 않게).
    /// 기계의 이름을 쥔 뒤에 부른다. 같은 이름으로 뜨려다 막힌 관리 서버가 주소를 덮지 않는다.
    pub fn set_addresses(&self, addresses: &MachineAddresses) -> Result<(), RecordError> {
        self.client()?
            .execute(
                "UPDATE orbital.machine SET api_url = $2, router_url = $3 WHERE name = $1",
                &[&self.machine.as_str(), &addresses.api, &addresses.router],
            )
            .map(drop)
            .map_err(pg("기계의 주소를 적"))
    }

    /// 그 기계의 주소. 기계가 기록에 없으면 주소가 없는 것과 같다.
    pub fn addresses_of(&self, machine: &str) -> Result<MachineAddresses, RecordError> {
        let row = self
            .client()?
            .query_opt(
                "SELECT api_url, router_url FROM orbital.machine WHERE name = $1",
                &[&machine],
            )
            .map_err(pg("기계의 주소를 읽"))?;
        Ok(
            row.map_or_else(MachineAddresses::default, |row| MachineAddresses {
                api: row.get(0),
                router: row.get(1),
            }),
        )
    }

    /// control database 의 이름.
    pub fn database(&self) -> &Ident {
        &self.database
    }

    /// control database 에 붙는 새 연결. 알림을 듣는 일처럼 오래 쥐는 연결에 쓴다.
    pub fn connect(&self) -> Result<Client, RecordError> {
        self.pool
            .config
            .connect(NoTls)
            .map_err(pg("듣으려고 control database 에 붙"))
    }

    /// 빌려 쓰는 연결.
    pub fn client(&self) -> Result<Pooled<'_>, RecordError> {
        self.pool.get()
    }

    /// 관리 주소. 같은 클러스터의 다른 database 에 붙을 때 쓴다.
    pub fn pg_url(&self) -> &str {
        &self.pg_url
    }

    // ---- 봉인(운영의 신원 열쇠 · 레이어가 만든 비밀) ----

    fn seal_field(
        key: &SealKey,
        organization: &str,
        instance: &str,
        field: &str,
        value: &mut String,
    ) -> Result<(), RecordError> {
        if is_sealed(value) {
            return Ok(());
        }
        *value = seal(
            key,
            &production_binding(organization, instance, field),
            value,
        )
        .ok_or_else(|| RecordError("난수를 읽지 못해 봉인하지 못했습니다".to_owned()))?;
        Ok(())
    }

    fn unseal_field(&self, organization: &str, instance: &str, field: &str, value: &mut String) {
        if !is_sealed(value) {
            return;
        }
        // 풀리지 않으면(열쇠가 없거나 다르다) 봉인한 글 그대로 둔다. 쓰는 쪽에서 읽지 못한 것으로 깨진다
        if let Some(plain) = self.seal.as_ref().and_then(|key| {
            open(
                key,
                &production_binding(organization, instance, field),
                value,
            )
        }) {
            *value = plain;
        }
    }

    /// 인스턴스의 몸을 적을 모양으로 바꾼다. 열쇠가 있으면 신원 열쇠와 레이어가 만든 비밀을 봉인한다.
    fn encode(&self, id: &str, record: &InstanceRecord) -> Result<String, RecordError> {
        let mut body = record.clone();
        body.schedules.clear();
        if let (Some(key), Some(production)) = (&self.seal, body.production.as_mut()) {
            Self::seal_field(
                key,
                &record.organization,
                id,
                IDENTITY_KEY,
                &mut production.identity_key,
            )?;
            for (name, value) in &mut production.generated {
                Self::seal_field(key, &record.organization, id, &generated_field(name), value)?;
            }
        }
        serde_json::to_string(&body).map_err(json("적"))
    }

    fn decode(
        &self,
        id: &str,
        (organization, app, machine): (String, String, String),
        text: &str,
    ) -> Result<InstanceRecord, RecordError> {
        let mut record: InstanceRecord = serde_json::from_str(text).map_err(json("읽"))?;
        record.organization = organization;
        record.app = app;
        record.machine = machine;
        if let Some(production) = record.production.as_mut() {
            self.unseal_field(
                &record.organization,
                id,
                IDENTITY_KEY,
                &mut production.identity_key,
            );
            for (name, value) in &mut production.generated {
                self.unseal_field(&record.organization, id, &generated_field(name), value);
            }
        }
        Ok(record)
    }

    /// 운영의 신원 열쇠와 레이어가 만든 비밀을 이 레이어의 열쇠로 맞춘다. 평문이던 칸은 봉인하고, 옛 열쇠(`previous`)로만 풀리는
    /// 칸은 새 열쇠로 다시 봉인한다. 어느 열쇠로도 풀리지 않는 칸은 건드리지 않고 이름만 알린다. 열쇠가 없는 레이어는 아무것도 하지 않는다.
    pub fn seal_production(
        &self,
        previous: Option<&SealKey>,
    ) -> Result<ProductionSealed, RecordError> {
        let Some(key) = &self.seal else {
            return Ok(ProductionSealed::default());
        };
        let mut outcome = ProductionSealed::default();
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("다시 봉인하"))?;
        let rows = transaction
            .query(
                "SELECT id, organization, body::text FROM orbital.instance WHERE body -> 'production' IS NOT NULL AND body ->> 'production' <> 'null' FOR UPDATE",
                &[],
            )
            .map_err(pg("다시 봉인하려고 읽"))?;
        for row in rows {
            let (id, organization, text): (String, String, String) =
                (row.get(0), row.get(1), row.get(2));
            let mut body: InstanceRecord = serde_json::from_str(&text).map_err(json("읽"))?;
            let Some(production) = body.production.as_mut() else {
                continue;
            };
            let mut changed = false;
            let mut fields: Vec<(String, &mut String)> =
                vec![(IDENTITY_KEY.to_owned(), &mut production.identity_key)];
            for (name, value) in &mut production.generated {
                fields.push((generated_field(name), value));
            }
            for (field, value) in fields {
                let bound = production_binding(&organization, &id, &field);
                if !is_sealed(value) {
                    *value = seal(key, &bound, value).ok_or_else(|| {
                        RecordError("난수를 읽지 못해 봉인하지 못했습니다".to_owned())
                    })?;
                    outcome.sealed += 1;
                    changed = true;
                    continue;
                }
                let rekeyed = match previous {
                    Some(previous) => reseal(key, previous, &bound, value).ok_or_else(|| {
                        RecordError("난수를 읽지 못해 봉인하지 못했습니다".to_owned())
                    })?,
                    None if open(key, &bound, value).is_some() => Rekeyed::Current,
                    None => Rekeyed::Unopened,
                };
                match rekeyed {
                    Rekeyed::Current => {}
                    Rekeyed::Changed(again) => {
                        *value = again;
                        outcome.resealed += 1;
                        changed = true;
                    }
                    Rekeyed::Unopened => outcome.unopened.push(format!("production {id} {field}")),
                }
            }
            if changed {
                let text = serde_json::to_string(&body).map_err(json("적"))?;
                transaction
                    .execute(
                        "UPDATE orbital.instance SET body = $2::text::jsonb, version = version + 1 WHERE id = $1",
                        &[&id, &text],
                    )
                    .map_err(pg("다시 봉인해 적"))?;
            }
        }
        transaction.commit().map_err(pg("다시 봉인해 적"))?;
        Ok(outcome)
    }

    // ---- 인스턴스 ----

    /// 인스턴스 하나. 없으면 `None` 이다.
    pub fn instance(&self, id: &str) -> Result<Option<InstanceRecord>, RecordError> {
        let row = self
            .client()?
            .query_opt(
                "SELECT organization, app, machine, body::text FROM orbital.instance WHERE id = $1",
                &[&id],
            )
            .map_err(pg("읽"))?;
        row.map(|row| {
            self.decode(
                id,
                (row.get(0), row.get(1), row.get(2)),
                &row.get::<_, String>(3),
            )
        })
        .transpose()
    }

    /// 모든 인스턴스.
    pub fn instances(&self) -> Result<BTreeMap<String, InstanceRecord>, RecordError> {
        let rows = self
            .client()?
            .query(
                "SELECT id, organization, app, machine, body::text FROM orbital.instance ORDER BY id",
                &[],
            )
            .map_err(pg("읽"))?;
        rows.iter()
            .map(|row| {
                let id: String = row.get(0);
                let record = self.decode(
                    &id,
                    (row.get(1), row.get(2), row.get(3)),
                    &row.get::<_, String>(4),
                )?;
                Ok((id, record))
            })
            .collect()
    }

    /// 새 인스턴스를 적는다. 놓인 기계는 `record.machine` 이다.
    pub fn insert_instance(&self, id: &str, record: &InstanceRecord) -> Result<(), RecordError> {
        let body = self.encode(id, record)?;
        self.client()?
            .execute(
                "INSERT INTO orbital.instance (id, organization, app, machine, body) VALUES ($1, $2, $3, $4, $5::text::jsonb)",
                &[&id, &record.organization, &record.app, &record.machine, &body],
            )
            .map_err(pg("적"))?;
        Ok(())
    }

    /// 인스턴스의 줄을 잠그고 읽어 `change` 로 고친 뒤 적는다. 없으면 `None` 이다. `change` 가 거절하면 아무것도 적지 않는다.
    pub fn update_instance<T, E: From<RecordError>>(
        &self,
        id: &str,
        change: impl FnOnce(&mut InstanceRecord) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        self.update_instance_noting(id, 0, |record, _| change(record))
    }

    /// [`Records::update_instance`] 와 같고, `change` 가 적은 이벤트를 같은 트랜잭션에 쌓는다(`now` 의 때로).
    /// 고친 것이 commit 될 때만 이벤트가 남고, 이벤트를 쌓지 못하면 고친 것도 적지 않는다.
    pub fn update_instance_noting<T, E: From<RecordError>>(
        &self,
        id: &str,
        now: u64,
        change: impl FnOnce(&mut InstanceRecord, &mut Vec<Note>) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        self.update_instance_logged(id, now, |record, notes, _| change(record, notes))
    }

    /// [`Records::update_instance_noting`] 와 같고, `change` 가 적은 이력의 줄(core 의 `history::Entry`)도 같은 트랜잭션에 쌓는다.
    /// 고친 것이 commit 될 때만 이벤트와 이력이 남는다.
    pub fn update_instance_logged<T, E: From<RecordError>>(
        &self,
        id: &str,
        now: u64,
        change: impl FnOnce(
            &mut InstanceRecord,
            &mut Vec<Note>,
            &mut Vec<orbital_core::history::Entry>,
        ) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("고치"))?;
        let Some(row) = transaction
            .query_opt(
                "SELECT organization, app, machine, body::text FROM orbital.instance WHERE id = $1 FOR UPDATE",
                &[&id],
            )
            .map_err(pg("고치려고 읽"))?
        else {
            return Ok(None);
        };
        let mut record = self.decode(
            id,
            (row.get(0), row.get(1), row.get(2)),
            &row.get::<_, String>(3),
        )?;
        let (mut notes, mut entries) = (Vec::new(), Vec::new());
        let made = change(&mut record, &mut notes, &mut entries)?;
        let body = self.encode(id, &record)?;
        transaction
            .execute(
                "UPDATE orbital.instance SET body = $2::text::jsonb, version = version + 1 WHERE id = $1",
                &[&id, &body],
            )
            .map_err(pg("고쳐 적"))?;
        append_in(&mut transaction, &record.organization, now, &notes)?;
        dashboard::append_history_in(
            &mut transaction,
            id,
            now,
            &entries,
            orbital_core::history::KEEP,
        )?;
        transaction.commit().map_err(pg("고쳐 적"))?;
        Ok(Some(made))
    }

    /// 인스턴스를 지운다. 그 인스턴스의 일정 · 금고의 값 · 요청 · 입력 표 · 닫은 작업도 함께 지워진다(외래 키의 `CASCADE`).
    /// 이벤트(`notes`)는 같은 트랜잭션에 쌓는다. 이벤트의 줄은 지우지 않는다(보관 기간 동안 남는다).
    pub fn remove_instance(
        &self,
        id: &str,
        organization: &str,
        now: u64,
        notes: &[Note],
    ) -> Result<(), RecordError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("지우"))?;
        transaction
            .execute("DELETE FROM orbital.instance WHERE id = $1", &[&id])
            .map_err(pg("지우"))?;
        append_in(&mut transaction, organization, now, notes)?;
        transaction.commit().map_err(pg("지우"))
    }

    // ---- 앱 ----

    /// 앱의 코드 저장소가 있는 기계. 올린 적이 없으면 `None` 이다.
    pub fn app_machine(
        &self,
        organization: &str,
        app: &str,
    ) -> Result<Option<String>, RecordError> {
        Ok(self
            .client()?
            .query_opt(
                "SELECT machine FROM orbital.app WHERE organization = $1 AND name = $2",
                &[&organization, &app],
            )
            .map_err(pg("읽"))?
            .map(|row| row.get(0)))
    }

    /// 앱을 이 기계의 것으로 적는다(이미 있으면 그대로 둔다). 앱이 있는 기계를 돌려준다.
    pub fn claim_app(
        &self,
        organization: &str,
        app: &str,
        now: u64,
    ) -> Result<String, RecordError> {
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        let mut client = self.client()?;
        client
            .execute(
                "INSERT INTO orbital.app (organization, name, machine, created_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (organization, name) DO NOTHING",
                &[&organization, &app, &self.machine.as_str(), &now],
            )
            .map_err(pg("적"))?;
        Ok(client
            .query_one(
                "SELECT machine FROM orbital.app WHERE organization = $1 AND name = $2",
                &[&organization, &app],
            )
            .map_err(pg("읽"))?
            .get(0))
    }

    // ---- 일정 ----

    /// 인스턴스의 일정마다의 기록.
    pub fn schedules(&self, id: &str) -> Result<BTreeMap<String, ScheduleRecord>, RecordError> {
        let rows = self
            .client()?
            .query(
                "SELECT key, next_at, last_run::text FROM orbital.schedule WHERE instance = $1",
                &[&id],
            )
            .map_err(pg("읽"))?;
        rows.iter()
            .map(|row| {
                let last_run: Option<String> = row.get(2);
                Ok((
                    row.get::<_, String>(0),
                    ScheduleRecord {
                        next_at: u64::try_from(row.get::<_, i64>(1)).unwrap_or(0),
                        last_run: last_run
                            .map(|text| serde_json::from_str(&text).map_err(json("읽")))
                            .transpose()?,
                    },
                ))
            })
            .collect()
    }

    /// 선언에 있는 일정만 남기고, 처음 보는 일정은 다음 때(`next_at`)를 적는다.
    pub fn sync_schedules(&self, id: &str, wanted: &[(String, u64)]) -> Result<(), RecordError> {
        let keys: Vec<&str> = wanted.iter().map(|(key, _)| key.as_str()).collect();
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("일정을 적"))?;
        transaction
            .execute(
                "DELETE FROM orbital.schedule WHERE instance = $1 AND NOT (key = ANY($2))",
                &[&id, &keys],
            )
            .map_err(pg("일정을 걷"))?;
        for (key, next_at) in wanted {
            let next_at = i64::try_from(*next_at).unwrap_or(i64::MAX);
            transaction
                .execute(
                    "INSERT INTO orbital.schedule (instance, key, next_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&id, key, &next_at],
                )
                .map_err(pg("일정을 적"))?;
        }
        transaction.commit().map_err(pg("일정을 적"))
    }

    /// 일정 하나의 때를 잡는다. 다음 때가 아직 `expected` 일 때만 `next_at` 으로 옮기고 `run` 을 적는다.
    /// 다른 관리 서버(또는 앞의 부름)가 먼저 잡았으면 `false` 다. 같은 때를 두 번 부르지 않는 것을 이 줄이 지킨다.
    pub fn claim_schedule(
        &self,
        id: &str,
        key: &str,
        expected: u64,
        next_at: u64,
        run: &ScheduleRun,
    ) -> Result<bool, RecordError> {
        let run = serde_json::to_string(run).map_err(json("적"))?;
        let (expected, next_at) = (
            i64::try_from(expected).unwrap_or(i64::MAX),
            i64::try_from(next_at).unwrap_or(i64::MAX),
        );
        let changed = self
            .client()?
            .execute(
                "UPDATE orbital.schedule SET next_at = $4, last_run = $5::text::jsonb
                 WHERE instance = $1 AND key = $2 AND next_at = $3",
                &[&id, &key, &expected, &next_at, &run],
            )
            .map_err(pg("일정을 잡"))?;
        Ok(changed == 1)
    }

    /// 부른 결과를 적는다. 그 사이 다음 때를 다시 잡았으면(다른 때의 실행이면) 적지 않는다.
    pub fn finish_schedule(
        &self,
        id: &str,
        key: &str,
        run: &ScheduleRun,
    ) -> Result<(), RecordError> {
        let due_at = i64::try_from(run.due_at).unwrap_or(i64::MAX);
        let text = serde_json::to_string(run).map_err(json("적"))?;
        self.client()?
            .execute(
                "UPDATE orbital.schedule SET last_run = $4::text::jsonb
                 WHERE instance = $1 AND key = $2 AND (last_run ->> 'due_at')::bigint = $3",
                &[&id, &key, &due_at, &text],
            )
            .map_err(pg("일정의 결과를 적"))?;
        Ok(())
    }

    // ---- rollout ----

    pub fn rollouts(&self) -> Result<BTreeMap<String, RolloutRecord>, RecordError> {
        let rows = self
            .client()?
            .query(
                "SELECT id, body::text FROM orbital.rollout ORDER BY id",
                &[],
            )
            .map_err(pg("읽"))?;
        rows.iter()
            .map(|row| {
                let text: String = row.get(1);
                Ok((
                    row.get::<_, String>(0),
                    serde_json::from_str(&text).map_err(json("읽"))?,
                ))
            })
            .collect()
    }

    pub fn rollout(&self, id: &str) -> Result<Option<RolloutRecord>, RecordError> {
        self.client()?
            .query_opt(
                "SELECT body::text FROM orbital.rollout WHERE id = $1",
                &[&id],
            )
            .map_err(pg("읽"))?
            .map(|row| serde_json::from_str(&row.get::<_, String>(0)).map_err(json("읽")))
            .transpose()
    }

    pub fn insert_rollout(&self, id: &str, record: &RolloutRecord) -> Result<(), RecordError> {
        self.insert_rollout_at(id, record, None)
    }

    /// rollout 을 적는다. `created_at` 은 목록의 차례가 된다(모르면 맨 앞에 선다).
    pub fn insert_rollout_at(
        &self,
        id: &str,
        record: &RolloutRecord,
        created_at: Option<u64>,
    ) -> Result<(), RecordError> {
        let body = serde_json::to_string(record).map_err(json("적"))?;
        let created_at = created_at.map(|at| i64::try_from(at).unwrap_or(i64::MAX));
        self.client()?
            .execute(
                "INSERT INTO orbital.rollout (id, organization, body, created_at) VALUES ($1, $2, $3::text::jsonb, $4)",
                &[&id, &record.organization, &body, &created_at],
            )
            .map_err(pg("적"))?;
        Ok(())
    }

    /// rollout 의 줄을 잠그고 읽어 고친 뒤 적는다. 없으면 `None` 이다. 진행이나 상태가 바뀌었으면 그 이벤트
    /// (core 의 `event::rollout_notes`)를 같은 트랜잭션에 `now` 의 때로 쌓는다.
    pub fn update_rollout<T, E: From<RecordError>>(
        &self,
        id: &str,
        now: u64,
        change: impl FnOnce(&mut RolloutRecord) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("고치"))?;
        let Some(row) = transaction
            .query_opt(
                "SELECT body::text FROM orbital.rollout WHERE id = $1 FOR UPDATE",
                &[&id],
            )
            .map_err(pg("고치려고 읽"))?
        else {
            return Ok(None);
        };
        let mut record: RolloutRecord =
            serde_json::from_str(&row.get::<_, String>(0)).map_err(json("읽"))?;
        let before = record.rollout.clone();
        let made = change(&mut record)?;
        let body = serde_json::to_string(&record).map_err(json("적"))?;
        transaction
            .execute(
                "UPDATE orbital.rollout SET body = $2::text::jsonb, version = version + 1 WHERE id = $1",
                &[&id, &body],
            )
            .map_err(pg("고쳐 적"))?;
        let notes = rollout_notes(id, &before, &record.rollout);
        append_in(&mut transaction, &record.organization, now, &notes)?;
        transaction.commit().map_err(pg("고쳐 적"))?;
        Ok(Some(made))
    }

    // ---- 닫은 작업 ----

    /// 닫은 작업인가. 요청마다 본다.
    pub fn revoked(&self, instance: &str, work: &str) -> Result<bool, RecordError> {
        Ok(self
            .client()?
            .query_opt(
                "SELECT 1 FROM orbital.revoked_work WHERE instance = $1 AND work = $2",
                &[&instance, &work],
            )
            .map_err(pg("읽"))?
            .is_some())
    }

    /// 작업을 닫는다. `until` 까지 기억한다. 기억할 때가 지난 줄은 함께 걷는다.
    pub fn revoke(
        &self,
        instance: &str,
        work: &str,
        until: u64,
        now: u64,
    ) -> Result<(), RecordError> {
        let (until, now) = (
            i64::try_from(until).unwrap_or(i64::MAX),
            i64::try_from(now).unwrap_or(i64::MAX),
        );
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg("적"))?;
        transaction
            .execute(
                "DELETE FROM orbital.revoked_work WHERE until <= $1",
                &[&now],
            )
            .map_err(pg("걷"))?;
        transaction
            .execute(
                "INSERT INTO orbital.revoked_work (instance, work, until) VALUES ($1, $2, $3)
                 ON CONFLICT (instance, work) DO UPDATE SET until = GREATEST(orbital.revoked_work.until, excluded.until)",
                &[&instance, &work, &until],
            )
            .map_err(pg("적"))?;
        transaction.commit().map_err(pg("적"))
    }

    // ---- 훈련 ----

    /// 훈련의 기록 모두. 읽지 못한 줄은 건너뛴다.
    pub fn drills(&self) -> Result<Vec<DrillRecord>, RecordError> {
        Ok(self
            .client()?
            .query("SELECT body::text FROM orbital.drill ORDER BY id", &[])
            .map_err(pg("읽"))?
            .iter()
            .filter_map(|row| serde_json::from_str(&row.get::<_, String>(0)).ok())
            .collect())
    }

    pub fn append_drill(&self, record: &DrillRecord) -> Result<(), RecordError> {
        let body = serde_json::to_string(record).map_err(json("적"))?;
        let at = i64::try_from(record.at).unwrap_or(i64::MAX);
        self.client()?
            .execute(
                "INSERT INTO orbital.drill (at, passed, machine, body) VALUES ($1, $2, $3, $4::text::jsonb)",
                &[&at, &record.passed, &self.machine.as_str(), &body],
            )
            .map_err(pg("훈련의 기록을 적"))?;
        Ok(())
    }

    // ---- 여럿 가운데 하나 ----

    /// 기반 백업과 복구 훈련을 맡는다. 다른 관리 서버가 쥐고 있으면 `None` 이다. 쥔 것이 떨어지면 놓는다.
    pub fn take_backup_turn(&self) -> Result<Option<Exclusive>, RecordError> {
        let mut client = self.connect()?;
        let taken: bool = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&BACKUP_LOCK])
            .map_err(pg("백업의 차례를 잡"))?
            .get(0);
        Ok(taken.then_some(Exclusive { _client: client }))
    }

    /// 이 기계의 이름을 쥔다. 같은 이름으로 뜬 관리 서버가 살아 있으면 `wait` 만큼 기다려 보고(막 내려가는 중일 수 있다) `None` 이다.
    ///
    /// 같은 이름의 관리 서버가 둘이면 둘 다 같은 인스턴스를 제 것으로 알고 같은 운영을 되살리고 같은 폴더에 빌드한다.
    /// 기본 이름(`local`)으로 둘을 띄우는 실수가 그렇게 된다. 그래서 이름마다 하나만 뜬다.
    pub fn hold_machine(&self, wait: Duration) -> Result<Option<MachineHold>, RecordError> {
        let mut client = self.connect()?;
        let lock = machine_lock(self.machine.as_str());
        let deadline = std::time::Instant::now() + wait;
        loop {
            let taken: bool = client
                .query_one("SELECT pg_try_advisory_lock($1)", &[&lock])
                .map_err(pg("기계의 이름을 쥐"))?
                .get(0);
            if taken {
                return Ok(Some(MachineHold {
                    client: Mutex::new(Some(client)),
                }));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ---- 놓인 기계에 알리기 ----

    /// 그 인스턴스가 놓인 기계에게 그 단계의 서비스를 재우라고 알린다. 이름만 싣는다.
    pub fn notify_refresh(
        &self,
        machine: &str,
        instance: &str,
        stage: &str,
    ) -> Result<(), RecordError> {
        let payload = format!("{machine} {instance} {stage}");
        self.client()?
            .execute("SELECT pg_notify($1, $2)", &[&REFRESH_CHANNEL, &payload])
            .map_err(pg("알리"))?;
        Ok(())
    }

    // ---- 옛 파일에서 옮기기 ----

    /// control database 가 비어 있고 `home` 에 옛 기록 파일이 있으면 한 트랜잭션으로 옮기고, 옮긴 파일의 이름을 `*.imported` 로 바꾼다.
    /// 옮기다 하나라도 실패하면 아무것도 적지 않고(트랜잭션) 까닭을 돌려준다. 옮긴 것이 있으면 인스턴스의 수를 돌려준다.
    pub fn import(&self, home: &Path, now: u64) -> Result<Option<usize>, String> {
        let present: Vec<&str> = OLD_FILES
            .iter()
            .copied()
            .filter(|name| home.join(name).is_file())
            .collect();
        if present.is_empty() {
            return Ok(None);
        }
        let read = |name: &str| fs::read(home.join(name)).ok();
        let unreadable = |name: &str| {
            format!(
                "옛 기록 파일 `{name}` 을 읽지 못해 control database 로 옮기지 못했습니다. 파일을 고치거나 앞의 판으로 되돌려 주세요"
            )
        };
        // 먼저 모두 읽는다. 하나라도 읽지 못하면 아무것도 적지 않는다
        let state: State = match read("registry.json") {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| unreadable("registry.json"))?
            }
            None => State::default(),
        };
        let settings = match read("settings.json") {
            Some(bytes) => {
                crate::settings::parse_old(&bytes).ok_or_else(|| unreadable("settings.json"))?
            }
            None => Vec::new(),
        };
        let vault = match read("vault.json") {
            Some(bytes) => {
                crate::vault::parse_old(&bytes).ok_or_else(|| unreadable("vault.json"))?
            }
            None => crate::vault::OldVault::default(),
        };
        let revoked: BTreeMap<String, u64> = match read("revoked.json") {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| unreadable("revoked.json"))?
            }
            None => BTreeMap::new(),
        };
        let drills: Vec<DrillRecord> = match read("drills.jsonl") {
            Some(bytes) => String::from_utf8_lossy(&bytes)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|_| unreadable("drills.jsonl"))?,
            None => Vec::new(),
        };
        let apps = old_apps(home);

        let mut client = self.client().map_err(|error| error.0)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| "옛 기록을 옮기지 못했습니다".to_owned())?;
        let empty: bool = transaction
            .query_one(
                "SELECT NOT EXISTS (SELECT 1 FROM orbital.instance) AND NOT EXISTS (SELECT 1 FROM orbital.rollout)
                    AND NOT EXISTS (SELECT 1 FROM orbital.factory_settings) AND NOT EXISTS (SELECT 1 FROM orbital.drill)
                    AND NOT EXISTS (SELECT 1 FROM orbital.organization)",
                &[],
            )
            .map_err(|_| "control database 가 비었는지 보지 못했습니다".to_owned())?
            .get(0);
        if !empty {
            eprintln!(
                "orbitald: control database 에 이미 기록이 있어 `ORBITAL_HOME` 의 옛 기록 파일을 옮기지 않았습니다. 옮긴 뒤 남은 파일이면 지워 주세요"
            );
            return Ok(None);
        }
        self.import_into(
            &mut transaction,
            &Old {
                state: &state,
                settings: &settings,
                vault: &vault,
                revoked: &revoked,
                drills: &drills,
                apps: &apps,
            },
            now,
        )
        .map_err(|error| {
            format!(
                "옛 기록을 control database 로 옮기지 못했습니다. 아무것도 적지 않았습니다. {error}"
            )
        })?;
        transaction
            .commit()
            .map_err(|_| "옛 기록을 옮기지 못했습니다. 아무것도 적지 않았습니다".to_owned())?;
        for name in present {
            let from = home.join(name);
            let to = home.join(format!("{name}.imported"));
            fs::rename(&from, &to).map_err(|_| {
                format!("옮긴 옛 기록 파일 `{name}` 의 이름을 바꾸지 못했습니다. 다시 옮기지 않게 `{name}.imported` 로 바꿔 주세요")
            })?;
        }
        Ok(Some(state.instances.len()))
    }

    fn import_into(
        &self,
        transaction: &mut Transaction<'_>,
        old: &Old<'_>,
        now: u64,
    ) -> Result<(), RecordError> {
        let now_signed = i64::try_from(now).unwrap_or(i64::MAX);
        for (organization, app) in old.apps {
            transaction
                .execute(
                    "INSERT INTO orbital.app (organization, name, machine, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    &[organization, app, &self.machine.as_str(), &now_signed],
                )
                .map_err(pg("앱을 옮기"))?;
        }
        // 옛 파일의 조직과 service key. sha256 을 그대로 옮겨 같은 비밀이 계속 통한다. 종류는 운영(`live`)이다
        for (organization, record) in &old.state.organizations {
            transaction
                .execute(
                    "INSERT INTO orbital.organization (id, name, kind, created_at) VALUES ($1, $2, 'live', $3)",
                    &[organization, &record.label, &signed(record.created_at)],
                )
                .map_err(pg("조직을 옮기"))?;
            for key in &record.keys {
                transaction
                    .execute(
                        "INSERT INTO orbital.service_key (id, organization, digest, label, created_at, revoked_at)
                         VALUES ($1, $2, $3, $4, $5, $6)",
                        &[
                            &key.id,
                            organization,
                            &key.digest,
                            &key.label,
                            &signed(key.created_at),
                            &key.revoked_at.map(signed),
                        ],
                    )
                    .map_err(pg("service key 를 옮기"))?;
            }
        }
        for (id, record) in &old.state.instances {
            let mut record = record.clone();
            record.machine = self.machine.as_str().to_owned();
            let body = self.encode(id, &record)?;
            transaction
                .execute(
                    "INSERT INTO orbital.instance (id, organization, app, machine, body) VALUES ($1, $2, $3, $4, $5::text::jsonb)",
                    &[id, &record.organization, &record.app, &record.machine, &body],
                )
                .map_err(pg("인스턴스를 옮기"))?;
            for (key, schedule) in &record.schedules {
                let next_at = i64::try_from(schedule.next_at).unwrap_or(i64::MAX);
                let last_run = schedule
                    .last_run
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(json("일정을 옮기"))?;
                transaction
                    .execute(
                        "INSERT INTO orbital.schedule (instance, key, next_at, last_run) VALUES ($1, $2, $3, $4::text::jsonb)",
                        &[id, key, &next_at, &last_run],
                    )
                    .map_err(pg("일정을 옮기"))?;
            }
        }
        for (id, record) in &old.state.rollouts {
            let body = serde_json::to_string(record).map_err(json("rollout 을 옮기"))?;
            transaction
                .execute(
                    "INSERT INTO orbital.rollout (id, organization, body) VALUES ($1, $2, $3::text::jsonb)",
                    &[id, &record.organization, &body],
                )
                .map_err(pg("rollout 을 옮기"))?;
        }
        for (organization, body) in old.settings {
            transaction
                .execute(
                    "INSERT INTO orbital.factory_settings (organization, body) VALUES ($1, $2::text::jsonb)",
                    &[organization, body],
                )
                .map_err(pg("팩토리의 설정을 옮기"))?;
        }
        crate::vault::import_old(transaction, old.vault)?;
        for (key, until) in old.revoked {
            let Some((instance, work)) = key.split_once('/') else {
                continue;
            };
            // 기억할 때가 지난 줄은 옮기지 않는다
            if *until <= now {
                continue;
            }
            let until = i64::try_from(*until).unwrap_or(i64::MAX);
            transaction
                .execute(
                    "INSERT INTO orbital.revoked_work (instance, work, until) VALUES ($1, $2, $3)",
                    &[&instance, &work, &until],
                )
                .map_err(pg("닫은 작업을 옮기"))?;
        }
        for record in old.drills {
            let body = serde_json::to_string(record).map_err(json("훈련의 기록을 옮기"))?;
            let at = i64::try_from(record.at).unwrap_or(i64::MAX);
            transaction
                .execute(
                    "INSERT INTO orbital.drill (at, passed, machine, body) VALUES ($1, $2, $3, $4::text::jsonb)",
                    &[&at, &record.passed, &self.machine.as_str(), &body],
                )
                .map_err(pg("훈련의 기록을 옮기"))?;
        }
        Ok(())
    }
}

/// 옛 파일에서 읽은 것.
struct Old<'a> {
    state: &'a State,
    settings: &'a [(String, String)],
    vault: &'a crate::vault::OldVault,
    revoked: &'a BTreeMap<String, u64>,
    drills: &'a [DrillRecord],
    apps: &'a [(String, String)],
}

/// `home/apps/<조직>/<앱>.git` 로 올라와 있던 앱들.
fn old_apps(home: &Path) -> Vec<(String, String)> {
    let mut found = BTreeSet::new();
    let Ok(organizations) = fs::read_dir(home.join("apps")) else {
        return Vec::new();
    };
    for organization in organizations.flatten() {
        let Ok(apps) = fs::read_dir(organization.path()) else {
            continue;
        };
        for app in apps.flatten() {
            let name = app.file_name().to_string_lossy().into_owned();
            if let Some(app) = name.strip_suffix(".git") {
                found.insert((
                    organization.file_name().to_string_lossy().into_owned(),
                    app.to_owned(),
                ));
            }
        }
    }
    found.into_iter().collect()
}
