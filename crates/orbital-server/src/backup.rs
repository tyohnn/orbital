//! 백업과 복구 훈련. 기반 백업을 뜨고 지난 것을 지우는 일, 사람 손 없이 끝까지 도는 복구 훈련 한 번, 훈련의 기록.
//!
//! 훈련은 관리 서버(`Layer`) 없이도 돈다(`orbitald drill`). 레이어의 기록(control database)은 읽고 훈련의 기록 한 줄만 더하며, 운영 클러스터에는
//! 훈련 전용 database(`orbital_drill`)와 잠깐 쓰는 임시 database 만 만든다. 인스턴스의 database 와 역할은 건드리지 않는다.
//!
//! 기록은 운영 클러스터 안(control database)에 있으므로 기반 백업과 WAL 에 함께 든다. 그래서 되살린 시점의 DB 와 그 시점의 기록이 같은 때의 것이다.
//! 기반 백업에 따로 묶는 것(`records.tar`)은 DB 에 없는 코드 저장소뿐이다. 열쇠(봉인 · service key · 토큰)는 어디에도 들지 않는다.
//!
//! 판정은 core 의 `backup` 이 한다(되살릴 수 있는 시점인지, 훈련이 통과했는지, 낡았는지, 무엇을 지울지).
//! 훈련의 기록(control database 의 `drill` 표)에는 이름과 숫자만 남는다. 행의 값 · 표식의 난수 · 경로 · Postgres 가 찍은 글은 남지 않는다.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orbital_backup::{
    Cluster, DatabaseName, Load, Store, databases, fingerprint, load_database, roles,
};
use orbital_core::access::Access;
use orbital_core::backup::{
    BaseBackup, Check, Checked, DrillFailure, DrillRecord, DrillStep, DrillVerdict, Fingerprint,
    judge_drill, judge_restore, prune,
};
use orbital_core::check::judge as judge_access;
use orbital_core::manifest::ValidManifest;
use orbital_core::name::InstanceId;
use orbital_core::plan::Names;
use orbital_pg::Admin;
use orbital_pg::rehearsal::RestorePoint;
use orbital_source::assemble::assemble;
use orbital_source::{Commit, SourceStore};
use postgres::{Client, Config, NoTls};

use crate::records::Records;

/// 운영 클러스터에 두는 훈련 전용 database. 훈련의 표식만 담는다.
pub const DRILL_DATABASE: &str = "orbital_drill";

/// 백업을 켠 레이어의 설정.
pub struct BackupOptions {
    /// 기반 백업과 WAL 을 두는 폴더(`ORBITAL_BACKUP_DIR`). 운영 클러스터의 `archive_command` 가 `<폴더>/wal` 에 복사해야 한다.
    pub root: PathBuf,
    /// 기반 백업을 두는 기간(`ORBITAL_BACKUP_KEEP_DAYS`, 기본 14일). 마지막 기반 백업은 기간이 지나도 남는다.
    pub keep_for: Duration,
    /// 훈련이 낡은 동안 새 인스턴스를 받지 않는다(`ORBITAL_REQUIRE_DRILL=1`).
    pub require_drill: bool,
}

impl BackupOptions {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            keep_for: Duration::from_secs(orbital_core::backup::KEEP_FOR),
            require_drill: false,
        }
    }
}

fn connect(url: &str) -> Result<Client, String> {
    let config: Config = url
        .parse()
        .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
    config
        .connect(NoTls)
        .map_err(|_| "운영 클러스터에 붙지 못했습니다".to_owned())
}

/// 운영 클러스터의 database 하나에 관리 역할로 붙는다.
fn connect_to(url: &str, database: &str) -> Result<Client, String> {
    let mut config: Config = url
        .parse()
        .map_err(|_| "DB 의 주소를 읽지 못했습니다".to_owned())?;
    config
        .dbname(database)
        .connect(NoTls)
        .map_err(|_| "운영 클러스터의 database 에 붙지 못했습니다".to_owned())
}

/// 운영 클러스터의 기반 백업을 하나 뜨고, 보관 기간이 지난 것을 지운다. 지금은 DB 의 시계(다 뜬 때)로 잰다.
pub fn take_base_backup(
    store: &dyn Store,
    home: &Path,
    pg_url: &str,
    keep_for: Duration,
) -> Result<BaseBackup, orbital_backup::Error> {
    let backup = store.base_backup(pg_url, home)?;
    let keep_for = u64::try_from(keep_for.as_millis()).unwrap_or(u64::MAX);
    let pruning = prune(&store.backups()?, backup.finished_at, keep_for);
    store.prune(&pruning)?;
    Ok(backup)
}

/// 훈련의 기록을 모두 읽는다. 읽지 못하면 비어 있다(낡은 것으로 본다).
pub fn history(records: &Records) -> Vec<DrillRecord> {
    records.drills().unwrap_or_default()
}

/// 훈련 한 번의 기록을 쌓는다.
pub fn append(records: &Records, record: &DrillRecord) -> Result<(), String> {
    records
        .append_drill(record)
        .map_err(|_| "훈련의 기록을 적지 못했습니다".to_owned())
}

/// 레이어의 기록에서 운영 중인 인스턴스. 훈련은 이것들의 database 를 견준다.
fn production_instances(records: &Records) -> Result<Vec<InstanceId>, String> {
    Ok(records
        .instances()
        .map_err(|error| error.0)?
        .iter()
        .filter(|(_, record)| record.production.is_some())
        .filter_map(|(id, _)| InstanceId::parse(id).ok())
        .collect())
}

/// 난수 hex. 훈련의 표식에 쓴다. 기록에는 남지 않는다.
fn nonce() -> Result<String, String> {
    use std::io::Read as _;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "난수를 읽지 못했습니다".to_owned())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// 훈련 전용 database 를 세운다(없으면). 아무에게도 접속을 주지 않는다.
fn prepare_drill_database(pg_url: &str) -> Result<Client, String> {
    let mut admin = connect(pg_url)?;
    let exists = admin
        .query_opt(
            "SELECT 1 FROM pg_database WHERE datname = $1",
            &[&DRILL_DATABASE],
        )
        .map_err(|_| "훈련 전용 database 를 찾지 못했습니다".to_owned())?
        .is_some();
    if !exists {
        admin
            .batch_execute(&format!("CREATE DATABASE \"{DRILL_DATABASE}\""))
            .map_err(|_| "훈련 전용 database 를 만들지 못했습니다".to_owned())?;
        admin
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE \"{DRILL_DATABASE}\" FROM PUBLIC"
            ))
            .map_err(|_| "훈련 전용 database 의 권한을 걷지 못했습니다".to_owned())?;
    }
    let mut drill = connect_to(pg_url, DRILL_DATABASE)?;
    drill
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS public.mark (nonce text PRIMARY KEY, at timestamptz NOT NULL DEFAULT clock_timestamp())",
        )
        .map_err(|_| "훈련의 표를 만들지 못했습니다".to_owned())?;
    Ok(drill)
}

fn write_mark(drill: &mut Client, nonce: &str) -> Result<(), String> {
    drill
        .execute("INSERT INTO public.mark (nonce) VALUES ($1)", &[&nonce])
        .map(|_| ())
        .map_err(|_| "훈련의 표식을 적지 못했습니다".to_owned())
}

fn has_mark(client: &mut Client, nonce: &str) -> bool {
    client
        .query_opt("SELECT 1 FROM public.mark WHERE nonce = $1", &[&nonce])
        .is_ok_and(|row| row.is_some())
}

/// 그 시점에 떠 둔 것. database 마다의 지문과 인스턴스마다의 역할.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Taken {
    prints: BTreeMap<String, Fingerprint>,
    roles: BTreeMap<String, Vec<String>>,
}

fn take(pg_url: &str, instances: &[InstanceId]) -> Result<Taken, String> {
    let mut prints = BTreeMap::new();
    let mut found_roles = BTreeMap::new();
    let mut admin = connect(pg_url)?;
    let present = databases(&mut admin).map_err(|error| error.to_string())?;
    for instance in instances {
        let names = Names::new(instance.clone());
        let database = names.database();
        if present.contains(&database) {
            let mut client = connect_to(pg_url, &database)?;
            prints.insert(
                database,
                fingerprint(&mut client).map_err(|error| error.to_string())?,
            );
        }
        found_roles.insert(
            instance.as_str().to_owned(),
            roles(&mut admin, &format!("{}_", names.prefix()))
                .map_err(|error| error.to_string())?,
        );
    }
    let mut drill = connect_to(pg_url, DRILL_DATABASE)?;
    prints.insert(
        DRILL_DATABASE.to_owned(),
        fingerprint(&mut drill).map_err(|error| error.to_string())?,
    );
    Ok(Taken {
        prints,
        roles: found_roles,
    })
}

fn db_now(client: &mut Client) -> Result<u64, String> {
    let millis: i64 = client
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .map_err(|_| "DB 의 시각을 읽지 못했습니다".to_owned())?
        .get(0);
    Ok(u64::try_from(millis).unwrap_or(0))
}

/// 잃을 수 있는 구간(초). 지금 − 마지막으로 보관된 WAL 의 시각. 보관된 것이 없으면 모른다.
fn exposure(pg_url: &str) -> Option<u64> {
    let mut client = connect(pg_url).ok()?;
    let seconds: Option<i64> = client
        .query_one(
            "SELECT extract(epoch FROM clock_timestamp() - last_archived_time)::bigint FROM pg_stat_archiver",
            &[],
        )
        .ok()?
        .get(0);
    seconds.map(|seconds| u64::try_from(seconds).unwrap_or(0))
}

/// 훈련의 결과를 모으는 것.
struct Run {
    started: Instant,
    record: DrillRecord,
}

impl Run {
    fn fail(mut self, failure: DrillFailure) -> DrillRecord {
        self.record.passed = false;
        self.record.failure = Some(failure);
        self.record.drill_millis = millis(self.started);
        self.record
    }
}

fn millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// 복구 훈련 한 번. 사람 손 없이 끝까지 돌고, 어떻게 끝났든 기록을 돌려준다(쌓는 것은 부른 쪽이 한다).
///
/// ① 훈련 전용 database 에 표식을 적고 지문을 뜬 뒤 시점 T 를 잡고, T 뒤에 표식을 하나 더 적는다
/// ② WAL 을 넘겨 보관을 확인한다 ③ 옆에 T 로 클러스터 전체를 되살린다
/// ④ 클러스터가 뜨는지, T 앞의 표식이 있고 뒤의 것이 없는지, 인스턴스마다 database · 지문 · 역할이 T 의 것과 같은지, 기록이 풀리는지 본다
/// ⑤ database 하나를 운영 클러스터의 임시 database 로 옮겨 지문을 견준다(인스턴스 하나를 되살리는 절차) ⑥ 옆의 클러스터와 파일을 지운다.
pub fn drill(store: &dyn Store, records: &Records, home: &Path, now: u64) -> DrillRecord {
    let pg_url = records.pg_url();
    let mut run = Run {
        started: Instant::now(),
        record: DrillRecord {
            at: now,
            passed: false,
            checks: Vec::new(),
            recovery_millis: 0,
            drill_millis: 0,
            exposure_seconds: exposure(pg_url),
            instances: 0,
            failure: None,
        },
    };
    let step = |step| DrillFailure::Step { step };

    // 기반 백업이 하나도 없으면 먼저 뜬다
    match store.backups() {
        Ok(backups) if !backups.is_empty() => {}
        Ok(_) => {
            if store.base_backup(pg_url, home).is_err() {
                return run.fail(step(DrillStep::BaseBackup));
            }
        }
        Err(_) => return run.fail(step(DrillStep::BaseBackup)),
    }

    // ① 표식과 지문, 시점 T
    let Ok(instances) = production_instances(records) else {
        return run.fail(step(DrillStep::Mark));
    };
    run.record.instances = instances.len();
    let Ok((before, after, at, taken)) = mark(pg_url, &instances) else {
        return run.fail(step(DrillStep::Mark));
    };

    // ② 보관을 확인한다
    if store.seal(pg_url).is_err() {
        return run.fail(step(DrillStep::Seal));
    }

    // ③ 옆에 되살린다
    let (Ok(backups), Ok(archive)) = (store.backups(), store.archive()) else {
        return run.fail(step(DrillStep::Recover));
    };
    let backup = match judge_restore(&backups, &archive, at) {
        Ok(backup) => backup.clone(),
        Err(refusal) => return run.fail(DrillFailure::Refused { refusal }),
    };
    let recovering = Instant::now();
    let side = match store.recover(&backup, at) {
        Ok(side) => side,
        Err(orbital_backup::Error::Recovery(failure)) => {
            run.record.recovery_millis = millis(recovering);
            return run.fail(DrillFailure::Recovery { failure });
        }
        Err(_) => return run.fail(step(DrillStep::Recover)),
    };
    run.record.recovery_millis = millis(recovering);

    // ④ ⑤ 확인
    run.record.checks = inspect(
        &Scene {
            store,
            home,
            records,
        },
        &side,
        &backup,
        &instances,
        (&before, &after),
        &taken,
    );

    // ⑥ 옆의 클러스터와 파일을 지운다
    drop(side);
    if store.restores_left() > 0 {
        return run.fail(step(DrillStep::Clean));
    }

    match judge_drill(&run.record.checks) {
        DrillVerdict::Passed => {
            run.record.passed = true;
            run.record.drill_millis = millis(run.started);
            run.record
        }
        DrillVerdict::Failed { failed } => run.fail(DrillFailure::Checks { failed }),
    }
}

/// 표식 둘과 그 사이의 시점 T, T 에 떠 둔 것. (앞의 표식, 뒤의 표식, T, 떠 둔 것).
fn mark(pg_url: &str, instances: &[InstanceId]) -> Result<(String, String, u64, Taken), String> {
    let mut drill = prepare_drill_database(pg_url)?;
    let before = nonce()?;
    write_mark(&mut drill, &before)?;
    // T 의 앞뒤로 뜬 지문이 같아야 T 의 모습이 그것이다. 그 사이에 운영이 쓰면 다시 잡는다
    let mut tries = 0;
    let (at, taken) = loop {
        let first = take(pg_url, instances)?;
        std::thread::sleep(Duration::from_millis(5));
        let at = db_now(&mut drill)?;
        std::thread::sleep(Duration::from_millis(5));
        let second = take(pg_url, instances)?;
        tries += 1;
        if first == second || tries >= 5 {
            break (at, first);
        }
    };
    let after = nonce()?;
    write_mark(&mut drill, &after)?;
    Ok((before, after, at, taken))
}

fn checked(check: Check, passed: bool) -> Checked {
    Checked { check, passed }
}

/// 옆의 클러스터에서 확인하고, database 하나를 옮겨 견준다.
/// 훈련이 도는 자리. 백업을 두는 곳, 코드 저장소가 있는 폴더, 레이어의 기록(과 운영 클러스터의 관리 주소).
struct Scene<'a> {
    store: &'a dyn Store,
    home: &'a Path,
    records: &'a Records,
}

fn inspect(
    scene: &Scene<'_>,
    side: &Cluster,
    backup: &BaseBackup,
    instances: &[InstanceId],
    (before, after): (&str, &str),
    taken: &Taken,
) -> Vec<Checked> {
    let Scene {
        store,
        home,
        records,
    } = *scene;
    let pg_url = records.pg_url();
    let mut checks = Vec::new();
    let started = side.connect("postgres");
    checks.push(checked(Check::ClusterStarted, started.is_ok()));
    let present = started
        .ok()
        .and_then(|mut client| databases(&mut client).ok())
        .unwrap_or_default();

    let mut drill = side.connect(DRILL_DATABASE).ok();
    checks.push(checked(
        Check::MarkBeforeKept,
        drill
            .as_mut()
            .is_some_and(|client| has_mark(client, before)),
    ));
    checks.push(checked(
        Check::MarkAfterGone,
        drill
            .as_mut()
            .is_some_and(|client| !has_mark(client, after)),
    ));
    drop(drill);

    let print_of = |database: &str| -> Option<Fingerprint> {
        let mut client = side.connect(database).ok()?;
        fingerprint(&mut client).ok()
    };
    for instance in instances {
        let names = Names::new(instance.clone());
        let database = names.database();
        let subject = instance.as_str().to_owned();
        let has = present.contains(&database);
        checks.push(checked(
            Check::Database {
                instance: subject.clone(),
            },
            has && taken.prints.contains_key(&database),
        ));
        checks.push(checked(
            Check::Fingerprint {
                instance: subject.clone(),
            },
            has && print_of(&database)
                .is_some_and(|print| taken.prints.get(&database) == Some(&print)),
        ));
        let side_roles = side
            .connect("postgres")
            .ok()
            .and_then(|mut client| roles(&mut client, &format!("{}_", names.prefix())).ok());
        let expected = taken.roles.get(&subject);
        checks.push(checked(
            Check::Roles { instance: subject },
            side_roles.is_some_and(|found| expected == Some(&found) && !found.is_empty()),
        ));
    }

    // 기록이 읽힌다. 옆의 클러스터의 control database 에서 그 시점의 운영 인스턴스가 T 의 것과 같고, 코드 저장소의 묶음이 풀린다
    let unpacked = side.root().join("records");
    let side_instances = side
        .connect(records.database().as_str())
        .ok()
        .and_then(|mut client| {
            client
                .query(
                    "SELECT id FROM orbital.instance WHERE body -> 'production' IS NOT NULL AND body ->> 'production' <> 'null'",
                    &[],
                )
                .ok()
        })
        .map(|rows| {
            rows.iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<BTreeSet<String>>()
        });
    let expected: BTreeSet<String> = instances
        .iter()
        .map(|instance| instance.as_str().to_owned())
        .collect();
    // 훈련은 다른 일을 막지 않는다. 목록을 읽은 뒤 표식까지의 사이에 운영에 오른 인스턴스가 있으면 옆의 것이 더 많다. 빠진 것만 틀린 것이다
    let readable = side_instances.is_some_and(|found| expected.is_subset(&found))
        && store.records(backup, &unpacked).is_ok();
    checks.push(checked(Check::Records, readable));

    // ⑤ 인스턴스 하나를 되살리기와 같은 절차로 운영 클러스터의 임시 database 에 세워 견준다. 코드 저장소가 이 기계에 있는 것(이 기계에 놓인 것)만
    // 고른다. 그런 인스턴스가 없으면 훈련 전용 database 를 옮긴다
    let here: BTreeSet<String> = records
        .instances()
        .map(|all| {
            all.into_iter()
                .filter(|(_, record)| record.machine == records.machine())
                .map(|(id, _)| id)
                .collect()
        })
        .unwrap_or_default();
    let sample = instances.iter().find(|instance| {
        here.contains(instance.as_str())
            && taken
                .prints
                .contains_key(&Names::new((*instance).clone()).database())
    });
    match sample {
        Some(instance) => {
            let database = Names::new(instance.clone()).database();
            let passed =
                rebuilt_matches(side, records, home, instance, taken.prints.get(&database));
            checks.push(checked(Check::Moved { database }, passed));
        }
        None => checks.push(checked(
            Check::Moved {
                database: DRILL_DATABASE.to_owned(),
            },
            drill_copy_matches(side, pg_url, taken.prints.get(DRILL_DATABASE)),
        )),
    }
    checks
}

/// 되살린 database 를 세울 것. 이름(`names`)은 옆 이름이어야 한다([`Names::staged`]).
pub struct Rebuild<'a> {
    pub names: &'a Names,
    pub manifest: &'a ValidManifest,
    pub access: &'a Access,
    /// 인스턴스의 서명 열쇠. 운영과 같은 열쇠를 둔다.
    pub identity_key: &'a [u8],
    pub pg_url: &'a str,
}

/// 옆의 클러스터에 되살린 인스턴스의 database 를 운영 클러스터의 옆 이름에 다시 세우고 권한 검사를 지난다. 깨지면 세우던 것을 지운다.
///
/// **앱의 정의를 관리 권한으로 되풀이하지 않는다.** 레이어의 것(database · 스키마 · `orbital` · `orbital_auth`)은 새 인스턴스를 세울 때처럼
/// 레이어의 계획으로 세우고, 앱의 스키마는 마이그레이션 역할이 소유자가 되어, `orbital_auth` 는 행만 인증 역할로 넣는다. 권한은 권한 표대로 다시 세운다.
pub fn rebuild(
    admin: &mut Admin,
    side: &Cluster,
    source: &DatabaseName,
    plan: &Rebuild<'_>,
) -> Result<(), String> {
    let names = plan.names;
    // 운영 자리를 가리키면 깨졌을 때 운영 DB 를 지우게 된다. 옆 이름만 받는다
    if names.database() == names.prefix() {
        return Err("되살린 DB 는 운영 자리가 아니라 옆 이름에 세웁니다".to_owned());
    }
    let built = build(admin, side, source, plan);
    if built.is_err() {
        let _ = admin.forget(RestorePoint::named(names.database()));
    }
    built
}

fn build(
    admin: &mut Admin,
    side: &Cluster,
    source: &DatabaseName,
    plan: &Rebuild<'_>,
) -> Result<(), String> {
    let (names, manifest) = (plan.names, plan.manifest);
    let text = |error: orbital_pg::Error| error.to_string();
    admin.provision(names, manifest).map_err(text)?;
    admin
        .install_identity(names, plan.identity_key)
        .map_err(text)?;
    admin.install_auth(names, manifest).map_err(text)?;
    let target = DatabaseName::parse(&names.database()).map_err(|error| error.to_string())?;
    let schemas: Vec<String> = manifest
        .get()
        .database
        .schemas
        .iter()
        .map(|schema| schema.as_str().to_owned())
        .collect();
    let (owner, migrator, auth) = (names.owner(), names.migrator(), names.auth());
    load_database(
        side,
        source,
        &Load {
            admin_url: plan.pg_url,
            database: &target,
            schemas: &schemas,
            owner: &owner,
            migrator: &migrator,
            auth: manifest.get().auth.is_some().then_some(auth.as_str()),
        },
    )
    .map_err(|error| error.to_string())?;
    admin.grant(names, manifest, plan.access).map_err(text)?;
    let snapshot = admin.snapshot(names).map_err(text)?;
    let findings: Vec<String> = judge_access(names, manifest, plan.access, &snapshot)
        .iter()
        .map(ToString::to_string)
        .collect();
    if findings.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "되살린 DB 가 권한 검사를 통과하지 못했습니다: {}",
            findings.join(" / ")
        ))
    }
}

/// 운영 중인 인스턴스의 지금 release 의 선언 · 권한 표와 서명 열쇠. 레이어의 기록과 코드 저장소에서 읽는다.
pub fn production_plan(
    records: &Records,
    home: &Path,
    instance: &InstanceId,
) -> Option<(orbital_source::assemble::Assembled, Vec<u8>)> {
    let record = records.instance(instance.as_str()).ok()??;
    let production = record.production.as_ref()?;
    let commit = Commit::parse(&record.releases.get(&production.release)?.commit)?;
    let assembled = assemble(&SourceStore::new(home.join("sources")), instance, &commit).ok()?;
    let key = crate::token::unhex(&production.identity_key)?;
    Some((assembled, key))
}

/// 인스턴스 하나를 되살리기와 같은 절차로 운영 클러스터의 임시 database 에 세우고, 지문을 그 시점의 것과 견준 뒤 지운다.
fn rebuilt_matches(
    side: &Cluster,
    records: &Records,
    home: &Path,
    instance: &InstanceId,
    expected: Option<&Fingerprint>,
) -> bool {
    let pg_url = records.pg_url();
    let (Some((assembled, key)), Ok(nonce)) = (production_plan(records, home, instance), nonce())
    else {
        return false;
    };
    let names = Names::new(instance.clone());
    let (Some(staged), Ok(source), Ok(mut admin)) = (
        names.staged(&format!("drill_{}", &nonce[..10])),
        DatabaseName::parse(&names.database()),
        Admin::connect(pg_url),
    ) else {
        return false;
    };
    let plan = Rebuild {
        names: &staged,
        manifest: &assembled.manifest,
        access: &assembled.access,
        identity_key: &key,
        pg_url,
    };
    if rebuild(&mut admin, side, &source, &plan).is_err() {
        return false;
    }
    let same = connect_to(pg_url, &staged.database())
        .ok()
        .and_then(|mut client| fingerprint(&mut client).ok())
        .is_some_and(|print| Some(&print) == expected);
    admin.forget(RestorePoint::named(staged.database())).is_ok() && same
}

/// 훈련 전용 database 를 운영 클러스터의 임시 database 로 옮겨 지문을 견준 뒤 지운다. 레이어가 만든 표 하나라 정의는 레이어가 세우고 행만 옮긴다.
fn drill_copy_matches(side: &Cluster, pg_url: &str, expected: Option<&Fingerprint>) -> bool {
    let Ok(nonce) = nonce() else {
        return false;
    };
    let target = format!("{DRILL_DATABASE}_copy_{}", &nonce[..10]);
    let Ok(mut admin) = connect(pg_url) else {
        return false;
    };
    let copied = (|| -> Result<bool, String> {
        let fail = |_| "훈련 전용 database 를 옮기지 못했습니다".to_owned();
        admin
            .batch_execute(&format!("CREATE DATABASE \"{target}\""))
            .map_err(fail)?;
        admin
            .batch_execute(&format!("REVOKE ALL ON DATABASE \"{target}\" FROM PUBLIC"))
            .map_err(fail)?;
        let mut into = connect_to(pg_url, &target)?;
        into.batch_execute(
            "CREATE TABLE public.mark (nonce text PRIMARY KEY, at timestamptz NOT NULL DEFAULT clock_timestamp())",
        )
        .map_err(fail)?;
        let mut from = side
            .connect(DRILL_DATABASE)
            .map_err(|error| error.to_string())?;
        for row in from
            .query("SELECT nonce, at FROM public.mark", &[])
            .map_err(fail)?
        {
            let (nonce, at): (String, std::time::SystemTime) = (row.get(0), row.get(1));
            into.execute(
                "INSERT INTO public.mark (nonce, at) VALUES ($1, $2)",
                &[&nonce, &at],
            )
            .map_err(fail)?;
        }
        let print = fingerprint(&mut into).map_err(|error| error.to_string())?;
        Ok(Some(&print) == expected)
    })();
    let dropped = admin
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS \"{target}\" WITH (FORCE)"
        ))
        .is_ok();
    copied.unwrap_or(false) && dropped
}
