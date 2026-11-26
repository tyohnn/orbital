//! `orbitald`: 관리 서버를 띄운다.
//!
//! 설정은 환경 변수로 받는다.
//! - `ORBITAL_HOME`: 레이어가 저장소 · 빌드 · 기록을 두는 폴더
//! - `ORBITAL_PG`: DB 의 관리 주소
//! - `ORBITAL_SERVICE_KEYS`: `조직=열쇠,조직=열쇠`. 팩토리의 서버가 쓰는 service key
//! - `ORBITAL_LISTEN`: 듣는 주소(기본 `127.0.0.1:7400`)
//! - `ORBITAL_PUBLIC_URL`: 레이어의 바깥 주소(기본 `http://<ORBITAL_LISTEN>`). Google 의 콜백이 `<바깥 주소>/v1/auth/google/callback` 에 서고,
//!   팩토리는 이 주소 하나를 Google 콘솔에 등록한다
//!   비밀의 입력 표(`<바깥 주소>/v1/secret-entries`, 표는 `Authorization: Bearer`)도 이 아래에 선다. 사람의 브라우저가 바로 닿는 주소여야 한다
//! - `ORBITAL_CONTROL_DB`: 레이어의 기록을 두는 database 의 이름(기본 `orbital_control`). `ORBITAL_PG` 의 클러스터 안에 두고, 없으면 세운다.
//!   같은 이름을 보는 관리 서버들은 같은 기록을 본다. 인스턴스의 어떤 역할도 이 database 에 접속하지 못한다(`PUBLIC` 의 접속을 걷는다)
//! - `ORBITAL_MACHINE`: 이 관리 서버의 기계 이름(기본 `local`, 소문자 · 숫자 · 밑줄 24자까지). 이 서버가 세운 인스턴스가 이 기계에 놓이고,
//!   그 인스턴스의 코드 저장소 · 빌드 · 프로세스에 닿는 일(git · 프리뷰 · 승격 · 되살리기 · 지우기)은 이 기계의 관리 서버만 한다.
//!   다른 기계의 관리 서버는 그 기계의 주소(`ORBITAL_MACHINE_URL`)를 알면 요청을 그대로 넘기고, 모르면 421 과 놓인 기계의 이름으로 답한다.
//!   다시 뜰 때는 이 기계에 놓인 운영만 되살린다.
//!   같은 이름으로는 관리 서버가 하나만 뜬다. 살아 있는 것이 있으면 5초 기다려 본 뒤 뜨지 않는다(다른 기계에는 다른 이름을 준다)
//! - `ORBITAL_MACHINE_URL`: 다른 관리 서버에서 닿는 이 관리 서버의 주소(`http://10.0.0.5:7400` 처럼 스킴 · 호스트 · 포트만). 뜰 때 기록에 적고,
//!   다른 기계가 받은 이 기계에 놓인 인스턴스의 요청(git · 프리뷰 · 승격 · 앱 올리기 · 인스턴스 만들기 같은)을 이리로 넘긴다. 넘긴 요청에는
//!   `x-orbital-forwarded-by` 가 붙고, 그런 요청은 다시 넘기지 않는다(그 머리말은 권한을 주지 않는다. 토큰과 service key 는 여기서 다시 판정한다).
//!   주지 않으면 기록의 주소를 비우고, 다른 기계는 421 로 답한다. 연결을 맺는 데 5초를 넘기면 502(`machine_unreachable`)다.
//!   이 주소는 관리 서버끼리만 닿는 망에 둔다. 관리 서버들은 같은 service key 와 `ORBITAL_TOKEN_KEY` 를 받아야 넘겨진 요청이 통한다
//! - `ORBITAL_MACHINE_ROUTER_URL`: 다른 관리 서버에서 닿는 이 기계의 공용 listener(`ORBITAL_ROUTER_LISTEN`)의 주소(`http://` 만).
//!   하위 도메인을 쓰는 레이어에서, 다른 기계가 받은 이 기계에 놓인 인스턴스의 고객 요청을 이리로 날것 그대로 넘긴다(세션과 신원은 이 기계의 router 가 본다).
//!   주지 않으면 다른 기계는 그 하위 도메인에 404 로 답한다
//! - `ORBITAL_TOKEN_KEY`: 작업의 토큰과 Google 의 `state` 에 서명하는 열쇠(32바이트 이상을 hex 로). 관리 서버가 여럿이면 모두 같은 값을 준다.
//!   없으면 `ORBITAL_HOME/token.key` 를 쓴다(없으면 만든다). 기록(control database)과 백업에는 두지 않는다
//! - `ORBITAL_SEAL_KEY`: 팩토리가 넣은 키(Resend · Google), 밖에서 넣는 비밀(금고), 운영의 신원 열쇠와 레이어가 만든 비밀을 기록에 봉인하는 열쇠.
//!   32바이트를 hex 64자로. 없으면 팩토리가 설정과 비밀의 값을 넣지 못하고(409), 밖에서 넣는 비밀을 선언한 release 는 운영에 오르지 못한다.
//!   열쇠가 없는 레이어는 개발용 모양이라 운영의 신원 열쇠와 레이어가 만든 비밀을 평문으로 적고 뜰 때 그렇다고 알린다. 열쇠를 준 뒤 처음 뜨면
//!   평문이던 줄을 봉인으로 바꾼다. 기록(control database)과 다른 자리에 둔다. 바꾸면 앞에서 넣은 키와 값이 풀리지 않아 다시 넣어야 한다
//! - `ORBITAL_DEV_MAIL`: `outbox` 일 때만 개발용 메일함을 켠다. 팩토리의 메일 키가 없어도 운영에 오르고, 로그인 링크를 보내지 않고
//!   `ORBITAL_HOME/outbox.jsonl`(주인만 읽는 파일)에 한 줄씩 쌓는다. 테스트가 이 파일에서 링크를 꺼낸다. 운영의 레이어에서는 켜지 않는다
//! - `ORBITAL_SLEEP_AFTER`: 마지막 요청이 끝난 뒤 이 초만큼 요청이 없으면 서버 서비스의 프로세스를 내린다(기본 300). 다음 요청에 깬다
//! - `ORBITAL_BASE_DOMAIN`: 기준 도메인(`apps.factory.example`, 로컬이면 `orbital.localhost:7480` 처럼 바깥 포트까지). 주면
//!   `<인스턴스>.<기준 도메인>` 이 운영, `<인스턴스>-preview.<기준 도메인>` 이 프리뷰의 주소가 되고, 모든 인스턴스의 요청을
//!   `ORBITAL_ROUTER_LISTEN` 하나에서 받아 `Host` 로 가른다. 주지 않으면 인스턴스마다 `127.0.0.1` 의 포트 하나를 낸다
//! - `ORBITAL_ROUTER_LISTEN`: 하위 도메인의 요청을 받는 주소(기본 `127.0.0.1:7480`). TLS 는 이 앞에서 끝낸다
//! - `ORBITAL_PUBLIC_SCHEME`: 하위 도메인의 바깥 스킴. `https`(기본) 이거나 로컬의 `http`
//! - `ORBITAL_BACKUP_DIR`: 기반 백업과 WAL 을 두는 폴더. 주면 백업과 복구 훈련을 켠다. 운영 클러스터는 `archive_mode = on` 이고
//!   `archive_command` 가 `<폴더>/wal` 에 복사해야 한다(켜지 않았으면 적을 명령을 알리고 뜨지 않는다)
//! - `ORBITAL_BACKUP_KEEP_DAYS`: 기반 백업을 두는 날 수(기본 14). 마지막 기반 백업은 기간이 지나도 남는다
//! - `ORBITAL_BACKUP_EVERY`: 기반 백업을 뜨는 주기(초, 기본 86400)
//! - `ORBITAL_DRILL_EVERY`: 복구 훈련을 돌리는 주기(초, 기본 604800 = 7일). 결과는 control database 의 `orbital.drill` 표에 쌓는다.
//!   관리 서버가 여럿이면 기반 백업과 훈련은 그 가운데 하나만 돌린다(advisory lock)
//! - `ORBITAL_REQUIRE_DRILL`: `1` 이면 마지막으로 통과한 훈련이 여드레를 넘겼거나 한 번도 통과하지 않은 동안 새 인스턴스를 받지 않는다.
//!   이미 선 인스턴스의 프리뷰와 승격은 막지 않는다
//! - `ORBITAL_BUILD_ENV`: 빌드에만 건넬 환경 변수의 이름을 쉼표로 가른 것(`HTTPS_PROXY,NODE_EXTRA_CA_CERTS,npm_config_registry` 같은 것).
//!   값은 이 프로세스의 환경에서 읽는다. 빌드는 그 밖의 환경을 받지 못해 레지스트리에 닿으려면 프록시와 CA 묶음을 여기에 적는다.
//!   빌드는 에이전트가 쓴 코드를 돌리므로 여기에 적은 값은 그 코드가 읽는다. `ORBITAL_` · `PG` 로 시작하는 이름과 `PATH` · `HOME` 은 받지 않는다.
//!   서버를 띄울 때와 적합성 테스트에는 건네지 않는다
//!
//! - `ORBITAL_SCHEDULE_TIMEOUT`: 선언의 일정(`[[schedule]]`)으로 부른 요청에 앱이 답하기를 기다리는 초(기본 600). 넘으면 시간 초과로 적고
//!   다시 부르지 않는다. 일정은 1분마다 보고, 운영의 인스턴스만 그 시각(UTC)에 부른다
//!
//! `orbitald drill` 은 복구 훈련을 한 번만 돌리고 끝난다. 관리 서버가 떠 있어도 함께 돌 수 있다(`ORBITAL_HOME` · `ORBITAL_PG` ·
//! `ORBITAL_BACKUP_DIR` · `ORBITAL_CONTROL_DB` · `ORBITAL_MACHINE` · `ORBITAL_SEAL_KEY` 만 읽는다). 다른 관리 서버가 백업이나 훈련을 돌리는 중이면 돌리지 않고 실패로 끝난다.
//! 훈련이 실패하면 0 이 아닌 코드로 끝나고, 기록 한 줄(이름과 숫자만)을 찍는다.
//!
//! 기록은 control database 에 있다. `ORBITAL_HOME` 에 옛 기록 파일(`registry.json` · `settings.json` · `vault.json` · `revoked.json` ·
//! `drills.jsonl`)이 있고 control database 가 비어 있으면 처음 뜰 때 한 번 옮기고 `*.imported` 로 이름을 바꾼다. 옮기다 실패하면 아무것도 적지 않고 뜨지 않는다.
//! `ORBITAL_HOME` 에는 이 기계의 것(코드 저장소 · 빌드 · 캐시 · 로그 · 개발용 메일함 · 토큰의 열쇠)만 남는다.
//!
//! 다시 뜨면 기록에서 이 기계에 놓인 운영 중인 인스턴스의 router 를 자는 채로 다시 세운다(첫 요청에 깬다). 프리뷰는 되살리지 않는다.
//!
//! 메일은 팩토리가 넣은 Resend 의 키와 보내는 주소로 나가고, Google 로그인은 팩토리가 넣은 Google 클라이언트로 돈다.
//! 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않는다.
//!
//! 지금의 실행기는 개발용이다. 앱을 이 기계의 프로세스로 돌리고 격리하지 않는다.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use orbital_core::host::{BaseDomain, Scheme};
use orbital_core::name::Ident;

use orbital_run::LocalRunner;
use orbital_server::backup::BackupOptions;
use orbital_server::http::serve;
use orbital_server::layer::{Hosting, Layer, Options};
use orbital_server::seal::SealKey;

fn setting(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("환경 변수 `{name}` 이 없습니다"))
}

/// 초로 적은 설정. 없으면 기본값이다.
fn seconds(name: &str, default: u64) -> Result<Duration, String> {
    match std::env::var(name) {
        Err(_) => Ok(Duration::from_secs(default)),
        Ok(text) => text
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .ok_or_else(|| format!("`{name}` 는 1 이상의 초로 적어 주세요(기본 {default})")),
    }
}

/// 백업의 설정. `ORBITAL_BACKUP_DIR` 이 없으면 백업하지 않는다.
fn backup_options() -> Result<Option<BackupOptions>, String> {
    let Ok(root) = std::env::var("ORBITAL_BACKUP_DIR") else {
        if std::env::var("ORBITAL_REQUIRE_DRILL").is_ok_and(|on| on == "1") {
            return Err(
                "`ORBITAL_REQUIRE_DRILL=1` 은 백업을 켠 레이어에서만 씁니다. `ORBITAL_BACKUP_DIR` 을 적어 주세요".to_owned(),
            );
        }
        return Ok(None);
    };
    let mut options = BackupOptions::new(root.into());
    if let Ok(days) = std::env::var("ORBITAL_BACKUP_KEEP_DAYS") {
        let days = days
            .parse::<u64>()
            .ok()
            .filter(|days| *days > 0)
            .ok_or_else(|| {
                "`ORBITAL_BACKUP_KEEP_DAYS` 는 1 이상의 날 수로 적어 주세요(기본 14)".to_owned()
            })?;
        options.keep_for = Duration::from_secs(days * 24 * 60 * 60);
    }
    options.require_drill = match std::env::var("ORBITAL_REQUIRE_DRILL") {
        Ok(on) if on == "1" => true,
        Ok(on) if on == "0" => false,
        Ok(_) => return Err("`ORBITAL_REQUIRE_DRILL` 은 `1` 이나 `0` 만 받습니다".to_owned()),
        Err(_) => false,
    };
    Ok(Some(options))
}

/// 봉인의 열쇠(`ORBITAL_SEAL_KEY`). 없으면 `None` 이다.
fn seal_key() -> Result<Option<SealKey>, String> {
    match std::env::var("ORBITAL_SEAL_KEY") {
        Ok(text) => Ok(Some(SealKey::from_hex(&text).ok_or_else(|| {
            "`ORBITAL_SEAL_KEY` 는 32바이트를 hex 64자로 적어야 합니다. `openssl rand -hex 32` 로 만들어 주세요".to_owned()
        })?)),
        Err(_) => Ok(None),
    }
}

/// 이름으로 쓰는 설정. 없으면 기본값이다.
fn name(variable: &str, default: &str) -> Result<Ident, String> {
    let text = std::env::var(variable).unwrap_or_else(|_| default.to_owned());
    Ident::parse(&text).map_err(|problem| {
        format!("`{variable}` 는 영문 소문자로 시작하고 소문자 · 숫자 · 밑줄만 쓰는 24자 안의 이름이어야 합니다({problem})")
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `orbitald drill`: 복구 훈련을 한 번 돌린다. 통과하면 참이다.
fn drill_once() -> Result<bool, String> {
    let home = std::path::PathBuf::from(setting("ORBITAL_HOME")?);
    let pg_url = setting("ORBITAL_PG")?;
    let tools = orbital_backup::Tools::find().map_err(|error| error.to_string())?;
    let store = orbital_backup::LocalStore::open(tools, setting("ORBITAL_BACKUP_DIR")?.into())
        .map_err(|error| format!("백업의 폴더를 열지 못했습니다. {error}"))?;
    let records = orbital_server::records::Records::open(
        &pg_url,
        &name(
            "ORBITAL_CONTROL_DB",
            orbital_server::records::CONTROL_DATABASE,
        )?,
        &name("ORBITAL_MACHINE", orbital_server::records::DEFAULT_MACHINE)?,
        // 인스턴스 하나를 되살려 보려면 기록의 신원 열쇠를 풀어야 한다
        seal_key()?,
        now(),
    )?;
    if let Some(count) = records.import(&home, now())? {
        eprintln!(
            "orbitald drill: 옛 기록 파일을 control database 로 옮겼습니다(인스턴스 {count}개)"
        );
    }
    // 여러 관리 서버 가운데 하나만 돌린다
    let Some(_turn) = records.take_backup_turn().map_err(|error| error.0)? else {
        return Err("다른 관리 서버가 기반 백업이나 복구 훈련을 돌리는 중입니다. 끝난 뒤에 다시 돌려 주세요".to_owned());
    };
    let record = orbital_server::backup::drill(&store, &records, &home, now());
    orbital_server::backup::append(&records, &record)?;
    // 기록 한 줄. 이름과 숫자만 있다
    println!(
        "{}",
        serde_json::to_string(&record).map_err(|_| "기록을 적지 못했습니다".to_owned())?
    );
    Ok(record.passed)
}

fn start() -> Result<(), String> {
    let service_keys = setting("ORBITAL_SERVICE_KEYS")?
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(organization, key)| (key.trim().to_owned(), organization.trim().to_owned()))
        .collect::<Vec<_>>();
    if service_keys.is_empty() {
        return Err("`ORBITAL_SERVICE_KEYS` 를 `조직=열쇠` 모양으로 적어 주세요".to_owned());
    }
    let listen = std::env::var("ORBITAL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7400".to_owned());
    let seal_key = seal_key()?;
    let previous_seal_key = match std::env::var("ORBITAL_SEAL_KEY_PREVIOUS") {
        Ok(text) => Some(SealKey::from_hex(&text).ok_or_else(|| {
            "`ORBITAL_SEAL_KEY_PREVIOUS` 는 앞에 쓰던 `ORBITAL_SEAL_KEY` 를 그대로(hex 64자) 적어야 합니다".to_owned()
        })?),
        Err(_) => None,
    };
    let dev_mailbox = match std::env::var("ORBITAL_DEV_MAIL") {
        Ok(mode) if mode == "outbox" => true,
        Ok(_) => {
            return Err(
                "`ORBITAL_DEV_MAIL` 은 `outbox` 만 받습니다. 개발용 메일함을 쓰지 않으려면 지워 주세요".to_owned(),
            );
        }
        Err(_) => false,
    };
    let public_url =
        std::env::var("ORBITAL_PUBLIC_URL").unwrap_or_else(|_| format!("http://{listen}"));
    let sleep_after = match std::env::var("ORBITAL_SLEEP_AFTER") {
        Ok(text) => Duration::from_secs(
            text.parse::<u64>()
                .ok()
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| {
                    "`ORBITAL_SLEEP_AFTER` 는 1 이상의 초로 적어 주세요(기본 300)".to_owned()
                })?,
        ),
        Err(_) => Duration::from_secs(5 * 60),
    };
    let wake_queue = match std::env::var("ORBITAL_WAKE_QUEUE") {
        Ok(text) => text
            .parse::<usize>()
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                "`ORBITAL_WAKE_QUEUE` 는 1 이상의 수로 적어 주세요(기본 128)".to_owned()
            })?,
        Err(_) => 128,
    };
    let hosting = match std::env::var("ORBITAL_BASE_DOMAIN") {
        Err(_) => None,
        Ok(text) => {
            let base = BaseDomain::parse(&text)
                .map_err(|problem| format!("`ORBITAL_BASE_DOMAIN`: {problem}"))?;
            let scheme = match std::env::var("ORBITAL_PUBLIC_SCHEME") {
                Err(_) => Scheme::Https,
                Ok(text) => Scheme::parse(&text).ok_or_else(|| {
                    "`ORBITAL_PUBLIC_SCHEME` 은 `https` 나 `http` 만 받습니다".to_owned()
                })?,
            };
            Some(Hosting {
                listen: std::env::var("ORBITAL_ROUTER_LISTEN")
                    .unwrap_or_else(|_| "127.0.0.1:7480".to_owned()),
                base,
                scheme,
            })
        }
    };
    let backup = backup_options()?;
    let backup_every = seconds("ORBITAL_BACKUP_EVERY", 24 * 60 * 60)?;
    let schedule_timeout = seconds("ORBITAL_SCHEDULE_TIMEOUT", 10 * 60)?;
    let drill_every = seconds("ORBITAL_DRILL_EVERY", 7 * 24 * 60 * 60)?;
    let build_env = orbital_run::build_env(
        &std::env::var("ORBITAL_BUILD_ENV").unwrap_or_default(),
        |name| std::env::var(name).ok(),
    )
    .map_err(|problem| format!("`ORBITAL_BUILD_ENV`: {problem}"))?;
    let tending = backup.is_some();
    let token_key = match std::env::var("ORBITAL_TOKEN_KEY") {
        Ok(text) => Some(
            orbital_server::token::unhex(text.trim())
                .filter(|key| key.len() >= 32)
                .ok_or_else(|| {
                    "`ORBITAL_TOKEN_KEY` 는 32바이트 이상을 hex 로 적어야 합니다. `openssl rand -hex 32` 로 만들고 모든 관리 서버에 같은 값을 주세요".to_owned()
                })?,
        ),
        Err(_) => None,
    };
    let no_seal_key = seal_key.is_none();
    let layer = Layer::open(Options {
        backup,
        seal_key,
        previous_seal_key,
        public_url,
        dev_mailbox,
        sleep_after,
        wake_queue,
        hosting,
        schedule_timeout,
        control_database: name(
            "ORBITAL_CONTROL_DB",
            orbital_server::records::CONTROL_DATABASE,
        )?,
        machine: name("ORBITAL_MACHINE", orbital_server::records::DEFAULT_MACHINE)?,
        token_key,
        machine_url: std::env::var("ORBITAL_MACHINE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty()),
        machine_router_url: std::env::var("ORBITAL_MACHINE_ROUTER_URL")
            .ok()
            .filter(|url| !url.trim().is_empty()),
        ..Options::new(
            setting("ORBITAL_HOME")?.into(),
            setting("ORBITAL_PG")?,
            service_keys,
            Box::new(LocalRunner {
                build_env,
                ..LocalRunner::default()
            }),
        )
    })?;
    let server =
        tiny_http::Server::http(&listen).map_err(|_| format!("`{listen}` 에서 듣지 못했습니다"))?;
    if let Some(resealed) = layer.resealed() {
        // 줄의 수와 이름만 찍는다. 값은 없다
        eprintln!(
            "orbitald: 봉인을 새 열쇠로 다시 했습니다(설정 {}줄 · 금고 {}줄 · 운영 {}칸). 확인했으면 `ORBITAL_SEAL_KEY_PREVIOUS` 를 빼고 다시 띄워 주세요",
            resealed.settings, resealed.vault, resealed.production
        );
        for name in &resealed.unopened {
            eprintln!("orbitald: 어느 열쇠로도 풀리지 않아 그대로 둔 줄: {name}");
        }
    }
    if no_seal_key {
        eprintln!(
            "orbitald: 봉인의 열쇠(`ORBITAL_SEAL_KEY`)가 없는 개발용 모양입니다. 운영의 신원 열쇠와 레이어가 만든 비밀을 기록에 평문으로 적습니다. 운영의 레이어에서는 열쇠를 주세요"
        );
    } else if layer.sealed_plaintext() > 0 {
        eprintln!(
            "orbitald: 평문이던 운영의 신원 열쇠 · 레이어가 만든 비밀 {}칸을 봉인했습니다",
            layer.sealed_plaintext()
        );
    }
    eprintln!(
        "orbitald: 기계 `{}` 로 control database `{}` 의 기록을 씁니다",
        layer.machine(),
        layer.records().database().as_str()
    );
    eprintln!("orbitald: http://{listen} 에서 듣습니다");
    if let Some(address) = layer.router_address() {
        eprintln!("orbitald: 인스턴스의 하위 도메인은 {address} 에서 받습니다");
    }
    if dev_mailbox {
        eprintln!(
            "orbitald: 개발용 메일함을 켰습니다. 팩토리의 메일 키가 없으면 메일을 보내지 않고 파일에 쌓습니다"
        );
    }
    let layer = Arc::new(layer);
    if tending {
        eprintln!("orbitald: 백업을 켰습니다. 기반 백업과 복구 훈련을 정한 주기로 돌립니다");
        let tended = Arc::clone(&layer);
        std::thread::spawn(move || {
            loop {
                tended.tend(backup_every, drill_every);
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }
    // 일정: 분이 바뀔 때마다 때가 된 것을 부른다. 부르는 일은 따로 된 스레드에서 돌아 이 고리를 막지 않는다
    let scheduled = Arc::clone(&layer);
    std::thread::spawn(move || {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            std::thread::sleep(Duration::from_secs(60 - now % 60));
            drop(scheduled.call_schedules());
        }
    });
    serve(layer, server);
    Ok(())
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("drill") {
        return match drill_once() {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(message) => {
                eprintln!("orbitald drill: {message}");
                ExitCode::FAILURE
            }
        };
    }
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("orbitald: {message}");
            ExitCode::FAILURE
        }
    }
}
