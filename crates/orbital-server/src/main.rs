//! `orbitald`: 관리 서버를 띄운다.
//!
//! 설정은 환경 변수로 받는다.
//! - `ORBITAL_HOME`: 레이어가 저장소 · 빌드 · 기록을 두는 폴더
//! - `ORBITAL_PG`: DB 의 관리 주소
//! - `ORBITAL_SERVICE_KEYS`: `조직=열쇠,조직=열쇠`. 부트스트랩의 service key. 조직이 API 로 만든 키는 기록에 있다
//! - `ORBITAL_ADMIN_KEY`: 운영자 키(32바이트 이상). 조직을 만들고 첫 키를 낸다(`/v1/admin/…`). 대시보드가 가입을 받을 때 쓴다.
//!   `ORBITAL_SERVICE_KEYS` 와 이것 가운데 하나는 있어야 한다
//! - `ORBITAL_LISTEN`: 듣는 주소(기본 `127.0.0.1:7400`)
//! - `ORBITAL_PUBLIC_URL`: 레이어의 바깥 주소(기본 `http://<ORBITAL_LISTEN>`). Google 의 콜백이 `<바깥 주소>/v1/auth/google/callback` 에 서고,
//!   팩토리는 이 주소 하나를 Google 콘솔에 등록한다
//!   비밀의 입력 표(`<바깥 주소>/v1/secret-entries/<표>`)도 이 아래에 선다. 사람의 브라우저가 바로 닿는 주소여야 한다
//! - `ORBITAL_SEAL_KEY`: 팩토리가 넣은 키(Resend · Google)와 밖에서 넣는 비밀(금고, `ORBITAL_HOME/vault.json`)을 봉인하는 열쇠.
//!   32바이트를 hex 64자로. 없으면 팩토리가 설정과 비밀의 값을 넣지 못하고(409), 밖에서 넣는 비밀을 선언한 release 는 운영에 오르지 못한다.
//!   기록(`ORBITAL_HOME`)과 다른 자리에 둔다. 바꾸면 앞에서 넣은 키와 값이 풀리지 않아 다시 넣어야 한다
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
//! - `ORBITAL_DRILL_EVERY`: 복구 훈련을 돌리는 주기(초, 기본 604800 = 7일). 결과는 `ORBITAL_HOME/drills.jsonl` 에 쌓는다
//! - `ORBITAL_REQUIRE_DRILL`: `1` 이면 마지막으로 통과한 훈련이 여드레를 넘겼거나 한 번도 통과하지 않은 동안 새 인스턴스를 받지 않는다.
//!   이미 선 인스턴스의 프리뷰와 승격은 막지 않는다
//!
//! `orbitald drill` 은 복구 훈련을 한 번만 돌리고 끝난다. 관리 서버가 떠 있어도 함께 돌 수 있다(`ORBITAL_HOME` · `ORBITAL_PG` ·
//! `ORBITAL_BACKUP_DIR` 만 읽는다). 훈련이 실패하면 0 이 아닌 코드로 끝나고, 기록 한 줄(이름과 숫자만)을 찍는다.
//!
//! 다시 뜨면 기록에서 운영 중인 인스턴스의 router 를 자는 채로 다시 세운다(첫 요청에 깬다). 프리뷰는 되살리지 않는다.
//!
//! 메일은 팩토리가 넣은 Resend 의 키와 보내는 주소로 나가고, Google 로그인은 팩토리가 넣은 Google 클라이언트로 돈다.
//! 레이어는 공용 발송 도메인도 공용 Google 클라이언트도 갖지 않는다.
//!
//! 지금의 실행기는 개발용이다. 앱을 이 기계의 프로세스로 돌리고 격리하지 않는다.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use orbital_core::host::{BaseDomain, Scheme};

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

/// `orbitald drill`: 복구 훈련을 한 번 돌린다. 통과하면 참이다.
fn drill_once() -> Result<bool, String> {
    let home = std::path::PathBuf::from(setting("ORBITAL_HOME")?);
    let pg_url = setting("ORBITAL_PG")?;
    let tools = orbital_backup::Tools::find().map_err(|error| error.to_string())?;
    let store = orbital_backup::LocalStore::open(tools, setting("ORBITAL_BACKUP_DIR")?.into())
        .map_err(|error| format!("백업의 폴더를 열지 못했습니다. {error}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let record = orbital_server::backup::drill(&store, &home, &pg_url, now);
    orbital_server::backup::append(&home, &record)?;
    // 기록 한 줄. 이름과 숫자만 있다
    println!(
        "{}",
        serde_json::to_string(&record).map_err(|_| "기록을 적지 못했습니다".to_owned())?
    );
    Ok(record.passed)
}

fn start() -> Result<(), String> {
    let admin_key = std::env::var("ORBITAL_ADMIN_KEY").ok();
    if admin_key.as_ref().is_some_and(|key| key.len() < 32) {
        return Err(
            "`ORBITAL_ADMIN_KEY` 는 32바이트 이상이어야 합니다. `openssl rand -hex 32` 로 만들어 주세요".to_owned(),
        );
    }
    let service_keys = std::env::var("ORBITAL_SERVICE_KEYS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(organization, key)| (key.trim().to_owned(), organization.trim().to_owned()))
        .collect::<Vec<_>>();
    if service_keys.is_empty() && admin_key.is_none() {
        return Err(
            "`ORBITAL_SERVICE_KEYS` 를 `조직=열쇠` 모양으로 적거나 `ORBITAL_ADMIN_KEY` 를 적어 주세요".to_owned(),
        );
    }
    let listen = std::env::var("ORBITAL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7400".to_owned());
    let seal_key = match std::env::var("ORBITAL_SEAL_KEY") {
        Ok(text) => Some(SealKey::from_hex(&text).ok_or_else(|| {
            "`ORBITAL_SEAL_KEY` 는 32바이트를 hex 64자로 적어야 합니다. `openssl rand -hex 32` 로 만들어 주세요".to_owned()
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
    let drill_every = seconds("ORBITAL_DRILL_EVERY", 7 * 24 * 60 * 60)?;
    let tending = backup.is_some();
    let layer = Layer::open(Options {
        admin_key,
        backup,
        seal_key,
        public_url,
        dev_mailbox,
        sleep_after,
        hosting,
        ..Options::new(
            setting("ORBITAL_HOME")?.into(),
            setting("ORBITAL_PG")?,
            service_keys,
            Box::new(LocalRunner::default()),
        )
    })?;
    let server =
        tiny_http::Server::http(&listen).map_err(|_| format!("`{listen}` 에서 듣지 못했습니다"))?;
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
