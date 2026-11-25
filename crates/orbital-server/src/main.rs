//! `orbitald`: 관리 서버를 띄운다.
//!
//! 설정은 환경 변수로 받는다.
//! - `ORBITAL_HOME`: 레이어가 저장소 · 빌드 · 기록을 두는 폴더
//! - `ORBITAL_PG`: DB 의 관리 주소
//! - `ORBITAL_SERVICE_KEYS`: `조직=열쇠,조직=열쇠`. 팩토리의 서버가 쓰는 service key
//! - `ORBITAL_LISTEN`: 듣는 주소(기본 `127.0.0.1:7400`)
//!
//! 지금의 실행기는 개발용이다. 앱을 이 기계의 프로세스로 돌리고 격리하지 않는다.

use std::process::ExitCode;
use std::sync::Arc;

use orbital_run::LocalRunner;
use orbital_server::http::serve;
use orbital_server::layer::{Layer, Options};

fn setting(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("환경 변수 `{name}` 이 없습니다"))
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
    let layer = Layer::open(Options {
        home: setting("ORBITAL_HOME")?.into(),
        pg_url: setting("ORBITAL_PG")?,
        service_keys,
        runner: Box::new(LocalRunner::default()),
    })?;
    let listen = std::env::var("ORBITAL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7400".to_owned());
    let server =
        tiny_http::Server::http(&listen).map_err(|_| format!("`{listen}` 에서 듣지 못했습니다"))?;
    eprintln!("orbitald: http://{listen} 에서 듣습니다");
    serve(Arc::new(layer), server);
    Ok(())
}

fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("orbitald: {message}");
            ExitCode::FAILURE
        }
    }
}
