//! 레이어에 닿는 명령. 에이전트가 sandbox 에서 토큰으로 부른다.
//!
//! 토큰은 환경 변수로 받는다. 토큰에는 운영을 바꾸는 능력이 없어서, 이 명령들을 에이전트에게 그대로 쥐여 줘도 된다.
//! 코드는 묶음(git bundle)으로 주고받는다. 레이어 쪽에 git 서버가 없어도 되고, 에이전트는 받은 폴더에서 평소대로 git 을 쓴다.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::{Outcome, fail};

pub(crate) struct Remote {
    url: String,
    instance: String,
    token: String,
}

/// 받은 묶음의 상한.
const MAX_BUNDLE: u64 = 64 * 1024 * 1024;

fn git(folder: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(folder)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "git 을 실행하지 못했습니다".to_owned())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("orbital-{}-{name}.bundle", std::process::id()))
}

/// 서버가 돌려준 오류를 사람이 읽는 글로 옮긴다.
fn explain(status: u16, body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return format!("레이어가 {status} 로 답했습니다\n");
    };
    let mut text = format!(
        "{}\n",
        value["message"]
            .as_str()
            .unwrap_or("레이어가 요청을 받지 않았습니다")
    );
    for detail in value["details"].as_array().into_iter().flatten() {
        for line in detail.as_str().unwrap_or_default().lines() {
            text.push_str(&format!("  {line}\n"));
        }
    }
    text
}

impl Remote {
    pub(crate) fn from_env() -> Result<Self, String> {
        let setting = |name: &str| {
            std::env::var(name).map_err(|_| format!("환경 변수 `{name}` 이 없습니다. 레이어에 닿는 명령은 주소 · 인스턴스 · 토큰이 있어야 합니다\n"))
        };
        Ok(Self {
            url: setting("ORBITAL_URL")?.trim_end_matches('/').to_owned(),
            instance: setting("ORBITAL_INSTANCE")?,
            token: setting("ORBITAL_TOKEN")?,
        })
    }

    fn call(&self, method: &str, tail: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let request = ureq::request(
            method,
            &format!("{}/v1/instances/{}/{tail}", self.url, self.instance),
        )
        .set("Authorization", &format!("Bearer {}", self.token));
        let response = match body {
            Some(body) => request.send_bytes(body),
            None => request.call(),
        };
        let (status, response) = match response {
            Ok(response) => (response.status(), response),
            Err(ureq::Error::Status(status, response)) => (status, response),
            Err(_) => return Err(format!("레이어(`{}`)에 닿지 못했습니다\n", self.url)),
        };
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_BUNDLE)
            .read_to_end(&mut bytes)
            .map_err(|_| "레이어의 답을 끝까지 받지 못했습니다\n".to_owned())?;
        if (200..300).contains(&status) {
            Ok(bytes)
        } else {
            Err(explain(status, &bytes))
        }
    }

    fn json(&self, method: &str, tail: &str, body: Option<Value>) -> Result<Value, String> {
        let body = body.map(|value| value.to_string().into_bytes());
        let bytes = self.call(method, tail, body.as_deref())?;
        serde_json::from_slice(&bytes).map_err(|_| "레이어의 답을 읽지 못했습니다\n".to_owned())
    }

    fn fetch_bundle(&self, name: &str) -> Result<PathBuf, String> {
        let file = scratch(name);
        fs::write(&file, self.call("GET", "source", None)?)
            .map_err(|_| "받은 코드를 적지 못했습니다\n".to_owned())?;
        Ok(file)
    }

    fn clone(&self, folder: &str) -> Result<String, String> {
        let bundle = self.fetch_bundle("clone")?;
        let cloned = git(
            Path::new("."),
            &["clone", "--quiet", &bundle.to_string_lossy(), folder],
        );
        let _ = fs::remove_file(&bundle);
        cloned.map_err(|error| format!("받은 코드를 폴더에 꺼내지 못했습니다:\n  {error}\n"))?;
        Ok(format!(
            "`{folder}` 에 코드를 받았습니다. 고친 뒤 commit 하고 `orbital push` 로 올립니다.\n"
        ))
    }

    fn pull(&self) -> Result<String, String> {
        let bundle = self.fetch_bundle("pull")?;
        let pulled = git(
            Path::new("."),
            &[
                "pull",
                "--quiet",
                "--no-rebase",
                &bundle.to_string_lossy(),
                "main",
            ],
        );
        let _ = fs::remove_file(&bundle);
        pulled.map_err(|error| format!("레이어의 최신 commit 을 합치지 못했습니다. 겹친 곳을 고쳐 commit 해 주세요:\n  {error}\n"))?;
        Ok("레이어의 최신 commit 을 받아 합쳤습니다.\n".to_owned())
    }

    fn push(&self) -> Result<String, String> {
        let dirty = git(Path::new("."), &["status", "--porcelain"])
            .map_err(|error| format!("git 저장소가 아닙니다:\n  {error}\n"))?;
        let bundle = scratch("push");
        git(
            Path::new("."),
            &[
                "bundle",
                "create",
                "--quiet",
                &bundle.to_string_lossy(),
                "main",
            ],
        )
        .map_err(|error| format!("올릴 묶음을 만들지 못했습니다:\n  {error}\n"))?;
        let bytes = fs::read(&bundle).map_err(|_| "올릴 묶음을 읽지 못했습니다\n".to_owned());
        let _ = fs::remove_file(&bundle);
        let reply: Value = serde_json::from_slice(&self.call("POST", "source", Some(&bytes?))?)
            .map_err(|_| "레이어의 답을 읽지 못했습니다\n".to_owned())?;
        let mut text = format!(
            "올렸습니다. commit {}\n",
            reply["commit"].as_str().unwrap_or_default()
        );
        if !dirty.is_empty() {
            text.push_str("commit 하지 않은 변경은 올라가지 않았습니다.\n");
        }
        Ok(text)
    }

    fn preview(&self) -> Result<String, String> {
        let report = self.json("POST", "previews", None)?;
        let lines = |key: &str| -> Vec<String> {
            report[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|line| line.as_str().map(str::to_owned))
                .collect()
        };
        let mut text = format!(
            "미리보기가 섰습니다. release {}\n",
            report["release"].as_str().unwrap_or_default()
        );
        for service in report["services"].as_array().into_iter().flatten() {
            match service["url"].as_str() {
                Some(url) => text.push_str(&format!(
                    "  {} → {url}\n",
                    service["name"].as_str().unwrap_or_default()
                )),
                None => text.push_str(&format!(
                    "  {} (정적 파일)\n",
                    service["name"].as_str().unwrap_or_default()
                )),
            }
        }
        for (title, key) in [
            ("권한 검사에서 어긋난 것", "findings"),
            ("운영과 견준 권한의 변화(승인 카드에 섭니다)", "changes"),
            ("승격을 막는 것", "blockers"),
        ] {
            let found = lines(key);
            if !found.is_empty() {
                text.push_str(&format!("{title}:\n"));
                for line in found {
                    text.push_str(&format!("  - {line}\n"));
                }
            }
        }
        if lines("blockers").is_empty() {
            text.push_str("막는 것이 없습니다. `orbital request-promotion <release>` 로 승격을 요청할 수 있습니다.\n");
        }
        Ok(text)
    }

    fn identity(&self, subject: &str) -> Result<String, String> {
        let reply = self.json(
            "POST",
            "previews/identities",
            Some(json!({ "subject": subject })),
        )?;
        Ok(format!(
            "{}\n",
            reply["identity"].as_str().unwrap_or_default()
        ))
    }

    fn rehearse(&self, release: &str) -> Result<String, String> {
        let report = self.json("POST", "rehearsals", Some(json!({ "release": release })))?;
        if report["needed"].as_bool() != Some(true) {
            return Ok("운영에 돌릴 마이그레이션이 없어 예행연습이 필요 없습니다.\n".to_owned());
        }
        let mut text = if report["passed"].as_bool() == Some(true) {
            format!("예행연습이 통과했습니다({} ms).\n", report["millis"])
        } else {
            format!(
                "예행연습이 실패했습니다. `{}` 에서 멈췄습니다(SQLSTATE {}). 운영의 데이터에서만 나는 문제일 수 있습니다.\n",
                report["failed_at"].as_str().unwrap_or_default(),
                report["sqlstate"].as_str().unwrap_or("모름")
            )
        };
        for table in report["tables"].as_array().into_iter().flatten() {
            text.push_str(&format!(
                "  {}: {}행 → {}행\n",
                table[0].as_str().unwrap_or_default(),
                table[1],
                table[2]
            ));
        }
        Ok(text)
    }

    fn request_promotion(&self, release: &str) -> Result<String, String> {
        self.json(
            "POST",
            "promotion-requests",
            Some(json!({ "release": release })),
        )?;
        Ok("승격을 요청했습니다. 사람이 승인하면 운영에 오릅니다.\n".to_owned())
    }

    pub(crate) fn run(&self, command: &str, argument: Option<&str>) -> Outcome {
        let need = |what: &str| argument.ok_or_else(|| format!("{what} 적어 주세요\n"));
        let result = match command {
            "clone" => need("받을 폴더를").and_then(|folder| self.clone(folder)),
            "pull" => self.pull(),
            "push" => self.push(),
            "preview" => self.preview(),
            "identity" => need("씨앗 데이터의 사람을").and_then(|subject| self.identity(subject)),
            "rehearse" => need("release 를").and_then(|release| self.rehearse(release)),
            "request-promotion" => {
                need("release 를").and_then(|release| self.request_promotion(release))
            }
            _ => Err("모르는 명령입니다\n".to_owned()),
        };
        match result {
            Ok(text) => Outcome { text, ok: true },
            Err(text) => fail(text),
        }
    }
}
