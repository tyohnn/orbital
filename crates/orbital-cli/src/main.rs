//! `orbital`: 에이전트가 sandbox 에서 쓰는 CLI.
//!
//! 명령은 두 갈래다. 서버에 닿지 않는 명령(`check` · `plan` · `diff`)은 선언(`orbital.toml`)과 권한 표(`db/access.toml`)를
//! 올리기 전에 검사하고, 세워질 역할과 권한을 미리 보고, 권한의 변화를 승인 카드에 설 문장으로 본다. 판정은 모두 `orbital-core` 가 한다.
//! 레이어에 닿는 명령(`clone` · `push` · `preview` …)은 `remote` 모듈에 있고 토큰으로 부른다.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use orbital_core::access::{Access, RawAccess};
use orbital_core::describe::changes;
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::{InstanceId, TableRef};
use orbital_core::plan::{Names, grants, logins, provision};

mod remote;

const USAGE: &str = "\
orbital check [폴더]                         선언과 권한 표를 검사한다
orbital plan [폴더] --instance <식별자>      세워질 역할과 권한을 SQL 로 본다
orbital diff <앞의 access.toml> [폴더]       권한의 변화를 문장으로 본다
orbital --version

레이어에 닿는 명령(ORBITAL_URL · ORBITAL_INSTANCE · ORBITAL_TOKEN 이 있어야 한다):
orbital clone <폴더>                         코드를 이력째 받는다
orbital pull                                 레이어의 최신 commit 을 받아 합친다
orbital push                                 commit 을 올린다
orbital preview                              올린 commit 을 빌드해 미리보기를 세운다
orbital identity <사용자>                    미리보기의 씨앗 사용자로 들어가 요청에 붙일 Cookie 값을 받는다
orbital rehearse <release>                   운영 사본에 마이그레이션을 예행연습한다
orbital request-promotion <release>          승격을 요청한다. 승인은 사람이 한다
";

/// 명령 하나의 결과. 글과 종료 코드다.
pub(crate) struct Outcome {
    pub(crate) text: String,
    pub(crate) ok: bool,
}

pub(crate) fn fail(text: impl Into<String>) -> Outcome {
    Outcome {
        text: text.into(),
        ok: false,
    }
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|_| {
        format!(
            "`{}` 을 읽지 못했습니다. 파일이 있는지 확인해 주세요",
            path.display()
        )
    })
}

fn load_manifest(folder: &Path) -> Result<ValidManifest, String> {
    let path = folder.join("orbital.toml");
    let manifest: Manifest = toml::from_str(&read(&path)?)
        .map_err(|error| format!("`{}` 을 읽지 못했습니다:\n{error}", path.display()))?;
    manifest.check().map_err(|problems| {
        let mut text = format!(
            "`{}` 에 고칠 것이 {}개 있습니다:\n",
            path.display(),
            problems.len()
        );
        for problem in problems {
            let _ = writeln!(text, "  - {problem}");
        }
        text
    })
}

fn load_access(path: &Path, manifest: &ValidManifest) -> Result<Access, String> {
    let raw: RawAccess = toml::from_str(&read(path)?)
        .map_err(|error| format!("`{}` 을 읽지 못했습니다:\n{error}", path.display()))?;
    Access::parse(&raw, manifest).map_err(|problems| {
        let mut text = format!(
            "`{}` 에 고칠 것이 {}개 있습니다:\n",
            path.display(),
            problems.len()
        );
        for problem in problems {
            let _ = writeln!(text, "  - {problem}");
        }
        text
    })
}

fn load(folder: &Path) -> Result<(ValidManifest, Access), String> {
    let manifest = load_manifest(folder)?;
    // database 를 쓰지 않는 앱은 권한 표가 없어도 된다
    let path = folder.join("db/access.toml");
    let access = if manifest.get().database.schemas.is_empty() && !path.exists() {
        Access::default()
    } else {
        load_access(&path, &manifest)?
    };
    Ok((manifest, access))
}

fn check(folder: &Path) -> Outcome {
    match load(folder) {
        Err(text) => fail(text),
        Ok((manifest, access)) => {
            let manifest = manifest.get();
            let mut text = String::from("선언과 권한 표가 맞습니다.\n");
            let _ = writeln!(
                text,
                "  서비스 {}개, 스키마 {}개, 업무 역할 {}개, 권한 표의 표 {}개",
                manifest.services.len(),
                manifest.database.schemas.len(),
                manifest.database.roles.len(),
                access.tables.len()
            );
            let external = &manifest.secrets.external;
            if !external.is_empty() {
                let names: Vec<&str> = external.iter().map(|name| name.as_str()).collect();
                let _ = writeln!(
                    text,
                    "  사람이 한 번 넣어야 하는 비밀: {}",
                    names.join(", ")
                );
            }
            Outcome { text, ok: true }
        }
    }
}

fn plan(folder: &Path, instance: &str) -> Outcome {
    let instance = match InstanceId::parse(instance) {
        Ok(instance) => instance,
        Err(error) => return fail(format!("인스턴스의 식별자 `{instance}`: {error}\n")),
    };
    let (manifest, access) = match load(folder) {
        Ok(loaded) => loaded,
        Err(text) => return fail(text),
    };
    let names = Names::new(instance);
    // 실제 DB 가 없으므로 권한 표에 적힌 표가 모두 있다고 보고 계획을 낸다
    let tables: Vec<TableRef> = access.tables.keys().cloned().collect();
    let mut text = String::from("-- 인스턴스를 처음 세울 때\n");
    for step in provision(&names, &manifest) {
        let _ = writeln!(text, "{};", step.sql());
    }
    text.push_str("\n-- 마이그레이션 뒤에 권한 표대로\n");
    for step in grants(&names, &manifest, &access, &tables) {
        let _ = writeln!(text, "{};", step.sql());
    }
    text.push_str("\n-- 서비스가 업무 역할로 들어갈 때의 로그인(비밀번호는 없다)\n");
    for login in logins(&names, &manifest) {
        let _ = writeln!(
            text,
            "-- {} · {} → {}",
            login.service, login.role, login.name
        );
    }
    Outcome { text, ok: true }
}

fn diff(before: &Path, folder: &Path) -> Outcome {
    let (manifest, after) = match load(folder) {
        Ok(loaded) => loaded,
        Err(text) => return fail(text),
    };
    let before = match load_access(before, &manifest) {
        Ok(before) => before,
        Err(text) => return fail(text),
    };
    let found = changes(&before, &after);
    if found.is_empty() {
        return Outcome {
            text: "권한이 달라지지 않습니다.\n".to_owned(),
            ok: true,
        };
    }
    let mut text = format!("권한이 {}곳 달라집니다:\n", found.len());
    for change in found {
        let _ = writeln!(text, "  - {}", change.sentence);
    }
    Outcome { text, ok: true }
}

fn run(args: &[String]) -> Outcome {
    let folder = |at: usize| {
        args.get(at)
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    };
    match args.first().map(String::as_str) {
        Some("--version") => Outcome {
            text: format!("orbital {}\n", env!("CARGO_PKG_VERSION")),
            ok: true,
        },
        Some("check") => check(&folder(1)),
        Some("plan") => match args
            .iter()
            .position(|arg| arg == "--instance")
            .and_then(|at| args.get(at + 1))
        {
            Some(instance) => {
                let folder = match args.get(1) {
                    Some(first) if first != "--instance" => PathBuf::from(first),
                    _ => PathBuf::from("."),
                };
                plan(&folder, instance)
            }
            None => fail("`--instance <식별자>` 를 적어 주세요\n"),
        },
        Some("diff") => match args.get(1) {
            Some(before) => diff(Path::new(before), &folder(2)),
            None => {
                fail("앞의 권한 표 파일을 적어 주세요: orbital diff <앞의 access.toml> [폴더]\n")
            }
        },
        Some(
            command @ ("clone" | "pull" | "push" | "preview" | "identity" | "rehearse"
            | "request-promotion"),
        ) => match remote::Remote::from_env() {
            Ok(remote) => remote.run(command, args.get(1).map(String::as_str)),
            Err(text) => fail(text),
        },
        _ => fail(USAGE),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = run(&args);
    if outcome.ok {
        print!("{}", outcome.text);
        ExitCode::SUCCESS
    } else {
        eprint!("{}", outcome.text);
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(name: &str) -> String {
        format!("{}/../../examples/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// 본보기를 고쳐 쓴 임시 폴더.
    fn altered(name: &str, edit: impl Fn(&str, &str) -> (String, String)) -> PathBuf {
        let source = PathBuf::from(example("hr-nest-vite"));
        let folder =
            std::env::temp_dir().join(format!("orbital-cli-{}-{name}", std::process::id()));
        fs::create_dir_all(folder.join("db")).unwrap();
        let manifest = fs::read_to_string(source.join("orbital.toml")).unwrap();
        let access = fs::read_to_string(source.join("db/access.toml")).unwrap();
        let (manifest, access) = edit(&manifest, &access);
        fs::write(folder.join("orbital.toml"), manifest).unwrap();
        fs::write(folder.join("db/access.toml"), access).unwrap();
        folder
    }

    #[test]
    fn 본보기_둘은_검사를_통과한다() {
        for name in ["hr-nest-vite", "todo-next"] {
            let outcome = run(&args(&["check", &example(name)]));
            assert!(outcome.ok, "{name}: {}", outcome.text);
        }
    }

    #[test]
    fn 검사는_사람이_넣어야_하는_비밀의_이름을_알려_준다() {
        let outcome = run(&args(&["check", &example("hr-nest-vite")]));
        assert!(outcome.text.contains("BANK_API_KEY"));
        assert!(!outcome.text.contains("SESSION_KEY"));
    }

    #[test]
    fn 선언에_문제가_있으면_무엇을_고칠지와_함께_실패한다() {
        let folder = altered("bad-manifest", |manifest, access| {
            (
                manifest.replace("start = \"npm run start -w api\"\n", ""),
                access.to_owned(),
            )
        });
        let outcome = run(&args(&["check", folder.to_str().unwrap()]));
        assert!(!outcome.ok);
        assert!(
            outcome.text.contains("실행 명령(`start`)이 없습니다"),
            "{}",
            outcome.text
        );
    }

    #[test]
    fn 권한_표에_빠진_역할이_있으면_어떻게_적을지와_함께_실패한다() {
        let folder = altered("bad-access", |manifest, access| {
            (
                manifest.to_owned(),
                access.replace("manager = \"none\"\n", ""),
            )
        });
        let outcome = run(&args(&["check", folder.to_str().unwrap()]));
        assert!(!outcome.ok);
        assert!(
            outcome
                .text
                .contains("`manager = \"none\"` 이라고 적어 주세요"),
            "{}",
            outcome.text
        );
    }

    #[test]
    fn 파일이_없으면_어느_파일인지_알려_준다() {
        let outcome = run(&args(&["check", "/nonexistent-orbital-folder"]));
        assert!(!outcome.ok);
        assert!(outcome.text.contains("orbital.toml"));
    }

    #[test]
    fn 계획은_비밀번호가_없는_sql_이다() {
        let outcome = run(&args(&[
            "plan",
            &example("hr-nest-vite"),
            "--instance",
            "k3f9x2ab",
        ]));
        assert!(outcome.ok, "{}", outcome.text);
        assert!(
            outcome
                .text
                .contains("CREATE ROLE \"i_k3f9x2ab_s_api_employee\" LOGIN")
        );
        assert!(outcome.text.contains(
            "GRANT SELECT ON TABLE \"payroll\".\"payslip\" TO \"i_k3f9x2ab_r_employee\""
        ));
        assert!(!outcome.text.to_uppercase().contains("PASSWORD"));
        // 정적 서비스는 DB 에 닿지 않는다
        assert!(!outcome.text.contains("_s_web_"));
    }

    #[test]
    fn 계획은_식별자가_규칙에_맞지_않으면_내지_않는다() {
        let outcome = run(&args(&[
            "plan",
            &example("hr-nest-vite"),
            "--instance",
            "Acme Corp",
        ]));
        assert!(!outcome.ok);
    }

    #[test]
    fn 권한의_변화를_문장으로_낸다() {
        let folder = altered("diff", |manifest, access| {
            (
                manifest.to_owned(),
                access.replace("manager = \"none\"", "manager = \"read\""),
            )
        });
        let before = format!("{}/db/access.toml", example("hr-nest-vite"));
        let outcome = run(&args(&["diff", &before, folder.to_str().unwrap()]));
        assert!(outcome.ok, "{}", outcome.text);
        assert!(
            outcome
                .text
                .contains("`manager` 역할이 `payroll.payslip` 표를 읽을 수 있게 됩니다"),
            "{}",
            outcome.text
        );
        let same = run(&args(&["diff", &before, &example("hr-nest-vite")]));
        assert_eq!(same.text, "권한이 달라지지 않습니다.\n");
    }

    #[test]
    fn 모르는_명령에는_쓰는_법을_보인다() {
        let outcome = run(&args(&["deploy"]));
        assert!(!outcome.ok);
        assert!(outcome.text.contains("orbital check"));
    }
}
