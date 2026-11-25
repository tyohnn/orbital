//! 레이어의 기록을 기반 백업에 묶는다. DB 만 되살리면 기록(인스턴스의 목록 · release · rollout)과 어긋나기 때문이다.
//!
//! 묶는 것은 이름을 적은 것([`RECORDS`])뿐이다. 그 밖의 파일(토큰의 열쇠, 개발용 메일함, 빌드 결과)은 묶지 않는다.
//! 봉인의 열쇠와 service key 는 처음부터 기록 밖(환경 변수)에 있어 묶일 수 없다. 금고와 팩토리의 설정은 봉인한 글 그대로 묶인다.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::{Error, Tools};

/// `ORBITAL_HOME` 에서 묶는 것. 레지스트리, 팩토리의 설정, 금고(봉인한 글), 인스턴스와 스캐폴드의 코드 저장소.
pub const RECORDS: [&str; 5] = [
    "registry.json",
    "settings.json",
    "vault.json",
    "sources",
    "apps",
];

fn tar() -> Command {
    let mut command = Command::new("tar");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// `home` 의 기록을 `into`(tar) 하나로 묶는다. 없는 것은 건너뛴다.
pub fn pack(home: &Path, into: &Path) -> Result<(), Error> {
    let present: Vec<&str> = RECORDS
        .iter()
        .copied()
        .filter(|name| home.join(name).exists())
        .collect();
    let mut command = tar();
    command.arg("-cf").arg(into);
    if present.is_empty() {
        // 기록이 아직 없는 레이어(폴더도 없을 수 있다)는 빈 묶음이다
        command.args(["-T", "/dev/null"]);
    } else {
        command.arg("-C").arg(home);
        // 이름 앞에 `--` 를 두어 옵션으로 읽히지 않게 한다
        command.arg("--").args(&present);
    }
    Tools::run(command, "레이어의 기록을 묶")?;
    // 금고와 설정의 봉인한 글이 들어 있다. 주인만 읽는다
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(into, std::fs::Permissions::from_mode(0o600))
        .map_err(crate::io("기록의 묶음을 좁히"))
}

/// 묶은 기록을 `into` 에 푼다. 주인과 권한은 푸는 쪽의 것으로 한다.
pub fn unpack(from: &Path, into: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(into).map_err(crate::io("기록을 풀 폴더를 만들"))?;
    let mut command = tar();
    command
        .args(["--no-same-owner", "--no-same-permissions", "-xf"])
        .arg(from)
        .arg("-C")
        .arg(into);
    Tools::run(command, "레이어의 기록을 풀")
}
