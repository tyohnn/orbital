//! 코드 저장소. 인스턴스마다 레이어 안에 git 이력을 둔다. GitHub 을 거치지 않는다.
//!
//! 인스턴스의 저장소는 스캐폴드의 한 버전에서 갈라지고(`create`), 에이전트는 묶음(git bundle)으로 받아 가서 고친 뒤 묶음으로 올린다(`receive`).
//! 올린 묶음은 `main` 의 이력을 잇는 것만 받는다. 레이어는 여기서 commit 하나의 파일을 읽고(`read`), 나무를 꺼내 직접 빌드한다(`export`).
//! 승인한 commit 과 운영에서 도는 코드가 같으려면 빌드의 재료가 이 저장소에서만 나와야 한다.
//!
//! git 은 명령으로 부른다. 묶음은 밖에서 온 것이라 받을 때 객체를 검사한다.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use orbital_core::name::InstanceId;

pub mod assemble;

/// commit 의 식별자. 40자의 16진수다.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Commit(String);

impl Commit {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        (text.len() == 40
            && text
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Commit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub enum Error {
    /// 이 인스턴스의 저장소가 없다.
    NoSuchInstance,
    /// 이 인스턴스의 저장소가 이미 있다.
    AlreadyExists,
    /// 스캐폴드에 그 버전이 없다.
    NoSuchVersion,
    /// 이 저장소에 없는 commit 이다.
    NoSuchCommit,
    /// 올린 묶음을 읽지 못했다.
    BadBundle,
    /// 올린 묶음이 `main` 의 이력을 잇지 않는다.
    NotFastForward,
    /// 저장소 안의 경로로 쓸 수 없는 글자열이다.
    BadPath,
    /// git 이나 파일을 다루다 깨졌다. `doing` 은 무엇을 하다 깨졌는지다.
    Failed { doing: &'static str },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchInstance => write!(f, "이 인스턴스의 코드 저장소가 없습니다"),
            Self::AlreadyExists => write!(f, "이 인스턴스의 코드 저장소가 이미 있습니다"),
            Self::NoSuchVersion => write!(f, "스캐폴드에 그 버전이 없습니다"),
            Self::NoSuchCommit => write!(f, "이 저장소에 없는 commit 입니다"),
            Self::BadBundle => write!(
                f,
                "올린 묶음을 읽지 못했습니다. `orbital push` 로 다시 올려 주세요"
            ),
            Self::NotFastForward => write!(
                f,
                "올린 commit 이 저장소의 최신 commit 을 잇지 않습니다. `orbital pull` 로 받아 합친 뒤 다시 올려 주세요"
            ),
            Self::BadPath => write!(f, "저장소 안의 경로로 쓸 수 없는 글자열입니다"),
            Self::Failed { doing } => write!(f, "{doing} 하다가 실패했습니다"),
        }
    }
}

impl std::error::Error for Error {}

fn failed(doing: &'static str) -> Error {
    Error::Failed { doing }
}

/// 저장소 안의 경로. 위로 올라가거나 git 의 옵션으로 읽힐 수 있는 것을 받지 않는다.
fn checked(path: &str) -> Result<&str, Error> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.starts_with('-')
        || path.contains(':')
        || path.contains('\0')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if bad { Err(Error::BadPath) } else { Ok(path) }
}

/// 스캐폴드의 버전 이름(태그나 브랜치). git 의 옵션이나 범위로 읽힐 수 있는 것을 받지 않는다.
fn checked_reference(reference: &str) -> Result<&str, Error> {
    let ok = !reference.is_empty()
        && !reference.starts_with('-')
        && !reference.contains("..")
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c));
    if ok {
        Ok(reference)
    } else {
        Err(Error::NoSuchVersion)
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

const MAIN: &str = "refs/heads/main";
const BASE: &str = "refs/orbital/base";
const INCOMING: &str = "refs/orbital/incoming";
/// 앱(위쪽)에서 받아 둔 commit. 업데이트 하나마다 `refs/orbital/upstream/<commit>` 하나다.
const UPSTREAM: &str = "refs/orbital/upstream";
/// 앱의 버전들을 받아 오는 자리.
const APP: &str = "refs/orbital/app";
/// 열린 rollout 의 업데이트 commit. 묶음에 함께 담겨, 에이전트가 받은 저장소에서 `origin/update` 로 보인다.
const UPDATE: &str = "refs/heads/update";

/// 레이어가 업데이트를 합쳐 본 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merged {
    /// `main` 이 이미 업데이트를 담고 있다. 아무것도 하지 않았다.
    Already(Commit),
    /// 충돌 없이 합쳐 새 commit 을 `main` 에 세웠다.
    Merged(Commit),
    /// 충돌했다. 저장소를 건드리지 않았다. 충돌한 파일의 이름이다.
    Conflicts(Vec<String>),
}

/// 레이어의 코드 저장소들이 사는 폴더.
#[derive(Debug, Clone)]
pub struct SourceStore {
    root: PathBuf,
}

impl SourceStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, instance: &InstanceId) -> PathBuf {
        self.root.join(format!("{}.git", instance.as_str()))
    }

    fn existing(&self, instance: &InstanceId) -> Result<PathBuf, Error> {
        let path = self.path(instance);
        if path.join("HEAD").is_file() {
            Ok(path)
        } else {
            Err(Error::NoSuchInstance)
        }
    }

    /// git 을 부른다. 레이어의 환경과 사람의 git 설정이 섞이지 않게 환경을 비운다.
    fn git(repository: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .arg("--git-dir")
            .arg(repository)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// 성공하면 표준 출력을, 실패하면 `None` 을 돌려준다.
    fn output(command: &mut Command, doing: &'static str) -> Result<Option<Vec<u8>>, Error> {
        let output = command.output().map_err(|_| failed(doing))?;
        Ok(output.status.success().then_some(output.stdout))
    }

    fn resolve(repository: &Path, name: &str) -> Result<Option<Commit>, Error> {
        let spec = format!("{name}^{{commit}}");
        let found = Self::output(
            Self::git(repository).args(["rev-parse", "--verify", "--quiet", &spec]),
            "commit 을 찾",
        )?;
        Ok(found.and_then(|bytes| Commit::parse(&String::from_utf8_lossy(&bytes))))
    }

    /// 인스턴스의 저장소를 스캐폴드의 한 버전에서 세운다. 그 버전이 갈라진 기준점으로 남는다.
    pub fn create(
        &self,
        instance: &InstanceId,
        scaffold: &Path,
        reference: &str,
    ) -> Result<Commit, Error> {
        let reference = checked_reference(reference)?;
        let path = self.path(instance);
        if path.exists() {
            return Err(Error::AlreadyExists);
        }
        fs::create_dir_all(&self.root).map_err(|_| failed("저장소의 폴더를 만들"))?;
        let made = Command::new("git")
            .args(["init", "--quiet", "--bare", "--initial-branch", "main"])
            .arg(&path)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| failed("저장소를 만들"))?;
        if !made.success() {
            return Err(failed("저장소를 만들"));
        }
        let fetched = Self::output(
            Self::git(&path)
                .args(["fetch", "--quiet", "--no-tags"])
                .arg(scaffold)
                .arg(reference),
            "스캐폴드를 받",
        )?;
        let commit = match fetched {
            Some(_) => Self::resolve(&path, "FETCH_HEAD")?,
            None => None,
        };
        let Some(commit) = commit else {
            let _ = fs::remove_dir_all(&path);
            return Err(Error::NoSuchVersion);
        };
        for name in [MAIN, BASE] {
            Self::output(
                Self::git(&path).args(["update-ref", name, commit.as_str()]),
                "기준점을 적",
            )?
            .ok_or(failed("기준점을 적"))?;
        }
        Ok(commit)
    }

    /// `main` 의 최신 commit.
    pub fn head(&self, instance: &InstanceId) -> Result<Commit, Error> {
        Self::resolve(&self.existing(instance)?, MAIN)?.ok_or(failed("최신 commit 을 찾"))
    }

    /// 스캐폴드에서 갈라진 기준점.
    pub fn base(&self, instance: &InstanceId) -> Result<Commit, Error> {
        Self::resolve(&self.existing(instance)?, BASE)?.ok_or(failed("기준점을 찾"))
    }

    /// 이 commit 이 이 인스턴스의 `main` 이력에 있는가.
    pub fn contains(&self, instance: &InstanceId, commit: &Commit) -> Result<bool, Error> {
        let path = self.existing(instance)?;
        let status = Self::git(&path)
            .args(["merge-base", "--is-ancestor", commit.as_str(), MAIN])
            .stdout(Stdio::null())
            .status()
            .map_err(|_| failed("commit 을 찾"))?;
        Ok(status.success())
    }

    /// 저장소 전체를 묶음으로 낸다. 에이전트가 받아 가서 `git clone` 한다.
    ///
    /// `HEAD` 를 함께 담는다. 빠지면 받은 쪽의 `git clone` 이 어느 브랜치를 꺼낼지 몰라 빈 작업 폴더가 된다.
    pub fn bundle(&self, instance: &InstanceId) -> Result<Vec<u8>, Error> {
        let path = self.existing(instance)?;
        let mut command = Self::git(&path);
        command.args(["bundle", "create", "--quiet", "-", "HEAD", MAIN]);
        // 열린 rollout 의 업데이트가 있으면 함께 담는다. 에이전트가 충돌을 풀 때 `git merge origin/update` 로 쓴다
        if Self::resolve(&path, UPDATE)?.is_some() {
            command.arg(UPDATE);
        }
        Self::output(&mut command, "묶음을 만들")?.ok_or(failed("묶음을 만들"))
    }

    /// 에이전트가 올린 묶음을 받는다. `main` 의 이력을 잇는 것만 받고, 받으면 `main` 이 그 끝으로 옮겨 간다.
    pub fn receive(&self, instance: &InstanceId, bundle: &[u8]) -> Result<Commit, Error> {
        let path = self.existing(instance)?;
        let before = Self::resolve(&path, MAIN)?.ok_or(failed("최신 commit 을 찾"))?;
        let file = path.join(format!(
            "incoming-{}-{}.bundle",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::File::create(&file)
            .and_then(|mut handle| handle.write_all(bundle))
            .map_err(|_| failed("묶음을 받"))?;

        let received = self.receive_file(&path, &file, &before);
        let _ = fs::remove_file(&file);
        let _ = Self::output(
            Self::git(&path).args(["update-ref", "-d", INCOMING]),
            "받던 자리를 치우",
        );
        received
    }

    fn receive_file(&self, path: &Path, file: &Path, before: &Commit) -> Result<Commit, Error> {
        // 밖에서 온 객체다. 받으면서 검사한다
        let refspec = format!("+{MAIN}:{INCOMING}");
        let fetched = Self::output(
            Self::git(path)
                .args([
                    "-c",
                    "transfer.fsckObjects=true",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                ])
                .arg(file)
                .arg(&refspec),
            "묶음을 읽",
        )?;
        if fetched.is_none() {
            return Err(Error::BadBundle);
        }
        let incoming = Self::resolve(path, INCOMING)?.ok_or(Error::BadBundle)?;
        let continues = Self::git(path)
            .args([
                "merge-base",
                "--is-ancestor",
                before.as_str(),
                incoming.as_str(),
            ])
            .stdout(Stdio::null())
            .status()
            .map_err(|_| failed("이력을 견주"))?
            .success();
        if !continues {
            return Err(Error::NotFastForward);
        }
        // 그사이 다른 올리기가 main 을 옮겼으면 실패한다
        Self::output(
            Self::git(path).args(["update-ref", MAIN, incoming.as_str(), before.as_str()]),
            "main 을 옮기",
        )?
        .ok_or(Error::NotFastForward)?;
        Ok(incoming)
    }

    fn known(&self, instance: &InstanceId, commit: &Commit) -> Result<PathBuf, Error> {
        let path = self.existing(instance)?;
        if self.contains(instance, commit)? {
            Ok(path)
        } else {
            Err(Error::NoSuchCommit)
        }
    }

    /// commit 하나에서 파일 하나를 읽는다. 없으면 `None` 이다.
    pub fn read(
        &self,
        instance: &InstanceId,
        commit: &Commit,
        file: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = self.known(instance, commit)?;
        let spec = format!("{commit}:{}", checked(file)?);
        Self::output(
            Self::git(&path).args(["cat-file", "blob", &spec]),
            "파일을 읽",
        )
    }

    /// commit 하나에서 폴더 바로 아래의 파일 이름을 순서대로 돌려준다. 폴더가 없으면 비어 있다.
    pub fn list(
        &self,
        instance: &InstanceId,
        commit: &Commit,
        folder: &str,
    ) -> Result<Vec<String>, Error> {
        let path = self.known(instance, commit)?;
        let spec = format!("{commit}:{}", checked(folder)?);
        let listed = Self::output(
            Self::git(&path).args(["ls-tree", "-z", "--name-only", &spec]),
            "폴더를 읽",
        )?;
        let mut names: Vec<String> = listed
            .unwrap_or_default()
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .filter_map(|name| String::from_utf8(name.to_vec()).ok())
            .collect();
        names.sort();
        Ok(names)
    }

    /// commit 의 나무를 빈 폴더에 꺼낸다. 레이어가 여기서 빌드한다.
    pub fn export(&self, instance: &InstanceId, commit: &Commit, into: &Path) -> Result<(), Error> {
        let path = self.known(instance, commit)?;
        fs::create_dir_all(into).map_err(|_| failed("꺼낼 폴더를 만들"))?;
        let mut archive = Self::git(&path)
            .args(["archive", "--format=tar", commit.as_str()])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| failed("나무를 꺼내"))?;
        let stream = archive.stdout.take().ok_or(failed("나무를 꺼내"))?;
        let unpacked = Command::new("tar")
            .arg("-x")
            .arg("-C")
            .arg(into)
            .stdin(stream)
            .stderr(Stdio::null())
            .status()
            .map_err(|_| failed("나무를 풀"))?;
        let archived = archive.wait().map_err(|_| failed("나무를 꺼내"))?;
        if archived.success() && unpacked.success() {
            Ok(())
        } else {
            Err(failed("나무를 꺼내"))
        }
    }

    /// `ancestor` 가 `commit` 의 조상(같은 것 포함)인가. 둘 다 이 저장소에 있어야 한다. 없으면 `false` 다.
    pub fn descends(
        &self,
        instance: &InstanceId,
        commit: &Commit,
        ancestor: &Commit,
    ) -> Result<bool, Error> {
        let path = self.existing(instance)?;
        Self::is_ancestor(&path, ancestor, commit)
    }

    fn is_ancestor(path: &Path, ancestor: &Commit, commit: &Commit) -> Result<bool, Error> {
        Ok(Self::git(path)
            .args([
                "merge-base",
                "--is-ancestor",
                ancestor.as_str(),
                commit.as_str(),
            ])
            .stdout(Stdio::null())
            .status()
            .map_err(|_| failed("이력을 견주"))?
            .success())
    }

    /// 앱(위쪽)의 commit 하나를 이 인스턴스의 저장소로 받아 둔다. 이 commit 을 열린 rollout 의 업데이트로 묶음에 담는다.
    ///
    /// 앱의 저장소에서 그 commit 을 담은 버전(브랜치 · 태그)을 모두 받고, 받은 commit 을 `refs/orbital/upstream/` 에 적는다.
    pub fn fetch_upstream(
        &self,
        instance: &InstanceId,
        app: &Path,
        commit: &Commit,
    ) -> Result<(), Error> {
        let path = self.existing(instance)?;
        Self::output(
            Self::git(&path)
                .args(["fetch", "--quiet", "--no-tags", "--force"])
                .arg(app)
                .arg(format!("refs/heads/*:{APP}/heads/*"))
                .arg(format!("refs/tags/*:{APP}/tags/*")),
            "앱의 업데이트를 받",
        )?
        .ok_or(failed("앱의 업데이트를 받"))?;
        if Self::resolve(&path, commit.as_str())?.is_none() {
            return Err(Error::NoSuchCommit);
        }
        for name in [format!("{UPSTREAM}/{commit}"), UPDATE.to_owned()] {
            Self::output(
                Self::git(&path).args(["update-ref", &name, commit.as_str()]),
                "업데이트를 적",
            )?
            .ok_or(failed("업데이트를 적"))?;
        }
        Ok(())
    }

    /// 묶음에 담던 업데이트를 뺀다. rollout 을 거뒀을 때 부른다. 받아 둔 commit 은 남긴다.
    pub fn clear_update(&self, instance: &InstanceId) -> Result<(), Error> {
        let path = self.existing(instance)?;
        let _ = Self::output(
            Self::git(&path).args(["update-ref", "-d", UPDATE]),
            "업데이트를 빼",
        )?;
        Ok(())
    }

    /// `commit` 이 담은 위쪽 commit 가운데 가장 새 것. 갈라진 기준점과 받아 둔 업데이트 가운데, 다른 후보의 조상이 아닌 것을 고른다.
    pub fn newest_upstream(
        &self,
        instance: &InstanceId,
        commit: &Commit,
    ) -> Result<Option<Commit>, Error> {
        let path = self.existing(instance)?;
        let listed = Self::output(
            Self::git(&path).args(["for-each-ref", "--format=%(objectname)", UPSTREAM]),
            "받아 둔 업데이트를 읽",
        )?
        .unwrap_or_default();
        let mut candidates: Vec<Commit> = String::from_utf8_lossy(&listed)
            .lines()
            .filter_map(Commit::parse)
            .collect();
        if let Some(base) = Self::resolve(&path, BASE)? {
            candidates.push(base);
        }
        let mut contained = Vec::new();
        for candidate in candidates {
            if !contained.contains(&candidate) && Self::is_ancestor(&path, &candidate, commit)? {
                contained.push(candidate);
            }
        }
        for candidate in &contained {
            let mut newest = true;
            for other in &contained {
                if other != candidate && Self::is_ancestor(&path, candidate, other)? {
                    newest = false;
                    break;
                }
            }
            if newest {
                return Ok(Some(candidate.clone()));
            }
        }
        Ok(None)
    }

    /// `main` 에 업데이트 commit 을 기계적으로 합친다(`git merge` 와 같은 판정). 에이전트를 돌리지 않는다.
    ///
    /// 충돌이 없으면 합친 commit 을 `main` 에 세우고, 충돌하면 저장소를 건드리지 않고 충돌한 파일의 이름만 돌려준다.
    pub fn merge(&self, instance: &InstanceId, update: &Commit) -> Result<Merged, Error> {
        let path = self.existing(instance)?;
        let head = Self::resolve(&path, MAIN)?.ok_or(failed("최신 commit 을 찾"))?;
        if Self::resolve(&path, update.as_str())?.is_none() {
            return Err(Error::NoSuchCommit);
        }
        if Self::is_ancestor(&path, update, &head)? {
            return Ok(Merged::Already(head));
        }
        let output = Self::git(&path)
            .args([
                "merge-tree",
                "--write-tree",
                "--name-only",
                "--no-messages",
                "-z",
                head.as_str(),
                update.as_str(),
            ])
            .output()
            .map_err(|_| failed("업데이트를 합쳐 보"))?;
        let mut parts = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned());
        let tree = parts.next().unwrap_or_default();
        match output.status.code() {
            Some(0) => {}
            Some(1) => {
                let mut files: Vec<String> = parts.collect();
                files.sort();
                files.dedup();
                return Ok(Merged::Conflicts(files));
            }
            _ => return Err(failed("업데이트를 합쳐 보")),
        }
        if !(tree.len() == 40 && tree.chars().all(|c| c.is_ascii_hexdigit())) {
            return Err(failed("업데이트를 합쳐 보"));
        }
        let message = format!("Orbital: 업데이트 {} 를 합칩니다", &update.as_str()[..12]);
        let made = Self::output(
            Self::git(&path)
                .env("GIT_AUTHOR_NAME", "Orbital")
                .env("GIT_AUTHOR_EMAIL", "layer@orbital.invalid")
                .env("GIT_COMMITTER_NAME", "Orbital")
                .env("GIT_COMMITTER_EMAIL", "layer@orbital.invalid")
                .args([
                    "commit-tree",
                    &tree,
                    "-p",
                    head.as_str(),
                    "-p",
                    update.as_str(),
                    "-m",
                    &message,
                ]),
            "합친 commit 을 만들",
        )?
        .and_then(|bytes| Commit::parse(&String::from_utf8_lossy(&bytes)))
        .ok_or(failed("합친 commit 을 만들"))?;
        // 그사이 다른 올리기가 main 을 옮겼으면 실패한다
        Self::output(
            Self::git(&path).args(["update-ref", MAIN, made.as_str(), head.as_str()]),
            "main 을 옮기",
        )?
        .ok_or(Error::NotFastForward)?;
        Ok(Merged::Merged(made))
    }

    /// commit 하나에서 폴더 하나를 꺼내 `into` 아래 같은 자리에 둔다. 적합성 테스트의 자리에 위쪽의 폴더를 놓을 때 쓴다.
    /// 폴더가 그 commit 에 없으면 `Ok(false)` 다.
    pub fn export_folder(
        &self,
        instance: &InstanceId,
        commit: &Commit,
        folder: &str,
        into: &Path,
    ) -> Result<bool, Error> {
        let path = self.known(instance, commit)?;
        let folder = checked(folder)?;
        let spec = format!("{commit}:{folder}");
        let present = Self::git(&path)
            .args(["cat-file", "-e", &spec])
            .stdout(Stdio::null())
            .status()
            .map_err(|_| failed("폴더를 찾"))?
            .success();
        if !present {
            return Ok(false);
        }
        fs::create_dir_all(into).map_err(|_| failed("꺼낼 폴더를 만들"))?;
        let mut archive = Self::git(&path)
            .args(["archive", "--format=tar", commit.as_str(), "--", folder])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| failed("폴더를 꺼내"))?;
        let stream = archive.stdout.take().ok_or(failed("폴더를 꺼내"))?;
        let unpacked = Command::new("tar")
            .arg("-x")
            .arg("-C")
            .arg(into)
            .stdin(stream)
            .stderr(Stdio::null())
            .status()
            .map_err(|_| failed("폴더를 풀"))?;
        let archived = archive.wait().map_err(|_| failed("폴더를 꺼내"))?;
        if archived.success() && unpacked.success() {
            Ok(true)
        } else {
            Err(failed("폴더를 꺼내"))
        }
    }

    /// 인스턴스의 저장소를 지운다. 되돌릴 수 없다.
    pub fn destroy(&self, instance: &InstanceId) -> Result<(), Error> {
        let path = self.path(instance);
        if path.exists() {
            fs::remove_dir_all(path).map_err(|_| failed("저장소를 지우"))?;
        }
        Ok(())
    }
}

/// 앱(스캐폴드)의 저장소에서 commit 하나를 찾는다. `reference` 가 없으면 `main` 의 끝이다.
pub fn app_commit(repository: &Path, reference: Option<&str>) -> Result<Commit, Error> {
    if !repository.join("HEAD").is_file() {
        return Err(Error::NoSuchCommit);
    }
    let name = match reference {
        None => MAIN,
        Some(text) => Commit::parse(text)
            .map(|_| text)
            .ok_or(Error::NoSuchCommit)?,
    };
    let commit = SourceStore::resolve(repository, name)?.ok_or(Error::NoSuchCommit)?;
    // 앱의 버전(브랜치 · 태그)에서 닿는 commit 만 받는다. 저장소에 떠도는 객체는 업데이트가 아니다
    let reachable = SourceStore::output(
        SourceStore::git(repository).args([
            "for-each-ref",
            "--contains",
            commit.as_str(),
            "--format=%(refname)",
            "refs/heads",
            "refs/tags",
        ]),
        "앱의 버전을 읽",
    )?
    .is_some_and(|bytes| !bytes.is_empty());
    if reachable {
        Ok(commit)
    } else {
        Err(Error::NoSuchCommit)
    }
}

/// 팩토리가 올린 스캐폴드의 묶음을 받아 둔다. 버전(태그와 브랜치)을 모두 받는다.
///
/// 인스턴스는 여기의 한 버전에서 갈라진다([`SourceStore::create`]).
pub fn receive_scaffold(repository: &Path, bundle: &[u8]) -> Result<(), Error> {
    if !repository.join("HEAD").is_file() {
        if let Some(parent) = repository.parent() {
            fs::create_dir_all(parent).map_err(|_| failed("스캐폴드의 폴더를 만들"))?;
        }
        let made = Command::new("git")
            .args(["init", "--quiet", "--bare", "--initial-branch", "main"])
            .arg(repository)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| failed("스캐폴드의 저장소를 만들"))?;
        if !made.success() {
            return Err(failed("스캐폴드의 저장소를 만들"));
        }
    }
    let file = repository.join(format!(
        "incoming-{}-{}.bundle",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::File::create(&file)
        .and_then(|mut handle| handle.write_all(bundle))
        .map_err(|_| failed("묶음을 받"))?;
    let fetched = SourceStore::output(
        SourceStore::git(repository)
            .args([
                "-c",
                "transfer.fsckObjects=true",
                "fetch",
                "--quiet",
                "--force",
            ])
            .arg(&file)
            .args(["refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"]),
        "묶음을 읽",
    );
    let _ = fs::remove_file(&file);
    fetched?.map(|_| ()).ok_or(Error::BadBundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_의_식별자는_40자의_소문자_16진수다() {
        assert!(Commit::parse(&"a".repeat(40)).is_some());
        assert!(Commit::parse(&format!("{}\n", "0".repeat(40))).is_some());
        assert!(Commit::parse(&"a".repeat(39)).is_none());
        assert!(Commit::parse(&"A".repeat(40)).is_none());
        assert!(Commit::parse("main").is_none());
        assert!(Commit::parse(&format!("--{}", "a".repeat(38))).is_none());
    }

    #[test]
    fn 위로_올라가거나_옵션으로_읽히는_경로는_받지_않는다() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "./a",
            "-rf",
            "a:b",
            "a/.",
        ] {
            assert!(matches!(checked(bad), Err(Error::BadPath)), "{bad}");
        }
        assert!(checked("db/migrations/001_init.sql").is_ok());
        assert!(checked("orbital.toml").is_ok());
    }

    #[test]
    fn 스캐폴드의_버전_이름에는_옵션이나_범위를_적지_못한다() {
        for bad in ["", "--upload-pack=x", "v1..v2", "v1 v2", "v1;rm"] {
            assert!(checked_reference(bad).is_err(), "{bad}");
        }
        assert!(checked_reference("v12").is_ok());
        assert!(checked_reference("release/2027.1").is_ok());
    }
}
