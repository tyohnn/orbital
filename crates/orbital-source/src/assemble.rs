//! commit 하나에서 release 의 재료를 읽는다.
//!
//! 선언(`orbital.toml`), 권한 표(`db/access.toml`), 마이그레이션, 씨앗 데이터를 그 commit 의 나무에서만 읽는다.
//! release 의 식별자는 인스턴스와 commit 에서 짓는다. commit 이 나무 전체를 정하므로, 파일이 하나라도 바뀌면 식별자가 달라진다.

use std::fmt;

use orbital_core::access::{Access, RawAccess};
use orbital_core::auth::{SeedUser, SeedUsers};
use orbital_core::manifest::{Manifest, ValidManifest};
use orbital_core::name::InstanceId;
use orbital_core::release::ReleaseId;
use sha2::{Digest, Sha256};

use crate::{Commit, Error, SourceStore};

pub const MANIFEST: &str = "orbital.toml";
pub const ACCESS: &str = "db/access.toml";
/// 미리보기의 씨앗 사용자. 선언의 `seed` 폴더와 상관없이 이 자리에서 읽는다.
pub const SEED_USERS: &str = "db/seed/users.toml";

/// 순서대로 돌릴 SQL 파일 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub name: String,
    pub sql: String,
}

/// commit 하나에서 읽은 release 의 재료.
#[derive(Debug, Clone)]
pub struct Assembled {
    pub release: ReleaseId,
    pub commit: Commit,
    pub manifest: ValidManifest,
    pub access: Access,
    pub migrations: Vec<Script>,
    /// 미리보기 DB 에 넣을 가짜 데이터.
    pub seed: Vec<Script>,
    /// 미리보기에 넣을 씨앗 사용자(`db/seed/users.toml`). 운영에는 들어가지 않는다.
    pub seed_users: Vec<SeedUser>,
}

#[derive(Debug)]
pub enum AssembleError {
    Source(Error),
    /// 코드에 고칠 것이 있다. 에이전트가 읽고 고칠 문장들이다.
    Problems(Vec<String>),
}

impl fmt::Display for AssembleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "{error}"),
            Self::Problems(problems) => {
                writeln!(f, "고칠 것이 {}개 있습니다:", problems.len())?;
                for problem in problems {
                    writeln!(f, "  - {problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for AssembleError {}

impl From<Error> for AssembleError {
    fn from(error: Error) -> Self {
        Self::Source(error)
    }
}

/// release 의 식별자를 짓는다. 같은 인스턴스의 같은 commit 이면 늘 같다.
pub fn release_id(instance: &InstanceId, commit: &Commit) -> ReleaseId {
    let digest = Sha256::digest(format!(
        "orbital/release/v1\n{}\n{commit}",
        instance.as_str()
    ));
    let hex: String = digest
        .iter()
        .take(10)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ReleaseId(format!("r_{hex}"))
}

fn text(
    store: &SourceStore,
    instance: &InstanceId,
    commit: &Commit,
    file: &str,
) -> Result<Option<String>, AssembleError> {
    match store.read(instance, commit, file)? {
        None => Ok(None),
        Some(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| AssembleError::Problems(vec![format!("`{file}` 이 UTF-8 글이 아닙니다")])),
    }
}

fn scripts(
    store: &SourceStore,
    instance: &InstanceId,
    commit: &Commit,
    folder: Option<&str>,
) -> Result<Vec<Script>, AssembleError> {
    let Some(folder) = folder else {
        return Ok(Vec::new());
    };
    let folder = folder.trim_end_matches('/');
    let mut found = Vec::new();
    for name in store
        .list(instance, commit, folder)
        .map_err(|error| match error {
            Error::BadPath => AssembleError::Problems(vec![format!(
                "`{folder}` 는 저장소 안의 폴더 경로가 아닙니다"
            )]),
            other => AssembleError::Source(other),
        })?
    {
        if !name.ends_with(".sql") {
            continue;
        }
        let file = format!("{folder}/{name}");
        if let Some(sql) = text(store, instance, commit, &file)? {
            found.push(Script { name, sql });
        }
    }
    Ok(found)
}

/// commit 하나에서 선언 · 권한 표 · 마이그레이션 · 씨앗 데이터를 읽고 검증한다.
pub fn assemble(
    store: &SourceStore,
    instance: &InstanceId,
    commit: &Commit,
) -> Result<Assembled, AssembleError> {
    let Some(manifest_text) = text(store, instance, commit, MANIFEST)? else {
        return Err(AssembleError::Problems(vec![format!(
            "저장소의 맨 위에 `{MANIFEST}` 이 없습니다"
        )]));
    };
    let manifest: Manifest = toml::from_str(&manifest_text).map_err(|error| {
        AssembleError::Problems(vec![format!(
            "`{MANIFEST}` 을 읽지 못했습니다: {}",
            error.message()
        )])
    })?;
    let manifest = manifest.check().map_err(|problems| {
        AssembleError::Problems(
            problems
                .iter()
                .map(|problem| format!("`{MANIFEST}`: {problem}"))
                .collect(),
        )
    })?;

    let database = &manifest.get().database;
    let access = match text(store, instance, commit, ACCESS)? {
        // database 를 쓰지 않는 앱은 권한 표가 없어도 된다
        None if database.schemas.is_empty() => Access::default(),
        None => {
            return Err(AssembleError::Problems(vec![format!(
                "스키마를 선언했는데 `{ACCESS}` 이 없습니다. 표마다 역할마다 할 수 있는 것을 적어 주세요"
            )]));
        }
        Some(access_text) => {
            let raw: RawAccess = toml::from_str(&access_text).map_err(|error| {
                AssembleError::Problems(vec![format!(
                    "`{ACCESS}` 을 읽지 못했습니다: {}",
                    error.message()
                )])
            })?;
            Access::parse(&raw, &manifest).map_err(|problems| {
                AssembleError::Problems(
                    problems
                        .iter()
                        .map(|problem| format!("`{ACCESS}`: {problem}"))
                        .collect(),
                )
            })?
        }
    };

    let migrations = scripts(store, instance, commit, database.migrations.as_deref())?;
    let seed = scripts(store, instance, commit, database.seed.as_deref())?;
    let seed_users = match text(store, instance, commit, SEED_USERS)? {
        None => Vec::new(),
        Some(users_text) => {
            let raw: SeedUsers = toml::from_str(&users_text).map_err(|error| {
                AssembleError::Problems(vec![format!(
                    "`{SEED_USERS}` 을 읽지 못했습니다: {}",
                    error.message()
                )])
            })?;
            raw.check(&manifest).map_err(|problems| {
                AssembleError::Problems(
                    problems
                        .iter()
                        .map(|problem| format!("`{SEED_USERS}`: {problem}"))
                        .collect(),
                )
            })?
        }
    };
    Ok(Assembled {
        release: release_id(instance, commit),
        commit: commit.clone(),
        manifest,
        access,
        migrations,
        seed,
        seed_users,
    })
}
