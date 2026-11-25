//! Orbital Auth 의 저장소. 인스턴스의 database 안 스키마 `orbital_auth` 에 사용자 · 초대 · 로그인 링크 · 세션을 둔다.
//!
//! 표는 레이어의 관리 역할이 갖고, 인증 역할(`i_<id>_auth`)만 읽고 쓴다. 업무 역할은 뷰 `orbital.me`(자기 한 줄)를 읽고,
//! 선언의 `directory` 에 적힌 업무 역할만 뷰 `orbital.users` 를 읽는다. 소유자는 `users(id)` 를 가리키는 외래 키만 만든다.
//!
//! 토큰(로그인 링크 · 세션 · 브라우저의 표식)은 32바이트 무작위 값이고, DB 에는 sha256 해시만 둔다. 표를 통째로 읽어도 그 값으로는 들어오지 못한다.
//! 링크 · 초대 · 세션이 아직 읽히는지는 core 의 `orbital_core::auth` 가 판정하고, 여기서는 읽어 와 넘기고 그 결과대로 적기만 한다.

use std::fmt;

use orbital_core::auth::{
    InvitationRefusal, InvitationState, LinkRefusal, LinkState, SeedUser, SessionState,
    invitation_expires_at, judge_invitation, judge_link, judge_session, link_expires_at,
    may_create_link, needs_touch, safe_next, session_expires_at, undeclared_roles,
};
use orbital_core::manifest::{Signup, ValidManifest};
use orbital_core::name::Ident;
use orbital_core::plan::Names;
use postgres::{Client, Transaction};
use sha2::{Digest, Sha256};

use crate::{Admin, Error, pg, quote};

/// 32바이트 무작위 값. 로그인 링크 · 세션의 토큰과 브라우저의 표식으로 쓴다. 값은 찍지 않는다.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret([u8; 32]);

impl Secret {
    /// 운영체제의 무작위 값으로 만든다.
    pub fn generate() -> Result<Self, AuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| AuthError::Random)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 쿠키와 링크에 싣는 글자. 64자의 hex 다.
    pub fn to_text(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// [`Secret::to_text`] 의 글자를 읽는다. 모양이 다르면 없는 것이다.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// DB 에 두는 값.
    pub(crate) fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.0).to_vec()
    }

    /// 세션을 가리키는 이름(`s_` 와 hex 24자). 신원의 `sid` 에 싣는다.
    ///
    /// 토큰에서 한쪽으로만 지어서 이것으로는 토큰도, DB 에 둔 해시도 되짚지 못한다. 같은 세션이면 늘 같다.
    pub fn session_id(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"orbital/sid/");
        digest.update(self.hash());
        let digest = digest.finalize();
        format!(
            "s_{}",
            digest[..12]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

#[derive(Debug)]
pub enum AuthError {
    /// DB 가 거절했거나 연결이 끊겼다.
    Db(Error),
    /// 선언에 `[auth]` 가 없다.
    NotDeclared,
    /// 선언에 없는 업무 역할을 주려 했다.
    UndeclaredRoles { roles: Vec<Ident> },
    /// 그런 링크가 없다.
    NoSuchLink,
    /// 링크가 읽히지 않는다(만료 · 이미 씀 · 다른 브라우저).
    Link(LinkRefusal),
    /// 초대받지 않은 이메일이다.
    NotInvited,
    /// 초대가 받아들여지지 않는다(만료).
    Invitation(InvitationRefusal),
    /// 막힌 사용자다.
    UserDisabled,
    /// 그런 사용자가 없다.
    NoSuchUser,
    /// 운영체제에서 무작위 값을 얻지 못했다.
    Random,
    /// 인가 코드나 refresh 토큰을 받지 않는다(RFC 6749 의 `invalid_grant`). 까닭은 밖에 알리지 않는다.
    InvalidGrant,
    /// 그런 인가 요청이 없거나, 남의 것이거나, 이미 정했거나, 만료됐다. 넷을 가르지 않는다.
    NoSuchRequest,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(error) => write!(f, "{error}"),
            Self::NotDeclared => write!(
                f,
                "이 인스턴스는 로그인을 레이어에 맡기지 않았습니다. `orbital.toml` 에 `[auth]` 를 적어 주세요"
            ),
            Self::UndeclaredRoles { roles } => write!(
                f,
                "업무 역할 {} 이 선언에 없습니다. `[database].roles` 에 적힌 역할만 줄 수 있습니다",
                roles
                    .iter()
                    .map(|role| format!("`{role}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NoSuchLink => write!(
                f,
                "로그인 링크를 찾지 못했습니다. 로그인 화면에서 링크를 다시 받아 주세요"
            ),
            Self::Link(LinkRefusal::Expired) => write!(
                f,
                "로그인 링크가 만료되었습니다. 로그인 화면에서 링크를 다시 받아 주세요"
            ),
            Self::Link(LinkRefusal::Used) => write!(
                f,
                "이미 쓴 로그인 링크입니다. 로그인 화면에서 링크를 다시 받아 주세요"
            ),
            Self::Link(LinkRefusal::OtherBrowser) => write!(
                f,
                "링크를 요청한 브라우저가 아닙니다. 링크를 요청한 브라우저에서 열어 주세요"
            ),
            Self::NotInvited => write!(
                f,
                "초대받지 않은 이메일입니다. 관리자에게 초대를 요청해 주세요"
            ),
            Self::Invitation(InvitationRefusal::Expired) => write!(
                f,
                "초대가 만료되었습니다. 관리자에게 다시 초대해 달라고 요청해 주세요"
            ),
            Self::Invitation(InvitationRefusal::Accepted) => write!(
                f,
                "이미 받아들인 초대입니다. 로그인 화면에서 링크를 받아 들어와 주세요"
            ),
            Self::UserDisabled => write!(
                f,
                "막힌 사용자입니다. 다시 들어오려면 관리자에게 요청해 주세요"
            ),
            Self::NoSuchUser => write!(
                f,
                "사용자를 찾지 못했습니다. 사용자 목록에서 식별자를 확인해 주세요"
            ),
            Self::Random => write!(
                f,
                "운영체제에서 무작위 값을 얻지 못했습니다. 잠시 뒤에 다시 해 주세요"
            ),
            Self::InvalidGrant => write!(
                f,
                "인가 코드나 refresh 토큰을 받지 않습니다. 처음부터 다시 인가를 받아 주세요"
            ),
            Self::NoSuchRequest => write!(
                f,
                "인가 요청을 찾지 못했습니다. 클라이언트에서 다시 연결해 주세요"
            ),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<Error> for AuthError {
    fn from(error: Error) -> Self {
        Self::Db(error)
    }
}

pub(crate) fn db(doing: &'static str) -> impl FnOnce(postgres::Error) -> AuthError {
    move |source| AuthError::Db(pg(doing)(source))
}

/// 링크로 들어온 결과.
#[derive(Debug)]
pub struct Entered {
    /// 브라우저의 쿠키에 담을 세션의 토큰.
    pub session: Secret,
    pub user: SessionUser,
    /// 로그인 뒤에 돌아갈 곳. 이 주소 안의 경로다.
    pub next: String,
}

/// 세션이 가리키는 사용자. router 가 서명된 신원을 만들 때 쓴다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    /// 업무 역할의 이름. 이름 순이다.
    pub roles: Vec<String>,
}

/// 사용자 목록의 한 줄.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    pub disabled: bool,
    /// 마지막으로 세션을 연 때(유닉스 초). 한 번도 들어오지 않았으면 없다.
    pub last_signed_in_at: Option<u64>,
}

/// 인스턴스의 database 에 두는 것. 이름이 인스턴스마다 다른 권한은 [`Admin::install_auth`] 가 따로 준다.
const INSTALL: &str = r#"
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA orbital;
CREATE SCHEMA IF NOT EXISTS orbital_auth;
REVOKE ALL ON SCHEMA orbital_auth FROM PUBLIC;

CREATE TABLE IF NOT EXISTS orbital_auth.users (
    id text PRIMARY KEY CONSTRAINT users_id_shape CHECK (id ~ '^u_[a-z0-9]{20}$'),
    email orbital.citext NOT NULL UNIQUE,
    name text,
    created_at timestamptz NOT NULL,
    disabled_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.user_role (
    user_id text NOT NULL REFERENCES orbital_auth.users (id) ON DELETE CASCADE,
    role text NOT NULL,
    PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS orbital_auth.login (
    provider text NOT NULL CHECK (provider IN ('email')),
    subject text NOT NULL,
    user_id text NOT NULL REFERENCES orbital_auth.users (id) ON DELETE CASCADE,
    PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS orbital_auth.invitation (
    email orbital.citext PRIMARY KEY,
    roles text[] NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.email_link (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    email orbital.citext NOT NULL,
    next text NOT NULL,
    browser_hash bytea NOT NULL CHECK (length(browser_hash) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.session (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id text NOT NULL REFERENCES orbital_auth.users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS session_user_id ON orbital_auth.session (user_id);
-- MCP 의 인가(OAuth 2.1). 코드 · 토큰 · 요청의 식별자는 sha256 해시로만 둔다
CREATE TABLE IF NOT EXISTS orbital_auth.oauth_client (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('registered', 'dynamic', 'document')),
    name text NOT NULL,
    redirect_uris text[] NOT NULL,
    application_type text,
    created_at timestamptz NOT NULL,
    fetched_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.oauth_request (
    id_hash bytea PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id text NOT NULL REFERENCES orbital_auth.users (id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES orbital_auth.oauth_client (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    resource text NOT NULL,
    scope text NOT NULL,
    state text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    decided_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.oauth_grant (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES orbital_auth.users (id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES orbital_auth.oauth_client (id) ON DELETE CASCADE,
    scope text NOT NULL,
    resource text NOT NULL,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.oauth_code (
    code_hash bytea PRIMARY KEY CHECK (length(code_hash) = 32),
    grant_id text NOT NULL REFERENCES orbital_auth.oauth_grant (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    resource text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE TABLE IF NOT EXISTS orbital_auth.oauth_token (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
    grant_id text NOT NULL REFERENCES orbital_auth.oauth_grant (id) ON DELETE CASCADE,
    -- 이 토큰을 처음 낸 코드. 갈아 준 토큰도 같은 코드를 적어, 코드가 다시 쓰이면 그 줄기를 모두 거둔다
    code_hash bytea NOT NULL,
    resource text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS oauth_token_grant ON orbital_auth.oauth_token (grant_id);
CREATE INDEX IF NOT EXISTS oauth_token_code ON orbital_auth.oauth_token (code_hash);
CREATE INDEX IF NOT EXISTS oauth_grant_user ON orbital_auth.oauth_grant (user_id);

REVOKE ALL ON ALL TABLES IN SCHEMA orbital_auth FROM PUBLIC;

-- 두 뷰는 레이어의 관리 역할이 갖는다. 읽는 역할에게 표의 권한이 없어도 뷰가 준 줄만 보인다.
-- security_barrier 는 읽는 쪽의 조건이 뷰의 조건보다 먼저 돌아 남의 줄을 엿보지 못하게 한다.
CREATE OR REPLACE VIEW orbital.me WITH (security_barrier) AS
    SELECT u.id,
           u.email::text AS email,
           u.name,
           ARRAY(SELECT r.role FROM orbital_auth.user_role r WHERE r.user_id = u.id ORDER BY r.role) AS roles
    FROM orbital_auth.users u
    WHERE u.id = orbital.subject() AND u.disabled_at IS NULL;
CREATE OR REPLACE VIEW orbital.users WITH (security_barrier) AS
    SELECT u.id, u.email::text AS email, u.name
    FROM orbital_auth.users u
    WHERE u.disabled_at IS NULL;

-- 앞에서 준 뷰의 권한을 모두 걷는다. 선언에서 directory 의 역할을 빼면 그 역할의 권한도 사라진다
DO $$
DECLARE
    granted record;
BEGIN
    FOR granted IN
        SELECT c.relname, a.grantee
        FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE c.relnamespace = 'orbital'::regnamespace AND c.relname IN ('me', 'users') AND a.grantee <> c.relowner
    LOOP
        IF granted.grantee = 0 THEN
            EXECUTE format('REVOKE ALL ON orbital.%I FROM PUBLIC', granted.relname);
        ELSE
            EXECUTE format('REVOKE ALL ON orbital.%I FROM %I', granted.relname, granted.grantee::regrole::text);
        END IF;
    END LOOP;
END
$$;
REVOKE ALL ON orbital.me, orbital.users FROM PUBLIC;
"#;

impl Admin {
    /// `[auth]` 를 선언한 인스턴스에 `orbital_auth` 와 두 뷰를 두고 권한을 준다. 선언하지 않았으면 아무것도 하지 않는다.
    ///
    /// [`Admin::provision`] 과 [`Admin::install_identity`] 뒤에, 마이그레이션 앞에 부른다. 앱의 마이그레이션이 사용자를 외래 키로 가리킬 수 있게 하려는 것이다.
    /// 다시 불러도 된다. 선언의 업무 역할이나 `directory` 가 바뀌면 다시 불러 뷰의 권한을 맞춘다.
    pub fn install_auth(&mut self, names: &Names, manifest: &ValidManifest) -> Result<(), Error> {
        let Some(auth) = &manifest.get().auth else {
            return Ok(());
        };
        let mut client = self.database(&names.database())?;
        let mut transaction = client
            .transaction()
            .map_err(pg("로그인의 표를 두기 시작"))?;
        transaction
            .batch_execute(INSTALL)
            .map_err(pg("로그인의 표를 두"))?;
        let mut grants = vec![
            format!(
                "GRANT USAGE ON SCHEMA orbital_auth TO {}",
                quote(&names.auth())
            ),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA orbital_auth TO {}",
                quote(&names.auth())
            ),
            // 외래 키를 만들려면 스키마의 USAGE 와 그 열의 REFERENCES 가 있어야 한다. 표를 읽거나 고치는 권한은 주지 않는다
            format!(
                "GRANT USAGE ON SCHEMA orbital_auth TO {}",
                quote(&names.owner())
            ),
            format!(
                "GRANT REFERENCES (id) ON orbital_auth.users TO {}",
                quote(&names.owner())
            ),
        ];
        for role in &manifest.get().database.roles {
            grants.push(format!(
                "GRANT SELECT ON orbital.me TO {}",
                quote(&names.group(role))
            ));
        }
        for role in &auth.directory {
            grants.push(format!(
                "GRANT SELECT ON orbital.users TO {}",
                quote(&names.group(role))
            ));
        }
        for grant in grants {
            transaction
                .batch_execute(&grant)
                .map_err(pg("로그인의 표에 권한을 주"))?;
        }
        transaction
            .commit()
            .map_err(pg("로그인의 표를 두기를 마무리"))
    }

    /// 미리보기의 DB 에 씨앗 사용자를 넣는다. **운영에는 부르지 않는다.** 마이그레이션 뒤, 씨앗 데이터의 SQL 앞에 부른다.
    ///
    /// 씨앗 사용자의 식별자(`u1` 같은)는 `u_` 모양이 아니다. 그래서 씨앗 사용자가 있을 때만 이 database 의 식별자 규칙을
    /// 「`u_` 모양이거나 선언의 이름 모양(`Ident`)」으로 넓힌다. 운영 DB 의 규칙은 넓어지지 않는다.
    pub fn seed_users(&mut self, names: &Names, users: &[SeedUser], now: u64) -> Result<(), Error> {
        if users.is_empty() {
            return Ok(());
        }
        let mut client = self.database(&names.database())?;
        let mut transaction = client
            .transaction()
            .map_err(pg("씨앗 사용자를 넣기 시작"))?;
        transaction
            .batch_execute(
                "ALTER TABLE orbital_auth.users DROP CONSTRAINT users_id_shape, \
                 ADD CONSTRAINT users_id_shape CHECK (id ~ '^u_[a-z0-9]{20}$' OR id ~ '^[a-z][a-z0-9_]{0,23}$')",
            )
            .map_err(pg("씨앗 사용자의 식별자 규칙을 넓히"))?;
        for user in users {
            let roles: Vec<&str> = user.roles.iter().map(Ident::as_str).collect();
            transaction
                .execute(
                    "INSERT INTO orbital_auth.users (id, email, name, created_at) VALUES ($1, $2, $3, to_timestamp($4::bigint))",
                    &[&user.id.as_str(), &user.email, &user.name, &seconds(now)],
                )
                .map_err(pg("씨앗 사용자를 넣"))?;
            transaction
                .execute(
                    "INSERT INTO orbital_auth.user_role (user_id, role) SELECT $1, unnest($2::text[])",
                    &[&user.id.as_str(), &roles],
                )
                .map_err(pg("씨앗 사용자의 역할을 넣"))?;
            transaction
                .execute(
                    "INSERT INTO orbital_auth.login (provider, subject, user_id) VALUES ('email', lower($1), $2)",
                    &[&user.email, &user.id.as_str()],
                )
                .map_err(pg("씨앗 사용자의 로그인 방법을 넣"))?;
        }
        transaction
            .commit()
            .map_err(pg("씨앗 사용자를 넣기를 마무리"))
    }

    /// 인증 역할로 붙은 저장소. router 와 관리 서버가 이것으로 사용자와 세션을 다룬다.
    pub fn auth_store(
        &self,
        names: &Names,
        manifest: &ValidManifest,
    ) -> Result<AuthStore, AuthError> {
        if manifest.get().auth.is_none() {
            return Err(AuthError::NotDeclared);
        }
        let client = self
            .connect_as(&names.database(), &names.auth())
            .map_err(db("인증 역할로 붙"))?;
        AuthStore::ready(client, manifest)
    }
}

impl AuthStore {
    /// DB 의 주소(`postgres://사용자@주소:포트/…`)에서 사용자와 database 만 이 인스턴스의 인증 역할로 바꿔 붙는다.
    /// router 의 연결 풀이 연결을 열 때 쓴다. 비밀번호는 없다. 운영에서는 proxy 만 닿는 자리에서만 연결을 받는다.
    pub fn connect(url: &str, names: &Names, manifest: &ValidManifest) -> Result<Self, AuthError> {
        if manifest.get().auth.is_none() {
            return Err(AuthError::NotDeclared);
        }
        let mut config: postgres::Config = url
            .parse()
            .map_err(|_| AuthError::Db(Error::Url("주소의 모양이 틀렸습니다".to_owned())))?;
        let client = config
            .user(&names.auth())
            .dbname(&names.database())
            .connect(postgres::NoTls)
            .map_err(db("인증 역할로 붙"))?;
        Self::ready(client, manifest)
    }

    fn ready(mut client: Client, manifest: &ValidManifest) -> Result<Self, AuthError> {
        // citext 의 비교 연산자는 스키마 orbital 에 있다. 찾는 길에 없으면 `=` 가 글자 비교로 떨어져 대소문자를 가린다.
        // orbital 은 레이어만 쓸 수 있는 스키마이고, pg_catalog 를 앞에 두어 기본 함수를 가리지 못하게 한다.
        client
            .batch_execute("SET search_path = pg_catalog, orbital")
            .map_err(db("인증 역할의 찾는 길을 정하"))?;
        Ok(Self {
            client,
            manifest: manifest.clone(),
        })
    }
}

/// 인증 역할로 붙은 연결 하나. `orbital_auth` 의 표만 읽고 쓴다.
pub struct AuthStore {
    pub(crate) client: Client,
    pub(crate) manifest: ValidManifest,
}

pub(crate) fn seconds(now: u64) -> i64 {
    i64::try_from(now).unwrap_or(i64::MAX)
}

pub(crate) fn unix(value: Option<i64>) -> Option<u64> {
    value.map(|value| u64::try_from(value).unwrap_or(0))
}

/// `u_` 와 소문자 · 숫자 20자. 고르게 나오도록 36의 배수를 넘는 바이트는 버린다.
fn user_id() -> Result<String, AuthError> {
    random_id("u_")
}

/// 머리말과 소문자 · 숫자 20자.
pub(crate) fn random_id(lead: &str) -> Result<String, AuthError> {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut id = String::from(lead);
    let length = lead.len() + 20;
    while id.len() < length {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| AuthError::Random)?;
        for byte in bytes {
            if byte < 252 && id.len() < length {
                id.push(char::from(ALPHABET[usize::from(byte % 36)]));
            }
        }
    }
    Ok(id)
}

impl AuthStore {
    fn check_roles(&self, roles: &[Ident]) -> Result<(), AuthError> {
        let undeclared = undeclared_roles(&self.manifest, roles);
        if undeclared.is_empty() {
            Ok(())
        } else {
            Err(AuthError::UndeclaredRoles { roles: undeclared })
        }
    }

    /// 이메일을 초대한다. 이미 초대했으면 역할과 기한을 새로 적는다. 선언에 없는 업무 역할이면 거절한다.
    pub fn invite(&mut self, email: &str, roles: &[Ident], now: u64) -> Result<(), AuthError> {
        self.check_roles(roles)?;
        let roles: Vec<&str> = roles.iter().map(Ident::as_str).collect();
        self.client
            .execute(
                "INSERT INTO orbital_auth.invitation (email, roles, created_at, expires_at) \
                 VALUES ($1, $2, to_timestamp($3::bigint), to_timestamp($4::bigint)) \
                 ON CONFLICT (email) DO UPDATE SET roles = excluded.roles, created_at = excluded.created_at, \
                 expires_at = excluded.expires_at, accepted_at = NULL",
                &[
                    &email,
                    &roles,
                    &seconds(now),
                    &seconds(invitation_expires_at(now)),
                ],
            )
            .map_err(db("초대를 적"))?;
        Ok(())
    }

    /// 로그인 링크를 만든다. 들어올 수 있는 이메일일 때만 만들고 토큰을 돌려준다. `None` 이면 메일을 보내지 않는다.
    ///
    /// 들어올 수 있는 이메일은 막히지 않은 사용자이거나, 받아들일 수 있는 초대가 있거나, `signup = "open"` 인 인스턴스의 새 이메일이다.
    /// `browser` 는 링크를 요청한 브라우저의 표식이고, 링크는 그 브라우저에서만 열린다. `next` 는 이 주소 안의 경로만 남긴다.
    pub fn request_link(
        &mut self,
        email: &str,
        next: &str,
        browser: &Secret,
        now: u64,
    ) -> Result<Option<Secret>, AuthError> {
        let open = self
            .manifest
            .get()
            .auth
            .as_ref()
            .is_some_and(|auth| auth.signup == Signup::Open);
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("링크를 만들기 시작"))?;
        let user = transaction
            .query_opt(
                "SELECT disabled_at IS NOT NULL FROM orbital_auth.users WHERE email = $1",
                &[&email],
            )
            .map_err(db("사용자를 찾"))?;
        let allowed = match user {
            Some(row) => !row.get::<_, bool>(0),
            None => match invitation(&mut transaction, email, false)? {
                Some((state, _)) => judge_invitation(&state, now).is_ok(),
                None => open,
            },
        };
        if !allowed {
            return Ok(None);
        }
        // 같은 이메일의 요청이 동시에 와도 하나씩 따지도록 이메일마다 잠근다. 잠금은 트랜잭션이 끝나면 풀린다
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtext(lower($1::text)))",
                &[&email],
            )
            .map_err(db("이메일을 잠그"))?;
        let last: Option<i64> = transaction
            .query_one(
                "SELECT extract(epoch FROM max(created_at))::bigint FROM orbital_auth.email_link WHERE email = $1",
                &[&email],
            )
            .map_err(db("마지막 링크를 찾"))?
            .get(0);
        if !may_create_link(unix(last), now) {
            return Ok(None);
        }
        let token = Secret::generate()?;
        transaction
            .execute(
                "INSERT INTO orbital_auth.email_link (token_hash, email, next, browser_hash, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, to_timestamp($5::bigint), to_timestamp($6::bigint))",
                &[
                    &token.hash(),
                    &email,
                    &safe_next(next),
                    &browser.hash(),
                    &seconds(now),
                    &seconds(link_expires_at(now)),
                ],
            )
            .map_err(db("링크를 적"))?;
        transaction.commit().map_err(db("링크를 만들기를 마무리"))?;
        Ok(Some(token))
    }

    /// 링크로 들어온다. 링크를 「쓴 것」으로 적고, 처음이면 초대에서 사용자를 만들고, 세션을 만든다.
    ///
    /// 링크의 줄을 잠그고 읽은 뒤 판정하고, `used_at IS NULL` 인 줄만 고치는 한 문장으로 쓴 것으로 적는다. 같은 링크를 동시에 열면
    /// 뒤에 온 쪽은 잠금이 풀리길 기다렸다가 쓴 것으로 적힌 줄을 읽어 거절된다. 판정에 걸리면 아무것도 적지 않으므로,
    /// 다른 브라우저(메일의 링크를 미리 여는 검사기 같은)가 열어도 링크는 남는다.
    pub fn enter(
        &mut self,
        link: &Secret,
        browser: &Secret,
        now: u64,
    ) -> Result<Entered, AuthError> {
        let mut transaction = self.client.transaction().map_err(db("들어오기 시작"))?;
        let Some(row) = transaction
            .query_opt(
                "SELECT email::text, next, browser_hash, extract(epoch FROM created_at)::bigint, \
                 extract(epoch FROM expires_at)::bigint, extract(epoch FROM used_at)::bigint \
                 FROM orbital_auth.email_link WHERE token_hash = $1 FOR UPDATE",
                &[&link.hash()],
            )
            .map_err(db("링크를 찾"))?
        else {
            return Err(AuthError::NoSuchLink);
        };
        let email: String = row.get(0);
        let next: String = row.get(1);
        let state = LinkState {
            created_at: unix(Some(row.get(3))).unwrap_or(0),
            expires_at: unix(Some(row.get(4))).unwrap_or(0),
            used_at: unix(row.get(5)),
            browser_hash: row.get(2),
        };
        judge_link(&state, &browser.hash(), now).map_err(AuthError::Link)?;
        let marked = transaction
            .execute(
                "UPDATE orbital_auth.email_link SET used_at = to_timestamp($2::bigint) \
                 WHERE token_hash = $1 AND used_at IS NULL",
                &[&link.hash(), &seconds(now)],
            )
            .map_err(db("링크를 쓴 것으로 적"))?;
        if marked != 1 {
            return Err(AuthError::Link(LinkRefusal::Used));
        }

        let user = transaction
            .query_opt(
                "SELECT id, disabled_at IS NOT NULL FROM orbital_auth.users WHERE email = $1 FOR UPDATE",
                &[&email],
            )
            .map_err(db("사용자를 찾"))?;
        let id = match user {
            Some(row) if row.get::<_, bool>(1) => return Err(AuthError::UserDisabled),
            Some(row) => row.get::<_, String>(0),
            None => {
                let roles = match invitation(&mut transaction, &email, true)? {
                    Some((state, roles)) => {
                        judge_invitation(&state, now).map_err(AuthError::Invitation)?;
                        transaction
                            .execute(
                                "UPDATE orbital_auth.invitation SET accepted_at = to_timestamp($2::bigint) WHERE email = $1",
                                &[&email, &seconds(now)],
                            )
                            .map_err(db("초대를 받아들인 것으로 적"))?;
                        roles
                    }
                    None => match &self.manifest.get().auth {
                        Some(auth) if auth.signup == Signup::Open => auth
                            .default_roles
                            .iter()
                            .map(|role| role.as_str().to_owned())
                            .collect(),
                        _ => return Err(AuthError::NotInvited),
                    },
                };
                // 초대한 뒤 선언에서 빠진 업무 역할은 주지 않는다
                let declared = &self.manifest.get().database.roles;
                let roles: Vec<String> = roles
                    .into_iter()
                    .filter(|role| declared.iter().any(|known| known.as_str() == role))
                    .collect();
                create_user(&mut transaction, &email, &roles, now)?
            }
        };

        let session = create_session(&mut transaction, &id, now)?;
        let user = session_user(&mut transaction, &id)?.ok_or(AuthError::NoSuchUser)?;
        transaction.commit().map_err(db("들어오기를 마무리"))?;
        Ok(Entered {
            session,
            user,
            next: safe_next(&next),
        })
    }

    /// 링크 없이 사용자의 세션을 만든다. **미리보기의 router 만 부른다**(씨앗 사용자로 들어가기). 운영의 router 에는 이 길이 없다.
    pub fn start_session(
        &mut self,
        user_id: &str,
        now: u64,
    ) -> Result<(Secret, SessionUser), AuthError> {
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("세션 만들기를 시작"))?;
        let disabled = transaction
            .query_opt(
                "SELECT disabled_at IS NOT NULL FROM orbital_auth.users WHERE id = $1",
                &[&user_id],
            )
            .map_err(db("사용자를 찾"))?
            .ok_or(AuthError::NoSuchUser)?
            .get::<_, bool>(0);
        if disabled {
            return Err(AuthError::UserDisabled);
        }
        let session = create_session(&mut transaction, user_id, now)?;
        let user = session_user(&mut transaction, user_id)?.ok_or(AuthError::NoSuchUser)?;
        transaction.commit().map_err(db("세션 만들기를 마무리"))?;
        Ok((session, user))
    }

    /// 세션의 사용자와 업무 역할. 없거나, 만료됐거나, 거뒀거나, 사용자가 막혀 있으면 `None` 이다.
    ///
    /// 요청마다 부르므로 세션 · 사용자 · 업무 역할을 한 문장으로 읽는다. 본 시각은 마지막으로 적은 지 1분이 지났을 때만 한 문장 더 적는다.
    pub fn session(&mut self, token: &Secret, now: u64) -> Result<Option<SessionUser>, AuthError> {
        let Some(row) = self
            .client
            .query_opt(
                "SELECT s.user_id, extract(epoch FROM s.expires_at)::bigint, extract(epoch FROM s.revoked_at)::bigint, \
                 extract(epoch FROM u.disabled_at)::bigint, extract(epoch FROM s.last_seen_at)::bigint, \
                 u.email::text, u.name, \
                 ARRAY(SELECT r.role FROM orbital_auth.user_role r WHERE r.user_id = u.id ORDER BY r.role) \
                 FROM orbital_auth.session s JOIN orbital_auth.users u ON u.id = s.user_id WHERE s.token_hash = $1",
                &[&token.hash()],
            )
            .map_err(db("세션을 찾"))?
        else {
            return Ok(None);
        };
        let state = SessionState {
            expires_at: unix(Some(row.get(1))).unwrap_or(0),
            revoked_at: unix(row.get(2)),
            user_disabled_at: unix(row.get(3)),
        };
        if judge_session(&state, now).is_err() {
            return Ok(None);
        }
        if needs_touch(unix(Some(row.get(4))).unwrap_or(0), now) {
            self.client
                .execute(
                    "UPDATE orbital_auth.session SET last_seen_at = to_timestamp($2::bigint) WHERE token_hash = $1",
                    &[&token.hash(), &seconds(now)],
                )
                .map_err(db("세션을 본 시각을 적"))?;
        }
        Ok(Some(SessionUser {
            id: row.get(0),
            email: row.get(5),
            name: row.get(6),
            roles: row.get(7),
        }))
    }

    /// 세션을 거둔다(로그아웃). 없는 세션이어도 실패하지 않는다.
    pub fn revoke(&mut self, token: &Secret, now: u64) -> Result<(), AuthError> {
        self.client
            .execute(
                "UPDATE orbital_auth.session SET revoked_at = to_timestamp($2::bigint) \
                 WHERE token_hash = $1 AND revoked_at IS NULL",
                &[&token.hash(), &seconds(now)],
            )
            .map_err(db("세션을 거두"))?;
        Ok(())
    }

    /// 모든 사용자. 막힌 사용자도 함께 돌려준다. 이메일 순이다.
    pub fn users(&mut self) -> Result<Vec<User>, AuthError> {
        let rows = self
            .client
            .query(
                "SELECT u.id, u.email::text, u.name, \
                 ARRAY(SELECT r.role FROM orbital_auth.user_role r WHERE r.user_id = u.id ORDER BY r.role), \
                 u.disabled_at IS NOT NULL, \
                 (SELECT extract(epoch FROM max(s.created_at))::bigint FROM orbital_auth.session s WHERE s.user_id = u.id) \
                 FROM orbital_auth.users u ORDER BY u.email",
                &[],
            )
            .map_err(db("사용자 목록을 읽"))?;
        Ok(rows
            .iter()
            .map(|row| User {
                id: row.get(0),
                email: row.get(1),
                name: row.get(2),
                roles: row.get(3),
                disabled: row.get(4),
                last_signed_in_at: unix(row.get(5)),
            })
            .collect())
    }

    /// 사용자의 업무 역할을 통째로 바꾼다. 선언에 없는 업무 역할이면 거절한다.
    pub fn set_roles(&mut self, user_id: &str, roles: &[Ident]) -> Result<(), AuthError> {
        self.check_roles(roles)?;
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("역할 바꾸기를 시작"))?;
        let found = transaction
            .query_opt(
                "SELECT 1 FROM orbital_auth.users WHERE id = $1 FOR UPDATE",
                &[&user_id],
            )
            .map_err(db("사용자를 찾"))?;
        if found.is_none() {
            return Err(AuthError::NoSuchUser);
        }
        let roles: Vec<&str> = roles.iter().map(Ident::as_str).collect();
        transaction
            .execute(
                "DELETE FROM orbital_auth.user_role WHERE user_id = $1",
                &[&user_id],
            )
            .map_err(db("앞의 역할을 걷"))?;
        transaction
            .execute(
                "INSERT INTO orbital_auth.user_role (user_id, role) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
                &[&user_id, &roles],
            )
            .map_err(db("역할을 적"))?;
        transaction.commit().map_err(db("역할 바꾸기를 마무리"))
    }

    /// 사용자를 뺀다. 막고, 그 사용자의 세션을 모두 거둔다. 사용자의 줄은 남는다(앱의 표가 외래 키로 가리킬 수 있다).
    pub fn remove(&mut self, user_id: &str, now: u64) -> Result<(), AuthError> {
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("사용자 빼기를 시작"))?;
        let changed = transaction
            .execute(
                "UPDATE orbital_auth.users SET disabled_at = coalesce(disabled_at, to_timestamp($2::bigint)) WHERE id = $1",
                &[&user_id, &seconds(now)],
            )
            .map_err(db("사용자를 막"))?;
        if changed == 0 {
            return Err(AuthError::NoSuchUser);
        }
        transaction
            .execute(
                "UPDATE orbital_auth.session SET revoked_at = to_timestamp($2::bigint) \
                 WHERE user_id = $1 AND revoked_at IS NULL",
                &[&user_id, &seconds(now)],
            )
            .map_err(db("사용자의 세션을 거두"))?;
        // 클라이언트에 준 승인과 그 토큰도 거둔다
        transaction
            .execute(
                "UPDATE orbital_auth.oauth_token t SET revoked_at = to_timestamp($2::bigint) \
                 FROM orbital_auth.oauth_grant g \
                 WHERE t.grant_id = g.id AND g.user_id = $1 AND t.revoked_at IS NULL",
                &[&user_id, &seconds(now)],
            )
            .map_err(db("사용자의 토큰을 거두"))?;
        transaction
            .execute(
                "UPDATE orbital_auth.oauth_grant SET revoked_at = to_timestamp($2::bigint) \
                 WHERE user_id = $1 AND revoked_at IS NULL",
                &[&user_id, &seconds(now)],
            )
            .map_err(db("사용자의 승인을 거두"))?;
        transaction.commit().map_err(db("사용자 빼기를 마무리"))
    }
}

/// 이메일의 초대와 그 역할. `lock` 이면 받아들이는 동안 줄을 잠근다.
fn invitation(
    transaction: &mut Transaction<'_>,
    email: &str,
    lock: bool,
) -> Result<Option<(InvitationState, Vec<String>)>, AuthError> {
    let sql = format!(
        "SELECT extract(epoch FROM created_at)::bigint, extract(epoch FROM expires_at)::bigint, \
         extract(epoch FROM accepted_at)::bigint, roles FROM orbital_auth.invitation WHERE email = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&email])
        .map_err(db("초대를 찾"))?;
    Ok(row.map(|row| {
        (
            InvitationState {
                created_at: unix(Some(row.get(0))).unwrap_or(0),
                expires_at: unix(Some(row.get(1))).unwrap_or(0),
                accepted_at: unix(row.get(2)),
            },
            row.get(3),
        )
    }))
}

fn create_user(
    transaction: &mut Transaction<'_>,
    email: &str,
    roles: &[String],
    now: u64,
) -> Result<String, AuthError> {
    let id = user_id()?;
    transaction
        .execute(
            "INSERT INTO orbital_auth.users (id, email, created_at) VALUES ($1, $2, to_timestamp($3::bigint))",
            &[&id, &email, &seconds(now)],
        )
        .map_err(db("사용자를 만들"))?;
    transaction
        .execute(
            "INSERT INTO orbital_auth.user_role (user_id, role) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
            &[&id, &roles],
        )
        .map_err(db("사용자의 역할을 적"))?;
    transaction
        .execute(
            "INSERT INTO orbital_auth.login (provider, subject, user_id) VALUES ('email', lower($1), $2)",
            &[&email, &id],
        )
        .map_err(db("로그인 방법을 적"))?;
    Ok(id)
}

fn create_session(
    transaction: &mut Transaction<'_>,
    user_id: &str,
    now: u64,
) -> Result<Secret, AuthError> {
    let session = Secret::generate()?;
    transaction
        .execute(
            "INSERT INTO orbital_auth.session (token_hash, user_id, created_at, last_seen_at, expires_at) \
             VALUES ($1, $2, to_timestamp($3::bigint), to_timestamp($3::bigint), to_timestamp($4::bigint))",
            &[
                &session.hash(),
                &user_id,
                &seconds(now),
                &seconds(session_expires_at(now)),
            ],
        )
        .map_err(db("세션을 만들"))?;
    Ok(session)
}

fn session_user(
    transaction: &mut Transaction<'_>,
    id: &str,
) -> Result<Option<SessionUser>, AuthError> {
    let row = transaction
        .query_opt(
            "SELECT u.id, u.email::text, u.name, \
             ARRAY(SELECT r.role FROM orbital_auth.user_role r WHERE r.user_id = u.id ORDER BY r.role) \
             FROM orbital_auth.users u WHERE u.id = $1",
            &[&id],
        )
        .map_err(db("사용자를 읽"))?;
    Ok(row.map(|row| SessionUser {
        id: row.get(0),
        email: row.get(1),
        name: row.get(2),
        roles: row.get(3),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 토큰의_글자는_64자의_hex_이고_다시_읽힌다() {
        let secret = Secret::generate().unwrap();
        let text = secret.to_text();
        assert_eq!(text.len(), 64);
        assert_eq!(Secret::parse(&text), Some(secret.clone()));
        assert_eq!(Secret::parse(&text[..63]), None);
        assert_eq!(Secret::parse(&format!("{}zz", &text[..62])), None);
        assert_ne!(Secret::generate().unwrap(), secret);
    }

    #[test]
    fn 토큰은_찍어도_값이_보이지_않는다() {
        let secret = Secret::from_bytes([0xab; 32]);
        assert_eq!(format!("{secret:?}"), "Secret(..)");
    }

    #[test]
    fn 사용자의_식별자는_u_와_소문자_숫자_20자다() {
        for _ in 0..50 {
            let id = user_id().unwrap();
            assert_eq!(id.len(), 22);
            assert!(id.starts_with("u_"));
            assert!(
                id[2..]
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            );
        }
    }
}
