//! 서명된 신원.
//!
//! 행의 주인은 서명된 신원으로만 정해진다. router 가 로그인을 확인해 [`sign`] 으로 서명한 글자열을 앱에 넘기고, 앱은 트랜잭션을 열 때
//! 그것을 그대로 DB 에 넘긴다(`SELECT set_config('orbital.identity', $1, true)`). 행 단위 규칙은 `orbital.subject()` 만 읽는다.
//!
//! 그 값은 누구나 바꿀 수 있는 설정에 담기지만, DB 안의 검증 함수가 읽을 때마다 서명을 확인한다. 서명의 열쇠는 업무 역할이 읽지 못하는
//! 표에 있다. 그래서 앱 코드나 주입된 SQL 이 값을 바꿔도 다른 사람이 되지 못하고, 서명이 틀리면 아무도 아닌 것(NULL)이 된다.
//!
//! 모양은 `v2.<claims 의 hex>.<HMAC-SHA256 의 hex>` 다. hex 를 쓰는 것은 DB 안에서 읽기 쉬워서다.
//! claims 는 `iid`(인스턴스) · `exp`(만료) · `roles`(업무 역할) 와, 사람이면 `sub`(사용자) · `sid`(세션)이다.
//! DB 는 지금 연결의 업무 역할이 `roles` 에 있을 때만 사람을 돌려주고(`orbital.subject()`), 역할 제한 정책은 `orbital.granted()` 로
//! 그 밖의 연결에서 모든 행을 막는다. 앞의 형식(`v1`, 업무 역할이 없다)은 읽지 않는다.

use hmac::{Hmac, Mac};
use orbital_core::name::Ident;
use orbital_core::plan::Names;
use sha2::Sha256;

use crate::{Admin, Error, pg};

/// 서명에 담는 것(`v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// 로그인한 사람(`orbital_auth.users.id`). 사람 없는 실행(스케줄)에는 없다.
    pub subject: Option<String>,
    /// 이 신원이 쓸 수 있는 업무 역할. 지금 연결의 업무 역할이 여기에 없으면 DB 는 어떤 행도 내주지 않는다.
    pub roles: Vec<String>,
    /// 세션을 가리키는 것. 세션의 토큰이 아니다. 사람 없는 실행에는 없다.
    pub session: Option<String>,
    /// 이 시각(유닉스 초)부터 읽히지 않는다.
    pub expires_at: u64,
}

impl Claims {
    /// 사람 없이 업무 역할 하나만 실은 신원. 레이어가 스케줄을 부를 때 쓴다(HTTP 로는 내주지 않는다).
    /// 이 신원으로는 그 역할의 「모든 행」 권한만 쓰고 「자기 행」은 읽지 못한다.
    pub fn for_role(role: &Ident, expires_at: u64) -> Self {
        Self {
            subject: None,
            roles: vec![role.as_str().to_owned()],
            session: None,
            expires_at,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 신원에 서명한다. 레이어(router)만 부른다. 열쇠는 레이어만 갖는다.
pub fn sign(key: &[u8], names: &Names, claims: &Claims) -> String {
    let mut body = serde_json::json!({
        "iid": names.instance().as_str(),
        "exp": claims.expires_at,
        "roles": claims.roles,
    });
    if let Some(subject) = &claims.subject {
        body["sub"] = serde_json::Value::from(subject.as_str());
    }
    if let Some(session) = &claims.session {
        body["sid"] = serde_json::Value::from(session.as_str());
    }
    let body = body.to_string();
    let signed = format!("v2.{}", hex(body.as_bytes()));
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC 은 어떤 길이의 열쇠도 받는다");
    mac.update(signed.as_bytes());
    format!("{signed}.{}", hex(&mac.finalize().into_bytes()))
}

/// 인스턴스의 database 에 두는 것. 스키마 `orbital` 은 레이어의 것이고 선언에 적을 수 없다.
const INSTALL: &str = r#"
CREATE SCHEMA IF NOT EXISTS orbital;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA orbital;

CREATE TABLE IF NOT EXISTS orbital.instance (
    one boolean PRIMARY KEY DEFAULT true CHECK (one),
    id text NOT NULL,
    prefix text NOT NULL,
    signing_key bytea NOT NULL
);
REVOKE ALL ON orbital.instance FROM PUBLIC;

-- 서명이 맞고, 이 인스턴스의 것이고, 만료되지 않았을 때만 내용을 돌려준다. 그 밖에는 모두 NULL 이다.
CREATE OR REPLACE FUNCTION orbital.claims() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = orbital, pg_catalog AS $$
DECLARE
    token text := current_setting('orbital.identity', true);
    parts text[];
    me orbital.instance;
    expected bytea;
    claims jsonb;
BEGIN
    IF token IS NULL OR token = '' THEN
        RETURN NULL;
    END IF;
    parts := string_to_array(token, '.');
    -- v2 만 읽는다. 앞의 형식(v1)에는 업무 역할이 없어서, 바르게 서명됐어도 읽지 않는다
    IF cardinality(parts) <> 3 OR parts[1] <> 'v2' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO me FROM orbital.instance;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    expected := orbital.hmac(convert_to('v2.' || parts[2], 'UTF8'), me.signing_key, 'sha256');
    -- 두 값을 한 번 더 해시해 견준다. 글자를 앞에서부터 견주면 걸린 시간으로 서명을 맞혀 갈 수 있다
    IF sha256(expected) IS DISTINCT FROM sha256(decode(parts[3], 'hex')) THEN
        RETURN NULL;
    END IF;
    claims := convert_from(decode(parts[2], 'hex'), 'UTF8')::jsonb;
    IF claims ->> 'iid' IS DISTINCT FROM me.id THEN
        RETURN NULL;
    END IF;
    IF (claims ->> 'exp')::bigint <= extract(epoch FROM now()) THEN
        RETURN NULL;
    END IF;
    IF jsonb_typeof(claims -> 'roles') IS DISTINCT FROM 'array' THEN
        RETURN NULL;
    END IF;
    RETURN claims;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END
$$;

-- 지금 연결의 업무 역할. 마이그레이션이 인스턴스의 식별자를 몰라도 행 단위 규칙에서 역할을 가를 수 있다.
CREATE OR REPLACE FUNCTION orbital.role() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = orbital, pg_catalog AS $$
    SELECT substr(g.rolname, length(i.prefix) + 4)
    FROM orbital.instance i
    JOIN pg_roles l ON l.rolname = session_user
    JOIN pg_auth_members a ON a.member = l.oid
    JOIN pg_roles g ON g.oid = a.roleid
    WHERE left(g.rolname, length(i.prefix) + 3) = i.prefix || '_r_'
    LIMIT 1
$$;

-- 지금 연결의 업무 역할이 서명된 신원의 업무 역할에 있는가. 신원이 없거나, 서명이 틀리거나, 업무 역할의 연결이 아니면 거짓이다.
-- 역할 제한 정책(orbital_role)이 이것으로 모든 행을 막는다. 그래서 앱이 연결을 잘못 골라도 다른 역할의 행이 나오지 않는다.
CREATE OR REPLACE FUNCTION orbital.granted() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = orbital, pg_catalog AS $$
    SELECT coalesce((orbital.claims() -> 'roles') ? orbital.role(), false)
$$;

-- 로그인한 사람. 행 단위 규칙은 이것만 읽는다. 지금 연결의 업무 역할이 신원에 있을 때만 사람을 돌려준다.
-- 사람 없이 업무 역할만 실은 신원(스케줄)에는 사람이 없다.
CREATE OR REPLACE FUNCTION orbital.subject() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = orbital, pg_catalog AS $$
    SELECT CASE WHEN orbital.granted() THEN orbital.claims() ->> 'sub' END
$$;

-- 이미 돈 마이그레이션의 이름. 소유자는 적기만 하고 고치거나 지우지 못한다.
CREATE TABLE IF NOT EXISTS orbital.migration (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON orbital.migration FROM PUBLIC;

GRANT USAGE ON SCHEMA orbital TO PUBLIC;
"#;

impl Admin {
    /// 인스턴스의 database 에 검증 함수와 서명의 열쇠를 둔다. 열쇠를 바꾸려면 다시 부른다.
    pub fn install_identity(&mut self, names: &Names, key: &[u8]) -> Result<(), Error> {
        let mut client = self.database(&names.database())?;
        client
            .batch_execute(INSTALL)
            .map_err(pg("신원의 검증 함수를 두"))?;
        client
            .execute(
                "INSERT INTO orbital.instance (id, prefix, signing_key) VALUES ($1, $2, $3) \
                 ON CONFLICT (one) DO UPDATE SET id = excluded.id, prefix = excluded.prefix, signing_key = excluded.signing_key",
                &[&names.instance().as_str(), &names.prefix(), &key],
            )
            .map_err(pg("서명의 열쇠를 두"))?;
        client
            .batch_execute(&format!(
                "GRANT SELECT, INSERT ON orbital.migration TO {}",
                crate::quote(&names.owner())
            ))
            .map_err(pg("마이그레이션의 기록을 두"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use orbital_core::name::InstanceId;

    use super::*;

    fn names() -> Names {
        Names::new(InstanceId::parse("k3f9x2ab").unwrap())
    }

    #[test]
    fn 서명은_세_조각이고_같은_입력이면_같은_서명이_나온다() {
        let claims = Claims {
            subject: Some("emp_1".to_owned()),
            roles: vec!["employee".to_owned()],
            session: Some("s_1".to_owned()),
            expires_at: 2_000_000_000,
        };
        let token = sign(b"key", &names(), &claims);
        assert_eq!(token.split('.').count(), 3);
        assert!(token.starts_with("v2."));
        assert_eq!(token, sign(b"key", &names(), &claims));
    }

    #[test]
    fn 열쇠나_사람이나_인스턴스가_다르면_서명이_다르다() {
        let claims = Claims {
            subject: Some("emp_1".to_owned()),
            roles: vec!["employee".to_owned()],
            session: Some("s_1".to_owned()),
            expires_at: 2_000_000_000,
        };
        let token = sign(b"key", &names(), &claims);
        assert_ne!(token, sign(b"other", &names(), &claims));
        assert_ne!(
            token,
            sign(
                b"key",
                &names(),
                &Claims {
                    subject: Some("emp_2".to_owned()),
                    ..claims.clone()
                }
            )
        );
        let other = Names::new(InstanceId::parse("zzzzzzzz").unwrap());
        assert_ne!(token, sign(b"key", &other, &claims));
    }

    #[test]
    fn 따옴표가_든_식별자도_json_을_깨지_않는다() {
        let claims = Claims {
            subject: Some("a\"b\\c".to_owned()),
            roles: Vec::new(),
            session: None,
            expires_at: 1,
        };
        let token = sign(b"key", &names(), &claims);
        let body = token.split('.').nth(1).unwrap();
        let bytes: Vec<u8> = (0..body.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&body[at..at + 2], 16).unwrap())
            .collect();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["sub"], "a\"b\\c");
    }

    fn body(token: &str) -> serde_json::Value {
        let hex = token.split('.').nth(1).unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn 사람의_신원에는_사람과_세션과_업무_역할이_실리고_역할만의_신원에는_사람도_세션도_없다() {
        let person = sign(
            b"key",
            &names(),
            &Claims {
                subject: Some("u_1".to_owned()),
                roles: vec!["employee".to_owned(), "manager".to_owned()],
                session: Some("s_1".to_owned()),
                expires_at: 7,
            },
        );
        assert_eq!(
            body(&person),
            serde_json::json!({ "iid": "k3f9x2ab", "sub": "u_1", "sid": "s_1", "roles": ["employee", "manager"], "exp": 7 })
        );
        let job = sign(
            b"key",
            &names(),
            &Claims::for_role(&Ident::parse("payroll_admin").unwrap(), 7),
        );
        assert_eq!(
            body(&job),
            serde_json::json!({ "iid": "k3f9x2ab", "roles": ["payroll_admin"], "exp": 7 })
        );
    }
}
