//! MCP 의 인가(OAuth 2.1)의 저장소. 인증 역할로 붙은 [`AuthStore`] 가 `orbital_auth` 의 `oauth_*` 표를 읽고 쓴다.
//!
//! 판정(인가 요청 · PKCE · 코드와 토큰의 만료 · 쓴 것 · 대상 자원)은 core 의 `orbital_core::oauth` 가 한다. 여기서는 읽어 넘기고
//! 그 답대로 적는다. 코드 · 토큰 · 요청의 식별자는 32바이트 무작위이고 DB 에는 sha256 해시만 둔다.
//!
//! 다시 쓰인 것을 거두는 규칙:
//! - 쓴 인가 코드가 다시 오면 그 코드로 낸 토큰(갈아 준 것까지)을 모두 거둔다.
//! - 쓴 refresh 토큰이 다시 오면 그 승인(grant) 전체와 그 토큰을 모두 거둔다.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbital_core::oauth::{
    ACCESS_TTL, Accepted, CodeRefusal, CodeState, REFRESH_TTL, REGISTRATION_WINDOW, REQUEST_TTL,
    TokenRefusal, TokenState, approved_location, code_expires_at, denied_location, judge_code,
    judge_token, pkce_matches, registration_wait, request_open, unapproved_cutoff,
};
use postgres::Transaction;
use sha2::{Digest, Sha256};

use crate::auth::{AuthError, AuthStore, Secret, SessionUser, db, random_id, seconds, sweep, unix};

/// 인가 서버가 아는 클라이언트.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthClient {
    pub id: String,
    /// `registered`(팩토리가 미리 등록) · `dynamic`(동적 등록) · `document`(metadata 문서).
    pub kind: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// metadata 문서를 기억해도 되는 마지막 때(유닉스 초).
    pub fresh_until: Option<u64>,
}

/// 동의 화면이 읽는 요청.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub scope: String,
    pub resource: String,
}

/// 낸 토큰 한 벌. 토큰은 여기서만 글자로 있고 DB 에는 해시만 있다.
#[derive(Debug)]
pub struct IssuedTokens {
    pub access: Secret,
    pub refresh: Secret,
    pub scope: String,
}

/// MCP 의 토큰이 가리키는 사용자와 클라이언트.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerUser {
    pub user: SessionUser,
    pub client_id: String,
}

/// 사용자가 클라이언트에 준 승인 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub created_at: u64,
}

/// PKCE 의 S256: `BASE64URL(SHA256(verifier))`(덧붙임 없음). 해시는 검증된 구현(`sha2`)으로 계산한다.
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// verifier 가 challenge 에 맞는가. 해시는 여기서 계산하고, 모양과 견주기는 core 의 `pkce_matches` 가 판정한다.
pub fn verifier_matches(challenge: &str, verifier: &str) -> bool {
    pkce_matches(challenge, verifier, &s256(verifier))
}

fn issue(
    transaction: &mut Transaction<'_>,
    grant_id: &str,
    code_hash: &[u8],
    resource: &str,
    scope: &str,
    now: u64,
) -> Result<IssuedTokens, AuthError> {
    let access = Secret::generate()?;
    let refresh = Secret::generate()?;
    for (token, kind, ttl) in [
        (&access, "access", ACCESS_TTL),
        (&refresh, "refresh", REFRESH_TTL),
    ] {
        transaction
            .execute(
                "INSERT INTO orbital_auth.oauth_token (token_hash, kind, grant_id, code_hash, resource, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint), to_timestamp($7::bigint))",
                &[
                    &token.hash(),
                    &kind,
                    &grant_id,
                    &code_hash,
                    &resource,
                    &seconds(now),
                    &seconds(now.saturating_add(ttl)),
                ],
            )
            .map_err(db("토큰을 내"))?;
    }
    Ok(IssuedTokens {
        access,
        refresh,
        scope: scope.to_owned(),
    })
}

impl AuthStore {
    /// 클라이언트를 등록한다(`registered` · `dynamic`). 식별자를 지어 돌려준다. redirect 의 판정은 부르는 쪽이 core 로 먼저 한다.
    pub fn register_client(
        &mut self,
        kind: &str,
        name: &str,
        redirect_uris: &[String],
        application_type: Option<&str>,
        now: u64,
    ) -> Result<String, AuthError> {
        let id = random_id("c_")?;
        self.client
            .execute(
                "INSERT INTO orbital_auth.oauth_client (id, kind, name, redirect_uris, application_type, created_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint))",
                &[&id, &kind, &name, &redirect_uris, &application_type, &seconds(now)],
            )
            .map_err(db("클라이언트를 등록하"))?;
        Ok(id)
    }

    /// 동적 등록(RFC 7591). 한도를 넘으면 `RateLimited` 로 몇 초 뒤에 다시 하라고 알린다.
    ///
    /// 한 번도 승인받지 못하고 하루가 지난 동적 클라이언트는 여기서 함께 치운다. 같은 인스턴스의 등록은 잠금으로 하나씩 센다.
    pub fn register_dynamic(
        &mut self,
        name: &str,
        redirect_uris: &[String],
        application_type: Option<&str>,
        now: u64,
    ) -> Result<String, AuthError> {
        let mut transaction = self.client.transaction().map_err(db("동적 등록을 시작"))?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtext('orbital_auth.oauth_register'))",
                &[],
            )
            .map_err(db("동적 등록을 잠그"))?;
        transaction
            .execute(
                "DELETE FROM orbital_auth.oauth_client c WHERE c.kind = 'dynamic' \
                 AND c.created_at < to_timestamp($1::bigint) \
                 AND NOT EXISTS (SELECT 1 FROM orbital_auth.oauth_grant g WHERE g.client_id = c.id)",
                &[&seconds(unapproved_cutoff(now))],
            )
            .map_err(db("승인받지 못한 동적 클라이언트를 치우"))?;
        let recent: Vec<u64> = transaction
            .query(
                "SELECT extract(epoch FROM created_at)::bigint FROM orbital_auth.oauth_client \
                 WHERE kind = 'dynamic' AND created_at > to_timestamp($1::bigint)",
                &[&seconds(now.saturating_sub(REGISTRATION_WINDOW))],
            )
            .map_err(db("최근의 동적 등록을 세"))?
            .iter()
            .filter_map(|row| unix(row.get(0)))
            .collect();
        let live: i64 = transaction
            .query_one(
                "SELECT count(*) FROM orbital_auth.oauth_client WHERE kind = 'dynamic'",
                &[],
            )
            .map_err(db("동적 클라이언트를 세"))?
            .get(0);
        if let Some(retry_after) =
            registration_wait(&recent, usize::try_from(live).unwrap_or(usize::MAX), now)
        {
            return Err(AuthError::RateLimited { retry_after });
        }
        let id = random_id("c_")?;
        transaction
            .execute(
                "INSERT INTO orbital_auth.oauth_client (id, kind, name, redirect_uris, application_type, created_at) \
                 VALUES ($1, 'dynamic', $2, $3, $4, to_timestamp($5::bigint))",
                &[&id, &name, &redirect_uris, &application_type, &seconds(now)],
            )
            .map_err(db("클라이언트를 등록하"))?;
        transaction.commit().map_err(db("동적 등록을 마무리"))?;
        Ok(id)
    }

    /// metadata 문서로 밝힌 클라이언트를 적어 둔다. 다시 받아 오면 이름과 redirect 를 새로 적는다.
    pub fn remember_document(
        &mut self,
        url: &str,
        name: &str,
        redirect_uris: &[String],
        now: u64,
        fresh_until: u64,
    ) -> Result<(), AuthError> {
        self.client
            .execute(
                "INSERT INTO orbital_auth.oauth_client (id, kind, name, redirect_uris, created_at, fetched_at, fresh_until) \
                 VALUES ($1, 'document', $2, $3, to_timestamp($4::bigint), to_timestamp($4::bigint), to_timestamp($5::bigint)) \
                 ON CONFLICT (id) DO UPDATE SET name = excluded.name, redirect_uris = excluded.redirect_uris, \
                 fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until \
                 WHERE orbital_auth.oauth_client.kind = 'document'",
                &[&url, &name, &redirect_uris, &seconds(now), &seconds(fresh_until)],
            )
            .map_err(db("metadata 문서를 적"))?;
        Ok(())
    }

    pub fn oauth_client(&mut self, id: &str) -> Result<Option<OauthClient>, AuthError> {
        let row = self
            .client
            .query_opt(
                "SELECT id, kind, name, redirect_uris, extract(epoch FROM fresh_until)::bigint \
                 FROM orbital_auth.oauth_client WHERE id = $1",
                &[&id],
            )
            .map_err(db("클라이언트를 찾"))?;
        Ok(row.map(|row| OauthClient {
            id: row.get(0),
            kind: row.get(1),
            name: row.get(2),
            redirect_uris: row.get(3),
            fresh_until: unix(row.get(4)),
        }))
    }

    /// 받아들인 인가 요청을 그 사용자의 것으로 적어 두고 요청의 식별자를 돌려준다. 동의 화면이 이것으로 읽고 정한다.
    pub fn open_request(
        &mut self,
        user_id: &str,
        request: &Accepted,
        now: u64,
    ) -> Result<Secret, AuthError> {
        sweep(&mut self.client, now)?;
        let id = Secret::generate()?;
        self.client
            .execute(
                "INSERT INTO orbital_auth.oauth_request (id_hash, user_id, client_id, redirect_uri, code_challenge, resource, scope, state, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9::bigint), to_timestamp($10::bigint))",
                &[
                    &id.hash(),
                    &user_id,
                    &request.client_id,
                    &request.redirect_uri,
                    &request.code_challenge,
                    &request.resource,
                    &request.scope,
                    &request.state,
                    &seconds(now),
                    &seconds(now.saturating_add(REQUEST_TTL)),
                ],
            )
            .map_err(db("인가 요청을 적"))?;
        Ok(id)
    }

    /// 동의 화면이 보일 요청. 그 요청을 연 사용자가 아니거나, 정했거나, 만료됐으면 없는 것이다.
    pub fn request(
        &mut self,
        id: &Secret,
        user_id: &str,
        now: u64,
    ) -> Result<Option<RequestView>, AuthError> {
        let row = self
            .client
            .query_opt(
                "SELECT r.client_id, c.name, r.redirect_uri, r.scope, r.resource, \
                 extract(epoch FROM r.expires_at)::bigint, r.decided_at IS NOT NULL \
                 FROM orbital_auth.oauth_request r JOIN orbital_auth.oauth_client c ON c.id = r.client_id \
                 WHERE r.id_hash = $1 AND r.user_id = $2",
                &[&id.hash(), &user_id],
            )
            .map_err(db("인가 요청을 찾"))?;
        Ok(row
            .filter(|row| request_open(unix(Some(row.get(5))).unwrap_or(0), row.get(6), now))
            .map(|row| RequestView {
                client_id: row.get(0),
                client_name: row.get(1),
                redirect_uri: row.get(2),
                scope: row.get(3),
                resource: row.get(4),
            }))
    }

    /// 사용자가 요청을 정한다. 승인이면 승인(grant)과 인가 코드를 만들고, 브라우저가 갈 주소를 돌려준다.
    ///
    /// 요청의 줄을 잠그고 읽은 뒤 core 로 판정하고, `decided_at IS NULL` 인 줄만 고치는 한 문장으로 정한 것으로 적는다.
    /// 그 요청을 연 사용자가 아니면 없는 것과 같은 답이다.
    pub fn decide(
        &mut self,
        id: &Secret,
        user_id: &str,
        approve: bool,
        issuer: &str,
        now: u64,
    ) -> Result<String, AuthError> {
        let mut transaction = self.client.transaction().map_err(db("동의를 적기 시작"))?;
        let row = transaction
            .query_opt(
                "SELECT client_id, redirect_uri, code_challenge, resource, scope, state, \
                 extract(epoch FROM expires_at)::bigint, decided_at IS NOT NULL \
                 FROM orbital_auth.oauth_request WHERE id_hash = $1 AND user_id = $2 FOR UPDATE",
                &[&id.hash(), &user_id],
            )
            .map_err(db("인가 요청을 찾"))?
            .ok_or(AuthError::NoSuchRequest)?;
        if !request_open(unix(Some(row.get(6))).unwrap_or(0), row.get(7), now) {
            return Err(AuthError::NoSuchRequest);
        }
        let marked = transaction
            .execute(
                "UPDATE orbital_auth.oauth_request SET decided_at = to_timestamp($2::bigint) \
                 WHERE id_hash = $1 AND decided_at IS NULL",
                &[&id.hash(), &seconds(now)],
            )
            .map_err(db("인가 요청을 정한 것으로 적"))?;
        if marked != 1 {
            return Err(AuthError::NoSuchRequest);
        }
        let request = Accepted {
            client_id: row.get(0),
            redirect_uri: row.get(1),
            code_challenge: row.get(2),
            resource: row.get(3),
            scope: row.get(4),
            state: row.get(5),
        };
        if !approve {
            transaction.commit().map_err(db("동의를 적기를 마무리"))?;
            return Ok(denied_location(&request, issuer));
        }
        let grant = random_id("g_")?;
        transaction
            .execute(
                "INSERT INTO orbital_auth.oauth_grant (id, user_id, client_id, scope, resource, created_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint))",
                &[&grant, &user_id, &request.client_id, &request.scope, &request.resource, &seconds(now)],
            )
            .map_err(db("승인을 적"))?;
        let code = Secret::generate()?;
        transaction
            .execute(
                "INSERT INTO orbital_auth.oauth_code (code_hash, grant_id, redirect_uri, code_challenge, resource, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint), to_timestamp($7::bigint))",
                &[
                    &code.hash(),
                    &grant,
                    &request.redirect_uri,
                    &request.code_challenge,
                    &request.resource,
                    &seconds(now),
                    &seconds(code_expires_at(now)),
                ],
            )
            .map_err(db("인가 코드를 적"))?;
        transaction.commit().map_err(db("동의를 적기를 마무리"))?;
        Ok(approved_location(&request, &code.to_text(), issuer))
    }

    /// 인가 코드를 토큰으로 바꾼다. 어긋나면 모두 `InvalidGrant` 이고 까닭은 밖에 알리지 않는다.
    ///
    /// 코드의 줄을 잠그고 읽어 core 로 판정한다. 이미 쓴 코드가 다시 왔으면 그 코드로 낸 토큰을 모두 거두고 그것을 적어 둔 채 거절한다.
    pub fn exchange_code(
        &mut self,
        code: &Secret,
        verifier: &str,
        client_id: &str,
        redirect_uri: &str,
        resource: Option<&str>,
        now: u64,
    ) -> Result<IssuedTokens, AuthError> {
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("코드 바꾸기를 시작"))?;
        let row = transaction
            .query_opt(
                "SELECT c.grant_id, c.redirect_uri, c.code_challenge, c.resource, \
                 extract(epoch FROM c.expires_at)::bigint, extract(epoch FROM c.used_at)::bigint, \
                 g.client_id, g.scope, g.revoked_at IS NOT NULL, u.disabled_at IS NOT NULL \
                 FROM orbital_auth.oauth_code c \
                 JOIN orbital_auth.oauth_grant g ON g.id = c.grant_id \
                 JOIN orbital_auth.users u ON u.id = g.user_id \
                 WHERE c.code_hash = $1 FOR UPDATE OF c",
                &[&code.hash()],
            )
            .map_err(db("인가 코드를 찾"))?
            .ok_or(AuthError::InvalidGrant)?;
        let state = CodeState {
            expires_at: unix(Some(row.get(4))).unwrap_or(0),
            used_at: unix(row.get(5)),
        };
        match judge_code(&state, now) {
            Ok(()) => {}
            Err(CodeRefusal::Used) => {
                transaction
                    .execute(
                        "UPDATE orbital_auth.oauth_token SET revoked_at = to_timestamp($2::bigint) \
                         WHERE code_hash = $1 AND revoked_at IS NULL",
                        &[&code.hash(), &seconds(now)],
                    )
                    .map_err(db("다시 쓰인 코드의 토큰을 거두"))?;
                transaction
                    .commit()
                    .map_err(db("다시 쓰인 코드의 토큰을 거두기를 마무리"))?;
                return Err(AuthError::InvalidGrant);
            }
            Err(CodeRefusal::Expired) => return Err(AuthError::InvalidGrant),
        }
        let grant_id: String = row.get(0);
        let stored_redirect: String = row.get(1);
        let challenge: String = row.get(2);
        let stored_resource: String = row.get(3);
        let stored_client: String = row.get(6);
        let scope: String = row.get(7);
        let (grant_revoked, user_disabled): (bool, bool) = (row.get(8), row.get(9));
        let matches = stored_client == client_id
            && stored_redirect == redirect_uri
            && resource.is_none_or(|given| given == stored_resource)
            && verifier_matches(&challenge, verifier)
            && !grant_revoked
            && !user_disabled;
        if !matches {
            return Err(AuthError::InvalidGrant);
        }
        let marked = transaction
            .execute(
                "UPDATE orbital_auth.oauth_code SET used_at = to_timestamp($2::bigint) WHERE code_hash = $1 AND used_at IS NULL",
                &[&code.hash(), &seconds(now)],
            )
            .map_err(db("인가 코드를 쓴 것으로 적"))?;
        if marked != 1 {
            return Err(AuthError::InvalidGrant);
        }
        let tokens = issue(
            &mut transaction,
            &grant_id,
            &code.hash(),
            &stored_resource,
            &scope,
            now,
        )?;
        transaction.commit().map_err(db("코드 바꾸기를 마무리"))?;
        Ok(tokens)
    }

    /// refresh 토큰을 새 토큰 한 벌로 간다. 쓴 refresh 토큰은 다시 쓰이지 않는다.
    ///
    /// 이미 쓴 refresh 토큰이 다시 왔으면 누군가 훔쳐 간 것으로 보고 그 승인 전체와 그 토큰을 거두고 그것을 적어 둔 채 거절한다.
    pub fn refresh_tokens(
        &mut self,
        refresh: &Secret,
        client_id: &str,
        resource: Option<&str>,
        now: u64,
    ) -> Result<IssuedTokens, AuthError> {
        let mut transaction = self.client.transaction().map_err(db("토큰 갈기를 시작"))?;
        let row = transaction
            .query_opt(
                "SELECT t.grant_id, t.code_hash, t.resource, extract(epoch FROM t.expires_at)::bigint, \
                 t.revoked_at IS NOT NULL, t.used_at IS NOT NULL, g.revoked_at IS NOT NULL, u.disabled_at IS NOT NULL, \
                 g.client_id, g.scope \
                 FROM orbital_auth.oauth_token t \
                 JOIN orbital_auth.oauth_grant g ON g.id = t.grant_id \
                 JOIN orbital_auth.users u ON u.id = g.user_id \
                 WHERE t.token_hash = $1 AND t.kind = 'refresh' FOR UPDATE OF t",
                &[&refresh.hash()],
            )
            .map_err(db("refresh 토큰을 찾"))?
            .ok_or(AuthError::InvalidGrant)?;
        let grant_id: String = row.get(0);
        let code_hash: Vec<u8> = row.get(1);
        let stored_resource: String = row.get(2);
        let state = TokenState {
            expires_at: unix(Some(row.get(3))).unwrap_or(0),
            revoked: row.get(4),
            used: row.get(5),
            grant_revoked: row.get(6),
            user_disabled: row.get(7),
            resource: stored_resource.clone(),
        };
        match judge_token(&state, resource.unwrap_or(&stored_resource), now) {
            Ok(()) => {}
            Err(TokenRefusal::Used) => {
                transaction
                    .execute(
                        "UPDATE orbital_auth.oauth_grant SET revoked_at = to_timestamp($2::bigint) WHERE id = $1 AND revoked_at IS NULL",
                        &[&grant_id, &seconds(now)],
                    )
                    .map_err(db("다시 쓰인 refresh 토큰의 승인을 거두"))?;
                transaction
                    .execute(
                        "UPDATE orbital_auth.oauth_token SET revoked_at = to_timestamp($2::bigint) WHERE grant_id = $1 AND revoked_at IS NULL",
                        &[&grant_id, &seconds(now)],
                    )
                    .map_err(db("다시 쓰인 refresh 토큰의 줄기를 거두"))?;
                transaction
                    .commit()
                    .map_err(db("다시 쓰인 refresh 토큰을 거두기를 마무리"))?;
                return Err(AuthError::InvalidGrant);
            }
            Err(_) => return Err(AuthError::InvalidGrant),
        }
        let stored_client: String = row.get(8);
        let scope: String = row.get(9);
        if stored_client != client_id {
            return Err(AuthError::InvalidGrant);
        }
        let marked = transaction
            .execute(
                "UPDATE orbital_auth.oauth_token SET used_at = to_timestamp($2::bigint) WHERE token_hash = $1 AND used_at IS NULL",
                &[&refresh.hash(), &seconds(now)],
            )
            .map_err(db("refresh 토큰을 쓴 것으로 적"))?;
        if marked != 1 {
            return Err(AuthError::InvalidGrant);
        }
        let tokens = issue(
            &mut transaction,
            &grant_id,
            &code_hash,
            &stored_resource,
            &scope,
            now,
        )?;
        transaction.commit().map_err(db("토큰 갈기를 마무리"))?;
        Ok(tokens)
    }

    /// MCP 요청의 access 토큰이 가리키는 사용자. 요청마다 부르므로 한 문장으로 읽는다.
    /// 없거나, 만료됐거나, 거뒀거나, 승인이 거둬졌거나, 사용자가 막혔거나, 이 자원용이 아니면 `None` 이다.
    pub fn bearer(
        &mut self,
        access: &Secret,
        resource: &str,
        now: u64,
    ) -> Result<Option<BearerUser>, AuthError> {
        let Some(row) = self
            .client
            .query_opt(
                "SELECT extract(epoch FROM t.expires_at)::bigint, t.revoked_at IS NOT NULL, g.revoked_at IS NOT NULL, \
                 u.disabled_at IS NOT NULL, t.resource, g.client_id, u.id, u.email::text, u.name, \
                 ARRAY(SELECT r.role FROM orbital_auth.user_role r WHERE r.user_id = u.id ORDER BY r.role) \
                 FROM orbital_auth.oauth_token t \
                 JOIN orbital_auth.oauth_grant g ON g.id = t.grant_id \
                 JOIN orbital_auth.users u ON u.id = g.user_id \
                 WHERE t.token_hash = $1 AND t.kind = 'access'",
                &[&access.hash()],
            )
            .map_err(db("access 토큰을 찾"))?
        else {
            return Ok(None);
        };
        let state = TokenState {
            expires_at: unix(Some(row.get(0))).unwrap_or(0),
            revoked: row.get(1),
            used: false,
            grant_revoked: row.get(2),
            user_disabled: row.get(3),
            resource: row.get(4),
        };
        if judge_token(&state, resource, now).is_err() {
            return Ok(None);
        }
        Ok(Some(BearerUser {
            client_id: row.get(5),
            user: SessionUser {
                id: row.get(6),
                email: row.get(7),
                name: row.get(8),
                roles: row.get(9),
            },
        }))
    }

    /// 사용자가 준 승인 가운데 살아 있는 것.
    pub fn grants(&mut self, user_id: &str) -> Result<Vec<GrantView>, AuthError> {
        let rows = self
            .client
            .query(
                "SELECT g.id, g.client_id, c.name, extract(epoch FROM g.created_at)::bigint \
                 FROM orbital_auth.oauth_grant g JOIN orbital_auth.oauth_client c ON c.id = g.client_id \
                 WHERE g.user_id = $1 AND g.revoked_at IS NULL ORDER BY g.created_at",
                &[&user_id],
            )
            .map_err(db("승인 목록을 읽"))?;
        Ok(rows
            .iter()
            .map(|row| GrantView {
                id: row.get(0),
                client_id: row.get(1),
                client_name: row.get(2),
                created_at: unix(Some(row.get(3))).unwrap_or(0),
            })
            .collect())
    }

    /// 사용자가 제 승인을 거둔다. 그 승인의 토큰도 모두 거둔다. 남의 것이거나 없으면 `false` 다.
    pub fn revoke_grant(
        &mut self,
        user_id: &str,
        grant_id: &str,
        now: u64,
    ) -> Result<bool, AuthError> {
        let mut transaction = self
            .client
            .transaction()
            .map_err(db("승인 거두기를 시작"))?;
        let changed = transaction
            .execute(
                "UPDATE orbital_auth.oauth_grant SET revoked_at = to_timestamp($3::bigint) \
                 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
                &[&grant_id, &user_id, &seconds(now)],
            )
            .map_err(db("승인을 거두"))?;
        if changed == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "UPDATE orbital_auth.oauth_token SET revoked_at = to_timestamp($2::bigint) WHERE grant_id = $1 AND revoked_at IS NULL",
                &[&grant_id, &seconds(now)],
            )
            .map_err(db("승인의 토큰을 거두"))?;
        transaction.commit().map_err(db("승인 거두기를 마무리"))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7636_부록_b_의_verifier_는_그_challenge_를_낸다() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256(verifier), challenge);
        assert!(verifier_matches(challenge, verifier));
    }

    #[test]
    fn verifier_가_challenge_와_맞지_않으면_토큰을_내지_않는다() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256(verifier);
        let mut other = verifier.to_owned();
        other.replace_range(0..1, "e");
        assert!(!verifier_matches(&challenge, &other));
        assert!(!verifier_matches(&challenge, ""));
        // verifier 자체를 challenge 로 내밀어도(plain) 맞지 않는다
        assert!(!verifier_matches(verifier, verifier));
        // 모양이 틀린 verifier 는 해시가 맞아도 받지 않는다(42자 · 허용되지 않는 글자)
        let short = &verifier[..42];
        assert!(!verifier_matches(&s256(short), short));
        let odd = format!("{}!", &verifier[..42]);
        assert!(!verifier_matches(&s256(&odd), &odd));
    }
}
