//! MCP 의 인가. router 가 자원 서버의 자리를, Orbital Auth 가 인가 서버의 자리를 맡는다. 발급자(`iss`)는 이 router 의 주소다.
//!
//! - 자원 서버: RFC 9728 의 메타데이터를 내고, MCP 주소로 온 요청은 `Authorization: Bearer` 만 본다. 토큰을 해시로 찾아
//!   이 자원용인지까지 본 뒤 신원(`v2`, `cid` 를 싣는다)에 서명해 앱에 넘기고, `Authorization` 머리말은 넘기지 않는다.
//! - 인가 서버: OAuth 2.1(인가 코드 + PKCE S256), RFC 8414 메타데이터, RFC 9207 의 `iss`, RFC 7591 의 동적 등록(끌 수 있다),
//!   Client ID Metadata Documents. 판정은 core 의 `orbital_core::oauth` 가 하고 저장은 `orbital_pg::oauth` 가 한다.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use orbital_core::auth::login_location;
use orbital_core::oauth::{
    ACCESS_TTL, Authorize, AuthorizeQuery, ClientMetadata, KnownClient, Registration, SCOPE,
    document_fresh, document_lifetime, document_url, is_document_id, is_resource_metadata_path,
    judge_authorize, judge_document, judge_registration, mcp, redirect_host, resource_url,
};
use orbital_pg::auth::{AuthError, Secret};
use orbital_pg::oauth::IssuedTokens;
use serde_json::{Value, json};

use super::{
    BODY_LIMIT, Body, Pool, Signed, State, StoreError, Unavailable, error, json_reply, now,
    redirect, same_origin,
};

/// `application/x-www-form-urlencoded` 를 푼다(`+` 는 공백).
fn form_pairs(text: &str) -> Vec<(String, String)> {
    let decode = |part: &str| -> String {
        let bytes = part.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0;
        while at < bytes.len() {
            match bytes[at] {
                b'+' => {
                    out.push(b' ');
                    at += 1;
                }
                b'%' if part.get(at + 1..at + 3).is_some() => {
                    match u8::from_str_radix(&part[at + 1..at + 3], 16) {
                        Ok(byte) => {
                            out.push(byte);
                            at += 3;
                        }
                        Err(_) => {
                            out.push(b'%');
                            at += 1;
                        }
                    }
                }
                byte => {
                    out.push(byte);
                    at += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
}

fn field(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

async fn read_body(request: Request<Incoming>) -> Option<Bytes> {
    Some(
        Limited::new(request.into_body(), BODY_LIMIT)
            .collect()
            .await
            .ok()?
            .to_bytes(),
    )
}

/// RFC 6749 의 오류 답(토큰과 등록의 길).
fn oauth_error(status: StatusCode, code: &str) -> Response<Body> {
    let mut response = json_reply(status, &json!({ "error": code }));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn tokens_reply(tokens: &IssuedTokens) -> Response<Body> {
    let mut response = json_reply(
        StatusCode::OK,
        &json!({
            "access_token": tokens.access.to_text(),
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": tokens.refresh.to_text(),
            "scope": tokens.scope,
        }),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

impl State {
    fn issuer(&self) -> &str {
        &self.config.origin
    }

    /// `/.well-known/oauth-*`. `[auth.mcp]` 가 없으면 모두 없다.
    pub(super) fn well_known(&self, path: &str) -> Response<Body> {
        let Some(mcp) = mcp(&self.config.manifest) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let issuer = self.issuer();
        if path == "/.well-known/oauth-authorization-server" {
            let mut metadata = json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/_orbital/oauth/authorize"),
                "token_endpoint": format!("{issuer}/_orbital/oauth/token"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": [SCOPE],
                "authorization_response_iss_parameter_supported": true,
                "client_id_metadata_document_supported": true,
            });
            if mcp.dynamic_registration {
                metadata["registration_endpoint"] =
                    Value::from(format!("{issuer}/_orbital/oauth/register"));
            }
            return json_reply(StatusCode::OK, &metadata);
        }
        if is_resource_metadata_path(mcp, path) {
            return json_reply(
                StatusCode::OK,
                &json!({
                    "resource": resource_url(issuer, mcp),
                    "authorization_servers": [issuer],
                    "scopes_supported": [SCOPE],
                    "bearer_methods_supported": ["header"],
                }),
            );
        }
        error(StatusCode::NOT_FOUND, "not_found")
    }

    /// 토큰이 없거나 틀렸을 때의 401. 인가 서버를 찾아갈 자원 메타데이터의 주소를 싣는다.
    fn bearer_challenge(&self, invalid: bool) -> Response<Body> {
        let mut response = error(StatusCode::UNAUTHORIZED, "unauthorized");
        let path = mcp(&self.config.manifest).map_or(String::new(), |mcp| resource_url("", mcp));
        let mut challenge = format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource{path}\", scope=\"{SCOPE}\"",
            self.issuer()
        );
        if invalid {
            challenge.push_str(", error=\"invalid_token\"");
        }
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }

    /// MCP 주소로 온 요청. 쿠키는 보지 않고 Bearer 토큰만 본다.
    pub(super) async fn mcp_request(
        &self,
        mut request: Request<Incoming>,
        port: u16,
    ) -> Response<Body> {
        let (Some(pool), Some(mcp)) = (self.pool.clone(), mcp(&self.config.manifest)) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let presented = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                value
                    .split_once(' ')
                    .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                    .map(|(_, token)| token.trim().to_owned())
            });
        // 받은 토큰은 앱으로 넘기지 않는다
        request.headers_mut().remove(header::AUTHORIZATION);
        let Some(presented) = presented else {
            return self.bearer_challenge(false);
        };
        let Some(token) = Secret::parse(&presented) else {
            return self.bearer_challenge(true);
        };
        let resource = resource_url(self.issuer(), mcp);
        match pool
            .run(move |store| store.bearer(&token, &resource, now()))
            .await
        {
            Ok(Some(bearer)) => {
                let signed = Signed {
                    user: bearer.user,
                    session: None,
                    client: Some(bearer.client_id),
                };
                self.forward(request, port, Some(&signed)).await
            }
            Ok(None) | Err(StoreError::Refused(_)) => self.bearer_challenge(true),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    /// `/_orbital/oauth/*`.
    pub(super) async fn oauth(
        &self,
        request: Request<Incoming>,
        pool: Arc<Pool>,
    ) -> Response<Body> {
        let Some(mcp) = mcp(&self.config.manifest) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let tail = path.trim_start_matches("/_orbital/oauth/").to_owned();
        let parts: Vec<&str> = tail.split('/').collect();
        // 사용자의 브라우저가 상태를 바꾸는 요청은 이 router 의 화면에서 온 것만 받는다
        let browser_change = matches!(
            (&method, parts.as_slice()),
            (&Method::POST, ["requests", _, "approve" | "deny"]) | (&Method::DELETE, ["grants", _])
        );
        if browser_change {
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok());
            if !same_origin(origin, &self.config.origin) {
                return error(StatusCode::FORBIDDEN, "forbidden");
            }
        }
        match (method, parts.as_slice()) {
            (Method::GET, ["authorize"]) => self.authorize(&request, pool).await,
            (Method::GET, ["requests", id]) => self.show_request(&request, pool, id).await,
            (Method::POST, ["requests", id, verb @ ("approve" | "deny")]) => {
                self.decide(&request, pool, id, *verb == "approve").await
            }
            (Method::POST, ["token"]) => Self::token(request, pool).await,
            (Method::POST, ["register"]) if mcp.dynamic_registration => {
                Self::register(request, pool).await
            }
            (Method::GET, ["grants"]) => self.list_grants(&request, pool).await,
            (Method::DELETE, ["grants", id]) => self.revoke_grant(&request, pool, id).await,
            _ => error(StatusCode::NOT_FOUND, "not_found"),
        }
    }

    /// `client_id` 의 클라이언트. 등록된 것은 DB 에서 찾고, metadata 문서의 주소이면 기억한 것을 쓰거나 받아 와 판정한다.
    async fn find_client(
        &self,
        pool: &Arc<Pool>,
        client_id: Option<String>,
    ) -> Result<Option<KnownClient>, Unavailable> {
        let Some(id) = client_id else {
            return Ok(None);
        };
        if is_document_id(&id) && document_url(&id).is_err() {
            // 사설망 · 이 기계를 가리키는 주소는 받아 오지도 않는다
            return Ok(None);
        }
        let lookup = id.clone();
        let known = match pool.run(move |store| store.oauth_client(&lookup)).await {
            Ok(known) => known,
            Err(StoreError::Refused(_)) => None,
            Err(StoreError::Unavailable) => return Err(Unavailable),
        };
        let fresh = |fresh_until: Option<u64>| {
            fresh_until.is_some_and(|until| document_fresh(until, now()))
        };
        match known {
            Some(client) if client.kind != "document" || fresh(client.fresh_until) => {
                return Ok(Some(KnownClient {
                    id: client.id,
                    redirect_uris: client.redirect_uris,
                }));
            }
            _ if !is_document_id(&id) => return Ok(None),
            _ => {}
        }
        // metadata 문서를 받아 온다. 막는 일이라 실행기를 막지 않게 따로 된 스레드에서 한다
        let fetcher = Arc::clone(&self.config.documents);
        let url = id.clone();
        let fetched = tokio::task::spawn_blocking(move || fetcher.fetch(&url))
            .await
            .ok()
            .and_then(Result::ok);
        let Some(fetched) = fetched else {
            return Ok(None);
        };
        let lifetime = document_lifetime(fetched.cache_control.as_deref());
        let Ok(document) = serde_json::from_slice::<ClientMetadata>(&fetched.body) else {
            return Ok(None);
        };
        if judge_document(&id, &document).is_err() {
            return Ok(None);
        }
        let name = document.client_name.clone().unwrap_or_default();
        let redirect_uris = document.redirect_uris.clone();
        let (url, uris) = (id.clone(), redirect_uris.clone());
        match pool
            .run(move |store| {
                let at = now();
                store.remember_document(&url, &name, &uris, at, at.saturating_add(lifetime))
            })
            .await
        {
            Ok(()) => Ok(Some(KnownClient { id, redirect_uris })),
            Err(StoreError::Refused(_)) => Ok(None),
            Err(StoreError::Unavailable) => Err(Unavailable),
        }
    }

    async fn authorize(&self, request: &Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let Some(mcp) = mcp(&self.config.manifest) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let pairs = form_pairs(request.uri().query().unwrap_or_default());
        let query = AuthorizeQuery {
            response_type: field(&pairs, "response_type"),
            client_id: field(&pairs, "client_id"),
            redirect_uri: field(&pairs, "redirect_uri"),
            code_challenge: field(&pairs, "code_challenge"),
            code_challenge_method: field(&pairs, "code_challenge_method"),
            resource: field(&pairs, "resource"),
            scope: field(&pairs, "scope"),
            state: field(&pairs, "state"),
        };
        let client = match self.find_client(&pool, query.client_id.clone()).await {
            Ok(client) => client,
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let resource = resource_url(self.issuer(), mcp);
        match judge_authorize(&query, client.as_ref(), &resource, self.issuer()) {
            // 클라이언트나 redirect 가 틀렸다. 그 redirect 로 보내지 않고 여기서 멈춘다
            Authorize::Stop { .. } => json_reply(
                StatusCode::BAD_REQUEST,
                &json!({ "error": "invalid_request", "error_description": "클라이언트나 redirect_uri 가 등록된 것과 다릅니다" }),
            ),
            Authorize::Refuse { location } => redirect(&location),
            Authorize::Accept { request: accepted } => {
                let signed = match self.signed_in(request.headers()).await {
                    Ok(signed) => signed,
                    Err(Unavailable) => {
                        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
                    }
                };
                let Some(signed) = signed else {
                    let path_and_query = request
                        .uri()
                        .path_and_query()
                        .map_or("/", |whole| whole.as_str());
                    return redirect(&login_location(self.login_path(), path_and_query));
                };
                let user = signed.user.id.clone();
                match pool
                    .run(move |store| store.open_request(&user, &accepted, now()))
                    .await
                {
                    Ok(id) => redirect(&format!("{}?request={}", mcp.consent_path, id.to_text())),
                    Err(StoreError::Refused(_) | StoreError::Unavailable) => {
                        error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
                    }
                }
            }
        }
    }

    /// 지금 세션의 사용자. 없으면 `None` 이다.
    async fn session_user(
        &self,
        request: &Request<Incoming>,
    ) -> Result<Option<String>, Unavailable> {
        Ok(self
            .signed_in(request.headers())
            .await?
            .map(|signed| signed.user.id))
    }

    async fn show_request(
        &self,
        request: &Request<Incoming>,
        pool: Arc<Pool>,
        id: &str,
    ) -> Response<Body> {
        // 세션이 없거나, 남의 것이거나, 없는 것이거나 같은 404 다
        let user = match self.session_user(request).await {
            Ok(Some(user)) => user,
            Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let Some(id) = Secret::parse(id) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        match pool
            .run(move |store| store.request(&id, &user, now()))
            .await
        {
            Ok(Some(view)) => json_reply(
                StatusCode::OK,
                &json!({
                    "client": {
                        "id": view.client_id,
                        "name": view.client_name,
                        "redirect_host": redirect_host(&view.redirect_uri),
                    },
                    "scopes": view.scope.split(' ').collect::<Vec<_>>(),
                    "resource": view.resource,
                }),
            ),
            Ok(None) | Err(StoreError::Refused(_)) => error(StatusCode::NOT_FOUND, "not_found"),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    async fn decide(
        &self,
        request: &Request<Incoming>,
        pool: Arc<Pool>,
        id: &str,
        approve: bool,
    ) -> Response<Body> {
        let user = match self.session_user(request).await {
            Ok(Some(user)) => user,
            Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let Some(id) = Secret::parse(id) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        let issuer = self.issuer().to_owned();
        match pool
            .run(move |store| store.decide(&id, &user, approve, &issuer, now()))
            .await
        {
            Ok(location) => json_reply(StatusCode::OK, &json!({ "redirect": location })),
            Err(StoreError::Refused(_)) => error(StatusCode::NOT_FOUND, "not_found"),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    async fn token(request: Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let Some(body) = read_body(request).await else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let pairs = form_pairs(&String::from_utf8_lossy(&body));
        let get = |name: &str| field(&pairs, name);
        let answer = match get("grant_type").as_deref() {
            Some("authorization_code") => {
                let (Some(code), Some(verifier), Some(client_id), Some(redirect_uri)) = (
                    get("code"),
                    get("code_verifier"),
                    get("client_id"),
                    get("redirect_uri"),
                ) else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
                };
                let Some(code) = Secret::parse(&code) else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
                };
                let resource = get("resource");
                pool.run(move |store| {
                    store.exchange_code(
                        &code,
                        &verifier,
                        &client_id,
                        &redirect_uri,
                        resource.as_deref(),
                        now(),
                    )
                })
                .await
            }
            Some("refresh_token") => {
                let (Some(refresh), Some(client_id)) = (get("refresh_token"), get("client_id"))
                else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
                };
                let Some(refresh) = Secret::parse(&refresh) else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
                };
                let resource = get("resource");
                pool.run(move |store| {
                    store.refresh_tokens(&refresh, &client_id, resource.as_deref(), now())
                })
                .await
            }
            _ => return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        };
        match answer {
            Ok(tokens) => tokens_reply(&tokens),
            Err(StoreError::Refused(AuthError::InvalidGrant)) => {
                oauth_error(StatusCode::BAD_REQUEST, "invalid_grant")
            }
            Err(StoreError::Refused(_)) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    async fn register(request: Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let Some(body) = read_body(request).await else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
        };
        let Ok(registration) = serde_json::from_slice::<Registration>(&body) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
        };
        if let Err(problem) = judge_registration(&registration) {
            return oauth_error(StatusCode::BAD_REQUEST, problem.code());
        }
        let name = registration
            .client_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "이름 없는 클라이언트".to_owned());
        let (stored_name, uris, kind) = (
            name.clone(),
            registration.redirect_uris.clone(),
            registration.application_type.clone(),
        );
        let issued_at = now();
        match pool
            .run(move |store| {
                store.register_dynamic(&stored_name, &uris, kind.as_deref(), issued_at)
            })
            .await
        {
            Ok(client_id) => json_reply(
                StatusCode::CREATED,
                &json!({
                    "client_id": client_id,
                    "client_id_issued_at": issued_at,
                    "client_name": name,
                    "redirect_uris": registration.redirect_uris,
                    "application_type": registration.application_type.unwrap_or_else(|| "web".to_owned()),
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                }),
            ),
            Err(StoreError::Refused(AuthError::RateLimited { retry_after })) => {
                let mut response =
                    oauth_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
                response
            }
            Err(StoreError::Refused(_) | StoreError::Unavailable) => {
                error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
            }
        }
    }

    async fn list_grants(&self, request: &Request<Incoming>, pool: Arc<Pool>) -> Response<Body> {
        let user = match self.session_user(request).await {
            Ok(Some(user)) => user,
            Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        match pool.run(move |store| store.grants(&user)).await {
            Ok(grants) => json_reply(
                StatusCode::OK,
                &json!({
                    "grants": grants.iter().map(|grant| json!({
                        "id": grant.id,
                        "client": { "id": grant.client_id, "name": grant.client_name },
                        "created_at": grant.created_at,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(StoreError::Refused(_) | StoreError::Unavailable) => {
                error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
            }
        }
    }

    async fn revoke_grant(
        &self,
        request: &Request<Incoming>,
        pool: Arc<Pool>,
        id: &str,
    ) -> Response<Body> {
        let user = match self.session_user(request).await {
            Ok(Some(user)) => user,
            Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
            Err(Unavailable) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let grant = id.to_owned();
        match pool
            .run(move |store| store.revoke_grant(&user, &grant, now()))
            .await
        {
            Ok(true) => {
                let mut response = Response::new(super::empty());
                *response.status_mut() = StatusCode::NO_CONTENT;
                response
            }
            Ok(false) | Err(StoreError::Refused(_)) => error(StatusCode::NOT_FOUND, "not_found"),
            Err(StoreError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }
}
