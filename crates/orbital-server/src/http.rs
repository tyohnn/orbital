//! HTTP API. CLI(에이전트)와 SDK(팩토리의 서버)가 모두 이것을 부른다.
//!
//! 요청마다 `Authorization: Bearer …` 를 본다. `orb1.` 로 시작하면 에이전트의 토큰이고, 아니면 팩토리의 service key 다.
//! 토큰으로 되는 일과 service key 로 되는 일은 길이 다르다. 운영을 바꾸는 길은 service key 쪽에만 있다.
//! 열쇠 없이 오는 길은 Google 의 콜백(`GET /v1/auth/google/callback`) 하나다. 무엇을 할지는 레이어가 서명한 `state` 가 정한다.
//! 팩토리의 로그인 설정(`/v1/settings/auth`)은 service key 에만 있고, 넣은 비밀은 어떤 답에도 싣지 않는다.
//! 밖에서 넣는 비밀(`/v1/instances/{id}/secrets`)의 값은 service key 와 입력 표(`/v1/secret-entries/{표}`)로만 들어오고 어떤 열쇠로도 나가지 않는다.
//! 입력 표의 길은 쿠키도 키도 보지 않고 표만 보며, 사람의 브라우저(팩토리의 카드)가 다른 출처에서 부르므로 CORS 를 연다.
//! 무엇이 허락되는지는 여기서 정하지 않는다. 토큰은 core 의 `scope::judge` 가, 승격은 core 의 `release::promote` 가 판정한다.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::sync::Arc;

use orbital_core::auth::query_value;
use orbital_core::name::InstanceId;
use orbital_core::release::{Approver, Change, PromoteDenied};
use orbital_core::scope::{Action, Capability};
use orbital_core::secrets::Stage as SecretStage;
use orbital_source::Commit;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::layer::{Failure, Layer, NewRollout};
use crate::vault::SecretValue;

/// 묶음(코드)의 상한.
const MAX_BUNDLE: usize = 64 * 1024 * 1024;

pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// 302 로 보낼 곳. Google 의 콜백만 쓴다.
    pub location: Option<String>,
    /// 다른 출처의 브라우저에 연다(`Access-Control-Allow-Origin: *`, 자격 증명 없이). 입력 표의 길만 쓴다.
    pub cors: bool,
}

fn ok(value: Value) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        body: value.to_string().into_bytes(),
        location: None,
        cors: false,
    }
}

fn found(location: String) -> Reply {
    Reply {
        status: 302,
        content_type: "application/json",
        body: b"{}".to_vec(),
        location: Some(location),
        cors: false,
    }
}

fn problem(status: u16, code: &str, message: &str, details: Vec<String>) -> Reply {
    let body = json!({ "error": code, "message": message, "details": details });
    Reply {
        status,
        content_type: "application/json",
        body: body.to_string().into_bytes(),
        location: None,
        cors: false,
    }
}

fn denied(denied: &PromoteDenied) -> Reply {
    use orbital_core::release::Blocker;
    let (message, details) = match denied {
        PromoteDenied::Blocked { blockers } => (
            "승격을 막는 것이 있습니다",
            blockers
                .iter()
                .map(|blocker| match blocker {
                    Blocker::NotBuiltByLayer => "레이어가 빌드한 것이 아닙니다".to_owned(),
                    Blocker::AccessCheckFailed { findings } => {
                        format!("권한 검사에서 어긋남이 {findings}개 나왔습니다. `orbital preview` 의 결과를 보고 고쳐 주세요")
                    }
                    Blocker::RehearsalNotRun => "마이그레이션의 리허설을 아직 돌리지 않았습니다. `orbital rehearse` 로 돌려 주세요".to_owned(),
                    Blocker::RehearsalFailed => "마이그레이션의 리허설이 실패했습니다".to_owned(),
                    Blocker::KeyMissing { key } => crate::layer::key_text(*key),
                    Blocker::SecretMissing { secret } => crate::layer::secret_text(secret),
                    Blocker::ConformanceFailed { outcome } => crate::layer::conformance_text(*outcome),
                })
                .collect(),
        ),
        PromoteDenied::NoApproval => ("사람의 승인이 없습니다", Vec::new()),
        PromoteDenied::ApprovalForOtherRelease => ("승인이 다른 release 의 것입니다. 승인한 뒤에 코드가 바뀌었습니다", Vec::new()),
        PromoteDenied::WrongApprover { needs: Approver::Customer } => ("이 변경은 고객이 승인해야 합니다", Vec::new()),
        PromoteDenied::WrongApprover { needs: Approver::Factory } => ("이 변경은 팩토리가 승인해야 합니다", Vec::new()),
    };
    problem(409, "denied", message, details)
}

fn failure(failure: Failure) -> Reply {
    match failure {
        // 없는 것과 범위 밖의 것을 같은 답으로 돌려준다
        Failure::NotFound => problem(404, "not_found", "없습니다", Vec::new()),
        Failure::Unauthorized => problem(
            401,
            "unauthorized",
            "토큰이 없거나 만료되었습니다",
            Vec::new(),
        ),
        Failure::Forbidden(why) => problem(403, "forbidden", &why, Vec::new()),
        Failure::Problems(problems) => problem(422, "problems", "고칠 것이 있습니다", problems),
        Failure::BuildFailed { service, log } => problem(
            422,
            "build_failed",
            &format!("서비스 `{service}` 의 빌드가 실패했습니다. 로그의 끝을 함께 보냅니다"),
            vec![log],
        ),
        Failure::StartFailed { service, log } => problem(
            422,
            "start_failed",
            &format!(
                "서비스 `{service}` 가 뜨지 않았습니다. 레이어가 알려 준 포트(PORT)에서 요청을 받는지 확인해 주세요"
            ),
            vec![log],
        ),
        Failure::MigrationFailed(message) => problem(422, "migration_failed", &message, Vec::new()),
        Failure::Invalid(message) => problem(400, "invalid", &message, Vec::new()),
        Failure::Denied(why) => denied(&why),
        Failure::Conflict(message) => problem(409, "conflict", &message, Vec::new()),
        Failure::Gone(message) => problem(410, "gone", &message, Vec::new()),
        Failure::Internal(message) => problem(500, "internal", &message, Vec::new()),
    }
}

fn parse<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Failure> {
    serde_json::from_slice(body)
        .map_err(|error| Failure::Problems(vec![format!("요청의 본문을 읽지 못했습니다: {error}")]))
}

/// 비밀이 실릴 수 있는 본문을 읽는다. JSON 의 오류 문구는 본문의 조각(값)을 되풀이할 수 있어 싣지 않고 모양만 알린다.
fn parse_quietly<'a, T: Deserialize<'a>>(body: &'a [u8], shape: &str) -> Result<T, Failure> {
    serde_json::from_slice(body).map_err(|_| {
        Failure::Problems(vec![format!(
            "요청의 본문은 `{shape}` 모양의 JSON 이어야 합니다. 모르는 칸은 받지 않습니다"
        )])
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSecretRequest {
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSecretValue {
    stage: SecretStage,
    value: SecretValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewEntry {
    stage: SecretStage,
}

/// 입력 표로 보낸 본문. 이름과 단계는 적지 않아도 되고, 적었으면 표의 것과 같아야 한다.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnteredValue {
    value: SecretValue,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    stage: Option<SecretStage>,
}

/// 비밀의 이름마다의 모습. 값은 싣지 않는다.
fn secrets_reply(
    layer: &Layer,
    organization: &str,
    instance: &InstanceId,
) -> Result<Reply, Failure> {
    Ok(ok(
        json!({ "secrets": layer.list_secrets(organization, instance)? }),
    ))
}

/// 사람의 브라우저가 입력 표로 값을 보내는 길. 쿠키도 키도 보지 않고, 다른 출처에서 부르므로 CORS 를 연다.
fn entry(layer: &Layer, method: &str, ticket: &str, body: &[u8]) -> Reply {
    let mut reply = match method {
        // 브라우저의 사전 요청. 무엇이든 표가 맞는지는 본 요청에서 본다
        "OPTIONS" => Reply {
            status: 204,
            content_type: "application/json",
            body: Vec::new(),
            location: None,
            cors: true,
        },
        "POST" => parse_quietly::<EnteredValue>(body, "{ \"value\": \"…\" }")
            .and_then(|entered| {
                layer.redeem_entry(
                    ticket,
                    entered.name.as_deref(),
                    entered.stage,
                    &entered.value,
                )
            })
            .map(|place| ok(json!({ "name": place.name, "stage": place.stage })))
            .unwrap_or_else(failure),
        _ => failure(Failure::NotFound),
    };
    reply.cors = true;
    reply
}

#[derive(Deserialize)]
struct NewInstance {
    app: String,
    version: String,
}

#[derive(Deserialize)]
struct NewSession {
    can: BTreeSet<Capability>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct NewPreview {
    #[serde(default)]
    commit: Option<String>,
}

#[derive(Deserialize)]
struct OfRelease {
    release: String,
}

#[derive(Deserialize)]
struct NewIdentity {
    /// 프리뷰의 씨앗 사용자의 식별자.
    user: String,
}

#[derive(Deserialize)]
struct NewOauthClient {
    name: String,
    redirect_uris: Vec<String>,
}

#[derive(Deserialize)]
struct NewRoles {
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct NewUser {
    email: String,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct NewPromotion {
    release: String,
    change: Change,
    approved_by: Approver,
}

/// 에이전트의 토큰으로 되는 일.
fn with_token(
    layer: &Layer,
    method: &str,
    rest: &[&str],
    token: &str,
    body: &[u8],
) -> Result<Reply, Failure> {
    let [id, tail @ ..] = rest else {
        return Err(Failure::NotFound);
    };
    let instance = InstanceId::parse(id).map_err(|_| Failure::NotFound)?;
    let allow = |action| layer.authorize(token, &instance, action);
    match (method, tail) {
        ("GET", ["source"]) => {
            allow(Action::SourceRead)?;
            Ok(Reply {
                status: 200,
                content_type: "application/octet-stream",
                body: layer.source_bundle(&instance)?,
                location: None,
                cors: false,
            })
        }
        ("POST", ["source"]) => {
            allow(Action::SourceWrite)?;
            Ok(ok(
                json!({ "commit": layer.push(&instance, body)?.as_str() }),
            ))
        }
        ("POST", ["previews"]) => {
            allow(Action::PreviewDeploy)?;
            let request: NewPreview = if body.is_empty() {
                NewPreview { commit: None }
            } else {
                parse(body)?
            };
            let commit = match request.commit {
                None => None,
                Some(text) => Some(Commit::parse(&text).ok_or_else(|| {
                    Failure::Problems(vec!["commit 은 40자의 식별자로 적어 주세요".to_owned()])
                })?),
            };
            Ok(ok(json!(layer.preview(&instance, commit)?)))
        }
        ("DELETE", ["previews"]) => {
            allow(Action::PreviewDeploy)?;
            layer.stop_preview(&instance)?;
            Ok(ok(json!({ "stopped": true })))
        }
        // 프리뷰의 씨앗 사용자로 세션을 만들어, 요청에 그대로 붙일 `Cookie` 머리말의 값을 돌려준다
        ("POST", ["previews", "identities"]) => {
            allow(Action::PreviewDatabase)?;
            let request: NewIdentity = parse(body)?;
            Ok(ok(
                json!({ "cookie": layer.preview_session(&instance, &request.user)? }),
            ))
        }
        ("POST", ["rehearsals"]) => {
            allow(Action::Rehearse)?;
            let request: OfRelease = parse(body)?;
            Ok(ok(json!(layer.rehearse(&instance, &request.release)?)))
        }
        ("POST", ["promotion-requests"]) => {
            allow(Action::RequestPromotion)?;
            let request: OfRelease = parse(body)?;
            layer.request_promotion(&instance, &request.release)?;
            Ok(ok(json!({ "requested": true })))
        }
        // 운영을 바꾸는 길을 토큰으로 두드리면 core 가 「service key 로만」이라고 답한다
        ("POST", ["promotions"]) => allow(Action::Promote).map(|()| ok(json!({}))),
        // 비밀은 이름과 채워졌는지만 본다
        ("GET", ["secrets"]) => {
            allow(Action::SecretsList)?;
            secrets_reply(layer, &layer.instance_organization(&instance)?, &instance)
        }
        ("POST", ["secrets", name, "request"]) => {
            allow(Action::SecretsRequest)?;
            let request: NewSecretRequest = parse_quietly(body, "{ \"reason\": \"…\" }")?;
            let organization = layer.instance_organization(&instance)?;
            layer.request_secret(&organization, &instance, name, &request.reason)?;
            Ok(ok(json!({ "requested": true })))
        }
        // 값을 넣거나 지우고 입력 표를 받는 길은 토큰으로 두드려도 core 가 「service key 로만」이라고 답한다. 본문은 읽지 않는다
        ("PUT" | "DELETE", ["secrets", _]) | ("POST", ["secrets", _, "entries"]) => {
            allow(Action::SecretsWrite).map(|()| ok(json!({})))
        }
        // 자기 인스턴스가 든 열린 rollout 의 진행. 다른 인스턴스는 싣지 않는다
        ("GET", ["rollout"]) => {
            allow(Action::RolloutView)?;
            Ok(ok(json!(layer.instance_rollout(&instance)?)))
        }
        // 사용자를 초대하는 길(`users`)은 service key 에만 있다. 토큰에는 없는 길이라 없는 것으로 답한다
        _ => Err(Failure::NotFound),
    }
}

/// 팩토리의 서버가 service key 로 하는 일.
fn with_service_key(
    layer: &Layer,
    method: &str,
    path: &[&str],
    query: &str,
    key: &str,
    body: &[u8],
) -> Result<Reply, Failure> {
    let organization = layer.organization(key)?;
    match (method, path) {
        // 팩토리마다 한 벌. 비밀은 답에 싣지 않는다
        ("GET", ["settings", "auth"]) => Ok(ok(layer.auth_settings(&organization))),
        ("PUT", ["settings", "auth"]) => {
            layer.put_auth_settings(&organization, body)?;
            Ok(ok(layer.auth_settings(&organization)))
        }
        ("PUT", ["apps", app]) => {
            layer.put_app(&organization, app, body)?;
            Ok(ok(json!({ "app": app })))
        }
        ("POST", ["apps", app, "rollouts"]) => {
            let request: NewRollout = parse(body)?;
            Ok(ok(json!(layer.create_rollout(
                &organization,
                app,
                request
            )?)))
        }
        ("GET", ["rollouts", id]) => Ok(ok(json!(layer.rollout(&organization, id)?))),
        ("POST", ["rollouts", id, "instances", instance, "apply"]) => {
            let instance = InstanceId::parse(instance).map_err(|_| Failure::NotFound)?;
            Ok(ok(json!(layer.apply_update(
                &organization,
                id,
                &instance
            )?)))
        }
        ("POST", ["rollouts", id, "resume"]) => {
            Ok(ok(json!(layer.resume_rollout(&organization, id)?)))
        }
        ("POST", ["rollouts", id, "cancel"]) => {
            Ok(ok(json!(layer.cancel_rollout(&organization, id)?)))
        }
        ("POST", ["instances"]) => {
            let request: NewInstance = parse(body)?;
            let instance = layer.create_instance(&organization, &request.app, &request.version)?;
            Ok(ok(json!({ "instance": instance.as_str() })))
        }
        (_, ["instances", id, tail @ ..]) => {
            let instance = InstanceId::parse(id).map_err(|_| Failure::NotFound)?;
            match (method, tail) {
                ("POST", ["sessions"]) => {
                    let request: NewSession = parse(body)?;
                    let (token, expires_at) = layer.open_session(
                        &organization,
                        &instance,
                        request.can,
                        request.ttl_seconds.unwrap_or(7200),
                    )?;
                    Ok(ok(json!({ "token": token, "expires_at": expires_at })))
                }
                ("POST", ["promotions"]) => {
                    let request: NewPromotion = parse(body)?;
                    let report = layer.promote(
                        &organization,
                        &instance,
                        &request.release,
                        request.change,
                        request.approved_by,
                    )?;
                    Ok(ok(json!(report)))
                }
                ("GET", ["promotion-request"]) => Ok(ok(json!(
                    layer.promotion_request(&organization, &instance)?
                ))),
                ("GET", ["production"]) => {
                    Ok(ok(json!(layer.production(&organization, &instance)?)))
                }
                ("POST", ["oauth-clients"]) => {
                    let request: NewOauthClient = parse(body)?;
                    let client_id = layer.register_oauth_client(
                        &organization,
                        &instance,
                        &request.name,
                        &request.redirect_uris,
                    )?;
                    Ok(ok(json!({ "client_id": client_id })))
                }
                ("GET", ["users"]) => Ok(ok(
                    json!({ "users": layer.users(&organization, &instance)? }),
                )),
                ("POST", ["users"]) => {
                    let request: NewUser = parse(body)?;
                    layer.invite(&organization, &instance, &request.email, &request.roles)?;
                    Ok(ok(json!({ "invited": true })))
                }
                ("PUT", ["users", user, "roles"]) => {
                    let request: NewRoles = parse(body)?;
                    layer.set_roles(&organization, &instance, user, &request.roles)?;
                    Ok(ok(json!({ "roles": request.roles })))
                }
                ("DELETE", ["users", user]) => {
                    layer.remove_user(&organization, &instance, user)?;
                    Ok(ok(json!({ "removed": true })))
                }
                ("GET", ["secrets"]) => secrets_reply(layer, &organization, &instance),
                ("POST", ["secrets", name, "request"]) => {
                    let request: NewSecretRequest = parse_quietly(body, "{ \"reason\": \"…\" }")?;
                    layer.request_secret(&organization, &instance, name, &request.reason)?;
                    Ok(ok(json!({ "requested": true })))
                }
                ("PUT", ["secrets", name]) => {
                    let request: NewSecretValue = parse_quietly(
                        body,
                        "{ \"stage\": \"preview\" | \"production\", \"value\": \"…\" }",
                    )?;
                    layer.put_secret(
                        &organization,
                        &instance,
                        name,
                        request.stage,
                        &request.value,
                    )?;
                    Ok(ok(json!({ "name": name, "stage": request.stage })))
                }
                ("DELETE", ["secrets", name]) => {
                    let stage = query_value(query, "stage")
                        .and_then(|stage| SecretStage::parse(&stage))
                        .ok_or_else(|| {
                            Failure::Problems(vec![
                                "지울 단계를 `?stage=preview` 나 `?stage=production` 으로 적어 주세요"
                                    .to_owned(),
                            ])
                        })?;
                    let removed = layer.remove_secret(&organization, &instance, name, stage)?;
                    Ok(ok(json!({ "removed": removed })))
                }
                ("POST", ["secrets", name, "entries"]) => {
                    let request: NewEntry =
                        parse_quietly(body, "{ \"stage\": \"preview\" | \"production\" }")?;
                    Ok(ok(json!(layer.open_entry(
                        &organization,
                        &instance,
                        name,
                        request.stage
                    )?)))
                }
                ("DELETE", []) => {
                    layer.destroy_instance(&organization, &instance)?;
                    Ok(ok(json!({ "destroyed": true })))
                }
                _ => Err(Failure::NotFound),
            }
        }
        _ => Err(Failure::NotFound),
    }
}

/// 요청 하나를 처리한다.
pub fn handle(layer: &Layer, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> Reply {
    let whole = path;
    let path: Vec<&str> = path
        .split('?')
        .next()
        .unwrap_or_default()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let ["v1", rest @ ..] = path.as_slice() else {
        return failure(Failure::NotFound);
    };
    let query = whole.split_once('?').map_or("", |(_, query)| query);
    // 사람의 브라우저가 입력 표로 값을 보내는 곳. 쿠키도 키도 보지 않는다(실려 와도 읽지 않는다)
    if let ["secret-entries", ticket] = rest {
        return entry(layer, method, ticket, body);
    }
    // Google 이 브라우저를 돌려보내는 곳. 열쇠 없이 오고, 무엇을 할지는 레이어가 서명한 `state` 가 정한다
    if method == "GET" && rest == ["auth", "google", "callback"] {
        return match layer.google_callback(query) {
            Ok(location) => found(location),
            Err(error) => failure(error),
        };
    }
    let Some(bearer) = bearer else {
        return failure(Failure::Unauthorized);
    };
    let result = if bearer.starts_with("orb1.") {
        match rest {
            ["instances", tail @ ..] => with_token(layer, method, tail, bearer, body),
            // rollout 을 만들고 · 합치고 · 다시 열고 · 거두는 길을 토큰으로 두드리면 core 가 「service key 로만」이라고 답한다
            ["apps", _, "rollouts"] | ["rollouts", ..] => layer
                .authorize_own(bearer, Action::RolloutManage)
                .map(|()| ok(json!({}))),
            _ => Err(Failure::NotFound),
        }
    } else {
        with_service_key(layer, method, rest, query, bearer, body)
    };
    result.unwrap_or_else(failure)
}

/// 요청을 받는다. 멈추지 않는다.
pub fn serve(layer: Arc<Layer>, server: tiny_http::Server) {
    for request in server.incoming_requests() {
        let layer = Arc::clone(&layer);
        std::thread::spawn(move || answer(&layer, request));
    }
}

/// 받은 요청 하나에 답한다. 테스트가 멈출 수 있는 받기 고리를 짤 때도 쓴다.
pub fn answer(layer: &Layer, mut request: tiny_http::Request) {
    let bearer = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("authorization"))
        .and_then(|header| header.value.as_str().strip_prefix("Bearer "))
        .map(str::to_owned);
    let method = request.method().as_str().to_owned();
    let path = request.url().to_owned();
    let mut body = Vec::new();
    let read = request
        .as_reader()
        .take(MAX_BUNDLE as u64 + 1)
        .read_to_end(&mut body);
    let reply = if read.is_err() || body.len() > MAX_BUNDLE {
        problem(413, "too_large", "요청의 본문이 너무 큽니다", Vec::new())
    } else {
        handle(layer, &method, &path, bearer.as_deref(), &body)
    };
    let header = tiny_http::Header::from_bytes("Content-Type", reply.content_type)
        .expect("고정된 머리말이다");
    let mut response = tiny_http::Response::from_data(reply.body)
        .with_status_code(reply.status)
        .with_header(header);
    if reply.cors {
        for (name, value) in [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "content-type"),
            ("Access-Control-Max-Age", "600"),
            ("Cache-Control", "no-store"),
        ] {
            if let Ok(header) = tiny_http::Header::from_bytes(name, value) {
                response.add_header(header);
            }
        }
    }
    if let Some(location) = reply.location {
        // 한 번 쓰는 표가 든 주소가 기록이나 다음 화면의 Referer 로 남지 않게 한다
        for (name, value) in [
            ("Location", location.as_str()),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
        ] {
            if let Ok(header) = tiny_http::Header::from_bytes(name, value) {
                response.add_header(header);
            }
        }
    }
    let _ = request.respond(response);
}
