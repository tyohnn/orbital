//! HTTP API. 팩토리의 서버가 SDK 로 부른다. 에이전트는 레이어를 직접 부르지 않고 팩토리의 도구와 git 만 쓴다.
//!
//! 요청마다 `Authorization: Bearer …` 를 본다. `orb1.` 로 시작하면 작업의 토큰이고, 아니면 팩토리의 service key 다.
//! 토큰으로 되는 일과 service key 로 되는 일은 길이 다르다. 운영을 바꾸는 길은 service key 쪽에만 있다.
//! git 이 바로 붙는 길(`/v1/instances/{id}/git/…`, smart HTTP)은 작업의 토큰으로만 열린다. git 의 자격 도우미가 보내는
//! `Basic` 의 비밀번호 자리에 든 토큰도 받고, 사용자 이름은 보지 않는다. 자격이 없으면 401 과 `WWW-Authenticate: Basic` 으로 답한다.
//! 열쇠 없이 오는 길은 Google 의 콜백(`GET /v1/auth/google/callback`) 하나다. 무엇을 할지는 레이어가 서명한 `state` 가 정한다.
//! 팩토리의 로그인 설정(`/v1/settings/auth`)은 service key 에만 있고, 넣은 비밀은 어떤 답에도 싣지 않는다.
//! 밖에서 넣는 비밀(`/v1/instances/{id}/secrets`)의 값은 service key 와 입력 표(`POST /v1/secret-entries`, 표는 `Authorization: Bearer`)로만 들어오고 어떤 열쇠로도 나가지 않는다.
//! 입력 표의 길은 쿠키도 키도 보지 않고 표만 보며, 사람의 브라우저(팩토리의 카드)가 다른 출처에서 부르므로 CORS 를 연다.
//! 무엇이 허락되는지는 여기서 정하지 않는다. 토큰은 core 의 `scope::judge` 가, 승격은 core 의 `release::promote` 가 판정한다.

use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

use orbital_core::auth::query_value;
use orbital_core::git::{Route as GitRoute, route as git_route};
use orbital_core::name::InstanceId;
use orbital_core::release::{Approver, Change, PromoteDenied};
use orbital_core::scope::{Action, Capability};
use orbital_core::secrets::Stage as SecretStage;
use orbital_source::Commit;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::layer::{Exchanged, Failure, Layer, NewRollout};
use crate::vault::SecretValue;

pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// 302 로 보낼 곳. Google 의 콜백만 쓴다.
    pub location: Option<String>,
    /// 다른 출처의 브라우저에 연다(`Access-Control-Allow-Origin: *`, 자격 증명 없이). 입력 표의 길만 쓴다.
    pub cors: bool,
    /// `WWW-Authenticate: Basic` 을 싣는다. git 의 길에서 자격이 없거나 맞지 않을 때만 쓴다. git 은 이것을 보고 자격 도우미를 부른다.
    pub challenge: bool,
    /// 흘려 보낼 본문. 있으면 `body` 대신 이것을 조각(chunked)으로 보낸다. git 의 받기(pack)만 쓴다.
    pub stream: Option<Box<dyn std::io::Read + Send>>,
}

impl Reply {
    /// 흘려 보낼 본문을 모두 읽어 `body` 에 담는다. 테스트가 부르는 [`handle`] 이 쓴다.
    fn drained(mut self) -> Self {
        if let Some(mut stream) = self.stream.take() {
            let mut body = Vec::new();
            if stream.read_to_end(&mut body).is_ok() {
                self.body = body;
            } else {
                self.status = 500;
            }
        }
        self
    }
}

fn ok(value: Value) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        body: value.to_string().into_bytes(),
        location: None,
        cors: false,
        challenge: false,
        stream: None,
    }
}

fn found(location: String) -> Reply {
    Reply {
        status: 302,
        content_type: "application/json",
        body: b"{}".to_vec(),
        location: Some(location),
        cors: false,
        challenge: false,
        stream: None,
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
        challenge: false,
        stream: None,
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
                        format!("권한 검사에서 어긋남이 {findings}개 나왔습니다. 프리뷰의 결과(`findings`)를 보고 고쳐 주세요")
                    }
                    Blocker::RehearsalNotRun => "마이그레이션의 리허설을 아직 돌리지 않았습니다. 이 release 로 리허설을 돌려 주세요".to_owned(),
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
            &if service == crate::layer::REPOSITORY_BUILD {
                "저장소의 빌드(`[build]`)가 실패했습니다. 서비스의 빌드는 돌지 않았습니다. 로그의 끝을 함께 보냅니다".to_owned()
            } else {
                format!("서비스 `{service}` 의 빌드가 실패했습니다. 로그의 끝을 함께 보냅니다")
            },
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
        Failure::UnsupportedMediaType(message) => {
            problem(415, "unsupported_media_type", &message, Vec::new())
        }
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
fn entry(layer: &Layer, method: &str, ticket: Option<&str>, body: &[u8]) -> Reply {
    let mut reply = match method {
        // 브라우저의 사전 요청. 무엇이든 표가 맞는지는 본 요청에서 본다
        "OPTIONS" => Reply {
            status: 204,
            content_type: "application/json",
            body: Vec::new(),
            location: None,
            cors: true,
            challenge: false,
            stream: None,
        },
        "POST" => ticket
            .ok_or(Failure::NotFound)
            .and_then(|ticket| {
                parse_quietly::<EnteredValue>(body, "{ \"value\": \"…\" }")
                    .map(|entered| (ticket, entered))
            })
            .and_then(|(ticket, entered)| {
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

/// 인스턴스를 되살릴 시점(유닉스 초).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    at: u64,
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
                challenge: false,
                stream: None,
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
        ("GET", ["previews", "logs"]) => {
            allow(Action::PreviewLogs)?;
            Ok(ok(json!(layer.preview_logs(&instance)?)))
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
        // 되살리는 길을 토큰으로 두드리면 core 가 「service key 로만」이라고 답한다. 본문은 읽지 않는다
        ("POST", ["restore"] | ["restore", "undo"]) => {
            allow(Action::RestoreInstance).map(|()| ok(json!({})))
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
        // 복구 훈련이 통과했는지와 숫자만
        ("GET", ["backup"]) => Ok(ok(json!(layer.backup_status(&organization)?))),
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
                    let (token, expires_at, session) = layer.open_session(
                        &organization,
                        &instance,
                        request.can,
                        request.ttl_seconds.unwrap_or(7200),
                    )?;
                    Ok(ok(
                        json!({ "token": token, "expires_at": expires_at, "session": session }),
                    ))
                }
                ("DELETE", ["sessions", session]) => {
                    layer.close_session(&organization, &instance, session)?;
                    Ok(ok(json!({ "closed": true })))
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
                ("POST", ["restore"]) => {
                    let request: RestoreRequest = parse(body)?;
                    Ok(ok(json!(layer.restore_instance(
                        &organization,
                        &instance,
                        request.at
                    )?)))
                }
                ("POST", ["restore", "undo"]) => {
                    Ok(ok(json!(layer.undo_restore(&organization, &instance)?)))
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

/// git 의 길이 보는 요청의 나머지.
#[derive(Clone, Copy)]
struct Incoming<'a> {
    method: &'a str,
    query: &'a str,
    credential: Option<&'a str>,
    content_type: Option<&'a str>,
    gzipped: bool,
    body: &'a [u8],
}

/// git 의 길(`/v1/instances/{id}/git/…`). 작업의 토큰으로만 열린다.
///
/// 판정은 다른 토큰의 길과 같다(`Layer::authorize`): 받기는 `SourceRead`, 올리기는 `SourceWrite` 이고, 토큰의 인스턴스 밖은 없는 것과 같다.
fn git(layer: &Layer, id: &str, tail: &[&str], incoming: &Incoming<'_>) -> Reply {
    let Incoming {
        method,
        query,
        credential,
        content_type,
        gzipped,
        body,
    } = *incoming;
    let challenged = |reply: Reply| Reply {
        challenge: true,
        ..reply
    };
    let Some(credential) = credential else {
        return challenged(failure(Failure::Unauthorized));
    };
    if !credential.starts_with("orb1.") {
        // service key 로는 열지 않는다. 그 열쇠는 운영을 바꾸는 길까지 열기 때문이다
        return if layer.organization(credential).is_ok() {
            failure(Failure::Forbidden(
                "git 의 길은 작업에 한정된 토큰으로만 엽니다. service key 로는 열지 않습니다. 팩토리의 서버가 작업을 열어 받은 토큰을 쓰세요".to_owned(),
            ))
        } else {
            challenged(failure(Failure::Unauthorized))
        };
    }
    let Ok(instance) = InstanceId::parse(id) else {
        return failure(Failure::NotFound);
    };
    let Some(route) = git_route(method, tail, query) else {
        return failure(Failure::NotFound);
    };
    let served = layer
        .authorize(credential, &instance, route.service().action())
        .and_then(|()| match route {
            GitRoute::Advertise(service) => layer
                .git_advertise(&instance, service)
                .map(Exchanged::Bytes),
            GitRoute::Exchange(_) if !route.accepts(content_type) => {
                Err(Failure::UnsupportedMediaType(format!(
                    "git 의 길은 `Content-Type: {}` 인 요청만 받습니다. git 이 보낸 요청을 그대로 넘겨 주세요",
                    route.request_type().unwrap_or_default()
                )))
            }
            GitRoute::Exchange(service) => {
                let inflated;
                let request = if gzipped {
                    inflated =
                        orbital_source::gunzip(body, layer.upload_limit()).map_err(|_| {
                            Failure::Problems(vec!["줄인(gzip) 요청을 풀지 못했습니다".to_owned()])
                        })?;
                    &inflated[..]
                } else {
                    body
                };
                layer.git_exchange(&instance, service, request)
            }
        });
    match served {
        Ok(exchanged) => {
            let (body, stream): (Vec<u8>, Option<Box<dyn std::io::Read + Send>>) = match exchanged {
                Exchanged::Bytes(body) => (body, None),
                Exchanged::Stream(stream) => (Vec::new(), Some(Box::new(stream))),
            };
            Reply {
                status: 200,
                content_type: route.content_type(),
                body,
                location: None,
                cors: false,
                challenge: false,
                stream,
            }
        }
        Err(Failure::Unauthorized) => challenged(failure(Failure::Unauthorized)),
        Err(other) => failure(other),
    }
}

/// 요청 하나를 처리한다.
///
/// 흘려 보낼 본문은 모두 읽어 `body` 에 담아 돌려준다(테스트가 부른다). `Content-Type` 은 싣지 않은 것으로 본다.
pub fn handle(layer: &Layer, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> Reply {
    handle_request(layer, method, path, bearer, None, false, body).drained()
}

/// 요청 하나를 처리한다. `gzipped` 는 본문이 `Content-Encoding: gzip` 으로 왔는지다(git 이 받는 요청을 줄여 보낸다).
pub fn handle_request(
    layer: &Layer,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    content_type: Option<&str>,
    gzipped: bool,
    body: &[u8],
) -> Reply {
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
    // git 이 바로 붙는 길. 자격이 없을 때 git 이 알아듣는 답(401 과 Basic 의 요청)을 해야 해서 따로 본다
    if let ["instances", id, "git", tail @ ..] = rest {
        let incoming = Incoming {
            method,
            query,
            credential: bearer,
            content_type,
            gzipped,
            body,
        };
        return git(layer, id, tail, &incoming);
    }
    // 사람의 브라우저가 입력 표로 값을 보내는 곳. 주소는 고정이고 표는 `Authorization: Bearer` 로만 온다.
    // 레이어 앞의 프록시가 남기는 접근 기록에 표가 실리지 않게 경로에는 싣지 않는다. 쿠키는 보지 않는다
    if let ["secret-entries", tail @ ..] = rest {
        return entry(
            layer,
            method,
            tail.is_empty().then_some(bearer).flatten(),
            body,
        );
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

/// `Authorization` 머리말의 자격. `Bearer` 는 그대로, `Basic` 은 비밀번호 자리만 꺼낸다(git 의 자격 도우미가 이렇게 보낸다).
fn credential(value: &str) -> Option<String> {
    use base64::Engine as _;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.trim().to_owned());
    }
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (_, password) = text.split_once(':')?;
    (!password.is_empty()).then(|| password.to_owned())
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
    let header = |name: &'static str| {
        request
            .headers()
            .iter()
            .find(|header| header.field.equiv(name))
            .map(|header| header.value.as_str().to_owned())
    };
    let bearer = header("authorization").and_then(|value| credential(&value));
    let gzipped = header("content-encoding").is_some_and(|value| value.trim() == "gzip");
    let content_type = header("content-type");
    let method = request.method().as_str().to_owned();
    let path = request.url().to_owned();
    let limit = layer.upload_limit();
    let mut body = Vec::new();
    let read = request
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut body);
    let reply = if read.is_err() || body.len() > limit {
        problem(
            413,
            "too_large",
            &format!(
                "요청의 본문이 너무 큽니다. {}MiB 안이어야 합니다",
                limit / (1024 * 1024)
            ),
            Vec::new(),
        )
    } else {
        handle_request(
            layer,
            &method,
            &path,
            bearer.as_deref(),
            content_type.as_deref(),
            gzipped,
            &body,
        )
    };
    let header = tiny_http::Header::from_bytes("Content-Type", reply.content_type)
        .expect("고정된 머리말이다");
    // 흘려 보낼 본문은 길이를 적지 않고 조각(chunked)으로 보낸다. 나머지는 길이를 적어 한 번에 보낸다
    let (reader, length): (Box<dyn Read + Send>, Option<usize>) = match reply.stream {
        Some(stream) => (stream, None),
        None => {
            let length = reply.body.len();
            (Box::new(std::io::Cursor::new(reply.body)), Some(length))
        }
    };
    let mut response = tiny_http::Response::new(
        tiny_http::StatusCode(reply.status),
        vec![header],
        reader,
        length,
        None,
    );
    if reply.cors {
        for (name, value) in [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "POST, OPTIONS"),
            (
                "Access-Control-Allow-Headers",
                "authorization, content-type",
            ),
            ("Access-Control-Max-Age", "600"),
            ("Cache-Control", "no-store"),
        ] {
            if let Ok(header) = tiny_http::Header::from_bytes(name, value) {
                response.add_header(header);
            }
        }
    }
    if reply.challenge {
        for (name, value) in [
            (
                "WWW-Authenticate",
                "Basic realm=\"Orbital\", charset=\"UTF-8\"",
            ),
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
