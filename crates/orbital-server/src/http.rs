//! HTTP API. CLI(에이전트)와 SDK(팩토리의 서버)가 모두 이것을 부른다.
//!
//! 요청마다 `Authorization: Bearer …` 를 본다. `orb1.` 로 시작하면 에이전트의 토큰이고, 아니면 팩토리의 service key 다.
//! 토큰으로 되는 일과 service key 로 되는 일은 길이 다르다. 운영을 바꾸는 길은 service key 쪽에만 있다.
//! 무엇이 허락되는지는 여기서 정하지 않는다. 토큰은 core 의 `scope::judge` 가, 승격은 core 의 `release::promote` 가 판정한다.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::sync::Arc;

use orbital_core::name::InstanceId;
use orbital_core::release::{Approver, Change, PromoteDenied};
use orbital_core::scope::{Action, Capability};
use orbital_source::Commit;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::layer::{Failure, Layer};

/// 묶음(코드)의 상한.
const MAX_BUNDLE: usize = 64 * 1024 * 1024;

pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn ok(value: Value) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        body: value.to_string().into_bytes(),
    }
}

fn problem(status: u16, code: &str, message: &str, details: Vec<String>) -> Reply {
    let body = json!({ "error": code, "message": message, "details": details });
    Reply {
        status,
        content_type: "application/json",
        body: body.to_string().into_bytes(),
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
                    Blocker::RehearsalNotRun => "마이그레이션의 예행연습을 아직 돌리지 않았습니다. `orbital rehearse` 로 돌려 주세요".to_owned(),
                    Blocker::RehearsalFailed => "마이그레이션의 예행연습이 실패했습니다".to_owned(),
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
        Failure::Denied(why) => denied(&why),
        Failure::Conflict(message) => problem(409, "conflict", &message, Vec::new()),
        Failure::Internal(message) => problem(500, "internal", &message, Vec::new()),
    }
}

fn parse<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Failure> {
    serde_json::from_slice(body)
        .map_err(|error| Failure::Problems(vec![format!("요청의 본문을 읽지 못했습니다: {error}")]))
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
    /// 미리보기의 씨앗 사용자의 식별자.
    user: String,
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
        // 미리보기의 씨앗 사용자로 세션을 만들어, 요청에 그대로 붙일 `Cookie` 머리말의 값을 돌려준다
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
        // 사용자를 초대하는 길(`users`)은 service key 에만 있다. 토큰에는 없는 길이라 없는 것으로 답한다
        _ => Err(Failure::NotFound),
    }
}

/// 팩토리의 서버가 service key 로 하는 일.
fn with_service_key(
    layer: &Layer,
    method: &str,
    path: &[&str],
    key: &str,
    body: &[u8],
) -> Result<Reply, Failure> {
    let organization = layer.organization(key)?;
    match (method, path) {
        ("PUT", ["apps", app]) => {
            layer.put_app(&organization, app, body)?;
            Ok(ok(json!({ "app": app })))
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
                ("POST", ["users"]) => {
                    let request: NewUser = parse(body)?;
                    layer.invite(&organization, &instance, &request.email, &request.roles)?;
                    Ok(ok(json!({ "invited": true })))
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
    let Some(bearer) = bearer else {
        return failure(Failure::Unauthorized);
    };
    let result = if bearer.starts_with("orb1.") {
        match rest {
            ["instances", tail @ ..] => with_token(layer, method, tail, bearer, body),
            _ => Err(Failure::NotFound),
        }
    } else {
        with_service_key(layer, method, rest, bearer, body)
    };
    result.unwrap_or_else(failure)
}

/// 요청을 받는다. 멈추지 않는다.
pub fn serve(layer: Arc<Layer>, server: tiny_http::Server) {
    for mut request in server.incoming_requests() {
        let layer = Arc::clone(&layer);
        std::thread::spawn(move || {
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
                handle(&layer, &method, &path, bearer.as_deref(), &body)
            };
            let header = tiny_http::Header::from_bytes("Content-Type", reply.content_type)
                .expect("고정된 머리말이다");
            let response = tiny_http::Response::from_data(reply.body)
                .with_status_code(reply.status)
                .with_header(header);
            let _ = request.respond(response);
        });
    }
}
