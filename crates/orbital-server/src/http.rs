//! HTTP API. 팩토리의 서버가 SDK 로 부른다. 에이전트는 레이어를 직접 부르지 않고 팩토리의 도구와 git 만 쓴다.
//!
//! 요청마다 `Authorization: Bearer …` 를 본다. `orb1.` 로 시작하면 작업의 토큰이고, 아니면 팩토리의 service key 다.
//! 토큰으로 되는 일과 service key 로 되는 일은 길이 다르다. 운영을 바꾸는 길은 service key 쪽에만 있다.
//! git 이 바로 붙는 길(`/v1/instances/{id}/git/…`, smart HTTP)은 작업의 토큰으로만 열린다. git 의 자격 도우미가 보내는
//! `Basic` 의 비밀번호 자리에 든 토큰도 받고, 사용자 이름은 보지 않는다. 자격이 없으면 401 과 `WWW-Authenticate: Basic` 으로 답한다.
//! 열쇠 없이 오는 길은 Google 의 콜백(`GET /v1/auth/google/callback`) 하나다. 무엇을 할지는 레이어가 서명한 `state` 가 정한다.
//! service key 는 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)이나 기록(control database, sha256 으로만)에 있고, 요청마다 거뒀는지와 조직이 닫혔는지를 본다.
//! 조직은 자기 열쇠를 더 내고(`POST /v1/keys`, 값은 그 답에만) 보고(`GET /v1/keys`, 값 없이) 거둔다(`DELETE /v1/keys/{id}`).
//! 운영자의 길(`/v1/operator/…`)은 운영자의 열쇠로만 열리고 조직을 만들고 보고 닫고 열쇠를 낸다. 운영자의 열쇠로는 조직의 일을 하지 못한다.
//! 팩토리의 로그인 설정(`/v1/settings/auth`)은 service key 에만 있고, 넣은 비밀은 어떤 답에도 싣지 않는다.
//! 이벤트(`GET /v1/events?after=&limit=`)와 웹훅(`/v1/settings/webhook`)도 service key 에만 있다. 웹훅의 서명 비밀은 걸 때의 답에만 실린다.
//! 밖에서 넣는 비밀(`/v1/instances/{id}/secrets`)의 값은 service key 와 입력 표(`POST /v1/secret-entries`, 표는 `Authorization: Bearer`)로만 들어오고 어떤 열쇠로도 나가지 않는다.
//! 입력 표의 길은 쿠키도 키도 보지 않고 표만 보며, 사람의 브라우저(팩토리의 카드)가 다른 출처에서 부르므로 CORS 를 연다.
//! 무엇이 허락되는지는 여기서 정하지 않는다. 토큰은 core 의 `scope::judge` 가, 승격은 core 의 `release::promote` 가 판정한다.
//!
//! 인스턴스(또는 앱)가 다른 기계에 놓여 있어 레이어가 아무것도 하지 않고 거절하면(`Failure::Misplaced`), 놓인 기계의 주소를 알 때 요청을
//! 그 기계로 그대로 넘기고 답을 그대로 돌려준다([`crate::forward`]). 넘길지는 core 의 `placement::route` 가 판정한다. 넘겨받은 요청
//! (`x-orbital-forwarded-by`)은 다시 넘기지 않는다. 넘기기 전에 이 서버가 토큰과 service key 를 판정하고, 놓인 기계도 다시 판정한다.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

use orbital_core::auth::query_value;
use orbital_core::git::{Route as GitRoute, route as git_route};
use orbital_core::name::InstanceId;
use orbital_core::organization::Kind as OrganizationKind;
use orbital_core::placement::{Route, Unforwarded, route as place_route};
use orbital_core::release::{Approver, Change, PromoteDenied};
use orbital_core::scope::{Action, Capability};
use orbital_core::secrets::Stage as SecretStage;
use orbital_source::Commit;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::forward::{Outgoing, Relayed, relay};
use crate::layer::{Exchanged, Failure, Layer, NewRollout};
use crate::vault::SecretValue;

pub struct Reply {
    pub status: u16,
    pub content_type: Cow<'static, str>,
    pub body: Vec<u8>,
    /// 302 로 보낼 곳. Google 의 콜백만 쓴다.
    pub location: Option<String>,
    /// 다른 출처의 브라우저에 연다(`Access-Control-Allow-Origin: *`, 자격 증명 없이). 입력 표의 길만 쓴다.
    pub cors: bool,
    /// `WWW-Authenticate: Basic` 을 싣는다. git 의 길에서 자격이 없거나 맞지 않을 때만 쓴다. git 은 이것을 보고 자격 도우미를 부른다.
    pub challenge: bool,
    /// 흘려 보낼 본문. 있으면 `body` 대신 이것을 조각(chunked)으로 보낸다. git 의 받기(pack)만 쓴다.
    pub stream: Option<Box<dyn std::io::Read + Send>>,
    /// 그대로 싣는 머리말. 놓인 기계에서 받은 답을 돌려줄 때만 쓴다.
    pub headers: Vec<(String, String)>,
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
        content_type: Cow::Borrowed("application/json"),
        body: value.to_string().into_bytes(),
        location: None,
        cors: false,
        challenge: false,
        stream: None,
        headers: Vec::new(),
    }
}

fn found(location: String) -> Reply {
    Reply {
        status: 302,
        content_type: Cow::Borrowed("application/json"),
        body: b"{}".to_vec(),
        location: Some(location),
        cors: false,
        challenge: false,
        stream: None,
        headers: Vec::new(),
    }
}

fn problem(status: u16, code: &str, message: &str, details: Vec<String>) -> Reply {
    let body = json!({ "error": code, "message": message, "details": details });
    Reply {
        status,
        content_type: Cow::Borrowed("application/json"),
        body: body.to_string().into_bytes(),
        location: None,
        cors: false,
        challenge: false,
        stream: None,
        headers: Vec::new(),
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
        Failure::KeyRejected(refusal) => problem(
            401,
            "unauthorized",
            crate::layer::key_refusal_text(refusal),
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
        // 넘기지 않기로 한 것만 여기 온다([`settle`]). 주소를 모른다고 본다
        Failure::Misplaced { machine, .. } => misplaced(&machine, Unforwarded::NoAddress),
        Failure::Internal(message) => problem(500, "internal", &message, Vec::new()),
    }
}

/// 놓인 기계의 이름을 실은 답. 이 관리 서버는 아무것도 하지 않았다.
fn on_machine(status: u16, code: &str, message: &str, machine: &str) -> Reply {
    let mut reply = problem(status, code, message, Vec::new());
    reply.body = json!({
        "error": code,
        "message": message,
        "details": [],
        "machine": machine,
    })
    .to_string()
    .into_bytes();
    reply
}

/// 다른 기계에 놓여 있어 넘기지도 하지도 않았다(421).
fn misplaced(machine: &str, why: Unforwarded) -> Reply {
    let message = match why {
        Unforwarded::NoAddress => format!(
            "이 인스턴스는 다른 기계(`{machine}`)에 놓여 있고 그 기계의 주소가 기록에 없어 넘기지 못했습니다. 이 관리 서버는 아무것도 하지 않았습니다. 그 기계의 관리 서버로 보내거나, 그 기계의 관리 서버에 `ORBITAL_MACHINE_URL` 을 주고 다시 띄워 주세요"
        ),
        Unforwarded::AlreadyForwarded => format!(
            "다른 관리 서버가 넘겨 준 요청인데 이 인스턴스는 이 기계가 아니라 `{machine}` 에 놓여 있습니다. 넘겨받은 요청은 다시 넘기지 않으므로 이 관리 서버는 아무것도 하지 않았습니다. 기록에 적힌 기계의 주소(`ORBITAL_MACHINE_URL`)가 다른 기계를 가리키지 않는지 확인해 주세요"
        ),
    };
    on_machine(421, "misplaced", &message, machine)
}

/// 받은 요청 하나. 놓인 기계로 넘길 때 받은 그대로 넘긴다.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    pub method: &'a str,
    /// 경로와 질의.
    pub path: &'a str,
    /// `Authorization` 머리말 그대로.
    pub authorization: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    /// `x-orbital-forwarded-by` 머리말. 있으면 다른 기계에서 넘겨받은 요청이라 다시 넘기지 않는다. 권한은 주지 않는다.
    pub forwarded_by: Option<&'a str>,
    pub body: &'a [u8],
}

/// 거절을 답으로 옮긴다. 다른 기계에 놓여 있어 아무것도 하지 않은 것이면 core 의 판정대로 놓인 기계로 넘기거나 421 로 답한다.
fn settle(layer: &Layer, call: &Call<'_>, failed: Failure) -> Reply {
    let Failure::Misplaced { machine, errand } = failed else {
        return failure(failed);
    };
    let forwarded = call.forwarded_by.is_some();
    // 넘겨받은 요청이면 주소를 읽을 까닭이 없다
    let address = if forwarded {
        None
    } else {
        match layer.addresses_of(&machine) {
            Ok(addresses) => addresses.api,
            Err(error) => return failure(error),
        }
    };
    match (
        place_route(
            errand,
            &machine,
            layer.machine(),
            forwarded,
            address.is_some(),
        ),
        address,
    ) {
        (Route::Forward { machine }, Some(base)) => forward(layer, call, &machine, &base),
        (Route::Refuse { machine, why }, _) => misplaced(&machine, why),
        // 레이어가 이 기계의 일이 아니라고 했는데 core 가 여기서 하라고 하거나, 주소 없이 넘기라고 할 수는 없다
        _ => failure(Failure::Internal(
            "놓인 자리의 판정이 엇갈렸습니다".to_owned(),
        )),
    }
}

/// 놓인 기계로 요청을 넘기고 그 답을 그대로 돌려준다.
fn forward(layer: &Layer, call: &Call<'_>, machine: &str, base: &str) -> Reply {
    let outgoing = Outgoing {
        method: call.method,
        path: call.path,
        authorization: call.authorization,
        content_type: call.content_type,
        content_encoding: call.content_encoding,
        body: call.body,
    };
    match relay(base, layer.machine(), &outgoing) {
        Relayed::Answered(answered) => Reply {
            status: answered.status,
            content_type: Cow::Owned(answered.content_type),
            body: Vec::new(),
            location: None,
            cors: false,
            challenge: false,
            stream: Some(answered.body),
            headers: answered.headers,
        },
        Relayed::Unreachable => on_machine(
            502,
            "machine_unreachable",
            &format!(
                "이 인스턴스가 놓인 기계(`{machine}`)의 관리 서버에 닿지 못해 요청을 넘기지 못했습니다. 이 관리 서버도 그 기계도 아무것도 하지 않았습니다. 그 기계의 관리 서버가 떠 있는지 확인한 뒤 다시 보내 주세요"
            ),
            machine,
        ),
        Relayed::Interrupted => on_machine(
            502,
            "machine_interrupted",
            &format!(
                "이 인스턴스가 놓인 기계(`{machine}`)로 요청을 넘겼지만 답을 받기 전에 끊겼습니다. 이 관리 서버는 아무것도 하지 않았지만 그 기계에서 일이 되었는지는 모릅니다. 상태를 확인한 뒤 다시 보내 주세요"
            ),
            machine,
        ),
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
            content_type: Cow::Borrowed("application/json"),
            body: Vec::new(),
            location: None,
            cors: true,
            challenge: false,
            stream: None,
            headers: Vec::new(),
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
                content_type: Cow::Borrowed("application/octet-stream"),
                body: layer.source_bundle(&instance)?,
                location: None,
                cors: false,
                challenge: false,
                stream: None,
                headers: Vec::new(),
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
    let caller = layer.caller(key)?;
    let organization = caller.organization.0.clone();
    match (method, path) {
        // 이 조직의 service key. 값은 낼 때의 답에만 실린다
        ("GET", ["keys"]) => Ok(ok(json!({ "keys": layer.list_keys(&caller)? }))),
        ("POST", ["keys"]) => {
            let request: NewKeyRequest = parse(body)?;
            Ok(ok(json!(layer.issue_key(&caller, &request.label)?)))
        }
        ("DELETE", ["keys", id]) => Ok(ok(json!(layer.revoke_key(&caller, id)?))),
        // 팩토리마다 한 벌. 비밀은 답에 싣지 않는다
        ("GET", ["settings", "auth"]) => Ok(ok(layer.auth_settings(&organization))),
        ("PUT", ["settings", "auth"]) => {
            layer.put_auth_settings(&organization, body)?;
            Ok(ok(layer.auth_settings(&organization)))
        }
        // 이 조직의 이벤트(차례대로)와 웹훅. 서명의 비밀은 걸 때의 답에만 실린다
        ("GET", ["events"]) => Ok(ok(layer.list_events(&organization, query)?)),
        ("GET", ["settings", "webhook"]) => {
            Ok(ok(json!({ "webhook": layer.webhook(&organization)? })))
        }
        ("PUT", ["settings", "webhook"]) => {
            let (webhook, secret) = layer.set_webhook(&organization, body)?;
            Ok(ok(json!({ "webhook": webhook, "secret": secret })))
        }
        ("DELETE", ["settings", "webhook"]) => Ok(ok(
            json!({ "removed": layer.remove_webhook(&organization)? }),
        )),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKeyRequest {
    label: String,
}

/// 운영자가 조직에 내는 열쇠. `revoke_others` 면 그 조직의 다른 살아 있는 열쇠를 함께 모두 거둔다(열쇠가 새어 나갔을 때).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorKeyRequest {
    label: String,
    #[serde(default)]
    revoke_others: bool,
}

/// 운영자가 만드는 조직. 첫 열쇠를 함께 낸다.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewOrganization {
    id: String,
    name: String,
    kind: OrganizationKind,
    /// 첫 열쇠의 이름. 없으면 「첫 열쇠」다.
    #[serde(default)]
    label: Option<String>,
}

/// 운영자의 길(`/v1/operator/…`). 운영자의 열쇠로만 연다. 조직을 만들고(첫 열쇠와 함께) 보고 닫고, 열쇠를 낸다.
/// 운영자의 열쇠를 주지 않은 레이어에는 이 길이 없다(404). service key 와 작업의 토큰으로는 열지 않는다(403).
fn operator(
    layer: &Layer,
    method: &str,
    path: &[&str],
    bearer: Option<&str>,
    body: &[u8],
) -> Result<Reply, Failure> {
    if !layer.operator_enabled() {
        return Err(Failure::NotFound);
    }
    let Some(bearer) = bearer else {
        return Err(Failure::Unauthorized);
    };
    if !layer.is_operator(bearer) {
        return Err(Failure::Forbidden(
            "운영자의 길은 운영자의 열쇠(`ORBITAL_OPERATOR_KEY`)로만 엽니다. service key 와 작업의 토큰으로는 열지 않습니다".to_owned(),
        ));
    }
    match (method, path) {
        ("POST", ["organizations"]) => {
            let request: NewOrganization = parse(body)?;
            let (organization, key) = layer.create_organization(
                &request.id,
                &request.name,
                request.kind,
                request.label.as_deref().unwrap_or("첫 열쇠"),
            )?;
            Ok(ok(json!({ "organization": organization, "key": key })))
        }
        ("GET", ["organizations"]) => Ok(ok(json!({ "organizations": layer.organizations()? }))),
        ("GET", ["organizations", id]) => Ok(ok(json!(layer.organization_report(id)?))),
        ("POST", ["organizations", id, "keys"]) => {
            let request: OperatorKeyRequest = parse(body)?;
            let (key, revoked) =
                layer.operator_issue_key(id, &request.label, request.revoke_others)?;
            let mut answer = json!(key);
            answer["revoked"] = json!(revoked);
            Ok(ok(answer))
        }
        ("POST", ["organizations", id, "close"]) => {
            Ok(ok(json!({ "organization": layer.close_organization(id)? })))
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
fn git(layer: &Layer, id: &str, tail: &[&str], incoming: &Incoming<'_>, call: &Call<'_>) -> Reply {
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
        // service key 로는 열지 않는다. 그 열쇠는 운영을 바꾸는 길까지 열기 때문이다. 기록을 읽지 못한 것은 「없는 열쇠」가 아니다
        return match layer.caller(credential) {
            Ok(_) | Err(Failure::Forbidden(_)) => failure(Failure::Forbidden(
                "git 의 길은 작업에 한정된 토큰으로만 엽니다. service key 로는 열지 않습니다. 팩토리의 서버가 작업을 열어 받은 토큰을 쓰세요".to_owned(),
            )),
            Err(refused @ (Failure::Unauthorized | Failure::KeyRejected(_))) => {
                challenged(failure(refused))
            }
            Err(other) => failure(other),
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
                content_type: Cow::Borrowed(route.content_type()),
                body,
                location: None,
                cors: false,
                challenge: false,
                stream,
                headers: Vec::new(),
            }
        }
        Err(Failure::Unauthorized) => challenged(failure(Failure::Unauthorized)),
        Err(other) => settle(layer, call, other),
    }
}

/// 요청 하나를 처리한다.
///
/// 흘려 보낼 본문은 모두 읽어 `body` 에 담아 돌려준다(테스트가 부른다). `Content-Type` 은 싣지 않은 것으로 본다.
pub fn handle(layer: &Layer, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> Reply {
    let authorization = bearer.map(|bearer| format!("Bearer {bearer}"));
    handle_call(
        layer,
        &Call {
            method,
            path,
            authorization: authorization.as_deref(),
            content_type: None,
            content_encoding: None,
            forwarded_by: None,
            body,
        },
    )
}

/// 요청 하나를 처리한다. 흘려 보낼 본문은 모두 읽어 `body` 에 담아 돌려준다(테스트가 머리말까지 정해 부른다).
pub fn handle_call(layer: &Layer, call: &Call<'_>) -> Reply {
    handle_request(layer, call).drained()
}

/// 요청 하나를 처리한다. `Content-Encoding: gzip` 인 본문은 git 의 길만 푼다(git 이 받는 요청을 줄여 보낸다).
pub fn handle_request(layer: &Layer, call: &Call<'_>) -> Reply {
    let method = call.method;
    let body = call.body;
    let bearer = call.authorization.and_then(credential);
    let bearer = bearer.as_deref();
    let whole = call.path;
    let path: Vec<&str> = whole
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
            content_type: call.content_type,
            gzipped: call
                .content_encoding
                .is_some_and(|value| value.trim() == "gzip"),
            body,
        };
        return git(layer, id, tail, &incoming, call);
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
    // 운영자의 길. 운영자의 열쇠를 준 레이어에만 있다
    if let ["operator", tail @ ..] = rest {
        return operator(layer, method, tail, bearer, body).unwrap_or_else(failure);
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
            // 조직의 이벤트와 웹훅도 토큰으로 두드리면 core 가 「service key 로만」이라고 답한다
            ["events"] | ["settings", "webhook"] => layer
                .authorize_own(bearer, Action::Events)
                .map(|()| ok(json!({}))),
            _ => Err(Failure::NotFound),
        }
    } else {
        with_service_key(layer, method, rest, query, bearer, body)
    };
    result.unwrap_or_else(|failed| settle(layer, call, failed))
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
    let authorization = header("authorization");
    let content_encoding = header("content-encoding");
    let content_type = header("content-type");
    let forwarded_by = header(crate::forward::FORWARDED_BY);
    let method = request.method().as_str().to_owned();
    let path = request.url().to_owned();
    let limit = layer.upload_limit();
    let mut body = Vec::new();
    let read = request
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut body);
    if body.len() > limit {
        // 한도를 넘었다. 남은 본문을 한도만큼 더 읽어 버린 뒤에 거절한다. 읽지 않은 본문을 두고 닫으면 보내던 쪽(git)은
        // 연결이 끊긴 것만 보고 413 을 받지 못할 수 있다. 버리는 양에 상한을 둬, 끝없이 보내는 쪽에 붙들리지 않는다
        let _ = std::io::copy(
            &mut request.as_reader().take(limit as u64),
            &mut std::io::sink(),
        );
    }
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
            &Call {
                method: &method,
                path: &path,
                authorization: authorization.as_deref(),
                content_type: content_type.as_deref(),
                content_encoding: content_encoding.as_deref(),
                forwarded_by: forwarded_by.as_deref(),
                body: &body,
            },
        )
    };
    let header = tiny_http::Header::from_bytes("Content-Type", reply.content_type.as_bytes())
        .unwrap_or_else(|()| {
            tiny_http::Header::from_bytes("Content-Type", "application/octet-stream")
                .expect("고정된 머리말이다")
        });
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
    // 놓인 기계의 답에서 옮긴 머리말
    for (name, value) in &reply.headers {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
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
