//! 대시보드가 올라설 조회. 함대의 목록 · 인스턴스 하나 · release 의 이력 · 운영의 로그와 서비스의 상태 · 연결된 MCP 클라이언트 ·
//! 조직의 모습 · rollout 의 목록. 모두 service key 로만 열린다(HTTP 층이 가른다).
//!
//! 목록과 이력과 조직의 모습은 기록에만 닿아 어느 관리 서버든 답한다. 운영의 로그와 서비스의 상태는 놓인 기계의 파일과 메모리에
//! 있어 놓인 기계가 답한다(`Errand::ProductionLive`). **운영의 로그는 앱이 찍은 글이라 고객의 데이터가 섞일 수 있다.** 그래서 service key 로만
//! 열고, 서비스마다 끝의 몇 줄과 한 줄의 길이를 묶으며(core 의 `fleet`), 레이어의 폴더 경로를 가린다. 기록 · 이벤트 · 이력에는 싣지 않는다.

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use orbital_core::auth::query_value;
use orbital_core::fleet::{
    LOG_LINE_MAX, LinesProblem, Live as LiveFacts, ServiceState, clip_line, log_lines,
    service_state,
};
use orbital_core::listing::{PageProblem, page};
use orbital_core::manifest::ServiceKind;
use orbital_core::name::InstanceId;
use orbital_core::organization::Kind;
use orbital_core::placement::Errand;
use orbital_core::release::ReleaseId;
use serde::Serialize;
use serde_json::{Value, json};

use super::{Failure, Layer, Outcome, Stage, masked};
use crate::records::FleetRow;

/// 운영의 로그. 서비스마다 빌드(`build`, `build-<서비스>`)와 서버(`production-<서비스>`)의 끝이다.
#[derive(Debug, Clone, Serialize)]
pub struct ProductionLogs {
    pub release: String,
    /// 서버가 찍은 로그(`production-<서비스>`)를 실었는가. 레이어의 운영자가 켜지 않았으면 `false` 이고 빌드의 로그만 있다.
    pub server_logs: bool,
    pub logs: Vec<ProductionLog>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductionLog {
    pub name: String,
    pub text: String,
    /// 한 줄의 상한에서 자른 줄의 수.
    pub clipped: usize,
}

/// 운영의 서비스마다의 상태.
#[derive(Debug, Clone, Serialize)]
pub struct ProductionServices {
    pub release: String,
    pub services: Vec<ServiceStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub kind: ServiceKind,
    pub state: ServiceState,
}

/// 운영의 살아 있는 승인 하나(연결된 MCP 클라이언트). 토큰 · 코드의 값과 해시는 없다.
#[derive(Debug, Clone, Serialize)]
pub struct GrantReport {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub client_kind: String,
    /// 승인한 사용자의 식별자(사용자 목록의 `id`).
    pub user: String,
    pub scope: String,
    pub created_at: u64,
    /// 이 승인으로 마지막으로 토큰을 받은 때.
    pub last_token_at: Option<u64>,
}

/// 조직 자신의 모습. 이름과 숫자만 있다.
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationView {
    pub id: String,
    /// 사람이 읽는 이름. 관리 서버의 설정에만 있는 조직은 `null` 이다.
    pub name: Option<String>,
    pub kind: Kind,
    pub created_at: Option<u64>,
    /// 레이어의 기록에 있는 조직인가(아니면 관리 서버의 설정 `ORBITAL_SERVICE_KEYS` 에만 있다).
    pub recorded: bool,
    /// 지금 세워진 인스턴스의 수.
    pub instances: u32,
    /// 세울 수 있는 인스턴스의 수. 시험용 조직에만 있다.
    pub instance_limit: Option<u32>,
}

fn page_failure(problems: &[PageProblem]) -> Failure {
    Failure::Problems(
        problems
            .iter()
            .map(|problem| match problem {
                PageProblem::After => {
                    "`after` 는 앞 쪽의 답에서 받은 `next` 를 그대로 적어 주세요".to_owned()
                }
                PageProblem::Limit { max } => {
                    format!("`limit` 은 1 에서 {max} 사이의 정수로 적어 주세요")
                }
            })
            .collect(),
    )
}

/// 파일의 끝 `count` 줄. 끝에서 상한만큼만 읽고, 레이어의 폴더 경로를 가린 뒤 줄마다 한 줄의 상한에서 자른다. (글, 자른 줄의 수).
fn bounded_tail(log: &Path, home: &Path, count: u32) -> (String, usize) {
    // 한 줄은 글자로 상한까지이고 UTF-8 의 글자는 4바이트까지다. 그만큼만 읽어 큰 로그에도 메모리가 줄의 수에 묶인다
    let window = u64::from(count) * (LOG_LINE_MAX as u64 * 4 + 1);
    let mut bytes = Vec::new();
    if let Ok(mut file) = fs::File::open(log) {
        let length = file.metadata().map_or(0, |meta| meta.len());
        let start = length.saturating_sub(window);
        if file.seek(SeekFrom::Start(start)).is_ok() {
            let _ = file.take(window).read_to_end(&mut bytes);
        }
        if start > 0 {
            // 창의 첫 줄은 중간에서 잘렸을 수 있다. 버린다
            let cut = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |at| at + 1);
            bytes.drain(..cut);
        }
    }
    let text = masked(&String::from_utf8_lossy(&bytes), home);
    let lines: Vec<&str> = text.lines().collect();
    let keep = usize::try_from(count).unwrap_or(usize::MAX);
    let mut clipped = 0;
    let shown: Vec<String> = lines[lines.len().saturating_sub(keep)..]
        .iter()
        .map(|line| {
            let (line, cut) = clip_line(line);
            clipped += usize::from(cut);
            line
        })
        .collect();
    (shown.join("\n"), clipped)
}

impl Layer {
    /// 이 조직의 인스턴스를 만든 차례로 한 쪽(`?after=&limit=`). 기록만으로 답한다.
    pub fn fleet(&self, organization: &str, query: &str) -> Outcome<Value> {
        let page = page(
            query_value(query, "after").as_deref(),
            query_value(query, "limit").as_deref(),
        )
        .map_err(|problems| page_failure(&problems))?;
        let (rows, more) = self.records.fleet(organization, &page)?;
        let next = rows
            .last()
            .map(|row| row.cursor.text())
            .or_else(|| page.after.as_ref().map(orbital_core::listing::Cursor::text));
        Ok(json!({ "instances": rows, "next": next, "has_more": more }))
    }

    /// 이 조직의 인스턴스 하나의 함대의 줄. 다른 조직의 것은 없는 것과 같다.
    pub fn fleet_row(&self, organization: &str, instance: &InstanceId) -> Outcome<FleetRow> {
        self.records
            .fleet_row(organization, instance.as_str())?
            .ok_or(Failure::NotFound)
    }

    /// 인스턴스의 release 의 이력을 차례대로 한 쪽(`?after=<n>&limit=`).
    pub fn history(
        &self,
        organization: &str,
        instance: &InstanceId,
        query: &str,
    ) -> Outcome<Value> {
        self.owned(organization, instance)?;
        let after = query_value(query, "after");
        let limit = query_value(query, "limit");
        // 이력의 표식은 인스턴스마다의 번호라 이벤트의 질의와 모양이 같다
        let page = orbital_core::event::page(after.as_deref(), limit.as_deref()).map_err(|problems| {
            Failure::Problems(
                problems
                    .iter()
                    .map(|problem| match problem {
                        orbital_core::event::PageProblem::After => {
                            "`after` 는 앞에서 받은 이력의 마지막 번호(`n`, 0 이상의 정수)로 적어 주세요".to_owned()
                        }
                        orbital_core::event::PageProblem::Limit { max } => {
                            format!("`limit` 은 1 에서 {max} 사이의 정수로 적어 주세요")
                        }
                    })
                    .collect(),
            )
        })?;
        let (rows, more) = self
            .records
            .history(instance.as_str(), page.after, page.limit)?;
        let next = rows.last().map_or(page.after, |row| row.n);
        Ok(json!({
            "history": rows.iter().map(crate::records::HistoryRow::envelope).collect::<Vec<_>>(),
            "next": next,
            "has_more": more,
        }))
    }

    /// 운영의 release. 운영이 없으면 까닭과 함께 409 다.
    fn production_release(&self, record: &crate::registry::InstanceRecord) -> Outcome<String> {
        record
            .production
            .as_ref()
            .map(|production| production.release.clone())
            .ok_or_else(|| {
                Failure::Conflict(
                    "운영에 오른 것이 없습니다. 운영에 올린 뒤에 다시 불러 주세요".to_owned(),
                )
            })
    }

    /// 운영의 로그(`?lines=`). 놓인 기계가 답한다. service key 로만 부른다(HTTP 층이 가른다).
    pub fn production_logs(
        &self,
        organization: &str,
        instance: &InstanceId,
        query: &str,
    ) -> Outcome<ProductionLogs> {
        let count = log_lines(query_value(query, "lines").as_deref()).map_err(
            |LinesProblem::Lines { max }| {
                Failure::Problems(vec![format!(
                    "`lines` 는 1 에서 {max} 사이의 정수로 적어 주세요"
                )])
            },
        )?;
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::ProductionLive)?;
        let release = self.production_release(&record)?;
        let manifest = self.live_or_recorded_manifest(instance, &record)?;
        let id = ReleaseId(release.clone());
        let mut names = Vec::new();
        if manifest.build.is_some() {
            names.push("build".to_owned());
        }
        for service in &manifest.services {
            names.push(format!("build-{}", service.name));
            // 서버가 찍은 글은 레이어의 운영자가 켠 레이어에서만 내준다. 고객의 데이터가 섞일 수 있다
            if service.kind == ServiceKind::Server && self.production_logs {
                names.push(format!("production-{}", service.name));
            }
        }
        let logs = names
            .into_iter()
            .map(|name| {
                let (text, clipped) =
                    bounded_tail(&self.log(instance, &id, &name), &self.home, count);
                ProductionLog {
                    name,
                    text,
                    clipped,
                }
            })
            .collect();
        Ok(ProductionLogs {
            release,
            server_logs: self.production_logs,
            logs,
        })
    }

    /// 운영의 선언. 이 기계에 떠 있으면 그것을, 아니면 기록의 것을 쓴다.
    fn live_or_recorded_manifest(
        &self,
        instance: &InstanceId,
        record: &crate::registry::InstanceRecord,
    ) -> Outcome<orbital_core::manifest::Manifest> {
        if let Some(live) = self
            .lock()
            .live
            .get(&(instance.as_str().to_owned(), Stage::Production))
        {
            return Ok(live.manifest.get().clone());
        }
        record
            .production
            .as_ref()
            .and_then(|production| production.manifest.clone())
            .ok_or_else(|| Failure::Internal("운영의 선언을 기록에서 찾지 못했습니다".to_owned()))
    }

    /// 운영의 서비스마다의 상태(깨어 있는지 · 자는지 · 빌드 중인지). 놓인 기계가 메모리에서 답한다.
    pub fn production_services(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<ProductionServices> {
        let record = self.owned(organization, instance)?;
        self.placed(&record, Errand::ProductionLive)?;
        let release = self.production_release(&record)?;
        let inner = self.lock();
        if let Some(live) = inner
            .live
            .get(&(instance.as_str().to_owned(), Stage::Production))
        {
            let services = live
                .services
                .iter()
                .map(|service| ServiceStatus {
                    name: service.name.clone(),
                    kind: service.kind,
                    state: service_state(
                        service.kind,
                        Some(LiveFacts {
                            building: live.building,
                            awake: service
                                .server
                                .as_ref()
                                .is_some_and(|server| server.is_awake()),
                        }),
                    ),
                })
                .collect();
            return Ok(ProductionServices {
                release: live.release.clone(),
                services,
            });
        }
        drop(inner);
        // 기록에는 운영이 있는데 이 기계에 떠 있지 않다
        let manifest = self.live_or_recorded_manifest(instance, &record)?;
        Ok(ProductionServices {
            release,
            services: manifest
                .services
                .iter()
                .map(|service| ServiceStatus {
                    name: service.name.to_string(),
                    kind: service.kind,
                    state: service_state(service.kind, None),
                })
                .collect(),
        })
    }

    /// 운영의 연결된 MCP 클라이언트(살아 있는 승인). 인스턴스의 DB 에만 닿아 어느 기계든 한다.
    pub fn oauth_grants(
        &self,
        organization: &str,
        instance: &InstanceId,
    ) -> Outcome<Vec<GrantReport>> {
        let mut store = self.production_auth(organization, instance)?;
        Ok(store
            .connections()
            .map_err(super::auth_failure)?
            .into_iter()
            .map(|connection| GrantReport {
                id: connection.id,
                client_id: connection.client_id,
                client_name: connection.client_name,
                client_kind: connection.client_kind,
                user: connection.user_id,
                scope: connection.scope,
                created_at: connection.created_at,
                last_token_at: connection.last_token_at,
            })
            .collect())
    }

    /// 이 조직 자신의 모습. 기록에 없는 조직(설정의 열쇠만 있는 조직)은 운영의 조직으로 본다.
    pub fn organization_view(&self, organization: &str) -> Outcome<OrganizationView> {
        let row = self.records.organization(organization)?;
        let (instances, _) = self.records.organization_counts(organization)?;
        let kind = row.as_ref().map_or(Kind::Live, |row| row.kind);
        Ok(OrganizationView {
            id: organization.to_owned(),
            name: row.as_ref().map(|row| row.name.clone()),
            kind,
            created_at: row.as_ref().map(|row| row.created_at),
            recorded: row.is_some(),
            instances,
            instance_limit: (kind == Kind::Test).then_some(self.test_instance_limit),
        })
    }

    /// 이 조직의 rollout 을 만든 차례로 한 쪽(`?after=&limit=`).
    pub fn list_rollouts(&self, organization: &str, query: &str) -> Outcome<Value> {
        let page = page(
            query_value(query, "after").as_deref(),
            query_value(query, "limit").as_deref(),
        )
        .map_err(|problems| page_failure(&problems))?;
        let (rows, more) = self.records.rollout_page(organization, &page)?;
        let next = rows
            .last()
            .map(|(cursor, _)| cursor.text())
            .or_else(|| page.after.as_ref().map(orbital_core::listing::Cursor::text));
        let rollouts: Vec<_> = rows
            .iter()
            .map(|(cursor, record)| super::rollout::report(&cursor.id, &record.rollout))
            .collect();
        Ok(json!({ "rollouts": rollouts, "next": next, "has_more": more }))
    }
}
