// 팩토리의 서버가 쓰는 client. service key 로 관리 서버의 HTTP API 를 부른다.
//
// 운영을 바꾸는 길은 여기에만 있다. 에이전트는 레이어를 직접 부르지 않는다. 팩토리의 도구와 git 만 쓰고, 그 뒤에서
// 팩토리의 서버가 작업(`works.open`)을 열어 작업의 토큰으로 프리뷰 · 리허설 · 승격 요청을 부르고 git 을 이어 준다.
// 작업의 토큰에는 운영을 바꾸는 능력이 아예 없다. 그래서 작업의 함수와 git 을 이어 주는 코드에 버그가 있어도 운영은 바뀌지 않는다.
// 타입은 관리 서버가 주고받는 JSON 의 모양을 옮긴 것이다. Rust 쪽의 serde 모양을 바꾸면 같은 PR 에서 함께 고친다.
// 누가 승인할 자격이 있는지는 팩토리가 정한다. Orbital 은 승인이 어느 쪽(고객 · 팩토리)의 것인지만 받는다.

import { createHmac, timingSafeEqual } from "node:crypto";

/** 토큰에 실을 수 있는 능력. 운영을 바꾸는 능력은 없다. `source_read` 는 코드를 받기만 한다. */
export type Capability = "source" | "source_read" | "preview" | "rehearse" | "secrets_request";

/** 무엇 때문에 올리는가. 누가 승인해야 하는지가 여기서 갈린다. */
export type Change =
    | "customer_request"
    | "feature_update"
    | "legal_update"
    | "security_update"
    | "core_package";

/** 승인한 쪽. 고객의 요청과 기능 업데이트는 고객이, 법 · 보안 · 핵심 패키지는 팩토리가 승인한다. */
export type Approver = "customer" | "factory";

export interface Service
{
    name: string;
    kind: "server" | "static";
    /** 서비스에 닿는 주소. 인스턴스의 router 의 주소 + 서비스의 `path` 다. */
    url: string | null;
}

/** 운영의 사용자 한 사람. 토큰이나 세션은 실리지 않는다. */
export interface User
{
    id: string;
    email: string;
    name: string | null;
    /** 업무 역할의 이름. 이름 순이다. */
    roles: string[];
    /** 막혔는가(뺐는가). */
    disabled: boolean;
    /** 마지막으로 들어온 때(Unix 초). 한 번도 들어오지 않았으면 `null` 이다. */
    lastSignedInAt: number | null;
}

export interface Production
{
    release: string;
    services: Service[];
    /** 이번 승격에서 돈 마이그레이션의 이름. */
    migrations: string[];
    /** 선언의 일정(`[[schedule]]`)마다 다음 때와 마지막 실행. 레이어가 그 시각(UTC)에 운영의 앱을 부른다. */
    schedules: Schedule[];
}

/** 일정을 한 번 부른 결과의 갈래. `running` 은 부르는 중이다. */
export type ScheduleOutcome = "running" | "ok" | "failed" | "unreachable" | "timed_out";

/** 일정을 한 번 부른 것. 숫자와 갈래만 있다(앱의 답의 본문은 없다). */
export interface ScheduleRun
{
    /** 맞춘 때(Unix 초). 레이어가 내려가 있어 놓쳤으면 놓친 때 가운데 마지막 것이다. */
    dueAt: number;
    /** 실제로 부른 때(Unix 초). */
    startedAt: number;
    outcome: ScheduleOutcome;
    /** 앱이 답한 상태 코드. 답하지 않았으면 `null` 이다. */
    status: number | null;
    /** 걸린 시간(밀리초). 부르는 중이면 `null` 이다. */
    millis: number | null;
}

/** 운영의 일정 하나. */
export interface Schedule
{
    service: string;
    path: string;
    /** 다섯 칸의 cron 식(UTC). */
    cron: string;
    /** 일정이 도는 업무 역할(선언의 `role`). 레이어가 사람 없이 이 역할만 실린 신원을 싣는다. 없으면 `null`(신원 없이 부른다). */
    role: string | null;
    /** 다음에 부를 때(Unix 초). */
    nextAt: number | null;
    /** 마지막으로 부른 것. 한 번도 부르지 않았으면 `null` 이다. */
    lastRun: ScheduleRun | null;
}

export interface Session
{
    /** 작업의 토큰. 팩토리의 서버 안에만 둔다. 에이전트에게 건네지 않는다(보통은 `works.open` 이 감싸 쓴다). */
    token: string;
    /** 만료되는 때(Unix 초). */
    expiresAt: number;
    /** 작업의 식별자. 토큰을 모르면 지을 수 없고, 이것으로 토큰을 되살리지 못한다. 만료 전에 거둘 때(`Work.close`) 쓴다. */
    id: string;
}

/** 사람의 승인을 기다리는 승격 요청. 승인 화면에 세운다. */
export interface PendingPromotion
{
    release: string;
    commit: string;
    /** 지금의 운영과 견준 권한의 변화. 사람이 읽는 문장이다. */
    changes: string[];
    /** 운영에 아직 돌지 않은 마이그레이션의 이름. */
    migrations: string[];
    /** 이번 변경으로 앱이 새로 받게 되는 밖에서 넣는 비밀의 이름. 지금의 운영과 견준다. 사람이 무엇을 승인하는지 읽는다. */
    newSecrets: string[];
    /** 이 release 가 담은 업데이트의 열린 rollout. 없으면 `null` 이다. 그 rollout 의 `change` 로만 오른다. */
    rollout: string | null;
}

/** rollout 이 어디에 있는가. `halted` 는 인스턴스 하나가 실패해 멈춘 것이고 팩토리가 다시 열어야 이어진다. */
export type RolloutStatus = "running" | "halted" | "cancelled" | "done";

/**
 * 인스턴스 하나가 업데이트를 어디까지 지났는가. `applied` 는 업데이트를 조상으로 담은 commit 이 포크에 선 것이고,
 * `passed` 는 그 프리뷰가 권한 검사와 적합성 테스트를 통과한 것이다. `failed` 는 다시 열면 `waiting` 부터 다시 지난다.
 */
export type RolloutState = "waiting" | "applied" | "previewed" | "passed" | "promoted" | "failed";

/** 인스턴스가 실패한 까닭. */
export type RolloutFailure = "access_check_failed" | "conformance_failed" | "rolled_back";

export interface RolloutInstance
{
    instance: string;
    state: RolloutState;
    /** `failed` 일 때만 있다. */
    reason: RolloutFailure | null;
}

/** 앱(위쪽)의 업데이트 하나를 포크 셋에 물결로 미는(당기는) 것. */
export interface Rollout
{
    id: string;
    app: string;
    /** 업데이트 commit. release 의 commit 이 이것을 조상으로 담으면 적용된 것이다. */
    commit: string;
    /** 이 업데이트를 담은 release 를 올릴 때 쓸 change. 기능 업데이트는 고객이, 법 · 보안 · 핵심 패키지는 팩토리가 승인한다. */
    change: Change;
    /** 순서 있는 물결. 앞 물결이 모두 오른 뒤에 뒤 물결이 오른다. */
    waves: string[][];
    status: RolloutStatus;
    /** 물결의 차례대로. */
    instances: RolloutInstance[];
}

/** 레이어가 업데이트를 합쳐 본 결과. 충돌하면 포크를 건드리지 않고 충돌한 파일의 이름만 온다. 에이전트가 풀어 올린다. */
export interface RolloutApply
{
    applied: boolean;
    /** 합친 뒤(또는 이미 담고 있던) 포크의 commit. 충돌했으면 `null` 이다. */
    commit: string | null;
    conflicts: string[];
}

/**
 * 밖에서 넣는 비밀의 단계. 값은 단계마다 따로이고 서로 넘어가지 않는다.
 * 프리뷰의 앱은 에이전트가 쓴 코드이고 에이전트가 그 로그와 답을 읽으므로, 프리뷰의 값은 에이전트가 볼 수 있다고 본다.
 */
export type SecretStage = "preview" | "production";

/** 단계 하나의 칸. 값은 없고 채워졌는지와 그 때(Unix 초)만 있다. */
export interface SecretSlot
{
    set: boolean;
    setAt: number | null;
}

/** 비밀 하나의 모습. 값 · 지문 · 길이는 어떤 열쇠로도 돌아오지 않는다. */
export interface Secret
{
    name: string;
    /** 이 인스턴스의 release(프리뷰로 세운 것과 운영의 것) 가운데 `[secrets] external` 에 적은 것이 있는가. */
    declared: boolean;
    /** 에이전트의 요청. 없으면 `null` 이다. */
    requested: { reason: string; at: number } | null;
    preview: SecretSlot;
    production: SecretSlot;
}

/**
 * 사람이 값을 넣을 입력 표. 10분 안에 한 번 쓴다. 사람의 브라우저가 `url`(고정된 주소)로 `Authorization: Bearer <ticket>` 을 실어
 * `{ value }` 를 바로 `POST` 한다. 표는 주소에 싣지 않는다(레이어 앞의 프록시가 남기는 접근 기록에 남지 않게).
 */
export interface SecretEntry
{
    url: string;
    /** 한 번 쓰는 표. 화면에만 건네고 모델이 읽는 자리에 싣지 않는다. */
    ticket: string;
    /** 만료되는 때(Unix 초). */
    expiresAt: number;
}

/**
 * 조직의 service key 하나. 값은 없다. 값은 낼 때(`keys.create`)의 답 한 번에만 오고, 레이어는 sha256 만 갖는다.
 * `prefix` 는 조직의 종류(`sk_live_` 운영 · `sk_test_` 시험용)다.
 */
export interface ServiceKey
{
    id: string;
    label: string;
    prefix: "sk_live_" | "sk_test_";
    /** 만든 때(Unix 초). */
    createdAt: number;
    /** 거둔 때(Unix 초). 살아 있으면 `null` 이다. */
    revokedAt: number | null;
    /** 마지막으로 쓴 때(Unix 초, 분 단위로 뭉친 것). 쓴 적이 없으면 `null` 이다. */
    usedAt: number | null;
}

/** 새로 낸 열쇠. `key`(값)는 이 답에만 있다. 팩토리의 서버의 비밀 저장소에 옮겨 두고, 다시 받을 길은 없다. */
export interface IssuedServiceKey
{
    id: string;
    label: string;
    key: string;
    createdAt: number;
}

/** 이벤트의 종류(`무엇.어찌됨`). 종류는 늘 수 있으니 받는 쪽은 모르는 종류를 건너뛴다. */
export type EventType =
    | "promotion.requested"
    | "promotion.succeeded"
    | "promotion.failed"
    | "rollout.advanced"
    | "rollout.halted"
    | "rollout.resumed"
    | "rollout.completed"
    | "rollout.cancelled"
    | "secret.requested"
    | "instance.created"
    | "instance.deleted";

/**
 * 레이어의 이벤트 하나. 목록(`events.list`)과 웹훅의 본문이 같은 모양이다. `data` 에는 이름과 숫자만 있다(값 · 행 · 로그 · 토큰은 없다).
 * 웹훅은 적어도 한 번 가므로 같은 이벤트가 두 번 올 수 있다. 받는 쪽은 `id` 로 겹침을 거른다. 한 조직의 이벤트는 `id` 의 차례로 온다.
 */
export interface OrbitalEvent
{
    id: number;
    /** 원래의 글. 아는 종류는 `EventType` 이다. */
    type: EventType | (string & {});
    /** 생긴 때(Unix 초). */
    createdAt: number;
    organization: string;
    /** 인스턴스 하나의 일이면 그 인스턴스. */
    instance: string | null;
    data: Record<string, unknown>;
}

/** 이벤트 목록의 한 쪽. 다음에는 `after: next` 로 이어 받는다. */
export interface EventPage
{
    events: OrbitalEvent[];
    /** 이 쪽의 마지막 id(없으면 물은 `after`). */
    next: number;
    hasMore: boolean;
}

/** 웹훅의 전달 모습. 숫자와 갈래만 있다(받은 답의 본문은 없다). */
export interface WebhookDelivery
{
    /** 이 id 까지는 보냈거나 그만뒀다. */
    deliveredThrough: number;
    /** 아직 보내지 않은 이벤트의 수. */
    pending: number;
    /** 다음에 보낼 때(Unix 초). 보낼 것이 없으면 `null` 이다. */
    nextAt: number | null;
    /** 지금 보내는 이벤트를 보내지 못한 횟수. 30초 · 2분 · 10분 · 1시간 · 6시간 뒤에 다시 보내고, 하루가 지나면 그만둔다. */
    failures: number;
    lastAttemptAt: number | null;
    lastStatus: number | null;
    lastError: "refused_address" | "unresolved" | "unreachable" | "timed_out" | "status" | "unsealed" | null;
    /** 마지막으로 2xx 를 받은 때. */
    deliveredAt: number | null;
    /** 하루 동안 보내지 못해 그만둔 이벤트의 수와 마지막 것의 id. 그만둔 것은 `events.list` 로 받는다. */
    abandoned: number;
    lastAbandoned: number | null;
}

/** 조직의 웹훅. 서명의 비밀은 없다(걸 때의 답에만 온다). */
export interface Webhook
{
    url: string;
    /** 건 때(Unix 초). */
    createdAt: number;
    delivery: WebhookDelivery;
}

/** 레이어의 마지막 복구 훈련. 숫자와 참 · 거짓만 있다. */
export interface DrillSummary
{
    passed: boolean;
    /** 훈련을 시작한 때(Unix 초). */
    at: number;
    /** 옆에 클러스터를 되살리는 데 걸린 시간(밀리초). */
    recoveryMillis: number;
    /** 훈련 전체에 걸린 시간(밀리초). */
    drillMillis: number;
    /** 잃을 수 있는 구간(초). 훈련을 시작한 때 − 마지막으로 보관된 WAL 의 시각. 보관된 것이 없었으면 `null` 이다. */
    exposureSeconds: number | null;
    /** 견준 인스턴스의 수. */
    instances: number;
    checks: number;
    failedChecks: number;
}

/**
 * 레이어의 백업과 복구 훈련의 모습. 마지막으로 통과한 훈련이 여드레 안이면 `fresh` 이다.
 * 훈련이 통과한 뒤에만 새 고객의 데이터를 받는다. 이 규칙을 켠 레이어는 낡은 동안 새 인스턴스를 409 로 거절한다.
 */
export interface Backup
{
    fresh: boolean;
    /** 마지막으로 통과한 훈련의 때(Unix 초). 한 번도 통과하지 않았으면 `null` 이다. */
    lastPassedAt: number | null;
    /** 마지막 훈련. 돈 적이 없으면 `null` 이다. */
    lastDrill: DrillSummary | null;
}

/** 인스턴스 하나를 지난 시점으로 되살린 결과. 이름과 숫자만 있다. */
export interface Restored
{
    instance: string;
    /** 되살린 시점(Unix 초). */
    at: number;
    /** 걸린 시간(밀리초). 그동안 그 인스턴스의 서버는 내려가 있다. */
    millis: number;
    /** 되살린 DB 의 표의 수. */
    tables: number;
    /** 되살리기 직전의 운영 DB 를 떠 둔 되돌릴 지점(database 의 이름). */
    restorePoint: string;
}

/** 되살리기를 무른 결과. 이름과 숫자만 있다. */
export interface RestoreUndone
{
    instance: string;
    /** 걸린 시간(밀리초). */
    millis: number;
    /** 돌아간 DB 의 표의 수. */
    tables: number;
}

/** 위쪽(앱)이 정한 적합성 테스트의 결과. */
/** 함대(조직의 인스턴스 목록)의 한 줄. 레이어의 기록만으로 짓는다. 이름과 숫자만 있다. */
export interface FleetInstance
{
    id: string;
    app: string;
    /** 갈라진 스캐폴드의 버전. 이 칸을 적기 전에 선 인스턴스는 `null` 이다. */
    version: string | null;
    /** 놓인 기계. */
    machine: string;
    createdAt: number | null;
    /** 운영에 오른 것. `promotedAt` 은 이 칸을 적기 전에 오른 운영이면 `null` 이다. */
    production: { release: string; promotedAt: number | null } | null;
    /** 사람의 승인을 기다리는 release. */
    promotionRequested: string | null;
    /** 프리뷰의 database 가 기록에 있는가. */
    preview: boolean;
    /** 마지막 승격(올랐거나 되돌려졌다). 「실패한 곳」은 `outcome` 이 `rolled_back` 이다. */
    lastPromotion: { release: string; at: number; outcome: "promoted" | "rolled_back" } | null;
}

/** 함대의 한 쪽. `hasMore` 면 `after: next` 로 이어 받는다. */
export interface FleetPage
{
    instances: FleetInstance[];
    /** 이 쪽의 마지막 줄의 표식. 처음부터 비었으면 `null` 이다. */
    next: string | null;
    hasMore: boolean;
}

/** 리허설의 숫자. 행의 내용은 없다. */
export interface RehearsalNumbers
{
    millis: number;
    failedAt: string | null;
    sqlstate: string | null;
    tables: { table: string; before: number | null; after: number | null }[];
}

/** release 의 이력의 승격 줄(올랐거나 되돌려졌다). */
export interface HistoryPromotion
{
    release: string;
    commit: string;
    previousRelease: string | null;
    change: Change;
    approvedBy: Approver;
    /** 팩토리가 붙인 승인한 사람의 이름표(`releases.promote` 의 `approver`). */
    approver: string | null;
    requestedAt: number | null;
    /** 승격을 요청한 작업의 식별자(`Session.id`). */
    requestedBy: string | null;
    /** 프리뷰에서 권한 검사가 찾은 어긋남의 수. */
    accessFindings: number;
    rehearsal: "not_needed" | "not_run" | "passed" | "failed";
    rehearsed: RehearsalNumbers | null;
    conformance: Conformance["outcome"];
    /** 돈 마이그레이션의 수. */
    migrations: number;
    /** 앞의 운영과 견준 권한의 변화(승인 카드의 문장). */
    changes: string[];
    rollout: string | null;
}

/** release 의 이력의 한 줄. `n` 은 인스턴스마다 1 부터의 차례다. */
export type HistoryEntry = { n: number; at: number } & (
    | ({ kind: "promoted" } & HistoryPromotion)
    | ({ kind: "rolled_back"; migrated: boolean } & HistoryPromotion)
    | { kind: "restored"; release: string; to: number }
    | { kind: "restore_undone"; release: string }
);

export interface HistoryPage
{
    history: HistoryEntry[];
    /** 이 쪽의 마지막 줄의 번호(`after` 로 이어 받는다). */
    next: number;
    hasMore: boolean;
}

/** 운영의 로그. 서비스마다 빌드와 서버의 끝이다. 앱이 찍은 글이라 고객의 데이터가 섞일 수 있다. 에이전트에게 넘기지 않는다. */
export interface ProductionLogs
{
    release: string;
    /** 서버가 찍은 로그(`production-<서비스>`)가 실렸는가. 레이어의 운영자가 켜지 않았으면 `false` 이고 빌드의 로그만 온다. */
    serverLogs: boolean;
    /** `clipped` 는 한 줄의 상한(2000자)에서 자른 줄의 수다. */
    logs: { name: string; text: string; clipped: number }[];
}

export type ServiceState = "awake" | "asleep" | "building" | "static" | "stopped";

/** 운영의 서비스마다의 상태. 놓인 기계가 답한다. */
export interface ProductionServices
{
    release: string;
    services: { name: string; kind: "server" | "static"; state: ServiceState }[];
}

/** 운영의 연결된 MCP 클라이언트(살아 있는 승인 하나). 토큰과 해시는 없다. */
export interface OauthGrant
{
    id: string;
    clientId: string;
    clientName: string;
    clientKind: "registered" | "dynamic" | "document";
    /** 승인한 사용자의 식별자(`users.list` 의 `id`). */
    user: string;
    scope: string;
    createdAt: number;
    /** 이 승인으로 마지막으로 토큰을 받은(코드를 바꾸거나 refresh 한) 때. */
    lastTokenAt: number | null;
}

/** 조직 자신의 모습. */
export interface OrganizationView
{
    id: string;
    /** 관리 서버의 설정에만 있는 조직이면 `null` 이다(`recorded: false`). */
    name: string | null;
    kind: "live" | "test";
    createdAt: number | null;
    recorded: boolean;
    instances: number;
    /** 세울 수 있는 인스턴스의 수. 시험용 조직에만 있다. */
    instanceLimit: number | null;
}

export interface RolloutPage
{
    rollouts: Rollout[];
    next: string | null;
    hasMore: boolean;
}

export interface Conformance
{
    passed: boolean;
    outcome: "not_declared" | "passed" | "failed" | "not_run" | "timed_out";
    millis: number;
    /** 출력의 끝부분. */
    output: string;
    /** 테스트를 가져온 위쪽 commit. */
    upstream: string;
}

/** 프리뷰를 세운 결과. 승격을 요청하기 전에 에이전트가 읽는다. */
export interface PreviewReport
{
    release: string;
    commit: string;
    /** 프리뷰의 주소. 고객과 에이전트가 여는 주소다. */
    services: Service[];
    /** 권한 검사가 찾은 어긋남. 비어 있어야 승격을 요청할 수 있다. */
    findings: string[];
    /** 지금의 운영과 견준 권한의 변화. 승인 카드에 설 문장이다. */
    changes: string[];
    /** 승격을 막는 것. */
    blockers: string[];
    /** 실패는 아니지만 알아 둘 것. */
    notices: string[];
    /** 프리뷰의 값이 없어 환경 변수 없이 선 밖에서 넣는 비밀의 이름. 사람에게 입력을 요청한다. */
    missingSecrets: string[];
    /** 위쪽이 선언하지 않았으면 `null` 이다. */
    conformance: Conformance | null;
}

/** 떠 있는 프리뷰의 로그. 서비스마다 빌드(`build-<서비스>`)와 서버(`preview-<서비스>`)의 끝이다. */
export interface PreviewLogs
{
    release: string;
    logs: { name: string; text: string }[];
}

/** 운영 사본에 마이그레이션을 미리 돌린 결과. 숫자만 있다. */
export interface Rehearsal
{
    release: string;
    /** 운영에 돌릴 마이그레이션이 없으면 `false` 이고 리허설이 필요 없다. */
    needed: boolean;
    passed: boolean;
    millis: number;
    failedAt: string | null;
    sqlstate: string | null;
    /** 표마다의 행 수(앞, 뒤). */
    tables: { table: string; before: number | null; after: number | null }[];
}

/** 작업의 인스턴스가 든 열린 rollout. 다른 인스턴스는 싣지 않는다. 받은 저장소에서 업데이트는 `origin/update` 다. */
export interface WorkRollout
{
    rollout: string;
    update: string;
    change: Change;
    halted: boolean;
    state: RolloutState;
}

/**
 * 에이전트의 작업 하나. 팩토리의 서버가 `works.open` 으로 열고, 작업의 토큰으로만 부른다(service key 를 싣지 않는다).
 * 토큰은 이 객체 밖으로 나오지 않는다. 운영을 바꾸는 함수는 없다.
 */
export interface Work
{
    readonly instance: string;
    /** 만료되는 때(Unix 초). 그 뒤의 부름은 401 로 거절된다. */
    readonly expiresAt: number;
    /**
     * 작업을 만료 전에 닫는다(service key 로). 그 뒤로 이 작업의 토큰으로 도는 부름은 진행 중인 git 의 다음 왕복까지 401 이다.
     * 관리 서버가 다시 떠도 닫은 채다. 여러 번 불러도 된다.
     */
    close(): Promise<void>;
    /** 레이어의 `main` 의 끝(또는 `commit`)을 빌드해 프리뷰를 세운다. */
    preview(input?: { commit?: string }): Promise<PreviewReport>;
    previewLogs(): Promise<PreviewLogs>;
    /** 프리뷰에 씨앗 사용자로 들어간다. 요청에 그대로 붙일 `Cookie` 머리말의 값을 돌려준다. 프리뷰에만 있고 운영에는 없다. */
    previewSignIn(user: string): Promise<{ cookie: string }>;
    rehearse(release: string): Promise<Rehearsal>;
    /** 승격을 요청한다. 승인은 사람이 하고, 운영에 올리는 일은 service key 의 `releases.promote` 만 한다. */
    requestPromotion(release: string): Promise<void>;
    rollout(): Promise<WorkRollout | null>;
    secrets: {
        list(): Promise<Secret[]>;
        request(name: string, input: { reason: string }): Promise<void>;
    };
    git: {
        /**
         * 팩토리의 서버가 받은 git 의 smart HTTP 요청을 이 작업의 토큰으로 레이어에 이어 준다. 주소의 끝은 셋 가운데 하나여야 한다:
         * `GET …/info/refs?service=git-upload-pack|git-receive-pack`, `POST …/git-upload-pack`, `POST …/git-receive-pack`.
         * 밖에서 온 `Authorization` 과 쿠키는 버리고, 본문은 스트림으로 넘긴다. 그 밖의 길은 레이어에 닿지 않고 404 다.
         */
        relay(request: Request): Promise<Response>;
    };
}

/**
 * 관리 서버가 받지 않은 요청. `code` 로 갈라 다루고 `message` 와 `details` 는 사람과 에이전트에게 보여 준다.
 * 인스턴스(또는 앱)가 다른 기계에 놓여 있으면 관리 서버는 놓인 기계의 주소를 알 때 요청을 그 기계로 넘기고 그 답을 그대로 돌려준다.
 * 넘기지 못했으면 `machine` 에 놓인 기계의 이름이 있고, 받은 관리 서버는 아무것도 하지 않았다. 주소를 모르거나 넘겨받은 요청이면
 * `status` 421 · `code` `misplaced`, 주소는 아는데 닿지 못했으면 502 · `machine_unreachable`, 넘긴 뒤 답을 받기 전에 끊겼으면
 * 502 · `machine_interrupted`(놓인 기계에서 일이 되었는지는 모른다)다.
 */
export class OrbitalError extends Error
{
    readonly status: number;
    readonly code: string;
    readonly details: readonly string[];
    readonly machine: string | null;

    constructor(status: number, code: string, message: string, details: readonly string[], machine: string | null = null)
    {
        super(message);
        this.name = "OrbitalError";
        this.status = status;
        this.code = code;
        this.details = details;
        this.machine = machine;
    }
}

/**
 * 팩토리의 로그인 설정(팩토리마다 한 벌, 그 팩토리의 모든 인스턴스의 운영이 쓴다). 비밀(`apiKey` · `clientSecret`)은 돌아오지 않는다.
 * `configured` 는 레이어가 그 키를 풀어 쓸 수 있는지다. `google.redirectUri` 는 Google 콘솔에 등록할 레이어의 콜백 주소다.
 */
export interface AuthSettings
{
    mail: { configured: boolean; provider: "resend" | null; from: string | null; fromName: string | null };
    google: { configured: boolean; clientId: string | null; redirectUri: string };
}

/** 메일 발송의 설정. 보내는 주소는 팩토리가 Resend 에서 확인한 도메인의 것이어야 한다. */
export interface MailSettings
{
    provider: "resend";
    apiKey: string;
    from: string;
    fromName?: string;
}

/** 팩토리의 Google 클라이언트(OAuth 웹 애플리케이션). redirect 로 `AuthSettings.google.redirectUri` 하나를 등록한다. */
export interface GoogleSettings
{
    clientId: string;
    clientSecret: string;
}

export interface OrbitalOptions
{
    /** 관리 서버의 주소. */
    url: string;
    /** 팩토리의 service key. 브라우저나 에이전트의 sandbox 에 두지 않는다. */
    serviceKey: string;
    /** 테스트에서 갈아 끼운다. */
    fetch?: typeof fetch;
}

export interface Orbital
{
    apps: {
        /** 스캐폴드를 올린다. `bundle` 은 버전마다 태그를 단 저장소의 git bundle 이다. */
        put(app: string, bundle: Uint8Array): Promise<void>;
    };
    instances: {
        /** 고객이 가입할 때: 스캐폴드의 한 버전에서 인스턴스를 세운다. */
        create(input: { app: string; from: string }): Promise<{ id: string }>;
        /** 인스턴스를 걷는다. DB 와 코드 저장소가 지워지고 되돌릴 수 없다. */
        destroy(instance: string): Promise<void>;
        /**
         * 운영 중인 인스턴스의 DB 를 지난 시점(Unix 초)으로 되살린다. 코드(release)와 비밀은 그대로다.
         * 되살리기 직전의 DB 는 되돌릴 지점으로 남는다. 그 시점을 덮는 기반 백업이 없거나 보관한 WAL 이 닿지 않으면 409 다.
         */
        restore(instance: string, input: { at: number }): Promise<Restored>;
        /**
         * 마지막 되살리기를 무른다: 그때 남긴 되돌릴 지점(되살리기 직전의 운영 DB)으로 돌아간다. 되돌릴 지점은 하나라 한 번만 무른다.
         * 되살린 뒤 승격이 있었거나 이미 물렀으면 409 와 까닭이다.
         */
        undoRestore(instance: string): Promise<RestoreUndone>;
        /** 함대: 이 조직의 인스턴스를 만든 차례로 한 쪽(기본 100 · 상한 500). 어느 관리 서버든 기록만으로 답한다. */
        list(input?: { after?: string; limit?: number }): Promise<FleetPage>;
        /** 인스턴스 하나의 함대의 줄. 다른 조직의 것은 없는 것과 같다(404). */
        get(instance: string): Promise<FleetInstance>;
        /** release 의 이력(승격 · 되돌려진 승격 · 되살리기 · 무르기)을 차례대로 한 쪽. 인스턴스마다 최근 500 줄을 둔다. */
        history(instance: string, input?: { after?: number; limit?: number }): Promise<HistoryPage>;
    };
    /** 조직 자신의 모습(이름 · 종류 · 인스턴스의 수와 상한). */
    organization: {
        get(): Promise<OrganizationView>;
    };
    backup: {
        /** 레이어의 복구 훈련이 통과했는지와 숫자. */
        get(): Promise<Backup>;
    };
    /**
     * 이 조직의 service key. 바꿀 때는 새 열쇠를 내고(`create`), 팩토리의 서버를 그 열쇠로 옮긴 뒤 옛 열쇠를 거둔다(`revoke`).
     * 둘은 거두기 전까지 함께 산다. 조직(과 첫 열쇠)은 레이어의 운영자가 만든다. 관리 서버의 설정에만 있는 조직은 열쇠를 내지 못한다(409).
     */
    keys: {
        /** 열쇠를 하나 더 낸다. 값은 이 답에만 있다. */
        create(input: { label: string }): Promise<IssuedServiceKey>;
        /** 이 조직의 열쇠 모두(거둔 것도). 값은 없다. */
        list(): Promise<ServiceKey[]>;
        /**
         * 열쇠를 거둔다. 어느 관리 서버에서든 다음 요청부터 받지 않는다. 다른 조직의 열쇠는 없는 것과 같고(404),
         * 살아 있는 마지막 열쇠는 거두지 않는다(409. 새 열쇠를 먼저 낸다). 이미 거둔 것이면 그대로 돌려준다.
         */
        revoke(id: string): Promise<ServiceKey>;
    };
    /**
     * 이 조직의 이벤트(승격의 요청 · 승격 · 되돌려진 승격 · rollout 의 진행 · 비밀의 요청 · 인스턴스의 생김과 지워짐). 30일 동안 둔다.
     * 웹훅을 걸지 않았거나 놓친 것을 받을 때 `after` 에 앞에서 받은 마지막 `id` 를 주어 차례대로 이어 받는다.
     */
    events: {
        list(input?: { after?: number; limit?: number }): Promise<EventPage>;
    };
    /**
     * 조직의 웹훅(주소 하나). 레이어는 `https://` 이고 바깥(공인)의 주소로만 풀리는 호스트로만 보낸다. 리다이렉트는 따라가지 않는다.
     * 받은 본문은 `verifyWebhook` 으로 확인한다.
     */
    webhook: {
        /** 걸지 않았으면 `null` 이다. */
        get(): Promise<Webhook | null>;
        /**
         * 건다. 서명의 비밀(`secret`, `whsec_…`)은 이 답에만 있다. 팩토리의 서버의 비밀 저장소에 옮겨 둔다. 비밀을 바꾸려면 다시 건다.
         * 처음 걸면 그 뒤에 생긴 이벤트부터 간다. 레이어에 봉인의 열쇠가 없으면 409 다.
         */
        set(input: { url: string }): Promise<{ webhook: Webhook; secret: string }>;
        /** 뗀다. 걸려 있었으면 참이다. */
        remove(): Promise<boolean>;
    };
    sessions: {
        /** 작업의 토큰을 받는다. 보통은 이것을 감싼 `works.open` 을 쓴다. 토큰은 에이전트에게 건네지 않는다. */
        open(input: { instance: string; can: readonly Capability[]; ttlSeconds?: number }): Promise<Session>;
    };
    works: {
        /** 에이전트의 작업을 연다: 팩토리가 판정한 범위로 작업의 토큰을 받아 감싼다. 누가 이 인스턴스를 고칠 수 있는지는 팩토리가 이미 판정했다. */
        open(input: { instance: string; can: readonly Capability[]; ttlSeconds?: number }): Promise<Work>;
    };
    releases: {
        /** 에이전트가 승격을 요청해 사람의 승인을 기다리는 release. 없으면 `null` 이다. */
        pending(instance: string): Promise<PendingPromotion | null>;
        /** 사람이 승인했을 때: 그 release 를 운영에 올린다. 승인은 이 release 하나에 묶인다. */
        /** `approver` 는 승인한 사람의 이름표(80자 안)로 이력에만 남는다. 이메일 대신 팩토리 쪽의 식별자를 권한다. */
        promote(input: { instance: string; release: string; change: Change; approvedBy: Approver; approver?: string }): Promise<Production>;
    };
    rollouts: {
        /**
         * 앱의 업데이트 하나로 rollout 을 만든다. `commit` 이 없으면 앱의 `main` 의 끝이다. 한 인스턴스는 같은 앱의 열린 rollout 하나에만 든다.
         * 업데이트를 담은 release 는 위쪽이 정한 적합성 테스트를 통과해야 하고, 한 곳이 실패하면 rollout 이 멈춘다.
         */
        create(app: string, input: { commit?: string; change: Change; waves: readonly (readonly string[])[] }): Promise<Rollout>;
        get(id: string): Promise<Rollout>;
        /** 이 조직의 rollout 을 만든 차례로 한 쪽. 끝났거나 거둔 것도 있다. */
        list(input?: { after?: string; limit?: number }): Promise<RolloutPage>;
        /** 포크의 머리에 업데이트를 기계적으로 합친다(`git merge`). 에이전트를 돌리지 않는다. */
        apply(id: string, instance: string): Promise<RolloutApply>;
        /** 멈춘 rollout 을 다시 연다. 실패한 인스턴스는 고친 release 로 프리뷰부터 다시 지난다. */
        resume(id: string): Promise<Rollout>;
        /** 거둔다. 아직 오르지 않은 곳은 그대로 남고, 어떤 사건도 받지 않는다. */
        cancel(id: string): Promise<Rollout>;
    };
    production: {
        /** 운영에 올라 있는 것. 아직 오른 것이 없으면 `null` 이다. */
        get(instance: string): Promise<Production | null>;
        /**
         * 운영의 로그(서비스마다 끝의 `lines` 줄, 기본 200 · 상한 1000). 레이어의 경로는 가려져 있지만 앱이 찍은 글은 그대로라
         * 고객의 데이터가 섞일 수 있다. service key 로만 열리고 에이전트의 토큰에는 길이 없다. 놓인 기계가 답한다.
         */
        logs(instance: string, input?: { lines?: number }): Promise<ProductionLogs>;
        /** 서비스마다 깨어 있는지 · 자는지 · 빌드 중인지. 놓인 기계가 답한다. */
        services(instance: string): Promise<ProductionServices>;
    };
    users: {
        /**
         * 운영에 사용자를 초대한다. 초대받은 사람은 앱의 로그인 화면에서 이메일 링크를 받아 들어온다.
         * `roles` 는 선언의 업무 역할이다. 신원은 router 가 로그인을 확인해 앱에 싣고, 레이어 밖으로는 내주지 않는다.
         */
        invite(input: { instance: string; email: string; roles: readonly string[] }): Promise<void>;
        /** 운영의 사용자 목록. 막힌 사용자도 함께 온다. 운영이 아직 서지 않았으면 409 로 거절된다. */
        list(instance: string): Promise<User[]>;
        /** 업무 역할을 통째로 바꾼다. 다음 요청부터 신원에 실린다. 선언에 없는 역할이면 422 다. */
        setRoles(input: { instance: string; user: string; roles: readonly string[] }): Promise<void>;
        /** 사용자를 뺀다. 막고 그 사용자의 세션을 모두 거둔다. */
        remove(input: { instance: string; user: string }): Promise<void>;
    };
    settings: {
        auth: {
            /** 팩토리의 로그인 설정. 비밀은 돌아오지 않는다. */
            get(): Promise<AuthSettings>;
            /**
             * 키를 넣는다. 적지 않은 칸은 그대로 두고, `null` 이면 지운다. 레이어에 봉인의 열쇠가 없으면 409 로 거절된다.
             * 키가 없으면 그 로그인 방법(`email_link` · `google`)을 선언한 release 는 운영에 오르지 못한다. 프리뷰는 선다.
             */
            set(input: { mail?: MailSettings | null; google?: GoogleSettings | null }): Promise<AuthSettings>;
        };
    };
    secrets: {
        /** 이름마다 선언됐는지 · 요청됐는지 · 단계마다 채워졌는지. 값은 돌아오지 않는다. */
        list(instance: string): Promise<Secret[]>;
        /** 사람에게 입력을 요청한다. `orbital.toml` 의 `[secrets] external` 에 적고 프리뷰를 세운 이름만 받는다. */
        request(instance: string, name: string, input: { reason: string }): Promise<void>;
        /**
         * 값을 넣는다. 값이 팩토리의 서버를 지나는 길이라, 사람이 넣는 값은 `entry` 로 레이어에 바로 보내게 한다.
         * 운영의 값을 바꾸면 도는 서비스가 자고, 다음 요청이 새 값으로 깬다. 봉인의 열쇠가 없는 레이어에서는 409 다.
         */
        set(instance: string, name: string, input: { stage: SecretStage; value: string }): Promise<void>;
        /** 값을 지운다. 지금 운영의 release 가 쓰는 비밀의 운영 값은 409 로 거절된다. */
        remove(instance: string, name: string, input: { stage: SecretStage }): Promise<void>;
        /** 사람의 입력 표를 받는다. 인스턴스 · 이름 · 단계 하나에 묶인다. 카드가 이 주소로 값을 보낸다. */
        entry(instance: string, name: string, input: { stage: SecretStage }): Promise<SecretEntry>;
    };
    oauthClients: {
        /**
         * MCP 의 OAuth 클라이언트를 미리 등록한다(`[auth.mcp]` 를 선언한 인스턴스만). redirect 는 `https` 이거나 `localhost` 여야 한다.
         * 클라이언트는 받은 `clientId` 로 인가를 받는다. 비밀(client_secret)은 없다(공개 클라이언트).
         */
        register(input: { instance: string; name: string; redirectUris: readonly string[] }): Promise<{ clientId: string }>;
        /** 운영의 연결된 클라이언트(사용자마다의 살아 있는 승인). */
        grants(instance: string): Promise<OauthGrant[]>;
    };
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function isRecord(value: unknown): value is Record<string, unknown>
{
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string
{
    return typeof value === "string" ? value : "";
}

function number(value: unknown): number
{
    return typeof value === "number" ? value : 0;
}

function texts(value: unknown): string[]
{
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function toProduction(value: unknown): Production
{
    const record = isRecord(value) ? value : {};
    const services = Array.isArray(record.services) ? record.services.filter(isRecord) : [];
    return {
        release: text(record.release),
        services: services.map((service) => ({
            name: text(service.name),
            kind: service.kind === "static" ? "static" : "server",
            url: typeof service.url === "string" ? service.url : null,
        })),
        migrations: texts(record.migrations),
        schedules: (Array.isArray(record.schedules) ? record.schedules.filter(isRecord) : []).map(toSchedule),
    };
}

const SCHEDULE_OUTCOMES: readonly ScheduleOutcome[] = ["running", "ok", "failed", "unreachable", "timed_out"];

function toSchedule(value: Record<string, unknown>): Schedule
{
    const run = isRecord(value.last_run) ? value.last_run : null;
    return {
        service: text(value.service),
        path: text(value.path),
        cron: text(value.cron),
        role: typeof value.role === "string" ? value.role : null,
        nextAt: typeof value.next_at === "number" ? value.next_at : null,
        lastRun: run === null
            ? null
            : {
                dueAt: number(run.due_at),
                startedAt: number(run.started_at),
                outcome: oneOf(SCHEDULE_OUTCOMES, run.outcome, "failed"),
                status: typeof run.status === "number" ? run.status : null,
                millis: typeof run.millis === "number" ? run.millis : null,
            },
    };
}

function toUser(value: Record<string, unknown>): User
{
    return {
        id: text(value.id),
        email: text(value.email),
        name: typeof value.name === "string" ? value.name : null,
        roles: texts(value.roles),
        disabled: value.disabled === true,
        lastSignedInAt: typeof value.last_signed_in_at === "number" ? value.last_signed_in_at : null,
    };
}

function toSlot(value: unknown): SecretSlot
{
    const record = isRecord(value) ? value : {};
    return { set: record.set === true, setAt: typeof record.set_at === "number" ? record.set_at : null };
}

function toSecret(value: Record<string, unknown>): Secret
{
    const requested = isRecord(value.requested) ? value.requested : null;
    return {
        name: text(value.name),
        declared: value.declared === true,
        requested: requested === null ? null : { reason: text(requested.reason), at: typeof requested.at === "number" ? requested.at : 0 },
        preview: toSlot(value.preview),
        production: toSlot(value.production),
    };
}

const CHANGES: readonly Change[] = ["customer_request", "feature_update", "legal_update", "security_update", "core_package"];
const ROLLOUT_STATUSES: readonly RolloutStatus[] = ["running", "halted", "cancelled", "done"];
const ROLLOUT_STATES: readonly RolloutState[] = ["waiting", "applied", "previewed", "passed", "promoted", "failed"];
const ROLLOUT_FAILURES: readonly RolloutFailure[] = ["access_check_failed", "conformance_failed", "rolled_back"];

function oneOf<T extends string>(choices: readonly T[], value: unknown, fallback: T): T
{
    return choices.find((choice) => choice === value) ?? fallback;
}

function toRollout(value: unknown): Rollout
{
    const record = isRecord(value) ? value : {};
    const waves = Array.isArray(record.waves) ? record.waves.map(texts) : [];
    const instances = Array.isArray(record.instances) ? record.instances.filter(isRecord) : [];
    return {
        id: text(record.id),
        app: text(record.app),
        commit: text(record.commit),
        change: oneOf(CHANGES, record.change, "customer_request"),
        waves,
        status: oneOf(ROLLOUT_STATUSES, record.status, "running"),
        instances: instances.map((entry) => ({
            instance: text(entry.instance),
            state: oneOf(ROLLOUT_STATES, entry.state, "waiting"),
            reason: entry.reason === undefined ? null : oneOf(ROLLOUT_FAILURES, entry.reason, "rolled_back"),
        })),
    };
}

function toAuthSettings(value: unknown): AuthSettings
{
    const record = isRecord(value) ? value : {};
    const mail = isRecord(record.mail) ? record.mail : {};
    const google = isRecord(record.google) ? record.google : {};
    return {
        mail: {
            configured: mail.configured === true,
            provider: mail.provider === "resend" ? "resend" : null,
            from: typeof mail.from === "string" ? mail.from : null,
            fromName: typeof mail.from_name === "string" ? mail.from_name : null,
        },
        google: {
            configured: google.configured === true,
            clientId: typeof google.client_id === "string" ? google.client_id : null,
            redirectUri: text(google.redirect_uri),
        },
    };
}

function toServiceKey(value: unknown): ServiceKey
{
    const record = isRecord(value) ? value : {};
    return {
        id: text(record.id),
        label: text(record.label),
        prefix: record.prefix === "sk_test_" ? "sk_test_" : "sk_live_",
        createdAt: number(record.created_at),
        revokedAt: typeof record.revoked_at === "number" ? record.revoked_at : null,
        usedAt: typeof record.used_at === "number" ? record.used_at : null,
    };
}

function toServices(value: unknown): Service[]
{
    return toProduction({ services: value }).services;
}

const CONFORMED: readonly Conformance["outcome"][] = ["not_declared", "passed", "failed", "not_run", "timed_out"];

function toPreview(value: unknown): PreviewReport
{
    const record = isRecord(value) ? value : {};
    const conformance = isRecord(record.conformance) ? record.conformance : null;
    return {
        release: text(record.release),
        commit: text(record.commit),
        services: toServices(record.services),
        findings: texts(record.findings),
        changes: texts(record.changes),
        blockers: texts(record.blockers),
        notices: texts(record.notices),
        missingSecrets: texts(record.missing_secrets),
        conformance: conformance === null
            ? null
            : {
                passed: conformance.passed === true,
                outcome: oneOf(CONFORMED, conformance.outcome, "not_run"),
                millis: number(conformance.millis),
                output: text(conformance.output),
                upstream: text(conformance.upstream),
            },
    };
}

const orNull = (value: unknown): number | null => (typeof value === "number" ? value : null);

function toRehearsal(value: unknown): Rehearsal
{
    const record = isRecord(value) ? value : {};
    const tables = Array.isArray(record.tables) ? record.tables.filter(Array.isArray) : [];
    return {
        release: text(record.release),
        needed: record.needed === true,
        passed: record.passed === true,
        millis: number(record.millis),
        failedAt: typeof record.failed_at === "string" ? record.failed_at : null,
        sqlstate: typeof record.sqlstate === "string" ? record.sqlstate : null,
        tables: tables.map((row: unknown[]) => ({ table: text(row[0]), before: orNull(row[1]), after: orNull(row[2]) })),
    };
}

const DELIVERY_ERRORS: readonly NonNullable<WebhookDelivery["lastError"]>[] = [
    "refused_address",
    "unresolved",
    "unreachable",
    "timed_out",
    "status",
    "unsealed",
];

function toEvent(value: unknown): OrbitalEvent
{
    const record = isRecord(value) ? value : {};
    return {
        id: number(record.id),
        type: text(record.type),
        createdAt: number(record.created_at),
        organization: text(record.organization),
        instance: typeof record.instance === "string" ? record.instance : null,
        data: isRecord(record.data) ? record.data : {},
    };
}

function toWebhook(value: Record<string, unknown>): Webhook
{
    const delivery = isRecord(value.delivery) ? value.delivery : {};
    return {
        url: text(value.url),
        createdAt: number(value.created_at),
        delivery: {
            deliveredThrough: number(delivery.delivered_through),
            pending: number(delivery.pending),
            nextAt: orNull(delivery.next_at),
            failures: number(delivery.failures),
            lastAttemptAt: orNull(delivery.last_attempt_at),
            lastStatus: orNull(delivery.last_status),
            lastError: DELIVERY_ERRORS.find((error) => error === delivery.last_error) ?? null,
            deliveredAt: orNull(delivery.delivered_at),
            abandoned: number(delivery.abandoned),
            lastAbandoned: orNull(delivery.last_abandoned),
        },
    };
}

function orText(value: unknown): string | null
{
    return typeof value === "string" ? value : null;
}

function query(input: { [key: string]: string | number | undefined }): string
{
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(input))
    {
        if (value !== undefined)
        {
            params.set(key, String(value));
        }
    }
    return params.size === 0 ? "" : `?${params.toString()}`;
}

function toFleetInstance(value: unknown): FleetInstance
{
    const record = isRecord(value) ? value : {};
    const production = isRecord(record.production) ? record.production : null;
    const last = isRecord(record.last_promotion) ? record.last_promotion : null;
    return {
        id: text(record.id),
        app: text(record.app),
        version: orText(record.version),
        machine: text(record.machine),
        createdAt: orNull(record.created_at),
        production: production === null ? null : { release: text(production.release), promotedAt: orNull(production.promoted_at) },
        promotionRequested: orText(record.promotion_requested),
        preview: record.preview === true,
        lastPromotion: last === null
            ? null
            : { release: text(last.release), at: number(last.at), outcome: last.outcome === "rolled_back" ? "rolled_back" : "promoted" },
    };
}

const REHEARSED: readonly HistoryPromotion["rehearsal"][] = ["not_needed", "not_run", "passed", "failed"];

function toHistoryEntry(value: unknown): HistoryEntry
{
    const record = isRecord(value) ? value : {};
    const head = { n: number(record.n), at: number(record.at) };
    if (record.kind === "restored")
    {
        return { ...head, kind: "restored", release: text(record.release), to: number(record.to) };
    }
    if (record.kind === "restore_undone")
    {
        return { ...head, kind: "restore_undone", release: text(record.release) };
    }
    const rehearsed = isRecord(record.rehearsed) ? record.rehearsed : null;
    const promotion: HistoryPromotion = {
        release: text(record.release),
        commit: text(record.commit),
        previousRelease: orText(record.previous_release),
        change: oneOf(CHANGES, record.change, "customer_request"),
        approvedBy: record.approved_by === "factory" ? "factory" : "customer",
        approver: orText(record.approver),
        requestedAt: orNull(record.requested_at),
        requestedBy: orText(record.requested_by),
        accessFindings: number(record.access_findings),
        rehearsal: oneOf(REHEARSED, record.rehearsal, "not_run"),
        rehearsed: rehearsed === null
            ? null
            : {
                millis: number(rehearsed.millis),
                failedAt: orText(rehearsed.failed_at),
                sqlstate: orText(rehearsed.sqlstate),
                tables: (Array.isArray(rehearsed.tables) ? rehearsed.tables.filter(isRecord) : []).map((table) => ({
                    table: text(table.table),
                    before: orNull(table.before),
                    after: orNull(table.after),
                })),
            },
        conformance: oneOf(CONFORMED, record.conformance, "not_run"),
        migrations: number(record.migrations),
        changes: texts(record.changes),
        rollout: orText(record.rollout),
    };
    return record.kind === "rolled_back"
        ? { ...head, kind: "rolled_back", migrated: record.migrated === true, ...promotion }
        : { ...head, kind: "promoted", ...promotion };
}

const SERVICE_STATES: readonly ServiceState[] = ["awake", "asleep", "building", "static", "stopped"];
const CLIENT_KINDS: readonly OauthGrant["clientKind"][] = ["registered", "dynamic", "document"];

/** 웹훅의 본문을 받지 않은 까닭. `malformed` 머리말이나 본문의 모양이 틀림, `stale` 서명의 때가 허용 시간차 밖, `mismatch` 서명이 맞지 않음. */
export class OrbitalWebhookError extends Error
{
    readonly code: "malformed" | "stale" | "mismatch";

    constructor(code: "malformed" | "stale" | "mismatch", message: string)
    {
        super(message);
        this.name = "OrbitalWebhookError";
        this.code = code;
    }
}

/**
 * 레이어가 보낸 웹훅의 본문을 확인하고 이벤트로 읽는다. 맞지 않으면 `OrbitalWebhookError` 를 던진다.
 *
 * - `body` 는 받은 그대로의 바이트(또는 글)여야 한다. JSON 으로 읽었다가 다시 쓴 것은 맞지 않는다.
 * - `signature` 는 `orbital-signature` 머리말(`t=<Unix 초>,v1=<hex>`)이다. `v1` 은 `HMAC-SHA256(비밀, "<t>.<본문>")` 이고, 견주기는
 *   시간이 값에 따라 달라지지 않게 한다. `t` 가 지금(`now`, Unix 초)에서 `toleranceSeconds`(기본 300초)보다 멀면 받지 않는다(되풀이 막기).
 * - 웹훅은 적어도 한 번 간다. 같은 `id` 가 다시 올 수 있으니 처리한 `id` 를 기억해 겹침을 거른다.
 */
export function verifyWebhook(input: {
    secret: string;
    signature: string | null | undefined;
    body: string | Uint8Array;
    toleranceSeconds?: number;
    now?: number;
}): OrbitalEvent
{
    const tolerance = input.toleranceSeconds ?? 300;
    const now = input.now ?? Math.floor(Date.now() / 1000);
    let at: number | null = null;
    const given: string[] = [];
    for (const part of (input.signature ?? "").split(","))
    {
        const split = part.indexOf("=");
        const key = split < 0 ? part.trim() : part.slice(0, split).trim();
        const value = split < 0 ? "" : part.slice(split + 1).trim();
        if (key === "t" && /^[0-9]{1,12}$/.test(value))
        {
            at = Number(value);
        }
        else if (key === "v1" && /^[0-9a-f]{64}$/.test(value))
        {
            given.push(value);
        }
    }
    if (at === null || given.length === 0)
    {
        throw new OrbitalWebhookError("malformed", "orbital-signature 머리말이 `t=<Unix 초>,v1=<hex>` 모양이 아닙니다");
    }
    if (Math.abs(now - at) > tolerance)
    {
        throw new OrbitalWebhookError("stale", `서명의 때가 지금과 ${tolerance}초보다 멉니다. 시계를 맞추거나 다시 보낸 것을 기다려 주세요`);
    }
    const bytes = typeof input.body === "string" ? Buffer.from(input.body, "utf8") : Buffer.from(input.body);
    const expected = createHmac("sha256", input.secret).update(`${at}.`).update(bytes).digest();
    const matched = given.some((value) =>
    {
        const candidate = Buffer.from(value, "hex");
        return candidate.length === expected.length && timingSafeEqual(candidate, expected);
    });
    if (!matched)
    {
        throw new OrbitalWebhookError("mismatch", "서명이 맞지 않습니다. 받은 본문을 고치지 않고 그대로 넘기고, 웹훅을 건 때 받은 비밀을 쓰는지 봐 주세요");
    }
    let parsed: unknown;
    try
    {
        parsed = JSON.parse(bytes.toString("utf8"));
    }
    catch
    {
        throw new OrbitalWebhookError("malformed", "본문이 JSON 이 아닙니다");
    }
    if (!isRecord(parsed))
    {
        throw new OrbitalWebhookError("malformed", "본문이 이벤트의 모양이 아닙니다");
    }
    return toEvent(parsed);
}

/** git 의 길 셋. 주소의 끝과 방법으로 고르고, 레이어의 `…/git/` 뒤에 붙일 것을 돌려준다. 셋이 아니면 `undefined` 다. */
function gitTail(method: string, url: URL): string | undefined
{
    const path = url.pathname;
    if (method === "GET" && path.endsWith("/info/refs"))
    {
        const service = url.searchParams.get("service");
        const only = [...url.searchParams.keys()].length === 1;
        return only && (service === "git-upload-pack" || service === "git-receive-pack") ? `info/refs?service=${service}` : undefined;
    }
    if (method === "POST" && url.search === "")
    {
        for (const service of ["git-upload-pack", "git-receive-pack"])
        {
            if (path.endsWith(`/${service}`))
            {
                return service;
            }
        }
    }
    return undefined;
}

/** git 이 주고받는 데 쓰는 머리말만 넘긴다. `Authorization` · 쿠키 · `Git-Protocol` 은 넘기지 않는다. */
const GIT_REQUEST_HEADERS = ["content-type", "content-encoding", "accept"];
const GIT_ANSWER_HEADERS = ["content-type", "cache-control"];

export function createOrbital(options: OrbitalOptions): Orbital
{
    const base = options.url.replace(/\/+$/, "");
    const send = options.fetch ?? fetch;

    async function call(method: string, path: string, body?: Json | Uint8Array, bearer: string = options.serviceKey): Promise<unknown>
    {
        const headers: Record<string, string> = { authorization: `Bearer ${bearer}` };
        const init: RequestInit = { method, headers };
        if (body instanceof Uint8Array)
        {
            headers["content-type"] = "application/octet-stream";
            // 공유 메모리 위의 배열은 요청의 본문이 되지 못한다. 옮겨 담아 보낸다
            init.body = new Uint8Array(body);
        }
        else if (body !== undefined)
        {
            headers["content-type"] = "application/json";
            init.body = JSON.stringify(body);
        }
        const response = await send(`${base}/v1/${path}`, init);
        const reply: unknown = await response.json().catch(() => null);
        if (response.ok)
        {
            return reply;
        }
        const problem = isRecord(reply) ? reply : {};
        throw new OrbitalError(
            response.status,
            text(problem.error) || "unknown",
            text(problem.message) || `관리 서버가 ${response.status} 로 답했습니다`,
            texts(problem.details),
            text(problem.machine) || null,
        );
    }

    const at = (instance: string, tail: string): string => `instances/${encodeURIComponent(instance)}${tail}`;

    async function openSession(input: { instance: string; can: readonly Capability[]; ttlSeconds?: number }): Promise<Session>
    {
        const body: { [key: string]: Json } = { can: [...input.can] };
        if (input.ttlSeconds !== undefined)
        {
            body.ttl_seconds = input.ttlSeconds;
        }
        const reply = await call("POST", at(input.instance, "/sessions"), body);
        const record = isRecord(reply) ? reply : {};
        return {
            token: text(record.token),
            expiresAt: typeof record.expires_at === "number" ? record.expires_at : 0,
            id: text(record.session),
        };
    }

    /** 작업 하나. 모든 부름이 작업의 토큰을 싣는다. service key 는 이 안에서 쓰지 않는다. */
    function work(instance: string, session: Session): Work
    {
        const token = session.token;
        const as = (method: string, tail: string, body?: Json): Promise<unknown> => call(method, at(instance, tail), body, token);
        const notFound = (): Response => new Response(
            JSON.stringify({ error: "not_found", message: "git 의 길이 아닙니다" }),
            { status: 404, headers: { "content-type": "application/json" } },
        );
        return {
            instance,
            expiresAt: session.expiresAt,
            async close()
            {
                // 닫는 일은 팩토리의 것이다. 작업의 토큰이 아니라 service key 로 부른다
                await call("DELETE", at(instance, `/sessions/${encodeURIComponent(session.id)}`));
            },
            async preview(input = {})
            {
                return toPreview(await as("POST", "/previews", input.commit === undefined ? undefined : { commit: input.commit }));
            },
            async previewLogs()
            {
                const reply = await as("GET", "/previews/logs");
                const record = isRecord(reply) ? reply : {};
                const logs = Array.isArray(record.logs) ? record.logs.filter(isRecord) : [];
                return { release: text(record.release), logs: logs.map((log) => ({ name: text(log.name), text: text(log.text) })) };
            },
            async previewSignIn(user)
            {
                const reply = await as("POST", "/previews/identities", { user });
                return { cookie: text(isRecord(reply) ? reply.cookie : undefined) };
            },
            async rehearse(release)
            {
                return toRehearsal(await as("POST", "/rehearsals", { release }));
            },
            async requestPromotion(release)
            {
                await as("POST", "/promotion-requests", { release });
            },
            async rollout()
            {
                const reply = await as("GET", "/rollout");
                if (!isRecord(reply))
                {
                    return null;
                }
                return {
                    rollout: text(reply.rollout),
                    update: text(reply.update),
                    change: oneOf(CHANGES, reply.change, "customer_request"),
                    halted: reply.halted === true,
                    state: oneOf(ROLLOUT_STATES, reply.state, "waiting"),
                };
            },
            secrets: {
                async list()
                {
                    const reply = await as("GET", "/secrets");
                    const secrets = isRecord(reply) && Array.isArray(reply.secrets) ? reply.secrets.filter(isRecord) : [];
                    return secrets.map(toSecret);
                },
                async request(name, { reason })
                {
                    await as("POST", `/secrets/${encodeURIComponent(name)}/request`, { reason });
                },
            },
            git: {
                async relay(request)
                {
                    const tail = gitTail(request.method, new URL(request.url));
                    if (tail === undefined)
                    {
                        return notFound();
                    }
                    const headers: Record<string, string> = { authorization: `Bearer ${token}` };
                    for (const name of GIT_REQUEST_HEADERS)
                    {
                        const value = request.headers.get(name);
                        if (value !== null)
                        {
                            headers[name] = value;
                        }
                    }
                    const init: RequestInit & { duplex?: "half" } = { method: request.method, headers };
                    if (request.method === "POST" && request.body !== null)
                    {
                        // 본문을 모아 두지 않고 흘려 넘긴다
                        init.body = request.body;
                        init.duplex = "half";
                    }
                    const answer = await send(`${base}/v1/${at(instance, `/git/${tail}`)}`, init);
                    const passed = new Headers();
                    for (const name of GIT_ANSWER_HEADERS)
                    {
                        const value = answer.headers.get(name);
                        if (value !== null)
                        {
                            passed.set(name, value);
                        }
                    }
                    // 레이어의 `WWW-Authenticate` 는 넘기지 않는다. 자격을 묻는 일은 팩토리의 길이 한다
                    return new Response(answer.body, { status: answer.status, headers: passed });
                },
            },
        };
    }

    return {
        apps: {
            async put(app, bundle)
            {
                await call("PUT", `apps/${encodeURIComponent(app)}`, bundle);
            },
        },
        instances: {
            async create({ app, from })
            {
                const reply = await call("POST", "instances", { app, version: from });
                return { id: text(isRecord(reply) ? reply.instance : undefined) };
            },
            async destroy(instance)
            {
                await call("DELETE", at(instance, ""));
            },
            async restore(instance, { at: moment })
            {
                const reply = await call("POST", at(instance, "/restore"), { at: moment });
                const record = isRecord(reply) ? reply : {};
                return {
                    instance: text(record.instance),
                    at: number(record.at),
                    millis: number(record.millis),
                    tables: number(record.tables),
                    restorePoint: text(record.restore_point),
                };
            },
            async undoRestore(instance)
            {
                const reply = await call("POST", at(instance, "/restore/undo"), {});
                const record = isRecord(reply) ? reply : {};
                return { instance: text(record.instance), millis: number(record.millis), tables: number(record.tables) };
            },
            async list(input = {})
            {
                const reply = await call("GET", `instances${query({ after: input.after, limit: input.limit })}`);
                const record = isRecord(reply) ? reply : {};
                return {
                    instances: (Array.isArray(record.instances) ? record.instances : []).map(toFleetInstance),
                    next: orText(record.next),
                    hasMore: record.has_more === true,
                };
            },
            async get(instance)
            {
                return toFleetInstance(await call("GET", at(instance, "")));
            },
            async history(instance, input = {})
            {
                const reply = await call("GET", at(instance, `/history${query({ after: input.after, limit: input.limit })}`));
                const record = isRecord(reply) ? reply : {};
                return {
                    history: (Array.isArray(record.history) ? record.history : []).map(toHistoryEntry),
                    next: number(record.next),
                    hasMore: record.has_more === true,
                };
            },
        },
        organization: {
            async get()
            {
                const reply = await call("GET", "organization");
                const record = isRecord(reply) ? reply : {};
                return {
                    id: text(record.id),
                    name: orText(record.name),
                    kind: record.kind === "test" ? "test" : "live",
                    createdAt: orNull(record.created_at),
                    recorded: record.recorded === true,
                    instances: number(record.instances),
                    instanceLimit: orNull(record.instance_limit),
                };
            },
        },
        backup: {
            async get()
            {
                const reply = await call("GET", "backup");
                const record = isRecord(reply) ? reply : {};
                const last = isRecord(record.last_drill) ? record.last_drill : null;
                return {
                    fresh: record.fresh === true,
                    lastPassedAt: typeof record.last_passed_at === "number" ? record.last_passed_at : null,
                    lastDrill: last === null
                        ? null
                        : {
                            passed: last.passed === true,
                            at: number(last.at),
                            recoveryMillis: number(last.recovery_millis),
                            drillMillis: number(last.drill_millis),
                            exposureSeconds: typeof last.exposure_seconds === "number" ? last.exposure_seconds : null,
                            instances: number(last.instances),
                            checks: number(last.checks),
                            failedChecks: number(last.failed_checks),
                        },
                };
            },
        },
        keys: {
            async create({ label })
            {
                const reply = await call("POST", "keys", { label });
                const record = isRecord(reply) ? reply : {};
                return { id: text(record.id), label: text(record.label), key: text(record.key), createdAt: number(record.created_at) };
            },
            async list()
            {
                const reply = await call("GET", "keys");
                return (isRecord(reply) && Array.isArray(reply.keys) ? reply.keys : []).map(toServiceKey);
            },
            async revoke(id)
            {
                return toServiceKey(await call("DELETE", `keys/${encodeURIComponent(id)}`));
            },
        },
        events: {
            async list(input = {})
            {
                const query = new URLSearchParams();
                if (input.after !== undefined)
                {
                    query.set("after", String(input.after));
                }
                if (input.limit !== undefined)
                {
                    query.set("limit", String(input.limit));
                }
                const tail = query.size === 0 ? "" : `?${query.toString()}`;
                const reply = await call("GET", `events${tail}`);
                const record = isRecord(reply) ? reply : {};
                return {
                    events: (Array.isArray(record.events) ? record.events : []).map(toEvent),
                    next: number(record.next),
                    hasMore: record.has_more === true,
                };
            },
        },
        webhook: {
            async get()
            {
                const reply = await call("GET", "settings/webhook");
                return isRecord(reply) && isRecord(reply.webhook) ? toWebhook(reply.webhook) : null;
            },
            async set({ url })
            {
                const reply = await call("PUT", "settings/webhook", { url });
                const record = isRecord(reply) ? reply : {};
                return { webhook: toWebhook(isRecord(record.webhook) ? record.webhook : {}), secret: text(record.secret) };
            },
            async remove()
            {
                const reply = await call("DELETE", "settings/webhook");
                return isRecord(reply) && reply.removed === true;
            },
        },
        sessions: {
            open: openSession,
        },
        works: {
            async open(input)
            {
                return work(input.instance, await openSession(input));
            },
        },
        releases: {
            async pending(instance)
            {
                const reply = await call("GET", at(instance, "/promotion-request"));
                if (!isRecord(reply))
                {
                    return null;
                }
                return {
                    release: text(reply.release),
                    commit: text(reply.commit),
                    changes: texts(reply.changes),
                    migrations: texts(reply.migrations),
                    newSecrets: texts(reply.new_secrets),
                    rollout: typeof reply.rollout === "string" ? reply.rollout : null,
                };
            },
            async promote({ instance, release, change, approvedBy, approver })
            {
                const body: { [key: string]: Json } = { release, change, approved_by: approvedBy };
                if (approver !== undefined)
                {
                    body.approver = approver;
                }
                return toProduction(await call("POST", at(instance, "/promotions"), body));
            },
        },
        rollouts: {
            async create(app, { commit, change, waves })
            {
                const body: { [key: string]: Json } = { change, waves: waves.map((wave) => [...wave]) };
                if (commit !== undefined)
                {
                    body.commit = commit;
                }
                return toRollout(await call("POST", `apps/${encodeURIComponent(app)}/rollouts`, body));
            },
            async get(id)
            {
                return toRollout(await call("GET", `rollouts/${encodeURIComponent(id)}`));
            },
            async list(input = {})
            {
                const reply = await call("GET", `rollouts${query({ after: input.after, limit: input.limit })}`);
                const record = isRecord(reply) ? reply : {};
                return {
                    rollouts: (Array.isArray(record.rollouts) ? record.rollouts : []).map(toRollout),
                    next: orText(record.next),
                    hasMore: record.has_more === true,
                };
            },
            async apply(id, instance)
            {
                const reply = await call("POST", `rollouts/${encodeURIComponent(id)}/instances/${encodeURIComponent(instance)}/apply`);
                const record = isRecord(reply) ? reply : {};
                return {
                    applied: record.applied === true,
                    commit: typeof record.commit === "string" ? record.commit : null,
                    conflicts: texts(record.conflicts),
                };
            },
            async resume(id)
            {
                return toRollout(await call("POST", `rollouts/${encodeURIComponent(id)}/resume`));
            },
            async cancel(id)
            {
                return toRollout(await call("POST", `rollouts/${encodeURIComponent(id)}/cancel`));
            },
        },
        production: {
            async get(instance)
            {
                const reply = await call("GET", at(instance, "/production"));
                return isRecord(reply) ? toProduction(reply) : null;
            },
            async logs(instance, input = {})
            {
                const reply = await call("GET", at(instance, `/production/logs${query({ lines: input.lines })}`));
                const record = isRecord(reply) ? reply : {};
                return {
                    release: text(record.release),
                    serverLogs: record.server_logs === true,
                    logs: (Array.isArray(record.logs) ? record.logs.filter(isRecord) : []).map((log) => ({
                        name: text(log.name),
                        text: text(log.text),
                        clipped: number(log.clipped),
                    })),
                };
            },
            async services(instance)
            {
                const reply = await call("GET", at(instance, "/production/services"));
                const record = isRecord(reply) ? reply : {};
                return {
                    release: text(record.release),
                    services: (Array.isArray(record.services) ? record.services.filter(isRecord) : []).map((service) => ({
                        name: text(service.name),
                        kind: service.kind === "static" ? "static" : "server",
                        state: oneOf(SERVICE_STATES, service.state, "stopped"),
                    })),
                };
            },
        },
        users: {
            async invite({ instance, email, roles })
            {
                await call("POST", at(instance, "/users"), { email, roles: [...roles] });
            },
            async list(instance)
            {
                const reply = await call("GET", at(instance, "/users"));
                const users = isRecord(reply) && Array.isArray(reply.users) ? reply.users.filter(isRecord) : [];
                return users.map(toUser);
            },
            async setRoles({ instance, user, roles })
            {
                await call("PUT", at(instance, `/users/${encodeURIComponent(user)}/roles`), { roles: [...roles] });
            },
            async remove({ instance, user })
            {
                await call("DELETE", at(instance, `/users/${encodeURIComponent(user)}`));
            },
        },
        settings: {
            auth: {
                async get()
                {
                    return toAuthSettings(await call("GET", "settings/auth"));
                },
                async set({ mail, google })
                {
                    const body: { [key: string]: Json } = {};
                    if (mail !== undefined)
                    {
                        body.mail = mail === null
                            ? null
                            : { provider: mail.provider, api_key: mail.apiKey, from: mail.from, from_name: mail.fromName ?? null };
                    }
                    if (google !== undefined)
                    {
                        body.google = google === null ? null : { client_id: google.clientId, client_secret: google.clientSecret };
                    }
                    return toAuthSettings(await call("PUT", "settings/auth", body));
                },
            },
        },
        secrets: {
            async list(instance)
            {
                const reply = await call("GET", at(instance, "/secrets"));
                const secrets = isRecord(reply) && Array.isArray(reply.secrets) ? reply.secrets.filter(isRecord) : [];
                return secrets.map(toSecret);
            },
            async request(instance, name, { reason })
            {
                await call("POST", at(instance, `/secrets/${encodeURIComponent(name)}/request`), { reason });
            },
            async set(instance, name, { stage, value })
            {
                await call("PUT", at(instance, `/secrets/${encodeURIComponent(name)}`), { stage, value });
            },
            async remove(instance, name, { stage })
            {
                await call("DELETE", at(instance, `/secrets/${encodeURIComponent(name)}?stage=${encodeURIComponent(stage)}`));
            },
            async entry(instance, name, { stage })
            {
                const reply = await call("POST", at(instance, `/secrets/${encodeURIComponent(name)}/entries`), { stage });
                const record = isRecord(reply) ? reply : {};
                return { url: text(record.url), ticket: text(record.ticket), expiresAt: typeof record.expires_at === "number" ? record.expires_at : 0 };
            },
        },
        oauthClients: {
            async register({ instance, name, redirectUris })
            {
                const reply = await call("POST", at(instance, "/oauth-clients"), { name, redirect_uris: [...redirectUris] });
                return { clientId: text(isRecord(reply) ? reply.client_id : undefined) };
            },
            async grants(instance)
            {
                const reply = await call("GET", at(instance, "/oauth-grants"));
                const grants = isRecord(reply) && Array.isArray(reply.grants) ? reply.grants.filter(isRecord) : [];
                return grants.map((grant) => ({
                    id: text(grant.id),
                    clientId: text(grant.client_id),
                    clientName: text(grant.client_name),
                    clientKind: oneOf(CLIENT_KINDS, grant.client_kind, "registered"),
                    user: text(grant.user),
                    scope: text(grant.scope),
                    createdAt: number(grant.created_at),
                    lastTokenAt: orNull(grant.last_token_at),
                }));
            },
        },
    };
}
