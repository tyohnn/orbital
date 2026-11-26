---
paths:
  - "crates/**"
---

# 용어

코드 파일을 열 때 읽힙니다. 화면 · 문서 · 주석 · 코드가 같은 말을 씁니다.

| 말 | 뜻 | 코드 |
|---|---|---|
| 팩토리 | Orbital 의 고객. 스캐폴드와 개발 플러그인을 만들어 자기 고객에게 파는 개발사. host 라고도 부른다 | `OrganizationId` |
| 인스턴스 | 팩토리의 고객 하나에게 선 것. 코드 저장소 + database + 도메인 | `InstanceId`, `Names` |
| 선언 파일 | 앱이 필요한 것의 이름을 적은 `orbital.toml`. 값은 적지 않는다 | `Manifest`, `ValidManifest` |
| 서비스 | 인스턴스 안에서 따로 빌드되고 서는 것. 서버이거나 정적이다 | `Service`, `ServiceKind` |
| 업무 역할 | 선언에 적은 역할(직원 · 팀장 · 급여 관리자). 권한 표의 주어 | `Database::roles` |
| 권한 표 | 표마다 업무 역할마다 할 수 있는 것을 적은 `db/access.toml` | `Access`, `Grant`, `Reach` |
| 묶음 | 업무 역할의 권한을 갖는 Postgres 역할. 로그인하지 못한다 | `Names::group` |
| 로그인 | 서비스가 업무 역할로 들어갈 때 쓰는 Postgres 역할. (서비스, 업무 역할)마다 하나 | `Names::login`, `Login` |
| 소유자 | 인스턴스의 모든 표의 주인. 로그인하지 못한다 | `Names::owner` |
| 마이그레이션 역할 | 레이어가 배포하는 동안만 들어가 스키마를 바꾸는 역할 | `Names::migrator` |
| 계획 | DB 에 세울 것을 적은 단계의 목록 | `Step`, `provision`, `grants` |
| 권한 검사 | 실제 DB 가 선언과 권한 표에 정확히 맞는지 보는 일. 승격의 관문 | `Snapshot`, `Finding`, `check::judge` |
| 토큰 | 작업 한 번 동안의 권한. 인스턴스 하나, 프리뷰까지. 팩토리의 서버 안에만 있고 에이전트에게 가지 않는다. `source_read` 는 받기만 한다 | `Token`, `Capability`, `scope::judge` |
| 작업(work) | 팩토리의 서버가 service key 로 열어 토큰을 감싼 것. 그 함수(프리뷰 · 로그 · 리허설 · 승격 요청)와 git 이어 주기(받은 git 요청을 작업의 토큰으로 넘기고 밖에서 온 `Authorization` 은 버린다)는 토큰으로만 부른다. 닫기(`close`)는 service key 로 하고, 닫은 작업의 토큰은 다음 요청부터(관리 서버가 다시 떠도) 거절된다 | SDK `works.open`, `Work`, `Work.git.relay` · `close`, `Revoked`, `session_of` |
| git 의 길 | 인스턴스마다 레이어가 받는 git 의 smart HTTP 셋(`info/refs` · `git-upload-pack` · `git-receive-pack`). 토큰으로만 열린다. 받는 ref 는 `main` 하나이고 앞으로만 가며, 묶음과 같은 판정과 같은 받는 자리(격리한 폴더에 받아 검사한 뒤 옮긴다)를 지난다 | `git::route`, `git::judge_push`, `SourceStore::ingest` |
| git 의 자격 | 팩토리가 에이전트에게 내는, 팩토리의 git 원격(`<팩토리>/git/<작업>`)에만 쓰는 자격. 그 작업 하나에서 두 시간 동안 통한다. 레이어는 모른다. 통하지 않으면 403 과 「`workspace_open` 을 다시」의 글 | 본보기의 `Works.forGit` |
| 리허설 | 운영 DB 의 사본에 마이그레이션을 미리 돌리는 일. 숫자만 돌아온다 | `orbital-pg` |
| 서명된 신원 | router 가 세션을 확인해 서명한 것(`v2`: 사람 · 세션 · 업무 역할). 요청마다 60초짜리로 앱에 싣는다. 행 단위 규칙은 이것만 읽는다 | `orbital-pg::identity`, `Claims` |
| 역할 제한 정책 | `[auth]` 를 선언한 인스턴스의 표마다 레이어가 두는 제한하는 정책. 연결의 업무 역할이 신원에 없으면 어떤 행도 내주지 않는다 | `Step::SetRolePolicy`, `orbital.granted()`, `ROLE_POLICY` |
| router | 프리뷰 · 운영마다 하나가 서서(포트 하나, 또는 레이어의 주소 하나를 하위 도메인으로 나눠) 요청을 서비스로 가르고, 세션을 확인해 신원을 싣는 것. `/_orbital/` 은 직접 답한다. 운영의 포트는 기록해 다시 잡는다 | `orbital-router`, `Router`, `auth::route`, `serve_slot` |
| 공개 경로 · 되돌림 | 서비스의 `public` 에 적은 경로의 머리. 로그인 없이 들이고 신원을 싣지 않는다. 되돌림은 정적 서비스의 `fallback`: 화면을 원하는 요청의 없는 파일에 그 파일을 내준다 | `Service::public` · `fallback`, `auth::is_public` · `fallback_file` |
| 일정 | 선언의 `[[schedule]]`. 운영에서 그 시각(UTC cron)에 레이어가 router 를 거쳐 `POST` 로 부르고 `x-orbital-schedule` 을 싣는다. `role` 을 적으면 사람 없이 그 역할만 실린 신원을 함께 싣는다. 그 경로는 밖에서 닿지 못한다. 놓친 때는 한 번, 실패는 다시 부르지 않는다 | `Cron`, `Schedule::key` · `role`, `auth::schedule_path`, `Layer::call_schedules`, `schedule_changes` |
| 기준 도메인 · 하위 도메인 | 레이어가 받는 도메인(`ORBITAL_BASE_DOMAIN`)과, 그 바로 아래 인스턴스마다의 한 조각(`<인스턴스>` 는 운영, `<인스턴스>-preview` 는 프리뷰). 그 주소가 인스턴스의 origin 이다 | `BaseDomain`, `HostTarget`, `judge_host`, `Hosts` |
| 재우기 · 깨우기 | 요청이 없는 서버 서비스의 프로세스를 내리는 일(`ORBITAL_SLEEP_AFTER`, 기본 5분)과, 첫 요청에 다시 띄우는 일. 깨우지 못하면 503 | `AppServer`, `Starter`, `WakeFailure` |
| 쓰고 남은 줄 | 만료됐거나 거둔 로그인 링크 · Google 의 표 · 인가 요청 · 코드 · 세션 · 토큰. 하루 뒤 새 줄을 적을 때 지운다 | `sweep`, `Leftover` |
| 사용자 | 인스턴스의 앱에 로그인하는 사람. 인스턴스의 database 안 `orbital_auth` 에 있다. 씨앗 사용자는 프리뷰에만 있다 | `SessionUser`, `User`, `SeedUser` |
| 초대 | 그 이메일이 들어올 수 있게 하고 처음 가질 업무 역할을 정한 것. 14일 동안 받아들여진다 | `AuthStore::invite`, `judge_invitation` |
| 로그인 링크 | 메일로 가는 한 번 쓰는 주소. 운영에서만 팩토리의 키로 나가고 프리뷰에서는 나가지 않는다. 15분, 요청한 브라우저에서만 열린다. 같은 이메일로는 1분에 하나 | `AuthStore::request_link` · `enter`, `judge_link` |
| 세션 | 로그인한 브라우저의 쿠키(`__Host-orbital-session`)가 가리키는 것. 거두거나 사용자를 빼면 다음 요청부터 없는 것이다 | `AuthStore::session`, `judge_session` |
| 팩토리의 설정 | 팩토리마다 한 벌인 로그인의 키(Resend 의 키 · 보내는 주소, Google 클라이언트). 비밀은 어떤 답에도 돌아오지 않는다. 없으면 그 로그인 방법은 운영에 오르지 못한다 | `Settings`, `PUT /v1/settings/auth`, `FactoryKey`, `missing_keys` |
| 봉인 | 비밀(팩토리의 키 · 금고 · 운영의 신원 열쇠 · 레이어가 만든 비밀 · 웹훅의 서명 비밀)을 기록에 두는 모양. 자리(조직 · 칸 등)를 함께 묶어 다른 줄에 옮기면 풀리지 않는다. 열쇠가 없는 개발용 레이어만 운영의 둘을 평문으로 적는다. 열쇠는 기록 밖(`ORBITAL_SEAL_KEY`)에 있고, 옛 열쇠(`ORBITAL_SEAL_KEY_PREVIOUS`)를 함께 주면 뜰 때 새 열쇠로 다시 봉인한다 | `seal`, `SealKey`, `reseal`, `Resealed` |
| 밖에서 넣는 비밀 | 선언의 `[secrets] external` 에 이름만 적은 바깥 서비스의 키. 사람이 넣고, 앱은 같은 이름의 환경 변수로 받는다. 빌드와 마이그레이션에는 가지 않는다 | `Secrets::external`, `missing_secrets`, `Blocker::SecretMissing` |
| 단계(stage) | 값이 들어가는 칸. 프리뷰(`preview`)와 운영(`production`) 둘이고 서로 넘어가지 않는다. 프리뷰의 값은 에이전트가 볼 수 있다고 본다 | `secrets::Stage` |
| 금고(vault) | 밖에서 넣는 비밀을 인스턴스와 단계마다 봉인해 둔 것(control database 의 `vault_value`). 조직 · 인스턴스 · 단계 · 이름을 함께 묶는다. 값을 읽는 API 는 없다 | `Vault`, `SecretValue`, `secret_binding` |
| 입력 표(entry) | 사람의 브라우저가 값을 레이어에 바로 보내는 한 번 쓰는 표. 주소(`POST /v1/secret-entries`)는 고정이고 표는 `Authorization: Bearer` 로만 간다. 인스턴스 · 이름 · 단계 하나에 묶이고 10분. sha256 으로만 둔다 | `Entry`, `judge_entry`, `EntryTicket` |
| 비밀의 요청 | 에이전트가 이름과 까닭만 적어 사람에게 입력을 부탁하는 것. 선언한 이름만 받는다 | `judge_request`, `Capability::SecretsRequest` |
| 개발용 메일함 | 메일을 보내지 않고 `outbox.jsonl` 에 쌓는 것. 명시해 켠 레이어(`ORBITAL_DEV_MAIL=outbox`)에서만 메일 키를 대신한다 | `Outbox`, `Options::dev_mailbox` |
| Google 로그인의 state · 표 | 레이어가 서명해 Google 에 넘기는 것(인스턴스 · `next` · 브라우저 표식과 `nonce` 의 해시, 10분)과, 콜백이 Google 계정을 확인한 뒤 인스턴스에 적는 한 번 쓰는 표(60초, 요청한 브라우저에서만) | `StateClaims`, `judge_state`, `judge_id_token`, `google_ticket`, `AuthStore::enter_google` |
| 인가 서버 · 자원 서버 | MCP 의 인가에서 Orbital Auth 가 토큰을 내는 쪽(발급자는 router 의 주소), router 가 MCP 주소에서 토큰을 확인하는 쪽. 동적 등록은 인스턴스마다 1분에 열 번 · 살아 있는 것 200개 | `orbital_core::oauth`, `orbital_router::oauth`, `registration_wait` |
| 승인(grant) · 인가 코드 · access · refresh 토큰 | 사용자가 클라이언트 하나에 준 허락. 코드(5분 한 번)와 토큰(1시간 · 30일, refresh 는 쓸 때마다 간다)은 승인에 딸리고 해시로만 두며, 승인을 거두면 함께 끊긴다 | `oauth_grant`, `oauth_code`, `oauth_token`, `AuthStore::decide` · `revoke_grant`, `judge_code` · `judge_token` |
| metadata 문서 | `https` 주소를 `client_id` 로 쓰는 클라이언트가 자신을 밝힌 문서. 받아 와서 그 답의 `max-age` 만큼(5분에서 하루 사이) 기억한다 | `DocumentFetcher`, `judge_document`, `document_lifetime` |
| 인증 역할 | `orbital_auth` 의 표만 읽고 쓰는 Postgres 역할. 앱의 스키마에는 닿지 못한다 | `Names::auth` |
| 인증의 주인 | `orbital_auth` 의 표와 `orbital.me` · `orbital.users` 뷰의 주인. 로그인하지 못하고 아무도 이 역할이 되지 못하며 앱의 표에 닿지 못한다 | `Names::auth_owner` |
| 스캐폴드 | 팩토리가 올린 앱의 원본. 버전(태그)이 있고 인스턴스가 그 하나에서 갈라진다 | `receive_scaffold`, `SourceStore::create` |
| 묶음 | 코드를 주고받는 git bundle. git 의 길과 같은 판정을 지나는 둘째 길이다. 팩토리의 서버와 테스트가 쓴다 | `SourceStore::bundle` · `receive` |
| release | commit 하나와 거기서 읽은 선언 · 권한 표 · 마이그레이션. 식별자가 commit 에 묶인다 | `ReleaseId`, `Assembled`, `release_id` |
| 프리뷰 | release 를 씨앗 데이터의 DB 와 함께 임시로 세운 것. 인스턴스마다 하나 | `Layer::preview` |
| 승격 | 사람이 승인한 release 를 운영에 올리는 일. 팩토리의 서버만 부른다 | `release::promote`, `Layer::promote` |
| 되돌릴 지점 | 승격 직전(또는 되살리기 직전)의 운영 DB 를 떠 둔 것. 하나만 둔다. 되살리기가 남긴 것이면 한 번 무를 수 있다 | `RestorePoint`, `Admin::mark` · `restore`, `Layer::undo_restore` |
| 조직 · service key · 운영자의 열쇠 | 조직은 팩토리 하나의 기록(`live` 와 시험용 `test`. 시험용은 인스턴스의 수에만 상한이 있다). service key 는 그 서버가 쓰는 열쇠(`sk_live_` · `sk_test_`)로 운영을 바꾸는 길은 이 열쇠에만 있다. 기록에는 sha256 만 두고 값은 낼 때 한 번 답에 싣는다. 새것을 내고 옛것을 거두며 살아 있는 마지막 하나는 거두지 못한다. 설정(`ORBITAL_SERVICE_KEYS`)의 열쇠도 함께 산다. 운영자의 열쇠(`ORBITAL_OPERATOR_KEY`)는 조직을 만들고 보고 닫고 열쇠를 내기만 한다 | `Layer::caller`, `organization::{judge_key, judge_revoke, judge_new_instance, judge_close}`, `/v1/keys`, `/v1/operator/organizations` |
| 실행기 | 빌드 명령(저장소에서 한 번 도는 `[build]` 뒤에 서비스마다)을 돌리고 서버를 띄우는 자리. 갈아 끼운다. 빌드에만 운영자가 정한 환경과 인스턴스마다의 홈(캐시의 자리)을 건넨다 | `Runner`, `LocalRunner`, `build_env`(`ORBITAL_BUILD_ENV`), `Job::home` |
| 업데이트 | 팩토리가 스캐폴드(위쪽)에 올린 commit 하나. 인스턴스의 release 가 이 commit 을 조상으로 담으면 「적용됐다」고 본다 | `Rollout::update`, `SourceStore::fetch_upstream` · `descends` |
| 밀기 · 당기기 | 업데이트를 인스턴스에 들이는 두 길. 법 · 보안 · 핵심 패키지는 팩토리가 밀고 팩토리가 승인한다. 기능 업데이트는 고객이 당기고 고객이 승인한다. 같은 기계다 | `Change`, `Change::approver` |
| rollout | 업데이트 하나가 인스턴스마다 어디까지 갔는지(`waiting` → `applied` → `previewed` → `passed` → `promoted`, 어디서든 `failed`)를 갖고 관문을 지키는 것. 한 곳이 실패하면 멈추고(`halted`) 팩토리가 다시 열어야 이어진다. 레이어는 에이전트를 돌리지 않는다 | `Rollout`, `Progress`, `Event`, `Rollout::step` |
| 물결 | rollout 의 인스턴스를 나눈 순서 있는 묶음. 앞 물결이 모두 오른 뒤에 뒤 물결이 오른다 | `Rollout::waves`, `Refusal::EarlierWave` |
| 합치기 | 레이어가 인스턴스의 `main` 에 업데이트를 기계적으로 합치는 일(`git merge` 의 판정). 충돌하면 인스턴스를 건드리지 않고 충돌한 파일의 이름만 알린다 | `SourceStore::merge`, `Merged`, `Layer::apply_update` |
| 적합성 테스트 | 인스턴스가 어떻게 고쳐졌든 통과해야 하는, 팩토리가 정한 테스트(`[conformance] run` · `files`). 위쪽의 선언과 폴더로 모든 프리뷰에서 돌고, 프리뷰의 주소만 받는다. 통과하지 못하면 오르지 못한다 | `Conformance`, `Conformed`, `Blocker::ConformanceFailed`, `Runner::check` |
| 기반 백업 · 보관 기간 | 운영 클러스터 전체를 뜬 것(`pg_basebackup`). control database(레이어의 기록)가 그 안에 들고, 코드 저장소의 묶음(`records.tar`: `sources` · `apps`, `RECORDS`)을 함께 둔다. 열쇠는 넣지 않는다. 다 뜬 때(`finished_at`) 뒤의 시점으로만 되살린다. 14일을 두고, 지난 것과 거기에만 딸린 WAL 을 지우되 마지막 기반 백업은 언제나 남긴다 | `BaseBackup`, `Store::base_backup`, `prune`, `KEEP_FOR` |
| WAL 보관 · 보관의 표시 | 다 찬 WAL 조각을 `archive_command` 로 `<ORBITAL_BACKUP_DIR>/wal` 에 복사해 두는 것과, commit 하나를 적고 WAL 을 넘겨 보관된 것을 본 뒤 적는 「이 시각까지는 되살릴 수 있다」 | `Archive`, `LocalStore::archive_command`, `Seal`, `Store::seal` |
| 기계 · 놓인 자리 · 넘겨 주기 | 관리 서버가 도는 자리(`ORBITAL_MACHINE`)와, 인스턴스를 세운 관리 서버의 기계. 그 인스턴스의 코드 저장소 · 빌드 · 프로세스에 닿는 일과 고객의 요청은 놓인 기계만 한다. 다른 기계는 아무것도 하지 않고, 놓인 기계의 주소(`ORBITAL_MACHINE_URL` · `ORBITAL_MACHINE_ROUTER_URL`)를 알면 요청을 그대로 넘기고(`x-orbital-forwarded-by` 를 붙이고, 그런 요청은 다시 넘기지 않는다) 모르면 421(`misplaced`), 닿지 못하면 502(`machine_unreachable`)로 답한다 | `Options::machine` · `machine_url`, `placement::{Errand, Reach, judge, route, Route}`, `Failure::Misplaced`, `forward::relay`, `Hosts::relaying` |
| 시점 복구 | 기반 백업과 보관한 WAL 로 정한 시각의 클러스터를 되살리는 일. **옆에 세운 클러스터에만** 한다 | `judge_restore`, `Store::recover` |
| 옆의 클러스터 | 시점 복구로 따로 세운 클러스터. 유닉스 소켓에서만 듣고 TCP 를 듣지 않으며 WAL 을 보관하지 않는다. 쓰고 나면 프로세스와 폴더를 걷는다 | `Cluster` |
| 인스턴스 되살리기 | 옆에 그 시점의 클러스터를 세우고 인스턴스 하나의 database 를 운영 클러스터의 옆 이름에 레이어의 계획으로 다시 세워 바꿔 넣는 일. 앱의 정의는 마이그레이션 역할로, 로그인의 행은 인증 역할로 넣고 관리 권한으로는 풀지 않는다. 직전의 DB 는 되돌릴 지점으로 남는다. service key 로만 | `Layer::restore_instance`, `backup::rebuild`, `load_database`, `Names::staged`, `Action::RestoreInstance` |
| 복구 훈련 | 표식 → 시점 → 표식 → 옆에 되살리기 → 확인 → 인스턴스 하나를 되살리기와 같은 절차로 임시 database 에 세워 보기 → 걷기 → 기록을 사람 손 없이 도는 한 번. 확인이 하나라도 어긋나면 실패다 | `drill`, `Check`, `judge_drill`, `DrillRecord`, `orbitald drill` |
| 지문 | database 하나의 스키마 해시와 표마다의 행 수. 이름과 숫자만 있고 행의 값은 없다 | `Fingerprint`, `fingerprint` |
| 잃을 수 있는 구간 | 훈련을 시작한 때 − 마지막으로 보관된 WAL 의 시각(초). 운영 클러스터를 잃으면 이만큼을 잃는다 | `DrillRecord::exposure_seconds` |
| 낡은 훈련 | 마지막으로 통과한 훈련이 여드레를 넘겼거나 한 번도 통과하지 않은 것. 켠 레이어(`ORBITAL_REQUIRE_DRILL=1`)는 그동안 새 인스턴스만 받지 않는다 | `Freshness`, `freshness`, `DRILL_FRESH_FOR` |
| control database | 레이어의 기록(인스턴스 · 일정 · rollout · 설정 · 금고 · 요청 · 입력 표 · 닫은 작업 · 훈련 · 기계 · 앱 · 조직 · service key · 이벤트 · 웹훅)을 두는, 운영 클러스터 안의 레이어 전용 database(`ORBITAL_CONTROL_DB`, 기본 `orbital_control`). 인스턴스의 역할은 붙지 못한다. 마이그레이션은 번호 붙은 SQL 을 차례로 한 번씩 | `Records`, `migrate`, `control::pending` |
| 이벤트 · 웹훅 | 레이어의 상태가 바뀐 것(`무엇.어찌됨`: 승격의 요청 · 승격 · 되돌려진 승격 · rollout 의 진행 · 비밀의 요청 · 인스턴스의 생김과 지워짐)을 그 일을 적는 트랜잭션에서 조직마다 차례대로 쌓은 것(30일)과, 조직이 건 주소 하나로 그것을 서명해(`orbital-signature`) 적어도 한 번 차례대로 보내는 것. 몸에는 이름과 숫자만. 바깥(공인)의 주소로만 보내고(보낼 때마다 풀어 판정한 그 주소에 붙는다) 리다이렉트는 따라가지 않는다. 사설 주소와 `http://` 는 명시해 켠 개발용 레이어(`ORBITAL_DEV_WEBHOOK=private`)만 | `event::Body`, `rollout_notes`, `after_failure`, `webhook::{judge_url, judge_resolved}`, `Layer::deliver_due`, `/v1/events` |
