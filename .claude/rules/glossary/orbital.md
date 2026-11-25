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
| 토큰 | 에이전트의 작업 한 번 동안의 권한. 인스턴스 하나, 미리보기까지 | `Token`, `Capability`, `scope::judge` |
| 예행연습 | 운영 DB 의 사본에 마이그레이션을 미리 돌리는 일. 숫자만 돌아온다 | `orbital-pg` |
| 서명된 신원 | router 가 세션을 확인해 서명한 것(`v2`: 사람 · 세션 · 업무 역할). 요청마다 60초짜리로 앱에 싣는다. 행 단위 규칙은 이것만 읽는다 | `orbital-pg::identity`, `Claims` |
| 역할 제한 정책 | `[auth]` 를 선언한 인스턴스의 표마다 레이어가 두는 제한하는 정책. 연결의 업무 역할이 신원에 없으면 어떤 행도 내주지 않는다 | `Step::SetRolePolicy`, `orbital.granted()`, `ROLE_POLICY` |
| router | 미리보기 · 운영마다 하나가 서서(포트 하나, 또는 레이어의 주소 하나를 하위 도메인으로 나눠) 요청을 서비스로 가르고, 세션을 확인해 신원을 싣는 것. `/_orbital/` 은 직접 답한다 | `orbital-router`, `Router`, `auth::route` |
| 기준 도메인 · 하위 도메인 | 레이어가 받는 도메인(`ORBITAL_BASE_DOMAIN`)과, 그 바로 아래 인스턴스마다의 한 조각(`<인스턴스>` 는 운영, `<인스턴스>-preview` 는 미리보기). 그 주소가 인스턴스의 origin 이다 | `BaseDomain`, `HostTarget`, `judge_host`, `Hosts` |
| 재우기 · 깨우기 | 요청이 없는 서버 서비스의 프로세스를 내리는 일(`ORBITAL_SLEEP_AFTER`, 기본 5분)과, 첫 요청에 다시 띄우는 일. 깨우지 못하면 503 | `AppServer`, `Starter`, `WakeFailure` |
| 쓰고 남은 줄 | 만료됐거나 거둔 로그인 링크 · Google 의 표 · 인가 요청 · 코드 · 세션 · 토큰. 하루 뒤 새 줄을 적을 때 지운다 | `sweep`, `Leftover` |
| 사용자 | 인스턴스의 앱에 로그인하는 사람. 인스턴스의 database 안 `orbital_auth` 에 있다. 씨앗 사용자는 미리보기에만 있다 | `SessionUser`, `User`, `SeedUser` |
| 초대 | 그 이메일이 들어올 수 있게 하고 처음 가질 업무 역할을 정한 것. 14일 동안 받아들여진다 | `AuthStore::invite`, `judge_invitation` |
| 로그인 링크 | 메일로 가는 한 번 쓰는 주소. 운영에서만 팩토리의 키로 나가고 미리보기에서는 나가지 않는다. 15분, 요청한 브라우저에서만 열린다. 같은 이메일로는 1분에 하나 | `AuthStore::request_link` · `enter`, `judge_link` |
| 세션 | 로그인한 브라우저의 쿠키(`__Host-orbital-session`)가 가리키는 것. 거두거나 사용자를 빼면 다음 요청부터 없는 것이다 | `AuthStore::session`, `judge_session` |
| 팩토리의 설정 | 팩토리마다 한 벌인 로그인의 키(Resend 의 키 · 보내는 주소, Google 클라이언트). 비밀은 어떤 답에도 돌아오지 않는다. 없으면 그 로그인 방법은 운영에 오르지 못한다 | `Settings`, `PUT /v1/settings/auth`, `FactoryKey`, `missing_keys` |
| 봉인 | 팩토리의 비밀을 기록에 두는 모양. 조직과 칸을 함께 묶어 다른 줄에 옮기면 풀리지 않는다. 열쇠는 기록 밖(`ORBITAL_SEAL_KEY`)에 있다 | `seal`, `SealKey` |
| 개발용 메일함 | 메일을 보내지 않고 `outbox.jsonl` 에 쌓는 것. 명시해 켠 레이어(`ORBITAL_DEV_MAIL=outbox`)에서만 메일 키를 대신한다 | `Outbox`, `Options::dev_mailbox` |
| Google 로그인의 state · 표 | 레이어가 서명해 Google 에 넘기는 것(인스턴스 · `next` · 브라우저 표식과 `nonce` 의 해시, 10분)과, 콜백이 Google 계정을 확인한 뒤 인스턴스에 적는 한 번 쓰는 표(60초, 요청한 브라우저에서만) | `StateClaims`, `judge_state`, `judge_id_token`, `google_ticket`, `AuthStore::enter_google` |
| 인가 서버 · 자원 서버 | MCP 의 인가에서 Orbital Auth 가 토큰을 내는 쪽(발급자는 router 의 주소), router 가 MCP 주소에서 토큰을 확인하는 쪽 | `orbital_core::oauth`, `orbital_router::oauth` |
| 승인(grant) | 사용자가 클라이언트 하나에 준 허락. 코드와 토큰은 승인에 딸리고, 승인을 거두면 함께 끊긴다 | `oauth_grant`, `AuthStore::decide` · `revoke_grant` |
| 인가 코드 · access 토큰 · refresh 토큰 | 5분 한 번 · 1시간 · 30일(쓸 때마다 간다). 해시로만 둔다 | `oauth_code`, `oauth_token`, `judge_code` · `judge_token` |
| metadata 문서 | `https` 주소를 `client_id` 로 쓰는 클라이언트가 자신을 밝힌 문서. 받아 와서 그 답의 `max-age` 만큼(5분에서 하루 사이) 기억한다 | `DocumentFetcher`, `judge_document`, `document_lifetime` |
| 인증 역할 | `orbital_auth` 의 표만 읽고 쓰는 Postgres 역할. 앱의 스키마에는 닿지 못한다 | `Names::auth` |
| 인증의 주인 | `orbital_auth` 의 표와 `orbital.me` · `orbital.users` 뷰의 주인. 로그인하지 못하고 아무도 이 역할이 되지 못하며 앱의 표에 닿지 못한다 | `Names::auth_owner` |
| 동적 등록의 한도 | 인스턴스마다 1분에 열 번, 살아 있는 동적 클라이언트 200개. 한 번도 승인받지 못한 것은 하루 뒤에 지운다 | `registration_wait`, `AuthStore::register_dynamic` |
| 스캐폴드 | 팩토리가 올린 앱의 원본. 버전(태그)이 있고 인스턴스가 그 하나에서 갈라진다 | `receive_scaffold`, `SourceStore::create` |
| 묶음 | 코드를 주고받는 git bundle. 에이전트가 받아 가서 고친 뒤 올린다 | `SourceStore::bundle` · `receive` |
| release | commit 하나와 거기서 읽은 선언 · 권한 표 · 마이그레이션. 식별자가 commit 에 묶인다 | `ReleaseId`, `Assembled`, `release_id` |
| 미리보기 | release 를 씨앗 데이터의 DB 와 함께 임시로 세운 것. 인스턴스마다 하나 | `Layer::preview` |
| 승격 | 사람이 승인한 release 를 운영에 올리는 일. 팩토리의 서버만 부른다 | `release::promote`, `Layer::promote` |
| 되돌릴 지점 | 승격 직전의 운영 DB 를 떠 둔 것 | `RestorePoint`, `Admin::mark` · `restore` |
| service key | 팩토리의 서버가 쓰는 열쇠. 운영을 바꾸는 길은 이 열쇠에만 있다 | `Layer::organization` |
| 실행기 | 빌드 명령을 돌리고 서버를 띄우는 자리. 갈아 끼운다 | `Runner`, `LocalRunner` |
