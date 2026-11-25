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
| 서명된 신원 | router 가 로그인을 확인해 서명한 것. 행 단위 규칙은 이것만 읽는다 | `orbital-pg` |
| 스캐폴드 | 팩토리가 올린 앱의 원본. 버전(태그)이 있고 인스턴스가 그 하나에서 갈라진다 | `receive_scaffold`, `SourceStore::create` |
| 묶음 | 코드를 주고받는 git bundle. 에이전트가 받아 가서 고친 뒤 올린다 | `SourceStore::bundle` · `receive` |
| release | commit 하나와 거기서 읽은 선언 · 권한 표 · 마이그레이션. 식별자가 commit 에 묶인다 | `ReleaseId`, `Assembled`, `release_id` |
| 미리보기 | release 를 씨앗 데이터의 DB 와 함께 임시로 세운 것. 인스턴스마다 하나 | `Layer::preview` |
| 승격 | 사람이 승인한 release 를 운영에 올리는 일. 팩토리의 서버만 부른다 | `release::promote`, `Layer::promote` |
| 되돌릴 지점 | 승격 직전의 운영 DB 를 떠 둔 것 | `RestorePoint`, `Admin::mark` · `restore` |
| service key | 팩토리의 서버가 쓰는 열쇠. 운영을 바꾸는 길은 이 열쇠에만 있다 | `Layer::organization` |
| 실행기 | 빌드 명령을 돌리고 서버를 띄우는 자리. 갈아 끼운다 | `Runner`, `LocalRunner` |
