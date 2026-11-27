# GCP 서울의 레이어 런북

GCP 서울에 계속 서 있는 개발용 레이어 하나를 세우고 다루는 절차입니다. 클라우드를 고른 까닭은
[결정](../decisions/2026-11-26-GCP-서울에-세운다.md)에, 잰 숫자는 [`findings.md`](../findings.md)에 있습니다.

⚠ **개발용입니다.** 실행기가 격리하지 않아(개발용 실행기) 앱의 코드가 레이어와 같은 사용자(root)로 돕니다. 실제 고객의 앱을 올리지 않습니다.

## 지금 서 있는 것 (2026-11-26)

| 무엇 | 값 |
|---|---|
| 프로젝트 · 존 | `orbital-515900` · `asia-northeast3-a` |
| VM | `orbital-layer`, `e2-standard-2`(2 vCPU · 8GB), Ubuntu 26.04 |
| 디스크 | 부트 pd-balanced 20GB, 데이터 `orbital-layer-data` pd-balanced 30GB(XFS, `/pg`, VM 을 지워도 남는다) |
| 고정 IP | `orbital-layer` = `34.47.102.176` |
| 방화벽 | `orb-web`: tcp 80 · 443, 태그 `orb-web` |
| 관리 서버 | `https://api.34-47-102-176.sslip.io` |
| 기준 도메인 | `34-47-102-176.sslip.io`(운영 `<인스턴스>.…`, 프리뷰 `<인스턴스>-preview.…`) |
| 바이너리를 옮기는 저장소 | Artifact Registry generic `orb-files`(서울) |

`sslip.io` 는 이름에 든 IP 로 풀리는 공용 DNS 라 도메인을 사지 않았습니다. 실제 고객을 받기 전에 우리 도메인과 와일드카드 인증서로 바꿉니다.

## 기계 안의 짜임

| 서비스 | 하는 일 | 설정 |
|---|---|---|
| `orbital-pg` | PostgreSQL 18(배포판). `127.0.0.1:54519` 에서만 듣고 `trust` 로 받는다. WAL 은 5분마다 넘긴다(`archive_timeout = 300`) | `/pg/data/postgresql.conf` · `pg_hba.conf` |
| `orbitald` | 관리 서버(`127.0.0.1:7400`)와 router(`127.0.0.1:7480`). 기반 백업과 복구 훈련을 돌린다 | `/etc/orbital/env`(0600), 봉인 열쇠 `/etc/orbital/seal.key` |
| `caddy` | TLS 를 끝내고 `api.<기준>` 은 7400, `*.<기준>` 은 7480 으로 넘긴다. 인스턴스의 인증서는 처음 요청 때 Let's Encrypt 에서 받는다(on-demand) | `/etc/caddy/Caddyfile` |

- 세 서비스 모두 `systemctl enable` 되어 있어 VM 을 다시 켜도 뜹니다(재부팅해 확인했습니다).
- 백업은 `/pg/backup`(같은 디스크)입니다. 기계나 디스크를 잃으면 백업도 잃습니다.
- `orbitald` 의 열쇠: 운영자 키 `ORBITAL_ADMIN_KEY` 는 `/etc/orbital/env` 와 대시보드의 Vercel 환경 변수(sensitive)에만 있습니다. 부트스트랩 service key 는 두지 않고, 팩토리는 대시보드나 운영자 키로 조직과 첫 키를 받습니다.

## 함정

- ⚠ **PostgreSQL 을 배포판의 `pg_createcluster` 로 세우면 복구 훈련이 실패합니다.** 그 모양은 `postgresql.conf` · `pg_hba.conf` 를 `/etc/postgresql` 에 두어,
  `pg_basebackup` 으로 뜬 사본에 설정이 없어 옆의 클러스터가 뜨지 않습니다(`did_not_start`). `initdb` 로 데이터 폴더 안에 설정을 두고 `orbital-pg` 유닛으로 띄웁니다.
- `pg_hba.conf` 에 `replication` 줄이 없으면 기반 백업이 실패합니다(`base_backup`).
- `archive_command` 를 배포판의 `conf.d` 에 따옴표를 겹쳐 적으면 클러스터가 뜨지 않습니다. 경로에 빈칸이 없으면 따옴표 없이 적습니다.
- 작업 컨테이너에서는 SSH(22번)가 막혀 있습니다. 명령은 VM 의 시작 스크립트가 띄운 대리인에게 메타데이터(`cmd`)로 보내고 결과를 guest attribute 로 받았습니다.
  사람은 GCP 콘솔의 브라우저 SSH 로 들어갈 수 있습니다.

## 바이너리 바꾸기

1. `main` 에서 `cargo build --release -p orbital-server -p orbital-cli` 로 짓습니다(glibc 2.39 에서 지은 것이 26.04 에서 돕니다).
2. `orbitald` · `orbital` 을 묶어 `orb-files` 에 새 버전으로 올립니다(`gcloud artifacts generic upload --package orb --version <n>`).
3. VM 에서 받아 `/usr/local/bin` 에 놓고 `systemctl restart orbitald` 합니다. 다시 뜨면 운영 중인 인스턴스의 router 가 자는 채로 다시 서고, 프리뷰는 되살리지 않습니다.
4. 기록을 control database 에 두는 판(2026-11-27 의 병합 뒤)으로 처음 바꾸면, 뜰 때 `ORBITAL_HOME` 의 옛 기록 파일(`registry.json` 의 조직과 키 포함)을
   같은 클러스터의 `orbital_control` 로 한 트랜잭션에 옮기고 `*.imported` 로 이름을 바꿉니다. 키는 sha256 그대로 옮겨 대시보드가 가진 키가 계속 통합니다.

## 지우기

`gcloud compute instances delete orbital-layer` 로 VM 을 지워도 데이터 디스크(`auto-delete=no`)와 고정 IP 는 남습니다. 다 걷으려면 디스크
`orbital-layer-data`, 주소 `orbital-layer`, 방화벽 `orb-web`, 저장소 `orb-files` 를 함께 지웁니다. 고정 IP 를 놓으면 기준 도메인이 바뀌어 모든 인스턴스의 주소가 바뀝니다.
