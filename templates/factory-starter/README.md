# 팩토리의 시작 템플릿

고객마다 갈라진 앱을 에이전트가 고치고, 고객이 승인한 것만 운영에 올리는 팩토리 하나가 이 폴더에 다 들어 있습니다.
통째로 복사해 제 것으로 고칩니다. 팩토리가 채울 것은 **제 앱(`scaffold/`)과 가격(계정의 자리)** 입니다.

```
scaffold/   고객마다 복사될 앱. 가장 작은 Next.js 앱(메모 하나)과 선언 · 권한 표 · 마이그레이션 · 씨앗 · 적합성 테스트
plugin/     에이전트 플랫폼(하모니 · 클로드)에 올리는 것. MCP 서버의 주소와 스킬 하나. 훅도 설치할 명령도 없다
server/     플러그인의 도구가 닿는 팩토리의 서버. service key 로 Orbital 을 부른다
```

에이전트는 Orbital 을 직접 부르지 않습니다. 플러그인의 도구(이 서버)와 평범한 `git` 만 씁니다. Orbital 의 주소와 열쇠는 이 서버의 환경 변수에만 있습니다.

## 빠른 시작

처음 10분에 고객 한 사람의 인스턴스가 프리뷰로 섭니다. 레이어(Orbital 의 관리 서버)는 이미 떠 있고, 그 운영자에게 **시험용 조직의 열쇠**(`sk_test_…`)를 받았다고 봅니다.
필요한 것은 Node 22.18 이상과 `git` 입니다.

```sh
# 1. Orbital 저장소에서 이 템플릿을 새 폴더로 복사하고 이름을 짓는다(소문자 · 숫자 · 하이픈)
node scripts/new-factory.mjs ../acme acme-notes

# 2. 서버의 의존성을 깐다. SDK 는 복사할 때 묶은 vendor/*.tgz 를 문다
cd ../acme/server
npm install

# 3. 서버를 띄운다. 스캐폴드를 레이어에 올리고 http://127.0.0.1:3840/mcp 에서 듣는다
export ORBITAL_URL=http://127.0.0.1:7700        # 레이어의 주소
export ORBITAL_SERVICE_KEY=sk_test_…            # 받은 열쇠
npm start

# 4. 다른 터미널에서: 플랫폼 없이 한 바퀴. 고객 「dev」로 연결해 인스턴스를 세우고, 고객의 사본을 ../try-app 에 받고, 프리뷰를 세운다
cd ../acme/server
npm run try
#   [try] 프리뷰 web: http://127.0.0.1:41235   ← 이 주소의 /health 를 열어 본다
```

`npm run try` 는 처음에 1분쯤 걸립니다(레이어가 스캐폴드를 `npm ci` 로 받고 빌드합니다). 고쳐 보려면 `../try-app` 에서 고쳐 commit 한 뒤 `npm run try` 를 다시 부릅니다.

**막히면.**

| 보이는 것 | 할 일 |
|---|---|
| `스캐폴드를 레이어에 올리지 못했습니다(unauthorized 401)` | `ORBITAL_SERVICE_KEY` 를 확인합니다 |
| `npm run try` 가 빌드에서 멈추고 `ENOTFOUND` · `SELF_SIGNED_CERT_IN_CHAIN` | 레이어가 레지스트리에 닿지 못합니다. 레이어의 운영자에게 `ORBITAL_BUILD_ENV`(프록시 · CA 의 이름)를 넣어 달라고 합니다 |
| `workspace_open` 이 인스턴스를 세우지 못함(상한) | 시험용 조직은 10개까지입니다. `npm run operator -- fleet` 로 보고 `npm run operator -- destroy <인스턴스>` 로 걷습니다 |
| 승격이 `메일 키` 로 막힘 | 스캐폴드는 이메일 링크로 로그인합니다. 팩토리의 메일 키를 넣거나(SDK `settings.auth.set`), 개발용 레이어면 운영자가 `ORBITAL_DEV_MAIL=outbox` 를 켭니다 |

## 플랫폼에 올리기

```sh
npm run pack -- ../acme.zip https://factory.example.com/mcp   # 플러그인 ZIP. 하모니와 클로드가 같은 것을 받는다
```

플랫폼은 바깥(https) 주소로 이 서버에 붙습니다. **이 서버의 연결(`server/src/connect.ts`)은 계정 이름을 믿는 개발용이라 바깥 주소로는 뜨지 않습니다.**
로그인을 붙인 뒤(아래 표) `FACTORY_PUBLIC_URL` 을 바깥 주소로 주고 띄웁니다. 서버는 127.0.0.1 에서만 들으니 앞에 TLS 를 끝내는 프록시를 둡니다.

## 무엇을 어디서 바꾸나

| 바꿀 것 | 자리 |
|---|---|
| 고객의 앱 | `scaffold/` 전체. ✏️ 표시가 바꿀 자리입니다. 선언 `orbital.toml`, 권한 표 `db/access.toml`, 마이그레이션 `db/migrations/`, 프리뷰의 가짜 데이터 `db/seed/` |
| 고객의 사본이 지켜야 하는 것 | `scaffold/conformance/check.mjs`. 모든 프리뷰에서 돌고, 통과하지 못하면 승격을 요청하지 못합니다 |
| 스캐폴드의 버전 | `server/src/brand.ts` 의 `VERSION`. 스캐폴드를 고쳐 다시 올릴 때 올립니다(새 고객이 그 버전에서 갈라집니다) |
| 팩토리의 이름 | `server/src/brand.ts` 의 `TITLE`, `plugin/plugin.json` 의 `displayName` · `description` · `defaultPrompt` |
| 도구의 설명(모델이 읽는다) | `server/src/tools.ts` 의 `TOOLS` |
| 에이전트에게 주는 차례 | `plugin/skills/app-dev/SKILL.md` 와 `references/` |
| **가격과 계정** | `server/src/accounts.ts` 의 `Accounts`. 인스턴스를 세우기 전에 결제를 확인하는 자리와, 고객과 인스턴스의 짝을 당신의 DB 에 두는 구현 |
| **로그인** | `server/src/connect.ts` 의 `POST /oauth/authorize`(고객의 계정 식별자를 정하는 자리). 붙이면 `main.ts` 의 바깥 주소 검사를 걷습니다 |
| 고객에게 알리기 | `server/src/notify.ts`. 승격 · 실패 · 비밀의 요청마다 자리가 있습니다 |

템플릿은 가입 · 로그인 · 결제를 넣지 않습니다. 자리만 있습니다. 고객과 인스턴스의 짝은 지금 메모리에만 있어서 서버가 다시 뜨면 같은 고객이 새 인스턴스를 받습니다.

## 환경 변수

| 이름 | 무엇 | 기본 |
|---|---|---|
| `ORBITAL_URL` | 레이어의 주소. 이 서버만 붙습니다 | 꼭 넣습니다 |
| `ORBITAL_SERVICE_KEY` | 팩토리의 service key. 로그 · 도구의 답 · 오류에 싣지 않습니다 | 꼭 넣습니다 |
| `ORBITAL_PUBLIC_URL` | 레이어의 바깥 주소. 비밀 입력 카드가 값을 이리로 바로 보냅니다 | `ORBITAL_URL` |
| `ORBITAL_WEBHOOK_SECRET` | 웹훅의 서명 비밀(`whsec_…`). 있으면 웹훅을 받고, 없으면 레이어에 물어봅니다 | 없음 |
| `FACTORY_PORT` | 듣는 포트 | `3840` |
| `FACTORY_PUBLIC_URL` | 플랫폼이 이 서버를 부르는 주소(OAuth 의 issuer, git 원격의 앞) | `http://127.0.0.1:<포트>` |
| `FACTORY_HOME` | 처리한 이벤트의 자리(`inbox.json`)를 두는 폴더 | `server/.factory` |
| `FACTORY_POLL_SECONDS` | 레이어에 이벤트를 물어보는 간격 | `5` |

## 이벤트: 웹훅과 물어보기

레이어는 승격의 요청 · 승격 · 실패 · 비밀의 요청 같은 일을 이벤트로 쌓습니다. 서버는 두 길 가운데 하나로 받아 **같은 처리기**(`notify.ts`)를 부릅니다.

- **로컬(기본).** 레이어가 이 서버에 닿지 못하므로 `FACTORY_POLL_SECONDS` 마다 `events.list` 로 물어봅니다.
- **운영.** 바깥 주소를 정한 뒤 웹훅을 겁니다. 서명 비밀은 이때 한 번만 찍힙니다. `ORBITAL_WEBHOOK_SECRET` 에 넣고 다시 띄웁니다.
  ```sh
  npm run operator -- webhook https://factory.example.com/webhooks/orbital
  ```

받는 길은 날것의 본문으로 서명을 확인하고(틀리면 401, 5분보다 오래된 서명도 401), 같은 `id` 는 한 번만 처리합니다. 처리기가 던지면 500 으로 답해 레이어가 다시 보냅니다.
웹훅을 받으면 받은 것 앞에 받지 못한 이벤트(웹훅을 걸기 전에 생긴 것, 레이어가 하루 동안 보내다 그만둔 것)를 `events.list` 로 먼저 이어 받아 차례대로 처리합니다.

## 열쇠 바꾸기

service key 는 새것을 먼저 내고, 서버를 옮긴 뒤, 옛것을 거둡니다. 둘은 그동안 함께 삽니다.

```sh
npm run operator -- key-create "2026-12 배포"   # 새 열쇠. 값은 이때 한 번만 찍힙니다. 비밀 저장소로 옮깁니다
# ORBITAL_SERVICE_KEY 를 새 값으로 바꿔 서버를 다시 배포합니다
npm run operator -- keys                        # 옛 열쇠의 「마지막으로 쓴 때」가 멈췄는지 봅니다
npm run operator -- key-revoke <옛 열쇠의 id>
```

열쇠가 새어 나갔으면 레이어의 운영자에게 알립니다(그 조직의 다른 열쇠를 한 번에 거두는 길은 운영자에게 있습니다).

## 운영자의 스크립트

운영의 로그 · 함대 · 이력은 팩토리의 운영자가 터미널에서 읽습니다. 에이전트의 도구로 돌려주지 않습니다(운영의 로그에는 고객의 데이터가 섞일 수 있습니다).

```sh
npm run operator -- fleet                   # 이 조직의 인스턴스
npm run operator -- history <인스턴스>       # release 의 이력. 누가 승인했는지(고객의 계정)가 남습니다
npm run operator -- services <인스턴스>      # 운영의 서비스가 깨어 있는지 · 자는지
npm run operator -- logs <인스턴스> [줄]     # 운영의 로그의 끝
```

## 테스트

```sh
npm run typecheck
npm test            # 웹훅 받기 · 계정의 자리 · 승인 카드 · 띄우기 · 플러그인. 레이어 없이 돕니다
```

## SDK 를 npm 에 올린 뒤

지금은 SDK 를 Orbital 저장소에서 묶은 tarball 로 뭅니다(`server/package.json` 의 `"@harmony/orbital": "file:../vendor/harmony-orbital-0.0.0.tgz"`).
npm 에 올린 뒤에는 이 한 줄을 `"@harmony/orbital": "^0.1.0"` 으로 바꾸고 `vendor/` 를 지웁니다.
