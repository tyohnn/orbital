# 프레임워크로 만든 앱(Next.js · NestJS · Vite)

앱이 `npm` 의 의존성을 쓰거나 프레임워크로 빌드하면 먼저 읽습니다. 레이어는 그 commit 에서 직접 빌드하고, 빌드와 서버를
환경을 비운 자리에서 돌립니다. 이 기계에서 되던 것이 레이어에서 막히는 자리를 모았습니다.

## 빌드

- **`package-lock.json` 을 commit 하고 빌드 명령은 `npm ci` 로 시작합니다.** `node_modules` 와 빌드 결과(`.next/`, `dist/`)는 commit 하지 않습니다.
  레이어는 에이전트가 올린 빌드 결과를 받지 않습니다.
- **빌드에는 비밀도 DB 도 없습니다.** 빌드가 받는 환경은 `PATH` · `HOME` 과 레이어가 정한 레지스트리 · 프록시의 설정뿐입니다.
  빌드할 때 DB 를 읽는 화면(미리 그리는 페이지)을 만들지 않습니다. Next.js 면 `headers()` 를 읽거나 `export const dynamic = "force-dynamic"` 으로
  요청마다 그리게 합니다.
- **서비스는 `orbital.toml` 에 적은 차례로 같은 폴더에서 빌드됩니다.** 서비스가 둘인 저장소(npm workspaces)는 앞 서비스의 빌드 명령에서
  `npm ci` 를 한 번 하고, 뒤 서비스는 `npm run build -w <이름>` 만 합니다. 둘 다 `npm ci` 를 하면 의존성을 두 번 받습니다.
- 빌드가 실패하면 `preview` 의 답에 로그의 끝이 오고, `preview_logs` 로 더 봅니다. 레지스트리에 닿지 못한 실패(`ENOTFOUND`, `SELF_SIGNED_CERT_IN_CHAIN`)는
  에이전트가 고칠 수 없는 일입니다. 코드를 바꾸지 말고 사람에게 알립니다.

## 서버

- **포트는 `PORT`, 듣는 주소는 `127.0.0.1` 입니다.** 레이어가 `PORT` 와 `HOST` 를 건넵니다. `next start` 는 `HOST` 를 읽지 않고 모든 주소에서 들으니
  `"start": "next start -H 127.0.0.1"` 로 적습니다. NestJS 는 `app.listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1")` 입니다.
- **경로의 머리는 잘리지 않습니다.** `path = "/api"` 인 서비스는 `/api/payslips` 를 그대로 받습니다. NestJS 는 `app.setGlobalPrefix("api")` 를 둡니다.
- **요청이 없으면 서버가 내려가고 첫 요청에 다시 뜹니다.** 메모리에 둔 것은 사라집니다. 뜨는 데 30초를 넘기면 그 요청은 실패합니다.
- **DB 는 `pg` 로 붙습니다.** 비밀번호 없이 `host: PGHOST`, `port: PGPORT`, `database: PGDATABASE`, `user` 자리에 업무 역할의 이름을 적습니다.
  요청마다 `BEGIN` → `SELECT set_config('orbital.identity', $1, true)`(신원 머리말 `x-orbital-identity` 를 그대로) → 질의 → `COMMIT` 입니다.
  업무 역할이 여럿이면 `orbital.me` 의 `roles` 를 읽고 그 사람에게 있는 역할로 붙습니다.

## 정적 서비스(Vite 같은 것)

- `output` 의 파일을 레이어가 그대로 내줍니다. `/` 와 `/` 로 끝나는 경로만 `index.html` 이고, **없는 경로를 `index.html` 로 되돌리지 않습니다.**
  화면 안의 경로(`/payslips/2026-11` 같은 것)는 404 가 되니, 해시(`#/payslips`)나 질의로 화면을 가릅니다.
- `[auth] login_path` 에 정적 서비스의 경로를 쓸 때는 실제 파일이 있는 경로(`/` 같은 것)를 적습니다.

## 로그인과 프레임워크

- **`auth = "required"` 는 로그인 화면의 스크립트(`/_next/static/…`)까지 막습니다.** 로그인하지 않은 브라우저는 그 파일을 받지 못해 화면이 뜨지 않습니다.
  프레임워크로 그린 로그인 화면이 있으면 서비스의 `auth` 는 기본값(`optional`)으로 두고, 앱이 신원 머리말이 없을 때 `/login` 으로 보냅니다.
- 화면의 로그인 함수(`sendLoginLink` · `me` · `logout`)는 아직 npm 에 없어 본보기처럼 `orbital-app.js` 를 앱 안에 넣어 둔 것을 씁니다.

## 일정

- `[[schedule]]` 은 선언으로 검사만 됩니다. **지금의 레이어는 그 시각에 부르지 않습니다.** 정해진 때에 돌아야 하는 일이 있으면 사람에게 알립니다.
