# dashboard

팩토리 제작자의 대시보드입니다. 가입 · 로그인 · 팀원 · API 키를 다루고 Vercel 에 섭니다. 관리 서버(`orbitald`)는 여기서 띄우지 않고 운영자 키로 부릅니다.
결정은 `docs/decisions/2026-11-26-팩토리는-대시보드로-가입하고-운영자-키가-조직과-첫-키를-낸다.md` 입니다.

## 자리

| 자리 | 무엇 |
|---|---|
| `src/domain/team.ts` | 역할(주인 · 관리자 · 멤버)과 팀 바꾸기의 판정. 순수 함수만 둔다 |
| `src/server/dashboard.ts` | 할 일(팩토리 만들기 · 키 · 팀원). 테스트 이름의 정본은 `dashboard.test.ts` 이고 실제 orbitald 에 붙는다 |
| `src/server/store.ts` · `pg-store.ts` | 기록의 포트와 메모리 · Postgres 구현. `store.contract.test.ts` 가 함께 잰다 |
| `src/actions/` | 서버 액션. 매번 `currentAccount()` 로 계정을 다시 확인한다 |
| `supabase/` | 로컬 Supabase(API 54421 · DB 54422), `org` 스키마, 시드 계정(비밀번호 `orbital-local`) |

## 지키는 것

- ⚠ **로그인은 scaffold 와 같습니다.** 운영은 Google, 로컬과 e2e 는 시드 계정의 이메일 · 비밀번호입니다. 문은 `lib/localAccounts.ts` 하나가 정하고
  로그인 화면과 서버 액션이 함께 읽습니다. 배포 환경에 `ALLOW_LOCAL_ACCOUNTS` 를 넣지 않습니다.
- ⚠ **운영자 키 · 봉인의 열쇠 · 팩토리의 키는 서버에만 있습니다.** 화면에는 첫 키와 새 키의 비밀이 한 번씩만 갑니다. 대시보드가 쓰는 키는
  `DASHBOARD_SEAL_KEY` 로 봉인해 기록에 두고 화면에서 폐기하지 못합니다.
- ⚠ **대시보드는 전용 롤 `dashboard_app` 으로만 DB 에 붙습니다.** `bypassrls` 라 GRANT 가 유일한 경계이고, 표마다 RLS 와 `deny_all` 을 둡니다.
  스키마는 업무 영역으로 짓습니다(`org`). 롤의 LOGIN · 비밀번호는 마이그레이션에 두지 않습니다(로컬은 `supabase/seed.sql`).
- 속하지 않은 팩토리는 없는 것과 같습니다(`not_found`, 화면은 404).

## 명령

```
npx supabase start                         # apps/dashboard 에서. 로컬 Supabase
ORBITAL_PG=… npm run test:dashboard        # 루트에서. orbitald 를 짓고 대시보드의 테스트를 돈다(DASHBOARD_DATABASE_URL 을 주면 Postgres 계약까지)
                                           # orbitald 의 기록은 그 클러스터의 `orbital_control` 에 두고 끝나면 걷는다(이미 있으면 돌지 않는다)
ORBITAL_PG=… E2E_SUPABASE_ANON_KEY=… npm run e2e -w @harmony/orbital-dashboard   # 로컬 Supabase + orbitald + 프로덕션 빌드
```

e2e 는 도커의 Supabase 가 있어야 해서 CI 에서 돌지 않습니다. PR 전에 로컬에서 돌립니다.
