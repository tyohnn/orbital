# Orbital

개발 에이전트를 위한 배포 레이어입니다. 고객마다 갈라진 앱을 고객마다의 서버와 Postgres 로 세웁니다. 에이전트가 코드를 올리면
레이어가 빌드하고, DB 의 역할과 권한을 세우고, 비밀을 잇고, 사람의 승인을 받아 운영에 올립니다. 사람은 비밀번호도 환경 변수도 만지지 않습니다.

- 무엇을 만드는지: [Orbital 기획안](https://claude.ai/artifact/R9fEaCArNwVN1aWt9WPdzY)
- 지금 무엇이 되는지: [`docs/지도.md`](docs/지도.md)
- 일하는 방법: [`CLAUDE.md`](CLAUDE.md)

```
npm run pr:check                       # fmt · clippy · test · 층 검사 · 지시문 검사
scripts/pg-local.sh                    # 로컬 PostgreSQL 을 띄우고 ORBITAL_PG 를 찍는다
ORBITAL_PG=… cargo test --workspace    # 실제 DB 에 역할을 세우는 테스트까지 돈다
```
