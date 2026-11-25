---
paths:
  - "crates/orbital-core/**"
---

# 도메인 crate

도메인 crate 의 파일을 열 때 읽힙니다. 같은 함수를 예시 테스트 · 속성 테스트 · 실제 DB 의 테스트가 함께 부르므로 순수해야 합니다.

- ❌ 파일(`std::fs`) · 네트워크(`std::net`) · 프로세스 · 환경 변수 · 시계(`SystemTime`, `Instant`) · 난수에 닿지 않습니다. 필요한 값은 인자로 받습니다.
- ❌ 런타임 의존을 더하지 않습니다. 허용 목록은 `scripts/check-layers.mjs` 의 `DOMAIN_ALLOWED` 이고 검사가 막습니다. 테스트 도구는 `dev-dependencies` 에 둡니다.
- **판정 함수의 입력과 출력은 serde 로 JSON 이 되는 타입입니다.** host 의 SDK 가 이 JSON 을 그대로 주고받습니다.
- **값이 될 수 없는 것은 만들지 못하게 합니다.** 검증은 생성자(`Ident::parse`, `Manifest::check`)에 두고, 계획과 판정은 이미 검증된 타입(`ValidManifest`, `Access`)만 받습니다.
- 거절에는 까닭(enum)을 돌려줍니다. `bool` 로 돌려주면 에이전트가 무엇을 고칠지 모릅니다. 문제는 하나만이 아니라 찾은 것을 모두 돌려줍니다.
- 계획은 SQL 글자열이 아니라 단계(`Step`)의 목록입니다. 테스트는 글자열이 아니라 단계를 봅니다.
