/**
 * 이메일 · 비밀번호(로컬 계정)로 들어오는 길이 열려 있는가: 이 규칙의 단 하나의 주인이다(scaffold 와 같다).
 * 로그인 화면이 칸을 보일지와 서버 액션이 받을지가 이 함수 하나를 읽어 둘이 갈라지지 않는다.
 *
 * 여는 조건은 둘 가운데 하나다.
 *   · 개발 환경이다(`next dev`)
 *   · `ALLOW_LOCAL_ACCOUNTS` 가 정확히 `"1"` 이다: 프로덕션 빌드를 상대로 e2e 를 돌리는 자리
 *
 * ⚠ 둘째 조건은 검사를 위한 자리이지 배포의 선택지가 아니다. 배포 환경에 이 이름이 들어가면 시드 계정으로 누구나 들어온다.
 * ⚠ `NEXT_PUBLIC_` 을 붙이지 않는다. 서버에서만 읽는다.
 */
export const localAccountsAllowed = (): boolean =>
    process.env.NODE_ENV !== "production" || process.env["ALLOW_LOCAL_ACCOUNTS"] === "1";
