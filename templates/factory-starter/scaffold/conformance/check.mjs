// 적합성 테스트. 레이어가 모든 프리뷰에서 돌리고, 통과하지 못하면 그 release 는 승격을 요청하지 못한다.
// 받는 것은 프리뷰의 주소(ORBITAL_PREVIEW_URL) 하나다. 환경은 비어 있고 DB 에는 닿지 않는다.
// ✏️ 고객의 사본이 어떻게 고쳐져도 지켜야 하는 것(당신의 앱의 약속)을 여기에 적는다.
const base = process.env.ORBITAL_PREVIEW_URL;

const health = await fetch(`${base}/health`).then((reply) => reply.json());
if (health.ok !== true)
{
    console.error("/health 가 { ok: true } 로 답해야 합니다");
    process.exit(1);
}

// 로그인하지 않은 사람은 메모를 읽지 못한다
const notes = await fetch(`${base}/api/notes`, { redirect: "manual" });
if (notes.status === 200)
{
    console.error("로그인하지 않은 요청에 /api/notes 가 200 으로 답했습니다. 로그인한 사람에게만 열어 주세요");
    process.exit(1);
}
console.log("통과");
