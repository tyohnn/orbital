// 위쪽(스캐폴드 v1)의 적합성 테스트. 프리뷰의 주소 하나만 받는다. 받은 환경을 그대로 찍어 테스트가 무엇이 건네졌는지 본다.
import { readdirSync } from "node:fs";
const base = process.env.ORBITAL_PREVIEW_URL;
console.log("위쪽의 적합성 테스트 v1");
console.log(`env ${JSON.stringify(process.env)}`);
console.log(`files ${JSON.stringify(readdirSync(".").sort())}`);
const health = await fetch(`${base}/health`).then((reply) => reply.json());
if (health.ok !== true)
{
    console.error("health 가 ok 가 아닙니다");
    process.exit(1);
}
console.log("통과");
