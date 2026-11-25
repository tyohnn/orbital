// 위쪽(스캐폴드 v2)의 적합성 테스트. 포크가 어떻게 고쳐졌든 새 기능(`/feature`)이 서야 한다.
import { readdirSync } from "node:fs";
const base = process.env.ORBITAL_PREVIEW_URL;
console.log("위쪽의 적합성 테스트 v2");
console.log(`env ${JSON.stringify(process.env)}`);
console.log(`files ${JSON.stringify(readdirSync(".").sort())}`);
const health = await fetch(`${base}/health`).then((reply) => reply.json());
if (health.ok !== true || health.version !== 2)
{
    console.error(`health 가 v2 의 ok 가 아닙니다: ${JSON.stringify(health)}`);
    process.exit(1);
}
const feature = await fetch(`${base}/feature`);
if (feature.status !== 200)
{
    console.error(`/feature 가 ${feature.status} 로 답했습니다`);
    process.exit(1);
}
console.log("통과");
