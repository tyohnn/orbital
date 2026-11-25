// rollout 테스트가 쓰는 서버(스캐폴드 v2, 업데이트). 의존성이 없다.
const fs = require("node:fs");
const http = require("node:http");

const VERSION = 2;
const custom = JSON.parse(fs.readFileSync("custom.json", "utf8"));
// 운영에서만 뜨지 않게 고친 포크를 흉내 낸다. 승격 뒤 상태 확인에 실패해 되돌려진다
if (custom.crash_in_production && process.env.ORBITAL_STAGE === "production") process.exit(1);

http.createServer((request, response) => {
    const send = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
    };
    if (request.url === "/health") return send(200, { ok: custom.unhealthy !== true, version: VERSION });
    if (request.url === "/greeting") return send(200, { greeting: custom.greeting });
    if (request.url === "/feature")
    {
        // 답하지 않는다. 적합성 테스트가 제한 시간을 넘긴다
        if (custom.slow_feature) return undefined;
        if (custom.break_feature) return send(500, { error: "broken" });
        return send(200, { feature: true });
    }
    return send(404, { error: "not found" });
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
