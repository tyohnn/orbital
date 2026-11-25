// rollout 테스트가 쓰는 서버(스캐폴드 v1). 의존성이 없다.
const fs = require("node:fs");
const http = require("node:http");

const VERSION = 1;
const custom = JSON.parse(fs.readFileSync("custom.json", "utf8"));

http.createServer((request, response) => {
    const send = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
    };
    if (request.url === "/health") return send(200, { ok: custom.unhealthy !== true, version: VERSION });
    if (request.url === "/greeting") return send(200, { greeting: custom.greeting });
    return send(404, { error: "not found" });
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
