// 비밀 테스트가 쓰는 서버. 의존성이 없다.
//
// 받은 비밀의 값은 어디에도 내지 않고 sha256 만 내준다. 테스트는 그 해시로 어느 값이 닿았는지 본다.
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");

const digest = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

http.createServer((request, response) => {
    const send = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
    };
    if (request.url === "/health") return send(200, { ok: true, version: 1 });
    if (request.url === "/secret") {
        const value = process.env.BANK_API_KEY;
        return send(200, { present: value !== undefined, sha256: value === undefined ? null : digest(value) });
    }
    if (request.url === "/env") return send(200, { names: Object.keys(process.env).sort() });
    if (request.url === "/build-env") return send(200, JSON.parse(fs.readFileSync("build-env.json", "utf8")));
    return send(404, { error: "not found" });
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
