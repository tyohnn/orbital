// 빌드가 받은 의존성을 실제로 읽고 뜨는 서버. 의존성이 없으면 뜨지 않는다
const http = require("node:http");
const isNumber = require("is-number");

http.createServer((request, response) =>
{
    response.writeHead(200, { "content-type": "application/json" });
    // 받은 환경의 이름만 돌려준다. 빌드와 서버가 받는 것이 다른지 테스트가 본다
    if (request.url === "/env") return response.end(JSON.stringify(Object.keys(process.env).sort()));
    response.end(JSON.stringify({ ok: isNumber(1) }));
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
