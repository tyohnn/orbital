// control database 의 테스트가 쓰는 서버. 의존성이 없다.
//
// 받은 비밀의 값은 어디에도 내지 않고 sha256 만 내준다. 테스트는 그 해시로 어느 값이 닿았는지 본다. 일정의 부름에는 200 으로 답한다.
const crypto = require("node:crypto");
const http = require("node:http");

const digest = (text) => (text === undefined ? null : crypto.createHash("sha256").update(text, "utf8").digest("hex"));

http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
        ok: true,
        bank: digest(process.env.BANK_API_KEY),
        session_key: digest(process.env.SESSION_KEY),
    }));
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
