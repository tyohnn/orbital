// 기계 사이로 넘겨지는 고객의 요청을 재는 서버. 의존성이 없다. `todo` 의 선언 위에 이 파일만 바꿔 쓴다.
//
// 받은 요청의 모습(`x-orbital-` 머리말 · 쿠키 · Host)과 본문의 길이 · sha256 을 돌려준다. 본문은 돌려주지 않는다.
// `/stream` 은 첫 조각을 보내고 1.5초 뒤에 끝 조각을 보낸다. `/busy` 는 503 과 `Retry-After` 로 답한다.
// 폴더에 `down` 파일이 있으면 뜨지 않고 끝난다(깨우지 못하는 서비스).
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

if (fs.existsSync(path.join(__dirname, "down"))) {
    process.exit(1);
}

http.createServer((request, response) => {
    if (request.url === "/stream") {
        response.writeHead(200, { "content-type": "text/plain" });
        response.write("first\n");
        setTimeout(() => response.end("last\n"), 1500);
        return;
    }
    if (request.url === "/busy") {
        response.writeHead(503, { "content-type": "application/json", "retry-after": "7" });
        response.end(JSON.stringify({ busy: true }));
        return;
    }
    const hash = crypto.createHash("sha256");
    let length = 0;
    request.on("data", (chunk) => {
        length += chunk.length;
        hash.update(chunk);
    });
    request.on("end", () => {
        const layer = Object.fromEntries(Object.entries(request.headers).filter(([name]) => name.startsWith("x-orbital-")));
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
            method: request.method,
            path: request.url,
            host: request.headers.host ?? null,
            cookie: request.headers.cookie ?? null,
            layer,
            length,
            sha256: hash.digest("hex"),
        }));
    });
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
