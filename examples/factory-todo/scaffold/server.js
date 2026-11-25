// 팩토리 「할 일 카드」의 스캐폴드 v1. 고객마다 이것에서 갈라진 인스턴스가 서고, 에이전트가 고객의 요청대로 고친다. 의존성이 없다.
//
// DB 에는 비밀번호 없이 붙는다. 사용자 자리에 업무 역할의 이름(member)을 적고, 주소는 레이어가 환경 변수로 건넨다.
// 실제 앱은 평범한 Postgres 드라이버를 쓰면 된다. 여기서는 설치 없이 뜨게 하려고 통신 규격의 필요한 부분만 손으로 적었다.
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");

function message(type, body) {
    const head = Buffer.alloc(type ? 5 : 4);
    if (type) head.write(type, 0);
    head.writeInt32BE(body.length + 4, type ? 1 : 0);
    return Buffer.concat([head, body]);
}

function cstring(...parts) {
    return Buffer.concat(parts.map((part) => Buffer.from(`${part}\0`)));
}

// 질의 하나(여러 문장일 수 있다)를 보내고, 문장마다의 행을 돌려준다.
function query(role, sql) {
    return new Promise((resolve, reject) => {
        const socket = net.connect(Number(process.env.PGPORT), process.env.PGHOST);
        let buffer = Buffer.alloc(0);
        const sets = [];
        let failure = null;
        let sent = false;
        socket.on("error", reject);
        socket.on("connect", () => {
            const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring("user", role, "database", "app"), Buffer.from([0])]);
            socket.write(message(null, startup));
        });
        socket.on("data", (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length >= 5 && buffer.length >= buffer.readInt32BE(1) + 1) {
                const type = String.fromCharCode(buffer[0]);
                const body = buffer.subarray(5, buffer.readInt32BE(1) + 1);
                buffer = buffer.subarray(body.length + 5);
                if (type === "T") {
                    sets.push([]);
                } else if (type === "D") {
                    const row = [];
                    let at = 2;
                    for (let field = 0; field < body.readInt16BE(0); field += 1) {
                        const length = body.readInt32BE(at);
                        at += 4;
                        row.push(length < 0 ? null : body.toString("utf8", at, at + length));
                        at += Math.max(length, 0);
                    }
                    sets[sets.length - 1].push(row);
                } else if (type === "E") {
                    failure = body.toString("utf8").split("\0").find((field) => field.startsWith("C"))?.slice(1) ?? "error";
                } else if (type === "Z") {
                    if (!sent && !failure) {
                        sent = true;
                        socket.write(message("Q", cstring(sql)));
                    } else {
                        socket.end();
                        if (failure) reject(new Error(failure));
                        else resolve(sets);
                    }
                }
            }
        });
        socket.on("close", () => failure && reject(new Error(failure)));
    });
}

const literal = (text) => `'${String(text).replaceAll("'", "''")}'`;

// 신원은 router 가 확인해 서명한 것이다. 앱은 그대로 DB 에 넘기기만 한다.
function withIdentity(request, statement) {
    const identity = String(request.headers["x-orbital-identity"] ?? "");
    if (!/^[a-z0-9.]*$/.test(identity)) throw new Error("bad identity");
    return `BEGIN; SELECT set_config('orbital.identity', ${literal(identity)}, true); ${statement}; COMMIT`;
}

function body(request) {
    return new Promise((resolve) => {
        const chunks = [];
        request.on("data", (chunk) => chunks.push(chunk));
        request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
}

http.createServer(async (request, response) => {
    const send = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
    };
    try {
        if (request.url === "/health") return send(200, { ok: true, version: 1 });
        // 로그인 · 동의 화면. 화면만 그리고, 링크와 인가는 레이어(/_orbital/…)가 맡는다. 화면은 vendor/orbital-app.js(SDK)로 레이어를 부른다
        const files = {
            "/login": ["pages/login.html", "text/html; charset=utf-8"],
            "/oauth/consent": ["pages/consent.html", "text/html; charset=utf-8"],
            "/vendor/orbital-app.js": ["vendor/orbital-app.js", "text/javascript; charset=utf-8"],
        };
        const file = files[request.url.split("?")[0]];
        if (file) {
            response.writeHead(200, { "content-type": file[1] });
            return response.end(fs.readFileSync(path.join(__dirname, file[0])));
        }
        if (request.url === "/cards" && request.method === "GET") {
            const sets = await query("member", withIdentity(request, "SELECT to_jsonb(c) - 'owner' FROM todo.card c ORDER BY id"));
            return send(200, sets[1].map((row) => JSON.parse(row[0])));
        }
        if (request.url === "/cards" && request.method === "POST") {
            const title = await body(request);
            const sets = await query("member", withIdentity(request, `INSERT INTO todo.card (title) VALUES (${literal(title)}) RETURNING id`));
            return send(201, { id: Number(sets[1][0][0]) });
        }
        return send(404, { error: "not found" });
    } catch (error) {
        return send(500, { error: String(error.message) });
    }
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
