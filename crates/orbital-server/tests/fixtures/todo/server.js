// 한 바퀴 테스트가 쓰는 서버. 의존성이 없다.
//
// DB 에는 비밀번호 없이 붙는다. 사용자 자리에 업무 역할의 이름(member)을 적고, 주소는 레이어가 환경 변수로 건넨다.
// 실제 앱은 평범한 Postgres 드라이버를 쓰면 된다. 여기서는 설치 없이 뜨게 하려고 통신 규격의 필요한 부분만 손으로 적었다.
const http = require("node:http");
const net = require("node:net");

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
        // 로그인 화면. 화면만 그리고, 링크를 보내고 받는 일은 레이어(/_orbital/auth/…)가 한다
        if (request.url.split("?")[0] === "/login") {
            response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            return response.end("<!doctype html><title>로그인</title><form id=login><input name=email type=email><button>링크 받기</button></form>");
        }
        // 앱에 닿은 머리말을 그대로 돌려준다. router 가 무엇을 지우고 붙였는지 테스트가 본다
        if (request.url === "/echo") return send(200, { headers: request.headers });
        // MCP 의 자리. 인가는 레이어가 하고, 앱은 router 가 붙인 신원으로 자기 카드만 읽는다. 받은 머리말을 함께 돌려준다
        if (request.url.split("?")[0] === "/mcp") {
            const sets = await query("member", withIdentity(request, "SELECT to_jsonb(c) - 'owner' FROM todo.card c ORDER BY id"));
            return send(200, { cards: sets[1].map((row) => JSON.parse(row[0])), headers: request.headers });
        }
        // 동의 화면. 화면만 그리고, 요청을 읽고 승인하는 일은 레이어(/_orbital/oauth/…)가 한다
        if (request.url.split("?")[0] === "/oauth/consent") {
            response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            return response.end("<!doctype html><title>연결 승인</title><button>승인</button><button>거절</button>");
        }
        // 답의 머리와 본문의 앞을 보낸 뒤 끝을 `ms` 만큼 늦게 보낸다. 처리 중인 요청이 있는 동안 재우지 않는지 테스트가 본다
        if (request.url.split("?")[0] === "/slow") {
            const ms = Number(new URL(request.url, "http://app").searchParams.get("ms") ?? 1000);
            response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
            response.write("처음");
            return setTimeout(() => response.end("끝"), ms);
        }
        if (request.url === "/env") return send(200, { names: Object.keys(process.env).sort() });
        // 공개 경로의 자리. 앱에 닿은 머리말을 그대로 돌려준다
        if (request.url.startsWith("/assets/")) return send(200, { public: true, headers: request.headers });
        // 일정이 부르는 자리. 불린 때와 받은 머리말을 작업 폴더의 파일에 남긴다(재워도 남는다)
        if (request.url.startsWith("/jobs/")) {
            require("node:fs").appendFileSync("jobs.jsonl", `${JSON.stringify({ path: request.url, method: request.method, headers: request.headers })}\n`);
            if (request.url === "/jobs/fail") return send(500, { error: "실패하는 일" });
            if (request.url === "/jobs/slow") return setTimeout(() => send(200, { ran: true }), 3000);
            return send(200, { ran: true });
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
        if (request.url === "/as-admin") {
            // 선언에 없는 역할로 붙어 본다. proxy 가 거절해야 한다
            await query("payroll_admin", "SELECT 1");
            return send(200, { connected: true });
        }
        return send(404, { error: "not found" });
    } catch (error) {
        return send(500, { error: String(error.message) });
    }
}).listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
