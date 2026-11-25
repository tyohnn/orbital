// 팩토리 서버를 플랫폼이 하듯이 부른다. 실제 `orbitald` 와 PostgreSQL 에 붙고, 모델은 부르지 않는다.
//
// - 플랫폼(하모니)처럼: OAuth 로 계정을 연결하고(SDK 의 발견 · 등록 · 인가), MCP client 로 도구를 부른다.
// - 에이전트처럼: 도구가 준 주소 · 인스턴스 · 토큰만 들고 `orbital` CLI 를 실제로 돌린다.
// - 팩토리와 레이어 사이에 기록하는 중계를 두어, 팩토리가 service key 로 무엇을 보냈는지 본다.
//
// `ORBITAL_PG` 가 없으면 레이어가 필요한 테스트는 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:factory` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";
import { crc32 } from "node:zlib";

import {
    Client,
    StreamableHTTPClientTransport,
    discoverAuthorizationServerMetadata,
    discoverOAuthProtectedResourceMetadata,
    exchangeAuthorization,
    registerClient,
    startAuthorization,
} from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";

import { createOrbital } from "@harmony/orbital/server";
import type { Orbital } from "@harmony/orbital/server";

import { CARD_META } from "../src/card.ts";
import { packageFiles, zip } from "../src/pack.ts";
import { CARD_URI, TOOLS } from "../src/tools.ts";

const here = resolve(import.meta.dirname, "..");
const root = resolve(here, "../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const execFileAsync = promisify(execFile);
const pg = process.env.ORBITAL_PG;
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

/** 팩토리의 service key. 어디에 새어도 찾을 수 있게 드문 글자로 짓는다 */
const SERVICE_KEY = "sk_test_factory_q7Zx91LmWv";
const REDIRECT = "http://127.0.0.1:9/callback";

let scratch = "";
let home = "";
let orbitald: ChildProcess | undefined;
let factory: ChildProcess | undefined;
let relay: HttpServer | undefined;
/** 레이어의 주소(중계). 팩토리와 에이전트가 이 주소로 붙는다 */
let layer = "";
let origin = "";
let orbital: Orbital;
/** 팩토리가 service key 로 레이어에 보낸 요청 */
const sent: { method: string; path: string; body: unknown }[] = [];
/** 플랫폼이 팩토리에게서 받은 답의 날것 */
const received: string[] = [];
/** 팩토리 프로세스의 표준 출력과 표준 오류 */
let logs = "";
/** 붙인 MCP client. 끝나면 닫는다 */
const clients: Client[] = [];

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

interface Workspace
{
    url: string;
    instance: string;
    token: string;
    expires_at: number;
}

/**
 * 에이전트의 sandbox 에는 작업을 연 답만 있다.
 * ⚠ 비동기로 부른다. CLI 는 이 프로세스 안의 중계로 붙으므로, 동기로 부르면 중계가 답하지 못해 서로 기다린다.
 */
async function agent(folder: string, workspace: Workspace, ...args: string[]): Promise<string>
{
    const { stdout } = await execFileAsync(bin("orbital"), args, {
        cwd: folder,
        encoding: "utf8",
        env: { PATH: process.env.PATH ?? "", ORBITAL_URL: workspace.url, ORBITAL_INSTANCE: workspace.instance, ORBITAL_TOKEN: workspace.token },
    });
    return stdout;
}

function wordAfter(text: string, marker: string): string
{
    return text.split(marker)[1]?.trim().split(/\s+/)[0] ?? "";
}

/** 에이전트가 고쳐 올리고 미리보기를 세운 뒤 승격을 요청한다. 요청한 release 를 돌려준다 */
async function shipChange(workspace: Workspace, folder: string, edit: (source: string) => string, message: string): Promise<string>
{
    const work = join(scratch, folder);
    try
    {
        readFileSync(join(work, "server.js"));
    }
    catch
    {
        await agent(scratch, workspace, "clone", folder);
    }
    writeFileSync(join(work, "server.js"), edit(readFileSync(join(work, "server.js"), "utf8")));
    git(work, "commit", "--quiet", "-am", message);
    await agent(work, workspace, "push");
    const release = wordAfter(await agent(work, workspace, "preview"), "release ");
    await agent(work, workspace, "request-promotion", release);
    return release;
}

async function startFactory(): Promise<void>
{
    const port = await freePort();
    origin = `http://127.0.0.1:${port}`;
    factory = spawn(process.execPath, [join(here, "src/main.ts")], {
        env: { PATH: process.env.PATH ?? "", ORBITAL_URL: layer, ORBITAL_SERVICE_KEY: SERVICE_KEY, FACTORY_PORT: String(port), FACTORY_HOME: home },
        stdio: ["ignore", "pipe", "pipe"],
    });
    factory.stdout?.on("data", (chunk: Buffer) => { logs += chunk.toString("utf8"); });
    factory.stderr?.on("data", (chunk: Buffer) => { logs += chunk.toString("utf8"); });
    for (let attempt = 0; ; attempt += 1)
    {
        const up = await fetch(`${origin}/health`).then((response) => response.ok, () => false);
        if (up)
        {
            return;
        }
        assert.ok(attempt < 400 && factory.exitCode === null, `팩토리 서버가 뜨지 않았습니다:\n${logs}`);
        await new Promise((done) => setTimeout(done, 50));
    }
}

async function stopFactory(): Promise<void>
{
    const stopping = factory;
    if (stopping === undefined || stopping.exitCode !== null)
    {
        return;
    }
    await new Promise<void>((done) =>
    {
        stopping.once("exit", () => done());
        stopping.kill();
    });
}

/** 플랫폼이 하듯이 계정을 연결해 접근 토큰을 받는다: 보호 자원 → 인가 서버 → 동적 등록 → 로그인 → 코드 교환 */
async function connect(account: string): Promise<string>
{
    const resource = await discoverOAuthProtectedResourceMetadata(`${origin}/mcp`);
    const issuer = resource.authorization_servers?.[0] ?? "";
    const metadata = await discoverAuthorizationServerMetadata(issuer);
    assert.ok(metadata !== undefined, "인가 서버 메타데이터가 있어야 합니다");
    const client = await registerClient(issuer, { metadata, clientMetadata: { client_name: "시험 플랫폼", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" } });
    const started = await startAuthorization(issuer, { metadata, clientInformation: client, redirectUrl: REDIRECT, resource: new URL(resource.resource) });
    const form = new URLSearchParams(started.authorizationUrl.searchParams);
    form.set("account", account);
    form.set("decision", "allow");
    const answered = await fetch(`${origin}/oauth/authorize`, { method: "POST", body: form, redirect: "manual" });
    const back = new URL(answered.headers.get("location") ?? "");
    const tokens = await exchangeAuthorization(issuer, {
        metadata,
        clientInformation: client,
        authorizationCode: back.searchParams.get("code") ?? "",
        // 콜백의 iss 를 인가 서버의 것과 견준다(RFC 9207). 플랫폼이 하듯이 넘긴다
        iss: back.searchParams.get("iss") ?? "",
        codeVerifier: started.codeVerifier,
        redirectUri: REDIRECT,
    });
    return tokens.access_token;
}

/** 연결의 토큰으로 MCP client 를 붙인다. 받은 답의 날것을 모은다 */
async function platform(token: string): Promise<Client>
{
    const client = new Client({ name: "시험 플랫폼", version: "0.0.0" }, { versionNegotiation: { mode: "auto" } });
    const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), {
        requestInit: { headers: { authorization: `Bearer ${token}` } },
        fetch: async (url, init) =>
        {
            const response = await fetch(url, init);
            received.push(await response.clone().text());
            return response;
        },
    });
    await client.connect(transport);
    clients.push(client);
    return client;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<CallToolResult>
{
    return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

function structured<T>(result: CallToolResult): T
{
    assert.ok(result.structuredContent !== undefined, `structuredContent 가 있어야 합니다: ${JSON.stringify(result)}`);
    return result.structuredContent as T;
}

function cardOf(result: CallToolResult): string
{
    const html = result._meta?.[CARD_META];
    assert.equal(typeof html, "string", "답의 _meta 에 카드가 있어야 합니다");
    return html as string;
}

function textOf(result: CallToolResult): string
{
    return result.content.map((block) => (block.type === "text" ? block.text : "")).join("\n");
}

/** 카드의 승인 단추가 실은 release 와 승인의 표 */
function approveButton(html: string): { release: string; approval: string } | undefined
{
    const button = /<button[^>]*data-action="approve"[^>]*>/.exec(html)?.[0];
    if (button === undefined)
    {
        return undefined;
    }
    return {
        release: /data-release="([^"]*)"/.exec(button)?.[1] ?? "",
        approval: /data-approval="([^"]*)"/.exec(button)?.[1] ?? "",
    };
}

/**
 * 하모니가 모델에게 줄지 가르는 규칙(os-playground `packages/apps/src/widget.ts` 의 `modelVisible`). `ui.visibility` 에 `model` 이 있어야 하고,
 * 적지 않았으면 옛 이름 `openai/visibility` 가 `private` 가 아니어야 한다.
 */
function modelVisible(meta: unknown): boolean
{
    const record = typeof meta === "object" && meta !== null ? meta as Record<string, unknown> : {};
    const ui = typeof record.ui === "object" && record.ui !== null ? record.ui as Record<string, unknown> : {};
    if (Array.isArray(ui.visibility))
    {
        return ui.visibility.includes("model");
    }
    return record["openai/visibility"] !== "private";
}

function tokenBody(token: string): { instance: string; can: string[]; expires_at: number }
{
    const hex = token.split(".")[1] ?? "";
    return JSON.parse(Buffer.from(hex, "hex").toString("utf8")) as { instance: string; can: string[]; expires_at: number };
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "factory-todo-"));
    home = join(scratch, "factory");

    const listen = `127.0.0.1:${await freePort()}`;
    orbitald = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "layer"),
            ORBITAL_PG: pg,
            ORBITAL_SERVICE_KEYS: `factory=${SERVICE_KEY}`,
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url: `http://${listen}`, serviceKey: SERVICE_KEY });

    // 기록하는 중계. 팩토리와 에이전트의 요청을 그대로 레이어에 넘기고, service key 로 온 JSON 요청을 적는다
    const relayPort = await freePort();
    layer = `http://127.0.0.1:${relayPort}`;
    relay = createHttpServer((request, response) =>
    {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () =>
        {
            const body = Buffer.concat(chunks);
            const headers: Record<string, string> = {};
            for (const name of ["authorization", "content-type"])
            {
                const value = request.headers[name];
                if (typeof value === "string")
                {
                    headers[name] = value;
                }
            }
            if (headers.authorization === `Bearer ${SERVICE_KEY}`)
            {
                const json = headers["content-type"] === "application/json";
                sent.push({ method: request.method ?? "", path: request.url ?? "", body: json ? JSON.parse(body.toString("utf8")) as unknown : null });
            }
            const method = request.method ?? "GET";
            fetch(`http://${listen}${request.url ?? "/"}`, { method, headers, ...(method === "GET" || method === "HEAD" ? {} : { body }) })
                .then(async (answer) =>
                {
                    response.writeHead(answer.status, { "content-type": answer.headers.get("content-type") ?? "application/octet-stream" });
                    response.end(Buffer.from(await answer.arrayBuffer()));
                })
                .catch(() =>
                {
                    response.writeHead(502);
                    response.end();
                });
        });
    });
    await new Promise<void>((done) => relay?.listen(relayPort, "127.0.0.1", done));

    // 팩토리는 뜰 때 스캐폴드를 레이어에 올린다. 레이어가 듣기 시작할 때까지 팩토리가 되풀이한다
    await startFactory();
});

/** 팩토리가 적은 고객과 인스턴스의 짝. 아직 파일이 없으면 빈 짝이다 */
function pairs(): Record<string, string>
{
    try
    {
        return JSON.parse(readFileSync(join(home, "customers.json"), "utf8")) as Record<string, string>;
    }
    catch
    {
        return {};
    }
}

// 앞의 일이 깨져도 띄운 것은 모두 닫는다. 하나라도 남으면 테스트 프로세스가 끝나지 않는다
after(async () =>
{
    try
    {
        await Promise.all(clients.map((client) => client.close().catch(() => undefined)));
        await stopFactory();
        if (pg !== undefined)
        {
            for (const instance of Object.values(pairs()))
            {
                await orbital.instances.destroy(instance).catch(() => undefined);
            }
        }
    }
    finally
    {
        orbitald?.kill();
        relay?.close();
        relay?.closeAllConnections();
        if (scratch !== "")
        {
            rmSync(scratch, { recursive: true, force: true });
        }
    }
});

// 테스트는 차례로 돈다. 앞의 테스트가 세운 고객(alice · bob)을 뒤의 테스트가 이어 쓴다
const workspaces = new Map<string, Workspace>();

test("작업을 열면 고객의 인스턴스가 한 번만 서고, 다시 열면 같은 인스턴스의 새 토큰이 온다 — 고객마다 인스턴스는 하나다", { skip }, async () =>
{
    const created = (): number => sent.filter((each) => each.method === "POST" && each.path === "/v1/instances").length;
    const before = created();
    const alice = await platform(await connect("alice"));

    // 처음 여는 요청 둘이 겹쳐 와도 인스턴스는 하나만 선다
    const [first, second] = await Promise.all([call(alice, "workspace_open"), call(alice, "workspace_open")]);
    const one = structured<Workspace>(first);
    const two = structured<Workspace>(second);
    assert.equal(two.instance, one.instance);
    assert.equal(created() - before, 1);

    // 다시 열면 같은 인스턴스의 새 토큰이다. 레이어의 토큰은 (인스턴스, 능력, 만료 초)만 서명해 같은 초에 낸 둘은 글자가 같으므로,
    // 사람이 다시 여는 때처럼 다음 초로 넘어간 뒤에 연다
    await new Promise((done) => setTimeout(done, 1000 - (Date.now() % 1000) + 50));
    const sessions = (): number => sent.filter((each) => each.method === "POST" && each.path === `/v1/instances/${one.instance}/sessions`).length;
    const opened = sessions();
    const again = structured<Workspace>(await call(alice, "workspace_open"));
    assert.equal(again.instance, one.instance);
    assert.equal(sessions() - opened, 1);
    assert.notEqual(again.token, one.token);
    assert.notEqual(again.token, two.token);
    assert.ok(again.expires_at > Math.max(one.expires_at, two.expires_at), "새 토큰은 만료가 뒤로 밀려야 합니다");
    assert.equal(created() - before, 1);

    // 팩토리가 다시 떠도 같은 계정은 같은 인스턴스를 받는다. 짝은 팩토리의 파일에 있다
    await stopFactory();
    await startFactory();
    const reconnected = structured<Workspace>(await call(await platform(await connect("alice")), "workspace_open"));
    assert.equal(reconnected.instance, one.instance);
    assert.equal(created() - before, 1);
    assert.deepEqual(JSON.parse(readFileSync(join(home, "customers.json"), "utf8")), { alice: one.instance });
    workspaces.set("alice", reconnected);
});

test("작업을 연 답에는 주소 · 인스턴스 · 토큰 · 만료만 있다 — 답은 모델이 읽는다", { skip }, async () =>
{
    const result = await call(await platform(await connect("alice")), "workspace_open");
    const opened = structured<Workspace>(result);

    assert.deepEqual(Object.keys(opened).sort(), ["expires_at", "instance", "token", "url"]);
    assert.equal(opened.url, layer);
    assert.equal(opened.instance, workspaces.get("alice")?.instance);
    assert.equal(typeof opened.expires_at, "number");
    // _meta 에는 카드도 값도 없다. 있는 것은 프로토콜이 모든 답에 찍는 서버의 이름과 버전뿐이다(2026-07-28 의 `io.modelcontextprotocol/serverInfo`)
    const { "io.modelcontextprotocol/serverInfo": stamp, ...meta } = result._meta ?? {};
    assert.deepEqual(meta, {});
    assert.ok(stamp === undefined || JSON.stringify(stamp) === JSON.stringify({ name: "factory-todo", version: "0.1.0" }), JSON.stringify(stamp));
    assert.equal(result.isError, undefined);
    // 글로도 같은 것만 싣는다. 첫 블록은 쓰는 법의 안내이고 값은 토큰과 만료 시각뿐이다
    assert.equal(result.content.length, 2);
    assert.deepEqual(JSON.parse(result.content[1]?.type === "text" ? result.content[1].text : ""), opened);
    workspaces.set("alice", opened);
});

test("토큰에는 source · preview · rehearse 만 실리고 두 시간 뒤 만료된다 — 운영을 바꾸는 능력은 토큰에 없다", { skip }, async () =>
{
    const asked = Math.floor(Date.now() / 1000);
    const opened = structured<Workspace>(await call(await platform(await connect("alice")), "workspace_open"));
    const body = tokenBody(opened.token);

    assert.deepEqual([...body.can].sort(), ["preview", "rehearse", "source"]);
    assert.equal(body.instance, opened.instance);
    assert.equal(body.expires_at, opened.expires_at);
    assert.ok(opened.expires_at >= asked + 7200 && opened.expires_at <= asked + 7260, `만료는 두 시간 뒤여야 합니다: ${opened.expires_at - asked}초`);

    // 코드는 받는다
    await agent(scratch, opened, "clone", "alice-probe");
    // 운영을 바꾸는 길은 두드려도 열리지 않는다
    for (const tail of ["promotions", "production/identities"])
    {
        const tried = await fetch(`${opened.url}/v1/instances/${opened.instance}/${tail}`, {
            method: "POST",
            headers: { authorization: `Bearer ${opened.token}`, "content-type": "application/json" },
            body: JSON.stringify({ release: "r", change: "customer_request", approved_by: "customer", subject: "u1" }),
        });
        assert.equal(tried.status, 403, tail);
    }
    assert.equal(await orbital.production.get(opened.instance), null);
    workspaces.set("alice", opened);
});

test("다른 고객의 연결로 작업을 열면 다른 인스턴스가 온다. 남의 인스턴스의 토큰은 받지 못한다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const bob = await platform(await connect("bob"));

    // 남의 인스턴스를 인자로 적어도 제 인스턴스가 온다
    const opened = structured<Workspace>(await call(bob, "workspace_open", { instance: alice.instance }));
    assert.notEqual(opened.instance, alice.instance);
    assert.equal(tokenBody(opened.token).instance, opened.instance);

    // bob 의 토큰으로는 alice 의 코드를 받지 못한다
    await assert.rejects(agent(scratch, { ...opened, instance: alice.instance }, "clone", "bob-into-alice"));
    assert.deepEqual(JSON.parse(readFileSync(join(home, "customers.json"), "utf8")), { alice: alice.instance, bob: opened.instance });
    workspaces.set("bob", opened);
});

test("연결 없이 호출한 도구는 401 이다", { skip }, async () =>
{
    const created = sent.filter((each) => each.path === "/v1/instances").length;
    const request = (authorization?: string): Promise<Response> => fetch(`${origin}/mcp`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            ...(authorization === undefined ? {} : { authorization }),
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "workspace_open", arguments: {} } }),
    });

    for (const authorization of [undefined, "Bearer fat_made_up", "Basic YWxpY2U6"])
    {
        const answer = await request(authorization);
        assert.equal(answer.status, 401, String(authorization));
        // 플랫폼은 이 주소를 따라가 「연결하기」를 연다
        assert.match(answer.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource\/mcp"$/);
    }
    assert.equal(sent.filter((each) => each.path === "/v1/instances").length, created);
});

test("승인 카드는 기다리는 release 와 권한이 바뀌는 문장과 실행될 마이그레이션을 보인다 — 사람이 무엇을 승인하는지 읽는다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const release = await shipChange(alice, "alice", (source) => source.replace("version: 1", "version: 2"), "버전을 올린다");
    const client = await platform(await connect("alice"));

    const shown = await call(client, "promotion_show");
    const { pending } = structured<{ pending: { release: string; changes: string[]; migrations: string[] } }>(shown);
    const change = "`member` 역할이 `todo.card` 표를 자기 행을 읽을 수 있게 됩니다 그리고 자기 행을 고칠 수 있게 됩니다";
    assert.equal(pending.release, release);
    assert.deepEqual(pending.changes, [change]);
    assert.deepEqual(pending.migrations, ["001_card.sql"]);

    const html = cardOf(shown);
    assert.ok(html.includes(release), "카드에 release 가 있어야 합니다");
    assert.ok(html.includes(`<li>${change}</li>`), "카드에 권한의 문장이 있어야 합니다");
    assert.ok(html.includes("<li>001_card.sql</li>"), "카드에 마이그레이션이 있어야 합니다");
    assert.equal(approveButton(html)?.release, release);

    // 카드는 화면 프레임으로 선다. 화면은 답의 _meta 에서 카드를 꺼내 꽂는다
    const tool = (await client.listTools()).tools.find((each) => each.name === "promotion_show");
    assert.deepEqual((tool?._meta as { ui?: unknown } | undefined)?.ui, { resourceUri: CARD_URI });
    const frame = (await client.readResource({ uri: CARD_URI })).contents[0];
    assert.equal(frame?.mimeType, "text/html;profile=mcp-app");
    assert.ok(frame !== undefined && "text" in frame && frame.text.includes(`"${CARD_META}"`), "화면이 카드의 _meta 이름을 읽어야 합니다");
});

test("기다리는 요청이 없으면 카드에 승인 단추가 없다", { skip }, async () =>
{
    // bob 은 작업을 열었지만 승격을 요청하지 않았다. carol 은 작업을 연 적도 없다
    for (const account of ["bob", "carol"])
    {
        const shown = await call(await platform(await connect(account)), "promotion_show");
        assert.equal(structured<{ pending: unknown }>(shown).pending, null, account);
        const html = cardOf(shown);
        assert.equal(approveButton(html), undefined, account);
        assert.ok(!html.includes("승인하고 올리기"), account);
    }
    // 카드를 보는 것으로는 인스턴스가 서지 않는다
    assert.equal(JSON.parse(readFileSync(join(home, "customers.json"), "utf8")).carol, undefined);
});

test("승인하기는 화면 전용 도구라 모델에게 주는 도구 목록에 없다 — 에이전트가 제 요청을 스스로 승인하지 못한다", { skip }, async () =>
{
    const client = await platform(await connect("alice"));
    const tools = (await client.listTools()).tools;
    const approve = tools.find((tool) => tool.name === "promotion_approve");

    assert.deepEqual(tools.filter((tool) => modelVisible(tool._meta)).map((tool) => tool.name).sort(), ["production_status", "promotion_show", "workspace_open"]);
    // 화면은 부를 수 있다
    assert.deepEqual((approve?._meta as { ui?: { visibility?: unknown } } | undefined)?.ui?.visibility, ["app"]);

    // 모델이 읽는 것(글과 structuredContent)에는 승인의 표가 없다. 표는 화면에만 가는 _meta 에 있다
    const shown = await call(client, "promotion_show");
    const ticket = approveButton(cardOf(shown));
    assert.ok(ticket !== undefined && ticket.approval.length >= 20);
    assert.ok(!textOf(shown).includes(ticket.approval));
    assert.ok(!JSON.stringify(shown.structuredContent).includes(ticket.approval));

    // 표 없이, 또는 지어낸 표로 승인하기를 불러도 오르지 않는다
    const instance = workspaces.get("alice")?.instance ?? "";
    for (const approval of ["", "지어낸-표"])
    {
        const tried = await call(client, "promotion_approve", { release: ticket.release, approval });
        assert.equal(tried.isError, true);
    }
    assert.equal(await orbital.production.get(instance), null);
    assert.equal((await orbital.releases.pending(instance))?.release, ticket.release);
});

test("승인하기는 카드가 보인 release 만 올린다. 그 뒤에 코드가 더 올라왔으면 올리지 않고 카드를 다시 보라고 답한다 — 승인은 사람이 본 release 하나에 묶인다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const client = await platform(await connect("alice"));

    // 사람이 카드를 연다
    const seen = approveButton(cardOf(await call(client, "promotion_show")));
    assert.ok(seen !== undefined);

    // 그 사이에 에이전트가 코드를 더 올리고 새 release 의 승격을 요청한다
    const newer = await shipChange(alice, "alice", (source) => source.replace("version: 2", "version: 3"), "버전을 또 올린다");
    assert.notEqual(newer, seen.release);

    // 사람이 앞에 본 카드에서 승인을 누른다
    const approved = await call(client, "promotion_approve", seen);
    assert.equal(approved.isError, true);
    assert.match(textOf(approved), /카드를 다시/);
    assert.equal(approveButton(cardOf(approved)), undefined);
    assert.equal(await orbital.production.get(alice.instance), null);
    assert.equal((await orbital.releases.pending(alice.instance))?.release, newer);
    assert.equal(sent.filter((each) => each.path.endsWith("/promotions")).length, 0);
});

test("승인하면 고객의 승인으로 운영에 오르고 답에 운영의 주소가 온다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const client = await platform(await connect("alice"));
    const seen = approveButton(cardOf(await call(client, "promotion_show")));
    assert.ok(seen !== undefined);

    const approved = await call(client, "promotion_approve", seen);
    assert.equal(approved.isError, undefined, textOf(approved));
    const live = structured<{ release: string; url: string }>(approved);
    assert.equal(live.release, seen.release);
    assert.match(live.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.ok(cardOf(approved).includes(live.url));

    // 레이어에는 고객의 요청을 고객이 승인한 것으로 보냈다
    assert.deepEqual(sent.filter((each) => each.path.endsWith("/promotions")).map((each) => [each.path, each.body]), [
        [`/v1/instances/${alice.instance}/promotions`, { release: seen.release, change: "customer_request", approved_by: "customer" }],
    ]);
    // 운영의 앱이 돈다
    const health = (await (await fetch(`${live.url}/health`)).json()) as { version: number };
    assert.equal(health.version, 3);
    assert.deepEqual(structured(await call(client, "production_status")), live);
    assert.equal(await orbital.releases.pending(alice.instance), null);

    // 같은 표로 다시 누르면 오르지 않는다. 표는 한 번 쓴다
    assert.equal((await call(client, "promotion_approve", seen)).isError, true);
    assert.equal(sent.filter((each) => each.path.endsWith("/promotions")).length, 1);
});

test("레이어가 승격을 거절하면 그 까닭을 사람이 읽는 문장으로 돌려주고 운영은 그대로다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const client = await platform(await connect("alice"));
    const before = structured<{ release: string; url: string }>(await call(client, "production_status"));

    // 미리보기에서는 뜨고 운영에서만 뜨지 않는 서버를 올린다
    await shipChange(alice, "alice", (source) => `if (process.env.ORBITAL_STAGE === "production") process.exit(1);\n${source.replace("version: 3", "version: 4")}`, "운영에서 뜨지 않는다");
    const seen = approveButton(cardOf(await call(client, "promotion_show")));
    assert.ok(seen !== undefined);

    const refused = await call(client, "promotion_approve", seen);
    assert.equal(refused.isError, true);
    assert.match(textOf(refused), /^운영에 올리지 못했습니다\. 서비스 `web` 가 뜨지 않았습니다/);
    const html = cardOf(refused);
    assert.ok(html.includes("운영에 올리지 못했어요"));
    assert.ok(html.includes("뜨지 않았습니다"));
    assert.equal(approveButton(html), undefined);

    // 운영은 앞의 release 그대로 돈다. 레이어는 되돌리며 앞의 release 의 서버를 다시 띄우고, router 가 아직 없어 주소(포트)는 새로 받는다
    const after = structured<{ release: string; url: string }>(await call(client, "production_status"));
    assert.equal(after.release, before.release);
    assert.match(after.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal((await orbital.production.get(alice.instance))?.release, before.release);
    const health = (await (await fetch(`${after.url}/health`)).json()) as { version: number };
    assert.equal(health.version, 3);
});

test("service key 는 어떤 도구의 답 · 오류 · 로그에도 실리지 않는다", { skip }, async () =>
{
    const client = await platform(await connect("alice"));
    // 오류의 길을 더 지난다: 모르는 도구, 지어낸 표, 레이어에 없는 인스턴스로 가는 길
    await call(client, "no_such_tool");
    await call(client, "promotion_approve", { release: "r", approval: "x" });
    await fetch(`${origin}/oauth/register`, { method: "POST", body: "{깨진" });
    await fetch(`${origin}/oauth/token`, { method: "POST", body: "grant_type=refresh_token&refresh_token=x" });

    assert.ok(received.length > 20, "모은 답이 있어야 합니다");
    for (const body of received)
    {
        assert.ok(!body.includes(SERVICE_KEY), `답에 service key 가 있습니다: ${body.slice(0, 200)}`);
    }
    assert.ok(logs.length > 0, "팩토리의 로그가 있어야 합니다");
    assert.ok(!logs.includes(SERVICE_KEY), "팩토리의 로그에 service key 가 있습니다");
    // 고객과 인스턴스의 짝을 둔 파일에도 없다
    assert.ok(!readFileSync(join(home, "customers.json"), "utf8").includes(SERVICE_KEY));
});

/** 저장 방식(stored)의 ZIP 을 읽는다. 중앙 디렉터리를 따라 이름과 내용을 꺼내고 CRC 를 견준다 */
function unzip(bytes: Uint8Array): Map<string, string>
{
    const data = Buffer.from(bytes);
    const end = data.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    assert.ok(end >= 0, "ZIP 의 끝 레코드가 있어야 합니다");
    const count = data.readUInt16LE(end + 10);
    let at = data.readUInt32LE(end + 16);
    const files = new Map<string, string>();
    for (let index = 0; index < count; index += 1)
    {
        assert.equal(data.readUInt32LE(at), 0x02014b50);
        const method = data.readUInt16LE(at + 10);
        const sum = data.readUInt32LE(at + 16);
        const size = data.readUInt32LE(at + 20);
        const nameLength = data.readUInt16LE(at + 28);
        const extra = data.readUInt16LE(at + 30) + data.readUInt16LE(at + 32);
        const local = data.readUInt32LE(at + 42);
        const name = data.toString("utf8", at + 46, at + 46 + nameLength);
        assert.equal(method, 0);
        const start = local + 30 + data.readUInt16LE(local + 26) + data.readUInt16LE(local + 28);
        const body = data.subarray(start, start + size);
        assert.equal(crc32(body), sum, name);
        files.set(name, body.toString("utf8"));
        at += 46 + nameLength + extra;
    }
    return files;
}

function frontmatter(body: string): Record<string, string>
{
    const head = /^---\n([\s\S]*?)\n---/.exec(body)?.[1] ?? "";
    return Object.fromEntries(head.split("\n").map((line) =>
    {
        const at = line.indexOf(":");
        return [line.slice(0, at).trim(), line.slice(at + 1).trim().replace(/^(["'])(.*)\1$/, "$2")];
    }));
}

test("패키지는 MCP 서버 하나와 스킬 하나를 묶고 훅이 없다 — 하모니와 클로드가 같은 ZIP 을 받는다", () =>
{
    const files = unzip(zip(packageFiles()));
    assert.deepEqual([...files.keys()].sort(), [".claude-plugin/plugin.json", ".mcp.json", "plugin.json", "skills/orbital-dev/SKILL.md"]);
    assert.ok(![...files.keys()].some((path) => path.startsWith("hooks/")));

    // 하모니(os-playground 의 `readBundle`)가 보는 것: 앱 번호와 버전, 훅이 없음, MCP 서버 하나의 원격 주소
    const plugin = JSON.parse(files.get("plugin.json") ?? "") as { name: string; version: string; hooks?: unknown; extensions: { "com.openai": { hooks?: unknown } } };
    assert.match(plugin.name, /^[a-z][a-z0-9-]*$/);
    assert.match(plugin.version, /^\d+\.\d+\.\d+$/);
    assert.equal(plugin.hooks, undefined);
    assert.equal(plugin.extensions["com.openai"].hooks, undefined);
    const servers = Object.values((JSON.parse(files.get(".mcp.json") ?? "") as { mcpServers: Record<string, { type: string; url: string }> }).mcpServers);
    assert.equal(servers.length, 1);
    assert.ok(["http", "streamable-http"].includes(servers[0]?.type ?? ""));
    const url = new URL(servers[0]?.url ?? "");
    assert.ok(url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "127.0.0.1"));
    assert.equal(url.pathname, "/mcp");

    // 클로드가 보는 것: 같은 이름과 버전, 훅이 없음
    const claude = JSON.parse(files.get(".claude-plugin/plugin.json") ?? "") as { name: string; version: string; hooks?: unknown };
    assert.deepEqual([claude.name, claude.version, claude.hooks], [plugin.name, plugin.version, undefined]);

    // 스킬 하나. 이름은 폴더와 같고, 스킬이 부르라는 도구는 모델이 부를 수 있는 도구다
    const skill = files.get("skills/orbital-dev/SKILL.md") ?? "";
    const head = frontmatter(skill);
    assert.equal(head.name, "orbital-dev");
    assert.ok((head.description ?? "").length > 0);
    const named = TOOLS.filter((tool) => skill.includes(`\`${tool.name}\``)).map((tool) => tool.name).sort();
    assert.deepEqual(named, TOOLS.filter((tool) => modelVisible(tool._meta)).map((tool) => tool.name).sort());

    // 배포한 팩토리의 주소로 바꿔 지을 수 있다
    const deployed = unzip(zip(packageFiles("https://factory.example.com/mcp")));
    assert.match(deployed.get(".mcp.json") ?? "", /"url": "https:\/\/factory\.example\.com\/mcp"/);
});
