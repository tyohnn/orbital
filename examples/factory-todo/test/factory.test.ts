// 팩토리 서버를 플랫폼이 하듯이 부른다. 실제 `orbitald` 와 PostgreSQL 에 붙고, 모델은 부르지 않는다.
//
// - 플랫폼(하모니)처럼: OAuth 로 계정을 연결하고(SDK 의 발견 · 등록 · 인가), MCP client 로 도구를 부른다.
// - 에이전트처럼: 도구가 준 git 원격과 자격만 들고 실제 `git` 을 돌린다. 레이어의 주소도 토큰도 받지 않는다.
// - 팩토리와 레이어 사이에 기록하는 중계를 두어, 팩토리가 무엇을 보냈는지(service key 와 작업의 토큰) 본다.
//
// `ORBITAL_PG` 가 없으면 레이어가 필요한 테스트는 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:factory` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
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
import type { Orbital, Work } from "@harmony/orbital/server";

import { CARD_META, ENTRY_META } from "../src/card.ts";
import { packageFiles, zip } from "../src/pack.ts";
import { CARD_URI, TOOLS } from "../src/tools.ts";
import { AGENT_CAN, createWorks } from "../src/works.ts";

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
/** 레이어의 바깥 주소(중계를 거치지 않는다). 사람의 브라우저(카드)가 입력 표로 값을 보내는 곳이다 */
let direct = "";
/** 중계를 지난 모든 요청과 답의 본문 */
const through: string[] = [];
let origin = "";
let orbital: Orbital;
/** 팩토리가 service key 로 레이어에 보낸 요청 */
const sent: { method: string; path: string; body: unknown }[] = [];
/** 팩토리가 작업의 토큰으로 레이어에 보낸 요청과 그 토큰 */
const workCalls: { method: string; path: string; token: string }[] = [];
/** 플랫폼이 팩토리에게서 받은 답의 날것 */
const received: string[] = [];
/** 팩토리 프로세스의 표준 출력과 표준 오류 */
let logs = "";
/** 붙인 MCP client. 끝나면 닫는다 */
const clients: Client[] = [];
/** 도구를 부른 것과 그 답. 모델이 읽는 것이다 */
const answers: { name: string; result: CallToolResult }[] = [];

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

interface Workspace
{
    remote: string;
    credential: string;
    expires_at: number;
}

const GIT_ENV = { PATH: process.env.PATH ?? "", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };

/**
 * 실제 `git`. 에이전트의 sandbox 에는 작업을 연 답(원격과 자격)만 있다. `credential` 을 주면 명령 한 번의 머리말로 건넨다.
 * ⚠ 비동기로 부른다. git 은 팩토리를 거쳐 이 프로세스 안의 중계로 붙으므로, 동기로 부르면 중계가 답하지 못해 서로 기다린다.
 */
async function git(folder: string, credential: string | undefined, ...args: string[]): Promise<string>
{
    const auth = credential === undefined ? [] : ["-c", `http.extraHeader=Authorization: Bearer ${credential}`];
    try
    {
        const { stdout } = await execFileAsync(
            "git",
            ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...auth, ...args],
            { cwd: folder, encoding: "utf8", env: GIT_ENV },
        );
        return stdout.trim();
    }
    catch (error)
    {
        const stderr = typeof error === "object" && error !== null && "stderr" in error ? String(error.stderr) : "";
        throw new Error(`git ${args[0] ?? ""}: ${stderr}`);
    }
}

/** 에이전트가 작업을 열어 받은 원격으로 고쳐 올리고, 도구로 프리뷰를 세운 뒤 승격을 요청한다. 요청한 release 를 돌려준다 */
async function shipChange(account: string, folder: string, edit: (source: string) => string, message: string): Promise<string>
{
    const client = await platform(await connect(account));
    const workspace = structured<Workspace>(await call(client, "workspace_open"));
    const work = join(scratch, folder);
    try
    {
        readFileSync(join(work, "server.js"));
        // 앞의 작업의 자격은 끝났을 수 있다. 원격을 새 작업의 것으로 바꾼다
        await git(work, undefined, "remote", "set-url", "origin", workspace.remote);
    }
    catch
    {
        await git(scratch, workspace.credential, "clone", "--quiet", workspace.remote, folder);
    }
    writeFileSync(join(work, "server.js"), edit(readFileSync(join(work, "server.js"), "utf8")));
    await git(work, undefined, "commit", "--quiet", "-am", message);
    await git(work, workspace.credential, "push", "--quiet", "origin", "main");
    const shown = await call(client, "preview");
    assert.equal(shown.isError, undefined, textOf(shown));
    const { release } = structured<{ release: string }>(shown);
    const requested = await call(client, "promotion_request", { release });
    assert.equal(requested.isError, undefined, textOf(requested));
    return release;
}

/** 팩토리 서버를 띄운다. `port` 를 주면 그 포트로 다시 띄운다(에이전트가 들고 있는 원격의 주소가 그대로다) */
async function startFactory(port?: number): Promise<void>
{
    port ??= await freePort();
    origin = `http://127.0.0.1:${port}`;
    // 워크스페이스의 SDK 는 빌드하지 않은 소스(.ts)를 쓴다(`orbital-source` 조건)
    factory = spawn(process.execPath, ["--conditions=orbital-source", join(here, "src/main.ts")], {
        env: { PATH: process.env.PATH ?? "", ORBITAL_URL: layer, ORBITAL_PUBLIC_URL: direct, ORBITAL_SERVICE_KEY: SERVICE_KEY, FACTORY_PORT: String(port), FACTORY_HOME: home },
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
    const result = (await client.callTool({ name, arguments: args })) as CallToolResult;
    answers.push({ name, result });
    return result;
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

/** 모델이 부를 수 있는 도구. 승인하기와 입력 표를 내는 도구는 화면 전용이다 */
const MODEL_TOOLS = ["preview", "preview_logs", "preview_sign_in", "production_status", "promotion_request", "promotion_show", "rehearse", "secret_request", "workspace_open"];

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "factory-todo-"));
    home = join(scratch, "factory");

    const listen = `127.0.0.1:${await freePort()}`;
    direct = `http://${listen}`;
    orbitald = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "layer"),
            ORBITAL_PG: pg,
            ORBITAL_SERVICE_KEYS: `factory=${SERVICE_KEY}`,
            // 팩토리의 메일 키 없이 운영에 올린다. 개발용 메일함을 명시해 켠다
            ORBITAL_DEV_MAIL: "outbox",
            ORBITAL_LISTEN: listen,
            // 비밀을 봉인하는 열쇠. 테스트에만 쓰는 값이다
            ORBITAL_SEAL_KEY: "07".repeat(32),
            // 입력 표의 주소가 이 아래에 선다. 카드는 중계(팩토리와 에이전트가 붙는 자리)를 거치지 않고 레이어에 바로 닿는다
            ORBITAL_PUBLIC_URL: direct,
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
            through.push(body.toString("utf8"));
            const headers: Record<string, string> = {};
            for (const name of ["authorization", "content-type", "content-encoding", "accept"])
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
            if (headers.authorization?.startsWith("Bearer orb1.") === true)
            {
                workCalls.push({ method: request.method ?? "", path: request.url ?? "", token: headers.authorization.slice("Bearer ".length) });
            }
            const method = request.method ?? "GET";
            fetch(`http://${listen}${request.url ?? "/"}`, { method, headers, ...(method === "GET" || method === "HEAD" ? {} : { body }) })
                .then(async (answer) =>
                {
                    const bytes = Buffer.from(await answer.arrayBuffer());
                    through.push(bytes.toString("utf8"));
                    response.writeHead(answer.status, { "content-type": answer.headers.get("content-type") ?? "application/octet-stream" });
                    response.end(bytes);
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

/** 그 고객의 인스턴스. 팩토리의 파일에서 읽는다(도구의 답에는 레이어의 식별자가 없다) */
const instanceOf = (account: string): string => pairs()[account] ?? "";

test("작업을 열면 고객의 인스턴스가 한 번만 서고, 다시 열면 같은 인스턴스에 새 자격이 오고 앞 작업은 닫힌다 — 고객마다 인스턴스는 하나다", { skip }, async () =>
{
    const created = (): number => sent.filter((each) => each.method === "POST" && each.path === "/v1/instances").length;
    const before = created();
    const alice = await platform(await connect("alice"));

    // 처음 여는 요청 둘이 겹쳐 와도 인스턴스는 하나만 선다
    const [first, second] = await Promise.all([call(alice, "workspace_open"), call(alice, "workspace_open")]);
    const one = structured<Workspace>(first);
    const two = structured<Workspace>(second);
    assert.equal(created() - before, 1);
    const instance = instanceOf("alice");
    assert.match(instance, /^[a-z0-9]{8,12}$/);

    // 다시 열면 같은 인스턴스에 레이어의 작업이 새로 열리고, 새 원격과 새 자격이 온다
    const sessions = (): number => sent.filter((each) => each.method === "POST" && each.path === `/v1/instances/${instance}/sessions`).length;
    const opened = sessions();
    const closes = (): number => sent.filter((each) => each.method === "DELETE" && each.path.startsWith(`/v1/instances/${instance}/sessions/`)).length;
    const closed = closes();
    const again = structured<Workspace>(await call(alice, "workspace_open"));
    assert.equal(sessions() - opened, 1);
    // 앞 작업 둘은 레이어에서 닫히고, 그 원격과 자격은 더는 통하지 않는다
    assert.equal(closes() - closed, 2);
    for (const old of [one, two])
    {
        const refused = await fetch(`${old.remote}/info/refs?service=git-upload-pack`, { headers: { authorization: `Bearer ${old.credential}` } });
        assert.equal(refused.status, 403);
    }
    const fresh = await fetch(`${again.remote}/info/refs?service=git-upload-pack`, { headers: { authorization: `Bearer ${again.credential}` } });
    assert.equal(fresh.status, 200);
    assert.equal(new Set([one.credential, two.credential, again.credential]).size, 3);
    assert.equal(new Set([one.remote, two.remote, again.remote]).size, 3);
    assert.ok(again.expires_at >= Math.max(one.expires_at, two.expires_at));
    assert.equal(created() - before, 1);

    // 팩토리가 다시 떠도 같은 계정은 같은 인스턴스를 받는다. 짝은 팩토리의 파일에 있다
    await stopFactory();
    await startFactory();
    const reconnected = structured<Workspace>(await call(await platform(await connect("alice")), "workspace_open"));
    assert.equal(created() - before, 1);
    assert.deepEqual(JSON.parse(readFileSync(join(home, "customers.json"), "utf8")), { alice: instance });
    workspaces.set("alice", reconnected);
});

test("작업을 연 답에는 팩토리의 git 원격 · 그 원격의 자격 · 만료만 있다 — 답은 모델이 읽는다", { skip }, async () =>
{
    const result = await call(await platform(await connect("alice")), "workspace_open");
    const opened = structured<Workspace>(result);

    assert.deepEqual(Object.keys(opened).sort(), ["credential", "expires_at", "remote"]);
    assert.match(opened.remote, new RegExp(`^${origin}/git/[0-9a-f]{24}$`));
    assert.match(opened.credential, /^fgit_[A-Za-z0-9_-]{32}$/);
    assert.equal(typeof opened.expires_at, "number");
    // _meta 에는 카드도 값도 없다. 있는 것은 프로토콜이 모든 답에 찍는 서버의 이름과 버전뿐이다(2026-07-28 의 `io.modelcontextprotocol/serverInfo`)
    const { "io.modelcontextprotocol/serverInfo": stamp, ...meta } = result._meta ?? {};
    assert.deepEqual(meta, {});
    assert.ok(stamp === undefined || JSON.stringify(stamp) === JSON.stringify({ name: "factory-todo", version: "0.1.0" }), JSON.stringify(stamp));
    assert.equal(result.isError, undefined);
    // 글로도 같은 것만 싣는다. 첫 블록은 쓰는 법의 안내이고, 자격은 주소에 넣지 않는 법으로 건넨다
    assert.equal(result.content.length, 2);
    assert.deepEqual(JSON.parse(result.content[1]?.type === "text" ? result.content[1].text : ""), opened);
    const guide = result.content[0]?.type === "text" ? result.content[0].text : "";
    assert.match(guide, /http\.extraHeader="Authorization: Bearer <credential>"/);
    assert.ok(!guide.includes(opened.credential));
    // 레이어의 주소와 토큰은 없다
    for (const leak of [layer, direct, "orb1.", SERVICE_KEY])
    {
        assert.ok(!JSON.stringify(result).includes(leak), leak);
    }
    workspaces.set("alice", opened);
});

test("작업에는 source · preview · rehearse · secrets_request 만 실리고 두 시간 뒤 만료된다 — 운영을 바꾸는 능력은 작업에 없다", { skip }, async () =>
{
    const asked = Math.floor(Date.now() / 1000);
    const opened = structured<Workspace>(await call(await platform(await connect("alice")), "workspace_open"));
    const instance = instanceOf("alice");

    // 팩토리가 레이어에 연 작업의 범위
    const asking = sent.filter((each) => each.path === `/v1/instances/${instance}/sessions`).at(-1);
    assert.deepEqual(asking?.body, { can: [...AGENT_CAN], ttl_seconds: 7200 });
    assert.deepEqual([...AGENT_CAN].sort(), ["preview", "rehearse", "secrets_request", "source"]);
    assert.ok(opened.expires_at >= asked + 7200 && opened.expires_at <= asked + 7260, `만료는 두 시간 뒤여야 합니다: ${opened.expires_at - asked}초`);

    // 코드는 받는다. 그 뒤에서 팩토리가 작업의 토큰으로 레이어에 이어 준다
    await git(scratch, opened.credential, "clone", "--quiet", opened.remote, "alice-probe");
    const token = workCalls.filter((each) => each.path.startsWith(`/v1/instances/${instance}/git/`)).at(-1)?.token ?? "";
    assert.deepEqual(tokenBody(token).instance, instance);
    assert.equal(tokenBody(token).expires_at, opened.expires_at);
    // 그 토큰으로도 운영을 바꾸는 길과 사용자를 초대하는 길은 열리지 않는다. 신원을 받아 가는 길은 아예 없다
    for (const [tail, status] of [["promotions", 403], ["users", 404], ["production/identities", 404]] as const)
    {
        const tried = await fetch(`${direct}/v1/instances/${instance}/${tail}`, {
            method: "POST",
            headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
            body: JSON.stringify({ release: "r", change: "customer_request", approved_by: "customer", subject: "u1", email: "u1@example.test" }),
        });
        assert.equal(tried.status, status, tail);
    }
    assert.equal(await orbital.production.get(instance), null);
    workspaces.set("alice", opened);
});

test("다른 고객의 연결로 작업을 열면 다른 인스턴스가 온다. 남의 작업의 원격에는 닿지 못한다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const bob = await platform(await connect("bob"));

    // 남의 인스턴스를 인자로 적어도 제 인스턴스가 온다
    const opened = structured<Workspace>(await call(bob, "workspace_open", { instance: instanceOf("alice") }));
    assert.notEqual(instanceOf("bob"), instanceOf("alice"));
    assert.notEqual(opened.remote, alice.remote);

    // bob 의 자격으로는 alice 의 원격에서 받지 못한다
    await assert.rejects(git(scratch, opened.credential, "clone", "--quiet", alice.remote, "bob-into-alice"));
    assert.deepEqual(JSON.parse(readFileSync(join(home, "customers.json"), "utf8")), { alice: instanceOf("alice"), bob: instanceOf("bob") });
    workspaces.set("bob", opened);
});

test("git 의 자격은 그 고객의 그 인스턴스에서만, 두 시간 동안만, git 의 길에서만 통한다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    const bob = workspaces.get("bob");
    assert.ok(alice !== undefined && bob !== undefined);
    const refs = (remote: string): string => `${remote}/info/refs?service=git-upload-pack`;
    const basic = (password: string): string => `Basic ${Buffer.from(`anyone:${password}`).toString("base64")}`;

    // 제 원격에서는 통한다. 한 번 쓰는 머리말(Bearer)과 자격 도우미의 모양(Basic, 사용자 이름은 보지 않는다) 모두
    assert.match(await git(scratch, alice.credential, "ls-remote", alice.remote), /refs\/heads\/main/);
    for (const authorization of [`Bearer ${alice.credential}`, basic(alice.credential)])
    {
        const advertised: Response = await fetch(refs(alice.remote), { headers: { authorization } });
        assert.equal(advertised.status, 200);
        assert.equal(advertised.headers.get("content-type"), "application/x-git-upload-pack-advertisement");
    }
    // 자격이 없으면 401 과 Basic 의 요청이다. git 은 이것을 보고 자격 도우미를 부른다
    const bare = await fetch(refs(alice.remote));
    assert.equal(bare.status, 401);
    assert.match(bare.headers.get("www-authenticate") ?? "", /^Basic /);
    // 남의 원격 · 지어낸 원격 · 지어낸 자격으로는 통하지 않는다. 자격을 냈는데 통하지 않으면 403 과 git 이 보일 글이다(무엇을 할지만, 레이어는 말하지 않는다)
    for (const [remote, credential] of [
        [bob.remote, alice.credential],
        [alice.remote, bob.credential],
        [`${origin}/git/${"0".repeat(24)}`, alice.credential],
        [alice.remote, `${alice.credential}x`],
        [alice.remote, "fgit_made_up"],
    ] as const)
    {
        const refused = await fetch(refs(remote), { headers: { authorization: `Bearer ${credential}` } });
        assert.equal(refused.status, 403, `${remote} ${credential.slice(0, 8)}`);
        assert.match(await refused.text(), /workspace_open/);
    }
    // git 의 길에서만 통한다: 도구의 길(/mcp)과 인가 서버의 길은 열지 못한다
    const tools = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.credential}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    assert.equal(tools.status, 401);

    // 두 시간 동안만: 팩토리의 자격은 레이어의 작업이 끝나는 때에 함께 끝난다(시계를 갈아 끼워 잰다)
    let clock = 1_000;
    let closedWorks = 0;
    const work = { instance: "k3f9x2ab", expiresAt: clock + 7200, close: async () => { closedWorks += 1; } } as unknown as Work;
    const works = createWorks({ works: { open: async () => work } } as unknown as Orbital, () => clock);
    const { opened, credential } = await works.open("alice", "k3f9x2ab");
    assert.equal(works.forGit(opened.id, credential)?.instance, "k3f9x2ab");
    assert.equal(works.forGit("0".repeat(24), credential), undefined);
    assert.equal(works.forGit(opened.id, "fat_mcp_token"), undefined);
    clock += 7199;
    assert.equal(works.forGit(opened.id, credential)?.customer, "alice");
    clock += 1;
    assert.equal(works.forGit(opened.id, credential), undefined);
    assert.equal(works.current("alice"), undefined);
    // 같은 고객이 다시 열면 앞 작업(아직 살아 있는 것)을 닫고 그 자격을 끊는다. 다른 고객의 작업은 그대로다
    clock = 1_000;
    const first = await works.open("alice", "k3f9x2ab");
    const others = await works.open("bob", "k3f9x2ab");
    const before = closedWorks;
    const second = await works.open("alice", "k3f9x2ab");
    assert.equal(closedWorks - before, 1);
    assert.equal(works.forGit(first.opened.id, first.credential), undefined);
    assert.equal(works.forGit(second.opened.id, second.credential)?.customer, "alice");
    assert.equal(works.forGit(others.opened.id, others.credential)?.customer, "bob");
});

test("MCP 의 토큰으로는 git 에 닿지 못하고 git 의 자격으로는 도구를 부르지 못한다", { skip }, async () =>
{
    const alice = workspaces.get("alice");
    assert.ok(alice !== undefined);
    const token = await connect("alice");

    // MCP 의 토큰은 도구를 부른다
    const client = await platform(token);
    assert.ok((await client.listTools()).tools.length > 0);
    // 그 토큰을 git 의 자격 자리에 넣어도 git 의 길은 열리지 않는다
    await assert.rejects(git(scratch, token, "ls-remote", alice.remote));
    for (const authorization of [`Bearer ${token}`, `Basic ${Buffer.from(`alice:${token}`).toString("base64")}`])
    {
        assert.equal((await fetch(`${alice.remote}/info/refs?service=git-receive-pack`, { headers: { authorization } })).status, 403);
        assert.equal((await fetch(`${alice.remote}/git-receive-pack`, { method: "POST", headers: { authorization }, body: "0000" })).status, 403);
    }
    // git 의 자격으로는 도구를 부르지 못한다
    const called = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.credential}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "preview", arguments: {} } }),
    });
    assert.equal(called.status, 401);
    assert.match(called.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata=/);
});

test("에이전트가 팩토리의 도구와 git 만으로 고치기 → 프리뷰 → 승인 → 운영을 돈다", { skip }, async () =>
{
    const client = await platform(await connect("erin"));
    const opened = structured<Workspace>(await call(client, "workspace_open"));
    const work = join(scratch, "erin");

    // 받기 → 고치기 → 올리기: 평범한 git 으로 팩토리의 원격에
    await git(scratch, opened.credential, "clone", "--quiet", opened.remote, "erin");
    writeFileSync(join(work, "server.js"), readFileSync(join(work, "server.js"), "utf8").replace("version: 1", "version: 2"));
    await git(work, undefined, "commit", "--quiet", "-am", "버전을 올린다");
    await git(work, opened.credential, "push", "--quiet", "origin", "main");
    const head = await git(work, undefined, "rev-parse", "HEAD");

    // 프리뷰: 주소 · 어긋난 것 · 권한의 변화 · 막는 것
    const shown = await call(client, "preview");
    assert.equal(shown.isError, undefined, textOf(shown));
    const preview = structured<{ release: string; commit: string; services: { name: string; url: string }[]; findings: string[]; changes: string[]; blockers: string[]; missing_secrets: string[]; conformance: unknown }>(shown);
    assert.equal(preview.commit, head);
    assert.deepEqual([preview.findings, preview.blockers, preview.missing_secrets], [[], [], []]);
    assert.deepEqual(preview.changes, ["`member` 역할이 `todo.card` 표를 자기 행을 읽을 수 있게 됩니다 그리고 자기 행을 고칠 수 있게 됩니다"]);
    assert.match(textOf(shown), /promotion_request/);
    const address = preview.services[0]?.url ?? "";
    assert.equal(((await (await fetch(`${address}/health`)).json()) as { version: number }).version, 2);
    // 씨앗 사용자로 들어가 본다
    const signedIn = structured<{ cookie: string }>(await call(client, "preview_sign_in", { user: "u1" }));
    assert.equal(((await (await fetch(`${address}/cards`, { headers: { cookie: signedIn.cookie } })).json()) as unknown[]).length, 2);
    const unknownUser = await call(client, "preview_sign_in", { user: "u404" });
    assert.equal(unknownUser.isError, true);
    assert.match(textOf(unknownUser), /씨앗 사용자/);
    // 로그와 리허설
    const logs = structured<{ release: string; logs: { name: string }[] }>(await call(client, "preview_logs"));
    assert.deepEqual([logs.release, logs.logs.map((log) => log.name)], [preview.release, ["build-web", "preview-web"]]);
    assert.equal(structured<{ needed: boolean }>(await call(client, "rehearse", { release: preview.release })).needed, false);

    // 승격 요청 → 카드 → 사람의 승인 → 운영
    assert.equal((await call(client, "promotion_request", { release: preview.release })).isError, undefined);
    const seen = approveButton(cardOf(await call(client, "promotion_show")));
    assert.equal(seen?.release, preview.release);
    const approved = await call(client, "promotion_approve", seen ?? {});
    assert.equal(approved.isError, undefined, textOf(approved));
    const live = structured<{ release: string; url: string }>(await call(client, "production_status"));
    assert.equal(live.release, preview.release);
    assert.equal(((await (await fetch(`${live.url}/health`)).json()) as { version: number }).version, 2);
    // 승인은 사람의 카드(화면 전용 도구)가 했다. 레이어에는 고객의 승인으로 갔다
    assert.deepEqual(sent.filter((each) => each.path === `/v1/instances/${instanceOf("erin")}/promotions`).map((each) => each.body), [
        { release: preview.release, change: "customer_request", approved_by: "customer" },
    ]);
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
    const release = await shipChange("alice", "alice", (source) => source.replace("version: 1", "version: 2"), "버전을 올린다");
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

    assert.deepEqual(tools.filter((tool) => modelVisible(tool._meta)).map((tool) => tool.name).sort(), MODEL_TOOLS);
    // 화면은 부를 수 있다
    assert.deepEqual((approve?._meta as { ui?: { visibility?: unknown } } | undefined)?.ui?.visibility, ["app"]);

    // 모델이 읽는 것(글과 structuredContent)에는 승인의 표가 없다. 표는 화면에만 가는 _meta 에 있다
    const shown = await call(client, "promotion_show");
    const ticket = approveButton(cardOf(shown));
    assert.ok(ticket !== undefined && ticket.approval.length >= 20);
    assert.ok(!textOf(shown).includes(ticket.approval));
    assert.ok(!JSON.stringify(shown.structuredContent).includes(ticket.approval));

    // 표 없이, 또는 지어낸 표로 승인하기를 불러도 오르지 않는다
    const instance = instanceOf("alice");
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
    const alice = { instance: instanceOf("alice") };
    const client = await platform(await connect("alice"));

    // 사람이 카드를 연다
    const seen = approveButton(cardOf(await call(client, "promotion_show")));
    assert.ok(seen !== undefined);

    // 그 사이에 에이전트가 코드를 더 올리고 새 release 의 승격을 요청한다
    const newer = await shipChange("alice", "alice", (source) => source.replace("version: 2", "version: 3"), "버전을 또 올린다");
    assert.notEqual(newer, seen.release);

    // 사람이 앞에 본 카드에서 승인을 누른다
    const approved = await call(client, "promotion_approve", seen);
    assert.equal(approved.isError, true);
    assert.match(textOf(approved), /카드를 다시/);
    assert.equal(approveButton(cardOf(approved)), undefined);
    assert.equal(await orbital.production.get(alice.instance), null);
    assert.equal((await orbital.releases.pending(alice.instance))?.release, newer);
    assert.equal(sent.filter((each) => each.path === `/v1/instances/${alice.instance}/promotions`).length, 0);
});

test("승인하면 고객의 승인으로 운영에 오르고 답에 운영의 주소가 온다", { skip }, async () =>
{
    const alice = { instance: instanceOf("alice") };
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
    assert.deepEqual(sent.filter((each) => each.path === `/v1/instances/${alice.instance}/promotions`).map((each) => [each.path, each.body]), [
        [`/v1/instances/${alice.instance}/promotions`, { release: seen.release, change: "customer_request", approved_by: "customer" }],
    ]);
    // 운영의 앱이 돈다
    const health = (await (await fetch(`${live.url}/health`)).json()) as { version: number };
    assert.equal(health.version, 3);
    assert.deepEqual(structured(await call(client, "production_status")), live);
    assert.equal(await orbital.releases.pending(alice.instance), null);

    // 같은 표로 다시 누르면 오르지 않는다. 표는 한 번 쓴다
    assert.equal((await call(client, "promotion_approve", seen)).isError, true);
    assert.equal(sent.filter((each) => each.path === `/v1/instances/${alice.instance}/promotions`).length, 1);
});

test("레이어가 승격을 거절하면 그 까닭을 사람이 읽는 문장으로 돌려주고 운영은 그대로다", { skip }, async () =>
{
    const alice = { instance: instanceOf("alice") };
    const client = await platform(await connect("alice"));
    const before = structured<{ release: string; url: string }>(await call(client, "production_status"));

    // 프리뷰에서는 뜨고 운영에서만 뜨지 않는 서버를 올린다
    await shipChange("alice", "alice", (source) => `if (process.env.ORBITAL_STAGE === "production") process.exit(1);\n${source.replace("version: 3", "version: 4")}`, "운영에서 뜨지 않는다");
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

// ---- 비밀 ----

/** 어디에 새어도 찾을 수 있게 드문 글자로 지은 값 */
const BANK = "sk_live_bank_factory_T9wKq2Zm";
const BANK_PREVIEW = "sk_test_bank_factory_R3vBn8Xc";

/** dave 의 에이전트가 `[secrets] external` 에 은행의 키를 선언하고 프리뷰를 세운다. 한 번만 한다. dave 의 인스턴스를 돌려준다 */
let daveReady: Promise<{ instance: string }> | undefined;
function daveDeclares(): Promise<{ instance: string }>
{
    daveReady ??= (async () =>
    {
        const client = await platform(await connect("dave"));
        const opened = structured<Workspace>(await call(client, "workspace_open"));
        await git(scratch, opened.credential, "clone", "--quiet", opened.remote, "dave");
        const work = join(scratch, "dave");
        const manifest = readFileSync(join(work, "orbital.toml"), "utf8");
        writeFileSync(join(work, "orbital.toml"), manifest.replace("generated = [\"SESSION_KEY\"]", "generated = [\"SESSION_KEY\"]\nexternal = [\"BANK_API_KEY\"]"));
        await git(work, undefined, "commit", "--quiet", "-am", "은행의 키를 밖에서 넣는다고 선언한다");
        await git(work, opened.credential, "push", "--quiet", "origin", "main");
        const shown = await call(client, "preview");
        // 프리뷰의 값이 없어 그 환경 변수 없이 섰다. 사람에게 요청할 이름이 답에 온다
        assert.deepEqual(structured<{ missing_secrets: string[] }>(shown).missing_secrets, ["BANK_API_KEY"]);
        assert.match(textOf(shown), /secret_request/);
        return { instance: instanceOf("dave") };
    })();
    return daveReady;
}

/** 카드가 하듯이: 화면 전용 도구로 입력 표를 받고, 그 주소(레이어)로 값을 바로 보낸다 */
async function cardSends(client: Client, stage: "preview" | "production", value: string): Promise<{ url: string; status: number; opened: CallToolResult }>
{
    const opened = await call(client, "secret_entry_open", { name: "BANK_API_KEY", stage });
    const entry = opened._meta?.[ENTRY_META] as { url?: unknown; ticket?: unknown } | undefined;
    assert.equal(typeof entry?.url, "string", JSON.stringify(opened));
    assert.equal(typeof entry?.ticket, "string", JSON.stringify(opened));
    const url = entry?.url as string;
    const sent = await fetch(url, {
        method: "POST",
        headers: { origin: "https://card.example", "content-type": "application/json", authorization: `Bearer ${entry?.ticket as string}` },
        body: JSON.stringify({ value }),
    });
    return { url, status: sent.status, opened };
}

test("에이전트가 비밀을 요청하면 입력 카드가 돌아온다", { skip }, async () =>
{
    const workspace = await daveDeclares();
    const client = await platform(await connect("dave"));

    // 선언하지 않은 이름은 무엇을 고칠지와 함께 거절된다
    const undeclared = await call(client, "secret_request", { name: "MAP_KEY", reason: "지도를 그립니다" });
    assert.equal(undeclared.isError, true);
    assert.match(textOf(undeclared), /\[secrets\] external/);

    const shown = await call(client, "secret_request", { name: "BANK_API_KEY", reason: "송금 기능이 은행 API 를 부릅니다" });
    assert.equal(shown.isError, undefined, textOf(shown));
    assert.deepEqual(structured(shown), { name: "BANK_API_KEY", preview: false, production: false });
    assert.match(textOf(shown), /값을 묻거나/);
    const html = cardOf(shown);
    assert.ok(html.includes("<code>BANK_API_KEY</code>"));
    assert.ok(html.includes("송금 기능이 은행 API 를 부릅니다"));
    assert.ok(html.includes(`data-stage="production"`) && html.includes(`data-stage="preview"`), "단계마다 칸이 있어야 합니다");
    assert.ok(html.includes("프리뷰의 값은 에이전트가 볼 수 있으니 시험용 키를 넣으세요"));
    // 카드는 화면 프레임으로 서고, 입력 표는 아직 없다
    const tool = (await client.listTools()).tools.find((each) => each.name === "secret_request");
    assert.deepEqual((tool?._meta as { ui?: unknown } | undefined)?.ui, { resourceUri: CARD_URI });
    assert.equal(shown._meta?.[ENTRY_META], undefined);
    // 레이어에 요청이 적혔다
    const [secret] = await orbital.secrets.list(workspace.instance);
    assert.equal(secret?.requested?.reason, "송금 기능이 은행 API 를 부릅니다");
});

test("입력 표를 내는 도구는 모델에게 보이지 않는다", { skip }, async () =>
{
    await daveDeclares();
    const client = await platform(await connect("dave"));
    const tools = (await client.listTools()).tools;
    const open = tools.find((tool) => tool.name === "secret_entry_open");
    assert.ok(open !== undefined);
    assert.equal(modelVisible(open._meta), false);
    assert.deepEqual((open._meta as { ui?: { visibility?: unknown } } | undefined)?.ui?.visibility, ["app"]);
    assert.ok(tools.filter((tool) => modelVisible(tool._meta)).every((tool) => tool.name !== "secret_entry_open"));

    // 화면이 부르면 표는 화면에만 가는 _meta 에 온다. 모델이 읽는 글과 structuredContent 에는 없고, 주소에도 실리지 않는다
    const opened = await call(client, "secret_entry_open", { name: "BANK_API_KEY", stage: "preview" });
    const { url, ticket } = opened._meta?.[ENTRY_META] as { url: string; ticket: string };
    assert.equal(ticket.length, 64);
    assert.ok(url.endsWith("/v1/secret-entries"), url);
    assert.ok(!url.includes(ticket));
    assert.ok(!textOf(opened).includes(ticket));
    assert.ok(!JSON.stringify(opened.structuredContent).includes(ticket));
});

test("카드가 보낸 값은 팩토리 서버를 지나지 않고 레이어에 닿는다", { skip }, async () =>
{
    const workspace = await daveDeclares();
    const client = await platform(await connect("dave"));

    // 카드는 레이어의 바깥 주소에만 닿을 수 있다(CSP)
    const frame = (await client.readResource({ uri: CARD_URI })).contents[0];
    const csp = (frame?._meta as { ui?: { csp?: { connectDomains?: string[] } } } | undefined)?.ui?.csp;
    assert.deepEqual(csp?.connectDomains, [direct]);

    for (const [stage, value] of [["production", BANK], ["preview", BANK_PREVIEW]] as const)
    {
        const { url, status } = await cardSends(client, stage, value);
        assert.equal(status, 200);
        assert.equal(new URL(url).origin, direct);
        assert.notEqual(new URL(url).origin, origin);
        assert.notEqual(new URL(url).origin, new URL(layer).origin);
    }
    const [secret] = await orbital.secrets.list(workspace.instance);
    assert.deepEqual([secret?.preview.set, secret?.production.set], [true, true]);
    // 팩토리가 레이어에 보낸 것과, 팩토리와 레이어 사이를 지난 모든 것에 값이 없다
    const relayed = [...through, JSON.stringify(sent)].join("\n");
    for (const value of [BANK, BANK_PREVIEW])
    {
        assert.ok(!relayed.includes(value), `팩토리와 레이어 사이에 \`${value}\` 가 지났습니다`);
    }
    // 다시 요청한 카드는 두 칸이 찼다고 보인다
    const again = await call(client, "secret_request", { name: "BANK_API_KEY", reason: "송금 기능이 은행 API 를 부릅니다" });
    assert.deepEqual(structured(again), { name: "BANK_API_KEY", preview: true, production: true });
});

test("도구의 답과 팩토리의 로그에 값이 실리지 않는다", { skip }, async () =>
{
    await daveDeclares();
    const client = await platform(await connect("dave"));
    // 값을 바꾸고, 틀린 단계와 틀린 이름으로도 불러 본다
    const { status } = await cardSends(client, "production", `${BANK}-2`);
    assert.equal(status, 200);
    assert.equal((await call(client, "secret_entry_open", { name: "BANK_API_KEY", stage: "staging" })).isError, true);
    assert.equal((await call(client, "secret_entry_open", { name: "MAP_KEY", stage: "production" })).isError, true);
    await call(client, "secret_request", { name: "BANK_API_KEY", reason: "다시" });

    const everything = [...received, logs, readFileSync(join(home, "customers.json"), "utf8"), ...through].join("\n");
    for (const value of [BANK, BANK_PREVIEW])
    {
        assert.ok(!everything.includes(value), `\`${value}\` 가 새었습니다`);
    }
});

test("팩토리의 서버가 다시 뜬 뒤에도 에이전트가 workspace_open 을 다시 불러 받던 작업 폴더로 이어서 올린다", { skip }, async () =>
{
    const client = await platform(await connect("frank"));
    const opened = structured<Workspace>(await call(client, "workspace_open"));
    await git(scratch, opened.credential, "clone", "--quiet", opened.remote, "frank");
    const work = join(scratch, "frank");
    writeFileSync(join(work, "server.js"), readFileSync(join(work, "server.js"), "utf8").replace("version: 1", "version: 3"));
    await git(work, undefined, "commit", "--quiet", "-am", "다시 뜨기 전에 고친 것");

    // 팩토리가 다시 뜬다. 작업 · git 의 자격 · 연결의 토큰은 메모리에만 있어 사라지고, 고객과 인스턴스의 짝(파일)은 남는다
    await stopFactory();
    await startFactory(Number(new URL(origin).port));

    // 앞의 자격으로 올리면 git 이 무엇을 할지 읽는다. 레이어의 주소 · 토큰은 보이지 않는다
    const helper = ["-c", "credential.helper=", "-c", `credential.helper=!f() { echo username=agent; echo password=${opened.credential}; }; f`];
    for (const credential of [opened.credential, undefined])
    {
        // 한 번 쓰는 머리말로도, 자격 도우미로도
        const args = credential === undefined ? [...helper, "push", "--quiet", "origin", "main"] : ["push", "--quiet", "origin", "main"];
        const failed = await git(work, credential, ...args).then(() => "", (error: unknown) => String(error));
        assert.match(failed, /remote: .*workspace_open/, failed);
        assert.match(failed, /git remote set-url origin/, failed);
        for (const leak of [layer, direct, new URL(direct).host, "orb1.", SERVICE_KEY])
        {
            assert.ok(!failed.includes(leak), `git 이 보인 글에 \`${leak}\` 가 있습니다`);
        }
    }
    // 앞의 연결의 토큰도 사라졌다. 플랫폼이 계정을 다시 연결하고(MCP 의 401 → OAuth), 에이전트가 작업을 다시 연다
    const stale = await fetch(`${origin}/mcp`, { method: "POST", headers: { authorization: "Bearer x", "content-type": "application/json" }, body: "{}" });
    assert.equal(stale.status, 401);
    const again = await platform(await connect("frank"));
    const reopened = structured<Workspace>(await call(again, "workspace_open"));
    assert.notEqual(reopened.remote, opened.remote);
    // 스킬이 적은 대로 원격만 바꿔 같은 폴더에서 이어서 올린다. 다시 받지 않는다
    await git(work, undefined, "remote", "set-url", "origin", reopened.remote);
    await git(work, reopened.credential, "push", "--quiet", "origin", "main");
    const head = await git(work, undefined, "rev-parse", "HEAD");
    const shown = await call(again, "preview");
    assert.equal(shown.isError, undefined, textOf(shown));
    assert.equal(structured<{ commit: string }>(shown).commit, head);
    const address = structured<{ services: { url: string }[] }>(shown).services[0]?.url ?? "";
    assert.equal(((await (await fetch(`${address}/health`)).json()) as { version: number }).version, 3);
});

test("도구의 답과 팩토리의 로그 어디에도 레이어의 주소와 토큰이 없다", { skip }, async () =>
{
    // 거절과 오류의 길도 지난다: 작업 없이 부른 도구, 모르는 release, 지어낸 git 의 자격
    const carol = await platform(await connect("carol"));
    await call(carol, "preview");
    await call(carol, "promotion_request", { release: "r_made_up" });
    const alice = await platform(await connect("alice"));
    await call(alice, "rehearse", { release: "r_made_up" });
    await call(alice, "preview_sign_in", { user: "nobody" });
    await fetch(`${origin}/git/${"0".repeat(24)}/info/refs?service=git-upload-pack`, { headers: { authorization: "Bearer fgit_x" } });

    const tokens = new Set(workCalls.map((each) => each.token));
    assert.ok(tokens.size >= 3, "팩토리가 작업의 토큰으로 레이어를 불렀어야 합니다");
    const secrets = [layer, direct, new URL(layer).host, new URL(direct).host, SERVICE_KEY, "orb1.", ...tokens];
    assert.ok(answers.length > 30, "모은 답이 있어야 합니다");
    for (const { name, result } of answers)
    {
        // 비밀 입력 표의 주소(레이어)는 화면 전용 도구의 `_meta` 에만 간다. 그 밖의 모든 것을 본다
        const shown = TOOLS.find((tool) => tool.name === name)?._meta === undefined || modelVisible(TOOLS.find((tool) => tool.name === name)?._meta)
            ? JSON.stringify(result)
            : JSON.stringify({ content: result.content, structuredContent: result.structuredContent });
        for (const leak of secrets)
        {
            assert.ok(!shown.includes(leak), `${name} 의 답에 \`${leak.slice(0, 24)}\` 가 있습니다`);
        }
    }
    // 플랫폼이 받은 날것 전체에도 토큰과 service key 는 없다(카드의 CSP 에 실린 레이어의 바깥 주소는 화면이 값을 보내는 곳이라 있다)
    for (const body of received)
    {
        for (const leak of [SERVICE_KEY, "orb1.", layer])
        {
            assert.ok(!body.includes(leak), `받은 답에 \`${leak.slice(0, 24)}\` 가 있습니다`);
        }
    }
    assert.ok(logs.length > 0, "팩토리의 로그가 있어야 합니다");
    for (const leak of secrets)
    {
        assert.ok(!logs.includes(leak), `팩토리의 로그에 \`${leak.slice(0, 24)}\` 가 있습니다`);
    }
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
    assert.deepEqual([...files.keys()].sort(), [".claude-plugin/plugin.json", ".mcp.json", "plugin.json", "skills/orbital-dev/SKILL.md", "skills/orbital-dev/references/auth.md", "skills/orbital-dev/references/frameworks.md", "skills/orbital-dev/references/secrets.md"]);
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

test("플러그인의 묶음과 스킬에는 orbital CLI 를 부르라는 말이 없다", () =>
{
    const files = unzip(zip(packageFiles()));
    for (const [path, body] of files)
    {
        // CLI 의 명령 · 레이어의 환경 변수 · 레이어의 HTTP 길
        assert.doesNotMatch(body, /`orbital [a-z-]+|orbital (clone|pull|push|preview|identity|rehearse|request-promotion|check)\b/, path);
        assert.doesNotMatch(body, /ORBITAL_(URL|TOKEN|INSTANCE)/, path);
        assert.doesNotMatch(body, /\/v1\/instances|orbitald/, path);
    }
    // 스킬은 평범한 git 으로 팩토리의 원격에 오가라고 말하고, 자격은 주소에 넣지 않게 한다
    const skill = files.get("skills/orbital-dev/SKILL.md") ?? "";
    assert.match(skill, /git -c http\.extraHeader="Authorization: Bearer \$CREDENTIAL" clone/);
    assert.match(skill, /git push origin main/);
    assert.match(skill, /자격 도우미/);
    assert.ok(!/https?:\/\/[^\s]*@/.test(skill), "원격의 주소에 자격을 넣는 예가 있으면 안 됩니다");
});
