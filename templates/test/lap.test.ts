// 시작 템플릿 한 바퀴. 템플릿을 복사 스크립트로 새 폴더에 복사하고, README 의 명령대로 깔고 띄워, 실제 관리 서버(`orbitald`)와 실제 PostgreSQL 에 붙인다.
//
// 스캐폴드 올리기 → 인스턴스 세우기(`npm run try`) → 프리뷰 → 에이전트가 git 으로 고쳐 올리기 → 승격 요청 → 승인 카드의 길로 승격 →
// 웹훅이 `promotion.succeeded` 를 한 번만 처리하기 → 운영자의 스크립트. 모델은 부르지 않는다. 플랫폼과 에이전트 노릇은 이 테스트가 한다.
//
// 무거운 묶음이다(`npm run test:frameworks` 의 뒤). 레지스트리에서 서버의 의존성을 받고, 레이어가 스캐폴드(Next.js)를 `npm ci` 로 받아 빌드한다.
// `ORBITAL_FRAMEWORKS=1` 과 `ORBITAL_PG` 가 함께 있어야 돌고, 없으면 건너뛰었다고 찍고 통과한다. 잰 숫자는 `잰 것:` 으로 찍는다.
// 이 테스트가 레이어의 운영자 노릇을 한다. 빌드에 건넬 환경은 `OPERATOR_ENV` 의 이름뿐이다(`crates/orbital-server/tests/frameworks.rs` 와 같다).

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";

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

import { controlDatabase, dropControlDatabase } from "../../examples/factory-todo/test/control.ts";

const root = resolve(import.meta.dirname, "../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const run = promisify(execFile);
const pg = process.env.ORBITAL_PG;
const on = process.env.ORBITAL_FRAMEWORKS === "1" && pg !== undefined;
const skip = on ? false : "ORBITAL_FRAMEWORKS=1 과 ORBITAL_PG 가 함께 있어야 돕니다. 건너뜁니다(npm run test:frameworks)";
const control = controlDatabase();

/** 운영자가 빌드에 건네는 환경의 이름. 레지스트리에 닿는 데 필요한 것만 적는다 */
const OPERATOR_ENV = ["HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "npm_config_https_proxy", "npm_config_noproxy", "npm_config_registry"];
/** 어디에 새어도 찾을 수 있게 드문 글자로 짓는다 */
const SERVICE_KEY = "sk_test_starter_lap_V7nQ2x";
const ACCOUNT = "dev";
const REDIRECT = "http://127.0.0.1:9/callback";
const GIT = ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false"];

let scratch = "";
let made = "";
let server = "";
let layer = "";
let origin = "";
let webhookSecret = "";
let orbital: Orbital;
let orbitald: ChildProcess | undefined;
let factory: ChildProcess | undefined;
/** 팩토리 프로세스(npm start)의 표준 출력과 표준 오류 */
let logs = "";
/** 도구를 부른 것과 그 답. 모델이 읽는 것이다 */
const answers: { name: string; result: CallToolResult }[] = [];
/** 운영자의 스크립트가 찍은 것. 운영자의 터미널에만 간다 */
let operatorOutput = "";
let client: Client | undefined;
let instance = "";

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

/** 팩토리 개발자의 터미널에서 치는 명령. 이 프로세스의 환경(프록시 · 레지스트리)을 그대로 쓴다 */
async function shell(cwd: string, command: string, args: string[], env: Record<string, string> = {}): Promise<string>
{
    try
    {
        // 이 테스트를 돌리는 node --test 의 표식은 넘기지 않는다. 넘기면 복사본의 npm test 가 결과를 이 프로세스에 보내는 모양으로 찍는다
        const { NODE_TEST_CONTEXT: _, ...inherited } = process.env;
        const { stdout } = await run(command, args, { cwd, encoding: "utf8", env: { ...inherited, ...env }, maxBuffer: 64 * 1024 * 1024 });
        return stdout;
    }
    catch (error)
    {
        const detail = typeof error === "object" && error !== null && "stderr" in error ? `${String((error as { stdout?: unknown }).stdout)}\n${String(error.stderr)}` : String(error);
        throw new Error(`${command} ${args.join(" ")}: ${detail}`);
    }
}

/** 에이전트의 git. sandbox 에는 작업을 연 답(원격과 자격)만 있다 */
async function git(folder: string, credential: string | undefined, ...args: string[]): Promise<string>
{
    const auth = credential === undefined ? [] : ["-c", `http.extraHeader=Authorization: Bearer ${credential}`];
    const env = { PATH: process.env.PATH ?? "", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
    const { stdout } = await run("git", [...GIT, ...auth, ...args], { cwd: folder, encoding: "utf8", env });
    return stdout.trim();
}

async function connect(): Promise<string>
{
    const resource = await discoverOAuthProtectedResourceMetadata(`${origin}/mcp`);
    const issuer = resource.authorization_servers?.[0] ?? "";
    const metadata = await discoverAuthorizationServerMetadata(issuer);
    assert.ok(metadata !== undefined);
    const registered = await registerClient(issuer, { metadata, clientMetadata: { client_name: "시험 플랫폼", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" } });
    const started = await startAuthorization(issuer, { metadata, clientInformation: registered, redirectUrl: REDIRECT, resource: new URL(resource.resource) });
    const form = new URLSearchParams(started.authorizationUrl.searchParams);
    form.set("account", ACCOUNT);
    form.set("decision", "allow");
    const answered = await fetch(`${origin}/oauth/authorize`, { method: "POST", body: form, redirect: "manual" });
    const back = new URL(answered.headers.get("location") ?? "");
    const tokens = await exchangeAuthorization(issuer, {
        metadata,
        clientInformation: registered,
        authorizationCode: back.searchParams.get("code") ?? "",
        iss: back.searchParams.get("iss") ?? "",
        codeVerifier: started.codeVerifier,
        redirectUri: REDIRECT,
    });
    return tokens.access_token;
}

async function platform(): Promise<Client>
{
    if (client === undefined)
    {
        client = new Client({ name: "시험 플랫폼", version: "0.0.0" }, { versionNegotiation: { mode: "auto" } });
        await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { authorization: `Bearer ${await connect()}` } } }));
    }
    return client;
}

const textOf = (result: CallToolResult): string => result.content.map((block) => (block.type === "text" ? block.text : "")).join("\n");

async function call(name: string, args: Record<string, unknown> = {}): Promise<CallToolResult>
{
    const result = (await (await platform()).callTool({ name, arguments: args })) as CallToolResult;
    answers.push({ name, result });
    return result;
}

async function ok<T>(name: string, args: Record<string, unknown> = {}): Promise<T>
{
    const result = await call(name, args);
    assert.equal(result.isError, undefined, `${name}: ${textOf(result)}`);
    return result.structuredContent as T;
}

function cardOf(result: CallToolResult): string
{
    const html = result._meta?.["acme-notes/card"];
    assert.equal(typeof html, "string", `카드가 있어야 합니다: ${JSON.stringify(result._meta)}`);
    return html as string;
}

function approveButton(html: string): { release: string; approval: string } | undefined
{
    const button = /<button[^>]*data-action="approve"[^>]*>/.exec(html)?.[0];
    return button === undefined
        ? undefined
        : { release: /data-release="([^"]*)"/.exec(button)?.[1] ?? "", approval: /data-approval="([^"]*)"/.exec(button)?.[1] ?? "" };
}

async function waitFor(what: string, check: () => boolean, seconds = 30): Promise<void>
{
    for (let waited = 0; waited < seconds * 10; waited += 1)
    {
        if (check())
        {
            return;
        }
        await new Promise((done) => setTimeout(done, 100));
    }
    assert.fail(`${what} 을 ${seconds}초 안에 보지 못했습니다:\n${logs}`);
}

const health = async (url: string): Promise<{ ok: boolean; version: number }> => (await (await fetch(`${url}/health`)).json()) as { ok: boolean; version: number };
const seconds = (since: number): string => ((Date.now() - since) / 1000).toFixed(1);

before(async () =>
{
    if (!on)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-starter-"));
    const listen = `127.0.0.1:${await freePort()}`;
    layer = `http://${listen}`;
    const passed: Record<string, string> = {};
    for (const name of OPERATOR_ENV)
    {
        const value = process.env[name];
        if (value !== undefined)
        {
            passed[name] = value;
        }
    }
    orbitald = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ...passed,
            ORBITAL_BUILD_ENV: Object.keys(passed).join(","),
            ORBITAL_HOME: join(scratch, "layer"),
            ORBITAL_PG: pg ?? "",
            ORBITAL_CONTROL_DB: control,
            ORBITAL_SERVICE_KEYS: `factory=${SERVICE_KEY}`,
            ORBITAL_DEV_MAIL: "outbox",
            ORBITAL_DEV_WEBHOOK: "private",
            ORBITAL_LISTEN: listen,
            ORBITAL_SEAL_KEY: "5e".repeat(32),
            ORBITAL_PUBLIC_URL: layer,
        },
    });
    orbital = createOrbital({ url: layer, serviceKey: SERVICE_KEY });
    for (let attempt = 0; ; attempt += 1)
    {
        const up = await orbital.organization.get().then(() => true, () => false);
        if (up)
        {
            break;
        }
        assert.ok(attempt < 400, "관리 서버가 뜨지 않았습니다");
        await new Promise((done) => setTimeout(done, 50));
    }
});

after(async () =>
{
    try
    {
        await client?.close().catch(() => undefined);
        if (factory?.pid !== undefined && factory.exitCode === null)
        {
            const stopping = factory;
            await new Promise<void>((done) =>
            {
                stopping.once("exit", () => done());
                // npm 과 그 아래의 node 를 함께 멈춘다
                process.kill(-(stopping.pid ?? 0), "SIGTERM");
            });
        }
        if (on)
        {
            for (const row of (await orbital.instances.list().catch(() => ({ instances: [] }))).instances)
            {
                await orbital.instances.destroy(row.id).catch(() => undefined);
            }
        }
    }
    finally
    {
        const layerProcess = orbitald;
        if (layerProcess !== undefined && layerProcess.exitCode === null)
        {
            await new Promise<void>((done) =>
            {
                layerProcess.once("exit", () => done());
                layerProcess.kill();
            });
        }
        if (on && pg !== undefined)
        {
            dropControlDatabase(pg, control);
        }
        if (scratch !== "")
        {
            rmSync(scratch, { recursive: true, force: true });
        }
    }
});

test("복사한 템플릿이 README 의 명령대로 설치되고 타입 검사와 자기 테스트를 통과한다", { skip }, async () =>
{
    const since = Date.now();
    made = join(scratch, "acme");
    await shell(root, process.execPath, ["scripts/new-factory.mjs", made, "acme-notes"]);
    server = join(made, "server");
    await shell(server, "npm", ["install", "--no-audit", "--no-fund"]);
    console.log(`잰 것: 복사와 npm install ${seconds(since)}초`);
    await shell(server, "npm", ["run", "typecheck"]);
    const tested = await shell(server, "npm", ["test"]);
    assert.match(tested, /# fail 0/);
    console.log(`잰 것: 타입 검사와 자기 테스트까지 ${seconds(since)}초`);
});

test("팩토리를 띄우고 npm run try 를 부르면 스캐폴드를 올리고 인스턴스를 세워 프리뷰가 선다 — 처음 10분", { skip }, async () =>
{
    const port = await freePort();
    origin = `http://127.0.0.1:${port}`;
    // 운영자가 웹훅을 건다(README 의 `npm run operator -- webhook`). 개발용 레이어라 loopback 의 http 로 보낸다
    const set = await shell(server, "npm", ["run", "--silent", "operator", "--", "webhook", `${origin}/webhooks/orbital`], { ORBITAL_URL: layer, ORBITAL_SERVICE_KEY: SERVICE_KEY });
    operatorOutput += set;
    webhookSecret = /서명 비밀: (whsec_[0-9a-f]+)/.exec(set)?.[1] ?? "";
    assert.match(webhookSecret, /^whsec_/);

    const since = Date.now();
    factory = spawn("npm", ["start"], {
        cwd: server,
        detached: true,
        env: {
            PATH: process.env.PATH ?? "",
            HOME: process.env.HOME ?? "",
            ORBITAL_URL: layer,
            ORBITAL_SERVICE_KEY: SERVICE_KEY,
            ORBITAL_WEBHOOK_SECRET: webhookSecret,
            FACTORY_PORT: String(port),
            FACTORY_HOME: join(scratch, "factory-home"),
        },
        stdio: ["ignore", "pipe", "pipe"],
    });
    factory.stdout?.on("data", (chunk: Buffer) => { logs += chunk.toString("utf8"); });
    factory.stderr?.on("data", (chunk: Buffer) => { logs += chunk.toString("utf8"); });
    await waitFor("팩토리가 뜬 것", () => logs.includes(`${origin}/mcp`));
    assert.match(logs, /스캐폴드 acme_notes v1 를 올렸습니다/);
    assert.match(logs, /웹훅을 .*\/webhooks\/orbital 에서 받습니다/);

    const tried = await shell(server, "npm", ["run", "--silent", "try", "--", join(scratch, "try-app"), ACCOUNT], { FACTORY_PORT: String(port) });
    const report = JSON.parse(tried.trim().split("\n").at(-1) ?? "{}") as { release: string; services: { name: string; url: string }[] };
    const url = report.services[0]?.url ?? "";
    assert.deepEqual(await health(url), { ok: true, version: 1 });
    console.log(`잰 것: 팩토리를 띄우고 npm run try 로 프리뷰가 서기까지 ${seconds(since)}초`);
    const fleet = await orbital.instances.list();
    assert.equal(fleet.instances.length, 1);
    instance = fleet.instances[0]?.id ?? "";
    assert.equal(fleet.instances[0]?.app, "acme_notes");
    // 받은 폴더에는 고객의 사본이 있다
    assert.match(readFileSync(join(scratch, "try-app", "orbital.toml"), "utf8"), /\[conformance\]/);
});

test("에이전트가 도구와 git 만으로 고쳐 올리고 승격을 요청하면 승인 카드의 길로 고객의 승인으로 오르고 이력에 고객의 이름표가 남는다", { skip }, async () =>
{
    const work = join(scratch, "try-app");
    const opened = await ok<{ remote: string; credential: string }>("workspace_open");
    await git(work, undefined, "remote", "set-url", "origin", opened.remote);
    const route = join(work, "app/health/route.js");
    writeFileSync(route, readFileSync(route, "utf8").replace("version: 1", "version: 2"));
    await git(work, undefined, "commit", "--quiet", "-am", "버전을 올린다");
    await git(work, opened.credential, "push", "--quiet", "origin", "main");

    const preview = await ok<{ release: string; services: { url: string }[]; blockers: string[]; conformance: { passed: boolean } | null }>("preview");
    assert.deepEqual(preview.blockers, []);
    assert.equal(preview.conformance?.passed, true);
    assert.equal((await health(preview.services[0]?.url ?? "")).version, 2);
    await ok("promotion_request", { release: preview.release });

    const shown = await call("promotion_show");
    const html = cardOf(shown);
    assert.ok(html.includes("`member` 역할이 `app.note` 표를"), html);
    assert.ok(html.includes("리허설이 필요 없어요"));
    assert.ok(html.includes("새로 쓰는 비밀이 없어요"));
    const seen = approveButton(html);
    assert.equal(seen?.release, preview.release);
    const approved = await ok<{ release: string; url: string }>("promotion_approve", seen ?? {});
    assert.equal(approved.release, preview.release);
    assert.equal((await health(approved.url)).version, 2);

    const history = await orbital.instances.history(instance);
    const last = history.history.at(-1);
    assert.equal(last?.kind, "promoted");
    assert.ok(last !== undefined && "approver" in last);
    assert.deepEqual([last.approvedBy, last.approver, last.change], ["customer", ACCOUNT, "customer_request"]);
});

test("웹훅이 promotion.succeeded 를 한 번만 처리한다 — 같은 이벤트를 다시 보내도", { skip }, async () =>
{
    const events = await orbital.events.list();
    const succeeded = events.events.find((each) => each.type === "promotion.succeeded" && each.instance === instance);
    assert.ok(succeeded !== undefined, JSON.stringify(events));
    const line = `[factory] 알림 #${succeeded.id} promotion.succeeded → ${ACCOUNT}: 운영에 올랐습니다`;
    // 레이어가 1초마다 보낸다
    await waitFor("웹훅으로 받은 promotion.succeeded", () => logs.includes(line));
    // 앞의 이벤트(요청)도 같은 길로 왔다
    assert.match(logs, /알림 #\d+ promotion\.requested → dev/);

    // 레이어가 같은 이벤트를 다시 보낸 것처럼 서명해 보낸다(적어도 한 번 가므로 생길 수 있다)
    const body = JSON.stringify({ id: succeeded.id, type: succeeded.type, created_at: succeeded.createdAt, organization: succeeded.organization, instance: succeeded.instance, data: succeeded.data });
    const at = Math.floor(Date.now() / 1000);
    const signature = `t=${at},v1=${createHmac("sha256", webhookSecret).update(`${at}.${body}`).digest("hex")}`;
    const again = await fetch(`${origin}/webhooks/orbital`, { method: "POST", headers: { "content-type": "application/json", "orbital-signature": signature }, body });
    assert.equal(again.status, 200);
    assert.deepEqual(await again.json(), { received: succeeded.id, duplicate: true });
    // 서명이 틀린 것은 받지 않는다
    const forged = await fetch(`${origin}/webhooks/orbital`, { method: "POST", headers: { "orbital-signature": signature.replace(/.$/, "0") }, body: body.replace("succeeded", "failed") });
    assert.equal(forged.status, 401);
    assert.equal(logs.split(line).length - 1, 1);
    // 레이어도 보낸 것으로 적었다
    const webhook = await orbital.webhook.get();
    assert.ok((webhook?.delivery.deliveredThrough ?? 0) >= succeeded.id, JSON.stringify(webhook));
});

test("마이그레이션과 밖에서 넣는 비밀을 더한 release 의 승인 카드는 리허설의 숫자와 새 비밀을 보인다", { skip }, async () =>
{
    const work = join(scratch, "try-app");
    const opened = await ok<{ remote: string; credential: string }>("workspace_open");
    await git(work, undefined, "remote", "set-url", "origin", opened.remote);
    writeFileSync(join(work, "db/migrations/002_note_done.sql"), "ALTER TABLE app.note ADD COLUMN done boolean NOT NULL DEFAULT false;\n");
    writeFileSync(join(work, "orbital.toml"), `${readFileSync(join(work, "orbital.toml"), "utf8")}\n[secrets]\nexternal = ["NOTES_KEY"]\n`);
    await git(work, undefined, "add", "-A");
    await git(work, undefined, "commit", "--quiet", "-m", "끝냄 칸과 바깥 서비스의 키를 더한다");
    await git(work, opened.credential, "push", "--quiet", "origin", "main");

    const first = await ok<{ missing_secrets: string[] }>("preview");
    assert.deepEqual(first.missing_secrets, ["NOTES_KEY"]);
    // 사람이 입력 카드에서 넣는다: 카드가 화면 전용 도구로 입력 표를 받아 레이어로 바로 보낸다
    cardOf(await call("secret_request", { name: "NOTES_KEY", reason: "메모를 바깥 서비스에 보관합니다" }));
    for (const stage of ["preview", "production"])
    {
        const entry = (await call("secret_entry_open", { name: "NOTES_KEY", stage }))._meta?.["acme-notes/entry"] as { url: string; ticket: string };
        const sent = await fetch(entry.url, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${entry.ticket}` }, body: JSON.stringify({ value: `notes_${stage}_value_Kx81` }) });
        assert.ok(sent.ok, String(sent.status));
    }
    const preview = await ok<{ release: string; missing_secrets: string[] }>("preview");
    assert.deepEqual(preview.missing_secrets, []);
    const rehearsal = await ok<{ needed: boolean; passed: boolean }>("rehearse", { release: preview.release });
    assert.deepEqual([rehearsal.needed, rehearsal.passed], [true, true]);
    await ok("promotion_request", { release: preview.release });

    const shown = await call("promotion_show");
    const html = cardOf(shown);
    assert.ok(html.includes("<li>002_note_done.sql</li>"), html);
    assert.match(html, /data-rehearsal="passed">운영 DB 의 사본에서 통과했어요\(\d+ ms\)/);
    assert.match(html, /<code>app\.note<\/code> \d+행 → \d+행/);
    assert.match(html, /<code>NOTES_KEY<\/code> · 운영의 값을 넣었어요/);
    assert.equal((shown.structuredContent as { ready: boolean }).ready, true);
    const seen = approveButton(html);
    assert.equal(seen?.release, preview.release);
    await ok("promotion_approve", seen ?? {});
    assert.equal((await orbital.production.get(instance))?.release, preview.release);
    const last = (await orbital.instances.history(instance)).history.at(-1);
    assert.ok(last !== undefined && "approver" in last);
    assert.deepEqual([last.approver, last.rehearsal, last.migrations], [ACCOUNT, "passed", 1]);
});

test("운영자의 스크립트가 함대 · 이력 · 서비스의 상태를 읽는다", { skip }, async () =>
{
    const env = { ORBITAL_URL: layer, ORBITAL_SERVICE_KEY: SERVICE_KEY };
    const fleet = await shell(server, "npm", ["run", "--silent", "operator", "--", "fleet"], env);
    assert.match(fleet, new RegExp(`^${instance}  acme_notes@v1  운영 r_`, "m"));
    // 설정(ORBITAL_SERVICE_KEYS)에만 있는 조직이라 상한은 찍히지 않는다. 운영자가 만든 시험용 조직이면 「/ 상한 10」이 붙는다
    assert.match(fleet, /^인스턴스 1개/m);
    const history = await shell(server, "npm", ["run", "--silent", "operator", "--", "history", instance], env);
    assert.equal(history.trim().split("\n").filter((line) => line.includes(`승인 customer(${ACCOUNT})`)).length, 2, history);
    const services = await shell(server, "npm", ["run", "--silent", "operator", "--", "services", instance], env);
    assert.match(services, /^ {2}web {2}server {2}(awake|asleep|building)$/m);
    const logsOut = await shell(server, "npm", ["run", "--silent", "operator", "--", "logs", instance, "20"], env);
    assert.match(logsOut, /== build-web/);
    operatorOutput += fleet + history + services + logsOut;
    // 열쇠의 목록에는 값이 없다
    const keys = await shell(server, "npm", ["run", "--silent", "operator", "--", "keys"], env);
    assert.ok(!keys.includes(SERVICE_KEY));
});

test("도구의 답과 팩토리의 로그에 레이어의 주소 · 토큰 · service key · 웹훅의 비밀이 없다", { skip }, async () =>
{
    assert.ok(answers.length >= 12, "모은 답이 있어야 합니다");
    const secrets = [layer, new URL(layer).host, SERVICE_KEY, "orb1.", webhookSecret, "notes_production_value", "notes_preview_value"];
    for (const { name, result } of answers)
    {
        // 비밀 입력 표의 주소(레이어)는 화면 전용 도구의 `_meta` 에만 간다. 모델이 읽는 것을 본다
        const shown = name === "secret_entry_open" ? JSON.stringify({ content: result.content, structuredContent: result.structuredContent }) : JSON.stringify(result);
        for (const leak of secrets)
        {
            assert.ok(!shown.includes(leak), `${name} 의 답에 \`${leak.slice(0, 24)}\` 가 있습니다`);
        }
    }
    assert.ok(logs.length > 0);
    for (const leak of secrets)
    {
        assert.ok(!logs.includes(leak), `팩토리의 로그에 \`${leak.slice(0, 24)}\` 가 있습니다`);
    }
    // 처리한 자리는 팩토리의 폴더에만 있고 비밀은 없다
    const inbox = readFileSync(join(scratch, "factory-home", "inbox.json"), "utf8");
    assert.ok(!inbox.includes(webhookSecret));
    // 운영자의 스크립트는 운영자의 터미널에만 찍는다(웹훅의 비밀은 걸 때 한 번)
    assert.equal(operatorOutput.split(webhookSecret).length - 1, 1);
});
