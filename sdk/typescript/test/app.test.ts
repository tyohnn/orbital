// 앱의 화면이 `@harmony/orbital/app` 으로 레이어를 부른다. 실제 `orbitald` 가 세운 운영의 router 에 실제 HTTP 로 붙는다.
//
// 브라우저가 하는 일(쿠키와 Origin 을 싣는 것)은 테스트의 `fetch` 가 대신한다. SDK 는 열쇠도 토큰도 받지 않는다.
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalAppError, identityOf, orbitalApp } from "../src/app.ts";
import { createOrbital } from "../src/server.ts";
import type { Orbital } from "../src/server.ts";
import { controlDatabase, dropControlDatabase } from "./control.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
/** 이 테스트의 `orbitald` 가 기록을 두는 control database. */
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_app_factory";
const CALLBACK = "http://localhost:7777/callback";
const VERIFIER = "a-verifier-that-is-long-enough-for-pkce-0123456789";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
let orbital: Orbital;
let instance = "";
let live = "";

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

function cookiePair(response: Response, name: string): string
{
    return response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))?.split(";")[0] ?? "";
}

/** 브라우저 하나. 같은 주소의 화면이 부르듯 Origin 을 싣고, 받은 레이어의 쿠키를 기억했다가 싣는다. */
function browser(): { fetch: typeof fetch; cookies: Map<string, string> }
{
    const cookies = new Map<string, string>();
    const send = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
    {
        const headers = new Headers(init?.headers);
        headers.set("origin", live);
        if (cookies.size > 0)
        {
            headers.set("cookie", [...cookies].map(([name, value]) => `${name}=${value}`).join("; "));
        }
        const response = await fetch(input, { ...init, headers });
        for (const line of response.headers.getSetCookie())
        {
            const [pair = ""] = line.split(";");
            const [name = "", value = ""] = pair.split("=");
            if (value === "" || /max-age=0/i.test(line))
            {
                cookies.delete(name);
            }
            else
            {
                cookies.set(name, value);
            }
        }
        return response;
    };
    return { fetch: send, cookies };
}

/** 개발용 메일함에 그 이메일로 쌓인 마지막 링크. 메일은 레이어가 답을 보낸 뒤에 뒤에서 쌓으니 올 때까지 기다린다. */
async function outbox(email: string): Promise<string>
{
    const deadline = Date.now() + 10_000;
    for (;;)
    {
        let text = "";
        try
        {
            text = readFileSync(join(scratch, "home", "outbox.jsonl"), "utf8");
        }
        catch
        {
            text = "";
        }
        const link = text
            .trim()
            .split("\n")
            .filter((line) => line !== "")
            .map((line) => JSON.parse(line) as { to: string; link: string })
            .filter((mail) => mail.to === email)
            .at(-1)?.link;
        if (link !== undefined || Date.now() >= deadline)
        {
            return link ?? "";
        }
        await new Promise((resolve) => setTimeout(resolve, 20));
    }
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-app-"));
    const listen = `127.0.0.1:${await freePort()}`;
    url = `http://${listen}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_CONTROL_DB: control,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY}`,
            // 팩토리의 메일 키 없이 운영에 올린다. 개발용 메일함을 명시해 켠다
            ORBITAL_DEV_MAIL: "outbox",
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url, serviceKey: FACTORY });

    // 할 일 앱에 MCP 의 인가를 더한 스캐폴드
    const scaffold = join(scratch, "scaffold");
    cpSync(join(root, "crates/orbital-server/tests/fixtures/todo"), scaffold, { recursive: true });
    cpSync(join(root, "crates/orbital-server/tests/fixtures/mcp/orbital.toml"), join(scaffold, "orbital.toml"));
    git(scaffold, "init", "--quiet", "--initial-branch", "main");
    git(scaffold, "add", "-A");
    git(scaffold, "commit", "--quiet", "-m", "스캐폴드 v1");
    git(scaffold, "tag", "v1");
    git(scaffold, "bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
    const bundle = readFileSync(join(scratch, "scaffold.bundle"));
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            await orbital.apps.put("todo", bundle);
            break;
        }
        catch (error)
        {
            if (attempt > 100)
            {
                throw error;
            }
            await new Promise((done) => setTimeout(done, 50));
        }
    }

    // 운영까지 세운다
    instance = (await orbital.instances.create({ app: "todo", from: "v1" })).id;
    const work = await orbital.works.open({ instance, can: ["source", "preview", "rehearse"], ttlSeconds: 600 });
    const { release } = await work.preview();
    await work.requestPromotion(release);
    const production = await orbital.releases.promote({
        instance,
        release,
        change: "customer_request",
        approvedBy: "customer",
    });
    live = production.services[0]?.url ?? "";
    await orbital.users.invite({ instance, email: "ana@example.test", roles: ["member"] });
});

after(async () =>
{
    if (instance !== "")
    {
        await orbital.instances.destroy(instance).catch(() => undefined);
    }
    server?.kill();
    if (pg !== undefined)
    {
        dropControlDatabase(pg, control);
    }
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

test("앱의 화면이 같은 주소의 레이어로 로그인하고 동의를 받고 승인을 거둔다", { skip }, async () =>
{
    const person = browser();
    const app = orbitalApp({ origin: live, fetch: person.fetch });

    // 로그인 화면은 이메일 주소만 다룬다. 링크는 메일로 가고, 같은 브라우저로 연다
    assert.equal(await app.me(), null);
    await app.sendLoginLink({ email: "ana@example.test", next: "/" });
    const opened = await person.fetch(await outbox("ana@example.test"), { redirect: "manual" });
    assert.equal(opened.status, 302);
    assert.ok(person.cookies.has("__Host-orbital-session"));
    const me = await app.me();
    assert.equal(me?.email, "ana@example.test");
    assert.deepEqual(me?.roles, ["member"]);

    // MCP 의 클라이언트가 등록하고 사람을 인가 주소로 보낸다
    const registered = await fetch(`${live}/_orbital/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_name: "메모 도우미", redirect_uris: [CALLBACK] }),
    });
    const client = ((await registered.json()) as { client_id: string }).client_id;
    const authorize = async (): Promise<string> =>
    {
        const query = new URLSearchParams({
            response_type: "code",
            client_id: client,
            redirect_uri: CALLBACK,
            code_challenge: createHash("sha256").update(VERIFIER).digest("base64url"),
            code_challenge_method: "S256",
            resource: `${live}/mcp`,
            scope: "mcp",
            state: "s1",
        });
        const sent = await person.fetch(`${live}/_orbital/oauth/authorize?${query}`, {
            redirect: "manual",
            headers: { accept: "text/html" },
        });
        assert.equal(sent.status, 302);
        return new URL(sent.headers.get("location") ?? "", live).searchParams.get("request") ?? "";
    };

    // 동의 화면은 레이어가 말한 것을 보이고, 사람이 누른 뒤에만 approve 를 부른다
    const asked = await app.consentRequest(await authorize());
    assert.deepEqual(asked.client.name, "메모 도우미");
    assert.equal(asked.client.redirectHost, "localhost:7777");
    assert.deepEqual(asked.scopes, ["mcp"]);
    const denied = await app.deny(await authorize());
    assert.match(denied.redirect, /error=access_denied/);
    assert.deepEqual(await app.grants(), []);
    const request = await authorize();
    const approved = await app.approve(request);
    assert.ok(approved.redirect.startsWith(`${CALLBACK}?code=`), approved.redirect);
    // 한 번 정한 요청은 다시 정하지 못한다
    await assert.rejects(app.approve(request), (error: unknown) => error instanceof OrbitalAppError && error.status === 404);

    // 승인 목록에서 거둔다
    const grants = await app.grants();
    assert.equal(grants.length, 1);
    assert.equal(grants[0]?.client.name, "메모 도우미");
    await app.revokeGrant(grants[0]?.id ?? "");
    assert.deepEqual(await app.grants(), []);

    // 로그아웃하면 그 브라우저는 다시 모르는 사람이다
    await app.logout();
    assert.equal(await app.me(), null);
    await assert.rejects(app.grants(), (error: unknown) => error instanceof OrbitalAppError && error.status === 401);

    // 다른 주소의 화면이 쿠키를 들고 와도 레이어는 상태를 바꾸지 않는다
    const stranger = orbitalApp({
        origin: live,
        fetch: (input, init) =>
            fetch(input, { ...init, headers: { ...Object.fromEntries(new Headers(init?.headers)), origin: "https://elsewhere.example" } }),
    });
    await assert.rejects(stranger.logout(), (error: unknown) => error instanceof OrbitalAppError && error.status === 403);
});

test("앱의 서버는 router 가 실은 신원을 글자 그대로 꺼낸다", () =>
{
    const signed = "v2.00ff.abcd";
    assert.equal(identityOf(new Request("http://app.example/", { headers: { "x-orbital-identity": signed } })), signed);
    assert.equal(identityOf({ headers: { "x-orbital-identity": signed } }), signed);
    assert.equal(identityOf(new Request("http://app.example/")), null);
    assert.equal(identityOf({ headers: {} }), null);
});
