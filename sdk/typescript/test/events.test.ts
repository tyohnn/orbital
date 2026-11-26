// 이벤트와 웹훅을 팩토리의 서버가 SDK 로 받는다. 실제 `orbitald` 에 실제 HTTP 로 붙고, 웹훅은 이 테스트가 127.0.0.1 에 띄운 받는 서버로 받는다.
//
// 관리 서버는 개발용 웹훅(`ORBITAL_DEV_WEBHOOK=private`)을 켜 loopback 의 `http://` 로 보낸다. 서명의 확인(`verifyWebhook`)은 관리 서버 없이도 잰다.
// `ORBITAL_PG` 가 없으면 관리 서버가 필요한 테스트는 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다.

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import { createServer as createNetServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalWebhookError, createOrbital, verifyWebhook } from "../src/server.ts";
import type { Orbital } from "../src/server.ts";
import { controlDatabase, dropControlDatabase } from "./control.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

/** 테스트에만 쓰는 열쇠들 */
const FACTORY = "sk_test_factory_sdk_events";
const SEAL = "07".repeat(32);
const SECRET = "whsec_test_not_a_secret";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
let orbital: Orbital;

/** 받은 웹훅 */
const hooks: { headers: IncomingHttpHeaders; body: Buffer }[] = [];
const receiver = createServer((request, response) =>
{
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () =>
    {
        hooks.push({ headers: request.headers, body: Buffer.concat(chunks) });
        response.writeHead(200).end();
    });
});

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=factory", "-c", "user.email=factory@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

async function freePort(): Promise<number>
{
    const probe = createNetServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

/** 관리 서버가 뜨기를 기다리며 부른다. */
async function retried<T>(work: () => Promise<T>): Promise<T>
{
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            return await work();
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
}

async function until(done: () => boolean, what: string): Promise<void>
{
    const deadline = Date.now() + 10_000;
    while (!done())
    {
        assert.ok(Date.now() < deadline, `${what}을 기다리다 시간이 다 됐습니다`);
        await new Promise((wait) => setTimeout(wait, 50));
    }
}

function sign(secret: string, at: number, body: string): string
{
    return `t=${at},v1=${createHmac("sha256", secret).update(`${at}.${body}`).digest("hex")}`;
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    await new Promise<void>((done) => receiver.listen(0, "127.0.0.1", done));
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-events-"));
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
            ORBITAL_SEAL_KEY: SEAL,
            ORBITAL_DEV_WEBHOOK: "private",
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url, serviceKey: FACTORY });
    const scaffold = join(scratch, "scaffold");
    cpSync(join(root, "crates/orbital-server/tests/fixtures/records"), scaffold, { recursive: true });
    git(scaffold, "init", "--quiet", "--initial-branch", "main");
    git(scaffold, "add", "-A");
    git(scaffold, "commit", "--quiet", "-m", "스캐폴드 v1");
    git(scaffold, "tag", "v1");
    git(scaffold, "bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
    const bundle = readFileSync(join(scratch, "scaffold.bundle"));
    await retried(() => orbital.apps.put("records", bundle));
});

after(() =>
{
    server?.kill();
    receiver.close();
    if (pg !== undefined)
    {
        dropControlDatabase(pg, control);
    }
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

test("웹훅을 걸면 비밀은 그 답에만 있고 받은 본문을 그 비밀로 확인해 이벤트로 읽는다", { skip }, async () =>
{
    const { port } = receiver.address() as AddressInfo;
    const hookUrl = `http://127.0.0.1:${port}/hooks`;
    const { webhook, secret } = await orbital.webhook.set({ url: hookUrl });
    assert.ok(secret.startsWith("whsec_"));
    assert.equal(webhook.url, hookUrl);
    const shown = await orbital.webhook.get();
    assert.equal(shown?.url, hookUrl);
    assert.ok(!JSON.stringify(shown).includes(secret));
    const { id } = await orbital.instances.create({ app: "records", from: "v1" });
    await until(() => hooks.length > 0, "웹훅");
    const [hook] = hooks;
    assert.ok(hook !== undefined);
    const event = verifyWebhook({ secret, signature: String(hook.headers["orbital-signature"]), body: hook.body });
    assert.equal(event.type, "instance.created");
    assert.equal(event.instance, id);
    assert.deepEqual(event.data, { app: "records", version: "v1" });
    assert.equal(event.organization, "factory");
    // 목록에도 같은 것이 있다
    const page = await orbital.events.list();
    assert.deepEqual(page.events.at(-1), event);
    // 받은 답을 적는 것은 답한 뒤라 잠깐 기다린다
    let delivered = await orbital.webhook.get();
    for (let attempt = 0; delivered?.delivery.lastStatus !== 200 && attempt < 100; attempt += 1)
    {
        await new Promise((wait) => setTimeout(wait, 50));
        delivered = await orbital.webhook.get();
    }
    assert.equal(delivered?.delivery.lastStatus, 200);
    assert.equal(delivered?.delivery.pending, 0);
    assert.equal(await orbital.webhook.remove(), true);
    assert.equal(await orbital.webhook.get(), null);
    await orbital.instances.destroy(id);
});

test("이벤트의 목록은 차례대로 오고 after 로 이어 받는다", { skip }, async () =>
{
    const first = await orbital.instances.create({ app: "records", from: "v1" });
    await orbital.instances.destroy(first.id);
    const all = await orbital.events.list({ limit: 500 });
    assert.equal(all.hasMore, false);
    const ids = all.events.map((event) => event.id);
    assert.deepEqual([...ids].sort((a, b) => a - b), ids);
    const tail = all.events.slice(-2).map((event) => [event.type, event.instance]);
    assert.deepEqual(tail, [["instance.created", first.id], ["instance.deleted", first.id]]);
    const head = await orbital.events.list({ limit: 1 });
    assert.equal(head.events.length, 1);
    assert.equal(head.hasMore, true);
    const rest = await orbital.events.list({ after: head.next });
    assert.deepEqual(rest.events.map((event) => event.id), ids.slice(1));
});

test("본문이나 서명을 한 글자 바꾸거나 다른 비밀이거나 오래된 서명은 확인하지 못한다", async () =>
{
    const body = JSON.stringify({ id: 7, type: "instance.created", created_at: 1_900_000_000, organization: "factory", instance: "iabc", data: { app: "records", version: "v1" } });
    const at = 1_900_000_000;
    const signature = sign(SECRET, at, body);
    const event = verifyWebhook({ secret: SECRET, signature, body, now: at + 10 });
    assert.equal(event.id, 7);
    assert.equal(event.createdAt, 1_900_000_000);
    // 바이트로 받아도 같다
    assert.equal(verifyWebhook({ secret: SECRET, signature, body: new TextEncoder().encode(body), now: at }).id, 7);
    const refused = (input: Parameters<typeof verifyWebhook>[0]): string =>
    {
        try
        {
            verifyWebhook(input);
        }
        catch (error)
        {
            assert.ok(error instanceof OrbitalWebhookError);
            return error.code;
        }
        assert.fail("받았습니다");
    };
    const flipped = signature.slice(0, -1) + (signature.endsWith("0") ? "1" : "0");
    assert.equal(refused({ secret: SECRET, signature: flipped, body, now: at }), "mismatch");
    assert.equal(refused({ secret: SECRET, signature, body: body.replace("records", "recordz"), now: at }), "mismatch");
    assert.equal(refused({ secret: "whsec_other", signature, body, now: at }), "mismatch");
    // 허용 시간차(기본 300초)의 경계: 안쪽은 받고 바깥은 받지 않는다
    assert.equal(verifyWebhook({ secret: SECRET, signature, body, now: at + 300 }).id, 7);
    assert.equal(refused({ secret: SECRET, signature, body, now: at + 301 }), "stale");
    assert.equal(refused({ secret: SECRET, signature, body, now: at - 301 }), "stale");
    // 오래된 t 에 맞는 서명을 새 t 로 바꿔 붙여도 맞지 않는다
    assert.equal(refused({ secret: SECRET, signature: signature.replace(`t=${at}`, `t=${at + 5}`), body, now: at }), "mismatch");
    assert.equal(refused({ secret: SECRET, signature: "", body, now: at }), "malformed");
    assert.equal(refused({ secret: SECRET, signature: `t=${at}`, body, now: at }), "malformed");
    assert.equal(refused({ secret: SECRET, signature: null, body, now: at }), "malformed");
});
