// 팩토리의 서버가 하듯이 SDK 를 쓰고, 에이전트가 하듯이 `orbital` CLI 를 쓴다. 둘 다 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:sdk` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalError, createOrbital } from "../src/server.ts";
import type { Orbital } from "../src/server.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_factory";
const OTHER_FACTORY = "sk_test_other";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
let orbital: Orbital;
const instances: string[] = [];

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

/** 에이전트의 sandbox 에는 주소 · 인스턴스 · 토큰만 있다. */
function agent(folder: string, instance: string, token: string, ...args: string[]): string
{
    return execFileSync(bin("orbital"), args, {
        cwd: folder,
        encoding: "utf8",
        env: { PATH: process.env.PATH ?? "", ORBITAL_URL: url, ORBITAL_INSTANCE: instance, ORBITAL_TOKEN: token },
    });
}

function wordAfter(text: string, marker: string): string
{
    return text.split(marker)[1]?.trim().split(/\s+/)[0] ?? "";
}

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

async function rejection(work: Promise<unknown>): Promise<OrbitalError>
{
    const caught: unknown = await work.then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(caught instanceof OrbitalError, "OrbitalError 로 거절되어야 합니다");
    return caught;
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-"));
    const listen = `127.0.0.1:${await freePort()}`;
    url = `http://${listen}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY},other=${OTHER_FACTORY}`,
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url, serviceKey: FACTORY });

    // 팩토리가 스캐폴드를 만들어 v1 을 달고 올린다. 서버가 듣기 시작할 때까지 잠깐 되풀이한다
    const scaffold = join(scratch, "scaffold");
    cpSync(join(root, "crates/orbital-server/tests/fixtures/todo"), scaffold, { recursive: true });
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
            if (error instanceof OrbitalError || attempt > 100)
            {
                throw error;
            }
            await new Promise((done) => setTimeout(done, 50));
        }
    }
});

after(async () =>
{
    for (const instance of instances)
    {
        await orbital.instances.destroy(instance).catch(() => undefined);
    }
    server?.kill();
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

test("팩토리의 서버가 인스턴스를 세워 토큰을 내고 에이전트가 올린 것을 승인받아 운영에 올린다", { skip }, async () =>
{
    // 고객이 가입한다
    const instance = await orbital.instances.create({ app: "todo", from: "v1" });
    instances.push(instance.id);
    assert.match(instance.id, /^[a-z0-9]{8,12}$/);
    assert.equal(await orbital.production.get(instance.id), null);
    assert.equal(await orbital.releases.pending(instance.id), null);

    // 에이전트의 작업을 연다. 토큰은 두 시간짜리로 달라고 했다
    const asked = Math.floor(Date.now() / 1000);
    const session = await orbital.sessions.open({
        instance: instance.id,
        can: ["source", "preview", "rehearse"],
        ttlSeconds: 7200,
    });
    assert.ok(session.token.startsWith("orb1."));
    assert.ok(session.expiresAt >= asked + 7200 && session.expiresAt <= asked + 7260);

    // 에이전트가 코드를 받아 고쳐 올리고, 미리보기를 세우고, 승격을 요청한다
    agent(scratch, instance.id, session.token, "clone", "work");
    const work = join(scratch, "work");
    const source = readFileSync(join(work, "server.js"), "utf8");
    writeFileSync(join(work, "server.js"), source.replace("version: 1", "version: 2"));
    git(work, "commit", "--quiet", "-am", "버전을 올린다");
    agent(work, instance.id, session.token, "push");
    const preview = agent(work, instance.id, session.token, "preview");
    const release = wordAfter(preview, "release ");
    agent(work, instance.id, session.token, "request-promotion", release);

    // 승인 화면에 세울 것이 온다
    const pending = await orbital.releases.pending(instance.id);
    assert.deepEqual(pending, {
        release,
        commit: git(work, "rev-parse", "HEAD"),
        changes: ["`member` 역할이 `todo.card` 표를 자기 행을 읽을 수 있게 됩니다 그리고 자기 행을 고칠 수 있게 됩니다"],
        migrations: ["001_card.sql"],
    });

    // 고객의 요청은 고객이 승인한다. 팩토리의 승인으로는 오르지 않고 까닭이 돌아온다
    const refused = await rejection(
        orbital.releases.promote({
            instance: instance.id,
            release,
            change: "customer_request",
            approvedBy: "factory",
        }),
    );
    assert.deepEqual(
        [refused.status, refused.code, refused.message],
        [409, "denied", "이 변경은 고객이 승인해야 합니다"],
    );
    assert.equal(await orbital.production.get(instance.id), null);

    // 사람이 승인했다
    const production = await orbital.releases.promote({
        instance: instance.id,
        release,
        change: "customer_request",
        approvedBy: "customer",
    });
    assert.equal(production.release, release);
    assert.deepEqual(production.migrations, ["001_card.sql"]);
    assert.equal(production.services[0]?.kind, "server");
    const live = production.services[0]?.url ?? "";
    assert.equal(await orbital.releases.pending(instance.id), null);
    assert.equal((await orbital.production.get(instance.id))?.release, release);

    // 운영의 앱이 돌고, 서명한 신원으로 자기 카드만 읽고 쓴다
    const health = (await (await fetch(`${live}/health`)).json()) as { version: number };
    assert.equal(health.version, 2);
    const identity = await orbital.production.identity({ instance: instance.id, subject: "u9" });
    const written = await fetch(`${live}/cards`, {
        method: "POST",
        headers: { "x-orbital-identity": identity },
        body: "첫 일",
    });
    assert.equal(written.status, 201);
    const other = await orbital.production.identity({ instance: instance.id, subject: "u8" });
    const cards = async (who: string): Promise<unknown[]> =>
        (await (await fetch(`${live}/cards`, { headers: { "x-orbital-identity": who } })).json()) as unknown[];
    assert.equal((await cards(identity)).length, 1);
    assert.equal((await cards(other)).length, 0);
});

test("다른 팩토리의 service key 로는 인스턴스가 없는 것으로 보인다", { skip }, async () =>
{
    const instance = await orbital.instances.create({ app: "todo", from: "v1" });
    instances.push(instance.id);
    const stranger = createOrbital({ url, serviceKey: OTHER_FACTORY });

    const attempts: (() => Promise<unknown>)[] = [
        () => stranger.production.get(instance.id),
        () => stranger.releases.pending(instance.id),
        () => stranger.sessions.open({ instance: instance.id, can: ["source"] }),
        () => stranger.instances.destroy(instance.id),
    ];
    for (const attempt of attempts)
    {
        const refused = await rejection(attempt());
        assert.deepEqual([refused.status, refused.code], [404, "not_found"]);
    }
    // 걷히지 않았다
    assert.equal(await orbital.production.get(instance.id), null);
});

test("모르는 service key 와 없는 스캐폴드 버전은 까닭과 함께 거절된다", { skip }, async () =>
{
    const nobody = createOrbital({ url, serviceKey: "sk_test_nobody" });
    const refused = await rejection(nobody.instances.create({ app: "todo", from: "v1" }));
    assert.equal(refused.status, 401);

    const missing = await rejection(orbital.instances.create({ app: "todo", from: "v999" }));
    assert.deepEqual([missing.status, missing.code], [422, "problems"]);
    // 무엇을 고칠지는 details 에 문장으로 온다
    assert.match(missing.details.join("\n"), /v999/);
});
