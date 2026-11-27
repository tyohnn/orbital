// 대시보드가 가입을 받아 조직을 만들고, 팩토리가 제 키를 다루는 한 바퀴를 SDK 로 돈다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// 판정의 경계는 Rust 의 테스트(`crates/orbital-server/tests/organizations.rs`)가 잰다. 여기서는 길과 모양만 맞춘다.
// 관리 서버에는 설정의 키(`ORBITAL_SERVICE_KEYS`)를 주지 않고 운영자 키만 준다. 대시보드가 붙는 레이어의 모양이다.
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:sdk` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalError, createOrbital, createOrbitalAdmin } from "../src/server.ts";
import type { Orbital, OrbitalAdmin } from "../src/server.ts";
import { controlDatabase, dropControlDatabase } from "./control.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const ADMIN = "admin_key_for_sdk_tests_0123456789abcdef";

let scratch = "";
let server: ChildProcess | undefined;
let url = "";
let admin: OrbitalAdmin;
/** SDK 가 받은 답의 날것 */
const received: string[] = [];

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

async function refusal(promise: Promise<unknown>): Promise<OrbitalError>
{
    const error: unknown = await promise.then(() => undefined, (caught: unknown) => caught);
    assert.ok(error instanceof OrbitalError, String(error));
    return error;
}

function sdk(serviceKey: string): Orbital
{
    return createOrbital({
        url,
        serviceKey,
        fetch: async (input, init) =>
        {
            const response = await fetch(input, init);
            received.push(await response.clone().text());
            return response;
        },
    });
}

/** 운영자가 조직을 만든다. 관리 서버가 뜨기를 기다린다. 첫 키의 비밀을 돌려준다. */
async function organization(id: string, kind?: "live" | "test"): Promise<string>
{
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            return (await admin.organizations.create(kind === undefined ? { id } : { id, label: `${id} 개발사`, kind })).key.secret;
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
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-keys-"));
    const listen = `127.0.0.1:${await freePort()}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_CONTROL_DB: control,
            ORBITAL_ADMIN_KEY: ADMIN,
            ORBITAL_LISTEN: listen,
        },
    });
    url = `http://${listen}`;
    admin = createOrbitalAdmin({ url, adminKey: ADMIN });
});

after(() =>
{
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

test("가입한 팩토리가 첫 키로 키를 더 만들고 앞의 키를 폐기한다", { skip }, async () =>
{
    // 관리 서버가 뜨기를 기다린다
    await organization("acme-warmup");
    const created = await admin.organizations.create({ id: "acme", label: "Acme" });
    assert.equal(created.organization, "acme");
    assert.match(created.key.secret, /^orb_sk_/);
    assert.equal(created.key.revokedAt, null);

    const first = createOrbital({ url, serviceKey: created.key.secret });
    const deploy = await first.keys.create({ label: "배포 서버" });
    assert.equal(deploy.label, "배포 서버");
    const listed = await first.keys.list();
    assert.deepEqual(listed.map((key) => key.id), [created.key.id, deploy.id]);
    assert.ok(listed.every((key) => !("secret" in key)));

    const second = createOrbital({ url, serviceKey: deploy.secret });
    const revoked = await second.keys.revoke(created.key.id);
    assert.equal(typeof revoked.revokedAt, "number");
    assert.equal((await refusal(first.keys.list())).status, 401);
    // 마지막 살아 있는 키는 폐기하지 못한다
    assert.equal((await refusal(second.keys.revoke(deploy.id))).status, 409);
});

test("운영자는 이미 있는 조직을 다시 만들지 못하고, 키를 갈면 앞의 키는 모두 끊긴다", { skip }, async () =>
{
    const globex = await admin.organizations.create({ id: "globex" });
    assert.equal((await refusal(admin.organizations.create({ id: "globex" }))).status, 409);
    assert.equal((await refusal(admin.organizations.issueKey("globex"))).status, 409);
    const fresh = await admin.organizations.resetKeys("globex");
    assert.equal((await refusal(createOrbital({ url, serviceKey: globex.key.secret }).keys.list())).status, 401);
    const keys = await createOrbital({ url, serviceKey: fresh.secret }).keys.list();
    assert.deepEqual(keys.filter((key) => key.revokedAt === null).map((key) => key.id), [fresh.id]);
    // service key 로는 운영자의 길을 부르지 못한다
    const pretender = createOrbitalAdmin({ url, adminKey: fresh.secret });
    assert.equal((await refusal(pretender.organizations.create({ id: "other" }))).status, 401);
});

test("열쇠를 내면 값은 그 답에만 있고 목록에는 값 없이 오른다", { skip }, async () =>
{
    const first = await organization("sdk_listing", "test");
    const orbital = sdk(first);
    const issued = await orbital.keys.create({ label: "배포 서버" });
    assert.match(issued.secret, /^orb_sk_/);
    assert.equal(issued.label, "배포 서버");
    assert.ok(issued.createdAt > 0);
    const keys = await orbital.keys.list();
    assert.equal(keys.length, 2);
    const listed = keys.find((key) => key.id === issued.id);
    assert.deepEqual(
        { label: listed?.label, revokedAt: listed?.revokedAt },
        { label: "배포 서버", revokedAt: null },
    );
    // 목록을 받은 키는 방금 쓴 때가 적혔다
    assert.equal(typeof keys.find((key) => key.id !== issued.id)?.usedAt, "number");
    // 낸 답 하나 밖에는 값이 없다
    const answers = received.filter((answer) => !answer.includes(`"secret":"${issued.secret}"`));
    for (const value of [first, issued.secret])
    {
        assert.ok(!answers.some((answer) => answer.includes(value.slice("orb_sk_".length))), "값이 목록의 답에 새었습니다");
    }
    // 이름이 너무 길면 무엇을 고칠지와 함께 거절된다. 이름 없이는 낸다
    const long = await refusal(orbital.keys.create({ label: "가".repeat(101) }));
    assert.deepEqual([long.status, long.code], [400, "invalid"]);
    assert.equal((await orbital.keys.create()).label, "");
});

test("새 열쇠로 옛 열쇠를 거두면 옛 열쇠의 다음 요청은 거절된다", { skip }, async () =>
{
    const old = sdk(await organization("sdk_rotating", "live"));
    const issued = await old.keys.create({ label: "새 키" });
    const fresh = sdk(issued.secret);
    // 둘이 함께 산다
    const [oldKey] = (await fresh.keys.list()).filter((key) => key.id !== issued.id);
    assert.ok(oldKey !== undefined);
    assert.equal((await old.keys.list()).length, 2);
    const revoked = await fresh.keys.revoke(oldKey.id);
    assert.equal(typeof revoked.revokedAt, "number");
    const refused = await refusal(old.keys.list());
    assert.deepEqual([refused.status, refused.code], [401, "unauthorized"]);
    assert.match(refused.message, /폐기한/);
    assert.equal((await fresh.keys.list()).length, 2);
});

test("살아 있는 마지막 열쇠는 거둘 수 없고 다른 조직의 열쇠는 없는 것과 같다", { skip }, async () =>
{
    const mine = sdk(await organization("sdk_last", "live"));
    const theirs = sdk(await organization("sdk_neighbour", "live"));
    const [only] = await mine.keys.list();
    assert.ok(only !== undefined);
    const last = await refusal(mine.keys.revoke(only.id));
    assert.deepEqual([last.status, last.code], [409, "conflict"]);
    const other = await refusal(theirs.keys.revoke(only.id));
    const unknown = await refusal(theirs.keys.revoke("key_0000000000000000"));
    assert.deepEqual([other.status, other.code, other.message], [unknown.status, unknown.code, unknown.message]);
    assert.equal(other.status, 404);
    assert.ok((await theirs.keys.list()).every((key) => key.id !== only.id));
    assert.equal((await mine.keys.list())[0]?.revokedAt, null);
});

test("운영자는 시험용 조직을 만들어 보고 인스턴스가 없으면 닫는다", { skip }, async () =>
{
    const secret = await organization("sdk_sandbox", "test");
    const report = await admin.organizations.get("sdk_sandbox");
    assert.deepEqual(
        { name: report.name, kind: report.kind, closedAt: report.closedAt, instances: report.instances, keys: report.keys },
        { name: "sdk_sandbox 개발사", kind: "test", closedAt: null, instances: 0, keys: 1 },
    );
    assert.ok((await admin.organizations.list()).some((organization) => organization.id === "sdk_sandbox"));
    const closed = await admin.organizations.close("sdk_sandbox");
    assert.equal(typeof closed.closedAt, "number");
    const refused = await refusal(createOrbital({ url, serviceKey: secret }).keys.list());
    assert.equal(refused.status, 401);
    assert.match(refused.message, /닫힌/);
    assert.equal((await refusal(admin.organizations.get("nobody"))).status, 404);
});
