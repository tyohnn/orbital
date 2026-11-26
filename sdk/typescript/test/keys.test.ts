// 대시보드가 가입을 받아 조직을 만들고, 팩토리가 제 키를 다루는 한 바퀴를 SDK 로 돈다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// 판정의 경계는 Rust 의 테스트(`crates/orbital-server/tests/organizations.rs`)가 잰다. 여기서는 길과 모양만 맞춘다.
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

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
import type { OrbitalAdmin } from "../src/server.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const ADMIN = "admin_key_for_sdk_tests_0123456789abcdef";

let scratch = "";
let server: ChildProcess | undefined;
let url = "";
let admin: OrbitalAdmin;

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

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-keys-"));
    const listen = `127.0.0.1:${await freePort()}`;
    // 환경 변수의 service key 없이 운영자 키만으로 뜬다. 대시보드가 붙는 레이어의 모양이다
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
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
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

test("가입한 팩토리가 첫 키로 키를 더 만들고 앞의 키를 폐기한다", { skip }, async () =>
{
    let created: Awaited<ReturnType<OrbitalAdmin["organizations"]["create"]>> | undefined;
    for (let attempt = 0; created === undefined; attempt += 1)
    {
        try
        {
            created = await admin.organizations.create({ id: "acme", label: "Acme" });
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
