// 조직의 service key 를 팩토리의 서버가 SDK 로 내고 보고 거둔다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// 조직과 첫 열쇠는 레이어의 운영자가 만든다(운영자의 길은 SDK 에 없어 테스트가 HTTP 로 부른다). 관리 서버에는 설정의 열쇠(`ORBITAL_SERVICE_KEYS`)를
// 주지 않는다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:sdk` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalError, createOrbital } from "../src/server.ts";
import type { Orbital } from "../src/server.ts";
import { controlDatabase, dropControlDatabase } from "./control.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

/** 운영자의 열쇠. 테스트에만 쓰는 값이다 */
const OPERATOR = "op_test_operator_key_not_a_secret_0000";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
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

async function rejection(work: Promise<unknown>): Promise<OrbitalError>
{
    const caught: unknown = await work.then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(caught instanceof OrbitalError, "OrbitalError 로 거절되어야 합니다");
    return caught;
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

/** 운영자가 조직을 만든다. 첫 열쇠의 값을 돌려준다. */
async function organization(id: string, kind: "live" | "test"): Promise<string>
{
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            const response = await fetch(`${url}/v1/operator/organizations`, {
                method: "POST",
                headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" },
                body: JSON.stringify({ id, name: `${id} 개발사`, kind }),
            });
            const body = (await response.json()) as { key: { key: string } };
            assert.equal(response.status, 200, JSON.stringify(body));
            return body.key.key;
        }
        catch (error)
        {
            if (error instanceof assert.AssertionError || attempt > 100)
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
    url = `http://${listen}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_CONTROL_DB: control,
            ORBITAL_OPERATOR_KEY: OPERATOR,
            ORBITAL_LISTEN: listen,
        },
    });
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

test("열쇠를 내면 값은 그 답에만 있고 목록에는 값 없이 오른다", { skip }, async () =>
{
    const first = await organization("sdk_listing", "test");
    assert.ok(first.startsWith("sk_test_"));
    const orbital = sdk(first);
    const issued = await orbital.keys.create({ label: "배포 서버" });
    assert.ok(issued.key.startsWith("sk_test_"));
    assert.equal(issued.label, "배포 서버");
    assert.ok(issued.createdAt > 0);
    const keys = await orbital.keys.list();
    assert.equal(keys.length, 2);
    const listed = keys.find((key) => key.id === issued.id);
    assert.deepEqual(
        { label: listed?.label, prefix: listed?.prefix, revokedAt: listed?.revokedAt },
        { label: "배포 서버", prefix: "sk_test_", revokedAt: null },
    );
    // 목록을 받은 열쇠는 방금 쓴 때가 적혔다
    assert.equal(typeof keys.find((key) => key.id !== issued.id)?.usedAt, "number");
    // 낸 답 하나 밖에는 값이 없다
    const answers = received.filter((answer) => !answer.includes(`"id":"${issued.id}","key"`) && !answer.includes(`"key":"${issued.key}"`));
    for (const value of [first, issued.key])
    {
        assert.ok(!answers.some((answer) => answer.includes(value.slice(8))), "값이 목록의 답에 새었습니다");
    }
    // 이름이 비면 무엇을 고칠지와 함께 거절된다
    const empty = await rejection(orbital.keys.create({ label: "   " }));
    assert.deepEqual([empty.status, empty.code], [422, "problems"]);
});

test("새 열쇠로 옛 열쇠를 거두면 옛 열쇠의 다음 요청은 거절된다", { skip }, async () =>
{
    const old = sdk(await organization("sdk_rotating", "live"));
    const issued = await old.keys.create({ label: "새 열쇠" });
    const fresh = sdk(issued.key);
    // 둘이 함께 산다
    const [oldKey] = (await fresh.keys.list()).filter((key) => key.id !== issued.id);
    assert.ok(oldKey !== undefined);
    assert.equal((await old.keys.list()).length, 2);
    const revoked = await fresh.keys.revoke(oldKey.id);
    assert.equal(typeof revoked.revokedAt, "number");
    const refused = await rejection(old.keys.list());
    assert.deepEqual([refused.status, refused.code], [401, "unauthorized"]);
    assert.match(refused.message, /거둔/);
    assert.equal((await fresh.keys.list()).length, 2);
});

test("살아 있는 마지막 열쇠는 거둘 수 없고 다른 조직의 열쇠는 없는 것과 같다", { skip }, async () =>
{
    const mine = sdk(await organization("sdk_last", "live"));
    const theirs = sdk(await organization("sdk_neighbour", "live"));
    const [only] = await mine.keys.list();
    assert.ok(only !== undefined);
    const last = await rejection(mine.keys.revoke(only.id));
    assert.deepEqual([last.status, last.code], [409, "conflict"]);
    const other = await rejection(theirs.keys.revoke(only.id));
    const unknown = await rejection(theirs.keys.revoke("key_0000000000000000"));
    assert.deepEqual([other.status, other.code, other.message], [unknown.status, unknown.code, unknown.message]);
    assert.equal(other.status, 404);
    assert.ok((await theirs.keys.list()).every((key) => key.id !== only.id));
    assert.equal((await mine.keys.list())[0]?.revokedAt, null);
});
