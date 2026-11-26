// 팩토리의 서버가 SDK 로 레이어의 복구 훈련을 본다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// 훈련이 통과한 레이어를 띄우는 것(WAL 보관을 켠 클러스터 · 기반 백업 · 시점 복구)은 Rust 의 테스트(`crates/orbital-server/tests/backup.rs`)가 잰다.
// 여기서는 길과 모양만 맞춘다. `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다.

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
/** 이 테스트의 `orbitald` 가 기록을 두는 control database. */
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_factory";

let scratch = "";
let server: ChildProcess | undefined;
let orbital: Orbital;

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-backup-"));
    const listen = `127.0.0.1:${await freePort()}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_CONTROL_DB: control,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY}`,
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url: `http://${listen}`, serviceKey: FACTORY });
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

test("훈련이 돈 적 없는 레이어는 낡았다고 답한다", { skip }, async () =>
{
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            const backup = await orbital.backup.get();
            assert.deepEqual(backup, { fresh: false, lastPassedAt: null, lastDrill: null });
            break;
        }
        catch (error)
        {
            if (error instanceof OrbitalError || error instanceof assert.AssertionError || attempt > 100)
            {
                throw error;
            }
            await new Promise((done) => setTimeout(done, 50));
        }
    }
    // 백업을 켜지 않은 레이어에서 되살리기는 409 로 거절된다(없는 인스턴스는 404)
    const refused: unknown = await orbital.instances.restore("i0000000000", { at: 1 }).then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(refused instanceof OrbitalError);
    assert.equal(refused.status, 404);
    // 무르는 길도 같다
    const undone: unknown = await orbital.instances.undoRestore("i0000000000").then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(undone instanceof OrbitalError);
    assert.equal(undone.status, 404);
});
