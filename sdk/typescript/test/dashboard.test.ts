// 대시보드가 올라설 조회 API 를 팩토리의 서버가 SDK 로 읽는다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// 함대의 목록 · 인스턴스 하나 · release 의 이력 · 운영의 로그와 서비스의 상태 · 조직의 모습 · rollout 의 목록 · 연결된 클라이언트.
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다.

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
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

/** 테스트에만 쓰는 열쇠와 비밀 */
const FACTORY = "sk_test_factory_sdk_dashboard";
const OTHER = "sk_test_other_sdk_dashboard";
const BANK = "sk_live_bank_sdk_Dash0";

let scratch = "";
let server: ChildProcess | undefined;
let orbital: Orbital;
let stranger: Orbital;
const made: string[] = [];

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

async function rejection(promise: Promise<unknown>): Promise<OrbitalError>
{
    try
    {
        await promise;
    }
    catch (error)
    {
        assert.ok(error instanceof OrbitalError);
        return error;
    }
    assert.fail("받아들였습니다");
}

/** 인스턴스를 세우고 프리뷰 · 승격의 요청 · 승격까지 한다. */
async function shipped(): Promise<{ instance: string; release: string }>
{
    const { id: instance } = await orbital.instances.create({ app: "records", from: "v1" });
    made.push(instance);
    const work = await orbital.works.open({ instance, can: ["source", "preview", "rehearse", "secrets_request"] });
    const { release } = await work.preview();
    await orbital.secrets.set(instance, "BANK_API_KEY", { stage: "production", value: BANK });
    await work.rehearse(release);
    await work.requestPromotion(release);
    await orbital.releases.promote({ instance, release, change: "customer_request", approvedBy: "customer", approver: "담당자 3" });
    return { instance, release };
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-dashboard-"));
    const listen = `127.0.0.1:${await freePort()}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_CONTROL_DB: control,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY},other=${OTHER}`,
            ORBITAL_SEAL_KEY: "07".repeat(32),
            ORBITAL_DEV_MAIL: "outbox",
            ORBITAL_PRODUCTION_LOGS: "service_key",
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url: `http://${listen}`, serviceKey: FACTORY });
    stranger = createOrbital({ url: `http://${listen}`, serviceKey: OTHER });
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

after(async () =>
{
    for (const instance of made)
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

test("함대의 목록과 인스턴스 하나와 이력을 읽고 next 로 이어 받는다", { skip }, async () =>
{
    const { instance, release } = await shipped();
    const { id: plain } = await orbital.instances.create({ app: "records", from: "v1" });
    made.push(plain);
    // 한 쪽에 하나씩 끝까지 따라간다
    const seen: string[] = [];
    let page = await orbital.instances.list({ limit: 1 });
    seen.push(...page.instances.map((row) => row.id));
    while (page.hasMore)
    {
        assert.ok(page.next !== null);
        page = await orbital.instances.list({ limit: 1, after: page.next });
        seen.push(...page.instances.map((row) => row.id));
    }
    assert.ok(seen.includes(instance) && seen.includes(plain));
    assert.equal(new Set(seen).size, seen.length);
    // 줄 하나
    const row = await orbital.instances.get(instance);
    assert.equal(row.version, "v1");
    assert.equal(row.app, "records");
    assert.equal(row.production?.release, release);
    assert.ok((row.production?.promotedAt ?? 0) > 0);
    assert.equal(row.lastPromotion?.outcome, "promoted");
    assert.equal(row.promotionRequested, null);
    assert.equal((await orbital.instances.get(plain)).production, null);
    // 다른 조직에게는 없는 것과 같다
    assert.equal((await rejection(stranger.instances.get(instance))).status, 404);
    assert.deepEqual((await stranger.instances.list()).instances, []);
    // 이력: 승격 한 줄, 승인한 사람의 이름표와 요청한 작업이 있다
    const history = await orbital.instances.history(instance);
    assert.equal(history.history.length, 1);
    assert.equal(history.hasMore, false);
    assert.equal(history.next, 1);
    const [line] = history.history;
    assert.ok(line !== undefined && line.kind === "promoted");
    assert.equal(line.n, 1);
    assert.equal(line.release, release);
    assert.equal(line.approver, "담당자 3");
    assert.equal(line.approvedBy, "customer");
    // 요청한 작업의 식별자(토큰의 sha256 앞 16바이트)다. 토큰 자체는 아니다
    assert.match(line.requestedBy ?? "", /^[0-9a-f]{32}$/);
    assert.ok(line.changes.length > 0);
    assert.equal(line.rehearsal, "not_needed");
    assert.deepEqual((await orbital.instances.history(instance, { after: 1 })).history, []);
    assert.ok(!JSON.stringify(history).includes(BANK));
});

test("운영의 로그와 서비스의 상태와 조직의 모습과 rollout 의 목록과 연결된 클라이언트를 읽는다", { skip }, async () =>
{
    const { instance, release } = await shipped();
    const logs = await orbital.production.logs(instance, { lines: 5 });
    assert.equal(logs.release, release);
    assert.equal(logs.serverLogs, true);
    assert.deepEqual(logs.logs.map((log) => log.name), ["build-web", "production-web"]);
    assert.ok(logs.logs.every((log) => log.text.split("\n").length <= 5));
    assert.ok(!JSON.stringify(logs).includes(scratch));
    assert.equal((await rejection(orbital.production.logs(instance, { lines: 0 }))).status, 422);
    assert.equal((await rejection(stranger.production.logs(instance))).status, 404);
    const services = await orbital.production.services(instance);
    assert.equal(services.release, release);
    assert.equal(services.services[0]?.name, "web");
    assert.ok(["awake", "asleep"].includes(services.services[0]?.state ?? ""));
    // 조직의 모습: 설정에만 있는 조직이다
    const organization = await orbital.organization.get();
    assert.equal(organization.id, "factory");
    assert.equal(organization.recorded, false);
    assert.equal(organization.kind, "live");
    assert.equal(organization.instanceLimit, null);
    assert.ok(organization.instances >= 1);
    // rollout 은 아직 없다
    assert.deepEqual(await orbital.rollouts.list(), { rollouts: [], next: null, hasMore: false });
    // 연결된 클라이언트: 아직 없다. 다른 조직에게는 없는 것과 같다
    assert.deepEqual(await orbital.oauthClients.grants(instance), []);
    assert.equal((await rejection(stranger.oauthClients.grants(instance))).status, 404);
});
