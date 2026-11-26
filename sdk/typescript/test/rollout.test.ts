// 팩토리의 서버가 SDK 로 앱의 업데이트 하나를 포크 셋에 밀고, 포크마다 작업을 열어 프리뷰를 세운다. 에이전트의 `git` 은 팩토리의 주소로 붙는다.
// 한 곳이 적합성 테스트에서 떨어지면 rollout 이 멈추고, 통과한 곳만 오른다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
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
import type { Orbital, PreviewReport, Work } from "../src/server.ts";
import { git as agentGit, startRelay } from "./relay.ts";
import type { Relay } from "./relay.ts";
import { controlDatabase, dropControlDatabase } from "./control.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const fixtures = join(root, "crates/orbital-server/tests/fixtures");
const pg = process.env.ORBITAL_PG;
/** 이 테스트의 `orbitald` 가 기록을 두는 control database. */
const control = controlDatabase();
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_factory";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
let orbital: Orbital;
let relay: Relay | undefined;
const instances: string[] = [];

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

async function rejection(work: Promise<unknown>): Promise<OrbitalError>
{
    const caught: unknown = await work.then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(caught instanceof OrbitalError, "OrbitalError 로 거절되어야 합니다");
    return caught;
}

/** 앱(위쪽)을 고치는 폴더의 버전을 모두 묶어 올린다. */
async function publish(folder: string): Promise<void>
{
    const bundle = join(scratch, `fleet-${Date.now()}.bundle`);
    git(folder, "bundle", "create", "--quiet", bundle, "--all");
    const bytes = readFileSync(bundle);
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            await orbital.apps.put("fleet", bytes);
            return;
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
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-rollout-"));
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
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url, serviceKey: FACTORY });
    relay = await startRelay();
    const upstream = join(scratch, "upstream");
    cpSync(join(fixtures, "fleet"), upstream, { recursive: true });
    git(upstream, "init", "--quiet", "--initial-branch", "main");
    git(upstream, "add", "-A");
    git(upstream, "commit", "--quiet", "-m", "스캐폴드 v1");
    git(upstream, "tag", "v1");
    await publish(upstream);
});

after(async () =>
{
    for (const instance of instances)
    {
        await orbital.instances.destroy(instance).catch(() => undefined);
    }
    await relay?.close();
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

interface Fork
{
    instance: string;
    session: Work;
    work: string;
}

/** 고객 하나의 인스턴스를 세우고 작업을 연다. 에이전트가 `custom.json` 을 고쳐 git 으로 올린다. */
async function fork(name: string, custom: Record<string, unknown>): Promise<Fork>
{
    const { id: instance } = await orbital.instances.create({ app: "fleet", from: "v1" });
    instances.push(instance);
    const session = await orbital.works.open({ instance, can: ["source", "preview"] });
    const work = join(scratch, name);
    await agentGit(scratch, "clone", "--quiet", relay?.remote(session) ?? "", work);
    writeFileSync(join(work, "custom.json"), JSON.stringify(custom));
    await agentGit(work, "commit", "--quiet", "-am", "고객의 손길");
    await agentGit(work, "push", "--quiet", "origin", "main");
    return { instance, session, work };
}

/** 에이전트가 레이어가 합친 commit 을 받고, 팩토리의 서버가 프리뷰를 세운다. */
async function preview(fork: Fork): Promise<PreviewReport>
{
    await agentGit(fork.work, "pull", "--quiet", "--no-rebase", "--no-edit", "origin", "main");
    return await fork.session.preview();
}

/** 거절의 글과 까닭을 한 글로. */
async function refusalText(work: Promise<unknown>): Promise<string>
{
    const refused = await rejection(work);
    return [refused.message, ...refused.details].join("\n");
}

test("포크 셋에 업데이트를 밀어 통과한 곳만 오른다", { skip }, async () =>
{
    const a = await fork("a", { greeting: "A사입니다" });
    const b = await fork("b", { greeting: "B사입니다" });
    // c 는 업데이트의 새 기능을 깨뜨리는 설정을 갖고 있다
    const c = await fork("c", { greeting: "C사입니다", break_feature: true });

    // 팩토리가 보안 업데이트(v2)를 앱에 올린다
    const upstream = join(scratch, "upstream");
    cpSync(join(fixtures, "fleet-update"), upstream, { recursive: true });
    git(upstream, "add", "-A");
    git(upstream, "commit", "--quiet", "-m", "업데이트 v2");
    git(upstream, "tag", "v2");
    await publish(upstream);
    const update = git(upstream, "rev-parse", "HEAD");

    const rollout = await orbital.rollouts.create("fleet", {
        change: "security_update",
        waves: [[a.instance], [b.instance, c.instance]],
    });
    assert.equal(rollout.commit, update);
    assert.equal(rollout.status, "running");
    assert.deepEqual(rollout.waves, [[a.instance], [b.instance, c.instance]]);
    for (const { instance } of [a, b, c])
    {
        const applied = await orbital.rollouts.apply(rollout.id, instance);
        assert.equal(applied.applied, true);
        assert.deepEqual(applied.conflicts, []);
    }

    // 앞 물결: 통과하고 팩토리의 승인으로 오른다. 승인 화면은 어느 rollout 의 것인지 안다
    const shown = await preview(a);
    assert.deepEqual(shown.blockers, []);
    assert.equal(shown.conformance?.passed, true);
    const releaseA = shown.release;
    await a.session.requestPromotion(releaseA);
    assert.equal((await orbital.releases.pending(a.instance))?.rollout, rollout.id);
    const productionA = await orbital.releases.promote({ instance: a.instance, release: releaseA, change: "security_update", approvedBy: "factory" });
    const live = productionA.services[0]?.url ?? "";
    assert.equal((await fetch(`${live}/feature`)).status, 200);
    assert.deepEqual(await (await fetch(`${live}/greeting`)).json(), { greeting: "A사입니다" });

    // 뒤 물결: c 가 적합성 테스트에서 떨어져 rollout 이 멈추고, 통과한 b 도 오르지 못한다
    const releaseB = (await preview(b)).release;
    await b.session.requestPromotion(releaseB);
    const shownC = await preview(c);
    assert.match(shownC.blockers.join("\n"), /적합성 테스트/);
    assert.equal(shownC.conformance?.passed, false);
    assert.match(await refusalText(c.session.requestPromotion(shownC.release)), /적합성 테스트/);
    const halted = await orbital.rollouts.get(rollout.id);
    assert.equal(halted.status, "halted");
    assert.deepEqual(halted.instances.find((entry) => entry.instance === c.instance), {
        instance: c.instance,
        state: "failed",
        reason: "conformance_failed",
    });
    const refused = await rejection(
        orbital.releases.promote({ instance: b.instance, release: releaseB, change: "security_update", approvedBy: "factory" }),
    );
    assert.equal(refused.status, 409);
    assert.match(refused.message, /멈춰/);
    assert.equal(await orbital.production.get(b.instance), null);

    // 팩토리가 다시 열면 b 가 오르고, c 는 고친 release 로 다시 지나 오른다
    assert.equal((await orbital.rollouts.resume(rollout.id)).status, "running");
    await orbital.releases.promote({ instance: b.instance, release: releaseB, change: "security_update", approvedBy: "factory" });
    writeFileSync(join(c.work, "custom.json"), JSON.stringify({ greeting: "C사입니다" }));
    await agentGit(c.work, "commit", "--quiet", "-am", "새 기능을 깨뜨리던 설정을 걷는다");
    await agentGit(c.work, "push", "--quiet", "origin", "main");
    const releaseC = (await preview(c)).release;
    await c.session.requestPromotion(releaseC);
    await orbital.releases.promote({ instance: c.instance, release: releaseC, change: "security_update", approvedBy: "factory" });

    const done = await orbital.rollouts.get(rollout.id);
    assert.equal(done.status, "done");
    assert.deepEqual(done.instances.map((entry) => entry.state), ["promoted", "promoted", "promoted"]);
    // 끝난 rollout 은 더 받지 않는다
    assert.equal((await rejection(orbital.rollouts.cancel(rollout.id))).status, 409);
});
