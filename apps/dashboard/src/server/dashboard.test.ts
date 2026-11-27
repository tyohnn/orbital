// 대시보드가 하는 일을 실제 관리 서버(`orbitald`)에 붙여 잰다. 대시보드의 기록은 메모리 구현이다(Postgres 구현은 계약 테스트가 잰다).
// `ORBITAL_PG` 가 없으면 관리 서버를 띄우지 못해 건너뛴다. `npm run test:dashboard` 가 orbitald 를 먼저 짓는다.

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

import { createOrbital, createOrbitalAdmin } from "@harmony/orbital/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { DASHBOARD_KEY_LABEL, createDashboard } from "./dashboard.ts";
import type { Dashboard } from "./dashboard.ts";
import { sealerFromHex } from "./seal.ts";
import { MemoryStore } from "./store.ts";
import type { Account } from "./store.ts";

const root = resolve(import.meta.dirname, "../../../..");
const orbitald = join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", "orbitald");
const pg = process.env.ORBITAL_PG;
const ADMIN = "admin_key_for_dashboard_tests_0123456789";

const ana: Account = { id: "00000000-0000-4000-8000-00000000000a", email: "ana@factory.example" };
const ben: Account = { id: "00000000-0000-4000-8000-00000000000b", email: "Ben@Factory.example" };
const cho: Account = { id: "00000000-0000-4000-8000-00000000000c", email: "cho@elsewhere.example" };

let scratch = "";
let server: ChildProcess | undefined;
let url = "";
let store: MemoryStore;
let dashboard: Dashboard;
let counter = 0;

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

/** 테스트마다 다른 팩토리 이름. 관리 서버 하나를 함께 쓴다. */
const fresh = (): string => `factory-${process.pid}-${(counter += 1)}`;

const value = <T>(result: { ok: true; value: T } | { ok: false; reason: string }): T =>
{
    if (!result.ok)
    {
        throw new Error(`거절됐습니다: ${result.reason}`);
    }
    return result.value;
};

describe.skipIf(pg === undefined)("대시보드", () =>
{
    beforeAll(async () =>
    {
        scratch = mkdtempSync(join(tmpdir(), "orbital-dashboard-"));
        const listen = `127.0.0.1:${await freePort()}`;
        server = spawn(orbitald, [], {
            stdio: "ignore",
            env: {
                NODE_ENV: "test",
                PATH: process.env.PATH ?? "",
                ORBITAL_HOME: join(scratch, "home"),
                ORBITAL_PG: pg ?? "",
                ORBITAL_ADMIN_KEY: ADMIN,
                ORBITAL_LISTEN: listen,
            },
        });
        url = `http://${listen}`;
        for (let attempt = 0; ; attempt += 1)
        {
            const up = await fetch(`${url}/v1/keys`).then(() => true, () => false);
            if (up)
            {
                break;
            }
            if (attempt > 200)
            {
                throw new Error("orbitald 가 뜨지 않았습니다");
            }
            await new Promise((done) => setTimeout(done, 50));
        }
    });

    afterAll(() =>
    {
        server?.kill();
        if (scratch !== "")
        {
            rmSync(scratch, { recursive: true, force: true });
        }
    });

    beforeEach(() =>
    {
        store = new MemoryStore();
        dashboard = createDashboard({
            store,
            admin: createOrbitalAdmin({ url, adminKey: ADMIN }),
            orbital: (serviceKey) => createOrbital({ url, serviceKey }),
            sealer: sealerFromHex(randomBytes(32).toString("hex")),
        });
    });

    it("팩토리를 만들면 첫 API 키를 한 번만 보여 주고 다시 보여 주지 않는다", async () =>
    {
        const name = fresh();
        const created = value(await dashboard.createFactory(ana, { name, label: "Acme" }));
        expect(created.factoryId).toBe(name);
        expect(created.firstKey.secret).toMatch(/^orb_sk_/);
        // 그 키로 관리 서버를 부를 수 있다
        expect((await createOrbital({ url, serviceKey: created.firstKey.secret }).keys.list()).length).toBe(2);
        // 목록에는 비밀이 없다
        const keys = value(await dashboard.keys(ana, name));
        expect(JSON.stringify(keys)).not.toContain(created.firstKey.secret);
        expect(keys.every((key) => !("secret" in key))).toBe(true);
        // 만든 사람이 주인이다
        expect(await dashboard.enter(ana)).toEqual([{ factoryId: name, label: "Acme", role: "owner" }]);
    });

    it("이미 있는 팩토리 이름이면 다른 이름을 고르라고 알린다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        expect(await dashboard.createFactory(cho, { name })).toEqual({ ok: false, reason: "name_taken" });
        expect(await dashboard.createFactory(cho, { name: "Not A Name" })).toEqual({ ok: false, reason: "invalid_name" });
        expect(await dashboard.enter(cho)).toEqual([]);
    });

    it("주인이 이메일로 팀원을 초대하면 그 이메일로 들어온 사람이 그 팩토리의 팀원이 된다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        value(await dashboard.invite(ana, name, { email: "ben@factory.example", role: "admin" }));
        expect(value(await dashboard.team(ana, name)).invitations).toEqual([{ email: "ben@factory.example", role: "admin" }]);
        // 대소문자가 달라도 같은 이메일이다
        expect(await dashboard.enter(ben)).toEqual([{ factoryId: name, label: "", role: "admin" }]);
        const team = value(await dashboard.team(ben, name));
        expect(team.invitations).toEqual([]);
        expect(team.members.map((member) => member.role)).toEqual(["owner", "admin"]);
    });

    it("초대받지 않은 이메일은 남의 팩토리에 들어가지 못하고 자기 팩토리를 만들 수만 있다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        value(await dashboard.invite(ana, name, { email: "ben@factory.example", role: "member" }));
        expect(await dashboard.enter(cho)).toEqual([]);
        expect(await dashboard.keys(cho, name)).toEqual({ ok: false, reason: "not_found" });
        const own = fresh();
        value(await dashboard.createFactory(cho, { name: own }));
        expect((await dashboard.enter(cho)).map((one) => one.factoryId)).toEqual([own]);
    });

    it("키를 만들고 폐기하는 것은 주인과 관리자만 하고 멤버는 목록만 본다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        value(await dashboard.invite(ana, name, { email: ben.email, role: "member" }));
        await dashboard.enter(ben);
        expect(value(await dashboard.keys(ben, name)).length).toBe(2);
        expect(await dashboard.createKey(ben, name, { label: "몰래" })).toEqual({ ok: false, reason: "not_allowed" });
        const made = value(await dashboard.createKey(ana, name, { label: "배포 서버" }));
        expect(await dashboard.revokeKey(ben, name, made.id)).toEqual({ ok: false, reason: "not_allowed" });
        // 관리자로 올리면 키를 다룬다
        value(await dashboard.setRole(ana, name, ben.id, "admin"));
        const revoked = value(await dashboard.revokeKey(ben, name, made.id));
        expect(revoked.revokedAt).not.toBeNull();
        // 폐기한 키는 관리 서버가 다음 요청부터 거절한다
        await expect(createOrbital({ url, serviceKey: made.secret }).keys.list()).rejects.toMatchObject({ status: 401 });
    });

    it("대시보드가 쓰는 키는 봉인해 두고 화면에서는 폐기하지 못한다", async () =>
    {
        const name = fresh();
        const created = value(await dashboard.createFactory(ana, { name }));
        const keys = value(await dashboard.keys(ana, name));
        const managed = keys.filter((key) => key.managed);
        expect(managed.map((key) => key.label)).toEqual([DASHBOARD_KEY_LABEL]);
        expect(await dashboard.revokeKey(ana, name, managed[0]?.id ?? "")).toEqual({ ok: false, reason: "dashboard_key" });
        // 기록에는 봉인한 글만 있다
        const stored = await store.factory(name);
        expect(stored?.sealedKey.startsWith("v1.")).toBe(true);
        expect(JSON.stringify(stored)).not.toContain("orb_sk_");
        // 첫 키는 사람의 것이라 폐기해도 대시보드는 계속 돈다
        value(await dashboard.revokeKey(ana, name, created.firstKey.id));
        expect(value(await dashboard.keys(ana, name)).filter((key) => key.revokedAt === null).length).toBe(1);
    });

    it("마지막 주인은 빠지거나 역할을 내리지 못한다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        expect(await dashboard.setRole(ana, name, ana.id, "admin")).toEqual({ ok: false, reason: "last_owner" });
        expect(await dashboard.removeMember(ana, name, ana.id)).toEqual({ ok: false, reason: "last_owner" });
        // 주인이 둘이면 한 사람은 내려간다
        value(await dashboard.invite(ana, name, { email: ben.email, role: "owner" }));
        await dashboard.enter(ben);
        value(await dashboard.setRole(ben, name, ana.id, "member"));
        expect(await dashboard.removeMember(ben, name, ben.id)).toEqual({ ok: false, reason: "last_owner" });
    });

    it("뺀 팀원은 다음 요청부터 그 팩토리를 보지 못한다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        value(await dashboard.invite(ana, name, { email: ben.email, role: "admin" }));
        await dashboard.enter(ben);
        value(await dashboard.removeMember(ana, name, ben.id));
        expect(await dashboard.keys(ben, name)).toEqual({ ok: false, reason: "not_found" });
        expect(await dashboard.team(ben, name)).toEqual({ ok: false, reason: "not_found" });
        expect(await dashboard.enter(ben)).toEqual([]);
    });

    it("팀원은 스스로 나갈 수 있지만 주인이 아니면 남을 빼거나 초대하지 못한다", async () =>
    {
        const name = fresh();
        value(await dashboard.createFactory(ana, { name }));
        value(await dashboard.invite(ana, name, { email: ben.email, role: "admin" }));
        await dashboard.enter(ben);
        expect(await dashboard.removeMember(ben, name, ana.id)).toEqual({ ok: false, reason: "not_allowed" });
        expect(await dashboard.invite(ben, name, { email: cho.email, role: "member" })).toEqual({ ok: false, reason: "not_allowed" });
        expect(await dashboard.invite(ana, name, { email: "not an email", role: "member" })).toEqual({ ok: false, reason: "invalid_email" });
        value(await dashboard.removeMember(ben, name, ben.id));
        expect(await dashboard.enter(ben)).toEqual([]);
    });

    it("다른 팩토리의 키와 팀원은 없는 것처럼 답한다", async () =>
    {
        const mine = fresh();
        const theirs = fresh();
        value(await dashboard.createFactory(ana, { name: mine }));
        const other = value(await dashboard.createFactory(cho, { name: theirs }));
        for (const result of [
            await dashboard.keys(ana, theirs),
            await dashboard.team(ana, theirs),
            await dashboard.createKey(ana, theirs, { label: "x" }),
            await dashboard.revokeKey(ana, theirs, other.firstKey.id),
            await dashboard.invite(ana, theirs, { email: ana.email, role: "owner" }),
            await dashboard.setRole(ana, theirs, cho.id, "member"),
            await dashboard.removeMember(ana, theirs, cho.id),
        ])
        {
            expect(result).toEqual({ ok: false, reason: "not_found" });
        }
        // 내 팩토리의 이름으로 남의 키를 폐기하려 해도 관리 서버가 없는 키로 답한다
        expect(await dashboard.revokeKey(ana, mine, other.firstKey.id)).toEqual({ ok: false, reason: "not_found" });
        expect(value(await dashboard.keys(cho, theirs)).find((key) => key.id === other.firstKey.id)?.revokedAt).toBeNull();
    });
});
