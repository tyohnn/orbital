// 대시보드의 기록 포트의 계약. 메모리 구현은 늘, Postgres 구현은 `DASHBOARD_DATABASE_URL` 이 있을 때 같은 테스트를 지난다.
// Postgres 는 테스트마다 새 database 를 만들어 `supabase/migrations` 를 적용한다.

import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

import pg from "pg";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { PgStore } from "./pg-store.ts";
import { MemoryStore } from "./store.ts";
import type { Account, Factory, Store } from "./store.ts";

const base = process.env.DASHBOARD_DATABASE_URL;
const migrations = resolve(import.meta.dirname, "../../supabase/migrations");

const ana: Account = { id: "00000000-0000-4000-8000-00000000000a", email: "Ana@Factory.example" };
const ben: Account = { id: "00000000-0000-4000-8000-00000000000b", email: "ben@factory.example" };

const factory = (id: string): Factory => ({ id, label: `${id} 팩토리`, dashboardKeyId: `key_${id}`, sealedKey: "v1.a.b.c" });

let created = 0;
const opened: PgStore[] = [];

async function pgStore(): Promise<Store>
{
    const admin = new pg.Client({ connectionString: base });
    await admin.connect();
    const name = `dashboard_contract_${process.pid}_${(created += 1)}`;
    await admin.query(`drop database if exists ${name}`);
    await admin.query(`create database ${name}`);
    await admin.end();
    const url = new URL(base ?? "");
    url.pathname = `/${name}`;
    const client = new pg.Client({ connectionString: url.toString() });
    await client.connect();
    for (const file of readdirSync(migrations).sort())
    {
        await client.query(readFileSync(join(migrations, file), "utf8"));
    }
    await client.end();
    const store = PgStore.connect(url.toString());
    opened.push(store);
    return store;
}

const kinds: [string, () => Promise<Store>][] = [["메모리", async () => new MemoryStore()]];
if (base !== undefined)
{
    kinds.push(["Postgres", pgStore]);
}

afterAll(async () =>
{
    await Promise.all(opened.map((store) => store.close()));
});

describe.each(kinds)("기록 포트(%s)", (_, make) =>
{
    let store: Store;

    beforeEach(async () =>
    {
        store = await make();
    });

    it("팩토리를 만들면 만든 사람이 주인이고 같은 이름은 다시 만들지 못한다", async () =>
    {
        expect(await store.createFactory(factory("acme"), ana)).toBe(true);
        expect(await store.createFactory(factory("acme"), ben)).toBe(false);
        expect(await store.factory("acme")).toEqual(factory("acme"));
        expect(await store.factory("nobody")).toBeNull();
        expect(await store.members("acme")).toEqual([{ accountId: ana.id, email: "ana@factory.example", role: "owner" }]);
        expect(await store.memberships(ana.id)).toEqual([{ factoryId: "acme", label: "acme 팩토리", role: "owner" }]);
        expect(await store.memberships(ben.id)).toEqual([]);
    });

    it("초대는 이메일의 대소문자를 가리지 않고 받으면 팀원이 되며 초대가 지워진다", async () =>
    {
        await store.createFactory(factory("acme"), ana);
        await store.invite("acme", "BEN@factory.example", "member");
        await store.invite("acme", "ben@factory.example", "admin");
        expect(await store.invitations("acme")).toEqual([{ email: "ben@factory.example", role: "admin" }]);
        expect(await store.acceptInvitations({ ...ben, email: "Ben@Factory.Example" })).toBe(1);
        expect(await store.invitations("acme")).toEqual([]);
        expect((await store.members("acme")).map((member) => member.role)).toEqual(["owner", "admin"]);
        expect(await store.acceptInvitations(ben)).toBe(0);
    });

    it("이미 팀원인 이메일은 초대되지 않는다", async () =>
    {
        await store.createFactory(factory("acme"), ana);
        await store.invite("acme", "ana@factory.example", "member");
        expect(await store.invitations("acme")).toEqual([]);
    });

    it("역할을 바꾸고 팀원을 빼면 그 팩토리의 소속이 사라진다", async () =>
    {
        await store.createFactory(factory("acme"), ana);
        await store.createFactory(factory("globex"), ben);
        await store.invite("acme", ben.email, "member");
        await store.acceptInvitations(ben);
        await store.setRole("acme", ben.id, "admin");
        expect((await store.memberships(ben.id)).map((one) => [one.factoryId, one.role])).toEqual([["acme", "admin"], ["globex", "owner"]]);
        await store.removeMember("acme", ben.id);
        expect((await store.memberships(ben.id)).map((one) => one.factoryId)).toEqual(["globex"]);
    });
});
