// 실제 관리 서버(orbitald)를 7699 에 띄운다. 대시보드는 운영자 키로 이 서버에 조직을 만든다.
// 대시보드의 기록(로컬 Supabase 의 `dashboard` 스키마)은 매번 비운다. 관리 서버의 기록은 매번 새 폴더다.

import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import pg from "pg";

export default async function globalSetup(): Promise<() => Promise<void>>
{
    const root = resolve(import.meta.dirname, "../../..");
    const home = mkdtempSync(join(tmpdir(), "orbital-dashboard-e2e-"));
    const server = spawn(join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", "orbitald"), [], {
        stdio: "inherit",
        env: {
            NODE_ENV: "test",
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: home,
            ORBITAL_PG: process.env.ORBITAL_PG ?? "",
            ORBITAL_ADMIN_KEY: "admin_key_for_dashboard_e2e_0123456789ab",
            ORBITAL_LISTEN: "127.0.0.1:7699",
        },
    });
    const db = new pg.Client({ connectionString: process.env.E2E_DASHBOARD_DATABASE_URL ?? "postgresql://postgres:postgres@127.0.0.1:54422/postgres" });
    await db.connect();
    await db.query("truncate org.factory, org.member, org.invitation cascade");
    await db.end();
    for (let attempt = 0; ; attempt += 1)
    {
        if (await fetch("http://127.0.0.1:7699/v1/keys").then(() => true, () => false))
        {
            break;
        }
        if (attempt > 200)
        {
            throw new Error("orbitald 가 뜨지 않았습니다");
        }
        await new Promise((done) => setTimeout(done, 50));
    }
    return async () =>
    {
        server.kill();
    };
}
