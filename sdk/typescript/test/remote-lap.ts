// 이미 떠 있는 레이어에 밖에서 붙어 한 바퀴를 돈다. 테스트가 아니라 실물 확인용 스크립트다(`node --test` 가 줍지 않는 이름이다).
//
//   ORBITAL_URL=https://<레이어의 바깥 주소> ORBITAL_SERVICE_KEY=… node sdk/typescript/test/remote-lap.ts open
//   ORBITAL_URL=… ORBITAL_INSTANCE=… ORBITAL_TOKEN=… node sdk/typescript/test/remote-lap.ts agent
//   ORBITAL_URL=… ORBITAL_SERVICE_KEY=… node sdk/typescript/test/remote-lap.ts promote <인스턴스> <release>
//   ORBITAL_URL=… ORBITAL_SERVICE_KEY=… node sdk/typescript/test/remote-lap.ts destroy <인스턴스>
//
// 팩토리의 서버(`open` · `promote` · `destroy`, SDK 와 service key)와 작업의 걸음(`agent`, 작업의 토큰과 `git`)은
// 서로 다른 기계일 수 있어서 걸음을 나눴다. 에이전트는 레이어를 직접 부르지 않으므로 `agent` 는 팩토리의 서버가 작업의 토큰으로 하는 일을 흉내 낸다. 스캐폴드는 한 바퀴 테스트의 것(`fixtures/todo`)이다.
// 운영의 앱에 사람으로 들어가 보는 일은 하지 않는다. 그 주소가 밖에서 닿는지는 레이어를 세운 자리마다 다르다.
// 걸음마다 걸린 시간을 JSON 한 줄로 찍는다. `open` 의 줄에는 에이전트에게 건넬 토큰이 실린다.

import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { createOrbital } from "../src/server.ts";

function need(name: string): string
{
    const value = process.env[name];
    if (value === undefined || value === "")
    {
        throw new Error(`환경 변수 \`${name}\` 이 없습니다`);
    }
    return value;
}

const root = resolve(import.meta.dirname, "../../..");
const url = need("ORBITAL_URL");
const factory = (): ReturnType<typeof createOrbital> => createOrbital({ url, serviceKey: need("ORBITAL_SERVICE_KEY") });
const scratch = mkdtempSync(join(tmpdir(), "orbital-remote-"));
const took: Record<string, number> = {};

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

async function step<T>(name: string, work: () => T | Promise<T>): Promise<T>
{
    const started = Date.now();
    try
    {
        return await work();
    }
    finally
    {
        took[name] = Date.now() - started;
    }
}

const [phase, ...rest] = process.argv.slice(2);
try
{
    if (phase === "open")
    {
        const orbital = factory();
        const scaffold = join(scratch, "scaffold");
        cpSync(join(root, "crates/orbital-server/tests/fixtures/todo"), scaffold, { recursive: true });
        git(scaffold, "init", "--quiet", "--initial-branch", "main");
        git(scaffold, "add", "-A");
        git(scaffold, "commit", "--quiet", "-m", "스캐폴드 v1");
        git(scaffold, "tag", "v1");
        git(scaffold, "bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
        await step("scaffold_put", () => orbital.apps.put("todo", readFileSync(join(scratch, "scaffold.bundle"))));
        const instance = await step("instance_create", () => orbital.instances.create({ app: "todo", from: "v1" }));
        const session = await step("session_open", () =>
            orbital.sessions.open({ instance: instance.id, can: ["source", "preview", "rehearse"], ttlSeconds: 7200 }),
        );
        console.log(JSON.stringify({ instance: instance.id, token: session.token, took_ms: took }));
    }
    else if (phase === "agent")
    {
        // 작업의 자리에는 주소 · 인스턴스 · 토큰만 있다. git 은 레이어의 git 의 길에 토큰을 머리말로 싣고, 나머지는 작업의 토큰으로 부른다
        const instance = need("ORBITAL_INSTANCE");
        const token = need("ORBITAL_TOKEN");
        const base = `${url.replace(/\/+$/, "")}/v1/instances/${encodeURIComponent(instance)}`;
        const auth = ["-c", `http.extraHeader=Authorization: Bearer ${token}`];
        const as = async (path: string, body?: unknown): Promise<Record<string, unknown>> =>
        {
            const response = await fetch(`${base}${path}`, {
                method: "POST",
                headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
                body: body === undefined ? null : JSON.stringify(body),
            });
            const reply = (await response.json().catch(() => ({}))) as Record<string, unknown>;
            if (!response.ok)
            {
                throw new Error(`${path} 가 ${response.status} 로 답했습니다: ${JSON.stringify(reply)}`);
            }
            return reply;
        };
        await step("clone", () => git(scratch, ...auth, "clone", "--quiet", `${base}/git`, "work"));
        const work = join(scratch, "work");
        const source = readFileSync(join(work, "server.js"), "utf8");
        writeFileSync(join(work, "server.js"), source.replace("version: 1", "version: 2"));
        git(work, "commit", "--quiet", "-am", "버전을 올린다");
        await step("push", () => git(work, ...auth, "push", "--quiet", "origin", "HEAD:main"));
        const preview = await step("preview", () => as("/previews"));
        const release = typeof preview.release === "string" ? preview.release : "";
        await step("rehearse", () => as("/rehearsals", { release }));
        await step("request_promotion", () => as("/promotion-requests", { release }));
        console.log(JSON.stringify({ release, took_ms: took }));
    }
    else if (phase === "promote")
    {
        const orbital = factory();
        const [instance = "", release = ""] = rest;
        const pending = await step("pending", () => orbital.releases.pending(instance));
        if (pending?.release !== release)
        {
            throw new Error("기다리는 release 가 프리뷰의 것과 다릅니다");
        }
        const production = await step("promote", () =>
            orbital.releases.promote({ instance, release, change: "customer_request", approvedBy: "customer" }),
        );
        console.log(JSON.stringify({
            passed: production.release === release,
            migrations: production.migrations.length,
            changes: pending.changes.length,
            services: production.services.map((service) => ({ kind: service.kind, url: service.url })),
            took_ms: took,
        }));
    }
    else if (phase === "destroy")
    {
        await factory().instances.destroy(rest[0] ?? "");
    }
    else
    {
        throw new Error("걸음을 적어 주세요: open · agent · promote · destroy");
    }
}
finally
{
    rmSync(scratch, { recursive: true, force: true });
}
