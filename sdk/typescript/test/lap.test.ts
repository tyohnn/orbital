// 팩토리의 서버가 하듯이 SDK 를 쓴다. 에이전트는 레이어를 직접 부르지 않는다: 팩토리의 서버가 작업을 열어 그 함수로 프리뷰와
// 승격 요청을 부르고, 에이전트의 `git` 은 팩토리의 주소(`relay.ts` 의 흉내)로 붙어 `git.relay` 를 지난다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
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
import type { Orbital } from "../src/server.ts";
import { git as agentGit, startRelay } from "./relay.ts";
import type { Relay } from "./relay.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_factory";
const OTHER_FACTORY = "sk_test_other";

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

/** 답의 `Set-Cookie` 가운데 이 이름의 것을 `이름=값` 으로 돌려준다. */
function cookiePair(response: Response, name: string): string
{
    return response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))?.split(";")[0] ?? "";
}

/**
 * 운영의 사람이 하듯이 들어온다. 로그인 링크를 요청하고, 레이어의 개발용 메일함(`ORBITAL_HOME/outbox.jsonl`)에서
 * 링크를 꺼내 같은 브라우저로 연다. 세션 쿠키(`이름=값`)를 돌려준다.
 */
async function signIn(live: string, email: string): Promise<string>
{
    const before = linksTo(email).length;
    const asked = await fetch(`${live}/_orbital/auth/email-link`, {
        method: "POST",
        headers: { origin: live, "content-type": "application/json" },
        body: JSON.stringify({ email }),
    });
    assert.equal(asked.status, 202);
    const browser = cookiePair(asked, "__Host-orbital-browser");
    // 메일은 레이어가 답을 보낸 뒤에 뒤에서 쌓는다
    const deadline = Date.now() + 10_000;
    while (linksTo(email).length <= before && Date.now() < deadline)
    {
        await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const link = linksTo(email).at(-1) ?? "";
    const opened = await fetch(link, { headers: { cookie: browser }, redirect: "manual" });
    assert.equal(opened.status, 302);
    return cookiePair(opened, "__Host-orbital-session");
}

/** 개발용 메일함에 그 이메일로 쌓인 링크. 파일이 아직 없으면 빈 목록이다. */
function linksTo(email: string): string[]
{
    let text = "";
    try
    {
        text = readFileSync(join(scratch, "home", "outbox.jsonl"), "utf8");
    }
    catch
    {
        return [];
    }
    return text
        .trim()
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as { to: string; link: string })
        .filter((mail) => mail.to === email)
        .map((mail) => mail.link);
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

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-"));
    const listen = `127.0.0.1:${await freePort()}`;
    url = `http://${listen}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY},other=${OTHER_FACTORY}`,
            // 팩토리의 메일 키 없이 운영에 올린다. 개발용 메일함을 명시해 켠다
            ORBITAL_DEV_MAIL: "outbox",
            // 팩토리의 키를 봉인하는 열쇠. 테스트에만 쓰는 값이다
            ORBITAL_SEAL_KEY: "07".repeat(32),
            ORBITAL_PUBLIC_URL: "https://layer.example",
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({ url, serviceKey: FACTORY });
    relay = await startRelay();

    // 팩토리가 스캐폴드를 만들어 v1 을 달고 올린다. 서버가 듣기 시작할 때까지 잠깐 되풀이한다
    const scaffold = join(scratch, "scaffold");
    cpSync(join(root, "crates/orbital-server/tests/fixtures/todo"), scaffold, { recursive: true });
    git(scaffold, "init", "--quiet", "--initial-branch", "main");
    git(scaffold, "add", "-A");
    git(scaffold, "commit", "--quiet", "-m", "스캐폴드 v1");
    git(scaffold, "tag", "v1");
    git(scaffold, "bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
    const bundle = readFileSync(join(scratch, "scaffold.bundle"));
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            await orbital.apps.put("todo", bundle);
            break;
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
});

after(async () =>
{
    for (const instance of instances)
    {
        await orbital.instances.destroy(instance).catch(() => undefined);
    }
    await relay?.close();
    server?.kill();
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

test("팩토리의 서버가 인스턴스를 세워 작업을 열고 에이전트가 git 으로 올린 것을 승인받아 운영에 올린다", { skip }, async () =>
{
    // 고객이 가입한다
    const instance = await orbital.instances.create({ app: "todo", from: "v1" });
    instances.push(instance.id);
    assert.match(instance.id, /^[a-z0-9]{8,12}$/);
    assert.equal(await orbital.production.get(instance.id), null);
    assert.equal(await orbital.releases.pending(instance.id), null);

    // 에이전트의 작업을 연다. 두 시간짜리로 달라고 했다
    const asked = Math.floor(Date.now() / 1000);
    const work = await orbital.works.open({
        instance: instance.id,
        can: ["source", "preview", "rehearse"],
        ttlSeconds: 7200,
    });
    assert.equal(work.instance, instance.id);
    assert.ok(work.expiresAt >= asked + 7200 && work.expiresAt <= asked + 7260);

    // 에이전트가 팩토리의 주소에서 코드를 받아 고쳐 올린다. 팩토리의 서버가 프리뷰를 세우고 승격을 요청한다
    const folder = join(scratch, "work");
    await agentGit(scratch, "clone", "--quiet", relay?.remote(work) ?? "", folder);
    const source = readFileSync(join(folder, "server.js"), "utf8");
    writeFileSync(join(folder, "server.js"), source.replace("version: 1", "version: 2"));
    await agentGit(folder, "commit", "--quiet", "-am", "버전을 올린다");
    await agentGit(folder, "push", "--quiet", "origin", "main");
    const preview = await work.preview();
    assert.equal(preview.commit, await agentGit(folder, "rev-parse", "HEAD"));
    assert.deepEqual(preview.blockers, []);
    const release = preview.release;
    // 프리뷰에 씨앗 사용자로 들어가 본다
    const previewUrl = preview.services[0]?.url ?? "";
    const { cookie } = await work.previewSignIn("u1");
    assert.equal(((await (await fetch(`${previewUrl}/cards`, { headers: { cookie } })).json()) as unknown[]).length, 2);
    assert.ok((await work.previewLogs()).logs.some((log) => log.name === "preview-web"));
    // 리허설은 운영이 아직 없어 필요 없다
    assert.equal((await work.rehearse(release)).needed, false);
    await work.requestPromotion(release);

    // 승인 화면에 세울 것이 온다
    const pending = await orbital.releases.pending(instance.id);
    assert.deepEqual(pending, {
        release,
        commit: await agentGit(folder, "rev-parse", "HEAD"),
        changes: ["`member` 역할이 `todo.card` 표를 자기 행을 읽을 수 있게 됩니다 그리고 자기 행을 고칠 수 있게 됩니다"],
        migrations: ["001_card.sql"],
        newSecrets: [],
        rollout: null,
    });

    // 고객의 요청은 고객이 승인한다. 팩토리의 승인으로는 오르지 않고 까닭이 돌아온다
    const refused = await rejection(
        orbital.releases.promote({
            instance: instance.id,
            release,
            change: "customer_request",
            approvedBy: "factory",
        }),
    );
    assert.deepEqual(
        [refused.status, refused.code, refused.message],
        [409, "denied", "이 변경은 고객이 승인해야 합니다"],
    );
    assert.equal(await orbital.production.get(instance.id), null);

    // 사람이 승인했다
    const production = await orbital.releases.promote({
        instance: instance.id,
        release,
        change: "customer_request",
        approvedBy: "customer",
    });
    assert.equal(production.release, release);
    assert.deepEqual(production.migrations, ["001_card.sql"]);
    assert.equal(production.services[0]?.kind, "server");
    const live = production.services[0]?.url ?? "";
    assert.equal(await orbital.releases.pending(instance.id), null);
    assert.equal((await orbital.production.get(instance.id))?.release, release);

    // 운영의 앱이 돈다. 팩토리가 초대한 사람이 링크로 들어와 자기 카드만 읽고 쓴다
    const health = (await (await fetch(`${live}/health`)).json()) as { version: number };
    assert.equal(health.version, 2);
    await orbital.users.invite({ instance: instance.id, email: "u9@example.test", roles: ["member"] });
    await orbital.users.invite({ instance: instance.id, email: "u8@example.test", roles: ["member"] });
    const u9 = await signIn(live, "u9@example.test");
    const written = await fetch(`${live}/cards`, {
        method: "POST",
        headers: { cookie: u9 },
        body: "첫 일",
    });
    assert.equal(written.status, 201);
    const u8 = await signIn(live, "u8@example.test");
    const cards = async (cookie: string): Promise<unknown[]> =>
        (await (await fetch(`${live}/cards`, { headers: { cookie } })).json()) as unknown[];
    assert.equal((await cards(u9)).length, 1);
    assert.equal((await cards(u8)).length, 0);
    // 팩토리의 관리 화면: 사용자 목록, 업무 역할 바꾸기, 빼기
    const listed = await orbital.users.list(instance.id);
    assert.deepEqual(
        listed.map((user) => [user.email, user.roles, user.disabled]).sort(),
        [["u8@example.test", ["member"], false], ["u9@example.test", ["member"], false]],
    );
    assert.ok(listed.every((user) => typeof user.lastSignedInAt === "number" && user.id.startsWith("u_")));
    const u8id = listed.find((user) => user.email === "u8@example.test")?.id ?? "";
    await orbital.users.setRoles({ instance: instance.id, user: u8id, roles: [] });
    assert.deepEqual((await orbital.users.list(instance.id)).find((user) => user.id === u8id)?.roles, []);
    const undeclared = await rejection(orbital.users.setRoles({ instance: instance.id, user: u8id, roles: ["auditor"] }));
    assert.deepEqual([undeclared.status, undeclared.code], [422, "problems"]);
    await orbital.users.remove({ instance: instance.id, user: u8id });
    assert.equal((await fetch(`${live}/_orbital/auth/me`, { headers: { cookie: u8 } })).status, 401);
    assert.equal((await orbital.users.list(instance.id)).find((user) => user.id === u8id)?.disabled, true);

    // MCP 를 선언하지 않은 앱에는 OAuth 클라이언트를 미리 등록하지 못하고 까닭이 돌아온다
    const noMcp = await rejection(orbital.oauthClients.register({ instance: instance.id, name: "팩토리의 앱", redirectUris: ["https://factory.example/callback"] }));
    assert.deepEqual([noMcp.status, noMcp.code], [422, "problems"]);
    assert.match(noMcp.details.join("\n"), /auth\.mcp/);

    // 밖에서 신원 머리말을 실어 보내도 앱에는 닿지 않는다
    assert.equal((await (await fetch(`${live}/cards`, { headers: { "x-orbital-identity": "v1.00.00" } })).json() as unknown[]).length, 0);
});

test("git 을 이어 주면 clone 과 push 가 팩토리의 주소로 된다", { skip }, async () =>
{
    const instance = (await orbital.instances.create({ app: "todo", from: "v1" })).id;
    instances.push(instance);
    const work = await orbital.works.open({ instance, can: ["source", "preview"] });
    const remote = relay?.remote(work) ?? "";
    assert.ok(!remote.startsWith(url), "원격은 팩토리의 주소여야 합니다");

    // 받는다: 이력째
    const folder = join(scratch, "relayed");
    await agentGit(scratch, "clone", "--quiet", remote, folder);
    assert.equal(await agentGit(folder, "log", "--format=%s"), "스캐폴드 v1");
    assert.equal(await agentGit(folder, "remote", "get-url", "origin"), remote);
    // 올린다: 레이어의 main 이 그 commit 이 되고 프리뷰가 그 commit 으로 선다
    writeFileSync(join(folder, "NOTES.md"), "팩토리를 거쳐 올린다\n");
    await agentGit(folder, "add", "-A");
    await agentGit(folder, "commit", "--quiet", "-m", "메모");
    await agentGit(folder, "push", "--quiet", "origin", "main");
    const head = await agentGit(folder, "rev-parse", "HEAD");
    assert.equal((await work.preview()).commit, head);
    // 다른 폴더가 이어 받는다
    const other = join(scratch, "relayed-other");
    await agentGit(scratch, "clone", "--quiet", remote, other);
    assert.equal(await agentGit(other, "rev-parse", "HEAD"), head);
    // 레이어가 받지 않는 올리기는 그 까닭이 팩토리의 주소를 지나 git 에 그대로 보인다
    await agentGit(other, "checkout", "--quiet", "-b", "feature");
    await assert.rejects(agentGit(other, "push", "origin", "feature"), /`main` 브랜치 하나만/);
    // 셋 가운데 하나의 길만 지났다
    const paths = new Set((relay?.seen ?? []).map((seen) => seen.replace(/^\/git\/[0-9a-f]+/, "")));
    for (const path of paths)
    {
        assert.match(path, /^\/(info\/refs\?service=git-(upload|receive)-pack|git-upload-pack|git-receive-pack)$/, path);
    }
});

test("작업의 토큰으로는 승격하지 못한다", { skip }, async () =>
{
    const instance = (await orbital.instances.create({ app: "todo", from: "v1" })).id;
    instances.push(instance);
    // 팩토리의 서버가 보내는 것을 엿본다. 작업의 토큰은 작업 밖으로 나오지 않으므로 요청에서 꺼낸다
    let workToken = "";
    const watched = createOrbital({
        url,
        serviceKey: FACTORY,
        fetch: async (input, init) =>
        {
            const authorization = new Headers(init?.headers).get("authorization") ?? "";
            if (authorization.startsWith("Bearer orb1."))
            {
                workToken = authorization.slice("Bearer ".length);
            }
            return await fetch(input, init);
        },
    });
    const work = await watched.works.open({ instance, can: ["source", "source_read", "preview", "rehearse", "secrets_request"] });
    const { release } = await work.preview();
    await work.requestPromotion(release);
    assert.ok(workToken.startsWith("orb1."));
    assert.ok(!("promote" in work));

    // 능력을 모두 실어도 운영을 바꾸는 길은 열리지 않는다
    const tried = await fetch(`${url}/v1/instances/${instance}/promotions`, {
        method: "POST",
        headers: { authorization: `Bearer ${workToken}`, "content-type": "application/json" },
        body: JSON.stringify({ release, change: "customer_request", approved_by: "customer" }),
    });
    assert.equal(tried.status, 403);
    // 운영을 바꾸는 능력은 적어 달라고 해도 실리지 않는다
    const widened = await rejection(orbital.works.open({ instance, can: ["source", "promote" as "source"] }));
    assert.equal(widened.status, 422);
    assert.equal(await orbital.production.get(instance), null);
    assert.equal((await orbital.releases.pending(instance))?.release, release);
});

test("다른 팩토리의 service key 로는 인스턴스가 없는 것으로 보인다", { skip }, async () =>
{
    const instance = await orbital.instances.create({ app: "todo", from: "v1" });
    instances.push(instance.id);
    const stranger = createOrbital({ url, serviceKey: OTHER_FACTORY });

    const attempts: (() => Promise<unknown>)[] = [
        () => stranger.production.get(instance.id),
        () => stranger.releases.pending(instance.id),
        () => stranger.sessions.open({ instance: instance.id, can: ["source"] }),
        () => stranger.works.open({ instance: instance.id, can: ["source"] }),
        () => stranger.instances.destroy(instance.id),
        () => stranger.users.invite({ instance: instance.id, email: "kim@example.test", roles: ["member"] }),
        () => stranger.users.list(instance.id),
        () => stranger.oauthClients.register({ instance: instance.id, name: "x", redirectUris: ["https://factory.example/callback"] }),
        () => stranger.users.setRoles({ instance: instance.id, user: "u_aaaaaaaaaaaaaaaaaaaa", roles: [] }),
        () => stranger.users.remove({ instance: instance.id, user: "u_aaaaaaaaaaaaaaaaaaaa" }),
    ];
    for (const attempt of attempts)
    {
        const refused = await rejection(attempt());
        assert.deepEqual([refused.status, refused.code], [404, "not_found"]);
    }
    // 걷히지 않았다
    assert.equal(await orbital.production.get(instance.id), null);
});

test("모르는 service key 와 없는 스캐폴드 버전은 까닭과 함께 거절된다", { skip }, async () =>
{
    const nobody = createOrbital({ url, serviceKey: "sk_test_nobody" });
    const refused = await rejection(nobody.instances.create({ app: "todo", from: "v1" }));
    assert.equal(refused.status, 401);

    const missing = await rejection(orbital.instances.create({ app: "todo", from: "v999" }));
    assert.deepEqual([missing.status, missing.code], [422, "problems"]);
    // 무엇을 고칠지는 details 에 문장으로 온다
    assert.match(missing.details.join("\n"), /v999/);
});

test("팩토리가 SDK 로 넣은 메일과 Google 의 키는 설정을 읽어도 돌아오지 않는다", { skip }, async () =>
{
    const other = createOrbital({ url, serviceKey: OTHER_FACTORY });
    const empty = await other.settings.auth.get();
    assert.deepEqual(empty, {
        mail: { configured: false, provider: null, from: null, fromName: null },
        google: { configured: false, clientId: null, redirectUri: "https://layer.example/v1/auth/google/callback" },
    });
    const set = await other.settings.auth.set({
        mail: { provider: "resend", apiKey: "re_sdk_secret_value", from: "login@other.example", fromName: "다른 팩토리" },
        google: { clientId: "other.apps.googleusercontent.com", clientSecret: "GOCSPX-sdk-secret" },
    });
    assert.deepEqual(set, {
        mail: { configured: true, provider: "resend", from: "login@other.example", fromName: "다른 팩토리" },
        google: { configured: true, clientId: "other.apps.googleusercontent.com", redirectUri: "https://layer.example/v1/auth/google/callback" },
    });
    const read = await other.settings.auth.get();
    assert.deepEqual(read, set);
    assert.ok(!JSON.stringify(read).includes("secret"));
    // SDK 가 걸러서가 아니라 관리 서버의 답에 없다
    const raw = await (await fetch(`${url}/v1/settings/auth`, { headers: { authorization: `Bearer ${OTHER_FACTORY}` } })).text();
    assert.ok(!raw.includes("re_sdk_secret_value") && !raw.includes("GOCSPX-sdk-secret"), raw);
    // 다른 팩토리의 설정에는 보이지 않는다
    assert.equal((await orbital.settings.auth.get()).mail.configured, false);
    // 보내지 않은 칸은 그대로 두고 null 은 지운다
    const cleared = await other.settings.auth.set({ google: null });
    assert.equal(cleared.google.configured, false);
    assert.equal(cleared.mail.configured, true);
    const refused = await rejection(other.settings.auth.set({ mail: { provider: "resend", apiKey: "re_sdk_secret_value", from: "not-an-address" } }));
    assert.equal(refused.status, 422);
    assert.ok(!JSON.stringify(refused).includes("re_sdk_secret_value"));
    assert.ok(!refused.message.includes("re_sdk_secret_value"));
});
