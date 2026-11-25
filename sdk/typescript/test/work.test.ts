// 작업(work)의 함수와 git 을 이어 주는 길이 무엇을 실어 보내는지 잰다. 관리 서버 대신 보낸 요청을 적는 `fetch` 를 끼운다.
//
// 실제 관리 서버에 붙어 도는 것은 `lap.test.ts` 가 잰다(git 을 이어 clone · push 하기, 작업의 토큰으로 승격하지 못하기).

import assert from "node:assert/strict";
import { test } from "node:test";

import { createOrbital } from "../src/server.ts";
import type { Work } from "../src/server.ts";

const SERVICE_KEY = "sk_test_factory_w8Zr2Qp";
const WORK_TOKEN = "orb1.7b7d.work-token";

interface Sent
{
    method: string;
    url: string;
    headers: Headers;
    body: string;
}

/** 보낸 요청을 적고, 길마다 그럴듯한 답을 돌려주는 관리 서버의 흉내. */
function fakeLayer(): { sent: Sent[]; fetch: typeof fetch }
{
    const sent: Sent[] = [];
    const fake = async (input: string | URL | Request, init?: RequestInit): Promise<Response> =>
    {
        const url = String(input);
        const headers = new Headers(init?.headers);
        const body = init?.body === undefined || init.body === null ? "" : await new Response(init.body).text();
        sent.push({ method: init?.method ?? "GET", url, headers, body });
        const json = (value: unknown): Response => new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
        if (url.endsWith("/sessions"))
        {
            return json({ token: WORK_TOKEN, expires_at: 1_900_000_000 });
        }
        if (url.includes("/git/"))
        {
            return new Response("0000", {
                status: 200,
                headers: { "content-type": "application/x-git-upload-pack-result", "www-authenticate": "Basic realm=\"Orbital\"", "set-cookie": "x=1" },
            });
        }
        if (url.endsWith("/previews"))
        {
            return json({ release: "r1", commit: "c".repeat(40), services: [{ name: "web", kind: "server", url: "http://127.0.0.1:9/" }], findings: [], changes: ["바뀐다"], blockers: [], notices: [], missing_secrets: ["BANK_API_KEY"], conformance: null });
        }
        if (url.endsWith("/previews/logs"))
        {
            return json({ release: "r1", logs: [{ name: "build-web", text: "ok" }] });
        }
        if (url.endsWith("/previews/identities"))
        {
            return json({ cookie: "__Host-orbital-session=abc" });
        }
        if (url.endsWith("/rehearsals"))
        {
            return json({ release: "r1", needed: true, passed: true, millis: 12, failed_at: null, sqlstate: null, tables: [["todo.card", 2, 2]] });
        }
        if (url.endsWith("/rollout"))
        {
            return json(null);
        }
        if (url.endsWith("/secrets"))
        {
            return json({ secrets: [] });
        }
        return json({});
    };
    return { sent, fetch: fake as typeof fetch };
}

async function openWork(): Promise<{ work: Work; sent: Sent[] }>
{
    const layer = fakeLayer();
    const orbital = createOrbital({ url: "http://layer.invalid/", serviceKey: SERVICE_KEY, fetch: layer.fetch });
    const work = await orbital.works.open({ instance: "k3f9x2ab", can: ["source", "preview", "rehearse", "secrets_request"], ttlSeconds: 7200 });
    return { work, sent: layer.sent };
}

test("작업의 함수들은 작업의 토큰으로만 부르고 service key 를 싣지 않는다", async () =>
{
    const { work, sent } = await openWork();
    // 작업을 여는 것만 service key 로 부른다
    assert.equal(sent.length, 1);
    assert.equal(sent[0]?.url, "http://layer.invalid/v1/instances/k3f9x2ab/sessions");
    assert.equal(sent[0]?.headers.get("authorization"), `Bearer ${SERVICE_KEY}`);
    assert.deepEqual(JSON.parse(sent[0]?.body ?? ""), { can: ["source", "preview", "rehearse", "secrets_request"], ttl_seconds: 7200 });
    assert.equal(work.instance, "k3f9x2ab");
    assert.equal(work.expiresAt, 1_900_000_000);
    // 토큰은 작업 밖으로 나오지 않는다
    assert.ok(!JSON.stringify(work).includes(WORK_TOKEN));

    const preview = await work.preview();
    assert.deepEqual(preview.missingSecrets, ["BANK_API_KEY"]);
    assert.deepEqual(preview.services, [{ name: "web", kind: "server", url: "http://127.0.0.1:9/" }]);
    assert.deepEqual(await work.previewLogs(), { release: "r1", logs: [{ name: "build-web", text: "ok" }] });
    assert.deepEqual(await work.previewSignIn("u1"), { cookie: "__Host-orbital-session=abc" });
    assert.deepEqual((await work.rehearse("r1")).tables, [{ table: "todo.card", before: 2, after: 2 }]);
    await work.requestPromotion("r1");
    assert.equal(await work.rollout(), null);
    assert.deepEqual(await work.secrets.list(), []);
    await work.secrets.request("BANK_API_KEY", { reason: "송금" });
    await work.git.relay(new Request("http://factory.invalid/git/w/info/refs?service=git-upload-pack"));

    const calls = sent.slice(1);
    assert.deepEqual(calls.map((call) => `${call.method} ${call.url.replace("http://layer.invalid/v1/instances/k3f9x2ab", "")}`), [
        "POST /previews",
        "GET /previews/logs",
        "POST /previews/identities",
        "POST /rehearsals",
        "POST /promotion-requests",
        "GET /rollout",
        "GET /secrets",
        "POST /secrets/BANK_API_KEY/request",
        "GET /git/info/refs?service=git-upload-pack",
    ]);
    for (const call of calls)
    {
        assert.equal(call.headers.get("authorization"), `Bearer ${WORK_TOKEN}`, call.url);
        assert.ok(![...call.headers.values()].some((value) => value.includes(SERVICE_KEY)), call.url);
        assert.ok(!call.body.includes(SERVICE_KEY), call.url);
    }
    // 운영을 바꾸는 함수는 작업에 없다
    assert.deepEqual(Object.keys(work).sort(), ["expiresAt", "git", "instance", "preview", "previewLogs", "previewSignIn", "rehearse", "requestPromotion", "rollout", "secrets"]);
});

test("이어 주는 길은 정해진 셋 밖의 경로와 밖에서 온 Authorization 을 넘기지 않는다", async () =>
{
    const { work, sent } = await openWork();
    const opened = sent.length;
    const factory = "http://factory.invalid/git/w";

    for (const [method, path] of [
        ["GET", "/info/refs"],
        ["GET", "/info/refs?service=git-upload-archive"],
        ["GET", "/info/refs?service=git-upload-pack&x=1"],
        ["POST", "/info/refs?service=git-upload-pack"],
        ["GET", "/git-upload-pack"],
        ["POST", "/git-upload-pack?x=1"],
        ["GET", "/HEAD"],
        ["GET", "/config"],
        ["GET", "/objects/info/packs"],
        ["POST", "/git-upload-archive"],
        ["DELETE", "/git-receive-pack"],
    ] as const)
    {
        const init: RequestInit = { method, headers: { authorization: `Bearer ${SERVICE_KEY}` } };
        if (method === "POST")
        {
            init.body = "0000";
        }
        const answer = await work.git.relay(new Request(`${factory}${path}`, init));
        assert.equal(answer.status, 404, `${method} ${path}`);
    }
    assert.equal(sent.length, opened, "정해진 셋 밖의 길은 레이어에 닿지 않아야 합니다");

    // 정해진 길은 작업의 토큰을 붙여 넘긴다. 밖에서 온 자격 · 쿠키 · 프로토콜의 판은 버린다
    const body = new ReadableStream<Uint8Array>({
        start(controller)
        {
            controller.enqueue(new TextEncoder().encode("0032want "));
            controller.enqueue(new TextEncoder().encode(`${"a".repeat(40)}\n00000009done\n`));
            controller.close();
        },
    });
    const answer = await work.git.relay(new Request(`${factory}/git-upload-pack`, {
        method: "POST",
        headers: {
            authorization: `Basic ${Buffer.from(`agent:${SERVICE_KEY}`).toString("base64")}`,
            cookie: "factory_session=secret",
            "git-protocol": "version=2",
            "content-type": "application/x-git-upload-pack-request",
            "content-encoding": "gzip",
            accept: "application/x-git-upload-pack-result",
        },
        body,
        duplex: "half",
    } as RequestInit & { duplex: "half" }));
    const passed = sent.at(-1);
    assert.ok(passed !== undefined && sent.length === opened + 1);
    assert.equal(passed.method, "POST");
    assert.equal(passed.url, "http://layer.invalid/v1/instances/k3f9x2ab/git/git-upload-pack");
    assert.deepEqual([...passed.headers.keys()].sort(), ["accept", "authorization", "content-encoding", "content-type"]);
    assert.equal(passed.headers.get("authorization"), `Bearer ${WORK_TOKEN}`);
    assert.equal(passed.headers.get("content-encoding"), "gzip");
    assert.equal(passed.body, `0032want ${"a".repeat(40)}\n00000009done\n`);
    // 답은 git 이 읽는 머리말만 돌려준다. 레이어의 자격 요청과 쿠키는 팩토리의 길로 새지 않는다
    assert.equal(answer.status, 200);
    assert.equal(answer.headers.get("content-type"), "application/x-git-upload-pack-result");
    assert.equal(answer.headers.get("www-authenticate"), null);
    assert.equal(answer.headers.get("set-cookie"), null);
    assert.equal(await answer.text(), "0000");
});
