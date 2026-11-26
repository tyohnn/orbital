// 레이어의 웹훅을 받는 길과 물어보는 고리. 팩토리의 HTTP 서버를 실제로 띄워 `POST /webhooks/orbital` 을 두드린다.
// 레이어는 띄우지 않는다. 서명은 레이어와 같은 방법(`HMAC-SHA256(비밀, "<t>.<본문>")`)으로 이 테스트가 짓는다.

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { createOrbital } from "@harmony/orbital/server";
import type { EventPage, OrbitalEvent } from "@harmony/orbital/server";

import { memoryAccounts } from "../src/accounts.ts";
import { createOAuth } from "../src/connect.ts";
import { createEvents, fileInbox } from "../src/events.ts";
import type { Events } from "../src/events.ts";
import { serve } from "../src/http.ts";
import { createNotifier } from "../src/notify.ts";
import { createFactory } from "../src/tools.ts";
import { createWorks } from "../src/works.ts";

/** 어디에 새어도 찾을 수 있게 드문 글자로 지은 비밀 */
const SECRET = "whsec_starter_test_Q8vLm2Rx";
const now = (): number => Math.floor(Date.now() / 1000);

const scratch = mkdtempSync(join(tmpdir(), "factory-webhook-"));
const logs: string[] = [];
const log = (line: string): void => { logs.push(line); };
/** 처리기가 받은 이벤트의 id */
const handled: number[] = [];
/** 처리기가 한 번 실패할 id */
const failOnce = new Set<number>();
/** 받은 웹훅의 답 */
const answers: string[] = [];

let server: Server;
let base = "";
let events: Events;

function event(id: number, type = "promotion.succeeded", instance: string | null = "k3f9x2ab"): OrbitalEvent
{
    return { id, type, createdAt: now(), organization: "factory", instance, data: { release: `r_${id}` } };
}

/** 레이어가 보내듯이 지은 본문. 칸의 이름은 레이어의 JSON(`created_at`)을 따른다 */
function wire(value: OrbitalEvent): string
{
    return JSON.stringify({ id: value.id, type: value.type, created_at: value.createdAt, organization: value.organization, instance: value.instance, data: value.data });
}

function sign(body: string, at = now(), secret = SECRET): string
{
    return `t=${at},v1=${createHmac("sha256", secret).update(`${at}.${body}`).digest("hex")}`;
}

async function deliver(body: string, signature: string): Promise<{ status: number; body: Record<string, unknown> }>
{
    const response = await fetch(`${base}/webhooks/orbital`, { method: "POST", headers: { "content-type": "application/json", "orbital-signature": signature }, body });
    const text = await response.text();
    answers.push(text);
    return { status: response.status, body: JSON.parse(text) as Record<string, unknown> };
}

before(async () =>
{
    const accounts = memoryAccounts();
    await accounts.instanceFor("alice", async () => "k3f9x2ab");
    const notify = createNotifier({ accounts, log });
    events = createEvents({
        // 물어보는 고리의 테스트가 갈아 끼운다
        list: async () => ({ events: [], next: 0, hasMore: false }),
        inbox: fileInbox(join(scratch, "home")),
        handle: async (value) =>
        {
            if (failOnce.delete(value.id))
            {
                throw new Error("알림을 보내지 못했습니다");
            }
            // 겹쳐 온 요청이 처리기 안에서 만나게 잠깐 쉰다
            await new Promise((done) => setTimeout(done, 20));
            handled.push(value.id);
            await notify(value);
        },
        secret: SECRET,
        log,
    });
    // 웹훅의 길은 레이어를 부르지 않는다. 닿지 않는 주소로 SDK 를 만든다
    const orbital = createOrbital({ url: "http://127.0.0.1:9", serviceKey: "sk_test_unused" });
    const works = createWorks(orbital);
    const origin = "http://127.0.0.1:0";
    const factory = createFactory({ orbital, accounts, works, origin, app: "starter", version: "v1", log });
    server = serve({ factory, oauth: createOAuth(origin), works, events, layerOrigin: "http://127.0.0.1:9" }, origin);
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() =>
{
    server.close();
    server.closeAllConnections();
    rmSync(scratch, { recursive: true, force: true });
});

test("서명이 맞는 웹훅은 처리기를 한 번 부르고 200 으로 답한다", async () =>
{
    const body = wire(event(1));
    const answer = await deliver(body, sign(body));
    assert.equal(answer.status, 200);
    assert.deepEqual(answer.body, { received: 1, duplicate: false });
    assert.deepEqual(handled, [1]);
    // 「여기서 고객에게 알린다」의 자리가 인스턴스의 고객을 찾아 불렸다
    assert.ok(logs.some((line) => line.startsWith("[factory] 알림 #1 promotion.succeeded → alice")), logs.join("\n"));
});

test("서명이 틀리면 401 로 거절하고 처리기를 부르지 않는다", async () =>
{
    const before = handled.length;
    const body = wire(event(2));
    for (const signature of [sign(body, now(), "whsec_other"), sign(`${body} `), `t=${now()},v1=${"0".repeat(64)}`])
    {
        assert.equal((await deliver(body, signature)).status, 401, signature);
    }
    // 머리말의 모양이 틀리면 400 이다
    assert.equal((await deliver(body, "v1=abc")).status, 400);
    assert.equal((await fetch(`${base}/webhooks/orbital`, { method: "POST", body })).status, 400);
    assert.equal(handled.length, before);
});

test("서명의 때가 5분보다 멀면 거절한다 — 되풀이 막기", async () =>
{
    const before = handled.length;
    const body = wire(event(3));
    for (const at of [now() - 301, now() + 301])
    {
        const answer = await deliver(body, sign(body, at));
        assert.equal(answer.status, 401);
        assert.equal(answer.body.error, "stale");
    }
    // 경계의 안쪽은 받는다
    assert.equal((await deliver(body, sign(body, now() - 290))).status, 200);
    assert.equal(handled.length, before + 1);
});

test("같은 id 를 두 번 받으면 겹쳐 와도 처리기는 한 번만 돈다", async () =>
{
    const before = handled.length;
    const body = wire(event(4));
    // 겹쳐 온 둘과 나중에 다시 온 하나
    const both = await Promise.all([deliver(body, sign(body)), deliver(body, sign(body))]);
    const again = await deliver(body, sign(body));
    for (const answer of [...both, again])
    {
        assert.equal(answer.status, 200);
    }
    assert.deepEqual([...both, again].map((answer) => answer.body.duplicate).sort(), [false, true, true]);
    assert.deepEqual(handled.slice(before), [4]);
    // 앞의 id 가 늦게 와도 다시 처리하지 않는다
    const old = wire(event(1));
    assert.equal((await deliver(old, sign(old))).body.duplicate, true);
    assert.deepEqual(handled.slice(before), [4]);
});

test("서명은 받은 날것의 본문으로 확인한다 — JSON 을 읽어 다시 쓴 본문이 아니다", async () =>
{
    // 레이어가 칸의 차례나 띄어쓰기를 다르게 써도 서명은 그 바이트로 맞는다. 다시 쓰면 바이트가 달라진다
    const body = `{ "data" : {"release":"r_5"}, "organization":"factory","instance":"k3f9x2ab", "type":"promotion.succeeded","created_at":${now()},"id":5 }`;
    const answer = await deliver(body, sign(body));
    assert.equal(answer.status, 200, JSON.stringify(answer.body));
    assert.ok(handled.includes(5));
});

test("처리기가 실패하면 500 으로 답하고 처리한 것으로 적지 않는다 — 레이어가 다시 보내면 처리한다", async () =>
{
    failOnce.add(6);
    const body = wire(event(6));
    const first = await deliver(body, sign(body));
    assert.equal(first.status, 500);
    assert.ok(!handled.includes(6));
    const retried = await deliver(body, sign(body));
    assert.equal(retried.status, 200);
    assert.deepEqual(retried.body, { received: 6, duplicate: false });
    assert.equal(handled.filter((id) => id === 6).length, 1);
});

test("물어보는 고리는 events.list 를 차례로 이어 받아 같은 처리기를 부르고 처리한 id 는 건너뛴다", async () =>
{
    const asked: number[] = [];
    const pages: Record<number, EventPage> = {
        // 웹훅으로 이미 받은 6 까지가 다시 와도(레이어에 물은 자리가 늦어도) 건너뛴다
        6: { events: [event(7), event(8, "instance.created")], next: 8, hasMore: true },
        8: { events: [event(9, "promotion.requested")], next: 9, hasMore: false },
    };
    const seen: number[] = [];
    const inbox = fileInbox(join(scratch, "home"));
    const polling = createEvents({
        list: async ({ after }) =>
        {
            asked.push(after);
            return pages[after] ?? { events: [], next: after, hasMore: false };
        },
        inbox,
        handle: async (value) => { seen.push(value.id); },
        log,
    });
    assert.equal(await polling.pollOnce(), 3);
    assert.deepEqual(asked, [6, 8]);
    assert.deepEqual(seen, [7, 8, 9]);
    // 다시 돌아도 처리한 것은 다시 부르지 않는다. 앞의 것을 다시 내주는 레이어여도 그렇다
    pages[9] = { events: [event(8), event(9)], next: 9, hasMore: false };
    assert.equal(await polling.pollOnce(), 0);
    assert.deepEqual(seen, [7, 8, 9]);
});

test("웹훅을 받으면 그 앞에 받지 못한 이벤트부터 목록에서 이어 받아 차례대로 처리한다", async () =>
{
    // 레이어가 12 와 13 은 보내지 못했고(웹훅을 걸기 전이거나 하루 동안 보내다 그만뒀다) 14 를 보냈다
    const seen: number[] = [];
    const asked: number[] = [];
    const inbox = fileInbox(join(scratch, "catch-up"));
    inbox.record(11);
    const receiving = createEvents({
        list: async ({ after }) =>
        {
            asked.push(after);
            return after < 13
                ? { events: [event(12), event(13, "promotion.failed")], next: 13, hasMore: true }
                : { events: [event(14), event(15)], next: 15, hasMore: false };
        },
        inbox,
        handle: async (value) => { seen.push(value.id); },
        secret: SECRET,
        log,
    });
    const body = wire(event(14));
    const answer = await receiving.receive(sign(body), Buffer.from(body));
    assert.deepEqual(answer, { status: 200, body: { received: 14, duplicate: false } });
    // 앞의 것을 차례대로 처리한 뒤에 받은 것을 처리했다. 받은 것보다 뒤의 것(15)은 그 웹훅이 올 때 처리한다
    assert.deepEqual(seen, [12, 13, 14]);
    assert.equal(inbox.through(), 14);
    // 이미 처리한 자리 앞의 웹훅(다시 온 13)은 목록을 묻지 않고 겹친 것으로 답한다
    const asks = asked.length;
    const again = wire(event(13, "promotion.failed"));
    assert.deepEqual((await receiving.receive(sign(again), Buffer.from(again))).body, { received: 13, duplicate: true });
    assert.equal(asked.length, asks);
    assert.deepEqual(seen, [12, 13, 14]);
});

test("앞의 것을 이어 받지 못하면 받은 웹훅도 처리하지 않고 500 으로 답한다 — 처리한 자리가 앞의 것을 건너뛰지 않는다", async () =>
{
    const seen: number[] = [];
    let down = true;
    const inbox = fileInbox(join(scratch, "catch-up-down"));
    inbox.record(20);
    const receiving = createEvents({
        list: async () =>
        {
            if (down)
            {
                throw new Error("레이어에 닿지 못했습니다");
            }
            return { events: [event(21), event(22)], next: 22, hasMore: false };
        },
        inbox,
        handle: async (value) => { seen.push(value.id); },
        secret: SECRET,
        log,
    });
    const body = wire(event(22));
    const refused = await receiving.receive(sign(body), Buffer.from(body));
    assert.deepEqual(refused, { status: 500, body: { error: "catch_up_failed" } });
    assert.deepEqual(seen, []);
    assert.equal(inbox.through(), 20);
    // 레이어가 다시 보내면 이어 받아 차례대로 처리한다
    down = false;
    const answer = await receiving.receive(sign(body), Buffer.from(body));
    assert.equal(answer.status, 200);
    assert.deepEqual(seen, [21, 22]);
});

test("처리한 자리는 팩토리의 폴더에 남아 다시 떠도 처리한 이벤트를 다시 알리지 않는다", async () =>
{
    const home = join(scratch, "restart");
    const first = fileInbox(home);
    first.record(41);
    // 다시 뜬 팩토리
    const seen: number[] = [];
    const restarted = createEvents({
        list: async ({ after }) => ({ events: [event(40), event(41), event(42)].filter((value) => value.id > after - 1), next: 42, hasMore: false }),
        inbox: fileInbox(home),
        handle: async (value) => { seen.push(value.id); },
        secret: SECRET,
        log,
    });
    assert.equal(await restarted.pollOnce(), 1);
    assert.deepEqual(seen, [42]);
    const body = wire(event(41));
    assert.equal((await restarted.receive(sign(body), Buffer.from(body))).body.duplicate, true);
});

test("웹훅의 답과 팩토리의 로그에 웹훅의 비밀이 실리지 않는다", async () =>
{
    assert.ok(answers.length >= 10, "모은 답이 있어야 합니다");
    for (const text of [...answers, ...logs])
    {
        assert.ok(!text.includes(SECRET), text);
        assert.ok(!text.includes("whsec_"), text);
    }
    // 비밀을 넣지 않은 팩토리는 웹훅을 받지 않는다고 답한다
    const plain = createEvents({ list: async () => ({ events: [], next: 0, hasMore: false }), inbox: fileInbox(join(scratch, "plain")), handle: async () => undefined, log });
    const body = wire(event(1));
    assert.equal((await plain.receive(sign(body), Buffer.from(body))).status, 404);
});
