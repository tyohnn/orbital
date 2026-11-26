// 고객 계정과 인스턴스를 잇는 자리. 메모리 구현을 잰다. 당신의 구현으로 바꾸면 같은 테스트를 그 구현에 돌린다.

import assert from "node:assert/strict";
import { test } from "node:test";

import { memoryAccounts } from "../src/accounts.ts";

test("같은 고객의 요청이 겹쳐 와도 인스턴스는 하나만 선다", async () =>
{
    const accounts = memoryAccounts();
    let created = 0;
    const create = async (): Promise<string> =>
    {
        created += 1;
        await new Promise((done) => setTimeout(done, 10));
        return `inst${created}`;
    };
    const answers = await Promise.all([accounts.instanceFor("alice", create), accounts.instanceFor("alice", create), accounts.instanceFor("alice", create)]);
    assert.equal(created, 1);
    assert.deepEqual(answers.map((answer) => answer.instance), ["inst1", "inst1", "inst1"]);
    assert.deepEqual(answers.map((answer) => answer.created).sort(), [false, false, true]);
    // 다른 고객은 다른 인스턴스를 받는다
    assert.equal((await accounts.instanceFor("bob", create)).instance, "inst2");
    // 세우다 실패해도 뒤의 요청은 다시 세운다
    const failed = accounts.instanceFor("carol", async () => { throw new Error("레이어가 받지 않았습니다"); });
    await assert.rejects(failed);
    assert.equal(accounts.find("carol"), undefined);
    assert.equal((await accounts.instanceFor("carol", create)).instance, "inst3");
});

test("인스턴스로 고객을 찾는다 — 웹훅을 받은 쪽이 누구에게 알릴지 안다", async () =>
{
    const accounts = memoryAccounts();
    await accounts.instanceFor("alice", async () => "k3f9x2ab");
    await accounts.instanceFor("bob", async () => "k3f9x2abc");
    assert.equal(accounts.customerOf("k3f9x2ab"), "alice");
    assert.equal(accounts.customerOf("k3f9x2abc"), "bob");
    assert.equal(accounts.customerOf("k3f9x2a"), undefined);
    assert.equal(accounts.find("alice"), "k3f9x2ab");
});
