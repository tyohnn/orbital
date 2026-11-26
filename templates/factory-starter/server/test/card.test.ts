// 승인 카드의 내용. 사람이 무엇을 승인하는지 읽는 자리다. 레이어 없이 카드의 HTML 을 잰다.

import assert from "node:assert/strict";
import { test } from "node:test";

import type { PendingPromotion, Rehearsal } from "@harmony/orbital/server";

import { renderCard } from "../src/card.ts";

const pending: PendingPromotion = {
    release: "r_0123456789abcdef0123",
    commit: "abcdef0123456789abcdef0123456789abcdef01",
    changes: ["`member` 역할이 `app.note` 표의 자기 행을 지울 수 있게 됩니다"],
    migrations: ["002_done.sql"],
    newSecrets: ["NOTES_KEY", "MAIL_KEY"],
    rollout: null,
};

const rehearsal: Rehearsal = {
    release: pending.release,
    needed: true,
    passed: true,
    millis: 412,
    failedAt: null,
    sqlstate: null,
    tables: [{ table: "app.note", before: 12, after: 12 }],
};

const approveButton = (html: string): boolean => /data-action="approve"/.test(html);

test("승인 카드는 권한이 바뀌는 문장 · 마이그레이션 · 리허설의 숫자 · 운영의 값이 없는 비밀을 보인다", () =>
{
    const html = renderCard({
        kind: "waiting",
        pending,
        rehearsalNeeded: true,
        rehearsal,
        secrets: [{ name: "NOTES_KEY", filled: true }, { name: "MAIL_KEY", filled: false }],
        approval: null,
        production: null,
    });
    assert.ok(html.includes("`member` 역할이 `app.note` 표의 자기 행을 지울 수 있게 됩니다"));
    assert.ok(html.includes("<li>002_done.sql</li>"));
    assert.ok(html.includes("412 ms"));
    assert.ok(html.includes("<code>app.note</code> 12행 → 12행"));
    assert.match(html, /<code>NOTES_KEY<\/code> · 운영의 값을 넣었어요/);
    assert.match(html, /<code>MAIL_KEY<\/code> · 운영의 값이 없어요/);
    assert.match(html, /role="alert">운영의 값이 없는 비밀이 있어 아직 올릴 수 없어요: <code>MAIL_KEY<\/code>/);
    assert.ok(!approveButton(html));

    // 다 갖추면 승인 단추가 서고 표를 싣는다
    const ready = renderCard({ kind: "waiting", pending, rehearsalNeeded: true, rehearsal, secrets: [{ name: "NOTES_KEY", filled: true }], approval: "tkt_1", production: null });
    assert.ok(approveButton(ready));
    assert.match(ready, /data-approval="tkt_1"/);
    assert.doesNotMatch(ready, /role="alert"/);
});

test("리허설이 필요한데 돌리지 않았으면 카드가 그렇다고 말하고 승인 단추를 세우지 않는다", () =>
{
    const html = renderCard({ kind: "waiting", pending, rehearsalNeeded: true, rehearsal: null, secrets: [], approval: null, production: null });
    assert.match(html, /data-rehearsal="not_run"/);
    assert.ok(!approveButton(html));
    const failed = renderCard({ kind: "waiting", pending, rehearsalNeeded: true, rehearsal: { ...rehearsal, passed: false, failedAt: "002_done.sql", sqlstate: "23502" }, secrets: [], approval: null, production: null });
    assert.match(failed, /data-rehearsal="failed"/);
    assert.ok(failed.includes("SQLSTATE 23502"));
    // 처음 오르는 것처럼 운영 DB 가 없으면 마이그레이션이 있어도 리허설이 필요 없다
    const plain = renderCard({ kind: "waiting", pending: { ...pending, newSecrets: [] }, rehearsalNeeded: false, rehearsal: null, secrets: [], approval: "tkt_2", production: null });
    assert.ok(plain.includes("리허설이 필요 없어요"));
    assert.ok(approveButton(plain));
});

test("에이전트가 지은 글은 카드에서 이스케이프된다", () =>
{
    const html = renderCard({
        kind: "waiting",
        pending: { ...pending, changes: ["<img src=x onerror=alert(1)>"], migrations: ["003_<script>.sql"] },
        rehearsalNeeded: true,
        rehearsal: { ...rehearsal, tables: [{ table: "app.\"note<b>\"", before: 1, after: 2 }] },
        secrets: [{ name: "A<B", filled: false }],
        approval: "\"><script>",
        production: null,
    });
    assert.doesNotMatch(html, /<img|<script|<b>/);
    assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"));
    assert.ok(html.includes("003_&lt;script&gt;.sql"));
    assert.ok(html.includes("A&lt;B"));
});
