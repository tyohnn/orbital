// 스캐폴드의 로그인 · 동의 화면은 `@harmony/orbital/app` 을 쓴다. 스캐폴드는 의존성 없이 뜨므로 SDK 를 타입만 걷어 `vendor/` 에 싣는다.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "../../..");
const scaffold = join(root, "examples/factory-todo/scaffold");
const read = (path: string): string => readFileSync(join(scaffold, path), "utf8");

test("스캐폴드에 실린 orbital-app.js 는 SDK 의 app.ts 에서 타입만 걷은 것과 같다", () =>
{
    const source = readFileSync(join(root, "sdk/typescript/src/app.ts"), "utf8");
    assert.equal(
        read("vendor/orbital-app.js"),
        stripTypeScriptTypes(source),
        "sdk/typescript/src/app.ts 를 고쳤으면 node -e 로 stripTypeScriptTypes 를 다시 돌려 vendor/orbital-app.js 를 새로 쓰세요",
    );
});

test("로그인 화면은 이메일 주소만 받고 링크를 보내는 일은 레이어에 맡긴다", () =>
{
    const page = read("pages/login.html");
    assert.match(page, /from "\/vendor\/orbital-app\.js"/);
    assert.match(page, /sendLoginLink\(/);
    assert.match(page, /type="email"/);
    assert.doesNotMatch(page, /password|비밀번호/i);
    assert.doesNotMatch(page, /fetch\(/);
});

test("동의 화면은 레이어가 말한 것을 보이고 사람이 단추를 눌렀을 때만 승인을 보낸다", () =>
{
    const page = read("pages/consent.html");
    assert.match(page, /consentRequest\(/);
    // approve 는 「허락」 단추의 click 처리 안에서만 부른다
    const calls = page.split("approve(").length - 1;
    assert.equal(calls, 1);
    assert.match(page, /allow\.addEventListener\("click", async \(\) =>\s*\{[^}]*approve\(/);
    assert.doesNotMatch(page, /fetch\(/);
});
