// 서버를 띄우는 자리(`src/main.ts`). 프로세스를 실제로 띄워 무엇이 빠졌을 때 뜨지 않고 무엇을 말하는지 본다.
// 레이어 대신 service key 를 거절하는 작은 HTTP 서버를 둔다.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

const main = join(resolve(import.meta.dirname, ".."), "src/main.ts");
/** 어디에 새어도 찾을 수 있게 드문 글자로 짓는다 */
const KEY = "sk_test_starter_main_Zp4Wq8";

/** 레이어처럼 답하는 서버. 어떤 열쇠도 받지 않는다 */
const layer = createServer((request, response) =>
{
    request.resume();
    response.writeHead(401, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "unauthorized", message: "service key 가 맞지 않습니다" }));
});
let layerUrl = "";

before(async () =>
{
    await new Promise<void>((done) => layer.listen(0, "127.0.0.1", done));
    layerUrl = `http://127.0.0.1:${(layer.address() as AddressInfo).port}`;
});

after(() =>
{
    layer.close();
});

/** 서버를 띄워 끝날 때까지 기다린다. 끝나지 않으면 5초 뒤에 멈춘다 */
async function start(env: Record<string, string>): Promise<{ code: number | null; output: string }>
{
    // 넘기는 환경은 이것뿐이다. 이 테스트를 돌리는 쪽의 환경이 섞이지 않는다. 저장소 안에서는 SDK 를 소스로 읽는 조건을 넘긴다
    const child = spawn(process.execPath, [...process.execArgv.filter((flag) => flag.startsWith("--conditions")), main], {
        env: { PATH: process.env.PATH ?? "", ...env },
        stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
    const timer = setTimeout(() => child.kill(), 5000);
    const code = await new Promise<number | null>((done) => child.once("exit", (exit) => done(exit)));
    clearTimeout(timer);
    return { code, output };
}

test("service key 가 없으면 뜨지 않고 무엇을 넣을지 말한다", async () =>
{
    const missingKey = await start({ ORBITAL_URL: layerUrl });
    assert.equal(missingKey.code, 1);
    assert.match(missingKey.output, /ORBITAL_SERVICE_KEY 이 없습니다\. .*sk_test_/);
    const missingUrl = await start({ ORBITAL_SERVICE_KEY: KEY });
    assert.equal(missingUrl.code, 1);
    assert.match(missingUrl.output, /ORBITAL_URL 이 없습니다/);
    assert.ok(!missingUrl.output.includes(KEY));
});

test("개발용 연결로는 바깥 주소에서 뜨지 않는다 — 운영에 내기 전에 로그인을 붙인다", async () =>
{
    for (const origin of ["https://factory.example.com", "http://10.0.0.5:3840"])
    {
        const started = await start({ ORBITAL_URL: layerUrl, ORBITAL_SERVICE_KEY: KEY, FACTORY_PUBLIC_URL: origin });
        assert.equal(started.code, 1, origin);
        assert.match(started.output, /바깥 주소입니다\. .*connect\.ts 에 로그인을 붙이고/, origin);
    }
});

test("레이어가 거절해 뜨지 못해도 service key 는 오류와 로그에 실리지 않는다", async () =>
{
    const started = await start({ ORBITAL_URL: layerUrl, ORBITAL_SERVICE_KEY: KEY, FACTORY_PUBLIC_URL: "http://127.0.0.1:3999" });
    assert.equal(started.code, 1);
    assert.match(started.output, /스캐폴드를 레이어에 올리지 못했습니다\(unauthorized 401\)\. ORBITAL_URL 과 service key 를 확인해 주세요/);
    assert.ok(!started.output.includes(KEY), started.output);
    assert.ok(!started.output.includes("sk_test_starter"), started.output);
});
