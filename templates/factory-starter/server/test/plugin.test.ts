// 플러그인의 묶음(ZIP). 하모니와 클로드가 같은 ZIP 을 받는다. 묶음을 지어 풀어 보고 무엇이 들었는지 본다.

import assert from "node:assert/strict";
import { test } from "node:test";
import { crc32 } from "node:zlib";

import { NAME } from "../src/brand.ts";
import { packageFiles, zip } from "../src/pack.ts";
import { TOOLS } from "../src/tools.ts";

/** 저장 방식(stored)의 ZIP 을 읽는다. 중앙 디렉터리를 따라 이름과 내용을 꺼내고 CRC 를 견준다 */
function unzip(bytes: Uint8Array): Map<string, string>
{
    const data = Buffer.from(bytes);
    const end = data.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    assert.ok(end >= 0, "ZIP 의 끝 레코드가 있어야 합니다");
    const count = data.readUInt16LE(end + 10);
    let at = data.readUInt32LE(end + 16);
    const files = new Map<string, string>();
    for (let index = 0; index < count; index += 1)
    {
        assert.equal(data.readUInt32LE(at), 0x02014b50);
        const sum = data.readUInt32LE(at + 16);
        const size = data.readUInt32LE(at + 20);
        const nameLength = data.readUInt16LE(at + 28);
        const extra = data.readUInt16LE(at + 30) + data.readUInt16LE(at + 32);
        const local = data.readUInt32LE(at + 42);
        const name = data.toString("utf8", at + 46, at + 46 + nameLength);
        const start = local + 30 + data.readUInt16LE(local + 26) + data.readUInt16LE(local + 28);
        const body = data.subarray(start, start + size);
        assert.equal(crc32(body), sum, name);
        files.set(name, body.toString("utf8"));
        at += 46 + nameLength + extra;
    }
    return files;
}

function frontmatter(body: string): Record<string, string>
{
    const head = /^---\n([\s\S]*?)\n---/.exec(body)?.[1] ?? "";
    return Object.fromEntries(head.split("\n").map((line) =>
    {
        const at = line.indexOf(":");
        return [line.slice(0, at).trim(), line.slice(at + 1).trim().replace(/^(["'])(.*)\1$/, "$2")];
    }));
}

/** 하모니가 모델에게 줄지 가르는 규칙. `ui.visibility` 에 `model` 이 있어야 하고, 적지 않았으면 옛 이름 `openai/visibility` 가 `private` 가 아니어야 한다 */
function modelVisible(meta: unknown): boolean
{
    const record = typeof meta === "object" && meta !== null ? meta as Record<string, unknown> : {};
    const ui = typeof record.ui === "object" && record.ui !== null ? record.ui as Record<string, unknown> : {};
    if (Array.isArray(ui.visibility))
    {
        return ui.visibility.includes("model");
    }
    return record["openai/visibility"] !== "private";
}

test("플러그인은 MCP 서버 하나와 스킬 하나를 묶고 훅이 없다 — 스킬이 부르라는 도구는 모델이 부를 수 있는 도구다", () =>
{
    const files = unzip(zip(packageFiles()));
    assert.ok(![...files.keys()].some((path) => path.startsWith("hooks/")));
    const skills = [...files.keys()].filter((path) => /^skills\/[^/]+\/SKILL\.md$/.test(path));
    assert.equal(skills.length, 1);

    // 하모니가 보는 것과 클로드가 보는 것: 같은 이름(서버의 이름과도 같다)과 버전, 훅이 없음
    const plugin = JSON.parse(files.get("plugin.json") ?? "") as { name: string; version: string; hooks?: unknown };
    const claude = JSON.parse(files.get(".claude-plugin/plugin.json") ?? "") as { name: string; version: string; hooks?: unknown };
    assert.equal(plugin.name, NAME);
    assert.match(plugin.version, /^\d+\.\d+\.\d+$/);
    assert.deepEqual([claude.name, claude.version, claude.hooks, plugin.hooks], [plugin.name, plugin.version, undefined, undefined]);
    const servers = (JSON.parse(files.get(".mcp.json") ?? "") as { mcpServers: Record<string, { type: string; url: string }> }).mcpServers;
    assert.deepEqual(Object.keys(servers), [NAME]);
    assert.equal(new URL(servers[NAME]?.url ?? "").pathname, "/mcp");

    // 스킬의 이름은 폴더와 같고, 스킬이 부르라는 도구는 모델이 부를 수 있는 도구 모두다
    const skill = files.get(skills[0] ?? "") ?? "";
    assert.equal(`skills/${frontmatter(skill).name ?? ""}/SKILL.md`, skills[0]);
    const named = TOOLS.filter((tool) => skill.includes(`\`${tool.name}\``)).map((tool) => tool.name).sort();
    assert.deepEqual(named, TOOLS.filter((tool) => modelVisible(tool._meta)).map((tool) => tool.name).sort());

    // 배포한 팩토리의 주소로 바꿔 지을 수 있다
    const deployed = unzip(zip(packageFiles("https://factory.example.com/mcp")));
    assert.match(deployed.get(".mcp.json") ?? "", /"url": "https:\/\/factory\.example\.com\/mcp"/);
});

test("플러그인의 묶음과 스킬에는 레이어를 직접 부르라는 말이 없다", () =>
{
    const files = unzip(zip(packageFiles()));
    for (const [path, body] of files)
    {
        assert.doesNotMatch(body, /`orbital [a-z-]+|orbital (clone|pull|push|preview|identity|rehearse|request-promotion|check)\b/, path);
        assert.doesNotMatch(body, /ORBITAL_(URL|TOKEN|INSTANCE|SERVICE_KEY)/, path);
        assert.doesNotMatch(body, /\/v1\/instances|orbitald|sk_(live|test)_/, path);
    }
    const skill = [...files].find(([path]) => path.endsWith("SKILL.md"))?.[1] ?? "";
    assert.match(skill, /git -c http\.extraHeader="Authorization: Bearer \$CREDENTIAL" clone/);
    assert.ok(!/https?:\/\/[^\s]*@/.test(skill), "원격의 주소에 자격을 넣는 예가 있으면 안 됩니다");
});
