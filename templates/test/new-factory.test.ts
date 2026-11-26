// 시작 템플릿을 새 폴더로 복사하는 스크립트(`scripts/new-factory.mjs`)를 잰다. 저장소에만 있는 테스트다(복사본에는 따라가지 않는다).
//
// 레지스트리에 닿지 않는다. 복사본에 의존성을 깔고 띄우는 것은 무거운 묶음(`lap.test.ts`)이 한다.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

const root = resolve(import.meta.dirname, "../..");
const template = join(root, "templates/factory-starter");
const script = join(root, "scripts/new-factory.mjs");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);

let scratch = "";
/** 한 번 복사해 둔 것. 여러 테스트가 읽는다 */
let made = "";

function run(...args: string[]): { status: number | null; stdout: string; stderr: string }
{
    const result = spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: "utf8" });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const json = (path: string): Record<string, unknown> => JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

function walk(folder: string, base = folder): string[]
{
    return readdirSync(folder, { withFileTypes: true }).flatMap((entry) =>
    {
        const path = join(folder, entry.name);
        return entry.isDirectory() ? walk(path, base) : [path.slice(base.length + 1)];
    });
}

before(() =>
{
    scratch = mkdtempSync(join(tmpdir(), "orbital-new-factory-"));
    // 템플릿에 개발하다 남은 것이 있어도 복사본에 따라가지 않아야 한다
    mkdirSync(join(template, "server/node_modules/left-over"), { recursive: true });
    mkdirSync(join(template, "server/.factory"), { recursive: true });
    writeFileSync(join(template, "server/.factory/inbox.json"), "{}\n");
    made = join(scratch, "acme");
    const result = run(made, "acme-notes");
    assert.equal(result.status, 0, result.stderr);
});

after(() =>
{
    rmSync(join(template, "server/node_modules/left-over"), { recursive: true, force: true });
    rmSync(join(template, "server/.factory"), { recursive: true, force: true });
    for (const leftover of [join(template, "server/node_modules")])
    {
        // 원래 비어 있던 폴더만 걷는다
        if (existsSync(leftover) && readdirSync(leftover).length === 0)
        {
            rmSync(leftover, { recursive: true });
        }
    }
    rmSync(scratch, { recursive: true, force: true });
});

test("템플릿을 새 폴더로 복사하고 플러그인 · MCP 서버 · 서버 패키지 · 앱의 이름을 바꾼다", () =>
{
    assert.equal(json(join(made, "plugin/plugin.json")).name, "acme-notes");
    assert.equal(json(join(made, "plugin/.claude-plugin/plugin.json")).name, "acme-notes");
    assert.deepEqual(Object.keys(json(join(made, "plugin/.mcp.json")).mcpServers as Record<string, unknown>), ["acme-notes"]);
    assert.equal(json(join(made, "server/package.json")).name, "acme-notes-server");
    const brand = readFileSync(join(made, "server/src/brand.ts"), "utf8");
    assert.match(brand, /export const NAME = "acme-notes";/);
    // 레이어의 앱 이름은 소문자 · 숫자 · 밑줄만 받는다
    assert.match(brand, /export const APP = "acme_notes";/);
    // 자리표시가 남지 않는다
    for (const path of ["plugin/plugin.json", "plugin/.claude-plugin/plugin.json", "plugin/.mcp.json", "server/package.json", "server/src/brand.ts"])
    {
        assert.doesNotMatch(readFileSync(join(made, path), "utf8"), /"starter/, path);
    }
    // 나머지는 템플릿과 같다
    for (const path of ["scaffold/orbital.toml", "server/src/tools.ts", "README.md"])
    {
        assert.equal(readFileSync(join(made, path), "utf8"), readFileSync(join(template, path), "utf8"), path);
    }
});

test("복사본의 서버는 저장소의 SDK 를 npm pack 한 tarball 로 문다", () =>
{
    const dependency = (json(join(made, "server/package.json")).dependencies as Record<string, string>)["@harmony/orbital"] ?? "";
    assert.match(dependency, /^file:\.\.\/vendor\/harmony-orbital-[0-9.]+\.tgz$/);
    const tarball = join(made, "server", dependency.slice("file:".length));
    assert.ok(existsSync(tarball), tarball);
    const listed = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).split("\n").filter((line) => line !== "").sort();
    assert.deepEqual(listed, ["package/dist/app.d.ts", "package/dist/app.js", "package/dist/server.d.ts", "package/dist/server.js", "package/package.json"]);
    // 저장소 안에서만 쓰는 조건(소스를 읽는 orbital-source)은 복사본의 스크립트와 tsconfig 에 없다
    for (const path of ["server/package.json", "server/tsconfig.json"])
    {
        assert.doesNotMatch(readFileSync(join(made, path), "utf8"), /orbital-source/, path);
    }
});

test("node_modules · .factory · 묶은 tarball 은 복사하지 않는다", () =>
{
    const files = walk(made);
    assert.deepEqual(files.filter((path) => /(^|\/)(node_modules|\.factory)(\/|$)/.test(path)), []);
    // vendor 에는 이번에 묶은 tarball 하나뿐이다
    assert.equal(files.filter((path) => path.startsWith("vendor/")).length, 1);
    // 템플릿의 파일은 모두 왔다(남은 것을 뺀)
    const expected = walk(template).filter((path) => !/(^|\/)(node_modules|\.factory)(\/|$)/.test(path) && !path.startsWith("vendor/"));
    for (const path of expected)
    {
        assert.ok(files.includes(path), path);
    }
});

test("이름이 틀리거나 폴더가 비어 있지 않으면 아무것도 쓰지 않고 무엇을 고칠지 말한다", () =>
{
    for (const name of ["Acme", "1acme", "acme_notes", "pg-acme", "a", "a".repeat(25), "orbital"])
    {
        const target = join(scratch, `bad-${Math.random().toString(16).slice(2)}`);
        const result = run(target, name);
        assert.notEqual(result.status, 0, name);
        assert.match(result.stderr, /이름/, name);
        assert.ok(!existsSync(target), `${name}: 폴더를 만들면 안 됩니다`);
    }
    const busy = join(scratch, "busy");
    mkdirSync(busy);
    writeFileSync(join(busy, "keep.txt"), "그대로");
    const refused = run(busy, "busy");
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /비어 있지 않습니다/);
    assert.deepEqual(readdirSync(busy), ["keep.txt"]);
    // 적을 것을 빠뜨려도 쓰는 법을 말한다
    const usage = run();
    assert.notEqual(usage.status, 0);
    assert.match(usage.stderr, /new-factory\.mjs <폴더> <이름>/);
});

test("스캐폴드에 실린 orbital-app.js 는 SDK 의 app.ts 에서 타입만 걷은 것과 같다", () =>
{
    const expected = stripTypeScriptTypes(readFileSync(join(root, "sdk/typescript/src/app.ts"), "utf8"));
    assert.equal(readFileSync(join(template, "scaffold/lib/orbital-app.js"), "utf8"), expected, "templates/factory-starter/scaffold/lib/orbital-app.js 를 새로 써 주세요");
});

test("스캐폴드의 선언과 권한 표는 orbital check 를 통과한다", () =>
{
    const result = spawnSync(bin("orbital"), ["check", join(template, "scaffold")], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
