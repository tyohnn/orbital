// 팩토리의 시작 템플릿(templates/factory-starter)을 새 폴더로 복사하고 이름을 바꾼다.
//
//   node scripts/new-factory.mjs <폴더> <이름>
//
// 하는 일은 넷이다.
//   1. 템플릿을 복사한다. 개발하다 남은 것(node_modules · .factory · .next · vendor 의 tarball)은 빼고 복사한다.
//   2. 이름을 바꾼다. 플러그인(plugin.json 둘) · MCP 서버(.mcp.json 의 열쇠) · 서버 패키지(server/package.json) · 레이어의 앱(server/src/brand.ts).
//   3. 저장소의 SDK(sdk/typescript)를 npm pack 해 <폴더>/vendor/ 에 두고, 서버가 그 tarball 을 file: 로 물게 한다.
//      SDK 를 npm 에 올린 뒤에는 이 한 줄이 "@harmony/orbital": "^0.1.0" 으로 바뀐다.
//   4. 다음에 칠 명령을 찍는다.
// 이름이 틀리거나 폴더가 비어 있지 않으면 아무것도 쓰지 않고 멈춘다.
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const template = join(root, "templates", "factory-starter");
const sdk = join(root, "sdk", "typescript");
/** 템플릿이 쓰는 자리표시 이름 */
const PLACEHOLDER = "starter";
/** 레이어와 Postgres 가 쓰는 이름. 앱의 이름(밑줄로 바꾼 것)으로 쓰지 못한다 */
const RESERVED = new Set(["public", "orbital", "orbital_auth", "information_schema", "postgres", "rls"]);
const SKIP = /(^|[\\/])(node_modules|\.factory|\.next)$/;

function fail(line)
{
    console.error(line);
    process.exit(1);
}

const [target, name] = process.argv.slice(2);
if (target === undefined || name === undefined)
{
    fail("쓰는 법: node scripts/new-factory.mjs <폴더> <이름>  (예: node scripts/new-factory.mjs ../acme acme-notes)");
}
// 이름은 플러그인 · 패키지의 이름이 되고, 하이픈을 밑줄로 바꾼 것이 레이어의 앱 이름(24자 안)이 된다
if (!/^[a-z][a-z0-9-]{1,23}$/.test(name) || name.endsWith("-") || name.includes("--"))
{
    fail(`이름 \`${name}\` 을 쓸 수 없습니다. 영문 소문자로 시작하고 소문자 · 숫자 · 하이픈으로 2~24자로 적어 주세요(예: acme-notes)`);
}
const app = name.replaceAll("-", "_");
if (app.startsWith("pg_") || RESERVED.has(app))
{
    fail(`이름 \`${name}\` 은 레이어가 쓰는 이름이라 쓸 수 없습니다. 다른 이름을 적어 주세요`);
}
const destination = resolve(target);
if (existsSync(destination) && readdirSync(destination).length > 0)
{
    fail(`폴더 ${destination} 가 비어 있지 않습니다. 없는 폴더나 빈 폴더를 적어 주세요`);
}

// 1. 복사
mkdirSync(destination, { recursive: true });
cpSync(template, destination, {
    recursive: true,
    filter: (source) => !SKIP.test(source) && !(basename(dirname(source)) === "vendor" && source.endsWith(".tgz")),
});

// 2. 이름
const editJson = (path, edit) =>
{
    const file = join(destination, path);
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    edit(parsed);
    writeFileSync(file, `${JSON.stringify(parsed, null, 4)}\n`);
};
const replaceOnce = (path, before, after) =>
{
    const file = join(destination, path);
    const text = readFileSync(file, "utf8");
    if (text.split(before).length !== 2)
    {
        rmSync(destination, { recursive: true, force: true });
        fail(`템플릿의 ${path} 에서 \`${before}\` 를 한 번 찾아야 하는데 찾지 못했습니다. scripts/new-factory.mjs 를 템플릿에 맞춰 고쳐 주세요`);
    }
    writeFileSync(file, text.replace(before, after));
};
editJson("plugin/plugin.json", (plugin) => { plugin.name = name; });
editJson("plugin/.claude-plugin/plugin.json", (plugin) => { plugin.name = name; });
editJson("plugin/.mcp.json", (config) =>
{
    const server = config.mcpServers[PLACEHOLDER];
    config.mcpServers = { [name]: server };
});
replaceOnce("server/src/brand.ts", `export const NAME = "${PLACEHOLDER}";`, `export const NAME = "${name}";`);
replaceOnce("server/src/brand.ts", `export const APP = "${PLACEHOLDER}";`, `export const APP = "${app}";`);

// 3. SDK 를 묶어 물린다. prepack 이 dist/ 에 JavaScript 와 타입을 짓는다
const vendor = join(destination, "vendor");
mkdirSync(vendor, { recursive: true });
let packed;
try
{
    packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--pack-destination", vendor], { cwd: sdk, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
}
catch (error)
{
    rmSync(destination, { recursive: true, force: true });
    fail(`저장소의 SDK 를 npm pack 하지 못했습니다. 저장소에서 npm install 을 먼저 해 주세요.\n${error.stderr ?? ""}`);
}
const tarball = packed[0].filename;
editJson("server/package.json", (pkg) =>
{
    pkg.name = `${name}-server`;
    pkg.dependencies["@harmony/orbital"] = `file:../vendor/${tarball}`;
});

// 4. 다음 차례
console.log(`팩토리 ${name} 를 ${destination} 에 만들었습니다(레이어의 앱 이름 ${app}).`);
console.log("다음:");
console.log(`  cd ${join(destination, "server")} && npm install`);
console.log("  ORBITAL_URL=<레이어의 주소> ORBITAL_SERVICE_KEY=orb_sk_… npm start");
console.log("  (다른 터미널에서) npm run try");
console.log(`자세한 차례는 ${join(destination, "README.md")} 에 있습니다.`);
