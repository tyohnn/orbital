// 앱 패키지(ZIP)를 짓는다. 하모니와 클로드가 같은 ZIP 을 받는다.
//
//   npm run pack -- <나갈 ZIP> [MCP 서버의 주소]
//
// 묶는 것은 `plugin/` 폴더 그대로다: `plugin.json`(Agent Plugins 형식, 하모니가 읽는다), `.claude-plugin/plugin.json`(클로드가 읽는다),
// `.mcp.json`(MCP 서버 하나), `skills/app-dev/`(스킬 하나와 그 참고 문서). 훅은 없다.
// 에이전트가 설치하거나 부를 명령도 없다. 스킬은 이 앱의 도구와 평범한 `git` 만 쓰라고 말한다(레이어를 직접 부르지 않는다).
// 주소를 주면 `.mcp.json` 의 서버 주소를 그것으로 바꿔 싣는다(배포한 팩토리의 https 주소).
//
// ⚠ 압축하지 않고 담는다(stored). 글 파일 몇 개라 크기가 문제 되지 않고, 의존성 없이 짓는다. 시각은 고정해 같은 폴더면 같은 ZIP 이 된다.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32 } from "node:zlib";

export const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "plugin");

function walk(folder: string): string[]
{
    return readdirSync(folder).sort().flatMap((name) =>
    {
        const path = join(folder, name);
        return statSync(path).isDirectory() ? walk(path) : [path];
    });
}

/** 패키지의 파일들(ZIP 안의 경로 → 내용) */
export function packageFiles(serverUrl?: string): Map<string, Uint8Array>
{
    const files = new Map<string, Uint8Array>();
    for (const path of walk(PACKAGE_DIR))
    {
        const name = relative(PACKAGE_DIR, path).split(sep).join("/");
        let body: Uint8Array = readFileSync(path);
        if (name === ".mcp.json" && serverUrl !== undefined)
        {
            const parsed = JSON.parse(Buffer.from(body).toString("utf8")) as { mcpServers: Record<string, { url: string }> };
            for (const server of Object.values(parsed.mcpServers))
            {
                server.url = serverUrl;
            }
            body = Buffer.from(`${JSON.stringify(parsed, null, 4)}\n`);
        }
        files.set(name, body);
    }
    return files;
}

/** 파일들을 ZIP 하나로 */
export function zip(files: ReadonlyMap<string, Uint8Array>): Uint8Array
{
    // 2026-11-25 00:00 의 DOS 시각
    const time = 0;
    const date = ((2026 - 1980) << 9) | (11 << 5) | 25;
    const locals: Buffer[] = [];
    const centrals: Buffer[] = [];
    let offset = 0;

    for (const [name, body] of files)
    {
        const path = Buffer.from(name, "utf8");
        const sum = crc32(body);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(0x0800, 6); // 이름은 UTF-8
        local.writeUInt16LE(0, 8);
        local.writeUInt16LE(time, 10);
        local.writeUInt16LE(date, 12);
        local.writeUInt32LE(sum, 14);
        local.writeUInt32LE(body.length, 18);
        local.writeUInt32LE(body.length, 22);
        local.writeUInt16LE(path.length, 26);
        local.writeUInt16LE(0, 28);
        locals.push(local, path, Buffer.from(body));

        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(0x0800, 8);
        central.writeUInt16LE(0, 10);
        central.writeUInt16LE(time, 12);
        central.writeUInt16LE(date, 14);
        central.writeUInt32LE(sum, 16);
        central.writeUInt32LE(body.length, 20);
        central.writeUInt32LE(body.length, 24);
        central.writeUInt16LE(path.length, 28);
        central.writeUInt32LE(offset, 42);
        centrals.push(central, path);
        offset += local.length + path.length + body.length;
    }

    const directory = Buffer.concat(centrals);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(files.size, 8);
    end.writeUInt16LE(files.size, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, directory, end]);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1])
{
    const out = process.argv[2];
    if (out === undefined)
    {
        console.error("나갈 ZIP 의 경로를 적어 주세요: npm run pack -- <ZIP> [MCP 서버의 주소]");
        process.exit(1);
    }
    writeFileSync(out, zip(packageFiles(process.argv[3])));
    console.log(`[factory] 패키지를 지었습니다: ${out}`);
}
