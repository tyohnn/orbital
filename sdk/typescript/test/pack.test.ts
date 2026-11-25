// npm 에 올릴 준비가 되었는지 잰다. 올리지는 않는다(npm 의 계정과 이름은 사람이 정한다).
//
// `npm pack` 으로 묶고(`prepack` 이 `dist/` 에 JavaScript 와 타입을 짓는다), 그 묶음을 새 폴더에 깔아 Node 가 `@harmony/orbital/app` 과
// `/server` 를 import 하는지 본다. 깐 쪽은 `orbital-source` 조건을 쓰지 않으므로 소스(.ts)가 아니라 지은 것을 읽는다.
// Node 는 node_modules 안의 .ts 에서 타입을 지우지 않아서, 소스만 묶으면 이 테스트가 깨진다.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const here = resolve(import.meta.dirname, "..");

test("SDK 는 npm pack 으로 묶이고, 새 폴더에 깔면 app 과 server 를 지은 JavaScript 로 import 한다", () =>
{
    const scratch = mkdtempSync(join(tmpdir(), "orbital-pack-"));
    try
    {
        const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--pack-destination", scratch], { cwd: here, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })) as { filename: string; files: { path: string }[] }[];
        const files = packed[0]?.files.map((file) => file.path).sort() ?? [];
        assert.deepEqual(files, ["dist/app.d.ts", "dist/app.js", "dist/server.d.ts", "dist/server.js", "package.json"]);

        const consumer = join(scratch, "consumer");
        execFileSync("mkdir", ["-p", consumer]);
        writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
        const tarball = readdirSync(scratch).find((name) => name.endsWith(".tgz")) ?? "";
        execFileSync("npm", ["install", "--no-audit", "--no-fund", "--offline", join(scratch, tarball)], { cwd: consumer, stdio: "ignore" });
        const loaded = execFileSync(process.execPath, [
            "--input-type=module",
            "-e",
            "const app = await import('@harmony/orbital/app'); const server = await import('@harmony/orbital/server'); console.log(JSON.stringify({ app: Object.keys(app).sort(), server: Object.keys(server).sort() }));",
        ], { cwd: consumer, encoding: "utf8" });
        const exported = JSON.parse(loaded) as { app: string[]; server: string[] };
        for (const name of ["orbitalApp", "identityOf", "OrbitalAppError"])
        {
            assert.ok(exported.app.includes(name), `${name}: ${exported.app.join(", ")}`);
        }
        for (const name of ["createOrbital", "OrbitalError"])
        {
            assert.ok(exported.server.includes(name), `${name}: ${exported.server.join(", ")}`);
        }
    }
    finally
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});
