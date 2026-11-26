// 테스트가 띄우는 `orbitald` 마다 다른 control database(`ORBITAL_CONTROL_DB`)를 주고, 끝나면 걷는다.
// 같은 클러스터를 다른 테스트와 함께 쓰므로 기록이 섞이지 않게 한다.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

/** 이 테스트의 control database 의 이름. 소문자 · 숫자 · 밑줄 24자 안이다. */
export function controlDatabase(): string
{
    return `ctl_${randomBytes(8).toString("hex")}`;
}

function psql(): string
{
    const root = "/usr/lib/postgresql";
    if (existsSync(root))
    {
        const versions = readdirSync(root).sort((a, b) => Number(b) - Number(a));
        for (const version of versions)
        {
            const candidate = join(root, version, "bin", "psql");
            if (existsSync(candidate))
            {
                return candidate;
            }
        }
    }
    return "psql";
}

/** control database 를 걷는다. 붙은 연결은 끊는다. */
export function dropControlDatabase(pg: string, name: string): void
{
    execFileSync(psql(), [pg, "-qAtc", `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`], { stdio: "ignore" });
}
