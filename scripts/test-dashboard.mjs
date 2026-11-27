// 대시보드의 테스트를 돌리고, 그 테스트가 띄운 orbitald 가 세운 control database 를 걷는다.
//
// 대시보드의 테스트는 orbitald 에 `ORBITAL_CONTROL_DB` 를 주지 않아 기본 이름(`orbital_control`)의 control database 를 쓴다.
// 같은 클러스터에 그 이름이 이미 있으면 남의 기록과 섞이고 기계 `local` 의 관리 서버와 부딪치므로 돌리지 않는다.
// `ORBITAL_PG` 가 없으면 대시보드의 테스트가 스스로 건너뛰므로 그대로 돌린다.
//
//   node scripts/test-dashboard.mjs

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const CONTROL = "orbital_control";
const pg = process.env.ORBITAL_PG;

function psql()
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

function sql(text)
{
    return execFileSync(psql(), [pg, "-qAtc", text], { encoding: "utf8" }).trim();
}

if (pg !== undefined)
{
    if (sql(`SELECT count(*) FROM pg_database WHERE datname = '${CONTROL}'`) !== "0")
    {
        console.error(
            `test-dashboard: ORBITAL_PG 의 클러스터에 이미 \`${CONTROL}\` 이 있어 돌리지 않습니다. 테스트 전용 클러스터(scripts/pg-local.sh)를 주거나, 쓰지 않는 것이면 걷어 주세요`,
        );
        process.exit(1);
    }
}
const run = spawnSync("npm", ["test", "-w", "@harmony/orbital-dashboard"], { stdio: "inherit" });
if (pg !== undefined)
{
    sql(`DROP DATABASE IF EXISTS "${CONTROL}" WITH (FORCE)`);
}
process.exit(run.status ?? 1);
