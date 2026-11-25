// crate 사이의 의존이 층 규약대로인지 본다. 규약의 정본은 이 파일의 LAYER 표다.
//
// 보는 것은 셋이다.
//   1. 모든 crate 가 LAYER 표에 있다. 새 crate 를 만들면 이 표에 줄을 더하는 것이 첫 작업이다.
//   2. 아래 층은 위 층을 가리키지 않는다. 앱 → 어댑터 → 도메인 한 방향이다.
//   3. 도메인 crate 의 런타임 의존은 DOMAIN_ALLOWED 안에서만 고른다. 파일 · 네트워크 · 시계에 닿는 crate 를 막는다.
//      dev-dependencies(proptest 같은 테스트 도구)는 보지 않는다.
import { execFileSync } from "node:child_process";

const LAYER = {
    "orbital-core": "domain",
    "orbital-pg": "adapter",
    "orbital-proxy": "adapter",
    "orbital-source": "adapter",
    "orbital-run": "adapter",
    "orbital-server": "app",
    "orbital-cli": "app",
};

const RANK = { domain: 0, adapter: 1, app: 2 };

const DOMAIN_ALLOWED = new Set(["serde"]);

const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { encoding: "utf8" }),
);

const members = new Set(metadata.workspace_members);
const crates = metadata.packages.filter((pkg) => members.has(pkg.id));
const names = new Set(crates.map((pkg) => pkg.name));
const problems = [];

for (const pkg of crates)
{
    const layer = LAYER[pkg.name];
    if (layer === undefined)
    {
        problems.push(`${pkg.name}: LAYER 표에 없습니다. scripts/check-layers.mjs 의 LAYER 에 층을 적어 주세요`);
        continue;
    }

    for (const dep of pkg.dependencies)
    {
        if (dep.kind === "dev")
        {
            continue;
        }

        if (names.has(dep.name))
        {
            const target = LAYER[dep.name];
            if (target !== undefined && RANK[target] > RANK[layer])
            {
                problems.push(`${pkg.name}(${layer}) → ${dep.name}(${target}): 아래 층이 위 층을 가리킵니다`);
            }
            if (layer === "app" && target === "app")
            {
                problems.push(`${pkg.name} → ${dep.name}: 앱끼리는 서로 의존하지 않습니다. 공통 코드는 어댑터나 도메인으로 내립니다`);
            }
            continue;
        }

        if (layer === "domain" && !DOMAIN_ALLOWED.has(dep.name))
        {
            problems.push(`${pkg.name}: 도메인 crate 에 런타임 의존 ${dep.name} 을 넣을 수 없습니다. 허용 목록은 ${[...DOMAIN_ALLOWED].join(", ")} 입니다`);
        }
    }
}

if (problems.length > 0)
{
    console.error(`층 검사 실패 (${problems.length}):`);
    for (const problem of problems)
    {
        console.error(`  - ${problem}`);
    }
    process.exit(1);
}

console.log(`층 검사 통과: crate ${crates.length}개`);
