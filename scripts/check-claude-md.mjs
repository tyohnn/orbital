// 지시문의 길이를 잰다. 루트 CLAUDE.md 는 모든 요청에 실리고, 폴더 CLAUDE.md 는 그 폴더의 어느 파일을 열어도 실린다.
// 길어지면 줄이는 대신 내용을 규칙 · docs · 검사로 옮긴다. 옮길 곳은 루트 CLAUDE.md 의 표가, 문장의 모양은 .claude/rules/claude-md.md 가 정한다.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const LIMITS = [
    { match: (path) => path === "CLAUDE.md", lines: 120, label: "루트 CLAUDE.md" },
    { match: (path) => path.endsWith("/CLAUDE.md"), lines: 60, label: "폴더 CLAUDE.md" },
    { match: (path) => path.startsWith(".claude/rules/glossary/"), lines: 80, label: "용어 규칙" },
    { match: (path) => path.startsWith(".claude/rules/"), lines: 100, label: "경로 규칙" },
];

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" })
    .split("\n")
    .filter((path) => path.endsWith("CLAUDE.md") || (path.startsWith(".claude/rules/") && path.endsWith(".md")));

const problems = [];

for (const path of files)
{
    const limit = LIMITS.find((entry) => entry.match(path));
    if (limit === undefined)
    {
        continue;
    }

    const lines = readFileSync(path, "utf8").replace(/\n$/, "").split("\n").length;
    if (lines > limit.lines)
    {
        problems.push(`${path}: ${lines}줄. ${limit.label}은 ${limit.lines}줄까지입니다`);
    }

    const head = readFileSync(path, "utf8").slice(0, 200);
    if (path.startsWith(".claude/rules/") && !head.startsWith("---\npaths:"))
    {
        problems.push(`${path}: paths 가 없는 규칙은 늘 로드됩니다. 머리에 paths 를 적어 주세요`);
    }
}

if (problems.length > 0)
{
    console.error(`지시문 검사 실패 (${problems.length}):`);
    for (const problem of problems)
    {
        console.error(`  - ${problem}`);
    }
    process.exit(1);
}

console.log(`지시문 검사 통과: ${files.length}개`);
