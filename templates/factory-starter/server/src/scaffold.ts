// 팩토리의 스캐폴드를 레이어에 올린다. 폴더를 git 저장소로 묶어 버전 태그를 달고, git bundle 로 보낸다.
//
// ⚠ commit 의 시각과 작성자를 고정한다. 같은 폴더면 같은 commit 이 되어, 서버를 다시 띄워 다시 올려도 이미 선 인스턴스의 기준점이 바뀌지 않는다.
// ⚠ git 은 환경을 비우고 부른다. service key 가 git 의 프로세스에 보이지 않게 한다.
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FIXED = "2026-11-25T00:00:00Z";

/** 폴더를 묶음(git bundle)으로. `version` 태그를 단다 */
export function bundleScaffold(folder: string, version: string): Uint8Array
{
    const scratch = mkdtempSync(join(tmpdir(), "factory-scaffold-"));
    try
    {
        const work = join(scratch, "work");
        // 로컬에서 깔고 지은 것(`node_modules` · `.next`)은 싣지 않는다. 레이어가 그 commit 에서 직접 받고 짓는다
        cpSync(folder, work, { recursive: true, filter: (source) => !/[\\/](node_modules|\.next)$/.test(source) });
        const env = {
            PATH: process.env.PATH ?? "",
            HOME: scratch,
            GIT_AUTHOR_NAME: "factory",
            GIT_AUTHOR_EMAIL: "factory@example.invalid",
            GIT_AUTHOR_DATE: FIXED,
            GIT_COMMITTER_NAME: "factory",
            GIT_COMMITTER_EMAIL: "factory@example.invalid",
            GIT_COMMITTER_DATE: FIXED,
        };
        const git = (...args: string[]): void =>
        {
            execFileSync("git", ["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args], { cwd: work, env, stdio: "ignore" });
        };
        git("init", "--quiet", "--initial-branch", "main");
        git("add", "-A");
        git("commit", "--quiet", "-m", `스캐폴드 ${version}`);
        git("tag", version);
        git("bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
        return readFileSync(join(scratch, "scaffold.bundle"));
    }
    finally
    {
        rmSync(scratch, { recursive: true, force: true });
    }
}
