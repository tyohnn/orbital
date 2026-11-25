// SDK 의 테스트가 함께 쓰는 것: 팩토리의 git 의 길을 흉내 낸 작은 서버와, 그 주소로 붙는 실제 `git`.
//
// 팩토리의 서버가 하듯이 `/git/<작업>/…` 로 받은 요청을 그 작업의 `git.relay` 로 넘긴다. 작업의 이름은 테스트 안에서만 쓰는
// 추측하지 못할 글자다(팩토리의 본보기는 이 앞에서 고객의 자격을 확인한다. 여기서는 SDK 의 이어 주기만 잰다).
// ⚠ git 은 비동기로 부른다. 이 서버가 같은 프로세스에 있어서, 동기로 부르면 서버가 답하지 못해 서로 기다린다.

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import { promisify } from "node:util";

import type { Work } from "../src/server.ts";

const run = promisify(execFile);

/** 사람의 git 설정이 섞이지 않는 git. 실패하면 표준 오류를 담아 던진다. */
export async function git(folder: string, ...args: string[]): Promise<string>
{
    try
    {
        const { stdout } = await run(
            "git",
            ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
            { cwd: folder, encoding: "utf8", env: { PATH: process.env.PATH ?? "", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" } },
        );
        return stdout.trim();
    }
    catch (error)
    {
        const stderr = typeof error === "object" && error !== null && "stderr" in error ? String(error.stderr) : "";
        throw new Error(`git ${args.join(" ")}: ${stderr}`);
    }
}

function webRequest(origin: string, request: IncomingMessage): Request
{
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers))
    {
        for (const one of Array.isArray(value) ? value : [value])
        {
            if (one !== undefined)
            {
                headers.append(name, one);
            }
        }
    }
    const method = request.method ?? "GET";
    const init: RequestInit & { duplex?: "half" } = { method, headers };
    if (method !== "GET" && method !== "HEAD")
    {
        init.body = Readable.toWeb(request) as ReadableStream<Uint8Array>;
        init.duplex = "half";
    }
    return new Request(`${origin}${request.url ?? "/"}`, init);
}

export interface Relay
{
    /** 이 작업의 원격 주소. `git clone` 에 그대로 쓴다. */
    remote(work: Work): string;
    /** 지나간 요청의 경로. */
    readonly seen: string[];
    close(): Promise<void>;
}

export async function startRelay(): Promise<Relay>
{
    const works = new Map<string, Work>();
    const seen: string[] = [];
    let origin = "";
    const server = createServer((request, response) =>
    {
        seen.push(request.url ?? "");
        const [, first, key] = new URL(request.url ?? "/", "http://relay").pathname.split("/");
        const work = first === "git" ? works.get(key ?? "") : undefined;
        if (work === undefined)
        {
            request.resume();
            response.writeHead(404).end();
            return;
        }
        work.git.relay(webRequest(origin, request))
            .then(async (answer) =>
            {
                response.writeHead(answer.status, Object.fromEntries(answer.headers.entries()));
                if (answer.body !== null)
                {
                    for await (const chunk of Readable.fromWeb(answer.body as NodeReadableStream<Uint8Array>))
                    {
                        response.write(chunk);
                    }
                }
                response.end();
            })
            .catch(() =>
            {
                if (!response.headersSent)
                {
                    response.writeHead(502);
                }
                response.end();
            });
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    return {
        remote(work)
        {
            const key = randomBytes(12).toString("hex");
            works.set(key, work);
            return `${origin}/git/${key}`;
        },
        seen,
        async close()
        {
            server.closeAllConnections();
            await new Promise<void>((done) => server.close(() => done()));
        },
    };
}
