// 플랫폼 없이 한 바퀴를 돌려 본다. 띄운 팩토리의 서버에 플랫폼처럼 연결하고(개발용 연결), 에이전트처럼 작업을 열어 평범한 `git` 으로 받은 뒤 프리뷰를 세운다.
//
//   npm run try -- [폴더] [계정]          기본: ../try-app, 계정 dev
//
// 처음이면 그 계정의 인스턴스가 스캐폴드에서 서고, 받은 폴더에 고객의 사본이 생긴다. 고쳐 보고 싶으면 그 폴더에서 고쳐 commit 한 뒤 다시 부른다.
// 이 스크립트는 팩토리의 서버만 부른다(`FACTORY_PUBLIC_URL`, 기본 http://127.0.0.1:3840). 레이어의 주소와 열쇠는 쓰지 않는다.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

import {
    Client,
    StreamableHTTPClientTransport,
    discoverAuthorizationServerMetadata,
    discoverOAuthProtectedResourceMetadata,
    exchangeAuthorization,
    registerClient,
    startAuthorization,
} from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";

const origin = (process.env.FACTORY_PUBLIC_URL ?? "").replace(/\/+$/, "") || `http://127.0.0.1:${process.env.FACTORY_PORT ?? "3840"}`;
const folder = resolve(process.argv[2] ?? "../try-app");
const account = process.argv[3] ?? "dev";
const REDIRECT = "http://127.0.0.1:9/callback";

/** 플랫폼이 하듯이 계정을 연결한다: 보호 자원 → 인가 서버 → 동적 등록 → 로그인(개발용: 계정 이름) → 코드 교환 */
async function connect(): Promise<string>
{
    const resource = await discoverOAuthProtectedResourceMetadata(`${origin}/mcp`);
    const issuer = resource.authorization_servers?.[0] ?? "";
    const metadata = await discoverAuthorizationServerMetadata(issuer);
    if (metadata === undefined)
    {
        throw new Error("인가 서버 메타데이터를 받지 못했습니다");
    }
    const client = await registerClient(issuer, { metadata, clientMetadata: { client_name: "npm run try", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" } });
    const started = await startAuthorization(issuer, { metadata, clientInformation: client, redirectUrl: REDIRECT, resource: new URL(resource.resource) });
    const form = new URLSearchParams(started.authorizationUrl.searchParams);
    form.set("account", account);
    form.set("decision", "allow");
    const answered = await fetch(`${origin}/oauth/authorize`, { method: "POST", body: form, redirect: "manual" });
    const back = new URL(answered.headers.get("location") ?? "");
    const tokens = await exchangeAuthorization(issuer, {
        metadata,
        clientInformation: client,
        authorizationCode: back.searchParams.get("code") ?? "",
        iss: back.searchParams.get("iss") ?? "",
        codeVerifier: started.codeVerifier,
        redirectUri: REDIRECT,
    });
    return tokens.access_token;
}

function textOf(result: CallToolResult): string
{
    return result.content.map((block) => (block.type === "text" ? block.text : "")).join("\n");
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<CallToolResult>
{
    const result = (await client.callTool({ name, arguments: args })) as CallToolResult;
    if (result.isError === true)
    {
        throw new Error(`${name}: ${textOf(result)}`);
    }
    return result;
}

function git(cwd: string, credential: string, ...args: string[]): void
{
    execFileSync("git", ["-c", `http.extraHeader=Authorization: Bearer ${credential}`, ...args], { cwd, stdio: "inherit" });
}

const started = Date.now();
try
{
    const token = await connect();
    const client = new Client({ name: "npm run try", version: "0.0.0" }, { versionNegotiation: { mode: "auto" } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    console.log(`[try] ${account} 로 연결했습니다. 작업을 엽니다(처음이면 인스턴스가 섭니다)`);
    const opened = (await call(client, "workspace_open")).structuredContent as { remote: string; credential: string };
    if (existsSync(folder))
    {
        execFileSync("git", ["remote", "set-url", "origin", opened.remote], { cwd: folder });
        git(folder, opened.credential, "push", "--quiet", "origin", "main");
        console.log(`[try] ${folder} 의 main 을 올렸습니다`);
    }
    else
    {
        git(resolve(folder, ".."), opened.credential, "clone", "--quiet", opened.remote, folder);
        console.log(`[try] 고객의 사본을 ${folder} 에 받았습니다`);
    }
    console.log("[try] 프리뷰를 세웁니다(레이어가 빌드합니다. 처음에는 1분쯤 걸립니다)");
    const shown = await call(client, "preview");
    const report = shown.structuredContent as { release: string; services: { name: string; url: string | null }[] };
    console.log(textOf(shown).split("\n")[0] ?? "");
    for (const service of report.services)
    {
        console.log(`[try] 프리뷰 ${service.name}: ${service.url ?? "(정적 파일)"}`);
    }
    console.log(`[try] ${((Date.now() - started) / 1000).toFixed(1)}초. 씨앗 사용자로 들어가려면 플랫폼에서 preview_sign_in 을 부르거나 /health 를 열어 보세요`);
    console.log(JSON.stringify({ release: report.release, services: report.services }));
    await client.close();
}
catch (error)
{
    console.error(`[try] 멈췄습니다: ${error instanceof Error ? error.message : String(error)}`);
    console.error("[try] 팩토리의 서버가 떠 있는지(npm start), 레이어가 떠 있는지 확인해 주세요.");
    process.exit(1);
}
