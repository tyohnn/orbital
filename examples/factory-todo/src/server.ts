// 팩토리의 HTTP 서버. `/mcp` 는 OAuth 로 지켜지는 MCP 서버이고, 나머지는 그 인가 서버(`oauth.ts`)다.
//
// | 자리 | 무엇 |
// |---|---|
// | `POST /mcp` | MCP 서버(SDK 2.x 의 `createMcpHandler`, 요청마다 새 서버를 세우는 상태 없는 방식). 2026-07-28 과 옛 버전을 함께 받는다 |
// | `/.well-known/*` · `/oauth/*` | 앱에 연결한 계정을 알아보는 인가 서버 |
// | `GET /health` | 떠 있는지 |
//
// ⚠ `/mcp` 는 토큰이 없으면 어떤 요청도 받지 않고 401 과 보호 자원 메타데이터의 주소로 답한다. 플랫폼은 그것을 보고 「연결하기」를 연다.
// ⚠ 고객은 토큰의 주체다. MCP 서버는 요청마다 그 고객에 묶여 서고(`authInfo`), 도구는 인자로 고객이나 인스턴스를 받지 않는다.
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createMcpHandler, ResourceNotFoundError, Server } from "@modelcontextprotocol/server";
import type { McpRequestContext } from "@modelcontextprotocol/server";

import type { Answer, Grant, OAuth } from "./oauth.ts";
import { CARD_URI, TOOLS } from "./tools.ts";
import type { Factory } from "./tools.ts";

const WIDGET = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "widget.html"), "utf8");
const CARD_MIME = "text/html;profile=mcp-app";

export interface ServeOptions
{
    factory: Factory;
    oauth: OAuth;
}

function mcpServer(factory: Factory, context: McpRequestContext): Server
{
    const server = new Server({ name: "factory-todo", version: "0.1.0" }, { capabilities: { tools: {}, resources: {} } });
    const extra = context.authInfo?.extra;
    const customer = typeof extra?.subject === "string" ? extra.subject : "";

    server.setRequestHandler("tools/list", async () => ({ tools: TOOLS }));
    server.setRequestHandler("tools/call", async (request) =>
    {
        const args = request.params.arguments ?? {};
        return await factory.call(request.params.name, args, customer);
    });
    server.setRequestHandler("resources/list", async () => ({
        resources: [{ uri: CARD_URI, name: "promotion", title: "승인 카드", mimeType: CARD_MIME }],
    }));
    server.setRequestHandler("resources/read", async (request) =>
    {
        if (request.params.uri !== CARD_URI)
        {
            throw new ResourceNotFoundError(request.params.uri, `없는 리소스입니다: ${request.params.uri}`);
        }
        return {
            contents: [{
                uri: CARD_URI,
                mimeType: CARD_MIME,
                text: WIDGET,
                // 화면은 밖으로 요청을 보내지 않는다. 도구는 호스트의 다리로만 부른다
                _meta: { ui: { prefersBorder: true }, "openai/widgetDescription": "사람이 운영에 올릴지 승인하는 카드예요. 카드에 보인 것을 다시 말하지 않아도 돼요." },
            }],
        };
    });
    return server;
}

async function readText(request: IncomingMessage): Promise<string>
{
    const chunks: Buffer[] = [];
    for await (const chunk of request)
    {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    }
    return Buffer.concat(chunks).toString("utf8");
}

function send(response: ServerResponse, answer: Answer): void
{
    if (answer.html !== undefined)
    {
        response.writeHead(answer.status, { "content-type": "text/html; charset=utf-8", ...answer.headers });
        response.end(answer.html);
        return;
    }
    if (answer.body === undefined)
    {
        response.writeHead(answer.status, { ...answer.headers });
        response.end();
        return;
    }
    response.writeHead(answer.status, { "content-type": "application/json; charset=utf-8", ...answer.headers });
    response.end(JSON.stringify(answer.body));
}

function webHeaders(incoming: IncomingMessage["headers"]): Headers
{
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming))
    {
        for (const one of Array.isArray(value) ? value : [value])
        {
            if (one !== undefined)
            {
                headers.append(name, one);
            }
        }
    }
    return headers;
}

/** node:http 의 요청을 SDK 의 웹 표준 처리기에 넘기고 답을 받은 그대로 흘려보낸다 */
async function serveMcp(handle: ReturnType<typeof createMcpHandler>, origin: string, request: IncomingMessage, response: ServerResponse, grant: Grant, text: string): Promise<void>
{
    const aborted = new AbortController();
    response.on("close", () =>
    {
        if (!response.writableFinished)
        {
            aborted.abort();
        }
    });
    const web = new Request(`${origin}${request.url ?? "/"}`, { method: "POST", headers: webHeaders(request.headers), body: text, signal: aborted.signal });
    const answer = await handle.fetch(web, {
        authInfo: { token: "", clientId: grant.clientId, scopes: [], expiresAt: Math.floor(grant.expiresAt / 1000), extra: { subject: grant.subject } },
    });
    response.writeHead(answer.status, Object.fromEntries(answer.headers.entries()));
    if (answer.body !== null)
    {
        for await (const chunk of answer.body)
        {
            response.write(chunk);
        }
    }
    response.end();
}

export function serve(options: ServeOptions, origin: string): HttpServer
{
    const handle = createMcpHandler((context) => mcpServer(options.factory, context));

    return createServer((request, response) =>
    {
        const url = new URL(request.url ?? "/", origin);
        const method = request.method ?? "GET";

        const work = async (): Promise<void> =>
        {
            if (url.pathname === "/mcp")
            {
                const checked = options.oauth.guard(request.headers.authorization);
                if ("refused" in checked)
                {
                    // 몸을 다 읽고 답한다. 읽지 않고 닫으면 클라이언트가 답 대신 끊긴 연결을 본다
                    await readText(request);
                    send(response, checked.refused);
                    return;
                }
                if (method !== "POST")
                {
                    send(response, { status: 405, headers: { allow: "POST" }, body: { error: "method_not_allowed", error_description: "POST 로만 받습니다" } });
                    return;
                }
                await serveMcp(handle, origin, request, response, checked.grant, await readText(request));
                return;
            }
            const answered = await options.oauth.handle(method, url, () => readText(request));
            if (answered !== undefined)
            {
                send(response, answered);
                return;
            }
            if (url.pathname === "/health")
            {
                send(response, { status: 200, body: { ok: true } });
                return;
            }
            send(response, { status: 404, body: { error: "not_found" } });
        };

        work().catch(() =>
        {
            // 오류의 글은 싣지 않는다. 무엇이 섞였는지 모르는 글을 밖으로 내보내지 않는다
            if (!response.headersSent)
            {
                send(response, { status: 500, body: { error: "internal", error_description: "팩토리 서버가 요청을 처리하지 못했습니다. 잠시 뒤에 다시 해 주세요" } });
            }
            else
            {
                response.end();
            }
        });
    });
}
