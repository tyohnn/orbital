// 플랫폼의 연결(OAuth). 앱에 연결한 계정을 알아본다. 이 서버가 인가 서버이자 보호 자원(`/mcp`)이다.
//
// 에이전트 플랫폼(하모니 · 클로드)은 사람이 「연결하기」를 누르면 이 인가 서버에서 토큰을 받아 금고에 두고, 앱 서버를 부를 때마다
// `Authorization: Bearer …` 로 싣는다. 모델이 부른 도구든 화면이 부른 도구든 같다. 팩토리는 그 토큰의 주체(`subject`)를 고객으로 본다.
//
// | 자리 | 무엇 |
// |---|---|
// | `GET /.well-known/oauth-protected-resource/mcp` | 보호 자원 메타데이터(RFC 9728). 인가 서버는 이 서버다 |
// | `GET /.well-known/oauth-authorization-server` | 인가 서버 메타데이터(RFC 8414) |
// | `POST /oauth/register` | 동적 등록(RFC 7591). 공개 클라이언트만 받는다 |
// | `GET` · `POST /oauth/authorize` | 로그인과 동의. 허락하면 code 를 실어 콜백으로 돌려보낸다(PKCE S256) |
// | `POST /oauth/token` | 인가 코드와 갱신 토큰 |
//
// ⚠ **개발용 연결이다. 로그인은 계정 이름을 적는 칸 하나이고 그 이름을 믿는다.** 그래서 서버는 이 연결로 바깥 주소에서 뜨지 않는다(`main.ts`).
//   ✏️ 운영에 내기 전에 여기에 당신의 로그인을 붙인다. 바뀌는 것은 `subject`(고객의 계정 식별자)를 정하는 자리(`POST /oauth/authorize`)뿐이다.
// ⚠ 토큰과 코드와 클라이언트는 이 프로세스의 메모리에만 있다. 서버가 다시 뜨면 사라지고, 플랫폼은 사람에게 다시 연결하라고 보인다.
//   고객과 인스턴스의 짝은 `accounts.ts` 가 정한다.
import { createHash, randomBytes } from "node:crypto";

import { TITLE } from "./brand.ts";

export interface Grant
{
    readonly clientId: string;
    /** 연결한 계정. 팩토리의 고객이다 */
    readonly subject: string;
    readonly expiresAt: number;
}

export interface Answer
{
    readonly status: number;
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: unknown;
    readonly html?: string;
}

interface Client
{
    readonly name: string;
    readonly redirectUris: readonly string[];
}

interface Code
{
    readonly clientId: string;
    readonly redirectUri: string;
    readonly challenge: string;
    readonly subject: string;
    readonly expiresAt: number;
}

const CODE_TTL_MS = 60_000;
const ACCESS_TTL_S = 3600;
/** 계정 이름의 모양. 파일의 열쇠가 되므로 좁힌다 */
const ACCOUNT = /^[a-z0-9][a-z0-9._-]{0,63}$/;

const escape = (text: string): string =>
    text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const secret = (prefix: string): string => `${prefix}_${randomBytes(24).toString("base64url")}`;

const list = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

export interface OAuth
{
    /** `/mcp` 의 문. 토큰이 맞으면 그 연결을, 아니면 보낼 401 을 돌려준다 */
    guard(authorization: string | undefined): { grant: Grant } | { refused: Answer };
    /** 토큰으로 연결을 찾는다. 없거나 끝났으면 `undefined` 다 */
    grantOf(authorization: string | null | undefined): Grant | undefined;
    /** OAuth 의 자리를 맡는다. 맡지 않는 주소면 `undefined` 다 */
    handle(method: string, url: URL, body: () => Promise<string>): Promise<Answer | undefined>;
}

export function createOAuth(origin: string): OAuth
{
    const resource = `${origin}/mcp`;
    const metadataUrl = `${origin}/.well-known/oauth-protected-resource/mcp`;
    const clients = new Map<string, Client>();
    const codes = new Map<string, Code>();
    const access = new Map<string, Grant>();
    const refresh = new Map<string, Omit<Grant, "expiresAt">>();

    const challenge = (): Answer => ({
        status: 401,
        headers: { "www-authenticate": `Bearer resource_metadata="${metadataUrl}"` },
        body: { error: "invalid_token", error_description: "연결이 없거나 끝났습니다. 앱을 다시 연결해 주세요" },
    });

    const issue = (clientId: string, subject: string): Answer =>
    {
        const accessToken = secret("fat");
        const refreshToken = secret("frt");
        access.set(accessToken, { clientId, subject, expiresAt: Date.now() + ACCESS_TTL_S * 1000 });
        refresh.set(refreshToken, { clientId, subject });
        return {
            status: 200,
            headers: { "cache-control": "no-store" },
            body: { access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TTL_S, refresh_token: refreshToken },
        };
    };

    const grantOf = (authorization: string | null | undefined): Grant | undefined =>
    {
        const token = typeof authorization === "string" && authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
        const grant = access.get(token);
        return grant !== undefined && grant.expiresAt > Date.now() ? grant : undefined;
    };

    /** 동의 화면에 온 요청이 등록한 클라이언트의 것이고 PKCE 를 갖췄는지 */
    const clientFor = (params: URLSearchParams): Client | undefined =>
    {
        const client = clients.get(params.get("client_id") ?? "");
        const ok = client !== undefined
            && client.redirectUris.includes(params.get("redirect_uri") ?? "")
            && params.get("response_type") === "code"
            && params.get("code_challenge_method") === "S256"
            && (params.get("code_challenge") ?? "") !== "";
        return ok ? client : undefined;
    };

    const loginPage = (client: Client, params: URLSearchParams, problem?: string): string =>
    {
        const hidden = [...params.entries()]
            .filter(([name]) => name !== "account" && name !== "decision")
            .map(([name, value]) => `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`)
            .join("");
        return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${escape(TITLE)}에 연결</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}button{font-size:1rem;padding:.5rem 1rem;margin-right:.5rem}input{font-size:1rem}</style></head>
<body><h1>${escape(TITLE)}에 연결할까요?</h1>
<p>${escape(client.name)}이 내 앱을 고치고, 고친 것을 내 승인을 받아 올릴 수 있게 돼요.</p>
${problem === undefined ? "" : `<p role="alert">${escape(problem)}</p>`}
<form method="post" action="/oauth/authorize">${hidden}
<p><label>계정 <input name="account" autocomplete="username" required></label></p>
<button name="decision" value="allow">연결하기</button><button name="decision" value="deny">거절하기</button></form>
</body></html>`;
    };

    const handle = async (method: string, url: URL, body: () => Promise<string>): Promise<Answer | undefined> =>
    {
        const path = url.pathname;

        if (method === "GET" && (path === "/.well-known/oauth-protected-resource/mcp" || path === "/.well-known/oauth-protected-resource"))
        {
            return { status: 200, body: { resource, authorization_servers: [origin], resource_name: TITLE } };
        }

        if (method === "GET" && path === "/.well-known/oauth-authorization-server")
        {
            return {
                status: 200,
                body: {
                    issuer: origin,
                    authorization_endpoint: `${origin}/oauth/authorize`,
                    token_endpoint: `${origin}/oauth/token`,
                    registration_endpoint: `${origin}/oauth/register`,
                    response_types_supported: ["code"],
                    grant_types_supported: ["authorization_code", "refresh_token"],
                    code_challenge_methods_supported: ["S256"],
                    token_endpoint_auth_methods_supported: ["none"],
                    authorization_response_iss_parameter_supported: true,
                },
            };
        }

        if (method === "POST" && path === "/oauth/register")
        {
            const request: unknown = await body().then((text) => JSON.parse(text || "{}") as unknown, () => null).catch(() => null);
            const record = typeof request === "object" && request !== null ? request as Record<string, unknown> : {};
            const redirectUris = list(record.redirect_uris);
            if (redirectUris.length === 0 || (record.token_endpoint_auth_method ?? "none") !== "none")
            {
                return { status: 400, body: { error: "invalid_client_metadata", error_description: "redirect_uris 를 적고 공개 클라이언트(none)로 등록해 주세요" } };
            }
            const clientId = secret("client");
            const name = typeof record.client_name === "string" ? record.client_name : "에이전트 플랫폼";
            clients.set(clientId, { name, redirectUris });
            return {
                status: 201,
                body: { client_id: clientId, client_name: name, redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] },
            };
        }

        if (method === "GET" && path === "/oauth/authorize")
        {
            const client = clientFor(url.searchParams);
            return client === undefined
                ? { status: 400, body: { error: "invalid_request", error_description: "등록한 클라이언트와 콜백, PKCE(S256)를 갖춰 주세요" } }
                : { status: 200, html: loginPage(client, url.searchParams) };
        }

        if (method === "POST" && path === "/oauth/authorize")
        {
            const form = new URLSearchParams(await body());
            const client = clientFor(form);
            if (client === undefined)
            {
                return { status: 400, body: { error: "invalid_request", error_description: "등록한 클라이언트와 콜백, PKCE(S256)를 갖춰 주세요" } };
            }
            const target = new URL(form.get("redirect_uri") ?? "");
            target.searchParams.set("state", form.get("state") ?? "");
            target.searchParams.set("iss", origin);
            if (form.get("decision") !== "allow")
            {
                target.searchParams.set("error", "access_denied");
                return { status: 302, headers: { location: target.toString() } };
            }
            const account = (form.get("account") ?? "").trim().toLowerCase();
            if (!ACCOUNT.test(account))
            {
                return { status: 400, html: loginPage(client, form, "계정은 영문 소문자 · 숫자 · 점 · 밑줄 · 하이픈으로 적어 주세요.") };
            }
            const code = secret("code");
            codes.set(code, {
                clientId: form.get("client_id") ?? "",
                redirectUri: form.get("redirect_uri") ?? "",
                challenge: form.get("code_challenge") ?? "",
                subject: account,
                expiresAt: Date.now() + CODE_TTL_MS,
            });
            target.searchParams.set("code", code);
            return { status: 302, headers: { location: target.toString() } };
        }

        if (method === "POST" && path === "/oauth/token")
        {
            const form = new URLSearchParams(await body());
            if (form.get("grant_type") === "authorization_code")
            {
                const presented = form.get("code") ?? "";
                const code = codes.get(presented);
                codes.delete(presented);
                const verified = code !== undefined
                    && code.expiresAt > Date.now()
                    && code.clientId === form.get("client_id")
                    && code.redirectUri === form.get("redirect_uri")
                    && createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") === code.challenge;
                return verified ? issue(code.clientId, code.subject) : { status: 400, body: { error: "invalid_grant" } };
            }
            if (form.get("grant_type") === "refresh_token")
            {
                const presented = form.get("refresh_token") ?? "";
                const grant = refresh.get(presented);
                if (grant === undefined || grant.clientId !== form.get("client_id"))
                {
                    return { status: 400, body: { error: "invalid_grant" } };
                }
                refresh.delete(presented);
                return issue(grant.clientId, grant.subject);
            }
            return { status: 400, body: { error: "unsupported_grant_type" } };
        }

        return undefined;
    };

    return {
        guard(authorization)
        {
            const grant = grantOf(authorization);
            return grant === undefined ? { refused: challenge() } : { grant };
        },
        grantOf,
        handle,
    };
}
