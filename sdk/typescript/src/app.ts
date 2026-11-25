// `@harmony/orbital/app`: 팩토리의 앱이 Orbital Auth 를 쓰는 길.
//
// 브라우저 쪽 함수는 같은 주소의 `/_orbital/…` 만 부른다. 열쇠도 토큰도 받지 않는다. 사람은 레이어의 쿠키(`__Host-orbital-*`)로
// 알아보고, 그 쿠키는 브라우저가 싣는다. 서버 쪽 함수는 router 가 실어 준 서명된 신원 머리말을 글자 그대로 꺼낼 뿐이고,
// 그 값은 DB 에 넘겨 행 단위 규칙이 읽는다(`set_config('orbital.identity', 값, true)`).

/** 로그인한 사람. */
export interface Me
{
    id: string;
    email: string;
    name: string | null;
    roles: string[];
}

/** 동의 화면이 보일 것. 레이어가 말한 것만 보입니다. */
export interface ConsentRequest
{
    client: { id: string; name: string; redirectHost: string };
    scopes: string[];
    resource: string;
}

/** 사용자가 클라이언트 하나에 준 승인. */
export interface Grant
{
    id: string;
    client: { id: string; name: string };
    createdAt: number;
}

/** 레이어가 요청을 거절했다. `code` 는 레이어의 오류 이름(`unauthorized` · `not_found` …)이다. */
export class OrbitalAppError extends Error
{
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string)
    {
        super(`레이어가 요청을 거절했습니다(${status} ${code})`);
        this.name = "OrbitalAppError";
        this.status = status;
        this.code = code;
    }
}

export interface OrbitalAppOptions
{
    /** 앱의 주소. 브라우저에서는 비워 두어 같은 주소를 부릅니다. 테스트가 router 의 주소를 넣습니다. */
    origin?: string;
    /** 바꿔 끼울 `fetch`. 테스트가 쿠키를 싣는 데 씁니다. */
    fetch?: typeof fetch;
}

export interface OrbitalApp
{
    /** 로그인 링크를 메일로 보냅니다. 초대받지 않은 주소여도 같은 답이 옵니다. */
    sendLoginLink(input: { email: string; next?: string }): Promise<void>;
    /** 로그인한 사람. 로그인하지 않았으면 `null`. */
    me(): Promise<Me | null>;
    logout(): Promise<void>;
    consentRequest(id: string): Promise<ConsentRequest>;
    /** 사람이 「허락」을 눌렀을 때만 부릅니다. 돌아온 주소로 브라우저를 보냅니다. */
    approve(id: string): Promise<{ redirect: string }>;
    deny(id: string): Promise<{ redirect: string }>;
    grants(): Promise<Grant[]>;
    revokeGrant(id: string): Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown>
{
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string
{
    return typeof value === "string" ? value : "";
}

function texts(value: unknown): string[]
{
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function orbitalApp(options: OrbitalAppOptions = {}): OrbitalApp
{
    const origin = options.origin ?? "";
    const send = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));

    async function call(method: string, path: string, body?: unknown): Promise<Response>
    {
        const headers: Record<string, string> = { accept: "application/json" };
        if (body !== undefined)
        {
            headers["content-type"] = "application/json";
        }
        const response = await send(`${origin}${path}`, {
            method,
            headers,
            body: body === undefined ? null : JSON.stringify(body),
            credentials: "same-origin",
        });
        if (!response.ok)
        {
            let code = "unknown";
            try
            {
                const answer: unknown = await response.json();
                code = isRecord(answer) ? text(answer.error) || code : code;
            }
            catch
            {
                // 몸이 JSON 이 아니면 상태만 알린다
            }
            throw new OrbitalAppError(response.status, code);
        }
        return response;
    }

    async function json(method: string, path: string, body?: unknown): Promise<Record<string, unknown>>
    {
        const answer: unknown = await (await call(method, path, body)).json();
        return isRecord(answer) ? answer : {};
    }

    const request = (id: string): string => `/_orbital/oauth/requests/${encodeURIComponent(id)}`;

    return {
        async sendLoginLink({ email, next })
        {
            await call("POST", "/_orbital/auth/email-link", { email, next: next ?? "/" });
        },
        async me()
        {
            try
            {
                const answer = await json("GET", "/_orbital/auth/me");
                return {
                    id: text(answer.id),
                    email: text(answer.email),
                    name: typeof answer.name === "string" ? answer.name : null,
                    roles: texts(answer.roles),
                };
            }
            catch (error)
            {
                if (error instanceof OrbitalAppError && error.status === 401)
                {
                    return null;
                }
                throw error;
            }
        },
        async logout()
        {
            await call("POST", "/_orbital/auth/logout");
        },
        async consentRequest(id)
        {
            const answer = await json("GET", request(id));
            const client = isRecord(answer.client) ? answer.client : {};
            return {
                client: { id: text(client.id), name: text(client.name), redirectHost: text(client.redirect_host) },
                scopes: texts(answer.scopes),
                resource: text(answer.resource),
            };
        },
        async approve(id)
        {
            return { redirect: text((await json("POST", `${request(id)}/approve`)).redirect) };
        },
        async deny(id)
        {
            return { redirect: text((await json("POST", `${request(id)}/deny`)).redirect) };
        },
        async grants()
        {
            const answer = await json("GET", "/_orbital/oauth/grants");
            const grants = Array.isArray(answer.grants) ? answer.grants.filter(isRecord) : [];
            return grants.map((grant) =>
            {
                const client = isRecord(grant.client) ? grant.client : {};
                return {
                    id: text(grant.id),
                    client: { id: text(client.id), name: text(client.name) },
                    createdAt: typeof grant.created_at === "number" ? grant.created_at : 0,
                };
            });
        },
        async revokeGrant(id)
        {
            await call("DELETE", `/_orbital/oauth/grants/${encodeURIComponent(id)}`);
        },
    };
}

const browser = orbitalApp();

export const sendLoginLink = browser.sendLoginLink;
export const me = browser.me;
export const logout = browser.logout;
export const consentRequest = browser.consentRequest;
export const approve = browser.approve;
export const deny = browser.deny;
export const grants = browser.grants;
export const revokeGrant = browser.revokeGrant;

/** router 가 실어 준 서명된 신원. 로그인하지 않은 요청이면 `null`. 값을 풀거나 믿지 말고 DB 에 그대로 넘깁니다. */
export function identityOf(request: Request | { headers: Headers | Record<string, string | string[] | undefined> }): string | null
{
    const headers = request.headers;
    if (headers instanceof Headers)
    {
        return headers.get("x-orbital-identity");
    }
    const value = headers["x-orbital-identity"];
    return typeof value === "string" ? value : null;
}
