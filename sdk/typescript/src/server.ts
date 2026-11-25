// 팩토리의 서버가 쓰는 client. service key 로 관리 서버의 HTTP API 를 부른다.
//
// 운영을 바꾸는 길은 여기에만 있다. 에이전트는 토큰과 `orbital` CLI 를 쓰고, 그 토큰에는 승격하는 능력이 없다.
// 타입은 관리 서버가 주고받는 JSON 의 모양을 옮긴 것이다. Rust 쪽의 serde 모양을 바꾸면 같은 PR 에서 함께 고친다.
// 누가 승인할 자격이 있는지는 팩토리가 정한다. Orbital 은 승인이 어느 쪽(고객 · 팩토리)의 것인지만 받는다.

/** 토큰에 실을 수 있는 능력. 운영을 바꾸는 능력은 없다. */
export type Capability = "source" | "preview" | "rehearse" | "secrets_request";

/** 무엇 때문에 올리는가. 누가 승인해야 하는지가 여기서 갈린다. */
export type Change =
    | "customer_request"
    | "feature_update"
    | "legal_update"
    | "security_update"
    | "core_package";

/** 승인한 쪽. 고객의 요청과 기능 업데이트는 고객이, 법 · 보안 · 핵심 패키지는 팩토리가 승인한다. */
export type Approver = "customer" | "factory";

export interface Service
{
    name: string;
    kind: "server" | "static";
    /** 서버 서비스가 요청을 받는 주소. 정적 서비스는 `null` 이다. */
    url: string | null;
}

export interface Production
{
    release: string;
    services: Service[];
    /** 이번 승격에서 돈 마이그레이션의 이름. */
    migrations: string[];
}

export interface Session
{
    /** 에이전트의 sandbox 에 `ORBITAL_TOKEN` 으로 넣는다. */
    token: string;
    /** 만료되는 때(Unix 초). */
    expiresAt: number;
}

/** 사람의 승인을 기다리는 승격 요청. 승인 화면에 세운다. */
export interface PendingPromotion
{
    release: string;
    commit: string;
    /** 지금의 운영과 견준 권한의 변화. 사람이 읽는 문장이다. */
    changes: string[];
    /** 운영에 아직 돌지 않은 마이그레이션의 이름. */
    migrations: string[];
}

/** 관리 서버가 받지 않은 요청. `code` 로 갈라 다루고 `message` 와 `details` 는 사람과 에이전트에게 보여 준다. */
export class OrbitalError extends Error
{
    readonly status: number;
    readonly code: string;
    readonly details: readonly string[];

    constructor(status: number, code: string, message: string, details: readonly string[])
    {
        super(message);
        this.name = "OrbitalError";
        this.status = status;
        this.code = code;
        this.details = details;
    }
}

export interface OrbitalOptions
{
    /** 관리 서버의 주소. */
    url: string;
    /** 팩토리의 service key. 브라우저나 에이전트의 sandbox 에 두지 않는다. */
    serviceKey: string;
    /** 테스트에서 갈아 끼운다. */
    fetch?: typeof fetch;
}

export interface Orbital
{
    apps: {
        /** 스캐폴드를 올린다. `bundle` 은 버전마다 태그를 단 저장소의 git bundle 이다. */
        put(app: string, bundle: Uint8Array): Promise<void>;
    };
    instances: {
        /** 고객이 가입할 때: 스캐폴드의 한 버전에서 인스턴스를 세운다. */
        create(input: { app: string; from: string }): Promise<{ id: string }>;
        /** 인스턴스를 걷는다. DB 와 코드 저장소가 지워지고 되돌릴 수 없다. */
        destroy(instance: string): Promise<void>;
    };
    sessions: {
        /** 에이전트의 작업을 열 때: 팩토리가 판정한 범위로 토큰을 받는다. */
        open(input: { instance: string; can: readonly Capability[]; ttlSeconds?: number }): Promise<Session>;
    };
    releases: {
        /** 에이전트가 승격을 요청해 사람의 승인을 기다리는 release. 없으면 `null` 이다. */
        pending(instance: string): Promise<PendingPromotion | null>;
        /** 사람이 승인했을 때: 그 release 를 운영에 올린다. 승인은 이 release 하나에 묶인다. */
        promote(input: { instance: string; release: string; change: Change; approvedBy: Approver }): Promise<Production>;
    };
    production: {
        /** 운영에 올라 있는 것. 아직 오른 것이 없으면 `null` 이다. */
        get(instance: string): Promise<Production | null>;
    };
    users: {
        /**
         * 운영에 사용자를 초대한다. 초대받은 사람은 앱의 로그인 화면에서 이메일 링크를 받아 들어온다.
         * `roles` 는 선언의 업무 역할이다. 신원은 router 가 로그인을 확인해 앱에 싣고, 레이어 밖으로는 내주지 않는다.
         */
        invite(input: { instance: string; email: string; roles: readonly string[] }): Promise<void>;
    };
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

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

function toProduction(value: unknown): Production
{
    const record = isRecord(value) ? value : {};
    const services = Array.isArray(record.services) ? record.services.filter(isRecord) : [];
    return {
        release: text(record.release),
        services: services.map((service) => ({
            name: text(service.name),
            kind: service.kind === "static" ? "static" : "server",
            url: typeof service.url === "string" ? service.url : null,
        })),
        migrations: texts(record.migrations),
    };
}

export function createOrbital(options: OrbitalOptions): Orbital
{
    const base = options.url.replace(/\/+$/, "");
    const send = options.fetch ?? fetch;

    async function call(method: string, path: string, body?: Json | Uint8Array): Promise<unknown>
    {
        const headers: Record<string, string> = { authorization: `Bearer ${options.serviceKey}` };
        const init: RequestInit = { method, headers };
        if (body instanceof Uint8Array)
        {
            headers["content-type"] = "application/octet-stream";
            // 공유 메모리 위의 배열은 요청의 본문이 되지 못한다. 옮겨 담아 보낸다
            init.body = new Uint8Array(body);
        }
        else if (body !== undefined)
        {
            headers["content-type"] = "application/json";
            init.body = JSON.stringify(body);
        }
        const response = await send(`${base}/v1/${path}`, init);
        const reply: unknown = await response.json().catch(() => null);
        if (response.ok)
        {
            return reply;
        }
        const problem = isRecord(reply) ? reply : {};
        throw new OrbitalError(
            response.status,
            text(problem.error) || "unknown",
            text(problem.message) || `관리 서버가 ${response.status} 로 답했습니다`,
            texts(problem.details),
        );
    }

    const at = (instance: string, tail: string): string => `instances/${encodeURIComponent(instance)}${tail}`;

    return {
        apps: {
            async put(app, bundle)
            {
                await call("PUT", `apps/${encodeURIComponent(app)}`, bundle);
            },
        },
        instances: {
            async create({ app, from })
            {
                const reply = await call("POST", "instances", { app, version: from });
                return { id: text(isRecord(reply) ? reply.instance : undefined) };
            },
            async destroy(instance)
            {
                await call("DELETE", at(instance, ""));
            },
        },
        sessions: {
            async open({ instance, can, ttlSeconds })
            {
                const body: { [key: string]: Json } = { can: [...can] };
                if (ttlSeconds !== undefined)
                {
                    body.ttl_seconds = ttlSeconds;
                }
                const reply = await call("POST", at(instance, "/sessions"), body);
                const record = isRecord(reply) ? reply : {};
                return {
                    token: text(record.token),
                    expiresAt: typeof record.expires_at === "number" ? record.expires_at : 0,
                };
            },
        },
        releases: {
            async pending(instance)
            {
                const reply = await call("GET", at(instance, "/promotion-request"));
                if (!isRecord(reply))
                {
                    return null;
                }
                return {
                    release: text(reply.release),
                    commit: text(reply.commit),
                    changes: texts(reply.changes),
                    migrations: texts(reply.migrations),
                };
            },
            async promote({ instance, release, change, approvedBy })
            {
                const reply = await call("POST", at(instance, "/promotions"), {
                    release,
                    change,
                    approved_by: approvedBy,
                });
                return toProduction(reply);
            },
        },
        production: {
            async get(instance)
            {
                const reply = await call("GET", at(instance, "/production"));
                return isRecord(reply) ? toProduction(reply) : null;
            },
        },
        users: {
            async invite({ instance, email, roles })
            {
                await call("POST", at(instance, "/users"), { email, roles: [...roles] });
            },
        },
    };
}
