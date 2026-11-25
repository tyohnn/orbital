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
    /** 서비스에 닿는 주소. 인스턴스의 router 의 주소 + 서비스의 `path` 다. */
    url: string | null;
}

/** 운영의 사용자 한 사람. 토큰이나 세션은 실리지 않는다. */
export interface User
{
    id: string;
    email: string;
    name: string | null;
    /** 업무 역할의 이름. 이름 순이다. */
    roles: string[];
    /** 막혔는가(뺐는가). */
    disabled: boolean;
    /** 마지막으로 들어온 때(Unix 초). 한 번도 들어오지 않았으면 `null` 이다. */
    lastSignedInAt: number | null;
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
    /** 이번 변경으로 앱이 새로 받게 되는 밖에서 넣는 비밀의 이름. 지금의 운영과 견준다. 사람이 무엇을 승인하는지 읽는다. */
    newSecrets: string[];
    /** 이 release 가 담은 업데이트의 열린 rollout. 없으면 `null` 이다. 그 rollout 의 `change` 로만 오른다. */
    rollout: string | null;
}

/** rollout 이 어디에 있는가. `halted` 는 인스턴스 하나가 실패해 멈춘 것이고 팩토리가 다시 열어야 이어진다. */
export type RolloutStatus = "running" | "halted" | "cancelled" | "done";

/**
 * 인스턴스 하나가 업데이트를 어디까지 지났는가. `applied` 는 업데이트를 조상으로 담은 commit 이 포크에 선 것이고,
 * `passed` 는 그 프리뷰가 권한 검사와 적합성 테스트를 통과한 것이다. `failed` 는 다시 열면 `waiting` 부터 다시 지난다.
 */
export type RolloutState = "waiting" | "applied" | "previewed" | "passed" | "promoted" | "failed";

/** 인스턴스가 실패한 까닭. */
export type RolloutFailure = "access_check_failed" | "conformance_failed" | "rolled_back";

export interface RolloutInstance
{
    instance: string;
    state: RolloutState;
    /** `failed` 일 때만 있다. */
    reason: RolloutFailure | null;
}

/** 앱(위쪽)의 업데이트 하나를 포크 셋에 물결로 미는(당기는) 것. */
export interface Rollout
{
    id: string;
    app: string;
    /** 업데이트 commit. release 의 commit 이 이것을 조상으로 담으면 적용된 것이다. */
    commit: string;
    /** 이 업데이트를 담은 release 를 올릴 때 쓸 change. 기능 업데이트는 고객이, 법 · 보안 · 핵심 패키지는 팩토리가 승인한다. */
    change: Change;
    /** 순서 있는 물결. 앞 물결이 모두 오른 뒤에 뒤 물결이 오른다. */
    waves: string[][];
    status: RolloutStatus;
    /** 물결의 차례대로. */
    instances: RolloutInstance[];
}

/** 레이어가 업데이트를 합쳐 본 결과. 충돌하면 포크를 건드리지 않고 충돌한 파일의 이름만 온다. 에이전트가 풀어 올린다. */
export interface RolloutApply
{
    applied: boolean;
    /** 합친 뒤(또는 이미 담고 있던) 포크의 commit. 충돌했으면 `null` 이다. */
    commit: string | null;
    conflicts: string[];
}

/**
 * 밖에서 넣는 비밀의 단계. 값은 단계마다 따로이고 서로 넘어가지 않는다.
 * 프리뷰의 앱은 에이전트가 쓴 코드이고 에이전트가 그 로그와 답을 읽으므로, 프리뷰의 값은 에이전트가 볼 수 있다고 본다.
 */
export type SecretStage = "preview" | "production";

/** 단계 하나의 칸. 값은 없고 채워졌는지와 그 때(Unix 초)만 있다. */
export interface SecretSlot
{
    set: boolean;
    setAt: number | null;
}

/** 비밀 하나의 모습. 값 · 지문 · 길이는 어떤 열쇠로도 돌아오지 않는다. */
export interface Secret
{
    name: string;
    /** 이 인스턴스의 release(프리뷰로 세운 것과 운영의 것) 가운데 `[secrets] external` 에 적은 것이 있는가. */
    declared: boolean;
    /** 에이전트의 요청. 없으면 `null` 이다. */
    requested: { reason: string; at: number } | null;
    preview: SecretSlot;
    production: SecretSlot;
}

/** 사람이 값을 넣을 입력 표. `url` 에 표가 실려 있고, 사람의 브라우저가 이 주소로 `{ value }` 를 바로 `POST` 한다. 10분 안에 한 번 쓴다. */
export interface SecretEntry
{
    url: string;
    /** 만료되는 때(Unix 초). */
    expiresAt: number;
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

/**
 * 팩토리의 로그인 설정(팩토리마다 한 벌, 그 팩토리의 모든 인스턴스의 운영이 쓴다). 비밀(`apiKey` · `clientSecret`)은 돌아오지 않는다.
 * `configured` 는 레이어가 그 키를 풀어 쓸 수 있는지다. `google.redirectUri` 는 Google 콘솔에 등록할 레이어의 콜백 주소다.
 */
export interface AuthSettings
{
    mail: { configured: boolean; provider: "resend" | null; from: string | null; fromName: string | null };
    google: { configured: boolean; clientId: string | null; redirectUri: string };
}

/** 메일 발송의 설정. 보내는 주소는 팩토리가 Resend 에서 확인한 도메인의 것이어야 한다. */
export interface MailSettings
{
    provider: "resend";
    apiKey: string;
    from: string;
    fromName?: string;
}

/** 팩토리의 Google 클라이언트(OAuth 웹 애플리케이션). redirect 로 `AuthSettings.google.redirectUri` 하나를 등록한다. */
export interface GoogleSettings
{
    clientId: string;
    clientSecret: string;
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
    rollouts: {
        /**
         * 앱의 업데이트 하나로 rollout 을 만든다. `commit` 이 없으면 앱의 `main` 의 끝이다. 한 인스턴스는 같은 앱의 열린 rollout 하나에만 든다.
         * 업데이트를 담은 release 는 위쪽이 정한 적합성 테스트를 통과해야 하고, 한 곳이 실패하면 rollout 이 멈춘다.
         */
        create(app: string, input: { commit?: string; change: Change; waves: readonly (readonly string[])[] }): Promise<Rollout>;
        get(id: string): Promise<Rollout>;
        /** 포크의 머리에 업데이트를 기계적으로 합친다(`git merge`). 에이전트를 돌리지 않는다. */
        apply(id: string, instance: string): Promise<RolloutApply>;
        /** 멈춘 rollout 을 다시 연다. 실패한 인스턴스는 고친 release 로 프리뷰부터 다시 지난다. */
        resume(id: string): Promise<Rollout>;
        /** 거둔다. 아직 오르지 않은 곳은 그대로 남고, 어떤 사건도 받지 않는다. */
        cancel(id: string): Promise<Rollout>;
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
        /** 운영의 사용자 목록. 막힌 사용자도 함께 온다. 운영이 아직 서지 않았으면 409 로 거절된다. */
        list(instance: string): Promise<User[]>;
        /** 업무 역할을 통째로 바꾼다. 다음 요청부터 신원에 실린다. 선언에 없는 역할이면 422 다. */
        setRoles(input: { instance: string; user: string; roles: readonly string[] }): Promise<void>;
        /** 사용자를 뺀다. 막고 그 사용자의 세션을 모두 거둔다. */
        remove(input: { instance: string; user: string }): Promise<void>;
    };
    settings: {
        auth: {
            /** 팩토리의 로그인 설정. 비밀은 돌아오지 않는다. */
            get(): Promise<AuthSettings>;
            /**
             * 키를 넣는다. 적지 않은 칸은 그대로 두고, `null` 이면 지운다. 레이어에 봉인의 열쇠가 없으면 409 로 거절된다.
             * 키가 없으면 그 로그인 방법(`email_link` · `google`)을 선언한 release 는 운영에 오르지 못한다. 프리뷰는 선다.
             */
            set(input: { mail?: MailSettings | null; google?: GoogleSettings | null }): Promise<AuthSettings>;
        };
    };
    secrets: {
        /** 이름마다 선언됐는지 · 요청됐는지 · 단계마다 채워졌는지. 값은 돌아오지 않는다. */
        list(instance: string): Promise<Secret[]>;
        /** 사람에게 입력을 요청한다. `orbital.toml` 의 `[secrets] external` 에 적고 프리뷰를 세운 이름만 받는다. */
        request(instance: string, name: string, input: { reason: string }): Promise<void>;
        /**
         * 값을 넣는다. 값이 팩토리의 서버를 지나는 길이라, 사람이 넣는 값은 `entry` 로 레이어에 바로 보내게 한다.
         * 운영의 값을 바꾸면 도는 서비스가 자고, 다음 요청이 새 값으로 깬다. 봉인의 열쇠가 없는 레이어에서는 409 다.
         */
        set(instance: string, name: string, input: { stage: SecretStage; value: string }): Promise<void>;
        /** 값을 지운다. 지금 운영의 release 가 쓰는 비밀의 운영 값은 409 로 거절된다. */
        remove(instance: string, name: string, input: { stage: SecretStage }): Promise<void>;
        /** 사람의 입력 표를 받는다. 인스턴스 · 이름 · 단계 하나에 묶인다. 카드가 이 주소로 값을 보낸다. */
        entry(instance: string, name: string, input: { stage: SecretStage }): Promise<SecretEntry>;
    };
    oauthClients: {
        /**
         * MCP 의 OAuth 클라이언트를 미리 등록한다(`[auth.mcp]` 를 선언한 인스턴스만). redirect 는 `https` 이거나 `localhost` 여야 한다.
         * 클라이언트는 받은 `clientId` 로 인가를 받는다. 비밀(client_secret)은 없다(공개 클라이언트).
         */
        register(input: { instance: string; name: string; redirectUris: readonly string[] }): Promise<{ clientId: string }>;
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

function toUser(value: Record<string, unknown>): User
{
    return {
        id: text(value.id),
        email: text(value.email),
        name: typeof value.name === "string" ? value.name : null,
        roles: texts(value.roles),
        disabled: value.disabled === true,
        lastSignedInAt: typeof value.last_signed_in_at === "number" ? value.last_signed_in_at : null,
    };
}

function toSlot(value: unknown): SecretSlot
{
    const record = isRecord(value) ? value : {};
    return { set: record.set === true, setAt: typeof record.set_at === "number" ? record.set_at : null };
}

function toSecret(value: Record<string, unknown>): Secret
{
    const requested = isRecord(value.requested) ? value.requested : null;
    return {
        name: text(value.name),
        declared: value.declared === true,
        requested: requested === null ? null : { reason: text(requested.reason), at: typeof requested.at === "number" ? requested.at : 0 },
        preview: toSlot(value.preview),
        production: toSlot(value.production),
    };
}

const CHANGES: readonly Change[] = ["customer_request", "feature_update", "legal_update", "security_update", "core_package"];
const ROLLOUT_STATUSES: readonly RolloutStatus[] = ["running", "halted", "cancelled", "done"];
const ROLLOUT_STATES: readonly RolloutState[] = ["waiting", "applied", "previewed", "passed", "promoted", "failed"];
const ROLLOUT_FAILURES: readonly RolloutFailure[] = ["access_check_failed", "conformance_failed", "rolled_back"];

function oneOf<T extends string>(choices: readonly T[], value: unknown, fallback: T): T
{
    return choices.find((choice) => choice === value) ?? fallback;
}

function toRollout(value: unknown): Rollout
{
    const record = isRecord(value) ? value : {};
    const waves = Array.isArray(record.waves) ? record.waves.map(texts) : [];
    const instances = Array.isArray(record.instances) ? record.instances.filter(isRecord) : [];
    return {
        id: text(record.id),
        app: text(record.app),
        commit: text(record.commit),
        change: oneOf(CHANGES, record.change, "customer_request"),
        waves,
        status: oneOf(ROLLOUT_STATUSES, record.status, "running"),
        instances: instances.map((entry) => ({
            instance: text(entry.instance),
            state: oneOf(ROLLOUT_STATES, entry.state, "waiting"),
            reason: entry.reason === undefined ? null : oneOf(ROLLOUT_FAILURES, entry.reason, "rolled_back"),
        })),
    };
}

function toAuthSettings(value: unknown): AuthSettings
{
    const record = isRecord(value) ? value : {};
    const mail = isRecord(record.mail) ? record.mail : {};
    const google = isRecord(record.google) ? record.google : {};
    return {
        mail: {
            configured: mail.configured === true,
            provider: mail.provider === "resend" ? "resend" : null,
            from: typeof mail.from === "string" ? mail.from : null,
            fromName: typeof mail.from_name === "string" ? mail.from_name : null,
        },
        google: {
            configured: google.configured === true,
            clientId: typeof google.client_id === "string" ? google.client_id : null,
            redirectUri: text(google.redirect_uri),
        },
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
                    newSecrets: texts(reply.new_secrets),
                    rollout: typeof reply.rollout === "string" ? reply.rollout : null,
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
        rollouts: {
            async create(app, { commit, change, waves })
            {
                const body: { [key: string]: Json } = { change, waves: waves.map((wave) => [...wave]) };
                if (commit !== undefined)
                {
                    body.commit = commit;
                }
                return toRollout(await call("POST", `apps/${encodeURIComponent(app)}/rollouts`, body));
            },
            async get(id)
            {
                return toRollout(await call("GET", `rollouts/${encodeURIComponent(id)}`));
            },
            async apply(id, instance)
            {
                const reply = await call("POST", `rollouts/${encodeURIComponent(id)}/instances/${encodeURIComponent(instance)}/apply`);
                const record = isRecord(reply) ? reply : {};
                return {
                    applied: record.applied === true,
                    commit: typeof record.commit === "string" ? record.commit : null,
                    conflicts: texts(record.conflicts),
                };
            },
            async resume(id)
            {
                return toRollout(await call("POST", `rollouts/${encodeURIComponent(id)}/resume`));
            },
            async cancel(id)
            {
                return toRollout(await call("POST", `rollouts/${encodeURIComponent(id)}/cancel`));
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
            async list(instance)
            {
                const reply = await call("GET", at(instance, "/users"));
                const users = isRecord(reply) && Array.isArray(reply.users) ? reply.users.filter(isRecord) : [];
                return users.map(toUser);
            },
            async setRoles({ instance, user, roles })
            {
                await call("PUT", at(instance, `/users/${encodeURIComponent(user)}/roles`), { roles: [...roles] });
            },
            async remove({ instance, user })
            {
                await call("DELETE", at(instance, `/users/${encodeURIComponent(user)}`));
            },
        },
        settings: {
            auth: {
                async get()
                {
                    return toAuthSettings(await call("GET", "settings/auth"));
                },
                async set({ mail, google })
                {
                    const body: { [key: string]: Json } = {};
                    if (mail !== undefined)
                    {
                        body.mail = mail === null
                            ? null
                            : { provider: mail.provider, api_key: mail.apiKey, from: mail.from, from_name: mail.fromName ?? null };
                    }
                    if (google !== undefined)
                    {
                        body.google = google === null ? null : { client_id: google.clientId, client_secret: google.clientSecret };
                    }
                    return toAuthSettings(await call("PUT", "settings/auth", body));
                },
            },
        },
        secrets: {
            async list(instance)
            {
                const reply = await call("GET", at(instance, "/secrets"));
                const secrets = isRecord(reply) && Array.isArray(reply.secrets) ? reply.secrets.filter(isRecord) : [];
                return secrets.map(toSecret);
            },
            async request(instance, name, { reason })
            {
                await call("POST", at(instance, `/secrets/${encodeURIComponent(name)}/request`), { reason });
            },
            async set(instance, name, { stage, value })
            {
                await call("PUT", at(instance, `/secrets/${encodeURIComponent(name)}`), { stage, value });
            },
            async remove(instance, name, { stage })
            {
                await call("DELETE", at(instance, `/secrets/${encodeURIComponent(name)}?stage=${encodeURIComponent(stage)}`));
            },
            async entry(instance, name, { stage })
            {
                const reply = await call("POST", at(instance, `/secrets/${encodeURIComponent(name)}/entries`), { stage });
                const record = isRecord(reply) ? reply : {};
                return { url: text(record.url), expiresAt: typeof record.expires_at === "number" ? record.expires_at : 0 };
            },
        },
        oauthClients: {
            async register({ instance, name, redirectUris })
            {
                const reply = await call("POST", at(instance, "/oauth-clients"), { name, redirect_uris: [...redirectUris] });
                return { clientId: text(isRecord(reply) ? reply.client_id : undefined) };
            },
        },
    };
}
