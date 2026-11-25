// 팩토리의 도구 넷. 누가 부르는지(고객)는 연결이 정하고, 도구의 인자로 받지 않는다.
//
// | 도구 | 답 | 누가 |
// |---|---|---|
// | `workspace_open` | `{ url, instance, token, expires_at }`. 고객의 인스턴스가 없으면 스캐폴드 v1 에서 세운다 | 모델 |
// | `promotion_show` | 승인 카드(화면). 기다리는 release, 권한이 바뀌는 문장, 실행될 마이그레이션 | 모델 · 화면 |
// | `promotion_approve` | 카드가 보인 release 를 고객의 승인으로 운영에 올린다 | 화면 전용(`ui.visibility: ["app"]`) |
// | `production_status` | 운영의 release 와 주소 | 모델 · 화면 |
//
// ⚠ **service key 는 이 파일 밖(`main.ts` 가 만든 `Orbital`)에 있고 어떤 답에도 싣지 않는다.** 레이어의 오류는 `code` 와 `message` 만 옮기고,
//   빌드와 서버의 로그(`details`)는 옮기지 않는다. 그 로그는 고객의 앱이 낸 것이라 데이터가 섞일 수 있다.
// ⚠ **에이전트의 토큰에는 운영을 바꾸는 능력이 없다.** 능력은 `source · preview · rehearse` 로 고정하고, 수명은 두 시간이다.
// ⚠ **승인은 사람이 본 release 하나에 묶인다.** 카드를 보일 때 승인의 표(`approval`)를 지어 화면에만 주고(`_meta`), 승인하기는 그 표와
//   지금 기다리는 release 가 같을 때만 올린다. 표는 한 번 쓰면 버린다.
// ⚠ 승인하기는 화면 전용이다. 하모니는 `ui.visibility` 에 `model` 이 없는 도구를 모델의 도구 목록에서 뺀다(os-playground 의
//   `packages/kernel/src/app-turn.ts`). 모델이 표를 볼 길도 없으므로 에이전트가 제 요청을 스스로 승인하지 못한다.
import { randomBytes } from "node:crypto";

import { OrbitalError } from "@harmony/orbital/server";
import type { Capability, Orbital, Production } from "@harmony/orbital/server";
import type { CallToolResult, Tool } from "@modelcontextprotocol/server";

import { CARD_META, renderCard } from "./card.ts";
import type { CardView, Live } from "./card.ts";
import type { Customers } from "./customers.ts";

export const CARD_URI = "ui://factory-todo/promotion.html";

/** 에이전트의 토큰에 싣는 능력. 운영을 바꾸는 능력은 SDK 의 타입에도 없다 */
export const AGENT_CAN: readonly Capability[] = ["source", "preview", "rehearse"];
export const AGENT_TTL_SECONDS = 7200;
/** 승인의 표가 살아 있는 시간. 사람이 카드를 읽는 동안이다 */
const APPROVAL_TTL_MS = 30 * 60 * 1000;

export type ToolResult = CallToolResult;

const EMPTY_INPUT: Tool["inputSchema"] = { type: "object", properties: {}, additionalProperties: false };

export const TOOLS: Tool[] = [
    {
        name: "workspace_open",
        title: "작업 열기",
        description: "Open a coding workspace on the user's own copy of the to-do app. Returns the Orbital address, instance and a two-hour token for the `orbital` CLI (set them as ORBITAL_URL, ORBITAL_INSTANCE, ORBITAL_TOKEN). Call again for a fresh token. The token cannot change production; the user approves that on a card.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
        name: "promotion_show",
        title: "승인 카드 보이기",
        description: "Show the user an approval card for the release the agent asked to promote: the release, how data permissions change, and the migrations that will run on production. Call this after `orbital request-promotion`. Only the user can approve, on the card.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        _meta: {
            ui: { resourceUri: CARD_URI },
            "openai/outputTemplate": CARD_URI,
            "openai/widgetAccessible": true,
            "openai/toolInvocation/invoking": "승인 카드를 여는 중",
            "openai/toolInvocation/invoked": "승인 카드를 열었어요",
        },
    },
    {
        name: "promotion_approve",
        title: "승인하고 올리기",
        description: "Approve the release shown on the card and promote it to production. Called by the approval card only.",
        inputSchema: {
            type: "object",
            properties: { release: { type: "string" }, approval: { type: "string" } },
            required: ["release", "approval"],
            additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
        // ⚠ 화면 전용. 모델의 도구 목록에 서지 않는다(MCP Apps 의 visibility, ChatGPT 의 옛 이름도 함께 적는다)
        _meta: { ui: { visibility: ["app"] }, "openai/visibility": "private", "openai/widgetAccessible": true },
    },
    {
        name: "production_status",
        title: "운영 보기",
        description: "Show which release of the user's app is live in production and where.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
];

export interface FactoryOptions
{
    orbital: Orbital;
    /** 에이전트가 `ORBITAL_URL` 로 쓸 레이어의 주소 */
    layerUrl: string;
    customers: Customers;
    /** 스캐폴드의 이름과 고객이 처음 받는 버전 */
    app: string;
    version: string;
    log: (line: string) => void;
}

export interface Factory
{
    call(name: string, args: Record<string, unknown>, customer: string): Promise<ToolResult>;
}

const text = (line: string): { type: "text"; text: string } => ({ type: "text", text: line });

const answer = (line: string, structured: Record<string, unknown>, meta?: Record<string, unknown>): ToolResult => ({
    // structuredContent 를 글로도 함께 싣는다(MCP 명세의 뒤 호환 권고)
    content: [text(line), text(JSON.stringify(structured))],
    structuredContent: structured,
    ...(meta === undefined ? {} : { _meta: meta }),
});

const failed = (line: string, meta?: Record<string, unknown>): ToolResult => ({
    content: [text(line)],
    isError: true,
    ...(meta === undefined ? {} : { _meta: meta }),
});

const card = (view: CardView): Record<string, unknown> => ({ [CARD_META]: renderCard(view) });

const liveOf = (production: Production | null): Live | null =>
    production === null ? null : { release: production.release, url: production.services.find((service) => service.url !== null)?.url ?? null };

/** 레이어의 거절을 사람이 읽는 문장으로. 로그는 옮기지 않는다 */
function reasonOf(error: unknown): { reason: string; details: readonly string[] }
{
    if (!(error instanceof OrbitalError))
    {
        return { reason: "레이어에 닿지 못했습니다. 잠시 뒤에 다시 해 주세요.", details: [] };
    }
    switch (error.code)
    {
        case "denied":
        case "problems":
            return { reason: error.message, details: error.details };
        case "build_failed":
        case "start_failed":
            return { reason: `${error.message}. 운영은 앞의 모습 그대로입니다. 에이전트에게 미리보기를 다시 세워 확인해 달라고 해 주세요.`, details: [] };
        case "not_found":
            return { reason: "그 release 를 레이어에서 찾지 못했습니다. 카드를 다시 열어 주세요.", details: [] };
        default:
            return { reason: `레이어가 승격을 받지 않았습니다(${error.code}).`, details: [] };
    }
}

export function createFactory(options: FactoryOptions): Factory
{
    const { orbital, customers } = options;
    const approvals = new Map<string, { customer: string; release: string; expiresAt: number }>();

    const logFailure = (tool: string, error: unknown): void =>
    {
        // 레이어의 답에서 갈래와 상태만 적는다. 글과 로그는 적지 않는다
        const what = error instanceof OrbitalError ? `${error.code} ${error.status}` : "unreachable";
        options.log(`[factory-todo] ${tool}: 레이어가 받지 않았습니다(${what})`);
    };

    const workspaceOpen = async (customer: string): Promise<ToolResult> =>
    {
        const { instance, created } = await customers.ensure(customer, async () =>
            (await orbital.instances.create({ app: options.app, from: options.version })).id);
        if (created)
        {
            options.log(`[factory-todo] 고객의 인스턴스를 세웠습니다: ${instance}`);
        }
        const session = await orbital.sessions.open({ instance, can: AGENT_CAN, ttlSeconds: AGENT_TTL_SECONDS });
        const opened = { url: options.layerUrl, instance, token: session.token, expires_at: session.expiresAt };
        return answer(
            `작업을 열었습니다. ORBITAL_URL · ORBITAL_INSTANCE · ORBITAL_TOKEN 에 넣고 \`orbital clone\` 으로 받으세요. 토큰은 ${new Date(session.expiresAt * 1000).toISOString()} 에 끝납니다.`,
            opened,
        );
    };

    const promotionShow = async (customer: string): Promise<ToolResult> =>
    {
        const instance = customers.find(customer);
        if (instance === undefined)
        {
            return answer("아직 작업 공간이 없습니다. 승인을 기다리는 것도 없습니다.", { pending: null, production: null }, card({ kind: "no-workspace" }));
        }
        const [pending, production] = await Promise.all([orbital.releases.pending(instance), orbital.production.get(instance).then(liveOf)]);
        if (pending === null)
        {
            return answer("승인을 기다리는 승격 요청이 없습니다.", { pending: null, production }, card({ kind: "idle", production }));
        }
        const approval = randomBytes(18).toString("base64url");
        approvals.set(approval, { customer, release: pending.release, expiresAt: Date.now() + APPROVAL_TTL_MS });
        return answer(
            "사람에게 승인 카드를 보였습니다. 사람이 카드에서 승인하면 운영에 오릅니다.",
            { pending, production },
            card({ kind: "waiting", pending, approval, production }),
        );
    };

    const promotionApprove = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const release = typeof args.release === "string" ? args.release : "";
        const presented = typeof args.approval === "string" ? args.approval : "";
        const ticket = approvals.get(presented);
        approvals.delete(presented);
        const instance = customers.find(customer);
        if (ticket === undefined || ticket.customer !== customer || ticket.release !== release || ticket.expiresAt <= Date.now() || instance === undefined)
        {
            return failed("승인 카드에서 승인한 것이 아닙니다. 카드를 다시 열어 사람이 승인하게 해 주세요.", card({ kind: "stale" }));
        }
        // 카드를 연 뒤에 에이전트가 다른 release 를 요청했으면 사람이 본 것과 다르다
        const pending = await orbital.releases.pending(instance);
        if (pending === null || pending.release !== release)
        {
            return failed("카드를 연 뒤에 승격 요청이 바뀌었습니다. 올리지 않았습니다. 카드를 다시 보여 주세요.", card({ kind: "stale" }));
        }
        try
        {
            const production = await orbital.releases.promote({ instance, release, change: "customer_request", approvedBy: "customer" });
            const live = liveOf(production);
            const shown = live ?? { release, url: null };
            options.log(`[factory-todo] 고객의 승인으로 운영에 올렸습니다: ${instance}`);
            return answer(`운영에 올렸습니다. ${shown.url ?? ""}`.trim(), { release: shown.release, url: shown.url }, card({ kind: "promoted", production: shown }));
        }
        catch (error)
        {
            logFailure("promotion_approve", error);
            const { reason, details } = reasonOf(error);
            const production = await orbital.production.get(instance).then(liveOf, () => null);
            return failed(`운영에 올리지 못했습니다. ${reason}`, card({ kind: "refused", reason, details, production }));
        }
    };

    const productionStatus = async (customer: string): Promise<ToolResult> =>
    {
        const instance = customers.find(customer);
        const live = instance === undefined ? null : liveOf(await orbital.production.get(instance));
        return live === null
            ? answer("아직 운영에 오른 것이 없습니다.", { release: null, url: null })
            : answer(`운영에 ${live.release} 가 올라 있습니다. ${live.url ?? ""}`.trim(), { release: live.release, url: live.url });
    };

    return {
        async call(name, args, customer)
        {
            if (customer === "")
            {
                return failed("연결한 계정이 없습니다. 앱을 다시 연결해 주세요.");
            }
            try
            {
                switch (name)
                {
                    case "workspace_open":
                        return await workspaceOpen(customer);
                    case "promotion_show":
                        return await promotionShow(customer);
                    case "promotion_approve":
                        return await promotionApprove(customer, args);
                    case "production_status":
                        return await productionStatus(customer);
                    default:
                        return failed(`모르는 도구입니다: ${name}. 도구 목록에 있는 이름으로 불러 주세요.`);
                }
            }
            catch (error)
            {
                logFailure(name, error);
                return failed(`레이어가 요청을 받지 않았습니다. ${reasonOf(error).reason}`);
            }
        },
    };
}
