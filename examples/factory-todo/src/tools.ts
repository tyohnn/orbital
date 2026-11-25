// 팩토리의 도구. 누가 부르는지(고객)는 연결이 정하고, 도구의 인자로 받지 않는다.
//
// | 도구 | 답 | 누가 |
// |---|---|---|
// | `workspace_open` | `{ remote, credential, expires_at }`: 팩토리의 git 원격과 그 원격에만 쓰는 두 시간짜리 자격. 고객의 인스턴스가 없으면 스캐폴드 v1 에서 세운다 | 모델 |
// | `preview` | 레이어의 `main` 으로 프리뷰를 세운다. 주소 · 권한 검사에서 어긋난 것 · 권한의 변화 · 적합성 테스트 · 빠진 비밀 | 모델 |
// | `preview_logs` | 떠 있는 프리뷰의 빌드와 서버의 로그 | 모델 |
// | `preview_sign_in` | 프리뷰에 씨앗 사용자로 들어갈 `Cookie` 의 값 | 모델 |
// | `rehearse` | 운영 사본에 마이그레이션을 미리 돌린 결과(숫자만) | 모델 |
// | `promotion_request` | 프리뷰로 선 release 의 승격을 요청한다. 승인은 사람이 카드에서 한다 | 모델 |
// | `promotion_show` | 승인 카드(화면). 기다리는 release, 권한이 바뀌는 문장, 실행될 마이그레이션 | 모델 · 화면 |
// | `promotion_approve` | 카드가 보인 release 를 고객의 승인으로 운영에 올린다 | 화면 전용(`ui.visibility: ["app"]`) |
// | `production_status` | 운영의 release 와 주소 | 모델 · 화면 |
// | `secret_request` | 레이어에 비밀의 입력을 요청하고 입력 카드(화면)를 보인다 | 모델 · 화면 |
// | `secret_entry_open` | 입력 카드가 값을 보낼 레이어의 입력 표(`_meta` 에만) | 화면 전용(`ui.visibility: ["app"]`) |
//
// ⚠ **에이전트는 레이어를 직접 부르지 않는다.** 레이어의 주소 · 작업의 토큰 · service key 는 어떤 답에도 싣지 않는다. 코드는 git 으로
//   팩토리의 주소(`server.ts` 의 `/git/<작업>`)에 오가고, 나머지는 이 도구들이 작업(`works.ts`)으로 레이어를 부른다.
//   답에 실리는 레이어 쪽의 주소는 프리뷰와 운영의 앱 주소뿐이다. 그것은 고객이 여는 주소다.
// ⚠ **service key 는 이 파일 밖(`main.ts` 가 만든 `Orbital`)에 있다.** 레이어의 오류는 `code` 와 `message` 만 옮기고, 운영의 빌드와 서버의
//   로그(`details`)는 옮기지 않는다. 그 로그는 고객의 앱이 낸 것이라 데이터가 섞일 수 있다. 프리뷰의 로그는 씨앗 데이터뿐이라 옮긴다.
// ⚠ **작업에는 운영을 바꾸는 능력이 없다.** 능력은 `source · preview · rehearse · secrets_request` 로 고정하고, 수명은 두 시간이다.
// ⚠ **승인은 사람이 본 release 하나에 묶인다.** 카드를 보일 때 승인의 표(`approval`)를 지어 화면에만 주고(`_meta`), 승인하기는 그 표와
//   지금 기다리는 release 가 같을 때만 올린다. 표는 한 번 쓰면 버린다.
// ⚠ 승인하기는 화면 전용이다. 하모니는 `ui.visibility` 에 `model` 이 없는 도구를 모델의 도구 목록에서 뺀다(os-playground 의
//   `packages/kernel/src/app-turn.ts`). 모델이 표를 볼 길도 없으므로 에이전트가 제 요청을 스스로 승인하지 못한다.
// ⚠ **비밀의 값은 팩토리를 지나지 않는다.** 에이전트는 이름과 까닭만 요청하고, 입력 카드가 레이어의 입력 표 주소로 값을 바로 보낸다.
//   입력 표의 주소는 화면에만 가는 `_meta` 에 싣고, 값을 받는 도구는 없다. 그래서 값이 도구 호출 기록에도 팩토리의 로그에도 남지 않는다.
import { randomBytes } from "node:crypto";

import { OrbitalError } from "@harmony/orbital/server";
import type { Orbital, Production, Work } from "@harmony/orbital/server";
import type { CallToolResult, Tool } from "@modelcontextprotocol/server";

import { CARD_META, ENTRY_META, renderCard } from "./card.ts";
import type { CardView, Live } from "./card.ts";
import type { Customers } from "./customers.ts";
import type { Works } from "./works.ts";

export const CARD_URI = "ui://factory-todo/promotion.html";

/** 승인의 표가 살아 있는 시간. 사람이 카드를 읽는 동안이다 */
const APPROVAL_TTL_MS = 30 * 60 * 1000;

export type ToolResult = CallToolResult;

const EMPTY_INPUT: Tool["inputSchema"] = { type: "object", properties: {}, additionalProperties: false };
/** 비밀의 이름. 레이어의 `SecretName` 과 같은 모양이다 */
const SECRET_NAME = { type: "string", pattern: "^[A-Z][A-Z0-9_]{0,47}$" } as const;
const RELEASE_INPUT: Tool["inputSchema"] = {
    type: "object",
    properties: { release: { type: "string", minLength: 1, maxLength: 200, description: "The release from the `preview` answer" } },
    required: ["release"],
    additionalProperties: false,
};

export const TOOLS: Tool[] = [
    {
        name: "workspace_open",
        title: "작업 열기",
        description: "Open a coding workspace on the user's own copy of the to-do app. Returns a git remote and a two-hour credential for that remote only. Clone and push with plain git, passing the credential as a header for one command (`git -c http.extraHeader=\"Authorization: Bearer <credential>\" clone <remote>`) or through a git credential helper; never put it in the remote URL. Only `main` is accepted. Call again for a fresh credential.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
        name: "preview",
        title: "프리뷰 세우기",
        description: "Build what you pushed to `main` and stand up a preview with seed data. Returns the preview address, access-check findings, how data permissions change against production, the conformance test result, blockers, and secrets that have no preview value yet. Push first.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
        name: "preview_logs",
        title: "프리뷰 로그 보기",
        description: "Read the end of the build and server logs of the running preview.",
        inputSchema: EMPTY_INPUT,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    {
        name: "preview_sign_in",
        title: "프리뷰에 씨앗 사용자로 들어가기",
        description: "Sign in to the running preview as a seed user (an id from `db/seed/users.toml`). Returns the value of a `Cookie` header to send with requests to the preview address. Works only on the preview.",
        inputSchema: {
            type: "object",
            properties: { user: { type: "string", minLength: 1, maxLength: 100 } },
            required: ["user"],
            additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    {
        name: "rehearse",
        title: "리허설 돌리기",
        description: "Run the release's new migrations on a copy of the production database. Only counts come back. Needed before promotion when there are migrations to run on production.",
        inputSchema: RELEASE_INPUT,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
        name: "promotion_request",
        title: "승격 요청",
        description: "Ask to promote a previewed release to production. Nothing changes until the user approves on the card; call `promotion_show` next to show it.",
        inputSchema: RELEASE_INPUT,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
        name: "promotion_show",
        title: "승인 카드 보이기",
        description: "Show the user an approval card for the release the agent asked to promote: the release, how data permissions change, and the migrations that will run on production. Call this after `promotion_request`. Only the user can approve, on the card.",
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
    {
        name: "secret_request",
        title: "비밀 입력 요청",
        description: "Ask the user to enter a secret (an API key the app needs) on an input card. Declare the name under `[secrets] external` in orbital.toml, push, and call `preview` first. Give the name and why the app needs it. Never ask for the value in chat and never write it in code: the app reads it from the environment variable of that name. The card sends the value straight to Orbital; you never see it.",
        inputSchema: {
            type: "object",
            properties: { name: SECRET_NAME, reason: { type: "string", minLength: 1, maxLength: 500 } },
            required: ["name", "reason"],
            additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        _meta: {
            ui: { resourceUri: CARD_URI },
            "openai/outputTemplate": CARD_URI,
            "openai/widgetAccessible": true,
            "openai/toolInvocation/invoking": "비밀 입력 카드를 여는 중",
            "openai/toolInvocation/invoked": "비밀 입력 카드를 열었어요",
        },
    },
    {
        name: "secret_entry_open",
        title: "비밀 입력 표 받기",
        description: "Get a one-time address for the input card to send a secret value to Orbital. Called by the secret input card only.",
        inputSchema: {
            type: "object",
            properties: { name: SECRET_NAME, stage: { type: "string", enum: ["preview", "production"] } },
            required: ["name", "stage"],
            additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
        // ⚠ 화면 전용. 모델의 도구 목록에 서지 않는다. 표가 든 주소는 `_meta` 에만 싣는다
        _meta: { ui: { visibility: ["app"] }, "openai/visibility": "private", "openai/widgetAccessible": true },
    },
];

export interface FactoryOptions
{
    orbital: Orbital;
    customers: Customers;
    works: Works;
    /** 플랫폼이 이 서버를 부르는 주소. git 원격이 이 아래(`/git/<작업>`)에 선다 */
    origin: string;
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
        // 레이어가 지은 까닭이다(봉인의 열쇠가 없음 같은). 값은 실리지 않는다
        case "conflict":
            return { reason: error.message, details: [] };
        case "build_failed":
        case "start_failed":
            return { reason: `${error.message}. 운영은 앞의 모습 그대로입니다. 에이전트에게 프리뷰를 다시 세워 확인해 달라고 해 주세요.`, details: [] };
        case "not_found":
            return { reason: "그 release 를 레이어에서 찾지 못했습니다. 카드를 다시 열어 주세요.", details: [] };
        default:
            return { reason: `레이어가 승격을 받지 않았습니다(${error.code}).`, details: [] };
    }
}

export function createFactory(options: FactoryOptions): Factory
{
    const { orbital, customers, works } = options;
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
        const { opened, credential } = await works.open(customer, instance);
        const remote = `${options.origin}/git/${opened.id}`;
        const until = new Date(opened.expiresAt * 1000).toISOString();
        return answer(
            [
                `작업을 열었습니다. git 원격은 ${remote} 이고, 자격은 ${until} 에 끝납니다.`,
                "자격은 원격의 주소에 넣지 말고 명령 한 번에만 머리말로 건네세요:",
                `git -c http.extraHeader="Authorization: Bearer <credential>" clone ${remote} todo`,
                "고친 뒤 `main` 에 commit 하고 같은 방법으로 `git push origin main` 한 다음 `preview` 를 부르세요.",
            ].join("\n"),
            { remote, credential, expires_at: opened.expiresAt },
        );
    };

    /** 고객의 살아 있는 작업. 없으면 고객의 인스턴스에 새로 연다(git 의 자격은 내지 않는다). 인스턴스가 없으면 `undefined` 다 */
    const workFor = async (customer: string): Promise<Work | undefined> =>
    {
        const current = works.current(customer);
        if (current !== undefined)
        {
            return current.work;
        }
        const instance = customers.find(customer);
        return instance === undefined ? undefined : (await works.open(customer, instance)).opened.work;
    };

    const NO_WORKSPACE = "아직 작업 공간이 없습니다. `workspace_open` 으로 작업을 열고 코드를 받아 고친 뒤 올려 주세요.";

    /** 프리뷰에서 난 거절. 프리뷰의 빌드와 서버의 로그는 씨앗 데이터뿐이라 에이전트에게 옮긴다 */
    const previewFailed = (tool: string, error: unknown): ToolResult =>
    {
        logFailure(tool, error);
        if (error instanceof OrbitalError)
        {
            return failed([error.message, ...error.details].join("\n"));
        }
        return failed(reasonOf(error).reason);
    };

    const preview = async (customer: string): Promise<ToolResult> =>
    {
        const work = await workFor(customer);
        if (work === undefined)
        {
            return failed(NO_WORKSPACE);
        }
        try
        {
            const report = await work.preview();
            const urls = report.services.map((service) => ({ name: service.name, url: service.url }));
            const lines = [`프리뷰가 섰습니다. release ${report.release}`];
            for (const service of urls)
            {
                lines.push(`  ${service.name} → ${service.url ?? "(정적 파일)"}`);
            }
            for (const [title, found] of [
                ["권한 검사에서 어긋난 것", report.findings],
                ["운영과 견준 권한의 변화(승인 카드에 섭니다)", report.changes],
                ["승격을 막는 것", report.blockers],
                ["알아 둘 것", report.notices],
                ["프리뷰의 값이 없는 비밀(`secret_request` 로 사람에게 요청합니다)", report.missingSecrets],
            ] as const)
            {
                if (found.length > 0)
                {
                    lines.push(`${title}:`, ...found.map((line) => `  - ${line}`));
                }
            }
            lines.push(report.blockers.length === 0
                ? "막는 것이 없습니다. `promotion_request` 로 승격을 요청할 수 있습니다."
                : "막는 것을 고쳐 다시 올린 뒤 `preview` 를 다시 부르세요.");
            return answer(lines.join("\n"), {
                release: report.release,
                commit: report.commit,
                services: urls,
                findings: report.findings,
                changes: report.changes,
                blockers: report.blockers,
                notices: report.notices,
                missing_secrets: report.missingSecrets,
                conformance: report.conformance === null
                    ? null
                    : { passed: report.conformance.passed, outcome: report.conformance.outcome, output: report.conformance.output },
            });
        }
        catch (error)
        {
            return previewFailed("preview", error);
        }
    };

    const previewLogs = async (customer: string): Promise<ToolResult> =>
    {
        const work = await workFor(customer);
        if (work === undefined)
        {
            return failed(NO_WORKSPACE);
        }
        try
        {
            const { release, logs } = await work.previewLogs();
            const text = logs.map((log) => `== ${log.name}\n${log.text}`).join("\n");
            return answer(`프리뷰 ${release} 의 로그입니다.\n${text}`, { release, logs });
        }
        catch (error)
        {
            return previewFailed("preview_logs", error);
        }
    };

    const previewSignIn = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const work = await workFor(customer);
        if (work === undefined)
        {
            return failed(NO_WORKSPACE);
        }
        const user = typeof args.user === "string" ? args.user : "";
        try
        {
            const { cookie } = await work.previewSignIn(user);
            return answer(`프리뷰에 \`${user}\` 로 들어갔습니다. 프리뷰의 주소로 보내는 요청에 \`Cookie: <cookie>\` 머리말을 붙이세요.`, { user, cookie });
        }
        catch (error)
        {
            return previewFailed("preview_sign_in", error);
        }
    };

    const rehearse = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const work = await workFor(customer);
        if (work === undefined)
        {
            return failed(NO_WORKSPACE);
        }
        const release = typeof args.release === "string" ? args.release : "";
        try
        {
            const report = await work.rehearse(release);
            const line = !report.needed
                ? "운영에 돌릴 마이그레이션이 없어 리허설이 필요 없습니다."
                : report.passed
                    ? `리허설이 통과했습니다(${report.millis} ms).`
                    : `리허설이 실패했습니다. \`${report.failedAt ?? ""}\` 에서 멈췄습니다(SQLSTATE ${report.sqlstate ?? "모름"}). 운영의 데이터에서만 나는 문제일 수 있습니다.`;
            return answer(line, {
                release: report.release,
                needed: report.needed,
                passed: report.passed,
                millis: report.millis,
                failed_at: report.failedAt,
                sqlstate: report.sqlstate,
                tables: report.tables,
            });
        }
        catch (error)
        {
            return previewFailed("rehearse", error);
        }
    };

    const promotionRequest = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const work = await workFor(customer);
        if (work === undefined)
        {
            return failed(NO_WORKSPACE);
        }
        const release = typeof args.release === "string" ? args.release : "";
        try
        {
            await work.requestPromotion(release);
            options.log("[factory-todo] 승격을 요청했습니다");
            return answer("승격을 요청했습니다. `promotion_show` 로 사람에게 승인 카드를 보여 주세요. 사람이 승인하면 운영에 오릅니다.", { release, requested: true });
        }
        catch (error)
        {
            return previewFailed("promotion_request", error);
        }
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

    const secretRequest = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const instance = customers.find(customer);
        if (instance === undefined)
        {
            return failed("아직 작업 공간이 없습니다. `workspace_open` 으로 작업을 열고 `[secrets] external` 에 이름을 적어 올린 뒤 `preview` 를 불러 주세요.");
        }
        const name = typeof args.name === "string" ? args.name : "";
        const reason = typeof args.reason === "string" ? args.reason : "";
        try
        {
            await orbital.secrets.request(instance, name, { reason });
        }
        catch (error)
        {
            logFailure("secret_request", error);
            const { reason: why, details } = reasonOf(error);
            return failed([`요청을 적지 못했습니다. ${why}`, ...details].join("\n"));
        }
        const shown = (await orbital.secrets.list(instance)).find((secret) => secret.name === name);
        const filled = { preview: shown?.preview.set === true, production: shown?.production.set === true };
        options.log(`[factory-todo] 비밀의 입력을 요청했습니다: ${instance}`);
        return answer(
            "사람에게 비밀 입력 카드를 보였습니다. 사람이 카드에서 값을 넣습니다. 값을 묻거나 대화 · 코드에 적지 마세요. 앱은 같은 이름의 환경 변수로 읽습니다.",
            { name, ...filled },
            card({ kind: "secret", name, reason, ...filled }),
        );
    };

    const secretEntryOpen = async (customer: string, args: Record<string, unknown>): Promise<ToolResult> =>
    {
        const instance = customers.find(customer);
        const name = typeof args.name === "string" ? args.name : "";
        const stage = args.stage === "preview" || args.stage === "production" ? args.stage : undefined;
        if (instance === undefined || stage === undefined)
        {
            return failed("입력 카드에서 부른 것이 아닙니다. 카드를 다시 열어 주세요.");
        }
        try
        {
            const entry = await orbital.secrets.entry(instance, name, { stage });
            // 표가 든 주소는 화면에만 간다. 모델이 읽는 글과 structuredContent 에는 싣지 않는다
            return {
                content: [text("입력 표를 열었습니다. 카드가 값을 레이어로 바로 보냅니다.")],
                structuredContent: { name, stage, expires_at: entry.expiresAt },
                _meta: { [ENTRY_META]: { url: entry.url, expires_at: entry.expiresAt } },
            };
        }
        catch (error)
        {
            logFailure("secret_entry_open", error);
            return failed(`입력 표를 받지 못했습니다. ${reasonOf(error).reason}`);
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
                    case "preview":
                        return await preview(customer);
                    case "preview_logs":
                        return await previewLogs(customer);
                    case "preview_sign_in":
                        return await previewSignIn(customer, args);
                    case "rehearse":
                        return await rehearse(customer, args);
                    case "promotion_request":
                        return await promotionRequest(customer, args);
                    case "promotion_show":
                        return await promotionShow(customer);
                    case "promotion_approve":
                        return await promotionApprove(customer, args);
                    case "production_status":
                        return await productionStatus(customer);
                    case "secret_request":
                        return await secretRequest(customer, args);
                    case "secret_entry_open":
                        return await secretEntryOpen(customer, args);
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
