// 승인 카드의 내용. 사람이 무엇을 승인하는지 읽는 자리다. 서버가 HTML 조각을 지어 도구 답의 `_meta` 에 싣고, 화면(`widget.html`)은 그것을 꽂기만 한다.
//
// ⚠ `_meta` 는 화면에만 가고 모델에게는 가지 않는다. 승인의 표(`approval`)를 여기에만 싣는 까닭이다.
// ⚠ 레이어와 에이전트가 지은 글(권한의 문장, 마이그레이션의 이름)은 모두 이스케이프한다. 에이전트가 마이그레이션 이름에 태그를 넣어도 카드를 바꾸지 못한다.
// ⚠ 승인 단추는 기다리는 요청이 있고, 리허설이 필요하면 통과했고, 새로 받는 비밀의 운영 값이 모두 있을 때만 선다.
//   레이어도 같은 것을 막지만, 사람이 누르고 나서 거절을 보는 것보다 누르기 전에 무엇이 남았는지 보는 편이 낫다.
// ⚠ 비밀 입력 카드의 값은 이 카드가 레이어의 입력 표 주소로 바로 보낸다. 서버가 지은 이 조각에는 값이 없고, 값은 도구의 인자로도 가지 않는다.
import type { PendingPromotion, Rehearsal } from "@harmony/orbital/server";

import { CARD_META, ENTRY_META } from "./brand.ts";

export { CARD_META, ENTRY_META };

export interface Live
{
    release: string;
    url: string | null;
}

export type CardView =
    | { kind: "no-workspace" }
    | { kind: "idle"; production: Live | null }
    | {
        kind: "waiting";
        pending: PendingPromotion;
        /** 리허설이 필요한가. 운영이 있고 운영에 돌 마이그레이션이 있을 때다(처음 오르는 것은 운영 DB 가 없어 필요 없다) */
        rehearsalNeeded: boolean;
        /** 에이전트가 이 release 로 돌린 마지막 리허설. 돌리지 않았으면 `null` 이다 */
        rehearsal: Rehearsal | null;
        /** 이번에 새로 받는 비밀마다 운영의 값이 있는가 */
        secrets: readonly { name: string; filled: boolean }[];
        /** 승인의 표. 단추를 세우지 않을 때는 `null` 이다 */
        approval: string | null;
        production: Live | null;
    }
    | { kind: "promoted"; production: Live }
    | { kind: "stale" }
    | { kind: "refused"; reason: string; details: readonly string[]; production: Live | null }
    | { kind: "secret"; name: string; reason: string; preview: boolean; production: boolean };


const escape = (text: string): string =>
    text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const short = (release: string): string => escape(release.length > 16 ? `${release.slice(0, 16)}…` : release);

const items = (lines: readonly string[]): string => `<ul>${lines.map((line) => `<li>${escape(line)}</li>`).join("")}</ul>`;

const live = (production: Live | null): string =>
{
    if (production === null)
    {
        return `<p class="muted">아직 운영에 오른 것이 없어요.</p>`;
    }
    const where = production.url === null ? "" : ` · <a href="${escape(production.url)}" target="_blank" rel="noreferrer">${escape(production.url)}</a>`;
    return `<p class="muted">지금 운영 · <code title="${escape(production.release)}">${short(production.release)}</code>${where}</p>`;
};

const refresh = `<button type="button" data-action="refresh">다시 보기</button>`;

/** 단계 하나의 입력 칸. 값은 화면이 레이어로 바로 보낸다 */
const slot = (name: string, stage: "production" | "preview", filled: boolean): string =>
{
    const label = stage === "production" ? "운영" : "프리뷰";
    const note = stage === "production"
        ? `<p class="muted">실제로 쓸 키예요. 에이전트와 팩토리는 이 값을 보지 못해요.</p>`
        : `<p class="muted">프리뷰의 값은 에이전트가 볼 수 있으니 시험용 키를 넣으세요.</p>`;
    const state = filled ? `<span class="muted" data-filled="true">넣었어요</span>` : `<span class="muted" data-filled="false">아직 없어요</span>`;
    return `<form class="secret" data-secret="${escape(name)}" data-stage="${stage}">
<h2>${label} ${state}</h2>${note}
<div class="actions"><input type="password" name="value" autocomplete="off" spellcheck="false" aria-label="${label}의 ${escape(name)} 값" required><button type="submit" class="primary">${filled ? "바꾸기" : "넣기"}</button></div>
</form>`;
};

/** 리허설의 숫자. 행의 내용은 없고 표마다 앞 · 뒤의 행 수뿐이다 */
const rehearsed = (needed: boolean, rehearsal: Rehearsal | null): string =>
{
    if (!needed)
    {
        return `<p class="muted">지금의 운영 DB 에 돌릴 마이그레이션이 없어 리허설이 필요 없어요.</p>`;
    }
    if (rehearsal === null)
    {
        return `<p role="alert" data-rehearsal="not_run">리허설을 아직 돌리지 않았어요. 에이전트에게 리허설을 돌려 달라고 해 주세요.</p>`;
    }
    if (!rehearsal.passed)
    {
        return `<p role="alert" data-rehearsal="failed">리허설이 <code>${escape(rehearsal.failedAt ?? "")}</code> 에서 실패했어요(SQLSTATE ${escape(rehearsal.sqlstate ?? "모름")}).</p>`;
    }
    const rows = rehearsal.tables.map((table) => `<li><code>${escape(table.table)}</code> ${table.before ?? "-"}행 → ${table.after ?? "-"}행</li>`).join("");
    return `<p data-rehearsal="passed">운영 DB 의 사본에서 통과했어요(${rehearsal.millis} ms).</p>${rows === "" ? "" : `<ul>${rows}</ul>`}`;
};

const secretsOf = (secrets: readonly { name: string; filled: boolean }[]): string =>
{
    if (secrets.length === 0)
    {
        return `<p class="muted">새로 쓰는 비밀이 없어요.</p>`;
    }
    const lines = secrets.map((secret) => `<li><code>${escape(secret.name)}</code> · ${secret.filled ? "운영의 값을 넣었어요" : "운영의 값이 없어요"}</li>`).join("");
    return `<ul data-secrets>${lines}</ul>`;
};

export function renderCard(view: CardView): string
{
    switch (view.kind)
    {
        case "no-workspace":
            return `<h1>승인 기다리는 것 없음</h1><p>아직 작업 공간이 없어요. 에이전트에게 앱을 고쳐 달라고 하면 만들어져요.</p>`;
        case "idle":
            return `<h1>승인 기다리는 것 없음</h1><p>에이전트가 올려 달라고 한 것이 없어요.</p>${live(view.production)}<div class="actions">${refresh}</div>`;
        case "waiting":
        {
            const { pending } = view;
            const changes = pending.changes.length === 0 ? `<p class="muted">권한은 그대로예요.</p>` : items(pending.changes);
            const migrations = pending.migrations.length === 0 ? `<p class="muted">실행될 마이그레이션이 없어요.</p>` : items(pending.migrations);
            const missing = view.secrets.filter((secret) => !secret.filled).map((secret) => secret.name);
            const approve = view.approval === null
                ? ""
                : `<button type="button" class="primary" data-action="approve" data-release="${escape(pending.release)}" data-approval="${escape(view.approval)}">승인하고 올리기</button>`;
            return `<h1>운영에 올릴까요?</h1>
<p>에이전트가 고친 것을 운영에 올려 달라고 했어요. 아래를 읽고 승인해 주세요.</p>
<dl><dt>올릴 것</dt><dd><code data-release="${escape(pending.release)}" title="${escape(pending.release)}">${short(pending.release)}</code> · commit <code>${escape(pending.commit.slice(0, 12))}</code></dd></dl>
<h2>권한이 이렇게 바뀌어요</h2>${changes}
<h2>운영 DB 에 실행될 마이그레이션</h2>${migrations}
<h2>리허설</h2>${rehearsed(view.rehearsalNeeded, view.rehearsal)}
<h2>새로 쓰는 비밀</h2>${secretsOf(view.secrets)}
${missing.length === 0 ? "" : `<p role="alert">운영의 값이 없는 비밀이 있어 아직 올릴 수 없어요: ${missing.map((name) => `<code>${escape(name)}</code>`).join(", ")}</p>`}
${live(view.production)}
<div class="actions">${approve}${refresh}</div>`;
        }
        case "promoted":
            return `<h1>운영에 올렸어요</h1>${live(view.production)}`;
        case "stale":
            return `<h1>카드를 연 뒤에 바뀐 것이 있어요</h1><p>승인하지 않았어요. 다시 보고 새로 올라온 것을 읽은 뒤에 승인해 주세요.</p><div class="actions">${refresh}</div>`;
        case "secret":
            return `<h1><code>${escape(view.name)}</code> 값을 넣어 주세요</h1>
<p>에이전트가 요청했어요: ${escape(view.reason)}</p>
<p class="muted">값은 이 카드에서 레이어로 바로 가요. 대화나 코드에 붙여 넣지 마세요.</p>
${slot(view.name, "production", view.production)}
${slot(view.name, "preview", view.preview)}`;
        case "refused":
            return `<h1>운영에 올리지 못했어요</h1><p>${escape(view.reason)}</p>${view.details.length === 0 ? "" : items(view.details)}${live(view.production)}<div class="actions">${refresh}</div>`;
    }
}
