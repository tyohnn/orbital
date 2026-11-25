// 승인 카드의 내용. 사람이 무엇을 승인하는지 읽는 자리다. 서버가 HTML 조각을 지어 도구 답의 `_meta` 에 싣고, 화면(`widget.html`)은 그것을 꽂기만 한다.
//
// ⚠ `_meta` 는 화면에만 가고 모델에게는 가지 않는다. 승인의 표(`approval`)를 여기에만 싣는 까닭이다.
// ⚠ 레이어와 에이전트가 지은 글(권한의 문장, 마이그레이션의 이름)은 모두 이스케이프한다. 에이전트가 마이그레이션 이름에 태그를 넣어도 카드를 바꾸지 못한다.
// ⚠ 승인 단추는 기다리는 요청이 있을 때만 선다.
import type { PendingPromotion } from "@harmony/orbital/server";

export interface Live
{
    release: string;
    url: string | null;
}

export type CardView =
    | { kind: "no-workspace" }
    | { kind: "idle"; production: Live | null }
    | { kind: "waiting"; pending: PendingPromotion; approval: string; production: Live | null }
    | { kind: "promoted"; production: Live }
    | { kind: "stale" }
    | { kind: "refused"; reason: string; details: readonly string[]; production: Live | null };

/** 화면이 카드를 찾는 `_meta` 의 이름 */
export const CARD_META = "factory-todo/card";

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
            return `<h1>운영에 올릴까요?</h1>
<p>에이전트가 고친 것을 운영에 올려 달라고 했어요. 아래를 읽고 승인해 주세요.</p>
<dl><dt>올릴 것</dt><dd><code data-release="${escape(pending.release)}" title="${escape(pending.release)}">${short(pending.release)}</code> · commit <code>${escape(pending.commit.slice(0, 12))}</code></dd></dl>
<h2>권한이 이렇게 바뀌어요</h2>${changes}
<h2>운영 DB 에 실행될 마이그레이션</h2>${migrations}
${live(view.production)}
<div class="actions"><button type="button" class="primary" data-action="approve" data-release="${escape(pending.release)}" data-approval="${escape(view.approval)}">승인하고 올리기</button>${refresh}</div>`;
        }
        case "promoted":
            return `<h1>운영에 올렸어요</h1>${live(view.production)}`;
        case "stale":
            return `<h1>카드를 연 뒤에 바뀐 것이 있어요</h1><p>승인하지 않았어요. 다시 보고 새로 올라온 것을 읽은 뒤에 승인해 주세요.</p><div class="actions">${refresh}</div>`;
        case "refused":
            return `<h1>운영에 올리지 못했어요</h1><p>${escape(view.reason)}</p>${view.details.length === 0 ? "" : items(view.details)}${live(view.production)}<div class="actions">${refresh}</div>`;
    }
}
