// 레이어의 이벤트를 받는 곳. 웹훅(`POST /webhooks/orbital`)과 물어보는 고리(`events.list`)가 같은 처리기(`notify.ts`)를 부른다.
//
// | 어디서 | 언제 |
// |---|---|
// | 웹훅 | `ORBITAL_WEBHOOK_SECRET` 이 있을 때. 레이어가 팩토리의 바깥 주소(`https://…/webhooks/orbital`)로 서명해 보낸다 |
// | 물어보는 고리 | 비밀이 없을 때(로컬처럼 레이어가 팩토리에 닿지 못하는 곳). 몇 초마다 `events.list` 로 이어 받는다 |
//
// ⚠ **서명은 받은 날것의 본문으로 확인한다.** JSON 으로 읽었다가 다시 쓴 본문은 서명이 맞지 않는다.
// ⚠ **겹침은 id 로 거른다.** 웹훅은 적어도 한 번 가므로 같은 이벤트가 다시 온다. 한 조직의 이벤트는 id 의 차례로 오고, 레이어는 앞의 것이 끝나기 전에
//   뒤의 것을 보내지 않는다. 그래서 「처리한 마지막 id」 하나(`Inbox`)로 거른다. 처리는 한 줄로 세워 같은 id 가 겹쳐 와도 한 번만 돈다.
// ⚠ **웹훅을 받으면 그 앞에 받지 못한 것부터 목록에서 이어 받는다.** 웹훅을 걸기 전에 생긴 이벤트와 레이어가 하루 동안 보내다 그만둔 이벤트는
//   웹훅으로 오지 않는다. 받은 것만 처리하면 그것들을 영영 건너뛴다.
// ⚠ **처리기가 실패하면 처리한 것으로 적지 않는다.** 웹훅은 500 으로 답해 레이어가 다시 보내고, 물어보는 고리는 다음 차례에 그 자리부터 다시 받는다.
// ⚠ 웹훅의 비밀은 확인 함수에만 건넨다. 답 · 로그 · 오류에 싣지 않는다.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { OrbitalWebhookError, verifyWebhook } from "@harmony/orbital/server";
import type { EventPage, OrbitalEvent } from "@harmony/orbital/server";

/** 처리한 자리. 다시 떠도 처리한 이벤트를 다시 알리지 않게 팩토리의 폴더에 둔다 */
export interface Inbox
{
    /** 처리한 마지막 id. 처음이면 0 이다 */
    through(): number;
    record(id: number): void;
}

export function fileInbox(home: string): Inbox
{
    mkdirSync(home, { recursive: true });
    const file = join(home, "inbox.json");
    const read = (): number =>
    {
        try
        {
            const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
            const through = typeof parsed === "object" && parsed !== null && "through" in parsed ? parsed.through : 0;
            return typeof through === "number" ? through : 0;
        }
        catch
        {
            return 0;
        }
    };
    let through = read();
    return {
        through: () => through,
        record(id)
        {
            through = Math.max(through, id);
            // 임시 파일에 쓰고 이름을 바꾼다. 쓰다 끊겨도 반쪽짜리 파일이 남지 않는다
            const temporary = `${file}.${process.pid}.tmp`;
            writeFileSync(temporary, `${JSON.stringify({ through }, null, 4)}\n`);
            renameSync(temporary, file);
        },
    };
}

export interface WebhookAnswer
{
    status: number;
    body: Record<string, unknown>;
}

export interface EventsOptions
{
    /** 물어보는 고리가 부른다. 보통은 SDK 의 `orbital.events.list` 다 */
    list: (input: { after: number; limit: number }) => Promise<EventPage>;
    inbox: Inbox;
    /** 이벤트 하나를 처리한다(`notify.ts`). 던지면 처리하지 않은 것이다 */
    handle: (event: OrbitalEvent) => Promise<void>;
    /** 웹훅의 서명 비밀(`whsec_…`). 없으면 웹훅을 받지 않는다 */
    secret?: string | undefined;
    log: (line: string) => void;
    /** 테스트에서 갈아 끼운다(Unix 초) */
    now?: () => number;
}

export interface Events
{
    /** 웹훅 하나를 받는다. `signature` 는 `orbital-signature` 머리말, `body` 는 받은 그대로의 바이트다 */
    receive(signature: string | undefined, body: Uint8Array): Promise<WebhookAnswer>;
    /** 물어보는 고리를 한 번 돈다. 처리한 이벤트의 수를 돌려준다 */
    pollOnce(): Promise<number>;
    /** 물어보는 고리를 `everyMs` 마다 돌린다. 멈추는 함수를 돌려준다 */
    startPolling(everyMs: number): () => void;
}

export function createEvents(options: EventsOptions): Events
{
    const { inbox, log } = options;
    let queue: Promise<unknown> = Promise.resolve();

    /** 한 줄로 세워 처리한다. 이미 처리한 id 면 처리기를 부르지 않는다 */
    const process = (event: OrbitalEvent): Promise<"handled" | "duplicate"> =>
    {
        const work = queue.then(async () =>
        {
            if (event.id <= inbox.through())
            {
                return "duplicate" as const;
            }
            await options.handle(event);
            inbox.record(event.id);
            return "handled" as const;
        });
        queue = work.catch(() => undefined);
        return work;
    };

    /** 처리한 자리 뒤의 이벤트를 목록에서 차례로 이어 받아 처리한다. `before` 가 있으면 그 id 앞의 것까지만 */
    const drain = async (before?: number): Promise<number> =>
    {
        let handled = 0;
        for (;;)
        {
            const page = await options.list({ after: inbox.through(), limit: 100 });
            for (const event of page.events)
            {
                if (before !== undefined && event.id >= before)
                {
                    return handled;
                }
                if (await process(event) === "handled")
                {
                    handled += 1;
                }
            }
            if (!page.hasMore || page.events.length === 0)
            {
                return handled;
            }
        }
    };
    const pollOnce = (): Promise<number> => drain();

    return {
        async receive(signature, body)
        {
            if (options.secret === undefined || options.secret === "")
            {
                return { status: 404, body: { error: "not_configured", error_description: "이 팩토리는 웹훅을 받지 않습니다. ORBITAL_WEBHOOK_SECRET 을 넣고 다시 띄워 주세요" } };
            }
            let event: OrbitalEvent;
            try
            {
                event = verifyWebhook({ secret: options.secret, signature, body, ...(options.now === undefined ? {} : { now: options.now() }) });
            }
            catch (error)
            {
                const code = error instanceof OrbitalWebhookError ? error.code : "malformed";
                log(`[factory] 웹훅을 받지 않았습니다(${code})`);
                return { status: code === "malformed" ? 400 : 401, body: { error: code } };
            }
            // 웹훅은 「새 것이 있다」는 신호이기도 하다. 받은 것 앞에 받지 못한 이벤트(웹훅을 걸기 전에 생긴 것, 레이어가 하루 동안
            // 보내다 그만둔 것)가 있으면 목록에서 차례로 이어 받아 먼저 처리한다. 이어 받지 못하면 받은 것도 처리하지 않는다.
            // 받은 것만 처리하면 처리한 자리가 그 뒤로 넘어가 앞의 것을 영영 건너뛴다. 레이어가 다시 보내면 그때 이어 받는다
            if (event.id > inbox.through())
            {
                try
                {
                    await drain(event.id);
                }
                catch
                {
                    log(`[factory] 이벤트 #${event.id} 앞의 것을 이어 받지 못했습니다. 레이어가 다시 보냅니다`);
                    return { status: 500, body: { error: "catch_up_failed" } };
                }
            }
            try
            {
                const outcome = await process(event);
                if (outcome === "duplicate")
                {
                    log(`[factory] 이벤트 #${event.id} 는 이미 처리했습니다`);
                }
                return { status: 200, body: { received: event.id, duplicate: outcome === "duplicate" } };
            }
            catch
            {
                // 글은 싣지 않는다. 레이어는 2xx 가 아니면 30초 뒤에 다시 보낸다
                log(`[factory] 이벤트 #${event.id} ${event.type} 를 처리하지 못했습니다. 레이어가 다시 보냅니다`);
                return { status: 500, body: { error: "handler_failed" } };
            }
        },
        pollOnce,
        startPolling(everyMs)
        {
            let stopped = false;
            let timer: NodeJS.Timeout | undefined;
            const tick = (): void =>
            {
                pollOnce()
                    .catch(() => log("[factory] 이벤트를 물어보지 못했습니다. 다음 차례에 이어 받습니다"))
                    .finally(() =>
                    {
                        if (!stopped)
                        {
                            timer = setTimeout(tick, everyMs);
                        }
                    });
            };
            tick();
            return () =>
            {
                stopped = true;
                clearTimeout(timer);
            };
        },
    };
}
