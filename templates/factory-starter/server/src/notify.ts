// 레이어의 이벤트마다 「여기서 고객에게 알린다」의 자리. 웹훅과 물어보는 고리가 함께 부른다(`events.ts`).
//
// ✏️ **당신의 알림을 여기에 붙인다**(메일 · 앱 안의 알림 · 슬랙). 지금은 로그에 한 줄 적기만 한다.
//   - 이벤트의 `data` 에는 이름과 숫자만 있다(값 · 행 · 로그 · 토큰은 없다). 고객에게 보일 글은 여기서 짓는다.
//   - 던지면 처리하지 않은 것이다. 웹훅이면 레이어가 다시 보내고, 물어보는 고리면 다음 차례에 다시 받는다. 같은 알림이 두 번 가지 않게
//     밖으로 보내는 일은 되풀이해도 괜찮게(같은 이벤트 id 로 한 번만) 짓는다.
//   - 모르는 종류는 건너뛴다. 레이어는 종류를 더할 수 있다.
import type { OrbitalEvent } from "@harmony/orbital/server";

import type { Accounts } from "./accounts.ts";

export function createNotifier(options: { accounts: Accounts; log: (line: string) => void }): (event: OrbitalEvent) => Promise<void>
{
    const tell = (event: OrbitalEvent, line: string): void =>
    {
        const customer = event.instance === null ? undefined : options.accounts.customerOf(event.instance);
        options.log(`[factory] 알림 #${event.id} ${event.type} → ${customer ?? "(고객 모름)"}: ${line}`);
    };

    return async (event) =>
    {
        switch (event.type)
        {
            case "promotion.requested":
                // ✏️ 고객에게: 「에이전트가 운영에 올려 달라고 했어요. 승인 카드를 확인해 주세요」
                tell(event, "승인을 기다리는 요청이 있습니다");
                return;
            case "promotion.succeeded":
                // ✏️ 고객에게: 「운영에 올렸어요」. data.release · data.migrations(수)
                tell(event, "운영에 올랐습니다");
                return;
            case "promotion.failed":
                // ✏️ 고객에게: 「운영에 올리지 못해 앞의 모습으로 돌렸어요」. data.migrated 는 마이그레이션이 돌았는지다
                tell(event, "운영에 올리지 못해 되돌렸습니다");
                return;
            case "secret.requested":
                // ✏️ 고객에게: 「앱이 비밀 data.name 을 쓰려고 해요. 입력 카드에서 넣어 주세요」
                tell(event, "비밀의 입력을 요청했습니다");
                return;
            case "rollout.halted":
                // ✏️ 팩토리의 운영자에게: 업데이트가 멈췄다. data.failed 에 실패한 인스턴스와 까닭이 있다
                tell(event, "업데이트가 멈췄습니다");
                return;
            default:
                // instance.created · instance.deleted · rollout.advanced 같은 것. 알릴 것이 없으면 건너뛴다
                return;
        }
    };
}
