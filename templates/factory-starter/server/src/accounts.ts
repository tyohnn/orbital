// 고객 계정과 인스턴스를 잇는 자리. 「이 사람은 이 인스턴스」를 정한다.
//
// 고객은 플랫폼이 연결한 계정(OAuth 의 주체, `connect.ts`)이고, 고객마다 인스턴스는 하나다.
//
// ✏️ **여기에 당신의 계정과 결제를 붙인다.** 템플릿은 가입 · 로그인 · 결제를 넣지 않는다(아직 정하지 않은 것이다).
//   - 가격과 결제: `instanceFor` 가 `create` 를 부르기 전에 이 고객이 값을 치렀는지 확인한다. 치르지 않았으면 던지고, 도구는 그 글을 사람에게 보인다.
//   - 저장: 아래의 `memoryAccounts` 는 메모리에만 둔다. 팩토리가 다시 뜨면 같은 고객이 새 인스턴스를 받는다(시험용 조직은 10개까지다).
//     운영에 내기 전에 당신의 DB 에 두는 구현으로 바꾼다. 인터페이스는 그대로 둔다.
//
// ⚠ 같은 고객의 요청이 동시에 와도 인스턴스를 두 번 세우지 않는다. 세우는 일은 한 줄로 세워 앞의 일이 끝난 뒤에 본다.

export interface Accounts
{
    /** 고객의 인스턴스. 아직 없으면 `undefined` 다 */
    find(customer: string): string | undefined;
    /** 고객의 인스턴스. 없으면 `create` 로 세워 적는다. 세우는 일은 차례로 처리한다 */
    instanceFor(customer: string, create: () => Promise<string>): Promise<{ instance: string; created: boolean }>;
    /** 인스턴스의 고객. 레이어의 이벤트를 받아 누구에게 알릴지 찾는다. 모르면 `undefined` 다 */
    customerOf(instance: string): string | undefined;
}

/** 가장 단순한 구현: 프로세스의 메모리에 짝을 둔다 */
export function memoryAccounts(): Accounts
{
    const pairs = new Map<string, string>();
    let queue: Promise<unknown> = Promise.resolve();

    const find = (customer: string): string | undefined => pairs.get(customer);

    return {
        find,
        instanceFor(customer, create)
        {
            const known = find(customer);
            if (known !== undefined)
            {
                return Promise.resolve({ instance: known, created: false });
            }
            const work = queue.then(async () =>
            {
                // 줄을 서 있는 동안 앞의 일이 이 고객의 인스턴스를 세웠을 수 있다
                const meanwhile = find(customer);
                if (meanwhile !== undefined)
                {
                    return { instance: meanwhile, created: false };
                }
                const instance = await create();
                pairs.set(customer, instance);
                return { instance, created: true };
            });
            // 앞의 일이 실패해도 뒤의 일은 돈다
            queue = work.catch(() => undefined);
            return work;
        },
        customerOf(instance)
        {
            for (const [customer, own] of pairs)
            {
                if (own === instance)
                {
                    return customer;
                }
            }
            return undefined;
        },
    };
}
