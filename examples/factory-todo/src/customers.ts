// 고객과 인스턴스의 짝. 팩토리가 제 파일에 둔다. 고객은 앱에 연결한 계정이고, 고객마다 인스턴스는 하나다.
//
// ⚠ 같은 고객의 요청이 동시에 와도 인스턴스를 두 번 세우지 않는다. 세우는 일은 한 줄로 세워 앞의 일이 끝난 뒤에 본다.
//   고객마다 줄을 따로 두면 서로 다른 고객이 파일을 동시에 고쳐 한쪽의 짝을 잃는다.
// ⚠ 파일은 임시 파일에 쓰고 이름을 바꿔 놓는다. 쓰다 끊겨도 반쪽짜리 파일이 남지 않는다.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface Customers
{
    /** 고객의 인스턴스. 아직 없으면 `undefined` 다 */
    find(customer: string): string | undefined;
    /** 고객의 인스턴스. 없으면 `create` 로 세워 적는다. 세우는 일은 차례로 처리한다 */
    ensure(customer: string, create: () => Promise<string>): Promise<{ instance: string; created: boolean }>;
}

export function openCustomers(home: string): Customers
{
    mkdirSync(home, { recursive: true });
    const file = join(home, "customers.json");
    let queue: Promise<unknown> = Promise.resolve();

    const read = (): Record<string, string> =>
    {
        try
        {
            const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
            if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
            {
                return {};
            }
            return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
        }
        catch
        {
            return {};
        }
    };

    const write = (pairs: Record<string, string>): void =>
    {
        const temporary = `${file}.${process.pid}.tmp`;
        writeFileSync(temporary, `${JSON.stringify(pairs, null, 4)}\n`);
        renameSync(temporary, file);
    };

    const find = (customer: string): string | undefined => read()[customer];

    return {
        find,
        ensure(customer, create)
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
                write({ ...read(), [customer]: instance });
                return { instance, created: true };
            });
            // 앞의 일이 실패해도 뒤의 일은 돈다
            queue = work.catch(() => undefined);
            return work;
        },
    };
}
