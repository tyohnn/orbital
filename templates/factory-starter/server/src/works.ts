// 에이전트의 작업과 그 git 의 자격. 팩토리의 서버 프로세스의 메모리에만 둔다.
//
// 작업 하나 = 레이어의 작업(SDK 의 `Work`, 작업의 토큰은 그 안에만 있다) + 팩토리가 지은 식별자 + 팩토리가 낸 git 의 자격.
// 에이전트는 팩토리의 주소(`<팩토리>/git/<작업>`)와 그 자격만 받는다. 레이어의 주소와 토큰은 이 프로세스 밖으로 나가지 않는다.
//
// ⚠ git 의 자격은 그 작업 하나(그 고객의 그 인스턴스 하나)에서만, 레이어의 작업이 만료될 때까지(두 시간)만, git 의 길에서만 통한다.
//   MCP 의 토큰과 섞이지 않게 앞머리를 따로 둔다(`fgit_`). 자격은 sha256 으로만 견주고, 견줄 때 걸리는 시간이 글자에 따라 달라지지 않게 한다.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { Capability, Orbital, Work } from "@harmony/orbital/server";

/** 작업에 싣는 능력. 운영을 바꾸는 능력은 SDK 의 타입에도 없다 */
export const AGENT_CAN: readonly Capability[] = ["source", "preview", "rehearse", "secrets_request"];
export const AGENT_TTL_SECONDS = 7200;

export interface Opened
{
    /** 팩토리가 지은 작업의 식별자. git 원격의 주소에 든다 */
    id: string;
    customer: string;
    instance: string;
    work: Work;
    /** 만료되는 때(Unix 초) */
    expiresAt: number;
}

export interface Works
{
    /** 고객의 인스턴스에 작업을 새로 연다. 그 고객의 앞 작업은 닫는다(레이어에서 거두고 git 의 자격도 끊는다). 작업과 그 git 의 자격(한 번만 돌려준다)을 돌려준다 */
    open(customer: string, instance: string): Promise<{ opened: Opened; credential: string }>;
    /** 고객의 살아 있는 가장 새 작업. 없으면 `undefined` 다 */
    current(customer: string): Opened | undefined;
    /** git 의 길에서: 그 작업의 자격이 맞고 만료되지 않았을 때만 작업을 돌려준다 */
    forGit(id: string, credential: string): Opened | undefined;
}

const digest = (text: string): Buffer => createHash("sha256").update(text).digest();

export function createWorks(orbital: Orbital, now: () => number = () => Math.floor(Date.now() / 1000)): Works
{
    const works = new Map<string, Opened & { credential: Buffer }>();

    const sweep = (): void =>
    {
        for (const [id, entry] of works)
        {
            if (entry.expiresAt <= now())
            {
                works.delete(id);
            }
        }
    };

    return {
        async open(customer, instance)
        {
            sweep();
            // 앞 작업을 닫는다. 그 토큰과 git 의 자격은 다음 요청부터 통하지 않는다
            for (const [id, entry] of works)
            {
                if (entry.customer === customer)
                {
                    works.delete(id);
                    // 레이어가 닫지 못해도(잠깐 닿지 않아도) 이 프로세스의 자격은 이미 끊었다. 레이어의 토큰은 길어야 두 시간 뒤 만료된다
                    await entry.work.close().catch(() => undefined);
                }
            }
            const work = await orbital.works.open({ instance, can: AGENT_CAN, ttlSeconds: AGENT_TTL_SECONDS });
            const id = randomBytes(12).toString("hex");
            const credential = `fgit_${randomBytes(24).toString("base64url")}`;
            const opened: Opened = { id, customer, instance, work, expiresAt: work.expiresAt };
            works.set(id, { ...opened, credential: digest(credential) });
            return { opened, credential };
        },
        current(customer)
        {
            let newest: Opened | undefined;
            for (const entry of works.values())
            {
                if (entry.customer === customer && entry.expiresAt > now() && (newest === undefined || entry.expiresAt >= newest.expiresAt))
                {
                    newest = entry;
                }
            }
            return newest;
        },
        forGit(id, credential)
        {
            const entry = works.get(id);
            if (entry === undefined || !credential.startsWith("fgit_") || entry.expiresAt <= now())
            {
                return undefined;
            }
            if (!timingSafeEqual(entry.credential, digest(credential)))
            {
                return undefined;
            }
            const { credential: _, ...opened } = entry;
            return opened;
        },
    };
}
