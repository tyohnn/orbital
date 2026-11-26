// 대시보드의 기록을 두는 포트. 연산마다 메서드 하나이고, 계약 테스트(`store.contract.test.ts`)가 메모리 구현과 Postgres 구현을 함께 잰다.
//
// 계정 자체(이메일 · Google 의 신원 · 비밀번호)는 Supabase Auth 에 있다. 여기에는 팩토리 · 팀원 · 초대만 둔다.
// ⚠ 대시보드가 쓰는 팩토리의 키는 봉인한 글(`sealedKey`)로만 둔다. 비밀 그대로는 어디에도 적지 않는다.

import type { Member, Role } from "../domain/team.ts";
import { normalizeEmail } from "../domain/team.ts";

export interface Account
{
    /** Supabase Auth 의 사용자 id. */
    readonly id: string;
    readonly email: string;
}

export interface Factory
{
    /** 관리 서버의 조직 이름과 같다. */
    readonly id: string;
    readonly label: string;
    /** 대시보드가 쓰는 service key 의 id. 화면에서 폐기하지 못한다. */
    readonly dashboardKeyId: string;
    /** 대시보드가 쓰는 service key 를 봉인한 글. */
    readonly sealedKey: string;
}

export interface Invitation
{
    readonly email: string;
    readonly role: Role;
}

export interface Membership
{
    readonly factoryId: string;
    readonly label: string;
    readonly role: Role;
}

export interface Store
{
    /** 팩토리를 만들고 만든 사람을 주인으로 넣는다. 이미 있는 이름이면 거짓이다. */
    createFactory(factory: Factory, owner: Account): Promise<boolean>;
    factory(id: string): Promise<Factory | null>;
    members(factoryId: string): Promise<Member[]>;
    /** 이 계정이 속한 팩토리. 만든 차례다. */
    memberships(accountId: string): Promise<Membership[]>;
    /** 초대를 적는다. 같은 이메일을 다시 초대하면 역할만 바꾼다. 이미 팀원이면 아무것도 하지 않는다. */
    invite(factoryId: string, email: string, role: Role): Promise<void>;
    invitations(factoryId: string): Promise<Invitation[]>;
    /** 이 계정의 이메일로 온 초대를 모두 받아 팀원이 되고 초대를 지운다. 받은 팩토리의 수를 돌려준다. */
    acceptInvitations(account: Account): Promise<number>;
    setRole(factoryId: string, accountId: string, role: Role): Promise<void>;
    removeMember(factoryId: string, accountId: string): Promise<void>;
}

/** 메모리 구현. 테스트와 Postgres 없는 개발에서 쓴다. */
export class MemoryStore implements Store
{
    private readonly factories = new Map<string, Factory>();
    private readonly teams = new Map<string, Member[]>();
    private readonly pending = new Map<string, Map<string, Role>>();

    async createFactory(factory: Factory, owner: Account): Promise<boolean>
    {
        if (this.factories.has(factory.id))
        {
            return false;
        }
        this.factories.set(factory.id, factory);
        this.teams.set(factory.id, [{ accountId: owner.id, email: normalizeEmail(owner.email), role: "owner" }]);
        this.pending.set(factory.id, new Map());
        return true;
    }

    async factory(id: string): Promise<Factory | null>
    {
        return this.factories.get(id) ?? null;
    }

    async members(factoryId: string): Promise<Member[]>
    {
        return [...(this.teams.get(factoryId) ?? [])];
    }

    async memberships(accountId: string): Promise<Membership[]>
    {
        const found: Membership[] = [];
        for (const [factoryId, team] of this.teams)
        {
            const member = team.find((one) => one.accountId === accountId);
            const factory = this.factories.get(factoryId);
            if (member !== undefined && factory !== undefined)
            {
                found.push({ factoryId, label: factory.label, role: member.role });
            }
        }
        return found;
    }

    async invite(factoryId: string, email: string, role: Role): Promise<void>
    {
        const address = normalizeEmail(email);
        if ((this.teams.get(factoryId) ?? []).some((member) => member.email === address))
        {
            return;
        }
        this.pending.get(factoryId)?.set(address, role);
    }

    async invitations(factoryId: string): Promise<Invitation[]>
    {
        return [...(this.pending.get(factoryId) ?? new Map<string, Role>())].map(([email, role]) => ({ email, role }));
    }

    async acceptInvitations(account: Account): Promise<number>
    {
        const address = normalizeEmail(account.email);
        let accepted = 0;
        for (const [factoryId, invited] of this.pending)
        {
            const role = invited.get(address);
            if (role === undefined)
            {
                continue;
            }
            invited.delete(address);
            const team = this.teams.get(factoryId) ?? [];
            if (!team.some((member) => member.accountId === account.id))
            {
                team.push({ accountId: account.id, email: address, role });
                accepted += 1;
            }
        }
        return accepted;
    }

    async setRole(factoryId: string, accountId: string, role: Role): Promise<void>
    {
        const team = this.teams.get(factoryId) ?? [];
        this.teams.set(factoryId, team.map((member) => (member.accountId === accountId ? { ...member, role } : member)));
    }

    async removeMember(factoryId: string, accountId: string): Promise<void>
    {
        const team = this.teams.get(factoryId) ?? [];
        this.teams.set(factoryId, team.filter((member) => member.accountId !== accountId));
    }
}
