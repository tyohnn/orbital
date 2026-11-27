// 대시보드가 하는 일. 화면의 서버 액션은 로그인한 계정을 확인한 뒤 여기를 부른다.
//
// - 팩토리를 만들면 관리 서버에 운영자 키로 조직을 만들고, 첫 키는 사람에게 한 번만 보여 주며, 대시보드가 쓸 키를 하나 더 만들어 봉인해 둔다.
// - 키는 관리 서버에만 있다. 대시보드는 봉인한 제 키로 목록을 읽고 만들고 폐기할 뿐 비밀을 다시 보여 주지 않는다.
// - 누가 무엇을 해도 되는지는 `domain/team.ts` 가 정한다. 속하지 않은 팩토리는 없는 것과 같다(`not_found`).
// ⚠ 운영자 키와 팩토리의 키는 이 모듈과 그 의존(관리 서버의 SDK)에만 있다. 답에는 비밀이 실리지 않는다(첫 키와 새 키의 `secret` 하나씩만 예외).

import { OrbitalError } from "@harmony/orbital/server";
import type { IssuedKey, Orbital, OrbitalAdmin, ServiceKey } from "@harmony/orbital/server";

import type { Member, Role } from "../domain/team.ts";
import { canManageKeys, canManageTeam, isEmail, isFactoryName, judgeTeamChange } from "../domain/team.ts";
import type { Sealer } from "./seal.ts";
import type { Account, Invitation, Membership, Store } from "./store.ts";

/** 대시보드가 쓰는 키의 이름. 목록에서 이 이름으로 보인다. */
export const DASHBOARD_KEY_LABEL = "대시보드";

export type Refusal =
    | "not_found"
    | "not_allowed"
    | "invalid_name"
    | "invalid_email"
    | "invalid_label"
    | "name_taken"
    | "last_owner"
    | "last_key"
    | "dashboard_key";

export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: Refusal };

const ok = <T>(value: T): Result<T> => ({ ok: true, value });
const no = <T>(reason: Refusal): Result<T> => ({ ok: false, reason });

export interface KeyRow extends ServiceKey
{
    /** 대시보드가 쓰는 키다. 화면에서 폐기하지 못한다. */
    readonly managed: boolean;
}

export interface Team
{
    readonly members: Member[];
    readonly invitations: Invitation[];
}

export interface Deps
{
    readonly store: Store;
    readonly admin: OrbitalAdmin;
    /** 팩토리의 service key 로 관리 서버를 부르는 client 를 짓는다. */
    readonly orbital: (serviceKey: string) => Orbital;
    readonly sealer: Sealer;
}

export interface Dashboard
{
    /** 로그인할 때마다 부른다. 이 이메일로 온 초대를 받아 팀원이 되고, 속한 팩토리를 돌려준다. */
    enter(account: Account): Promise<Membership[]>;
    /** 팩토리를 만든다. 첫 키(`secret`)는 이 답에서 한 번만 보인다. */
    createFactory(account: Account, input: { name: string; label?: string }): Promise<Result<{ factoryId: string; firstKey: IssuedKey }>>;
    keys(account: Account, factoryId: string): Promise<Result<KeyRow[]>>;
    createKey(account: Account, factoryId: string, input: { label: string }): Promise<Result<IssuedKey>>;
    revokeKey(account: Account, factoryId: string, keyId: string): Promise<Result<ServiceKey>>;
    team(account: Account, factoryId: string): Promise<Result<Team>>;
    invite(account: Account, factoryId: string, input: { email: string; role: Role }): Promise<Result<null>>;
    setRole(account: Account, factoryId: string, accountId: string, role: Role): Promise<Result<null>>;
    removeMember(account: Account, factoryId: string, accountId: string): Promise<Result<null>>;
}

export const createDashboard = (deps: Deps): Dashboard =>
{
    const { store, admin, sealer } = deps;

    /** 이 계정의 역할. 속하지 않았으면 `null` 이다. */
    const roleIn = async (account: Account, factoryId: string): Promise<Role | null> =>
    {
        const members = await store.members(factoryId);
        return members.find((member) => member.accountId === account.id)?.role ?? null;
    };

    /** 대시보드의 키로 지은 client. 풀지 못하면 던진다(열쇠를 바꾼 대시보드는 사람이 고칠 일이다). */
    const client = async (factoryId: string): Promise<{ orbital: Orbital; dashboardKeyId: string }> =>
    {
        const factory = await store.factory(factoryId);
        const secret = factory === null ? null : sealer.open(factory.id, factory.sealedKey);
        if (factory === null || secret === null)
        {
            throw new Error(`팩토리 ${factoryId} 의 대시보드 키를 풀지 못했습니다. DASHBOARD_SEAL_KEY 를 확인해 주세요`);
        }
        return { orbital: deps.orbital(secret), dashboardKeyId: factory.dashboardKeyId };
    };

    return {
        async enter(account)
        {
            await store.acceptInvitations(account);
            return store.memberships(account.id);
        },

        async createFactory(account, { name, label = "" })
        {
            if (!isFactoryName(name))
            {
                return no("invalid_name");
            }
            if ([...label].length > 100)
            {
                return no("invalid_label");
            }
            let created: Awaited<ReturnType<OrbitalAdmin["organizations"]["create"]>>;
            try
            {
                created = await admin.organizations.create({ id: name, label });
            }
            catch (error)
            {
                if (error instanceof OrbitalError && error.status === 409)
                {
                    return no("name_taken");
                }
                throw error;
            }
            const dashboardKey = await deps.orbital(created.key.secret).keys.create({ label: DASHBOARD_KEY_LABEL });
            const stored = await store.createFactory(
                { id: name, label, dashboardKeyId: dashboardKey.id, sealedKey: sealer.seal(name, dashboardKey.secret) },
                account,
            );
            if (!stored)
            {
                return no("name_taken");
            }
            return ok({ factoryId: name, firstKey: created.key });
        },

        async keys(account, factoryId)
        {
            if (await roleIn(account, factoryId) === null)
            {
                return no("not_found");
            }
            const { orbital, dashboardKeyId } = await client(factoryId);
            const keys = await orbital.keys.list();
            return ok(keys.map((key) => ({ ...key, managed: key.id === dashboardKeyId })));
        },

        async createKey(account, factoryId, { label })
        {
            const role = await roleIn(account, factoryId);
            if (role === null)
            {
                return no("not_found");
            }
            if (!canManageKeys(role))
            {
                return no("not_allowed");
            }
            if ([...label].length > 100)
            {
                return no("invalid_label");
            }
            const { orbital } = await client(factoryId);
            return ok(await orbital.keys.create({ label }));
        },

        async revokeKey(account, factoryId, keyId)
        {
            const role = await roleIn(account, factoryId);
            if (role === null)
            {
                return no("not_found");
            }
            if (!canManageKeys(role))
            {
                return no("not_allowed");
            }
            const { orbital, dashboardKeyId } = await client(factoryId);
            if (keyId === dashboardKeyId)
            {
                return no("dashboard_key");
            }
            try
            {
                return ok(await orbital.keys.revoke(keyId));
            }
            catch (error)
            {
                if (error instanceof OrbitalError && error.status === 404)
                {
                    return no("not_found");
                }
                if (error instanceof OrbitalError && error.status === 409)
                {
                    return no("last_key");
                }
                throw error;
            }
        },

        async team(account, factoryId)
        {
            if (await roleIn(account, factoryId) === null)
            {
                return no("not_found");
            }
            return ok({ members: await store.members(factoryId), invitations: await store.invitations(factoryId) });
        },

        async invite(account, factoryId, { email, role })
        {
            const mine = await roleIn(account, factoryId);
            if (mine === null)
            {
                return no("not_found");
            }
            if (!canManageTeam(mine))
            {
                return no("not_allowed");
            }
            if (!isEmail(email))
            {
                return no("invalid_email");
            }
            await store.invite(factoryId, email, role);
            return ok(null);
        },

        async setRole(account, factoryId, accountId, role)
        {
            const verdict = judgeTeamChange(await store.members(factoryId), account.id, accountId, role);
            if (!verdict.ok)
            {
                return no(verdict.reason);
            }
            await store.setRole(factoryId, accountId, role);
            return ok(null);
        },

        async removeMember(account, factoryId, accountId)
        {
            const verdict = judgeTeamChange(await store.members(factoryId), account.id, accountId, null);
            if (!verdict.ok)
            {
                return no(verdict.reason);
            }
            await store.removeMember(factoryId, accountId);
            return ok(null);
        },
    };
};
