"use server";

import { redirect } from "next/navigation";

import type { Role } from "@/domain/team";
import { ROLES } from "@/domain/team";
import { paths } from "@/lib/paths";
import type { Refusal } from "@/server/dashboard";
import { currentAccount, dashboard } from "@/server/runtime";
import type { Account } from "@/server/store";

/**
 * 화면이 부르는 액션. 모두 로그인한 계정을 매번 다시 확인한 뒤 `server/dashboard.ts` 를 부른다.
 * 거절은 화면의 어휘(`Refusal`)로만 돌려준다. 비밀은 첫 키와 새 키의 `secret` 하나씩만 화면에 한 번 간다.
 */
const account = async (): Promise<Account> =>
{
    const found = await currentAccount();
    if (found === null)
    {
        redirect(paths.login());
    }
    return found;
};

export type Outcome<T> = { ok: true; value: T } | { ok: false; reason: Refusal };

const field = (form: FormData, name: string): string => String(form.get(name) ?? "").trim();

const roleOf = (text: string): Role => ROLES.find((role) => role === text) ?? "member";

export async function createFactory(_: unknown, form: FormData): Promise<Outcome<{ factoryId: string; secret: string }>>
{
    const result = await dashboard().createFactory(await account(), { name: field(form, "name"), label: field(form, "label") });
    return result.ok ? { ok: true, value: { factoryId: result.value.factoryId, secret: result.value.firstKey.secret } } : result;
}

export async function createKey(factoryId: string, _: unknown, form: FormData): Promise<Outcome<{ label: string; secret: string }>>
{
    const result = await dashboard().createKey(await account(), factoryId, { label: field(form, "label") });
    return result.ok ? { ok: true, value: { label: result.value.label, secret: result.value.secret } } : result;
}

export async function revokeKey(factoryId: string, keyId: string): Promise<Outcome<null>>
{
    const result = await dashboard().revokeKey(await account(), factoryId, keyId);
    return result.ok ? { ok: true, value: null } : result;
}

export async function invite(factoryId: string, _: unknown, form: FormData): Promise<Outcome<null>>
{
    return dashboard().invite(await account(), factoryId, { email: field(form, "email"), role: roleOf(field(form, "role")) });
}

export async function setRole(factoryId: string, accountId: string, form: FormData): Promise<Outcome<null>>
{
    return dashboard().setRole(await account(), factoryId, accountId, roleOf(field(form, "role")));
}

export async function removeMember(factoryId: string, accountId: string): Promise<Outcome<null>>
{
    return dashboard().removeMember(await account(), factoryId, accountId);
}
