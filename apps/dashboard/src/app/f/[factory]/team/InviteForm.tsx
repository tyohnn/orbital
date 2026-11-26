"use client";

import { useActionState } from "react";

import { invite } from "@/actions/factory";
import type { Outcome } from "@/actions/factory";
import { ROLES } from "@/domain/team";

import { REFUSALS } from "../../../_components/refusal";

const NAMES = { owner: "주인", admin: "관리자", member: "멤버" } as const;

export function InviteForm({ factoryId }: { factoryId: string })
{
    const [state, action, pending] = useActionState<Outcome<null> | null, FormData>(invite.bind(null, factoryId), null);
    return (
        <div className="mt-6 flex flex-col gap-2">
            <form action={action} className="flex flex-wrap gap-2">
                <input name="email" type="email" required placeholder="팀원의 이메일" aria-label="팀원의 이메일" className="flex-1 rounded-md border border-neutral-300 bg-transparent px-3 py-2 text-sm dark:border-neutral-700" />
                <select name="role" defaultValue="member" aria-label="역할" className="rounded-md border border-neutral-300 bg-transparent px-2 text-sm dark:border-neutral-700">
                    {ROLES.map((role) => <option key={role} value={role}>{NAMES[role]}</option>)}
                </select>
                <button disabled={pending} className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-white dark:text-neutral-900">초대하기</button>
            </form>
            {state?.ok === true && <p role="status" className="text-sm text-green-700">초대했어요. 그 이메일로 로그인하면 팀원이 돼요.</p>}
            {state?.ok === false && <p role="alert" className="text-sm text-red-600">{REFUSALS[state.reason]}</p>}
        </div>
    );
}
