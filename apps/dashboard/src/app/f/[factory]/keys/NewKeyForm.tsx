"use client";

import { useActionState } from "react";

import { createKey } from "@/actions/factory";
import type { Outcome } from "@/actions/factory";

import { REFUSALS } from "../../../_components/refusal";
import { SecretOnce } from "../../../_components/SecretOnce";

export function NewKeyForm({ factoryId }: { factoryId: string })
{
    const [state, action, pending] = useActionState<Outcome<{ label: string; secret: string }> | null, FormData>(createKey.bind(null, factoryId), null);
    return (
        <div className="mt-6 flex flex-col gap-3">
            <form action={action} className="flex gap-2">
                <input name="label" maxLength={100} placeholder="키 이름(예: 배포 서버)" aria-label="키 이름" className="flex-1 rounded-md border border-neutral-300 bg-transparent px-3 py-2 text-sm dark:border-neutral-700" />
                <button disabled={pending} className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-white dark:text-neutral-900">새 키 만들기</button>
            </form>
            {state?.ok === true && <SecretOnce secret={state.value.secret} />}
            {state?.ok === false && <p role="alert" className="text-sm text-red-600">{REFUSALS[state.reason]}</p>}
        </div>
    );
}
