"use client";

import Link from "next/link";
import { useActionState } from "react";

import { createFactory } from "@/actions/factory";
import type { Outcome } from "@/actions/factory";
import { paths } from "@/lib/paths";

import { REFUSALS } from "../_components/refusal";
import { SecretOnce } from "../_components/SecretOnce";

export function NewFactoryForm()
{
    const [state, action, pending] = useActionState<Outcome<{ factoryId: string; secret: string }> | null, FormData>(createFactory, null);
    if (state?.ok === true)
    {
        return (
            <div className="mt-6 flex flex-col gap-4">
                <p>팩토리 <strong>{state.value.factoryId}</strong> 를 만들었어요.</p>
                <SecretOnce secret={state.value.secret} />
                <Link href={paths.keys(state.value.factoryId)} className="text-sm underline">API 키 화면으로 가기</Link>
            </div>
        );
    }
    return (
        <form action={action} className="mt-6 flex max-w-md flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm">
                팩토리 이름
                <input name="name" required pattern="[a-z0-9][a-z0-9_\-]{0,63}" placeholder="acme" className="rounded-md border border-neutral-300 bg-transparent px-3 py-2 dark:border-neutral-700" />
                <span className="text-xs text-neutral-500">영어 소문자 · 숫자 · - · _ 로 써요. 나중에 바꿀 수 없어요.</span>
            </label>
            <label className="flex flex-col gap-1 text-sm">
                보이는 이름(선택)
                <input name="label" maxLength={100} placeholder="Acme 팩토리" className="rounded-md border border-neutral-300 bg-transparent px-3 py-2 dark:border-neutral-700" />
            </label>
            {state?.ok === false && <p role="alert" className="text-sm text-red-600">{REFUSALS[state.reason]}</p>}
            <button disabled={pending} className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-white dark:text-neutral-900">
                {pending ? "만드는 중…" : "팩토리 만들기"}
            </button>
        </form>
    );
}
