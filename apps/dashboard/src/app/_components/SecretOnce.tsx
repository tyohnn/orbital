"use client";

import { useState } from "react";

/** 막 만든 키의 비밀. 이 화면을 떠나면 다시 볼 수 없다. */
export function SecretOnce({ secret }: { secret: string })
{
    const [copied, setCopied] = useState(false);
    return (
        <div role="status" className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm dark:border-amber-700 dark:bg-amber-950">
            <p className="font-medium">이 키는 지금만 보여요. 안전한 곳에 복사해 두세요.</p>
            <div className="mt-2 flex items-center gap-2">
                <code data-testid="secret" className="min-w-0 flex-1 break-all rounded bg-white px-2 py-1 font-mono text-xs dark:bg-neutral-900">{secret}</code>
                <button
                    type="button"
                    onClick={() =>
                    {
                        void navigator.clipboard.writeText(secret).then(() => setCopied(true));
                    }}
                    className="rounded-md border border-neutral-300 px-3 py-1 dark:border-neutral-700"
                >
                    {copied ? "복사했어요" : "복사"}
                </button>
            </div>
        </div>
    );
}
