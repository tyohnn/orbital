import { signInWithPassword, startGoogleSignIn } from "@/actions/session";
import { localAccountsAllowed } from "@/lib/localAccounts";
import { safeRedirect } from "@/lib/safeRedirect";

const ERRORS: Record<string, string> = {
    failed: "로그인하지 못했어요. 다시 시도해 주세요.",
    credentials: "이메일이나 비밀번호가 맞지 않아요.",
};

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ next?: string; error?: string }> })
{
    const { next, error } = await searchParams;
    const target = safeRedirect(next, "/");
    const local = localAccountsAllowed();
    return (
        <main className="mx-auto flex min-h-dvh max-w-sm flex-col justify-center gap-6 px-4">
            <div>
                <h1 className="text-2xl font-semibold">Orbital</h1>
                <p className="mt-1 text-sm text-neutral-500">팩토리를 만들고 API 키를 받아 가세요.</p>
            </div>
            {error !== undefined && ERRORS[error] !== undefined && (
                <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950 dark:text-red-300">{ERRORS[error]}</p>
            )}
            <form action={startGoogleSignIn}>
                <input type="hidden" name="next" value={target} />
                <button className="w-full rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white dark:bg-white dark:text-neutral-900">
                    Google로 계속하기
                </button>
            </form>
            {local && (
                <form action={signInWithPassword} className="flex flex-col gap-2 border-t border-neutral-200 pt-6 dark:border-neutral-800">
                    <p className="text-xs text-neutral-500">개발용 계정</p>
                    <input type="hidden" name="next" value={target} />
                    <input name="email" type="email" required placeholder="이메일" aria-label="이메일" className="rounded-md border border-neutral-300 bg-transparent px-3 py-2 text-sm dark:border-neutral-700" />
                    <input name="password" type="password" required placeholder="비밀번호" aria-label="비밀번호" className="rounded-md border border-neutral-300 bg-transparent px-3 py-2 text-sm dark:border-neutral-700" />
                    <button className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium dark:border-neutral-700">이메일로 로그인</button>
                </form>
            )}
        </main>
    );
}
