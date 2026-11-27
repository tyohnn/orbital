"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { localAccountsAllowed } from "@/lib/localAccounts";
import { paths } from "@/lib/paths";
import { safeRedirect } from "@/lib/safeRedirect";
import { supabaseServer } from "@/lib/supabase/server";

/**
 * 세션을 여닫는 액션. 아무 기록도 만지지 않고 Supabase Auth 에 넘기는 것과 돌아갈 주소를 정하는 것만 한다.
 * ⚠ `redirect()` 는 예외를 던져 흐름을 끊는다. `try` 로 감싸지 않는다.
 */
const originOf = async (): Promise<string> =>
{
    const store = await headers();
    const host = store.get("x-forwarded-host") ?? store.get("host") ?? "localhost:7600";
    const protocol = store.get("x-forwarded-proto") ?? (host.startsWith("localhost") || host.startsWith("127.") ? "http" : "https");
    return `${protocol}://${host}`;
};

/** 운영의 로그인. 돌아오는 자리는 `/auth/callback` 이다. */
export async function startGoogleSignIn(formData: FormData): Promise<void>
{
    const next = safeRedirect(String(formData.get("next") ?? ""), paths.home());
    const supabase = await supabaseServer();
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: { redirectTo: `${await originOf()}/auth/callback?next=${encodeURIComponent(next)}` },
    });
    if (error !== null || data.url === null)
    {
        redirect(paths.login(next, "failed"));
    }
    redirect(data.url);
}

/** 로컬 계정으로 들어온다. 문이 닫힌 환경(운영)에서는 화면이 칸을 감추고, 여기서도 받지 않는다. */
export async function signInWithPassword(formData: FormData): Promise<void>
{
    const next = safeRedirect(String(formData.get("next") ?? ""), paths.home());
    if (!localAccountsAllowed())
    {
        redirect(paths.login(next, "failed"));
    }
    const supabase = await supabaseServer();
    const { error } = await supabase.auth.signInWithPassword({
        email: String(formData.get("email") ?? ""),
        password: String(formData.get("password") ?? ""),
    });
    if (error !== null)
    {
        redirect(paths.login(next, "credentials"));
    }
    redirect(next);
}

export async function signOut(): Promise<void>
{
    const supabase = await supabaseServer();
    await supabase.auth.signOut();
    redirect(paths.login());
}
