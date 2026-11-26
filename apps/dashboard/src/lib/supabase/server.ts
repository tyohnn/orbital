import "server-only";

import { cookies } from "next/headers";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createServerClient } from "@supabase/ssr";

/**
 * 서버에서 쓰는 Supabase 클라이언트를 만드는 단 한 곳(scaffold 와 같은 규약).
 * ⚠ 서버에서는 `getUser()` 를 쓴다. `getSession()` 은 쿠키를 그대로 믿는다.
 */
export const supabaseConfig = (): { url: string; anonKey: string } =>
{
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    if (url === undefined || url === "" || anonKey === undefined || anonKey === "")
    {
        throw new Error("NEXT_PUBLIC_SUPABASE_URL 과 NEXT_PUBLIC_SUPABASE_ANON_KEY 를 적어 주세요(apps/dashboard/.env.example)");
    }
    return { url, anonKey };
};

export const supabaseServer = async (): Promise<SupabaseClient> =>
{
    const { url, anonKey } = supabaseConfig();
    const store = await cookies();
    return createServerClient(url, anonKey, {
        cookies: {
            getAll: () => store.getAll(),
            setAll: (items) =>
            {
                try
                {
                    for (const item of items)
                    {
                        store.set(item.name, item.value, item.options);
                    }
                }
                catch
                {
                    // 서버 컴포넌트는 쿠키를 쓰지 못한다. 갱신은 proxy 의 몫이다
                }
            },
        },
    });
};
