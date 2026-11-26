import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";

import { isPublic, paths } from "@/lib/paths";

/**
 * 세션 쿠키를 갱신하고 로그인하지 않은 사람을 로그인 화면으로 보낸다.
 * ⚠ 문 앞의 안내이지 자물쇠가 아니다. 실제 판정은 서버 액션과 화면이 매 요청 `currentAccount()` 로 다시 한다.
 * ⚠ 응답 객체를 새로 만들지 않는다. 갱신한 쿠키가 아래의 `response` 에 적힌다.
 */
export async function proxy(request: NextRequest)
{
    const response = NextResponse.next({ request });
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";
    const supabase = createServerClient(url, anonKey, {
        cookies: {
            getAll: () => request.cookies.getAll(),
            setAll: (items) =>
            {
                for (const item of items)
                {
                    request.cookies.set(item.name, item.value);
                    response.cookies.set(item.name, item.value, item.options);
                }
            },
        },
    });
    const { data } = await supabase.auth.getUser();
    if (data.user === null && !isPublic(request.nextUrl.pathname))
    {
        return NextResponse.redirect(new URL(paths.login(request.nextUrl.pathname + request.nextUrl.search), request.url));
    }
    return response;
}

export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
