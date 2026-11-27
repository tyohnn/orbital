import { NextResponse, type NextRequest } from "next/server";

import { paths } from "@/lib/paths";
import { safeRedirect } from "@/lib/safeRedirect";
import { supabaseServer } from "@/lib/supabase/server";

/** Google 이 돌아오는 자리. 받은 코드를 세션으로 바꿔 쿠키에 적는다. 실패하면 화면의 어휘로만 알린다. */
export async function GET(request: NextRequest)
{
    const { searchParams, origin } = request.nextUrl;
    const code = searchParams.get("code");
    const next = safeRedirect(searchParams.get("next"), paths.home());
    if (code === null)
    {
        return NextResponse.redirect(new URL(paths.login(next, "failed"), origin));
    }
    const supabase = await supabaseServer();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error !== null)
    {
        return NextResponse.redirect(new URL(paths.login(next, "failed"), origin));
    }
    return NextResponse.redirect(new URL(next, origin));
}
