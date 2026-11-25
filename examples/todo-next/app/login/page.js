"use client";

import { useState } from "react";

import { sendLoginLink } from "../../lib/orbital-app.js";

// 로그인 화면은 이메일 주소만 다룬다. 링크를 만들고 보내고 받는 일은 레이어(/_orbital/auth/…)가 한다
export default function Login()
{
    const [state, setState] = useState("idle");

    async function submit(event)
    {
        event.preventDefault();
        const email = new FormData(event.currentTarget).get("email");
        const next = new URLSearchParams(location.search).get("next") ?? "/";
        try
        {
            await sendLoginLink({ email: String(email), next });
            setState("sent");
        }
        catch
        {
            setState("failed");
        }
    }

    if (state === "sent")
    {
        return <p>메일함을 확인해 주세요. 받은 링크를 이 브라우저에서 열면 들어와요.</p>;
    }
    return (
        <main>
            <h1>할 일에 들어가기</h1>
            <form id="login" onSubmit={submit}>
                <label htmlFor="email">이메일</label>
                <input id="email" name="email" type="email" autoComplete="email" required />
                <button type="submit">로그인 링크 받기</button>
            </form>
            {state === "failed" && <p role="alert">링크를 보내지 못했어요. 잠시 뒤에 다시 해 주세요.</p>}
        </main>
    );
}
