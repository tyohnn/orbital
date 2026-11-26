// 로컬 계정(이메일 · 비밀번호)의 문. 화면이 칸을 감추는 것만으로는 부족하다: 서버 액션은 화면을 지나지 않고도 불린다.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const signIn = vi.fn(async () => ({ error: null }));

vi.mock("next/navigation", () => ({
    redirect: (to: string) =>
    {
        throw new Error(`redirect:${to}`);
    },
}));
vi.mock("next/headers", () => ({ headers: async () => new Headers() }));
vi.mock("@/lib/supabase/server", () => ({
    supabaseServer: async () => ({ auth: { signInWithPassword: signIn } }),
}));

const form = (): FormData =>
{
    const data = new FormData();
    data.set("email", "ana@factory.test");
    data.set("password", "orbital-local");
    data.set("next", "/new");
    return data;
};

describe("로컬 계정의 문", () =>
{
    beforeEach(() =>
    {
        signIn.mockClear();
    });

    afterEach(() =>
    {
        vi.unstubAllEnvs();
    });

    it("이메일 · 비밀번호 로그인은 로컬 계정 문이 닫힌 운영에서는 서버 액션도 거절하고 Auth 에 묻지도 않는다", async () =>
    {
        vi.stubEnv("NODE_ENV", "production");
        vi.stubEnv("ALLOW_LOCAL_ACCOUNTS", "");
        const { signInWithPassword } = await import("./session.ts");
        await expect(signInWithPassword(form())).rejects.toThrow("redirect:/login?next=%2Fnew&error=failed");
        expect(signIn).not.toHaveBeenCalled();
    });

    it("문이 열린 환경(개발 · e2e 의 ALLOW_LOCAL_ACCOUNTS=1)에서는 이메일 · 비밀번호로 들어온다", async () =>
    {
        for (const [nodeEnv, allow] of [["development", ""], ["production", "1"]] as const)
        {
            vi.stubEnv("NODE_ENV", nodeEnv);
            vi.stubEnv("ALLOW_LOCAL_ACCOUNTS", allow);
            const { signInWithPassword } = await import("./session.ts");
            await expect(signInWithPassword(form())).rejects.toThrow("redirect:/new");
        }
        expect(signIn).toHaveBeenCalledTimes(2);
    });

    it("문은 ALLOW_LOCAL_ACCOUNTS 가 정확히 1 일 때만 운영에서 열린다", async () =>
    {
        const { localAccountsAllowed } = await import("../lib/localAccounts.ts");
        vi.stubEnv("NODE_ENV", "production");
        for (const value of ["true", "yes", "0", ""])
        {
            vi.stubEnv("ALLOW_LOCAL_ACCOUNTS", value);
            expect(localAccountsAllowed()).toBe(false);
        }
        vi.stubEnv("ALLOW_LOCAL_ACCOUNTS", "1");
        expect(localAccountsAllowed()).toBe(true);
    });
});
