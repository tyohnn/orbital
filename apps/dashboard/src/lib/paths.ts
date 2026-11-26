/** 대시보드의 주소를 만드는 단 한 곳. */
export const paths = {
    home: (): string => "/",
    login: (next?: string, error?: "failed" | "credentials"): string =>
    {
        const query = new URLSearchParams();
        if (next !== undefined && next !== "/")
        {
            query.set("next", next);
        }
        if (error !== undefined)
        {
            query.set("error", error);
        }
        const text = query.toString();
        return text === "" ? "/login" : `/login?${text}`;
    },
    newFactory: (): string => "/new",
    keys: (factory: string): string => `/f/${encodeURIComponent(factory)}/keys`,
    team: (factory: string): string => `/f/${encodeURIComponent(factory)}/team`,
};

/** 로그인 없이 여는 자리. */
export const isPublic = (pathname: string): boolean => pathname === "/login" || pathname.startsWith("/auth/");
