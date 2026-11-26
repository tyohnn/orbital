/** 돌아갈 주소는 같은 사이트의 경로만 받는다. 사람이 주소창에 적을 수 있는 값이다. */
export const safeRedirect = (candidate: string | null | undefined, fallback: string): string =>
{
    if (candidate === null || candidate === undefined || candidate === "")
    {
        return fallback;
    }
    if (!candidate.startsWith("/") || candidate.startsWith("//") || candidate.startsWith("/\\"))
    {
        return fallback;
    }
    return candidate;
};
