import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

// 모든 화면이 로그인한 사람마다 다르다. 미리 렌더하지 않는다
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
    title: "Orbital 대시보드",
    description: "팩토리를 만들고 API 키와 팀원을 관리해요",
};

export default function RootLayout({ children }: { children: ReactNode })
{
    return (
        <html lang="ko">
            <body className="min-h-dvh bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">{children}</body>
        </html>
    );
}
