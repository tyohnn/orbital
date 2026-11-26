// ✏️ 앱의 이름
export const metadata = { title: "메모" };

export default function RootLayout({ children })
{
    return (
        <html lang="ko">
            <body>{children}</body>
        </html>
    );
}
