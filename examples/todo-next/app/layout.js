export const metadata = { title: "할 일" };

export default function RootLayout({ children })
{
    return (
        <html lang="ko">
            <body>{children}</body>
        </html>
    );
}
