// 실제 브라우저(Playwright 의 Chromium)로 `examples/hr-nest-vite` 의 화면을 연다. 무거운 묶음(`tests/frameworks.rs`)이 부른다.
//
//   node hr-nest-vite.cjs <주소> <씨앗 사용자의 세션 쿠키 값>
//
// 화면 안의 경로(`/payslips/<달>`)를 바로 열고 새로 고쳐도 화면이 뜨는지 본다(정적 서비스의 `fallback`). 본 것을 JSON 한 줄로 찍는다.
const { chromium } = require("playwright");

async function shown(page)
{
    await page.waitForSelector("#payslips:not([hidden])", { timeout: 15_000 });
    return {
        path: new URL(page.url()).pathname,
        month: await page.$eval("#month", (heading) => (heading.hidden ? null : heading.textContent)),
        rows: await page.$$eval("#payslips tbody tr", (rows) => rows.map((row) => [...row.cells].map((cell) => cell.textContent))),
    };
}

(async () =>
{
    const [origin, cookie] = process.argv.slice(2);
    const browser = await chromium.launch();
    try
    {
        const seen = {};
        // 로그인하지 않은 브라우저가 화면 안의 경로를 바로 열면, 그 자리에서 화면이 떠 로그인 칸을 보인다
        const stranger = await browser.newPage();
        const answer = await stranger.goto(`${origin}/payslips/2026-11`);
        seen.strangerStatus = answer.status();
        await stranger.waitForSelector("#login:not([hidden])", { timeout: 15_000 });
        seen.strangerLogin = true;

        const context = await browser.newContext();
        await context.addCookies([{ name: "__Host-orbital-session", value: cookie, domain: "127.0.0.1", path: "/", secure: true, httpOnly: true, sameSite: "Lax" }]);
        const page = await context.newPage();
        await page.goto(`${origin}/`);
        seen.root = await shown(page);
        // 달의 링크를 누르면 화면 안에서 경로만 바뀐다
        await page.click("#months a:has-text('2026-10')");
        await page.waitForSelector("#month:not([hidden])");
        seen.clicked = await shown(page);
        // 그 경로를 새로 고쳐도 화면이 뜬다
        const reloaded = await page.reload();
        seen.reloadStatus = reloaded.status();
        seen.reloaded = await shown(page);
        seen.browser = browser.version();
        console.log(JSON.stringify(seen));
    }
    finally
    {
        await browser.close();
    }
})().catch((error) =>
{
    console.error(error);
    process.exit(1);
});
