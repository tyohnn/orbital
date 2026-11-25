// 실제 브라우저(Playwright 의 Chromium)로 `examples/todo-next` 를 연다. 무거운 묶음(`tests/frameworks.rs`)이 부른다.
//
//   node todo-next.cjs preview <주소> <씨앗 사용자의 세션 쿠키 값>
//   node todo-next.cjs production <주소> <메일함 파일> <초대한 이메일>
//
// 본 것을 JSON 한 줄로 찍는다. 판정은 부른 쪽(Rust 의 테스트)이 한다. 막히면 던지고 0 이 아닌 코드로 끝난다.
// ⚠ CommonJS 로 둔다. Playwright 는 전역(NODE_PATH)에 깔려 있고 ESM 의 import 는 NODE_PATH 를 보지 않는다.
const { createServer } = require("node:http");
const { readFileSync } = require("node:fs");
const { chromium } = require("playwright");

const SESSION = "__Host-orbital-session";

async function titles(page)
{
    return page.$$eval("#todos li", (items) => items.map((item) => item.textContent));
}

/** 로그인 화면이 hydrate 된 뒤 단추가 동작하는지. JS 가 돌지 않으면 폼이 GET 으로 나가 주소에 이메일이 붙는다 */
async function askLink(page, email)
{
    await page.waitForLoadState("networkidle");
    await page.fill("#email", email);
    const asked = page.waitForResponse((response) => response.url().endsWith("/_orbital/auth/email-link"));
    await page.click("button[type=submit]");
    const status = (await asked).status();
    await page.waitForSelector("text=메일함을 확인해 주세요", { timeout: 10_000 });
    return { status, url: page.url() };
}

async function addTodo(page, title)
{
    await page.fill("#title", title);
    await page.click("button:has-text('더하기')");
    await page.waitForSelector(`#todos li:has-text('${title}')`, { timeout: 15_000 });
}

async function preview(page, context, url, cookie)
{
    const seen = {};
    await page.goto(`${url}/`);
    const landed = new URL(page.url());
    seen.landed = `${landed.pathname}${landed.search}`;
    seen.asked = await askLink(page, "u1@example.test");
    await context.addCookies([{ name: SESSION, value: cookie, domain: "127.0.0.1", path: "/", secure: true, httpOnly: true, sameSite: "Lax" }]);
    await page.goto(`${url}/`);
    seen.before = await titles(page);
    await addTodo(page, "브라우저에서 더한 일");
    seen.after = await titles(page);
    return seen;
}

/** 다른 주소(origin)의 화면. 레이어의 상태를 바꾸는 길로 폼과 fetch 를 보낸다 */
async function otherOrigin(target)
{
    const server = createServer((request, response) =>
    {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(`<!doctype html><form method="post" action="${target}/_orbital/auth/logout"><button id="logout">나가기</button></form>`);
    });
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    return { server, url: `http://127.0.0.1:${server.address().port}/` };
}

async function production(page, context, url, outbox, email)
{
    const seen = {};
    await page.goto(`${url}/`);
    seen.asked = await askLink(page, email);
    let link = "";
    for (let tries = 0; link === "" && tries < 200; tries += 1)
    {
        try
        {
            link = readFileSync(outbox, "utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((mail) => mail.to === email).at(-1)?.link ?? "";
        }
        catch
        {
            link = "";
        }
        if (link === "")
        {
            await new Promise((done) => setTimeout(done, 50));
        }
    }
    if (link === "")
    {
        throw new Error("메일함에 링크가 오지 않았습니다");
    }
    // 같은 브라우저로 링크를 연다. 레이어가 세션 쿠키를 심고 돌아갈 곳(/)으로 보낸다
    await page.goto(link);
    seen.landed = new URL(page.url()).pathname;
    seen.cookies = (await context.cookies()).map((cookie) => ({ name: cookie.name, secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite, path: cookie.path }));
    seen.before = await titles(page);
    await addTodo(page, "운영의 브라우저에서 더한 일");
    seen.after = await titles(page);

    // 다른 주소의 화면이 보낸 로그아웃은 막힌다. 세션은 그대로다
    const other = await otherOrigin(url);
    try
    {
        await page.goto(other.url);
        const answered = page.waitForResponse((response) => response.url().endsWith("/_orbital/auth/logout"));
        await page.click("#logout");
        seen.crossLogout = (await answered).status();
        // 다른 주소의 화면에서 fetch 로 링크를 요청해도 막힌다(답은 읽지 못하고, 레이어는 403 으로 답한다). 폼이 레이어의 답으로 옮겨 갔으니 돌아온다
        await page.goto(other.url);
        seen.otherOrigin = new URL(page.url()).origin !== new URL(url).origin;
        const fetched = page.waitForResponse((response) => response.url().endsWith("/_orbital/auth/email-link"));
        await page.evaluate((target) => fetch(`${target}/_orbital/auth/email-link`, { method: "POST", mode: "no-cors", credentials: "include", headers: { "content-type": "text/plain" }, body: JSON.stringify({ email: "x@example.test" }) }).catch(() => undefined), url);
        seen.crossLink = (await fetched).status();
    }
    finally
    {
        other.server.close();
    }
    await page.goto(`${url}/`);
    seen.stillIn = new URL(page.url()).pathname === "/" && (await titles(page)).length > 0;
    // 같은 주소의 화면에서는 나간다
    seen.logout = await page.evaluate(async () => (await fetch("/_orbital/auth/logout", { method: "POST" })).status);
    await page.goto(`${url}/`);
    seen.afterLogout = new URL(page.url()).pathname;
    return seen;
}

(async () =>
{
    const [mode, url, ...rest] = process.argv.slice(2);
    const browser = await chromium.launch();
    try
    {
        const context = await browser.newContext();
        const page = await context.newPage();
        const seen = mode === "preview"
            ? await preview(page, context, url, rest[0])
            : await production(page, context, url, rest[0], rest[1]);
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
