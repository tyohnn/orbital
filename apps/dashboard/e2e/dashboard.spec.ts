import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const PASSWORD = "orbital-local";

async function signIn(page: Page, email: string): Promise<void>
{
    await page.context().clearCookies();
    await page.goto("/login");
    await page.getByLabel("이메일").fill(email);
    await page.getByLabel("비밀번호").fill(PASSWORD);
    await page.getByRole("button", { name: "이메일로 로그인" }).click();
}

test.skip(process.env.ORBITAL_PG === undefined, "ORBITAL_PG 가 없어 관리 서버를 띄우지 못합니다");

test("로그인하지 않으면 로그인 화면으로 가고 로컬 계정 문이 열린 환경에서는 이메일과 비밀번호 칸이 선다", async ({ page }) =>
{
    await page.goto("/new");
    await expect(page).toHaveURL(/\/login\?next=%2Fnew/);
    await expect(page.getByRole("button", { name: "Google로 계속하기" })).toBeVisible();
    await expect(page.getByLabel("비밀번호")).toBeVisible();
});

test("틀린 비밀번호로는 들어오지 못한다", async ({ page }) =>
{
    await page.goto("/login");
    await page.getByLabel("이메일").fill("ana@factory.test");
    await page.getByLabel("비밀번호").fill("wrong-password");
    await page.getByRole("button", { name: "이메일로 로그인" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "이메일이나 비밀번호가 맞지 않아요." })).toBeVisible();
});

test("처음 들어온 사람이 팩토리를 만들면 첫 키를 한 번 받고 팀원을 초대하며, 초대받지 않은 사람은 그 팩토리를 보지 못한다", async ({ page }) =>
{
    // 속한 팩토리가 없으면 만들기 화면으로 간다
    await signIn(page, "ana@factory.test");
    await expect(page).toHaveURL(/\/new$/);
    await page.getByLabel("팩토리 이름").fill("acme");
    await page.getByLabel("보이는 이름(선택)").fill("Acme 팩토리");
    await page.getByRole("button", { name: "팩토리 만들기" }).click();
    const secret = await page.getByTestId("secret").textContent();
    expect(secret).toMatch(/^orb_sk_/);

    // 키 화면에는 비밀이 다시 보이지 않고, 대시보드가 쓰는 키에는 폐기 단추가 없다
    await page.getByRole("link", { name: "API 키 화면으로 가기" }).click();
    await expect(page.getByRole("heading", { name: "API 키" })).toBeVisible();
    expect(await page.content()).not.toContain(secret ?? "never");
    await expect(page.getByText("대시보드가 써요")).toBeVisible();
    await page.getByLabel("키 이름").fill("배포 서버");
    await page.getByRole("button", { name: "새 키 만들기" }).click();
    await expect(page.getByTestId("secret")).toHaveText(/^orb_sk_/);

    // 팀원을 관리자로 초대한다
    await page.getByRole("link", { name: "팀원" }).click();
    await page.getByLabel("팀원의 이메일").fill("Ben@Factory.test");
    await page.getByLabel("역할", { exact: true }).selectOption("admin");
    await page.getByRole("button", { name: "초대하기" }).click();
    await expect(page.getByRole("status")).toContainText("초대했어요");

    // 초대받은 사람은 들어오면 그 팩토리의 관리자다
    await signIn(page, "ben@factory.test");
    await expect(page).toHaveURL(/\/f\/acme\/keys$/);
    await expect(page.getByRole("button", { name: "새 키 만들기" })).toBeVisible();

    // 초대받지 않은 사람은 만들기 화면으로 가고, 남의 팩토리 주소는 없는 것과 같다
    await signIn(page, "cho@elsewhere.test");
    await expect(page).toHaveURL(/\/new$/);
    await page.getByLabel("팩토리 이름").fill("acme");
    await page.getByRole("button", { name: "팩토리 만들기" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "이미 쓰는 이름이에요. 다른 이름을 골라 주세요." })).toBeVisible();
    const response = await page.goto("/f/acme/keys");
    expect(response?.status()).toBe(404);
});
