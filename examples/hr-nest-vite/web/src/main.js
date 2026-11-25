// 화면은 레이어의 로그인(`/_orbital/auth/…`)과 같은 주소의 API(`/api/…`)만 부른다.
// 화면 안의 경로 `/payslips/<달>` 은 그 달의 명세만 보인다. 정적 서비스의 `fallback` 이 이 경로를 새로 고쳐도 index.html 을 내준다
import { logout, me, sendLoginLink } from "./orbital-app.js";

const show = (id, visible) =>
{
    document.getElementById(id).hidden = !visible;
};

async function payslips()
{
    const response = await fetch("/api/payslips", { headers: { accept: "application/json" } });
    if (!response.ok)
    {
        throw new Error(String(response.status));
    }
    const answer = await response.json();
    // 화면 안의 경로가 달을 가리키면 그 달의 것만 보인다
    const month = /^\/payslips\/(\d{4}-\d{2})$/.exec(location.pathname)?.[1];
    const shown = month === undefined ? answer.payslips : answer.payslips.filter((payslip) => payslip.month === month);
    if (month !== undefined)
    {
        document.getElementById("month").textContent = `${month} 의 명세`;
        show("month", true);
    }
    const months = [...new Set(answer.payslips.map((payslip) => payslip.month))].sort();
    document.getElementById("months").replaceChildren(...months.map((each) =>
    {
        const link = document.createElement("a");
        link.href = `/payslips/${each}`;
        link.textContent = each;
        link.addEventListener("click", (event) =>
        {
            event.preventDefault();
            history.pushState(null, "", link.href);
            void payslips();
        });
        return link;
    }));
    const body = document.querySelector("#payslips tbody");
    body.replaceChildren(...shown.map((payslip) =>
    {
        const row = document.createElement("tr");
        for (const value of [payslip.employee, payslip.month, payslip.amount.toLocaleString("ko-KR")])
        {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.append(cell);
        }
        return row;
    }));
}

async function start()
{
    try
    {
        const person = await me();
        if (person === null)
        {
            show("login", true);
            return;
        }
        document.getElementById("who").textContent = `${person.email} 으로 들어왔어요`;
        await payslips();
        show("payslips", true);
    }
    catch
    {
        show("failed", true);
    }
}

document.getElementById("login").addEventListener("submit", async (event) =>
{
    event.preventDefault();
    try
    {
        await sendLoginLink({ email: event.currentTarget.email.value, next: "/" });
        show("login", false);
        show("sent", true);
    }
    catch
    {
        show("failed", true);
    }
});

document.getElementById("logout").addEventListener("click", async () =>
{
    await logout();
    location.reload();
});

void start();
