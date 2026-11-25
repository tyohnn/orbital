// 화면은 레이어의 로그인(`/_orbital/auth/…`)과 같은 주소의 API(`/api/…`)만 부른다
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
    const body = document.querySelector("#payslips tbody");
    body.replaceChildren(...answer.payslips.map((payslip) =>
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
