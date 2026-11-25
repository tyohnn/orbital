import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { addTodo, listTodos } from "../lib/db.js";

// 로그인한 사람의 할 일. 신원이 없으면(로그인하지 않았으면) 로그인 화면으로 보낸다
export default async function Home()
{
    const identity = (await headers()).get("x-orbital-identity");
    if (identity === null)
    {
        redirect("/login?next=/");
    }
    const todos = await listTodos(identity);

    async function add(form)
    {
        "use server";
        const signed = (await headers()).get("x-orbital-identity");
        const title = String(form.get("title") ?? "").trim();
        if (signed !== null && title !== "")
        {
            await addTodo(signed, title);
        }
        revalidatePath("/");
    }

    return (
        <main>
            <h1>할 일</h1>
            <ul id="todos">
                {todos.map((todo) => <li key={todo.id}>{todo.title}</li>)}
            </ul>
            <form action={add}>
                <label htmlFor="title">새 할 일</label>
                <input id="title" name="title" required />
                <button type="submit">더하기</button>
            </form>
        </main>
    );
}
