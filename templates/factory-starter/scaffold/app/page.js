import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { addNote, listNotes } from "../lib/db.js";

// ✏️ 당신의 앱의 첫 화면. 지금은 로그인한 사람의 메모를 보이고 더한다. 신원이 없으면 로그인 화면으로 보낸다
export default async function Home()
{
    const identity = (await headers()).get("x-orbital-identity");
    if (identity === null)
    {
        redirect("/login?next=/");
    }
    const notes = await listNotes(identity);

    async function add(form)
    {
        "use server";
        const signed = (await headers()).get("x-orbital-identity");
        const body = String(form.get("body") ?? "").trim();
        if (signed !== null && body !== "")
        {
            await addNote(signed, body);
        }
        revalidatePath("/");
    }

    return (
        <main>
            <h1>메모</h1>
            <ul id="notes">
                {notes.map((note) => <li key={note.id}>{note.body}</li>)}
            </ul>
            <form action={add}>
                <label htmlFor="body">새 메모</label>
                <input id="body" name="body" required />
                <button type="submit">더하기</button>
            </form>
        </main>
    );
}
