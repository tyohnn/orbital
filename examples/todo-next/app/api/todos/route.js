import { addTodo, listTodos } from "../../../lib/db.js";

// 화면 밖에서 부르는 길(JSON). 신원이 없으면 401 이다
function identityOf(request)
{
    return request.headers.get("x-orbital-identity");
}

export async function GET(request)
{
    const identity = identityOf(request);
    if (identity === null)
    {
        return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    return Response.json(await listTodos(identity));
}

export async function POST(request)
{
    const identity = identityOf(request);
    if (identity === null)
    {
        return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const body = await request.json().catch(() => ({}));
    const title = typeof body.title === "string" ? body.title.trim() : "";
    if (title === "")
    {
        return Response.json({ error: "title" }, { status: 400 });
    }
    return Response.json({ id: await addTodo(identity, title) }, { status: 201 });
}
