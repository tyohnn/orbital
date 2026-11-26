import { addNote, listNotes } from "../../../lib/db.js";

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
    return Response.json(await listNotes(identity));
}

export async function POST(request)
{
    const identity = identityOf(request);
    if (identity === null)
    {
        return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const input = await request.json().catch(() => ({}));
    const body = typeof input.body === "string" ? input.body.trim() : "";
    if (body === "")
    {
        return Response.json({ error: "body" }, { status: 400 });
    }
    return Response.json({ id: await addNote(identity, body) }, { status: 201 });
}
