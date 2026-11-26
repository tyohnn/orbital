// DB 에는 비밀번호 없이 붙는다. 주소(PGHOST · PGPORT)는 레이어가 건네고, 사용자 자리에 업무 역할의 이름을 적는다.
// 신원은 router 가 요청에 실어 준 서명된 머리말이다. 앱은 풀거나 믿지 않고 그대로 DB 에 넘겨 행 단위 규칙이 가르게 한다.
// ✏️ 당신의 앱의 질의를 이 파일에 둔다. `withIdentity` 는 그대로 쓴다.
import pg from "pg";

let pool = null;

function members()
{
    // 빌드할 때는 DB 가 없다. 처음 쓸 때 만든다
    pool ??= new pg.Pool({
        host: process.env.PGHOST,
        port: Number(process.env.PGPORT),
        database: process.env.PGDATABASE ?? "app",
        user: "member",
        max: 5,
    });
    return pool;
}

async function withIdentity(identity, work)
{
    const client = await members().connect();
    try
    {
        await client.query("BEGIN");
        await client.query("SELECT set_config('orbital.identity', $1, true)", [identity]);
        const result = await work(client);
        await client.query("COMMIT");
        return result;
    }
    catch (error)
    {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
    }
    finally
    {
        client.release();
    }
}

export async function listNotes(identity)
{
    return withIdentity(identity, async (client) =>
    {
        const result = await client.query("SELECT id, body FROM app.note ORDER BY id");
        return result.rows;
    });
}

export async function addNote(identity, body)
{
    return withIdentity(identity, async (client) =>
    {
        const result = await client.query("INSERT INTO app.note (body) VALUES ($1) RETURNING id", [body]);
        return result.rows[0].id;
    });
}
