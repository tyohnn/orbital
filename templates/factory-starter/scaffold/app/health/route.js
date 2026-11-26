// 떠 있는지. 적합성 테스트와 팩토리의 운영자가 부른다. 로그인 없이 열린다(orbital.toml 의 public)
export const dynamic = "force-dynamic";

export function GET()
{
    return Response.json({ ok: true, version: 1 });
}
