import { notFound } from "next/navigation";

import { revokeKey } from "@/actions/factory";
import { canManageKeys } from "@/domain/team";
import { dashboard } from "@/server/runtime";

import { Shell } from "../../../_components/Shell";
import { signedIn } from "../../../_components/session";
import { NewKeyForm } from "./NewKeyForm";

const date = (seconds: number): string => new Date(seconds * 1000).toLocaleDateString("ko-KR");

export default async function KeysPage({ params }: { params: Promise<{ factory: string }> })
{
    const { factory } = await params;
    const { account, memberships } = await signedIn();
    const mine = memberships.find((one) => one.factoryId === factory);
    const keys = await dashboard().keys(account, factory);
    if (mine === undefined || !keys.ok)
    {
        notFound();
    }
    const manage = canManageKeys(mine.role);
    return (
        <Shell email={account.email} memberships={memberships} current={factory}>
            <h1 className="text-xl font-semibold">API 키</h1>
            <p className="mt-1 text-sm text-neutral-500">팩토리 서버가 Orbital 을 부를 때 쓰는 키예요. 키의 값은 만들 때 한 번만 보여요.</p>
            {manage && <NewKeyForm factoryId={factory} />}
            <table className="mt-6 w-full text-left text-sm">
                <thead className="text-neutral-500">
                    <tr><th className="py-2 font-normal">이름</th><th className="font-normal">만든 날</th><th className="font-normal">상태</th><th /></tr>
                </thead>
                <tbody>
                    {keys.value.map((key) => (
                        <tr key={key.id} className="border-t border-neutral-200 dark:border-neutral-800">
                            <td className="py-2">{key.label === "" ? <span className="text-neutral-500">이름 없음</span> : key.label}<div className="font-mono text-xs text-neutral-500">{key.id}</div></td>
                            <td>{date(key.createdAt)}</td>
                            <td>{key.revokedAt === null ? "사용 중" : `${date(key.revokedAt)}에 폐기`}</td>
                            <td className="text-right">
                                {manage && key.revokedAt === null && !key.managed && (
                                    <form action={async () =>
                                    {
                                        "use server";
                                        await revokeKey(factory, key.id);
                                    }}>
                                        <button className="text-red-600 underline">폐기</button>
                                    </form>
                                )}
                                {key.managed && <span className="text-xs text-neutral-500">대시보드가 써요</span>}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </Shell>
    );
}
