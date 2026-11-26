import { notFound } from "next/navigation";

import { removeMember, setRole } from "@/actions/factory";
import { ROLES, canManageTeam } from "@/domain/team";
import { dashboard } from "@/server/runtime";

import { Shell, roleName } from "../../../_components/Shell";
import { signedIn } from "../../../_components/session";
import { InviteForm } from "./InviteForm";

export default async function TeamPage({ params }: { params: Promise<{ factory: string }> })
{
    const { factory } = await params;
    const { account, memberships } = await signedIn();
    const mine = memberships.find((one) => one.factoryId === factory);
    const team = await dashboard().team(account, factory);
    if (mine === undefined || !team.ok)
    {
        notFound();
    }
    const manage = canManageTeam(mine.role);
    return (
        <Shell email={account.email} memberships={memberships} current={factory}>
            <h1 className="text-xl font-semibold">팀원</h1>
            <p className="mt-1 text-sm text-neutral-500">초대한 이메일로 Google 에 로그인하면 이 팩토리의 팀원이 돼요.</p>
            {manage && <InviteForm factoryId={factory} />}
            <ul className="mt-6 divide-y divide-neutral-200 text-sm dark:divide-neutral-800">
                {team.value.members.map((member) => (
                    <li key={member.accountId} className="flex flex-wrap items-center gap-3 py-2">
                        <span className="flex-1">{member.email}{member.accountId === account.id && <span className="text-neutral-500"> (나)</span>}</span>
                        {manage
                            ? (
                                <form action={async (form: FormData) =>
                                {
                                    "use server";
                                    await setRole(factory, member.accountId, form);
                                }} className="flex gap-1">
                                    <select name="role" defaultValue={member.role} aria-label={`${member.email}의 역할`} className="rounded-md border border-neutral-300 bg-transparent px-2 py-1 dark:border-neutral-700">
                                        {ROLES.map((role) => <option key={role} value={role}>{roleName(role)}</option>)}
                                    </select>
                                    <button className="underline">바꾸기</button>
                                </form>
                            )
                            : <span>{roleName(member.role)}</span>}
                        {(manage || member.accountId === account.id) && (
                            <form action={async () =>
                            {
                                "use server";
                                await removeMember(factory, member.accountId);
                            }}>
                                <button className="text-red-600 underline">{member.accountId === account.id ? "나가기" : "빼기"}</button>
                            </form>
                        )}
                    </li>
                ))}
                {team.value.invitations.map((invitation) => (
                    <li key={invitation.email} className="flex items-center gap-3 py-2 text-neutral-500">
                        <span className="flex-1">{invitation.email}</span>
                        <span>{roleName(invitation.role)} · 초대함</span>
                    </li>
                ))}
            </ul>
        </Shell>
    );
}
