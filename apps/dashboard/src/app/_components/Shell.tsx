import Link from "next/link";
import type { ReactNode } from "react";

import { signOut } from "@/actions/session";
import { paths } from "@/lib/paths";
import type { Membership } from "@/server/store";

const ROLE_NAMES = { owner: "주인", admin: "관리자", member: "멤버" } as const;

export const roleName = (role: keyof typeof ROLE_NAMES): string => ROLE_NAMES[role];

/** 로그인한 화면의 틀. 팩토리를 고르고 키와 팀원 사이를 오간다. */
export function Shell({ email, memberships, current, children }: {
    email: string;
    memberships: readonly Membership[];
    current?: string;
    children: ReactNode;
})
{
    return (
        <div className="mx-auto max-w-4xl px-4 py-6">
            <header className="mb-8 flex flex-wrap items-center gap-3 border-b border-neutral-200 pb-4 dark:border-neutral-800">
                <Link href={paths.home()} className="font-semibold">Orbital</Link>
                <nav aria-label="팩토리" className="flex flex-wrap gap-1">
                    {memberships.map((one) => (
                        <Link
                            key={one.factoryId}
                            href={paths.keys(one.factoryId)}
                            aria-current={one.factoryId === current ? "page" : undefined}
                            className="rounded-md px-2 py-1 text-sm aria-[current=page]:bg-neutral-200 dark:aria-[current=page]:bg-neutral-800"
                        >
                            {one.label === "" ? one.factoryId : one.label}
                        </Link>
                    ))}
                    <Link href={paths.newFactory()} className="rounded-md px-2 py-1 text-sm text-neutral-500">+ 새 팩토리</Link>
                </nav>
                <form action={signOut} className="ml-auto flex items-center gap-3 text-sm text-neutral-500">
                    <span>{email}</span>
                    <button className="underline">로그아웃</button>
                </form>
            </header>
            {current !== undefined && (
                <nav aria-label="팩토리 메뉴" className="mb-6 flex gap-4 text-sm">
                    <Link href={paths.keys(current)} className="font-medium">API 키</Link>
                    <Link href={paths.team(current)} className="font-medium">팀원</Link>
                </nav>
            )}
            {children}
        </div>
    );
}
