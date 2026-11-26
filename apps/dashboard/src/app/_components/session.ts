import "server-only";

import { redirect } from "next/navigation";

import { paths } from "@/lib/paths";
import { currentAccount, dashboard } from "@/server/runtime";
import type { Account, Membership } from "@/server/store";

/** 로그인한 화면이 처음 하는 일. 계정을 확인하고 초대를 받고 속한 팩토리를 돌려준다. */
export const signedIn = async (): Promise<{ account: Account; memberships: Membership[] }> =>
{
    const account = await currentAccount();
    if (account === null)
    {
        redirect(paths.login());
    }
    return { account, memberships: await dashboard().enter(account) };
};
