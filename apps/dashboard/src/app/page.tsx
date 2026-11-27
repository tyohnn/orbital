import { redirect } from "next/navigation";

import { paths } from "@/lib/paths";
import { currentAccount, dashboard } from "@/server/runtime";

/** 들어오면 초대를 받고, 속한 팩토리가 없으면 만들기로, 있으면 첫 팩토리의 키로 간다. */
export default async function Home()
{
    const account = await currentAccount();
    if (account === null)
    {
        redirect(paths.login());
    }
    const memberships = await dashboard().enter(account);
    const first = memberships[0];
    redirect(first === undefined ? paths.newFactory() : paths.keys(first.factoryId));
}
