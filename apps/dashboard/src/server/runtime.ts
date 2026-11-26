import "server-only";

import { createOrbital, createOrbitalAdmin } from "@harmony/orbital/server";

import { supabaseServer } from "../lib/supabase/server.ts";
import { createDashboard } from "./dashboard.ts";
import type { Dashboard } from "./dashboard.ts";
import { PgStore } from "./pg-store.ts";
import { sealerFromHex } from "./seal.ts";
import { MemoryStore } from "./store.ts";
import type { Account, Store } from "./store.ts";

/**
 * 환경 변수에서 대시보드를 한 번 짓는다. 운영자 키와 봉인의 열쇠는 서버의 환경 변수에만 있다.
 * ⚠ `DASHBOARD_DATABASE_URL` 이 없으면 개발에서만 메모리에 둔다(서버가 다시 뜨면 사라진다). 프로덕션에서는 멈춘다.
 */
const need = (name: string): string =>
{
    const value = process.env[name];
    if (value === undefined || value === "")
    {
        throw new Error(`${name} 을 적어 주세요(apps/dashboard/.env.example)`);
    }
    return value;
};

const storeFromEnv = (): Store =>
{
    const url = process.env.DASHBOARD_DATABASE_URL;
    if (url !== undefined && url !== "")
    {
        return PgStore.connect(url);
    }
    if (process.env.NODE_ENV === "production")
    {
        throw new Error("DASHBOARD_DATABASE_URL 을 적어 주세요. 프로덕션에서는 메모리에 두지 않습니다");
    }
    return new MemoryStore();
};

let built: Dashboard | undefined;

export const dashboard = (): Dashboard =>
{
    if (built === undefined)
    {
        const url = need("ORBITAL_URL");
        built = createDashboard({
            store: storeFromEnv(),
            admin: createOrbitalAdmin({ url, adminKey: need("ORBITAL_ADMIN_KEY") }),
            orbital: (serviceKey) => createOrbital({ url, serviceKey }),
            sealer: sealerFromHex(need("DASHBOARD_SEAL_KEY")),
        });
    }
    return built;
};

/** 로그인한 계정. Auth 서버에 물어 토큰을 확인한다. 없으면 `null` 이다. */
export const currentAccount = async (): Promise<Account | null> =>
{
    const supabase = await supabaseServer();
    const { data } = await supabase.auth.getUser();
    const user = data.user;
    if (user === null || user.email === undefined)
    {
        return null;
    }
    return { id: user.id, email: user.email };
};
