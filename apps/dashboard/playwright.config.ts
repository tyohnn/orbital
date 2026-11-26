import { defineConfig } from "@playwright/test";

/**
 * 대시보드의 e2e. 로컬 Supabase(`npx supabase start`, API 54421 · DB 54422)와 실제 관리 서버(orbitald)에 붙는다.
 * 대시보드는 프로덕션 빌드로 띄우고 로컬 계정 문만 연다(`ALLOW_LOCAL_ACCOUNTS=1`). orbitald 는 `e2e/global-setup.ts` 가 띄운다.
 * `ORBITAL_PG` 가 없으면 관리 서버를 띄우지 못해 모두 건너뛴다.
 */
const SUPABASE_URL = process.env.E2E_SUPABASE_URL ?? "http://127.0.0.1:54421";
const PORT = 7601;

export default defineConfig({
    testDir: "e2e",
    fullyParallel: false,
    workers: 1,
    timeout: 60_000,
    globalSetup: "./e2e/global-setup.ts",
    use: {
        baseURL: `http://127.0.0.1:${PORT}`,
        launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH === undefined ? {} : { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH },
    },
    webServer: {
        command: `npx next build && npx next start -p ${PORT}`,
        url: `http://127.0.0.1:${PORT}/login`,
        timeout: 300_000,
        reuseExistingServer: false,
        env: {
            NODE_ENV: "production",
            ALLOW_LOCAL_ACCOUNTS: "1",
            NEXT_PUBLIC_SUPABASE_URL: SUPABASE_URL,
            NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.E2E_SUPABASE_ANON_KEY ?? "",
            DASHBOARD_DATABASE_URL: "postgresql://dashboard_app:dashboard-app-local@127.0.0.1:54422/postgres",
            DASHBOARD_SEAL_KEY: "33".repeat(32),
            ORBITAL_URL: "http://127.0.0.1:7699",
            ORBITAL_ADMIN_KEY: "admin_key_for_dashboard_e2e_0123456789ab",
        },
    },
});
