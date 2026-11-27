import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
    resolve: {
        alias: {
            // 서버 전용 게이트(`import "server-only"`)는 Next 서버 밖에서 throw 한다. 테스트에서만 빈 모듈로 바꾼다
            "server-only": fileURLToPath(new URL("./test/server-only.ts", import.meta.url)),
            "@/": fileURLToPath(new URL("./src/", import.meta.url)),
            // 워크스페이스의 SDK 는 빌드하지 않은 소스(.ts)를 쓴다(`orbital-source` 조건과 같은 자리)
            "@harmony/orbital/server": fileURLToPath(new URL("../../sdk/typescript/src/server.ts", import.meta.url)),
        },
    },
    test: {
        include: ["src/**/*.test.ts"],
        // 관리 서버(orbitald)를 띄우는 테스트가 있어 넉넉히 둔다
        testTimeout: 30_000,
        hookTimeout: 60_000,
        fileParallelism: false,
    },
});
