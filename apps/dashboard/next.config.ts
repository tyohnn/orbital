import type { NextConfig } from "next";

const nextConfig: NextConfig =
{
    // SDK 는 raw TS 로 소비한다. 워크스페이스의 SDK 는 묶을 때만 `dist/` 를 지으므로 소스를 가리킨다(`orbital-source` 조건과 같은 자리)
    transpilePackages: ["@harmony/orbital"],
    turbopack: {
        resolveAlias: {
            "@harmony/orbital/server": "../../sdk/typescript/src/server.ts",
        },
    },
};

export default nextConfig;
