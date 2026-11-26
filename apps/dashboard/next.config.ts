import type { NextConfig } from "next";

const nextConfig: NextConfig =
{
    // SDK 는 raw TS 로 소비한다(빌드 산출물이 없다)
    transpilePackages: ["@harmony/orbital"],
};

export default nextConfig;
