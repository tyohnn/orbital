// 대시보드가 쓰는 팩토리의 service key 를 봉인한다. AES-256-GCM 이고, 팩토리 이름을 함께 묶어(AAD) 다른 팩토리의 줄에 옮기면 풀리지 않는다.
// 열쇠는 기록 밖의 `DASHBOARD_SEAL_KEY`(32바이트, hex 64자)에서 온다.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface Sealer
{
    seal(factoryId: string, secret: string): string;
    /** 풀지 못하면(열쇠가 다르거나 다른 팩토리의 줄이면) `null` 이다. */
    open(factoryId: string, sealed: string): string | null;
}

export const sealerFromHex = (hex: string): Sealer =>
{
    if (!/^[0-9a-f]{64}$/i.test(hex))
    {
        throw new Error("DASHBOARD_SEAL_KEY 는 32바이트를 hex 64자로 적어야 합니다. `openssl rand -hex 32` 로 만들어 주세요");
    }
    const key = Buffer.from(hex, "hex");
    return {
        seal(factoryId, secret)
        {
            const nonce = randomBytes(12);
            const cipher = createCipheriv("aes-256-gcm", key, nonce);
            cipher.setAAD(Buffer.from(`factory:${factoryId}`));
            const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
            return ["v1", nonce.toString("base64url"), body.toString("base64url"), cipher.getAuthTag().toString("base64url")].join(".");
        },
        open(factoryId, sealed)
        {
            const [version, nonce, body, tag] = sealed.split(".");
            if (version !== "v1" || nonce === undefined || body === undefined || tag === undefined)
            {
                return null;
            }
            try
            {
                const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(nonce, "base64url"));
                decipher.setAAD(Buffer.from(`factory:${factoryId}`));
                decipher.setAuthTag(Buffer.from(tag, "base64url"));
                return Buffer.concat([decipher.update(Buffer.from(body, "base64url")), decipher.final()]).toString("utf8");
            }
            catch
            {
                return null;
            }
        },
    };
};
