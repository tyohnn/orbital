import { describe, expect, it } from "vitest";

import { sealerFromHex } from "./seal.ts";

const KEY = "11".repeat(32);

describe("봉인", () =>
{
    it("봉인한 글은 같은 열쇠와 같은 팩토리에서만 풀린다", () =>
    {
        const sealer = sealerFromHex(KEY);
        const sealed = sealer.seal("acme", "orb_sk_secret");
        expect(sealed).not.toContain("orb_sk_secret");
        expect(sealer.open("acme", sealed)).toBe("orb_sk_secret");
        expect(sealer.open("globex", sealed)).toBeNull();
        expect(sealerFromHex("22".repeat(32)).open("acme", sealed)).toBeNull();
        expect(sealer.open("acme", "v1.broken")).toBeNull();
    });

    it("열쇠는 32바이트의 hex 여야 한다", () =>
    {
        expect(() => sealerFromHex("short")).toThrow(/hex 64자/);
    });
});
