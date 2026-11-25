// 밖에서 넣는 비밀을 팩토리의 서버가 SDK 로 다루고, 사람의 브라우저가 입력 표로 레이어에 바로 값을 보낸다. 실제 `orbitald` 에 실제 HTTP 로 붙는다.
//
// `ORBITAL_PG` 가 없으면 건너뛰었다고 찍고 통과한다. 실행 파일은 `cargo build` 가 만든 것을 쓴다(`npm run test:sdk` 가 먼저 빌드한다).

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";

import { OrbitalError, createOrbital } from "../src/server.ts";
import type { Orbital, Work } from "../src/server.ts";

const root = resolve(import.meta.dirname, "../../..");
const bin = (name: string): string => join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "debug", name);
const pg = process.env.ORBITAL_PG;
const skip = pg === undefined ? "ORBITAL_PG 가 없어 건너뜁니다. scripts/pg-local.sh 로 띄워 주세요" : false;

const FACTORY = "sk_test_factory";
/** 어디에 새어도 찾을 수 있게 드문 글자로 지은 값 */
const BANK = "sk_live_bank_sdk_P4mQ8zXr";
const BANK_PREVIEW = "sk_test_bank_sdk_Lw2Nc7Vt";

let scratch = "";
let url = "";
let server: ChildProcess | undefined;
/** SDK 가 받은 답의 날것 */
const received: string[] = [];
let orbital: Orbital;
const instances: string[] = [];

function git(folder: string, ...args: string[]): string
{
    return execFileSync(
        "git",
        ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid", "-c", "commit.gpgsign=false", ...args],
        { cwd: folder, encoding: "utf8" },
    ).trim();
}

async function freePort(): Promise<number>
{
    const probe = createServer();
    await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((done) => probe.close(() => done()));
    return port;
}

const sha = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

async function rejection(work: Promise<unknown>): Promise<OrbitalError>
{
    const caught: unknown = await work.then(
        () => undefined,
        (error: unknown) => error,
    );
    assert.ok(caught instanceof OrbitalError, "OrbitalError 로 거절되어야 합니다");
    return caught;
}

before(async () =>
{
    if (pg === undefined)
    {
        return;
    }
    scratch = mkdtempSync(join(tmpdir(), "orbital-sdk-secrets-"));
    const listen = `127.0.0.1:${await freePort()}`;
    url = `http://${listen}`;
    server = spawn(bin("orbitald"), [], {
        stdio: "ignore",
        env: {
            PATH: process.env.PATH ?? "",
            ORBITAL_HOME: join(scratch, "home"),
            ORBITAL_PG: pg,
            ORBITAL_SERVICE_KEYS: `factory=${FACTORY}`,
            // 비밀을 봉인하는 열쇠. 테스트에만 쓰는 값이다
            ORBITAL_SEAL_KEY: "07".repeat(32),
            // 입력 표의 주소가 이 아래에 선다. 사람의 브라우저가 바로 닿는 주소다
            ORBITAL_PUBLIC_URL: url,
            ORBITAL_LISTEN: listen,
        },
    });
    orbital = createOrbital({
        url,
        serviceKey: FACTORY,
        fetch: async (input, init) =>
        {
            const response = await fetch(input, init);
            received.push(await response.clone().text());
            return response;
        },
    });

    const scaffold = join(scratch, "scaffold");
    cpSync(join(root, "crates/orbital-server/tests/fixtures/vault"), scaffold, { recursive: true });
    git(scaffold, "init", "--quiet", "--initial-branch", "main");
    git(scaffold, "add", "-A");
    git(scaffold, "commit", "--quiet", "-m", "스캐폴드 v1");
    git(scaffold, "tag", "v1");
    git(scaffold, "bundle", "create", "--quiet", join(scratch, "scaffold.bundle"), "--all");
    const bundle = readFileSync(join(scratch, "scaffold.bundle"));
    for (let attempt = 0; ; attempt += 1)
    {
        try
        {
            await orbital.apps.put("vault", bundle);
            break;
        }
        catch (error)
        {
            if (error instanceof OrbitalError || attempt > 100)
            {
                throw error;
            }
            await new Promise((done) => setTimeout(done, 50));
        }
    }
});

after(async () =>
{
    for (const instance of instances)
    {
        await orbital.instances.destroy(instance).catch(() => undefined);
    }
    server?.kill();
    if (scratch !== "")
    {
        rmSync(scratch, { recursive: true, force: true });
    }
});

/** 인스턴스를 세우고 작업을 열어 프리뷰를 세운다. (인스턴스, 작업, 프리뷰의 release) */
async function previewed(): Promise<{ instance: string; work: Work; release: string }>
{
    const { id: instance } = await orbital.instances.create({ app: "vault", from: "v1" });
    instances.push(instance);
    const work = await orbital.works.open({ instance, can: ["source", "preview", "rehearse", "secrets_request"] });
    const preview = await work.preview();
    // 프리뷰의 값이 없어 환경 변수 없이 섰다. 사람에게 입력을 요청할 이름이다
    assert.deepEqual(preview.missingSecrets, ["BANK_API_KEY"]);
    return { instance, work, release: preview.release };
}

test("비밀을 요청하고 사람이 입력 표로 넣으면 운영에 오른다", { skip }, async () =>
{
    const { instance, work, release } = await previewed();

    // 에이전트의 요청을 팩토리의 서버가 작업으로 적는다. 아직 값이 없어 승격 요청이 거절된다
    await work.secrets.request("BANK_API_KEY", { reason: "송금 기능이 은행 API 를 부릅니다" });
    assert.deepEqual((await work.secrets.list()).map((secret) => secret.name), ["BANK_API_KEY"]);
    const [asked] = await orbital.secrets.list(instance);
    assert.equal(asked?.name, "BANK_API_KEY");
    assert.equal(asked?.declared, true);
    assert.equal(asked?.requested?.reason, "송금 기능이 은행 API 를 부릅니다");
    assert.deepEqual([asked?.preview, asked?.production], [{ set: false, setAt: null }, { set: false, setAt: null }]);
    const blocked = await rejection(work.requestPromotion(release));
    assert.match([blocked.message, ...blocked.details].join("\n"), /BANK_API_KEY/);
    // 선언하지 않은 이름은 무엇을 고칠지와 함께 거절된다
    const undeclared = await rejection(orbital.secrets.request(instance, "MAP_KEY", { reason: "지도" }));
    assert.deepEqual([undeclared.status, undeclared.code], [422, "problems"]);
    assert.match(undeclared.details.join("\n"), /\[secrets\] external/);

    // 사람의 브라우저(카드)가 입력 표의 주소로 레이어에 바로 보낸다. 팩토리의 서버를 지나지 않는다
    const entry = await orbital.secrets.entry(instance, "BANK_API_KEY", { stage: "production" });
    assert.ok(entry.url.startsWith(`${url}/v1/secret-entries/`), entry.url);
    assert.ok(entry.expiresAt > Date.now() / 1000 + 590);
    const sent = await fetch(entry.url, {
        method: "POST",
        headers: { origin: "https://factory-card.example", "content-type": "application/json" },
        body: JSON.stringify({ value: BANK }),
    });
    assert.equal(sent.status, 200);
    assert.equal(sent.headers.get("access-control-allow-origin"), "*");
    const [filled] = await orbital.secrets.list(instance);
    assert.equal(filled?.production.set, true);
    assert.equal(typeof filled?.production.setAt, "number");
    assert.equal(filled?.preview.set, false);

    // 승인 화면은 새로 받게 되는 비밀의 이름을 보인다
    await work.requestPromotion(release);
    const pending = await orbital.releases.pending(instance);
    assert.deepEqual(pending?.newSecrets, ["BANK_API_KEY"]);
    const production = await orbital.releases.promote({ instance, release, change: "customer_request", approvedBy: "customer" });
    const live = production.services[0]?.url ?? "";
    const secret = (await (await fetch(`${live}/secret`)).json()) as { present: boolean; sha256: string | null };
    assert.deepEqual(secret, { present: true, sha256: sha(BANK) });
});

test("비밀의 값은 SDK 의 어떤 답에도 돌아오지 않는다", { skip }, async () =>
{
    const { instance, work, release } = await previewed();
    const errors: OrbitalError[] = [];

    await orbital.secrets.set(instance, "BANK_API_KEY", { stage: "preview", value: BANK_PREVIEW });
    await orbital.secrets.set(instance, "BANK_API_KEY", { stage: "production", value: BANK });
    // 틀린 값과 모르는 이름의 오류에도 값이 실리지 않는다
    errors.push(await rejection(orbital.secrets.set(instance, "BANK_API_KEY", { stage: "production", value: `${BANK}\u0000` })));
    errors.push(await rejection(orbital.secrets.set(instance, "MAP_KEY", { stage: "production", value: BANK })));
    errors.push(await rejection(orbital.secrets.set(instance, "BANK_API_KEY", { stage: "staging" as "preview", value: BANK })));
    const listed = await orbital.secrets.list(instance);
    assert.deepEqual(listed.map((secret) => [secret.name, secret.preview.set, secret.production.set]), [["BANK_API_KEY", true, true]]);

    await work.requestPromotion(release);
    await orbital.releases.pending(instance);
    const production = await orbital.releases.promote({ instance, release, change: "customer_request", approvedBy: "customer" });
    await orbital.production.get(instance);
    // 운영이 쓰는 값은 지우지 못하고, 프리뷰의 값은 지운다
    const refused = await rejection(orbital.secrets.remove(instance, "BANK_API_KEY", { stage: "production" }));
    assert.deepEqual([refused.status, refused.code], [409, "conflict"]);
    errors.push(refused);
    await orbital.secrets.remove(instance, "BANK_API_KEY", { stage: "preview" });
    await orbital.secrets.list(instance);
    const live = production.services[0]?.url ?? "";
    assert.equal(((await (await fetch(`${live}/secret`)).json()) as { sha256: string }).sha256, sha(BANK));

    assert.ok(received.length > 10, "모은 답이 있어야 합니다");
    const everything = [...received, ...errors.map((error) => `${error.message}\n${error.details.join("\n")}`)].join("\n");
    for (const value of [BANK, BANK_PREVIEW])
    {
        assert.ok(!everything.includes(value), `\`${value}\` 가 새었습니다`);
        assert.ok(!everything.includes(Buffer.from(value).toString("hex")));
    }
});
