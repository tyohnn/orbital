// 팩토리의 서버를 띄운다.
//
//   ORBITAL_URL=… ORBITAL_SERVICE_KEY=sk_test_… npm start
//
// | 환경 변수 | 무엇 |
// |---|---|
// | `ORBITAL_URL` | 레이어(관리 서버)의 주소. 이 서버만 붙는다. 에이전트에게는 알리지 않는다 |
// | `ORBITAL_SERVICE_KEY` | 팩토리의 service key. 이 프로세스 밖으로 나가지 않는다 |
// | `ORBITAL_PUBLIC_URL` | 레이어의 바깥 주소. 비밀 입력 카드가 값을 이리로 바로 보낸다. 기본 `ORBITAL_URL` |
// | `ORBITAL_WEBHOOK_SECRET` | 웹훅의 서명 비밀(`whsec_…`). 있으면 `/webhooks/orbital` 로 받고, 없으면 `events.list` 로 물어본다 |
// | `FACTORY_PORT` | 듣는 포트. 기본 3840 |
// | `FACTORY_PUBLIC_URL` | 플랫폼이 이 서버를 부르는 주소(OAuth 의 issuer, git 원격의 앞). 기본 `http://127.0.0.1:<포트>` |
// | `FACTORY_HOME` | 처리한 이벤트의 자리를 두는 폴더. 기본 `server/.factory` |
// | `FACTORY_POLL_SECONDS` | 물어보는 고리의 간격(초). 기본 5 |
//
// ⚠ service key 와 웹훅의 비밀은 SDK 와 확인 함수에 한 번 건네고 다른 어디에도 두지 않는다. 로그에 환경을 찍지 않는다.
// ⚠ 개발용 연결(`connect.ts`)은 계정 이름을 믿는다. 그래서 `FACTORY_PUBLIC_URL` 이 loopback 이 아니면 뜨지 않는다.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { OrbitalError, createOrbital } from "@harmony/orbital/server";

import { memoryAccounts } from "./accounts.ts";
import { APP, VERSION } from "./brand.ts";
import { createOAuth } from "./connect.ts";
import { createEvents, fileInbox } from "./events.ts";
import { serve } from "./http.ts";
import { createNotifier } from "./notify.ts";
import { bundleScaffold } from "./scaffold.ts";
import { createFactory } from "./tools.ts";
import { createWorks } from "./works.ts";

const here = dirname(fileURLToPath(import.meta.url));
const log = (line: string): void => console.log(line);

function required(name: string, what: string): string
{
    const value = process.env[name] ?? "";
    if (value === "")
    {
        console.error(`[factory] 환경 변수 ${name} 이 없습니다. ${what}을 넣고 다시 띄워 주세요.`);
        process.exit(1);
    }
    return value;
}

const layerUrl = required("ORBITAL_URL", "레이어(관리 서버)의 주소");
const serviceKey = required("ORBITAL_SERVICE_KEY", "레이어의 운영자에게 받은 service key(시험용은 sk_test_ 로 시작합니다)");
const port = Number(process.env.FACTORY_PORT ?? "3840");
const origin = (process.env.FACTORY_PUBLIC_URL ?? "").replace(/\/+$/, "") || `http://127.0.0.1:${port}`;
const home = process.env.FACTORY_HOME ?? join(here, "..", ".factory");

// ✏️ 로그인을 붙였으면(`connect.ts`) 이 검사를 걷는다
const host = new URL(origin).hostname;
if (!["127.0.0.1", "localhost", "[::1]"].includes(host))
{
    console.error(`[factory] FACTORY_PUBLIC_URL(${origin}) 이 바깥 주소입니다. 이 서버의 연결은 계정 이름을 믿는 개발용이라 바깥 주소로는 띄우지 않습니다. server/src/connect.ts 에 로그인을 붙이고 main.ts 의 이 검사를 걷어 주세요.`);
    process.exit(1);
}

const orbital = createOrbital({ url: layerUrl, serviceKey });

// 스캐폴드를 올린다. 레이어가 아직 듣기 전이면 잠깐 되풀이한다
const bundle = bundleScaffold(join(here, "..", "..", "scaffold"), VERSION);
for (let attempt = 0; ; attempt += 1)
{
    try
    {
        await orbital.apps.put(APP, bundle);
        break;
    }
    catch (error)
    {
        if (error instanceof OrbitalError || attempt >= 200)
        {
            const why = error instanceof OrbitalError ? `${error.code} ${error.status}` : "닿지 않음";
            console.error(`[factory] 스캐폴드를 레이어에 올리지 못했습니다(${why}). ORBITAL_URL 과 service key 를 확인해 주세요.`);
            process.exit(1);
        }
        await new Promise((done) => setTimeout(done, 50));
    }
}
log(`[factory] 스캐폴드 ${APP} ${VERSION} 를 올렸습니다`);

const accounts = memoryAccounts();
const works = createWorks(orbital);
const factory = createFactory({ orbital, accounts, works, origin, app: APP, version: VERSION, log });
const secret = process.env.ORBITAL_WEBHOOK_SECRET ?? "";
const events = createEvents({
    list: (input) => orbital.events.list(input),
    inbox: fileInbox(home),
    handle: createNotifier({ accounts, log }),
    secret,
    log,
});
const layerOrigin = new URL(process.env.ORBITAL_PUBLIC_URL ?? layerUrl).origin;
const server = serve({ factory, oauth: createOAuth(origin), works, events, layerOrigin }, origin);
// 웹훅의 비밀이 없으면(로컬) 레이어에 물어본다. 같은 처리기를 부른다
const stopPolling = secret === ""
    ? events.startPolling(Number(process.env.FACTORY_POLL_SECONDS ?? "5") * 1000)
    : () => undefined;
server.listen(port, "127.0.0.1", () =>
{
    log(`[factory] ${origin}/mcp`);
    log(secret === "" ? "[factory] 이벤트는 레이어에 물어봅니다(웹훅의 비밀이 없습니다)" : `[factory] 웹훅을 ${origin}/webhooks/orbital 에서 받습니다`);
});

const stop = (): void =>
{
    stopPolling();
    server.close();
    server.closeAllConnections();
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
