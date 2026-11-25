// 팩토리 서버를 띄운다.
//
//   ORBITAL_URL=… ORBITAL_SERVICE_KEY=… node examples/factory-todo/src/main.ts
//
// | 환경 변수 | 무엇 |
// |---|---|
// | `ORBITAL_URL` | 레이어(`orbitald`)의 주소. 에이전트도 이 주소로 붙는다 |
// | `ORBITAL_SERVICE_KEY` | 팩토리의 service key. 이 프로세스 밖으로 나가지 않는다 |
// | `ORBITAL_PUBLIC_URL` | 레이어의 바깥 주소(레이어의 `ORBITAL_PUBLIC_URL` 과 같은 것). 비밀 입력 카드가 값을 이리로 바로 보낸다. 기본 `ORBITAL_URL` |
// | `FACTORY_PORT` | 듣는 포트. 기본 3840 |
// | `FACTORY_PUBLIC_URL` | 플랫폼이 이 서버를 부르는 주소(OAuth 의 issuer 와 resource). 기본 `http://127.0.0.1:<포트>` |
// | `FACTORY_HOME` | 고객과 인스턴스의 짝을 두는 폴더. 기본 `examples/factory-todo/.factory` |
//
// ⚠ service key 는 SDK 를 만들 때 한 번 건네고 다른 어디에도 두지 않는다. 로그에 환경을 찍지 않는다.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { OrbitalError, createOrbital } from "@harmony/orbital/server";

import { openCustomers } from "./customers.ts";
import { createOAuth } from "./oauth.ts";
import { bundleScaffold } from "./scaffold.ts";
import { serve } from "./server.ts";
import { createFactory } from "./tools.ts";

const APP = "todo";
const VERSION = "v1";
const here = dirname(fileURLToPath(import.meta.url));

function required(name: string): string
{
    const value = process.env[name] ?? "";
    if (value === "")
    {
        console.error(`[factory-todo] 환경 변수 ${name} 이 없습니다. 레이어의 주소와 팩토리의 service key 를 넣고 다시 띄워 주세요.`);
        process.exit(1);
    }
    return value;
}

const layerUrl = required("ORBITAL_URL");
const orbital = createOrbital({ url: layerUrl, serviceKey: required("ORBITAL_SERVICE_KEY") });
const port = Number(process.env.FACTORY_PORT ?? "3840");
const origin = (process.env.FACTORY_PUBLIC_URL ?? "").replace(/\/+$/, "") || `http://127.0.0.1:${port}`;
const home = process.env.FACTORY_HOME ?? join(here, "..", ".factory");
const log = (line: string): void => console.log(line);

// 스캐폴드를 올린다. 레이어가 아직 듣기 전이면 잠깐 되풀이한다
const bundle = bundleScaffold(join(here, "..", "scaffold"), VERSION);
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
            console.error(`[factory-todo] 스캐폴드를 레이어에 올리지 못했습니다(${why}). ORBITAL_URL 과 service key 를 확인해 주세요.`);
            process.exit(1);
        }
        await new Promise((done) => setTimeout(done, 50));
    }
}
log(`[factory-todo] 스캐폴드 ${APP} ${VERSION} 를 올렸습니다`);

const factory = createFactory({ orbital, layerUrl, customers: openCustomers(home), app: APP, version: VERSION, log });
const layerOrigin = new URL(process.env.ORBITAL_PUBLIC_URL ?? layerUrl).origin;
const server = serve({ factory, oauth: createOAuth(origin), layerOrigin }, origin);
server.listen(port, "127.0.0.1", () => log(`[factory-todo] ${origin}/mcp`));

const stop = (): void =>
{
    server.close();
    server.closeAllConnections();
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
