// 팩토리의 운영자가 터미널에서 부르는 스크립트. 함대 · 이력 · 서비스의 상태 · 운영의 로그를 읽고, service key 와 웹훅을 다룬다.
//
//   npm run operator -- fleet                     함대(이 조직의 인스턴스)
//   npm run operator -- history <인스턴스>         release 의 이력(누가 승인했는지 포함)
//   npm run operator -- services <인스턴스>        운영의 서비스마다 깨어 있는지 · 자는지
//   npm run operator -- logs <인스턴스> [줄]       운영의 로그의 끝
//   npm run operator -- destroy <인스턴스>         인스턴스를 걷는다(되돌릴 수 없다)
//   npm run operator -- keys                      service key 의 목록(비밀 없이)
//   npm run operator -- key-create [이름표]        키를 하나 더 낸다. 비밀은 이때 한 번만 찍힌다
//   npm run operator -- key-revoke <id>           키를 폐기한다
//   npm run operator -- webhook <https 주소>       웹훅을 건다. 서명 비밀은 이때 한 번만 찍힌다
//
// ⚠ **운영의 로그는 여기서만 읽는다.** 앱이 찍은 글이라 고객의 데이터가 섞일 수 있다. 에이전트의 도구로 돌려주지 않는다.
// ⚠ 키와 웹훅의 비밀은 낼 때 한 번 찍힌다. 터미널의 기록에 남기지 말고 팩토리의 비밀 저장소로 옮긴다.
import { createOrbital } from "@harmony/orbital/server";

const url = process.env.ORBITAL_URL ?? "";
const serviceKey = process.env.ORBITAL_SERVICE_KEY ?? "";
if (url === "" || serviceKey === "")
{
    console.error("ORBITAL_URL 과 ORBITAL_SERVICE_KEY 를 넣고 다시 불러 주세요.");
    process.exit(1);
}
const orbital = createOrbital({ url, serviceKey });
const [command, first, second] = process.argv.slice(2);
const when = (at: number | null): string => (at === null ? "-" : new Date(at * 1000).toISOString());

function needs(value: string | undefined, what: string): string
{
    if (value === undefined || value === "")
    {
        console.error(`${what}을 적어 주세요. 예: npm run operator -- ${command ?? ""} <${what}>`);
        process.exit(1);
    }
    return value;
}

switch (command)
{
    case "fleet":
    {
        let after: string | undefined;
        for (;;)
        {
            const page = await orbital.instances.list(after === undefined ? {} : { after });
            for (const row of page.instances)
            {
                const live = row.production === null ? "운영 없음" : `운영 ${row.production.release.slice(0, 16)}`;
                console.log(`${row.id}  ${row.app}@${row.version ?? "-"}  ${live}  요청 ${row.promotionRequested === null ? "-" : row.promotionRequested.slice(0, 16)}  만든 때 ${when(row.createdAt)}`);
            }
            if (!page.hasMore || page.next === null)
            {
                break;
            }
            after = page.next;
        }
        const organization = await orbital.organization.get();
        console.log(`인스턴스 ${organization.instances}개${organization.instanceLimit === null ? "" : ` / 상한 ${organization.instanceLimit}`}`);
        break;
    }
    case "history":
    {
        const page = await orbital.instances.history(needs(first, "인스턴스"));
        for (const entry of page.history)
        {
            const who = "approver" in entry ? ` 승인 ${entry.approvedBy}${entry.approver === null ? "" : `(${entry.approver})`}` : "";
            console.log(`#${entry.n} ${when(entry.at)} ${entry.kind} ${entry.release.slice(0, 16)}${who}`);
        }
        break;
    }
    case "services":
    {
        const answer = await orbital.production.services(needs(first, "인스턴스"));
        console.log(`운영 ${answer.release}`);
        for (const service of answer.services)
        {
            console.log(`  ${service.name}  ${service.kind}  ${service.state}`);
        }
        break;
    }
    case "logs":
    {
        const answer = await orbital.production.logs(needs(first, "인스턴스"), second === undefined ? {} : { lines: Number(second) });
        for (const log of answer.logs)
        {
            console.log(`== ${log.name}\n${log.text}`);
        }
        if (!answer.serverLogs)
        {
            console.log("(서버의 로그는 레이어의 운영자가 켜지 않아 빌드의 로그만 왔습니다)");
        }
        break;
    }
    case "destroy":
        await orbital.instances.destroy(needs(first, "인스턴스"));
        console.log("걷었습니다");
        break;
    case "keys":
        for (const key of await orbital.keys.list())
        {
            console.log(`${key.id}  ${key.label}  만든 때 ${when(key.createdAt)}  폐기한 때 ${when(key.revokedAt)}  마지막으로 쓴 때 ${when(key.usedAt)}`);
        }
        break;
    case "key-create":
    {
        const issued = await orbital.keys.create(first === undefined ? {} : { label: first });
        console.log(`새 키 ${issued.id}: ${issued.secret}`);
        console.log("비밀은 다시 받을 수 없습니다. 팩토리의 비밀 저장소에 옮기고 서버를 이 키로 다시 띄운 뒤 옛 키를 폐기해 주세요.");
        break;
    }
    case "key-revoke":
        await orbital.keys.revoke(needs(first, "id"));
        console.log("폐기했습니다");
        break;
    case "webhook":
    {
        const set = await orbital.webhook.set({ url: needs(first, "https 주소") });
        console.log(`웹훅을 ${set.webhook.url} 에 걸었습니다. 서명 비밀: ${set.secret}`);
        console.log("비밀은 다시 받을 수 없습니다. 서버의 ORBITAL_WEBHOOK_SECRET 에 넣고 다시 띄워 주세요.");
        break;
    }
    default:
        console.error("명령을 적어 주세요: fleet · history · services · logs · destroy · keys · key-create · key-revoke · webhook (src/operator.ts 의 머리말)");
        process.exit(1);
}
