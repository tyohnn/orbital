import { Shell } from "../_components/Shell";
import { signedIn } from "../_components/session";
import { NewFactoryForm } from "./NewFactoryForm";

export default async function NewFactoryPage()
{
    const { account, memberships } = await signedIn();
    return (
        <Shell email={account.email} memberships={memberships}>
            <h1 className="text-xl font-semibold">새 팩토리</h1>
            <p className="mt-1 text-sm text-neutral-500">팩토리를 만들면 첫 API 키를 드려요. 팩토리 서버의 환경 변수에 넣어 쓰세요.</p>
            <NewFactoryForm />
        </Shell>
    );
}
