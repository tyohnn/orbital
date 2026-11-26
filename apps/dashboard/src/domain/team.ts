// 팩토리의 팀원과 역할의 판정. 순수 함수만 둔다(파일 · 네트워크 · 시계에 닿지 않는다).
//
// 대시보드의 계정은 Orbital 의 것이다. 팩토리 제작자 한 사람이 팩토리 여럿에 속할 수 있고, 팩토리마다 역할이 하나다.
// 관리 서버(`orbitald`)는 「이 열쇠가 어느 조직의 것인가」만 알고, 누가 키를 다룰 수 있는지는 여기서 정한다.

/** 주인 · 관리자 · 멤버. 주인만 팀원을 다루고, 키는 주인과 관리자가 다룬다. */
export type Role = "owner" | "admin" | "member";

export const ROLES: readonly Role[] = ["owner", "admin", "member"];

export interface Member
{
    readonly accountId: string;
    readonly email: string;
    readonly role: Role;
}

/** 키를 만들고 폐기할 수 있는가. 멤버는 목록만 본다. */
export const canManageKeys = (role: Role): boolean => role === "owner" || role === "admin";

/** 팀원을 초대하고 역할을 바꾸고 뺄 수 있는가. */
export const canManageTeam = (role: Role): boolean => role === "owner";

export type TeamChangeRefusal =
    | { readonly reason: "not_allowed" }
    | { readonly reason: "not_found" }
    | { readonly reason: "last_owner" };

export type TeamChange = { readonly ok: true } | ({ readonly ok: false } & TeamChangeRefusal);

const ownersAfter = (members: readonly Member[], accountId: string, role: Role | null): number =>
    members.filter((member) => (member.accountId === accountId ? role === "owner" : member.role === "owner")).length;

/**
 * `actor` 가 `target` 의 역할을 `role` 로 바꾸거나(`role`), 팀에서 빼도(`null`) 되는가.
 * 팩토리에는 주인이 언제나 한 사람은 남는다. 자기 자신을 빼는 것(나가기)은 주인이 아니어도 된다.
 */
export const judgeTeamChange = (
    members: readonly Member[],
    actor: string,
    target: string,
    role: Role | null,
): TeamChange =>
{
    const self = members.find((member) => member.accountId === actor);
    const other = members.find((member) => member.accountId === target);
    if (self === undefined || other === undefined)
    {
        return { ok: false, reason: "not_found" };
    }
    const leaving = actor === target && role === null;
    if (!leaving && !canManageTeam(self.role))
    {
        return { ok: false, reason: "not_allowed" };
    }
    if (ownersAfter(members, target, role) === 0)
    {
        return { ok: false, reason: "last_owner" };
    }
    return { ok: true };
};

/** 이메일을 견주는 모양. 대소문자와 앞뒤 공백을 무시한다. */
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const isEmail = (email: string): boolean => EMAIL.test(normalizeEmail(email)) && email.length <= 320;

/**
 * 팩토리 이름(관리 서버의 조직 이름). Orbital core 의 `organization_name` 과 같은 규칙이다:
 * 소문자 · 숫자로 시작하고 소문자 · 숫자 · `-` · `_` 로 64글자까지.
 */
export const isFactoryName = (name: string): boolean => /^[a-z0-9][a-z0-9_-]{0,63}$/.test(name);
