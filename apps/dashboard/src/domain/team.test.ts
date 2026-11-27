import { describe, expect, it } from "vitest";

import type { Member, Role } from "./team.ts";
import { ROLES, isEmail, isFactoryName, judgeTeamChange } from "./team.ts";

const member = (accountId: string, role: Role): Member => ({ accountId, email: `${accountId}@x.example`, role });

describe("팀의 판정", () =>
{
    it("어떤 팀과 어떤 바꾸기든 허락된 바꾸기 뒤에는 주인이 한 사람 이상 남는다", () =>
    {
        // 셋까지의 팀을 모두 늘어놓고, 모든 (하는 이, 대상, 새 역할 또는 빼기)를 해 본다. 기대값은 바꾼 뒤의 주인 수를 직접 센다
        const ids = ["a", "b", "c"];
        const teams: Member[][] = [];
        for (const size of [1, 2, 3])
        {
            const combos = (n: number): Role[][] => (n === 0 ? [[]] : combos(n - 1).flatMap((rest) => ROLES.map((role) => [...rest, role])));
            for (const roles of combos(size))
            {
                teams.push(roles.map((role, index) => member(ids[index] ?? "z", role)));
            }
        }
        for (const team of teams.filter((one) => one.some((m) => m.role === "owner")))
        {
            for (const actor of team)
            {
                for (const target of team)
                {
                    for (const next of [...ROLES, null])
                    {
                        const verdict = judgeTeamChange(team, actor.accountId, target.accountId, next);
                        const after = team
                            .map((m) => (m.accountId === target.accountId ? (next === null ? null : { ...m, role: next }) : m))
                            .filter((m): m is Member => m !== null);
                        const owners = after.filter((m) => m.role === "owner").length;
                        const leaving = actor.accountId === target.accountId && next === null;
                        const expected = !leaving && actor.role !== "owner" ? "not_allowed" : owners === 0 ? "last_owner" : "ok";
                        expect(verdict.ok ? "ok" : verdict.reason).toBe(expected);
                    }
                }
            }
        }
    });

    it("팀에 없는 사람이 하거나 팀에 없는 사람을 대상으로 하면 없는 것으로 답한다", () =>
    {
        const team = [member("a", "owner")];
        expect(judgeTeamChange(team, "x", "a", "member")).toEqual({ ok: false, reason: "not_found" });
        expect(judgeTeamChange(team, "a", "x", null)).toEqual({ ok: false, reason: "not_found" });
    });

    it("팩토리 이름은 관리 서버의 조직 이름과 같은 규칙이다", () =>
    {
        for (const good of ["acme", "0-factory_co", "a".repeat(64)])
        {
            expect(isFactoryName(good)).toBe(true);
        }
        for (const bad of ["", "-acme", "_acme", "Acme", "ac me", "a".repeat(65), "아크미"])
        {
            expect(isFactoryName(bad)).toBe(false);
        }
    });

    it("이메일은 앞뒤 공백과 대소문자를 무시하고 모양만 본다", () =>
    {
        expect(isEmail(" Ana@Factory.Example ")).toBe(true);
        expect(isEmail("not an email")).toBe(false);
        expect(isEmail("a@b")).toBe(false);
    });
});
