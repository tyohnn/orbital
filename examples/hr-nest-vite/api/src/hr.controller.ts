import { Controller, ForbiddenException, Get, Headers, HttpCode, Post, UnauthorizedException } from "@nestjs/common";

import { Db, ROLES, Role } from "./db";

interface Me
{
    id: string;
    roles: Role[];
}

/** 가장 넓게 보는 업무 역할. 급여 관리자 → 팀장 → 직원의 차례다. 어느 행이 보이는지는 DB 의 행 단위 규칙이 정한다. */
function widest(roles: Role[]): Role | null
{
    for (const role of ["payroll_admin", "manager", "employee"] as const)
    {
        if (roles.includes(role))
        {
            return role;
        }
    }
    return null;
}

@Controller()
export class HrController
{
    constructor(private readonly db: Db)
    {
    }

    private identity(value: string | undefined): string
    {
        if (value === undefined || value === "")
        {
            throw new UnauthorizedException();
        }
        return value;
    }

    /** 신원의 사람과 업무 역할. 업무 역할이면 누구나 `orbital.me` 를 읽는다. */
    private async me(identity: string): Promise<Me>
    {
        for (const role of ROLES)
        {
            const rows = await this.db.query<{ id: string; roles: string[] }>(role, identity, "SELECT id, roles FROM orbital.me");
            if (rows.length > 0)
            {
                const roles = rows[0].roles.filter((name): name is Role => (ROLES as readonly string[]).includes(name));
                return { id: rows[0].id, roles };
            }
        }
        throw new UnauthorizedException();
    }

    @Get("health")
    health(): { ok: boolean }
    {
        return { ok: true };
    }

    @Get("me")
    async whoami(@Headers("x-orbital-identity") header?: string): Promise<Me>
    {
        return this.me(this.identity(header));
    }

    @Get("payslips")
    async payslips(@Headers("x-orbital-identity") header?: string): Promise<{ as: Role; payslips: unknown[] }>
    {
        const identity = this.identity(header);
        const role = widest((await this.me(identity)).roles);
        if (role === null)
        {
            throw new UnauthorizedException();
        }
        const payslips = await this.db.query(
            role,
            identity,
            "SELECT employee, month, amount FROM payroll.payslip ORDER BY employee, month",
        );
        return { as: role, payslips };
    }

    /**
     * 선언의 `[[schedule]]` 이 부르는 자리. 레이어가 router 를 거쳐 부르고 `x-orbital-schedule` 을 싣는다.
     * 밖에서 온 `x-orbital-` 머리말은 router 가 언제나 지우고 이 경로는 밖에서 닿지 못하므로, 그 머리말이 있으면 레이어가 부른 것이다.
     *
     * 일정에 `role = "payroll_admin"` 을 적었으므로 레이어가 사람 없이 그 역할만 실린 신원(`x-orbital-identity`)을 함께 싣는다.
     * 그 신원으로 급여 관리자의 연결에 붙어 이달의 명세가 없는 사람마다 하나씩 만든다(금액은 그 사람의 마지막 명세를 따른다).
     * 신원이 없으면 역할 제한 정책이 한 행도 내주지 않는다. 은행 키의 값은 돌려주지 않고 있는지만 답한다.
     */
    @Post("jobs/payroll")
    @HttpCode(200)
    async payroll(
        @Headers("x-orbital-schedule") schedule?: string,
        @Headers("x-orbital-identity") identity?: string,
    ): Promise<{ ran: boolean; bank: "set" | "missing"; people: number; created: number }>
    {
        if (schedule === undefined || schedule === "")
        {
            throw new ForbiddenException();
        }
        const signed = identity ?? "";
        const month = new Date().toISOString().slice(0, 7);
        const people = await this.db.query<{ count: string }>("payroll_admin", signed, "SELECT count(*) FROM hr.person");
        const created = await this.db.query(
            "payroll_admin",
            signed,
            `INSERT INTO payroll.payslip (employee, month, amount)
             SELECT p.id, $1, coalesce((SELECT s.amount FROM payroll.payslip s WHERE s.employee = p.id ORDER BY s.month DESC LIMIT 1), 0)
             FROM hr.person p
             WHERE NOT EXISTS (SELECT 1 FROM payroll.payslip s WHERE s.employee = p.id AND s.month = $1)
             RETURNING employee`,
            [month],
        );
        return {
            ran: true,
            bank: process.env.BANK_API_KEY ? "set" : "missing",
            people: Number(people[0]?.count ?? 0),
            created: created.length,
        };
    }
}
