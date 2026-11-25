// DB 에는 비밀번호 없이 붙는다. 주소(PGHOST · PGPORT)는 레이어가 건네고, 사용자 자리에 업무 역할의 이름을 적는다.
// 신원은 router 가 요청에 실어 준 서명된 머리말이다. 앱은 풀거나 믿지 않고 그대로 DB 에 넘겨 행 단위 규칙이 가르게 한다.
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import pg from "pg";

export const ROLES = ["employee", "manager", "payroll_admin"] as const;
export type Role = (typeof ROLES)[number];

@Injectable()
export class Db implements OnModuleDestroy
{
    private readonly pools = new Map<Role, pg.Pool>();

    private pool(role: Role): pg.Pool
    {
        let pool = this.pools.get(role);
        if (pool === undefined)
        {
            pool = new pg.Pool({
                host: process.env.PGHOST,
                port: Number(process.env.PGPORT),
                database: process.env.PGDATABASE ?? "app",
                user: role,
                max: 3,
            });
            this.pools.set(role, pool);
        }
        return pool;
    }

    /** 업무 역할 `role` 로 붙어 신원을 건넨 채로 질의 하나를 돌린다. */
    async query<T extends pg.QueryResultRow>(role: Role, identity: string, sql: string, values: unknown[] = []): Promise<T[]>
    {
        const client = await this.pool(role).connect();
        try
        {
            await client.query("BEGIN");
            await client.query("SELECT set_config('orbital.identity', $1, true)", [identity]);
            const result = await client.query<T>(sql, values);
            await client.query("COMMIT");
            return result.rows;
        }
        catch (error)
        {
            await client.query("ROLLBACK").catch(() => undefined);
            throw error;
        }
        finally
        {
            client.release();
        }
    }

    async onModuleDestroy(): Promise<void>
    {
        await Promise.all([...this.pools.values()].map((pool) => pool.end()));
    }
}
