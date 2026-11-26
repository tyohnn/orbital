// Postgres 구현. 대시보드의 서버만 붙고(`DASHBOARD_DATABASE_URL`), 표는 `supabase/migrations` 가 세운다.

import pg from "pg";

import type { Member, Role } from "../domain/team.ts";
import { ROLES, normalizeEmail } from "../domain/team.ts";
import type { Account, Factory, Invitation, Membership, Store } from "./store.ts";

const role = (value: unknown): Role =>
{
    const found = ROLES.find((one) => one === value);
    if (found === undefined)
    {
        throw new Error(`알 수 없는 역할입니다: ${String(value)}`);
    }
    return found;
};

const text = (value: unknown): string => (typeof value === "string" ? value : String(value));

export class PgStore implements Store
{
    constructor(private readonly pool: pg.Pool)
    {
    }

    static connect(url: string): PgStore
    {
        return new PgStore(new pg.Pool({ connectionString: url, max: 5 }));
    }

    async close(): Promise<void>
    {
        await this.pool.end();
    }

    async createFactory(factory: Factory, owner: Account): Promise<boolean>
    {
        const client = await this.pool.connect();
        try
        {
            await client.query("begin");
            const inserted = await client.query(
                `insert into dashboard.factory (id, label, dashboard_key_id, sealed_key) values ($1, $2, $3, $4)
                 on conflict (id) do nothing`,
                [factory.id, factory.label, factory.dashboardKeyId, factory.sealedKey],
            );
            if (inserted.rowCount !== 1)
            {
                await client.query("rollback");
                return false;
            }
            await client.query(
                "insert into dashboard.member (factory_id, account_id, email, role) values ($1, $2, $3, 'owner')",
                [factory.id, owner.id, normalizeEmail(owner.email)],
            );
            await client.query("commit");
            return true;
        }
        catch (error)
        {
            await client.query("rollback");
            throw error;
        }
        finally
        {
            client.release();
        }
    }

    async factory(id: string): Promise<Factory | null>
    {
        const { rows } = await this.pool.query(
            "select id, label, dashboard_key_id, sealed_key from dashboard.factory where id = $1",
            [id],
        );
        const row: Record<string, unknown> | undefined = rows[0];
        return row === undefined
            ? null
            : { id: text(row.id), label: text(row.label), dashboardKeyId: text(row.dashboard_key_id), sealedKey: text(row.sealed_key) };
    }

    async members(factoryId: string): Promise<Member[]>
    {
        const { rows } = await this.pool.query(
            "select account_id, email, role from dashboard.member where factory_id = $1 order by created_at, account_id",
            [factoryId],
        );
        return rows.map((row: Record<string, unknown>) => ({ accountId: text(row.account_id), email: text(row.email), role: role(row.role) }));
    }

    async memberships(accountId: string): Promise<Membership[]>
    {
        const { rows } = await this.pool.query(
            `select f.id, f.label, m.role from dashboard.member m join dashboard.factory f on f.id = m.factory_id
             where m.account_id = $1 order by f.created_at, f.id`,
            [accountId],
        );
        return rows.map((row: Record<string, unknown>) => ({ factoryId: text(row.id), label: text(row.label), role: role(row.role) }));
    }

    async invite(factoryId: string, email: string, invited: Role): Promise<void>
    {
        await this.pool.query(
            `insert into dashboard.invitation (factory_id, email, role)
             select $1, $2, $3 where not exists (select 1 from dashboard.member where factory_id = $1 and email = $2)
             on conflict (factory_id, email) do update set role = excluded.role`,
            [factoryId, normalizeEmail(email), invited],
        );
    }

    async invitations(factoryId: string): Promise<Invitation[]>
    {
        const { rows } = await this.pool.query(
            "select email, role from dashboard.invitation where factory_id = $1 order by created_at, email",
            [factoryId],
        );
        return rows.map((row: Record<string, unknown>) => ({ email: text(row.email), role: role(row.role) }));
    }

    async acceptInvitations(account: Account): Promise<number>
    {
        const { rowCount } = await this.pool.query(
            `with taken as (delete from dashboard.invitation where email = $2 returning factory_id, role)
             insert into dashboard.member (factory_id, account_id, email, role)
             select factory_id, $1, $2, role from taken
             on conflict (factory_id, account_id) do nothing`,
            [account.id, normalizeEmail(account.email)],
        );
        return rowCount ?? 0;
    }

    async setRole(factoryId: string, accountId: string, next: Role): Promise<void>
    {
        await this.pool.query("update dashboard.member set role = $3 where factory_id = $1 and account_id = $2", [factoryId, accountId, next]);
    }

    async removeMember(factoryId: string, accountId: string): Promise<void>
    {
        await this.pool.query("delete from dashboard.member where factory_id = $1 and account_id = $2", [factoryId, accountId]);
    }
}
