-- 대시보드의 기록(팩토리 · 팀원 · 초대)을 업무 영역의 이름인 `org` 스키마로 옮기고, 대시보드는 전용 롤 `dashboard_app` 으로만 붙는다.
--
-- ⚠ **스키마는 업무 영역으로 짓고, 롤은 붙는 앱마다 하나다.** 대시보드가 새 스키마를 읽게 되면 `dashboard_app` 에 GRANT 를 더한다.
-- ⚠ `dashboard_app` 은 `bypassrls` 로 붙어 **GRANT 가 유일한 경계**다. 표마다 RLS 를 켜고 `deny_all` 을 두어 다른 롤은 행을 보지 못한다.
-- ⚠ **이 파일은 롤의 이름만 만든다.** LOGIN · BYPASSRLS 와 비밀번호는 커밋되고 `schema_migrations` 에도 남으므로 여기 두지 않는다.
--   로컬은 `supabase/seed.sql`, 원격은 사람이 SQL 편집기에서(또는 Management API 로) 넣는다.
-- ⚠ 롤은 클러스터 수준 객체라 `db reset` 을 지나도 남는다. `if not exists` 가드가 없으면 두 번째 reset 이 깨진다.

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'dashboard_app') then
        create role dashboard_app;
    end if;
end
$$;

comment on role dashboard_app is
    '대시보드(apps/dashboard) 전용 DB 접속 롤. LOGIN·BYPASSRLS·비밀번호는 마이그레이션 밖에서 부여한다';

create schema if not exists org;
revoke all on schema org from public;

alter table dashboard.factory set schema org;
alter table dashboard.member set schema org;
alter table dashboard.invitation set schema org;
drop schema dashboard;

create policy deny_all on org.factory as restrictive for all using (false) with check (false);
create policy deny_all on org.member as restrictive for all using (false) with check (false);
create policy deny_all on org.invitation as restrictive for all using (false) with check (false);

-- Supabase 의 브라우저 롤에는 어떤 권한도 주지 않는다. 그 롤이 없는 Postgres(계약 테스트)에서는 건너뛴다.
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        revoke all on all tables in schema org from anon, authenticated;
    end if;
end
$$;

grant usage on schema org to dashboard_app;
grant select, insert, update, delete on org.factory, org.member, org.invitation to dashboard_app;
