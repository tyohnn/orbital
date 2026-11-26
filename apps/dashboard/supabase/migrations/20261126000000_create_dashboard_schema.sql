-- 대시보드의 기록: 팩토리 · 팀원 · 초대. 계정 자체는 Supabase Auth(`auth.users`)에 있다.
-- ⚠ 이 표는 대시보드의 서버만 읽고 쓴다. 브라우저(anon · authenticated)에는 열지 않는다(RLS 를 켜고 정책을 두지 않는다).
-- ⚠ 대시보드가 쓰는 service key 는 봉인한 글(`sealed_key`)로만 둔다.

create schema if not exists dashboard;

create table if not exists dashboard.factory
(
    id               text primary key check (id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    label            text        not null default '' check (char_length(label) <= 100),
    dashboard_key_id text        not null,
    sealed_key       text        not null,
    created_at       timestamptz not null default now()
);

create table if not exists dashboard.member
(
    factory_id text        not null references dashboard.factory (id) on delete cascade,
    account_id uuid        not null,
    email      text        not null check (email = lower(email)),
    role       text        not null check (role in ('owner', 'admin', 'member')),
    created_at timestamptz not null default now(),
    primary key (factory_id, account_id)
);

create index if not exists member_account on dashboard.member (account_id);

create table if not exists dashboard.invitation
(
    factory_id text        not null references dashboard.factory (id) on delete cascade,
    email      text        not null check (email = lower(email)),
    role       text        not null check (role in ('owner', 'admin', 'member')),
    created_at timestamptz not null default now(),
    primary key (factory_id, email)
);

create index if not exists invitation_email on dashboard.invitation (email);

alter table dashboard.factory enable row level security;
alter table dashboard.member enable row level security;
alter table dashboard.invitation enable row level security;
revoke all on schema dashboard from public;
