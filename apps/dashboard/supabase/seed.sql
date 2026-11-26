-- 로컬과 e2e 의 시드 계정. 모두 비밀번호는 `orbital-local` 이고, 로컬 계정 문이 열린 환경에서만 들어온다.
-- ana: 팩토리를 만드는 사람 · ben: 초대받는 사람 · cho: 아무 데도 초대받지 않은 사람
-- ⚠ 확인 시각(`email_confirmed_at`)이 비어 있으면 Auth 가 로그인을 거절한다.
-- ⚠ 토큰 칸을 빈 문자열로 채운다. GoTrue 는 그 칸이 null 인 행을 만나면 죽는다.
insert into auth.users (id, instance_id, aud, role, email, created_at, updated_at)
values
    ('00000000-0000-4000-8000-00000000000a', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'ana@factory.test', now(), now()),
    ('00000000-0000-4000-8000-00000000000b', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'ben@factory.test', now(), now()),
    ('00000000-0000-4000-8000-00000000000c', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'cho@elsewhere.test', now(), now())
on conflict (id) do nothing;

update auth.users
   set encrypted_password         = extensions.crypt('orbital-local', extensions.gen_salt('bf')),
       email_confirmed_at         = now(),
       confirmation_token         = '',
       recovery_token             = '',
       email_change_token_new     = '',
       email_change_token_current = '',
       email_change               = '',
       phone_change               = '',
       phone_change_token         = '',
       reauthentication_token     = '',
       raw_app_meta_data          = '{"provider":"email","providers":["email"]}'::jsonb,
       raw_user_meta_data         = '{}'::jsonb
 where id in ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000c');

insert into auth.identities (id, user_id, provider_id, provider, identity_data, created_at, updated_at, last_sign_in_at)
select gen_random_uuid(), id, id::text, 'email', jsonb_build_object('sub', id::text, 'email', email, 'email_verified', true), now(), now(), now()
  from auth.users
 where id in ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000c')
on conflict do nothing;

-- 대시보드 전용 롤(`dashboard_app`)의 로컬 비밀번호. 원격의 비밀번호는 여기 두지 않는다.
alter role dashboard_app with login bypassrls password 'dashboard-app-local';
