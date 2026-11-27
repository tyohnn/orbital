-- 조직과 service key 의 길을 `main` 의 모양(운영자 키 `ORBITAL_ADMIN_KEY` · `/v1/admin/organizations` · `POST /v1/keys/{id}/revoke`)에 맞췄다.
-- 0003 의 주석이 말하는 `ORBITAL_OPERATOR_KEY` 는 이제 `ORBITAL_ADMIN_KEY` 다. 표의 모양은 그대로 쓴다.
--
-- 키의 목록은 만든 차례다. 만든 때(초)가 같은 키도 차례가 흔들리지 않게 적은 차례의 번호를 둔다.
-- 앞에 있던 줄도 번호를 받는다(줄이 놓인 차례).
ALTER TABLE orbital.service_key ADD COLUMN made bigint GENERATED ALWAYS AS IDENTITY;
CREATE INDEX service_key_listing ON orbital.service_key (organization, made);
