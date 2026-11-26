-- ✏️ 당신의 표. 메모 한 줄의 주인은 로그인한 사람이고, 행 단위 규칙이 자기 것만 보이고 고치게 한다.
-- 이미 운영에 돈 마이그레이션은 고치지 않는다. 바꿀 것은 새 번호의 파일로 더한다
CREATE TABLE app.note (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner text NOT NULL DEFAULT orbital.subject() REFERENCES orbital_auth.users (id),
    body text NOT NULL
);
ALTER TABLE app.note ENABLE ROW LEVEL SECURITY;
CREATE POLICY mine ON app.note
    USING (owner = (SELECT orbital.subject()))
    WITH CHECK (owner = (SELECT orbital.subject()));
