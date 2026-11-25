-- 할 일 한 줄. 주인은 로그인한 사람이고, 행 단위 규칙이 자기 것만 보이고 고치게 한다
CREATE TABLE todo.card (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner text NOT NULL DEFAULT orbital.subject() REFERENCES orbital_auth.users (id),
    title text NOT NULL
);
ALTER TABLE todo.card ENABLE ROW LEVEL SECURITY;
CREATE POLICY mine ON todo.card
    USING (owner = (SELECT orbital.subject()))
    WITH CHECK (owner = (SELECT orbital.subject()));
