CREATE TABLE ledger.note (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner text NOT NULL,
    body text NOT NULL
);
ALTER TABLE ledger.note ENABLE ROW LEVEL SECURITY;
-- 회원은 자기 메모만, 관리자는 모두. 업무 역할은 연결의 것을 읽는다
CREATE POLICY own ON ledger.note FOR SELECT
    USING ((SELECT orbital.role()) = 'member' AND owner = (SELECT orbital.subject()));
CREATE POLICY admin ON ledger.note
    USING ((SELECT orbital.role()) = 'admin') WITH CHECK ((SELECT orbital.role()) = 'admin');
