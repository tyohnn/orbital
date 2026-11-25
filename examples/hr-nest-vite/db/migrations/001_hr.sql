-- 부서와 사람. 부서 목록은 모든 직원이 본다(행 단위 규칙을 끈다)
CREATE TABLE hr.department (
    id text PRIMARY KEY,
    name text NOT NULL,
    manager text REFERENCES orbital_auth.users (id)
);

CREATE TABLE hr.person (
    id text PRIMARY KEY REFERENCES orbital_auth.users (id),
    name text NOT NULL,
    department text NOT NULL REFERENCES hr.department (id)
);
ALTER TABLE hr.person ENABLE ROW LEVEL SECURITY;
-- 직원은 자기 줄만, 팀장과 급여 관리자는 모두 본다. 고치는 것은 급여 관리자뿐이다
CREATE POLICY own ON hr.person FOR SELECT
    USING ((SELECT orbital.role()) = 'employee' AND id = (SELECT orbital.subject()));
CREATE POLICY manager ON hr.person FOR SELECT
    USING ((SELECT orbital.role()) = 'manager');
CREATE POLICY admin ON hr.person
    USING ((SELECT orbital.role()) = 'payroll_admin') WITH CHECK ((SELECT orbital.role()) = 'payroll_admin');
