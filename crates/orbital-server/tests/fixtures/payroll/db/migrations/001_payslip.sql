CREATE TABLE payroll.payslip (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee text NOT NULL REFERENCES orbital_auth.users (id),
    amount int NOT NULL
);
ALTER TABLE payroll.payslip ENABLE ROW LEVEL SECURITY;
-- 직원은 자기 명세만, 급여 관리자는 모두. 업무 역할은 연결의 것을 읽는다
CREATE POLICY own ON payroll.payslip FOR SELECT
    USING (orbital.role() = 'employee' AND employee = (SELECT orbital.subject()));
CREATE POLICY admin ON payroll.payslip
    USING (orbital.role() = 'payroll_admin') WITH CHECK (orbital.role() = 'payroll_admin');
-- 행 단위 규칙을 끈 표. 역할 제한 정책이 걸리지 않는다
CREATE TABLE payroll.calendar (day text PRIMARY KEY);
INSERT INTO payroll.calendar VALUES ('25일');
