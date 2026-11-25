-- 급여 명세. 직원은 자기 것만, 팀장은 자기가 맡은 부서 사람의 것을, 급여 관리자는 모두 본다
CREATE TABLE payroll.payslip (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee text NOT NULL REFERENCES orbital_auth.users (id),
    month text NOT NULL,
    amount int NOT NULL
);
ALTER TABLE payroll.payslip ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON payroll.payslip FOR SELECT
    USING ((SELECT orbital.role()) = 'employee' AND employee = (SELECT orbital.subject()));
CREATE POLICY team ON payroll.payslip FOR SELECT
    USING (
        (SELECT orbital.role()) = 'manager'
        AND employee IN (
            SELECT p.id FROM hr.person p JOIN hr.department d ON d.id = p.department
            WHERE d.manager = (SELECT orbital.subject())
        )
    );
CREATE POLICY admin ON payroll.payslip
    USING ((SELECT orbital.role()) = 'payroll_admin') WITH CHECK ((SELECT orbital.role()) = 'payroll_admin');
