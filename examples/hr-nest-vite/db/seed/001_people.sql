-- 프리뷰 DB 에만 들어가는 가짜 데이터다. 운영에는 들어가지 않는다
INSERT INTO hr.department (id, name, manager) VALUES ('dev', '개발팀', 'm1'), ('sales', '영업팀', NULL);
INSERT INTO hr.person (id, name, department) VALUES ('e1', '김개발', 'dev'), ('m1', '박팀장', 'dev'), ('e2', '이영업', 'sales');
INSERT INTO payroll.payslip (employee, month, amount) VALUES
    ('e1', '2026-10', 3100000), ('e1', '2026-11', 3200000),
    ('m1', '2026-11', 4500000),
    ('e2', '2026-11', 2900000);
