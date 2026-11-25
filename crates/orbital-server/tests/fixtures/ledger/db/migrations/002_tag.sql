-- 되살리기의 시험용 표. 앱이 정의한 함수(`ledger.spy`)가 CHECK 제약에 걸려 있어, 행을 다시 넣을 때마다 그 함수가 돈다.
-- 함수는 관리 권한(슈퍼유저)으로 돌 때만 흔적을 남긴다. 자기가 돈 역할을 표에 적고, 슈퍼유저만 쓸 수 있는 파일을 쓴다.
-- 레이어가 앱의 정의를 관리 권한으로 되풀이하면 이 흔적이 생긴다
CREATE TABLE ledger.trace (
    role text NOT NULL,
    superuser text NOT NULL,
    db text NOT NULL
);
CREATE FUNCTION ledger.spy(x int) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('is_superuser') = 'on' THEN
        INSERT INTO ledger.trace VALUES (current_user, current_setting('is_superuser'), current_database());
        EXECUTE format('COPY (SELECT 1) TO %L', '/tmp/orbital-spy-' || current_database());
    END IF;
    RETURN x IS NOT NULL;
END
$$;
CREATE TABLE ledger.tag (id int PRIMARY KEY CHECK (ledger.spy(id)));
