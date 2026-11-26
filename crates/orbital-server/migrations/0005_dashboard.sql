-- 대시보드가 올라설 조회의 바탕. 함대와 rollout 의 목록을 (만든 때, 식별자)의 차례로 쪽을 나누고, release 의 이력을 인스턴스마다 쌓는다.

-- 만든 때. 이 마이그레이션 전에 선 것은 모른다(NULL). 목록은 NULL 을 0 으로 보고 맨 앞에 세운다.
ALTER TABLE orbital.instance ADD COLUMN created_at bigint;
CREATE INDEX instance_listing ON orbital.instance (organization, (coalesce(created_at, 0)), id);

ALTER TABLE orbital.rollout ADD COLUMN created_at bigint;
CREATE INDEX rollout_listing ON orbital.rollout (organization, (coalesce(created_at, 0)), id);

-- release 의 이력. 운영을 적는 트랜잭션(승격 · 되살리기 · 무르기)과 되돌려진 승격을 적는 트랜잭션에서 한 줄씩 쌓는다.
-- n 은 인스턴스마다 1 부터의 차례이고(인스턴스의 줄을 잠그고 짓는다) 쪽의 표식이다. 전역의 번호를 내보내지 않는다.
-- 몸(body)의 칸은 core 의 `history::Entry` 가 정한다. 이름과 숫자와 권한 변화의 문장만 있다.
-- 인스턴스를 지우면 함께 지워진다. 인스턴스마다 정한 수(core 의 `history::KEEP`)를 넘으면 오랜 것부터 걷는다.
CREATE TABLE orbital.release_history (
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    n bigint NOT NULL CHECK (n > 0),
    kind text NOT NULL CHECK (kind IN ('promoted', 'rolled_back', 'restored', 'restore_undone')),
    at bigint NOT NULL,
    body jsonb NOT NULL,
    PRIMARY KEY (instance, n)
);
