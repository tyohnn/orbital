-- 레이어의 기록. 관리 서버가 여럿이어도 같은 기록을 보도록 control database 에 둔다.
-- 따로 고쳐지는 것마다 줄을 두고, 찾는 열만 타입을 두고 나머지 몸은 jsonb 로 둔다.
-- 봉인한 글(금고 · 팩토리의 설정 · 운영의 신원 열쇠 · 레이어가 만든 비밀)은 봉인한 그대로 둔다. 열쇠는 이 database 밖에 있다.

-- 관리 서버가 도는 기계. 뜰 때 자신을 적는다.
CREATE TABLE orbital.machine (
    name text PRIMARY KEY,
    started_at bigint NOT NULL,
    seen_at bigint NOT NULL
);

-- 팩토리가 올린 앱(스캐폴드). 코드 저장소가 있는 기계를 적는다.
CREATE TABLE orbital.app (
    organization text NOT NULL,
    name text NOT NULL,
    machine text NOT NULL REFERENCES orbital.machine (name),
    created_at bigint NOT NULL,
    PRIMARY KEY (organization, name)
);

-- 인스턴스. 놓인 기계와 release · 운영 · 프리뷰 · 승격 요청의 몸(jsonb).
CREATE TABLE orbital.instance (
    id text PRIMARY KEY,
    organization text NOT NULL,
    app text NOT NULL,
    machine text NOT NULL REFERENCES orbital.machine (name),
    version bigint NOT NULL DEFAULT 1,
    body jsonb NOT NULL
);
CREATE INDEX instance_machine ON orbital.instance (machine);

-- 운영의 일정 하나. 부르기 전에 다음 때를 적어 같은 때를 두 번 부르지 않는다.
CREATE TABLE orbital.schedule (
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    key text NOT NULL,
    next_at bigint NOT NULL,
    last_run jsonb,
    PRIMARY KEY (instance, key)
);

-- rollout 하나.
CREATE TABLE orbital.rollout (
    id text PRIMARY KEY,
    organization text NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    body jsonb NOT NULL
);

-- 팩토리마다의 설정. 비밀은 봉인한 글이다.
CREATE TABLE orbital.factory_settings (
    organization text PRIMARY KEY,
    version bigint NOT NULL DEFAULT 1,
    body jsonb NOT NULL
);

-- 금고의 값. (인스턴스, 단계, 이름)마다 봉인한 글 하나.
CREATE TABLE orbital.vault_value (
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    stage text NOT NULL CHECK (stage IN ('preview', 'production')),
    name text NOT NULL,
    sealed text NOT NULL CHECK (sealed LIKE 'seal1.%'),
    set_at bigint NOT NULL,
    PRIMARY KEY (instance, stage, name)
);

-- 에이전트가 사람에게 한 비밀의 요청. 값이 아니라 까닭만.
CREATE TABLE orbital.secret_request (
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    name text NOT NULL,
    reason text NOT NULL,
    at bigint NOT NULL,
    PRIMARY KEY (instance, name)
);

-- 입력 표. 표의 sha256 으로만 찾는다.
CREATE TABLE orbital.secret_entry (
    digest text PRIMARY KEY,
    organization text NOT NULL,
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    name text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('preview', 'production')),
    expires_at bigint NOT NULL,
    used boolean NOT NULL DEFAULT false
);

-- 닫은 작업. 토큰이 살 수 있는 가장 긴 때까지 기억한다.
CREATE TABLE orbital.revoked_work (
    instance text NOT NULL REFERENCES orbital.instance (id) ON DELETE CASCADE,
    work text NOT NULL,
    until bigint NOT NULL,
    PRIMARY KEY (instance, work)
);

-- 복구 훈련의 기록. 이름과 숫자만.
CREATE TABLE orbital.drill (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at bigint NOT NULL,
    passed boolean NOT NULL,
    machine text NOT NULL,
    body jsonb NOT NULL
);
