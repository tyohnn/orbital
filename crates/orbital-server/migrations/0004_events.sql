-- 이벤트와 웹훅. 레이어의 상태가 바뀐 것을 조직마다 차례대로 쌓고, 조직이 건 주소 하나로 서명해 보낸다.
-- 이벤트의 몸(data)에는 이름과 숫자만 있다. 몸의 칸은 core 의 `event::Body` 가 정한다.

-- 이벤트 하나. id 는 쌓인 차례다. 한 조직의 이벤트는 그 조직의 advisory lock 을 쥐고 쌓아, 조직 안에서는 id 의 차례와 commit 의 차례가 같다.
-- instance 는 외래 키가 아니다. 인스턴스를 지운 뒤에도 그 인스턴스의 이벤트(`instance.deleted` 까지)가 보관 기간 동안 남는다.
-- organization 도 외래 키가 아니다. 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)에만 있는 조직의 이벤트도 쌓인다.
CREATE TABLE orbital.event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization text NOT NULL,
    type text NOT NULL,
    instance text,
    data jsonb NOT NULL,
    created_at bigint NOT NULL
);
CREATE INDEX event_organization ON orbital.event (organization, id);
CREATE INDEX event_created ON orbital.event (created_at);

-- 조직마다의 웹훅 하나. 서명의 비밀은 봉인한 글로만 둔다(조직에 묶는다).
-- delivered 는 「이 id 까지는 보냈거나 그만뒀다」는 표시이고, 다음에 보낼 것은 그 뒤의 가장 앞 이벤트 하나다(차례를 지킨다).
-- 보내는 관리 서버는 이 줄을 잠그고(`FOR UPDATE SKIP LOCKED`) 보내므로, 여러 관리 서버 가운데 하나만 같은 이벤트를 보낸다.
-- 받은 답의 본문은 적지 않는다. 마지막 시도의 때 · 상태 코드 · 갈래만 적는다.
CREATE TABLE orbital.webhook (
    organization text PRIMARY KEY,
    url text NOT NULL,
    secret text NOT NULL CHECK (secret LIKE 'seal1.%'),
    created_at bigint NOT NULL,
    delivered bigint NOT NULL,
    next_at bigint NOT NULL,
    failures integer NOT NULL DEFAULT 0,
    failing_since bigint,
    last_attempt_at bigint,
    last_status integer,
    last_error text CHECK (last_error IN ('refused_address', 'unresolved', 'unreachable', 'timed_out', 'status', 'unsealed')),
    delivered_at bigint,
    abandoned bigint NOT NULL DEFAULT 0,
    last_abandoned bigint
);
