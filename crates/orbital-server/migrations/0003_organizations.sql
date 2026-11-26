-- 조직과 그 service key. 운영자의 열쇠(`ORBITAL_OPERATOR_KEY`)로 조직을 만들고, 조직은 자기 열쇠를 더 내고 거둔다.
-- id 는 코드가 쓰는 조직의 이름(`OrganizationId`)이다. 관리 서버의 설정(`ORBITAL_SERVICE_KEYS`)의 조직 이름과 같은 이름을 가리킬 수 있다.
CREATE TABLE orbital.organization (
    id text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('live', 'test')),
    created_at bigint NOT NULL,
    closed_at bigint
);

-- service key. 값은 두지 않고 sha256(hex)만 둔다. 값은 낼 때의 답에 한 번만 실린다.
-- used_at 은 마지막으로 쓴 때를 분 단위로 뭉친 것이라 요청마다 적지 않는다.
CREATE TABLE orbital.service_key (
    id text PRIMARY KEY,
    organization text NOT NULL REFERENCES orbital.organization (id),
    digest text NOT NULL UNIQUE CHECK (digest ~ '^[0-9a-f]{64}$'),
    label text NOT NULL,
    created_at bigint NOT NULL,
    revoked_at bigint,
    used_at bigint
);
CREATE INDEX service_key_organization ON orbital.service_key (organization);
