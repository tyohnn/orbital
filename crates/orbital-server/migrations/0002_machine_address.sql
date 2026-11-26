-- 기계의 주소. 다른 기계에 놓인 인스턴스의 요청을 그 기계로 넘길 때 쓴다.
-- api_url 은 관리 API 를(`ORBITAL_MACHINE_URL`), router_url 은 하위 도메인으로 고객의 요청을 받는 공용 listener 를(`ORBITAL_MACHINE_ROUTER_URL`)
-- 다른 관리 서버에서 닿는 주소로 적는다. 적지 않은 기계로는 넘기지 않는다.
ALTER TABLE orbital.machine
    ADD COLUMN api_url text,
    ADD COLUMN router_url text;
