#!/usr/bin/env bash
# 로컬 PostgreSQL 클러스터를 띄운다. orbital-pg 와 orbital-proxy 의 테스트가 실제 DB 에 역할을 세우고 격리를 잰다.
#
#   scripts/pg-local.sh          # 띄운다(이미 떠 있으면 그대로)
#   scripts/pg-local.sh stop     # 내린다
#
# ⚠ 가장 높은 버전의 PostgreSQL 을 쓴다. database 복제(file_copy_method)는 18 부터 있어서 그보다 낮으면 멈춘다.
# ⚠ 클러스터는 .sessions/pg 에 둔다(커밋하지 않는다). Postgres 는 root 로 실행되지 않아서 postgres 사용자로 띄운다.
# ⚠ 개발용이라 127.0.0.1 의 연결을 비밀번호 없이 받는다. 운영에서는 proxy 만 닿는 소켓에서만 듣는다.
# ⚠ 다 뜨면 붙을 주소를 찍는다: ORBITAL_PG=postgres://postgres@127.0.0.1:54519/postgres
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${PG_DATA:-$ROOT/.sessions/pg}"
PORT="${PG_PORT:-54519}"
BIN="$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)"
AS=(runuser -u postgres --)
if [ "$(id -u)" != "0" ]; then AS=(); fi

if [ "${1:-}" = "stop" ]; then
    "${AS[@]}" "$BIN/pg_ctl" -D "$DATA" stop -m fast || true
    exit 0
fi

MAJOR="$("$BIN/postgres" --version | sed -E 's/.* ([0-9]+)\..*/\1/')"
if [ "$MAJOR" -lt 18 ]; then
    echo "PostgreSQL 18 이상이 필요합니다(지금 $MAJOR). database 복제가 18 부터 있습니다" >&2
    exit 1
fi

mkdir -p "$DATA"
if [ "$(id -u)" = "0" ]; then chown -R postgres "$DATA"; fi

if [ ! -f "$DATA/PG_VERSION" ]; then
    "${AS[@]}" "$BIN/initdb" -D "$DATA" -U postgres -A trust >/dev/null
fi

if ! "${AS[@]}" "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
    "${AS[@]}" "$BIN/pg_ctl" -D "$DATA" -l "$DATA/log" -w start \
        -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=/tmp -c file_copy_method=clone -c max_connections=300" >/dev/null
fi

echo "ORBITAL_PG=postgres://postgres@127.0.0.1:$PORT/postgres"
