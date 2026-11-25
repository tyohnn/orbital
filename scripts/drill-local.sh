#!/usr/bin/env bash
# 복구 훈련의 절차를 처음부터 끝까지 한 번 돌려 본다. 매주 도는 워크플로(.github/workflows/drill.yml)가 부른다.
#
#   scripts/drill-local.sh
#
# 임시 폴더에 WAL 보관을 켠 클러스터를 따로 세우고(scripts/pg-local.sh 의 클러스터는 건드리지 않는다), 인스턴스처럼 생긴
# database 하나에 행을 적은 뒤 `orbitald drill` 을 두 번 돌린다. 첫 번째는 기반 백업부터 뜨고, 두 번째는 그 백업과 그 뒤의 WAL 로 돈다.
# 훈련이 실패하면 0 이 아닌 코드로 끝난다. 끝나면 클러스터와 폴더를 걷는다.
#
# ⚠ Postgres 는 root 로 돌지 않는다. root 로 부르면 postgres 사용자로 띄우고, orbitald 도 같은 방식(runuser)으로 도구를 부른다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)"
AS=(runuser -u postgres --)
if [ "$(id -u)" != "0" ]; then AS=(); fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/orbital-drill-XXXXXX")"
PGROOT="$WORK/pg"
DATA="$PGROOT/data"
BACKUP="$PGROOT/backup"
PORT="${DRILL_PG_PORT:-54620}"

cleanup() {
    "${AS[@]}" "$BIN/pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Postgres 의 사용자가 이 아래에 클러스터와 백업을 만든다
if [ "$(id -u)" = "0" ]; then chown postgres "$WORK"; fi
"${AS[@]}" mkdir -m 0700 "$PGROOT"

"${AS[@]}" mkdir -m 0700 "$BACKUP" "$BACKUP/wal"
"${AS[@]}" "$BIN/initdb" -D "$DATA" -U postgres -A trust --wal-segsize=1 --no-sync --locale=C -E UTF8 >/dev/null
"${AS[@]}" "$BIN/pg_ctl" -D "$DATA" -l "$PGROOT/log" -w start -o "-p $PORT -c listen_addresses=127.0.0.1 \
    -c unix_socket_directories=$PGROOT -c wal_level=replica -c archive_mode=on \
    -c archive_command='test ! -f $BACKUP/wal/%f && cp %p $BACKUP/wal/%f'" >/dev/null

URL="postgres://postgres@127.0.0.1:$PORT/postgres"
"${AS[@]}" "$BIN/psql" -X -q -d "$URL" -c "CREATE DATABASE i_drillsample"
"${AS[@]}" "$BIN/psql" -X -q -d "${URL%/postgres}/i_drillsample" \
    -c "CREATE TABLE note (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body text); INSERT INTO note (body) VALUES ('a'), ('b')"

cargo build --quiet -p orbital-server
ORBITALD="${CARGO_TARGET_DIR:-$ROOT/target}/debug/orbitald"
run() {
    env -i PATH="$PATH" ORBITAL_HOME="$WORK/home" ORBITAL_PG="$URL" ORBITAL_BACKUP_DIR="$BACKUP" "$ORBITALD" drill
}
run
"${AS[@]}" "$BIN/psql" -X -q -d "${URL%/postgres}/i_drillsample" -c "INSERT INTO note (body) VALUES ('c')"
run
echo "복구 훈련이 두 번 모두 통과했습니다"
