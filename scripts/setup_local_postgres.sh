#!/usr/bin/env bash
# Alternative to a system Postgres role: initializes a small Postgres cluster
# owned entirely by the current user, listening on port 5433 with peer auth
# over its own Unix socket. No sudo required.
#
# Use this if you don't have (or don't want to use) sudo access to create a
# role on the system Postgres cluster. This is what the reference deployment
# of this project actually runs on.
set -euo pipefail

PGBIN="${PGBIN:-/usr/lib/postgresql/14/bin}"
DATADIR="${DATADIR:-$HOME/pgdata}"
PORT="${PORT:-5433}"

if [ ! -d "$DATADIR" ]; then
  echo "==> Initializing cluster at $DATADIR"
  "$PGBIN/initdb" -D "$DATADIR" -U "$(whoami)" --auth=trust
  sed -i "s/^#port = 5432/port = $PORT/" "$DATADIR/postgresql.conf"
fi

if ! "$PGBIN/pg_ctl" -D "$DATADIR" status >/dev/null 2>&1; then
  echo "==> Starting cluster on port $PORT"
  "$PGBIN/pg_ctl" -D "$DATADIR" -l "$DATADIR/logfile" -o "-k $DATADIR" start
  sleep 2
fi

export PGHOST="$DATADIR"
export PGPORT="$PORT"
export PGUSER="$(whoami)"

createdb llm_firewall 2>/dev/null || echo "    (llm_firewall already exists)"
psql -d llm_firewall -c "CREATE EXTENSION IF NOT EXISTS vector;"
psql -d llm_firewall -f "$(dirname "$0")/../db/init.sql"

echo "==> Done. Set this in backend/.env:"
echo "DATABASE_URL=postgresql+psycopg://$(whoami)@/llm_firewall?host=$DATADIR&port=$PORT"
echo
echo "To stop the cluster later: $PGBIN/pg_ctl -D $DATADIR stop"
