#!/usr/bin/env bash
# Throwaway-Postgres test for the messaging consent migration.
# Needs a reachable Postgres superuser (PGHOST/PGPORT/PGUSER). Creates and drops its own databases.
#   path "prod":  repo base migration + the hand-made columns production has, then the new migration (twice)
#   path "fresh": repo base migration only, then the new migration
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mig="$here/../../migrations"
new="$mig/20261020000000_messaging_consent_enforcement.sql"
psqlq() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }

# Roles are cluster-wide, so start from a clean cluster.
psql -X -q -c "drop database if exists msgtest_prod" -c "drop database if exists msgtest_fresh"
psql -X -q -c "drop role if exists anon" -c "drop role if exists authenticated" -c "drop role if exists service_role"

for path in prod fresh; do
  db="msgtest_$path"
  psql -X -q -c "create database $db"
  echo "== $path =="
  psqlq -d "$db" -f "$here/00_prestate.sql"
  psqlq -d "$db" -f "$mig/20261019130000_messaging.sql"
  [ "$path" = prod ] && psqlq -d "$db" -f "$here/01_live_hand_state.sql"
  psqlq -d "$db" -f "$new"
  psqlq -d "$db" -f "$new"            # must be safe to run twice
  psqlq -d "$db" -f "$here/02_assertions.sql" 2>&1 | grep -E "FAIL|ERROR|PASSED" || { echo "assertions did not finish"; exit 1; }
done

# Concurrency: many simultaneous requests must still make one thread per pair, and the
# per-minute message cap must hold under parallel inserts.
db=msgtest_prod
A=00000000-0000-0000-0000-0000000000a1; B=00000000-0000-0000-0000-0000000000b2
psql -X -q -d "$db" -c "insert into profiles(id) values ('00000000-0000-0000-0000-0000000000aa'),('00000000-0000-0000-0000-0000000000bb') on conflict do nothing"
X=00000000-0000-0000-0000-0000000000aa; Y=00000000-0000-0000-0000-0000000000bb
as() { printf "set role authenticated; select set_config('request.jwt.claim.sub','%s',false), set_config('request.jwt.claim.role','authenticated',false);\n" "$1"; }
for i in $(seq 1 8); do
  { as $X; echo "select start_conversation('$Y');"; } | psql -X -q -d "$db" >/dev/null 2>&1 &
  { as $Y; echo "select start_conversation('$X');"; } | psql -X -q -d "$db" >/dev/null 2>&1 &
done
wait
pairs=$(psql -X -At -d "$db" -c "select count(*) from conversations where pair_key = least('$X','$Y') || ':' || greatest('$X','$Y')")
[ "$pairs" = 1 ] && echo "ok   16 parallel starts -> 1 thread" || { echo "FAIL parallel starts made $pairs threads"; exit 1; }

cid=$(psql -X -At -d "$db" -c "select id from conversations where pair_key = least('$X','$Y') || ':' || greatest('$X','$Y')")
asker=$(psql -X -At -d "$db" -c "select requested_by from conversations where id = '$cid'")
answerer=$X; [ "$asker" = "$X" ] && answerer=$Y
{ as $answerer; echo "select respond_to_request('$cid', true);"; } | psql -X -q -d "$db" >/dev/null
for i in $(seq 1 40); do
  { as $X; echo "insert into messages(conversation_id, sender_id, body) values ('$cid','$X','p$i');"; } | psql -X -q -d "$db" >/dev/null 2>&1 &
done
wait
sent=$(psql -X -At -d "$db" -c "select count(*) from messages where sender_id = '$X'")
[ "$sent" = 20 ] && echo "ok   40 parallel sends -> exactly 20 stored" || { echo "FAIL parallel sends stored $sent"; exit 1; }

for path in prod fresh; do psql -X -q -c "drop database if exists msgtest_$path"; done
psql -X -q -c "drop role if exists anon" -c "drop role if exists authenticated" -c "drop role if exists service_role"
echo "ALL MESSAGING TESTS PASSED"
