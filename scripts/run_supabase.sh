#!/usr/bin/env bash
set -euo pipefail

# Apply migrations to a linked Supabase project or local stack.
#
# Remote (hosted project):
#   export SUPABASE_ACCESS_TOKEN=...   # from https://supabase.com/dashboard/account/tokens
#   npx supabase link --project-ref jlaajejpqjldpbinktln
#   ./scripts/run_supabase.sh push
#
# Local stack (requires Docker):
#   npx supabase start
#   ./scripts/run_supabase.sh push

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cmd="${1:-status}"

case "$cmd" in
  start)
    npx supabase start
    ;;
  stop)
    npx supabase stop
    ;;
  status)
    npx supabase status || true
    ;;
  push)
    npx supabase db push
    ;;
  reset)
    npx supabase db reset
    ;;
  *)
    echo "Usage: $0 {start|stop|status|push|reset}" >&2
    exit 1
    ;;
esac
