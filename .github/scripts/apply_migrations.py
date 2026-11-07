#!/usr/bin/env python3
"""Apply the Shield Supabase migrations, in order, failing on the first error.

Replaces five near-identical copy-pasted workflow steps. The ordered list of
migrations lives here, in one place, so adding one is a single-line change
instead of another duplicated 18-line step.

The service role key is read from the environment (SUPABASE_SERVICE_KEY), never
from a command-line argument or a workflow input: workflow_dispatch string
inputs are not masked, and `${{ }}` interpolation into a run block both exposes
the value to the runner's process list and is a script-injection vector.

These migrations are expected to be idempotent -- the workflow is run manually
and may be re-run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Applied in this order. Add new migrations to the end.
MIGRATIONS = [
    ("Base schema & RLS", "20260914000000_shield_schema_and_rls.sql"),
    ("Hardening", "20260914010000_shield_hardening.sql"),
    ("Field notes", "20260914020000_shield_field_notes.sql"),
    ("Retake index", "20260914030000_shield_retake_index.sql"),
    ("RLS security fixes", "20260928000000_rls_close_privilege_escalation.sql"),
]

MIGRATIONS_DIR = Path("supabase/migrations")

VERIFY_SQL = """
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public' AND table_name LIKE 'shield_%'
ORDER BY table_name;
"""


def make_client():
    from supabase import create_client

    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
    if not url or not key:
        sys.exit(
            "SUPABASE_URL and SUPABASE_SERVICE_KEY must both be set in the "
            "environment. Set SUPABASE_SERVICE_KEY as a repository secret; do "
            "not pass it as a workflow input."
        )
    return create_client(url, key)


def run_sql(client, sql: str):
    return client.rpc("execute_sql", {"sql": sql}).execute()


def verify(client) -> int:
    try:
        result = run_sql(client, VERIFY_SQL)
    except Exception as exc:  # noqa: BLE001 - surface whatever the client raised
        print(f"::error::Verification failed: {exc}", file=sys.stderr)
        return 1
    print("Verification successful. shield_* tables present:")
    print(result)
    return 0


def apply_all(client) -> int:
    missing = [f for _, f in MIGRATIONS if not (MIGRATIONS_DIR / f).is_file()]
    if missing:
        # Check every file up front rather than failing halfway through a
        # sequence of writes to the live database.
        for name in missing:
            print(f"::error::Migration file not found: {MIGRATIONS_DIR / name}", file=sys.stderr)
        return 1

    for label, filename in MIGRATIONS:
        path = MIGRATIONS_DIR / filename
        sql = path.read_text(encoding="utf-8")
        try:
            run_sql(client, sql)
        except Exception as exc:  # noqa: BLE001
            print(f"::error::{label} ({filename}) failed: {exc}", file=sys.stderr)
            return 1
        print(f"Applied: {label} ({filename})")

    print(f"All {len(MIGRATIONS)} migrations applied.")
    return 0


def main() -> int:
    verify_only = "--verify-only" in sys.argv[1:]
    client = make_client()
    return verify(client) if verify_only else apply_all(client)


if __name__ == "__main__":
    sys.exit(main())
