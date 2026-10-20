"""Read-only checks after the migrations ran. Exits 1 if anything is missing.

Messaging is NOT applied by this workflow (it is tested in supabase/tests/messaging and applied
by hand after a staging pass). These checks only confirm the consent rules the app assumes.
"""
import os
import sys

from supabase import create_client

SUPABASE_URL = "https://jlaajejpqjldpbinktln.supabase.co"
client = create_client(SUPABASE_URL, os.environ["SERVICE_KEY"])


def rows(sql):
    return client.rpc("execute_sql", {"sql": sql}).execute().data or []


MESSAGING_TABLES = "('conversations','conversation_members','messages')"
CHECKS = {
    "new conversations are not accepted by default": """
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='conversations' AND column_name='status'
          AND column_default LIKE '%pending%'""",
    "sending requires an accepted conversation": """
        SELECT 1 FROM pg_policies
        WHERE schemaname='public' AND tablename='messages' AND policyname='Members can send messages'
          AND with_check LIKE '%accepted%'""",
    "conversations are published to realtime": """
        SELECT 1 FROM pg_publication_tables
        WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='conversations'""",
    "anon has no messaging table privileges": f"""
        SELECT 1 WHERE NOT EXISTS (
          SELECT 1 FROM information_schema.role_table_grants
          WHERE table_schema='public' AND grantee='anon' AND table_name IN {MESSAGING_TABLES})""",
    "clients cannot truncate or modify messaging tables": f"""
        SELECT 1 WHERE NOT EXISTS (
          SELECT 1 FROM information_schema.role_table_grants
          WHERE table_schema='public' AND grantee='authenticated' AND table_name IN {MESSAGING_TABLES}
            AND privilege_type IN ('TRUNCATE','TRIGGER','DELETE','UPDATE'))""",
}

problems = []
try:
    tables = rows("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name LIKE 'shield_%' ORDER BY table_name""")
    print(f"shield tables: {len(tables)}")
    if not tables:
        problems.append("no shield_* tables found")
    for label, sql in CHECKS.items():
        if rows(sql):
            print(f"ok   {label}")
        else:
            problems.append(label)
except Exception as e:  # a check that cannot run is a failed check
    problems.append(f"verification could not run: {e}")

for p in problems:
    print(f"FAIL {p}")
sys.exit(1 if problems else 0)
