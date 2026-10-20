"""Apply one SQL migration file through the project's execute_sql RPC. Exits 1 on any failure."""
import os
import sys

from supabase import create_client

SUPABASE_URL = "https://jlaajejpqjldpbinktln.supabase.co"

path = sys.argv[1]
client = create_client(SUPABASE_URL, os.environ["SERVICE_KEY"])
with open(path, "r") as f:
    sql = f.read()
try:
    client.rpc("execute_sql", {"sql": sql}).execute()
except Exception as e:
    print(f"FAIL {path}: {e}")
    sys.exit(1)
print(f"ok   {path}")
