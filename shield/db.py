"""Supabase client, attached per-request.

Uses the service-role key, so it bypasses RLS entirely. That is the intended
shape: the policies in the migration govern the *browser's* anon key, and every
Shield mutation is meant to travel through this service so the custody log is
always written. Authorization lives in auth.py, not in the database.

Job tickets are written here and nowhere else. The table is the shared store
across gunicorn workers. This module does not keep a copy of a ticket in
memory.
"""
from flask import g
from supabase import create_client

import config

SCHEMA = "shield"

_client = None


def client():
    global _client
    if _client is None:
        _client = create_client(config.get("SUPABASE_URL"),
                                config.get("SUPABASE_SERVICE_KEY"))
    return _client


def db():
    return getattr(g, "supabase", None) or client()


def _job_tickets():
    """Service-role access to shield.job_tickets. RLS does not apply."""
    return db().schema(SCHEMA).table("job_tickets")


def insert_job_ticket(row):
    """Insert one genesis ticket.

    The unique index on ``record_id`` is what stops two workers, both
    having passed a read, from storing two tickets for one record. This
    function does not consult an in-process jar and does not update an
    existing row.
    """
    if not isinstance(row, dict):
        raise TypeError("job ticket row must be an object")
    return _job_tickets().insert(dict(row)).execute()


def find_job_ticket(tenant_id, record_id):
    """The ticket for one record in one tenant, or None.

    Both filters are required. A lookup by record id alone would be a
    cross-tenant read if a caller ever passed another tenant's id.
    """
    res = (_job_tickets().select("*")
           .eq("tenant_id", tenant_id)
           .eq("record_id", record_id)
           .limit(1)
           .execute())
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None
