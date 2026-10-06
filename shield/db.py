"""Supabase client, attached per-request.

Uses the service-role key, so it bypasses RLS entirely. That is the intended
shape: the policies in the migration govern the *browser's* anon key, and every
Shield mutation is meant to travel through this service so the custody log is
always written. Authorization lives in auth.py, not in the database.

Job tickets are written here and nowhere else. The table is the shared store
across gunicorn workers. This module does not keep a copy of a ticket in
memory.

Receipts and timestamp tokens are the same shape: one row, written by the
service role, after the batch has been accepted. A missing timestamp is a
row whose status is ``missing``. It is not a forgery, and this module does
not invent a token to fill it in.
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


def _receipts():
    """Service-role access to shield.receipts. RLS does not apply."""
    return db().schema(SCHEMA).table("receipts")


def _tsa_tokens():
    """Service-role access to shield.tsa_tokens. RLS does not apply."""
    return db().schema(SCHEMA).table("tsa_tokens")


def insert_receipt(row):
    """Insert one batch receipt. Does not update an existing row."""
    if not isinstance(row, dict):
        raise TypeError("receipt row must be an object")
    return _receipts().insert(dict(row)).execute()


def latest_receipt(tenant_id, record_id):
    """The newest receipt for one record in one tenant, or None.

    Both filters are required, same as a job ticket. ``batch_index`` is
    the order the batches were accepted, which is the order the phone
    chain grew.
    """
    res = (_receipts().select("*")
           .eq("tenant_id", tenant_id)
           .eq("record_id", record_id)
           .order("batch_index", desc=True)
           .limit(1)
           .execute())
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def insert_tsa_token(row):
    """Insert the timestamp outcome for one receipt.

    ``status`` is ``present`` or ``missing``. Missing means the authority
    did not give us a token we could check. This function does not rewrite
    that into a success.
    """
    if not isinstance(row, dict):
        raise TypeError("timestamp row must be an object")
    return _tsa_tokens().insert(dict(row)).execute()


def find_receipt_by_phone_head(tenant_id, record_id, phone_chain_head):
    """The receipt whose phone-chain head is this one, or None.

    A phone that already received a receipt, and lost the response, sends
    the same batch again. This is how the route finds that receipt without
    accepting the batch a second time. Both tenant and record are required.
    """
    res = (_receipts().select("*")
           .eq("tenant_id", tenant_id)
           .eq("record_id", record_id)
           .eq("phone_chain_head", phone_chain_head)
           .limit(1)
           .execute())
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def find_tsa_token(tenant_id, receipt_id):
    """The timestamp row for one receipt in one tenant, or None."""
    res = (_tsa_tokens().select("*")
           .eq("tenant_id", tenant_id)
           .eq("receipt_id", receipt_id)
           .limit(1)
           .execute())
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None
