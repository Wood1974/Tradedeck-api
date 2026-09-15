"""Supabase client, attached per-request.

Uses the service-role key, so it bypasses RLS entirely. That is the intended
shape: the policies in the migration govern the *browser's* anon key, and every
Shield mutation is meant to travel through this service so the custody log is
always written. Authorization lives in auth.py, not in the database.
"""
from flask import g
from supabase import create_client

import config

_client = None


def client():
    global _client
    if _client is None:
        _client = create_client(config.get("SUPABASE_URL"),
                                config.get("SUPABASE_SERVICE_KEY"))
    return _client


def db():
    return getattr(g, "supabase", None) or client()
