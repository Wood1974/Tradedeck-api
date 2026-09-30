"""LEGACY: the TradeDeck-coupled auth path, kept only until routes are ported.

This is the old `auth.py`, moved here unchanged on 2026-09-20 when Shield got
an identity of its own. It is still imported by `routes.py`, which is why it
still exists: deleting it today would stop the service booting, and a broken
service is not a separated one.

What it does that the new path does not
---------------------------------------
It asks TradeDeck's Supabase project who the caller is, then authorises by
comparing that user against `homeowner_id` and `contractor_id` on
`public.shield_jobs` — a table keyed into TradeDeck's `jobs` and `profiles`.
Every one of those is a coupling the separation exists to remove.

It is a dead end on purpose. Nothing new should import it, `auth.py` is where
new work goes, and this file is deleted in one piece the moment the last route
stops calling it. `legacy-auth-is-not-spreading` fails the build if anything
other than `routes.py` starts using it.
"""
import functools
import logging
from datetime import datetime, timezone

from flask import g, jsonify, request

from db import db

log = logging.getLogger(__name__)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _err(msg, code):
    return jsonify({"error": msg}), code


def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return _err("Missing or invalid Authorization header", 401)
        token = header[7:].strip()
        if not token:
            return _err("Missing bearer token", 401)
        try:
            resp = db().auth.get_user(token)
        except Exception:
            log.warning("Token verification failed", exc_info=True)
            return _err("Invalid or expired token", 401)
        user = getattr(resp, "user", None)
        if not user or not getattr(user, "id", None):
            return _err("Invalid or expired token", 401)
        g.user, g.user_id, g.access_token = user, user.id, token
        return fn(*args, **kwargs)
    return wrapper


def get_shield_job(shield_job_id):
    if not shield_job_id:
        return None
    res = db().table("shield_jobs").select("*").eq("id", shield_job_id).limit(1).execute()
    return res.data[0] if res.data else None


def is_participant(job, user_id):
    return bool(job) and user_id in (job.get("homeowner_id"), job.get("contractor_id"))


def require_shield_job(param="shield_job_id", role=None):
    """Load the shield job and check the caller belongs to it.

    role=None       any participant
    role='homeowner' only the buyer (payment, cancellation)
    role='contractor' only the assigned contractor (uploads)
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            payload = request.get_json(silent=True) or request.form or {}
            job_id = kwargs.get(param) or payload.get(param)
            if not job_id:
                return _err(f"{param} required", 400)
            job = get_shield_job(job_id)
            if not job:
                return _err("Shield job not found", 404)
            if not is_participant(job, g.user_id):
                # 404 rather than 403: a stranger should not learn the id exists.
                return _err("Shield job not found", 404)
            if role == "homeowner" and job.get("homeowner_id") != g.user_id:
                return _err("Only the homeowner can perform this action", 403)
            if role == "contractor" and job.get("contractor_id") != g.user_id:
                return _err("Only the assigned contractor can perform this action", 403)
            g.shield_job = job
            return fn(*args, **kwargs)
        return wrapper
    return decorator
