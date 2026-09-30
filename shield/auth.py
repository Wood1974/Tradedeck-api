"""Authentication: two credentials, one principal, one scoped query.

This replaces the version that borrowed TradeDeck's identity. That one asked
TradeDeck's Supabase project who the caller was, then checked the caller
against `homeowner_id` and `contractor_id` on a table keyed into TradeDeck's
`jobs`. Shield could not be sold to anyone else while that was true.

Now there are two ways in:

* **`Authorization: Bearer shld_<public>_<secret>`** — a business calling from
  its own systems. Verified against `shield.api_keys`.
* **`Authorization: Bearer <jwt>`** — a human signed in to Shield's own web
  client. The token is verified by Shield's own auth provider, and the subject
  is then looked up in `shield.members` to find which tenant they belong to.

Both produce a `tenancy.Principal` on `g.principal`, and everything downstream
scopes on `g.principal.tenant_id`.

Two things this file is careful about
-------------------------------------
**A valid signature is not authorisation.** A JWT that verifies tells us a
human exists, not that they belong to a tenant here. Someone with an account
in Shield's auth provider and no membership row gets 403, not a blank tenant.
The old code had no equivalent step because the tenant was implied.

**Ownership is checked by scoping, not by comparing ids.** The old
`require_shield_job` loaded a row by id and then compared `homeowner_id`
against the caller. That works but it is the wrong shape: it fetches the row
first and decides afterwards, so every new route has to remember to decide.
Here the lookup itself is constrained to the caller's tenant, so a record
belonging to another tenant is not "forbidden" — it does not exist. A route
that forgets the check cannot leak, because there is no unscoped read to
forget.
"""
import functools
import logging
from datetime import datetime, timezone

from flask import g, jsonify, request

import tenancy
from db import db

log = logging.getLogger(__name__)

SCHEMA = "shield"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _err(msg, code):
    return jsonify({"error": msg}), code


def _table(name):
    """A query builder against Shield's own schema.

    Every read in the service goes through here, so the schema name is stated
    once. Nothing in `public` is reachable from this module by construction.
    """
    return db().schema(SCHEMA).table(name)


def _bearer():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header[7:].strip()
        if token:
            return token
    # A key may also arrive in its own header, which is conventional for
    # machine callers and keeps it out of proxy logs that record Authorization.
    return (request.headers.get("X-API-Key") or "").strip() or None


def _principal_from_api_key(token):
    parsed = tenancy.parse_key(token)
    if not parsed:
        return None
    public_id, secret = parsed
    try:
        res = (_table("api_keys")
               .select("id,tenant_id,key_hash,revoked_at,tenants(status)")
               .eq("public_id", public_id).limit(1).execute())
    except Exception:
        log.warning("API key lookup failed", exc_info=True)
        return None

    row = (res.data or [None])[0]
    if row:
        # Flatten the joined tenant status so usable_key sees one dict and
        # makes every decision in one place.
        tenant = row.get("tenants") or {}
        if isinstance(tenant, list):
            tenant = tenant[0] if tenant else {}
        row = {**row, "tenant_status": tenant.get("status")}

    principal = tenancy.usable_key(row, secret)
    if principal:
        _touch_key(row.get("id"))
    return principal


def _touch_key(key_id):
    """Record that a key was used. Never fails the request.

    Useful for spotting a key that is still live and has not been used in a
    year, which is the one most worth revoking. Not worth returning a 500 for.
    """
    if not key_id:
        return
    try:
        _table("api_keys").update({"last_used_at": utc_now_iso()}).eq("id", key_id).execute()
    except Exception:
        log.debug("Could not update last_used_at for key %s", key_id, exc_info=True)


def _principal_from_session(token):
    try:
        resp = db().auth.get_user(token)
    except Exception:
        log.warning("Session verification failed", exc_info=True)
        return None
    user = getattr(resp, "user", None)
    user_id = getattr(user, "id", None) if user else None
    if not user_id:
        return None

    try:
        res = (_table("members")
               .select("id,tenant_id,role,disabled_at,tenants(status)")
               .eq("auth_user_id", user_id).limit(1).execute())
    except Exception:
        log.warning("Member lookup failed", exc_info=True)
        return None

    row = (res.data or [None])[0]
    if row:
        tenant = row.get("tenants") or {}
        if isinstance(tenant, list):
            tenant = tenant[0] if tenant else {}
        row = {**row, "tenant_status": tenant.get("status")}
    return tenancy.usable_member(row)


def require_tenant(fn):
    """Resolve either credential to a principal, or refuse.

    An API key is tried first and only when the token actually looks like one,
    so a malformed key is never handed to the session verifier and reported as
    an expired login.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = _bearer()
        if not token:
            return _err("Missing credentials. Send an API key or a session "
                        "token in the Authorization header.", 401)

        if tenancy.parse_key(token):
            principal = _principal_from_api_key(token)
            if not principal:
                return _err("Invalid, revoked or suspended API key", 401)
        else:
            principal = _principal_from_session(token)
            if not principal:
                # Deliberately one message for "bad token" and "valid token,
                # no membership": distinguishing them tells an outsider which
                # accounts exist in this Shield instance.
                return _err("Invalid session, or this account does not belong "
                            "to a tenant on this service", 401)

        g.principal = principal
        g.tenant_id = principal.tenant_id
        return fn(*args, **kwargs)
    return wrapper


def require_record(param="record_id", writable=True):
    """Load a record, scoped to the caller's tenant.

    The scoping is the authorisation. A record belonging to another tenant
    does not come back, so there is no separate ownership check to forget and
    no 403 that confirms the id exists.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            payload = request.get_json(silent=True) or request.form or {}
            record_id = kwargs.get(param) or payload.get(param)
            if not record_id:
                return _err(f"{param} required", 400)

            try:
                query = _table("records").select("*").eq("id", record_id)
                res = tenancy.scope(query, g.principal).limit(1).execute()
            except Exception:
                log.exception("Record lookup failed for %s", record_id)
                return _err("Could not load the record", 500)

            record = (res.data or [None])[0]
            if not record:
                return _err("Record not found", 404)

            if writable and g.principal.is_member and g.principal.role == "viewer":
                return _err("This account has read-only access", 403)

            g.record = record
            return fn(*args, **kwargs)
        return wrapper
    return decorator
