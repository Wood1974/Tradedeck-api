"""Checkr background checks for TradeDeck profiles.

Flow: Profile "Start Background Check" -> POST /checkr/start (auth) -> we create a Checkr candidate (once) and a
hosted invitation -> the browser is sent to Checkr's invitation_url, where Checkr collects the FCRA disclosure,
consent, SSN/DOB and runs the report -> Checkr calls POST /checkr/webhook -> we set profiles.checkr_status.

Configuration (Render env):
  CHECKR_API_KEY  - Checkr secret API key. Also the key Checkr signs webhooks with.
  CHECKR_PACKAGE  - package slug from the Checkr dashboard (Account Settings -> Packages).
  CHECKR_ENABLED  - must be "1" to start checks. Unset = ON HOLD (holding message), even with keys present.
  CHECKR_BASE_URL - optional; https://api.checkr-staging.com for staging keys. Default production.
While CHECKR_API_KEY or CHECKR_PACKAGE is unset, /checkr/start answers 503 {"error": "not_configured"} and the
frontend shows its holding message, so the feature turns on by adding the env vars, with no code change.

Privacy: SSN, DOB and report contents never reach this service. We keep only the candidate id and a status.
Status values written to profiles.checkr_status: pending | cleared | consider | suspended | canceled | dispute.
'cleared' is the only value profiles_public.background_verified treats as verified.
"""
import hashlib
import hmac
import json
import logging
import os

import requests
from flask import Blueprint, g, jsonify, request

from auth import require_auth, utc_now_iso

log = logging.getLogger(__name__)
checkr_bp = Blueprint("checkr", __name__, url_prefix="/checkr")

DEFAULT_BASE_URL = "https://api.checkr.com"
TIMEOUT = 20
# Checkr report.result -> our checkr_status
RESULT_STATUS = {"clear": "cleared", "consider": "consider"}
# Report lifecycle events that end a check without a clear/consider result
REPORT_EVENT_STATUS = {
    "report.suspended": "suspended",
    "report.canceled": "canceled",
    "report.disputed": "dispute",
}


def _enabled():
    """Master switch. Checkr is ON HOLD unless CHECKR_ENABLED=1, even with keys set."""
    return os.environ.get("CHECKR_ENABLED", "").strip() == "1"


def _config():
    key = os.environ.get("CHECKR_API_KEY", "").strip()
    package = os.environ.get("CHECKR_PACKAGE", "").strip()
    base = (os.environ.get("CHECKR_BASE_URL", "").strip() or DEFAULT_BASE_URL).rstrip("/")
    return key, package, base


def _checkr_post(path, payload):
    key, _package, base = _config()
    resp = requests.post(f"{base}/v1/{path}", json=payload, auth=(key, ""), timeout=TIMEOUT)
    if resp.status_code >= 400:
        log.error("Checkr %s failed: %s %s", path, resp.status_code, resp.text[:500])
        resp.raise_for_status()
    return resp.json()


def _split_name(full_name):
    parts = (full_name or "").strip().split()
    if not parts:
        return None, None
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


@checkr_bp.route("/start", methods=["POST"])
@require_auth
def start():
    key, package, _base = _config()
    if not _enabled() or not key or not package:
        return jsonify({"error": "not_configured"}), 503

    db = g.supabase
    rows = db.table("profiles").select("id,email,full_name,checkr_candidate_id,checkr_status") \
        .eq("id", g.user_id).limit(1).execute().data
    if not rows:
        return jsonify({"error": "Profile not found"}), 404
    profile = rows[0]

    if profile.get("checkr_status") == "cleared":
        return jsonify({"error": "already_cleared"}), 409

    email = profile.get("email") or getattr(g.user, "email", None)
    if not email:
        return jsonify({"error": "An email address is required to start a background check"}), 400

    try:
        candidate_id = profile.get("checkr_candidate_id")
        if not candidate_id:
            first, last = _split_name(profile.get("full_name"))
            body = {"email": email, "custom_id": str(g.user_id)}
            if first:
                body["first_name"] = first
            if last:
                body["last_name"] = last
            candidate_id = _checkr_post("candidates", body)["id"]

        invitation = _checkr_post("invitations", {
            "candidate_id": candidate_id,
            "package": package,
            "work_locations": [{"country": "US", "state": "UT"}],
        })
    except Exception:
        log.exception("Could not start Checkr check for %s", g.user_id)
        return jsonify({"error": "Could not start background check. Try again later."}), 502

    db.table("profiles").update({"checkr_candidate_id": candidate_id, "checkr_status": "pending"}) \
        .eq("id", g.user_id).execute()
    return jsonify({"candidate_id": candidate_id, "invitation_url": invitation.get("invitation_url")}), 201


def _valid_signature(raw, signature, key):
    if not key or not signature:
        return False
    expected = hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


@checkr_bp.route("/webhook", methods=["POST"])
def webhook():
    key, _package, _base = _config()
    raw = request.get_data()
    if not _valid_signature(raw, request.headers.get("X-Checkr-Signature", ""), key):
        log.warning("Rejected Checkr webhook with bad signature")
        return jsonify({"error": "Invalid signature"}), 400

    try:
        event = json.loads(raw)
    except ValueError:
        return jsonify({"error": "Invalid JSON"}), 400

    event_type = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    candidate_id = obj.get("candidate_id")
    patch = None

    if event_type == "report.completed":
        status = RESULT_STATUS.get(obj.get("result") or obj.get("status"))
        if status:
            patch = {"checkr_status": status}
            if status == "cleared":
                patch["checkr_cleared_at"] = utc_now_iso()
    elif event_type in REPORT_EVENT_STATUS:
        patch = {"checkr_status": REPORT_EVENT_STATUS[event_type]}
    elif event_type in ("invitation.expired", "invitation.deleted"):
        # Candidate never finished the hosted form: let them start again.
        patch = {"checkr_status": None}

    if patch and candidate_id:
        q = g.supabase.table("profiles").update(patch).eq("checkr_candidate_id", candidate_id)
        if patch.get("checkr_status") is None:
            q = q.eq("checkr_status", "pending")  # never wipe a finished result on a late invitation event
        q.execute()
        log.info("Checkr %s for candidate %s -> %s", event_type, candidate_id, patch)

    return jsonify({"received": True})
