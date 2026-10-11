"""ID check + signed photographer note, for the Shield phone app.

Flow: consent -> /identity/start (Stripe Identity hosted check: document + live selfie match) ->
/identity/status (server asks Stripe, never trusts the client) -> /identity/note (device-signed
statement, accepted only after Stripe reports `verified`).

Privacy: ID and selfie images never reach this service; Stripe holds them. We keep only the
session id, its status, the consent record and the signed note. No name or document data is stored.
"""
import logging
import os
import re
import uuid

import stripe
from flask import Blueprint, g, jsonify, request

from auth import require_auth, utc_now_iso
from identity_core import STATEMENT, STATEMENT_VERSION, load_receipt_key, make_receipt, receipt_public, statement_sha256, verify_note

log = logging.getLogger(__name__)
identity_bp = Blueprint("identity", __name__, url_prefix="/identity")

CONSENT_VERSION = "1"
SESSIONS = "shield_identity_sessions"
NOTES = "shield_note_attestations"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _db():
    return g.supabase


def _receipt_key():
    try:
        return load_receipt_key(os.environ.get("IDENTITY_RECEIPT_KEY"))
    except ValueError:
        log.error("IDENTITY_RECEIPT_KEY is set but is not a usable EC P-256 private key")
        return None


def _latest_session(user_id):
    rows = _db().table(SESSIONS).select("*").eq("user_id", user_id).order("created_at", desc=True).limit(1).execute().data
    return rows[0] if rows else None


def _refresh(row):
    """Ask Stripe for the truth and persist it. Returns the (possibly updated) row."""
    sess = stripe.identity.VerificationSession.retrieve(row["stripe_session_id"])
    if sess.status != row["status"]:
        patch = {"status": sess.status, "updated_at": utc_now_iso()}
        if sess.status == "verified":
            patch["verified_at"] = utc_now_iso()
        _db().table(SESSIONS).update(patch).eq("id", row["id"]).execute()
        row = {**row, **patch}
    return row


@identity_bp.route("/statement", methods=["GET"])
def statement():
    return jsonify({"statement": STATEMENT, "version": STATEMENT_VERSION, "sha256": statement_sha256(), "consentVersion": CONSENT_VERSION})


@identity_bp.route("/receipt-key", methods=["GET"])
def receipt_key():
    """The public key that verifies ID-check receipts. Pin it in the app; do not trust it from this endpoint alone."""
    key = _receipt_key()
    if key is None:
        return jsonify({"error": "receipt-key-not-configured"}), 503
    pub, kid = receipt_public(key)
    return jsonify({"alg": "ECDSA-P256-SHA256", "kid": kid, "publicKey": pub})


@identity_bp.route("/start", methods=["POST"])
@require_auth
def start():
    body = request.get_json(silent=True) or {}
    if body.get("consent") is not True or body.get("consentVersion") != CONSENT_VERSION:
        return jsonify({"error": "consent-required"}), 400
    existing = _latest_session(g.user_id)
    if existing and existing["status"] == "verified":
        return jsonify({"sessionId": existing["stripe_session_id"], "status": "verified", "url": None})
    try:
        sess = stripe.identity.VerificationSession.create(
            type="document",
            options={"document": {"require_matching_selfie": True, "require_live_capture": True}},
            metadata={"user_id": str(g.user_id), "product": "shield_note"},
        )
    except stripe.error.StripeError:
        log.warning("Stripe Identity session create failed", exc_info=True)
        return jsonify({"error": "id-check-unavailable"}), 502
    _db().table(SESSIONS).insert({
        "user_id": g.user_id, "stripe_session_id": sess.id, "status": sess.status,
        "consent_at": utc_now_iso(), "consent_version": CONSENT_VERSION,
    }).execute()
    return jsonify({"sessionId": sess.id, "status": sess.status, "url": sess.url})


@identity_bp.route("/status", methods=["GET"])
@require_auth
def status():
    row = _latest_session(g.user_id)
    if not row:
        return jsonify({"status": "none", "verified": False})
    try:
        row = _refresh(row)
    except stripe.error.StripeError:
        return jsonify({"error": "id-check-unavailable"}), 502
    return jsonify({"sessionId": row["stripe_session_id"], "status": row["status"], "verified": row["status"] == "verified"})


@identity_bp.route("/note", methods=["POST"])
@require_auth
def note():
    row = _latest_session(g.user_id)
    if not row:
        return jsonify({"error": "no-id-check"}), 409
    try:
        row = _refresh(row)  # never trust a stored or client-supplied status
    except stripe.error.StripeError:
        return jsonify({"error": "id-check-unavailable"}), 502
    if row["status"] != "verified":
        return jsonify({"error": "id-check-not-verified", "status": row["status"]}), 409
    body = request.get_json(silent=True) or {}
    ok, reason, note_sha = verify_note(body, row["stripe_session_id"])
    if not ok:
        return jsonify({"error": reason}), 400
    # Fail closed: a note without a signed receipt would be the unverifiable kind this exists to avoid.
    key = _receipt_key()
    if key is None:
        return jsonify({"error": "receipt-key-not-configured"}), 503
    existing = _db().table(NOTES).select("*").eq("note_sha256", note_sha).limit(1).execute().data
    if existing:
        return jsonify({"attestationId": existing[0]["id"], "noteSha256": note_sha, "receipt": existing[0]["receipt"]})
    att_id = str(uuid.uuid4())
    receipt = make_receipt(key, attestation_id=att_id, note_sha256=note_sha,
                           device_seal_id=body["payload"]["deviceSealId"], session_id=row["stripe_session_id"])
    _db().table(NOTES).insert({
        "id": att_id, "user_id": g.user_id, "session_id": row["id"],
        "device_seal_id": body["payload"]["deviceSealId"], "device_public_key": body["devicePublicKey"],
        "statement_version": STATEMENT_VERSION, "note_payload": body["payload"], "note_sha256": note_sha,
        "signature": body["signature"], "signed_at": body["payload"]["signedAt"], "receipt": receipt,
    }).execute()
    return jsonify({"attestationId": att_id, "noteSha256": note_sha, "receipt": receipt}), 201


@identity_bp.route("/attestations/<att_id>", methods=["GET"])
def attestation(att_id):
    """Public, minimal: lets a third party confirm a note exists and its ID check passed. No personal data."""
    if not UUID_RE.match(att_id):
        return jsonify({"error": "not-found"}), 404
    rows = _db().table(NOTES).select("*").eq("id", att_id).limit(1).execute().data
    if not rows:
        return jsonify({"error": "not-found"}), 404
    n = rows[0]
    sess = _db().table(SESSIONS).select("status").eq("id", n["session_id"]).limit(1).execute().data
    verified = bool(sess) and sess[0]["status"] == "verified" and not n.get("revoked_at")
    return jsonify({
        "attestationId": n["id"], "verified": verified, "noteSha256": n["note_sha256"],
        "deviceSealId": n["device_seal_id"], "signedAt": n["signed_at"],
        "statementVersion": n["statement_version"], "provider": "stripe-identity",
    })
