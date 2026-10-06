"""The product a second business can actually buy.

`routes.py` is the original service: eighteen routes against TradeDeck's own
tables, through TradeDeck's own identity. It works, and it can never be sold to
anyone, because a caller has to exist as a row in somebody else's marketplace
before they can hold a record.

This is the same evidence loop with the coupling removed. A tenant presents an
API key or a member session, `tenancy.Principal` carries their `tenant_id`, and
every query is scoped on it before it runs. Parties are opaque strings the
tenant supplies -- `subject_ref` is whoever they mean by the party being
documented, `buyer_ref` whoever is paying for the assurance. Shield does not
resolve either and could not.

Separation by addition, again
-----------------------------
This does not edit `routes.py`. PR #7 made the same choice for the schema and
it was right: a half-ported module speaks two dialects and is worse than either
one. The legacy blueprint keeps serving what it serves until the last caller
leaves, and `legacy-auth-not-spreading` fails the build if the dead end grows.

The one rule this file exists to keep
--------------------------------------
**Nothing a caller sends is evidence.** The hash is computed here from the
bytes that arrived. EXIF is read here. The distance from site is measured here
against coordinates the *record* carries, which the uploader did not write.
A caller supplies a file and a checkpoint; everything sealed into the chain is
derived, and `webapp-sends-no-evidence` has a counterpart test for this module
for the same reason.

The parent's `/shield/analyze-photo` took `comp_url`, `has_exif`, `gps_lat` and
`original_hash` from the request body and never re-read the row it was about to
update, so a contractor could upload a real photo and point the analyser at a
stock image of perfect work. That is the mistake this file is shaped to make
impossible: no route here accepts a value it could derive.
"""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

import config
import android_attest
import app_attest
import attestation
import db as shield_db
import integrity
import ledger
import queue_ingest
import tenancy
import ticket
import tsa
import verdict as verdict_mod
from auth import require_record, require_tenant
from db import db

log = logging.getLogger(__name__)

bp = Blueprint("shield_v2", __name__, url_prefix="/shield/v2")

SCHEMA = "shield"
MAX_CHECKPOINTS = 40

#: Single-use capture challenges. Issued to one actor, spent once, on a clock.
#:
#: AR-9, restated where it bites rather than left in the register: this store
#: is per process. Under more than one gunicorn worker a challenge issued by
#: worker A is invisible to worker B, so a legitimate capture is refused
#: depending on which worker answers, and "single use" holds per worker rather
#: than per service. That is a correctness bug under load and an availability
#: one before it is a security one, and the fix is a shared store (the
#: database, or Redis) behind this same interface. Until the owner picks one,
#: run a single worker.
CHALLENGES = attestation.ChallengeStore()


def _t(name):
    return db().schema(SCHEMA).table(name)


def _err(message, code):
    return jsonify({"error": message}), code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _principal():
    return g.principal


def _issue_capture_token(record_id):
    """Generate and store a single-use capture challenge.

    Returns the nonce, or None if storage fails. Falls back to in-memory store.
    """
    principal = _principal()
    nonce = CHALLENGES.issue(principal.actor_id)
    CHALLENGES.purge()

    # Store in database for multi-worker persistence.
    try:
        expires_at = (datetime.now(timezone.utc) +
                      __import__('datetime').timedelta(
                          seconds=attestation.CHALLENGE_TTL_S))
        _t("capture_tokens").insert({
            "token": nonce,
            "tenant_id": str(principal.tenant_id),
            "actor_id": principal.actor_id,
            "record_id": record_id,
            "expires_at": expires_at.isoformat(),
        }).execute()
    except Exception:
        log.exception("Failed to store capture token")
        # In-memory store is still available as fallback.

    return nonce


def _consume_capture_token(nonce, principal=None):
    """Spend a single-use capture challenge.

    Checks both database and in-memory store. Returns True only for a live,
    unspent, non-expired nonce of the specified actor (or current principal).
    """
    if not nonce:
        return False

    if principal is None:
        principal = _principal()

    # Try database first.
    try:
        result = (_t("capture_tokens")
                  .select("token, actor_id, used_at, expires_at")
                  .eq("token", nonce)
                  .limit(1).execute()).data
        if result:
            row = result[0]
            # Check actor matches (single-use token tied to the actor it was issued to).
            if row.get("actor_id") != principal.actor_id:
                return False  # Wrong actor.
            # Check if already used or expired.
            if row.get("used_at"):
                return False  # Already spent.
            expires_at = row.get("expires_at")
            if expires_at:
                exp_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > exp_time:
                    return False  # Expired.
            # Mark as used.
            try:
                _t("capture_tokens").update(
                    {"used_at": _now()}
                ).eq("token", nonce).execute()
            except Exception:
                log.exception("Failed to mark capture token as used")
            return True
    except Exception:
        log.exception("Failed to check capture token in database")

    # Fall back to in-memory store.
    return CHALLENGES.consume(nonce, principal.actor_id)


# --------------------------------------------------------------- the chain --
def chain_in_order(entries, record_id):
    """Put a record's custody entries in causal order by following the links.

    Sorting on `recorded_at` is the obvious approach and it is wrong. Several
    entries can be written inside one request -- a retake writes `superseded`
    and then `uploaded` -- and they can land on the same timestamp, at which
    point the order is whatever the database felt like. A chain assembled in
    the wrong order fails to verify, and the failure looks exactly like
    tampering, which is the worst possible way to be wrong.

    The links already encode the order, so use them: start at the genesis hash
    and follow `prev_hash` -> `entry_hash`. Anything that does not hang off
    that walk is returned afterwards, in timestamp order, rather than dropped
    -- a verifier must be given every row we hold, including the ones that do
    not fit, because silently omitting an entry would turn a broken chain into
    a clean one.
    """
    by_prev = {}
    for entry in entries:
        by_prev.setdefault(entry.get("prev_hash"), []).append(entry)

    ordered, seen = [], set()
    cursor = ledger.genesis_hash(record_id)
    while True:
        candidates = [e for e in by_prev.get(cursor, []) if id(e) not in seen]
        if not candidates:
            break
        # A fork would mean two entries share a predecessor. Take the first and
        # let the orphan pass below carry the other, so verify_chain reports it
        # rather than this function hiding it.
        entry = candidates[0]
        ordered.append(entry)
        seen.add(id(entry))
        cursor = entry.get("entry_hash")

    orphans = [e for e in entries if id(e) not in seen]
    orphans.sort(key=lambda e: e.get("recorded_at") or "")
    return ordered + orphans


def _head_and_append(record_id, entry):
    """Seal one entry onto a record's chain and insert it.

    Read-then-append is a race if two writes land together. The unique index
    on `entry_hash` is what actually protects the chain: two entries computed
    from the same predecessor produce different hashes only if their content
    differs, and identical content would be a duplicate anyway. A conflict
    there means a genuine concurrent write, and failing the request is better
    than writing a fork and calling it evidence.
    """
    principal = _principal()
    existing = (_t("custody_log")
                .select("entry_hash,prev_hash,recorded_at")
                .eq("record_id", record_id).execute()).data or []
    ordered = chain_in_order(existing, record_id)
    prev = (ordered[-1].get("entry_hash") if ordered
            else ledger.genesis_hash(record_id))

    body = {
        "record_id": record_id,
        "photo_id": entry.get("photo_id"),
        "event_type": entry["event_type"],
        "actor_ref": principal.actor_id,
        "actor_kind": "api_key" if principal.is_api_key else "member",
        "event_data": entry.get("event_data"),
        "gps_lat": entry.get("gps_lat"),
        "gps_lng": entry.get("gps_lng"),
        "file_hash": entry.get("file_hash"),
        "integrity_note": entry.get("integrity_note"),
        "recorded_at": _now(),
    }
    # ledger.seal() normalises event_data and stamps chain_version, so the row
    # stored is the row that was hashed. See SPEC.md section 7.
    sealed = ledger.seal(body, prev)
    sealed["tenant_id"] = principal.tenant_id
    _t("custody_log").insert(sealed).execute()
    return sealed["entry_hash"]


# ------------------------------------------------------------------ whoami --
@bp.route("/whoami", methods=["GET"])
@require_tenant
def whoami():
    """What this credential is, so an integrator can check their wiring."""
    principal = _principal()
    try:
        res = (_t("tenants").select("name,slug,status")
               .eq("id", principal.tenant_id).limit(1).execute())
        tenant = (res.data or [{}])[0]
    except Exception:
        log.exception("Tenant lookup failed")
        return _err("Could not load the tenant", 500)

    return jsonify({
        "tenant": {"id": principal.tenant_id, **tenant},
        "credential": "api_key" if principal.is_api_key else "member",
        "role": principal.role,
        "chain_version": ledger.CHAIN_VERSION,
    })


# ----------------------------------------------------------------- records --
@bp.route("/records", methods=["POST"])
@require_tenant
def create_record():
    """Open a record. `external_ref` is the tenant's own identifier for it."""
    principal = _principal()
    if principal.is_member and principal.role == "viewer":
        return _err("This account has read-only access", 403)

    data = request.get_json(silent=True) or {}
    external_ref = (data.get("external_ref") or "").strip()
    if not external_ref:
        return _err("external_ref is required — it is how you will find this "
                    "record in your own system", 400)

    lat, lng = data.get("site_lat"), data.get("site_lng")
    if (lat is None) != (lng is None):
        return _err("site_lat and site_lng must be given together", 400)
    try:
        lat = None if lat is None else float(lat)
        lng = None if lng is None else float(lng)
    except (TypeError, ValueError):
        return _err("site_lat and site_lng must be numbers", 400)

    subject = (data.get("subject_ref") or "").strip() or None
    buyer = (data.get("buyer_ref") or "").strip() or None
    if subject and buyer and subject == buyer:
        return _err("subject_ref and buyer_ref must differ — one party cannot "
                    "both do the work and attest to it", 400)

    row = {
        "tenant_id": principal.tenant_id,
        "external_ref": external_ref,
        "subject_ref": subject,
        "buyer_ref": buyer,
        "trade": (data.get("trade") or "").strip() or None,
        "site_address": (data.get("site_address") or "").strip() or None,
        "site_lat": lat,
        "site_lng": lng,
    }
    try:
        res = _t("records").insert(row).execute()
    except Exception as exc:
        # The (tenant_id, external_ref) unique index is deliberate: it is what
        # lets two tenants use the same reference without colliding, and stops
        # one tenant opening the same record twice.
        if "records_tenant_id_external_ref_key" in str(exc) or "duplicate key" in str(exc):
            return _err(f"You already have a record with external_ref "
                        f"{external_ref!r}", 409)
        log.exception("Record insert failed")
        return _err("Could not create the record", 500)

    record = (res.data or [{}])[0]
    _head_and_append(record["id"], {
        "event_type": "created",
        "event_data": {"external_ref": external_ref, "trade": row["trade"]},
        "gps_lat": lat, "gps_lng": lng,
    })
    return jsonify({"record": record}), 201


@bp.route("/records", methods=["GET"])
@require_tenant
def list_records():
    """The tenant's records. Scoped, so there is no other tenant's to leak."""
    try:
        query = _t("records").select(
            "id,external_ref,subject_ref,buyer_ref,trade,site_address,"
            "status,created_at,completed_at,checkpoints_locked_at")
        res = (tenancy.scope(query, _principal())
               .order("created_at", desc=True).limit(200).execute())
    except Exception:
        log.exception("Record list failed")
        return _err("Could not list records", 500)
    return jsonify({"records": res.data or []})


@bp.route("/records/<record_id>", methods=["GET"])
@require_tenant
@require_record(writable=False)
def get_record(record_id):
    """One record with its checkpoints and the live photo for each."""
    try:
        points = (_t("checkpoints").select("*")
                  .eq("record_id", record_id)
                  .order("point_number").execute()).data or []
        photos = (_t("photos").select(
            "id,checkpoint_id,original_hash,verdict,verdict_confidence,"
            "verdict_notes,has_exif,gps_lat,gps_lng,site_distance_m,"
            "integrity_note,attestation_tier,uploaded_at,superseded_by,"
            "superseded_at")
            .eq("record_id", record_id).order("uploaded_at").execute()).data or []
    except Exception:
        log.exception("Record detail failed for %s", record_id)
        return _err("Could not load the record", 500)

    live = [p for p in photos if verdict_mod.is_live(p)]
    by_point = {}
    for photo in live:
        by_point[photo["checkpoint_id"]] = photo

    return jsonify({
        "record": g.record,
        "checkpoints": [{**p, "live_photo": by_point.get(p["id"])} for p in points],
        "photos_total": len(photos),
        "photos_superseded": len(photos) - len(live),
    })


# ------------------------------------------------------------- checkpoints --
@bp.route("/records/<record_id>/checkpoints", methods=["POST"])
@require_tenant
@require_record()
def set_checkpoints(record_id):
    """Define the checkpoints, then lock them.

    Locking is the point. A checkpoint list that can be edited after photos
    start arriving is not a commitment -- the party being documented could drop
    the checkpoint they failed and the record would still read as complete.
    Once locked, the set is the set.
    """
    if g.record.get("checkpoints_locked_at"):
        return _err("Checkpoints are locked for this record. They are fixed "
                    "once set, so a failed checkpoint cannot be removed after "
                    "the fact.", 409)

    data = request.get_json(silent=True) or {}
    items = data.get("checkpoints")
    if not isinstance(items, list) or not items:
        return _err("checkpoints must be a non-empty list", 400)
    if len(items) > MAX_CHECKPOINTS:
        return _err(f"At most {MAX_CHECKPOINTS} checkpoints per record", 400)

    rows = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            return _err(f"Checkpoint {index} must be an object", 400)
        label = (item.get("label") or "").strip()
        if not label:
            return _err(f"Checkpoint {index} needs a label", 400)
        rows.append({
            "tenant_id": _principal().tenant_id,
            "record_id": record_id,
            "point_number": index,
            "label": label,
            "description": (item.get("description") or "").strip() or None,
            "code_reference": (item.get("code_reference") or "").strip() or None,
            "must_show": (item.get("must_show") or "").strip() or None,
        })

    try:
        res = _t("checkpoints").insert(rows).execute()
        _t("records").update({"checkpoints_locked_at": _now()}) \
            .eq("id", record_id).execute()
    except Exception:
        log.exception("Checkpoint insert failed for %s", record_id)
        return _err("Could not set the checkpoints", 500)

    _head_and_append(record_id, {
        "event_type": "checkpoints_locked",
        "event_data": {"count": len(rows),
                       "labels": [r["label"] for r in rows]},
    })
    return jsonify({"checkpoints": res.data or [], "locked": True}), 201


def _b64(value):
    """Decode base64 from an untrusted client. None rather than an exception.

    Accepts standard and URL-safe alphabets with or without padding, because
    which one arrives depends on how the client happened to encode it, and a
    capture refused over an alphabet choice would be indistinguishable on the
    device from a refused attestation.
    """
    if not value:
        return None
    text = value.strip()
    text += "=" * (-len(text) % 4)
    # validate=True is load-bearing, not tidiness. Without it `b64decode`
    # *discards* characters outside the standard alphabet instead of
    # raising, so a URL-safe string decodes to short, silently wrong bytes
    # and the urlsafe branch below is never reached. A 32-byte key id
    # arrives as 26 and the capture is refused with "the attested key does
    # not match the key id presented" -- which names the wrong cause, and a
    # refusal that misdiagnoses itself is how a real problem gets chased in
    # the wrong direction.
    # `urlsafe_b64decode` takes no validate flag, so the alternative alphabet
    # is passed to b64decode as altchars instead -- same result, and both
    # attempts then reject rather than discard.
    for altchars in (None, b"-_"):
        try:
            return base64.b64decode(text, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


@bp.route("/records/<record_id>/capture-challenge", methods=["POST"])
@require_tenant
@require_record()
def capture_challenge(record_id):
    """Issue the single-use nonce one capture must be bound to.

    Without this the app could present the same attestation for every upload
    forever, including uploads of files the device never saw. The nonce is
    what makes an attestation say *this capture* rather than "this device was
    genuine at some point".

    It is issued to the calling actor and spent by them, so one party cannot
    have their challenge answered by another party's device.
    """
    nonce = _issue_capture_token(record_id)

    return jsonify({
        "challenge": nonce,
        "expires_in_s": attestation.CHALLENGE_TTL_S,
        "client_data_hash_alg": "sha256",
        "note": ("clientDataHash = SHA-256(challenge || SHA-256(photo bytes)), "
                 "for DCAppAttestService.attestKey on a key's first capture "
                 "and generateAssertion after it. Send the challenge back "
                 "verbatim as attestation_challenge."),
    }), 201


def _attestation_for(req, principal, payload_sha256):
    """Decide whether one capture may be recorded at all.

    Returns attestation.assess()'s verdict. The only tiers that count are the
    two in `attestation.TRUSTED_TIERS`; absence, ambiguity and refusal are all
    the same answer here, which is no.

    Two things this function is careful never to do. It does not accept a
    caller's word that verification happened -- `verified` comes only from
    `app_attest.verify` or `app_attest.verify_assertion`, which check the
    cryptography themselves. And it does not treat a missing trust anchor as a
    reason to skip the chain check: with no root configured, `verify` refuses,
    and so does this.

    The challenge is spent exactly once, whatever the outcome. A failed
    attestation that left the nonce live would let an attacker grind attempts
    against one challenge until something stuck.

    `payload_sha256` is the digest of the bytes that actually arrived,
    computed here, and the attestation must be bound to it. Without that the
    attestation says a genuine app was running when the nonce was issued and
    nothing at all about the file in the same request — so an attacker with a
    real iPhone attests honestly and uploads a stock photograph.

    Two shapes reach trust on iOS. `attestation` is the first capture from a
    key: the full chain to Apple's root, after which the key's public half is
    stored. `assertion` is every capture after that: a Secure Enclave
    signature checked against the stored key, whose counter must advance.
    Both commit to the same client data -- challenge and photo digest -- so
    the binding argument above holds for either.
    """
    platform = (req.form.get("attestation_platform") or "").strip().lower()
    token = (req.form.get("attestation") or "").strip()
    assertion = (req.form.get("assertion") or "").strip()
    nonce = (req.form.get("attestation_challenge") or "").strip()
    if not token and not assertion:
        return {"trusted": False, "tier": attestation.TIER_UNATTESTED,
                "reason": "no device attestation was presented."}

    challenge_ok = _consume_capture_token(nonce, principal)

    if token and assertion:
        return {"trusted": False, "tier": attestation.TIER_UNVERIFIABLE,
                "reason": "both an attestation and an assertion were "
                          "presented; a capture carries exactly one."}

    allow_dev = config.get("APP_ATTEST_ALLOW_DEVELOPMENT") == "1"
    app_id = config.get("APP_ATTEST_APP_ID") or ""
    extra = {}
    checked = key_row = None
    if platform in ("ios", "android") and assertion:
        checked, key_row, extra = _check_assertion(
            assertion, req.form.get("attestation_key_id"), principal,
            platform=platform, challenge=nonce,
            payload_sha256=payload_sha256, app_id=app_id,
            allow_development=allow_dev)
        interpret = (attestation.interpret_app_attest if platform == "ios"
                     else attestation.interpret_key_attestation)
        kw = ({} if platform == "ios"
              else {"security_level": (key_row or {}).get("security_level")})
        verdict = interpret(
            verified=checked["verified"],
            receipt_ok=checked["receipt_ok"],
            token_nonce=checked["token_nonce"],
            expect_nonce=nonce or None, **kw)
    elif platform == "ios":
        blob = _b64(token)
        if blob is None:
            verdict = attestation.interpret_app_attest(verified=False)
        else:
            checked = app_attest.verify(
                blob,
                challenge=nonce,
                payload_sha256=payload_sha256,
                app_id=app_id,
                key_id=_b64(req.form.get("attestation_key_id")),
                root_pem=config.get("APPLE_APP_ATTEST_ROOT_PEM"),
                allow_development=allow_dev)
            if not checked["verified"]:
                log.info("App Attest refused for record: %s", checked["reason"])
            verdict = attestation.interpret_app_attest(
                verified=checked["verified"],
                receipt_ok=checked["receipt_ok"],
                token_nonce=checked["token_nonce"],
                expect_nonce=nonce or None)
    elif platform == "android":
        # Key Attestation: a certificate chain, leaf first, as comma-separated
        # base64 DER. Checked here against the configured Google roots; Play
        # Integrity is not used, because its tokens can only be decoded by a
        # call to Google on every capture.
        chain = [_b64(part) for part in token.split(",")]
        if not chain or any(c is None for c in chain):
            verdict = attestation.interpret_key_attestation(verified=False)
        else:
            checked = android_attest.verify(
                chain,
                challenge=nonce,
                payload_sha256=payload_sha256,
                package_name=config.get("ANDROID_PACKAGE_NAME") or "",
                signing_digests=config.android_signing_digests(),
                roots_pem=config.get("ANDROID_ATTESTATION_ROOTS_PEM"),
                revoked=android_attest.revoked_serials(
                    config.get("ANDROID_ATTESTATION_STATUS_URL")))
            if not checked["verified"]:
                log.info("Key attestation refused for record: %s",
                         checked["reason"])
            verdict = attestation.interpret_key_attestation(
                verified=checked["verified"],
                receipt_ok=checked["receipt_ok"],
                token_nonce=checked["token_nonce"],
                expect_nonce=nonce or None,
                security_level=checked.get("security_level"))
    else:
        return {"trusted": False, "tier": attestation.TIER_UNVERIFIABLE,
                "reason": f"attestation_platform {platform!r} is not one this "
                          f"service can check."}

    result = attestation.assess(platform=platform, verdict=verdict,
                                challenge_ok=challenge_ok if nonce else None)
    result.update(extra)
    if not result["trusted"]:
        return result

    if assertion and platform == "ios":
        # The compare-and-set is what makes the counter check hold across
        # requests. `verify_assertion` compared against the value it was
        # handed; this refuses if another upload advanced it in between.
        if not _advance_counter(key_row["key_id"], checked["counter"]):
            return {"trusted": False, "tier": attestation.TIER_UNVERIFIABLE,
                    "reason": "this assertion was already used for another "
                              "capture."}
    elif assertion:
        # Android keys carry no counter. The single-use challenge the
        # signature covers was spent above, which is what stops a replay.
        _touch_key(key_row["key_id"])
    else:
        result["key_registered"] = _register_key(checked, principal, platform)
    return result


def _check_assertion(assertion, key_id_field, principal, *, platform,
                     previous_counter=None, **kw):
    """Look the key up, then verify. Returns (checked, key_row, extra).

    `extra` carries `reattest: True` when the refusal is about the key rather
    than the capture -- unknown, revoked, or attested under a different
    credential. The app answers that by attesting a fresh key, which is the
    one recovery it has, so saying so saves it guessing from the prose.

    The key refusals share one message on purpose. "This key belongs to
    somebody else" would confirm to a caller that a key id they hold is live.
    A key attested on one platform is unknown on the other: an iOS key is
    checked as an App Attest assertion, an Android key as a plain signature,
    and the two must not be confusable.
    """
    unknown = ({**app_attest._no("this device's key is not on file for this "
                                 "credential, so the capture must be attested "
                                 "afresh"), "counter": None},
               None, {"reattest": True})
    raw_key_id = _b64(key_id_field)
    blob = _b64(assertion)
    if raw_key_id is None or blob is None:
        return ({**app_attest._no("the assertion or its key id is not valid "
                                  "base64"), "counter": None}, None, {})
    key_id = base64.b64encode(raw_key_id).decode()
    try:
        rows = (_t("attested_keys").select("*").eq("key_id", key_id)
                .limit(1).execute()).data or []
    except Exception:
        log.exception("Attested key lookup failed")
        return ({**app_attest._no("the device key could not be looked up"),
                 "counter": None}, None, {})
    row = rows[0] if rows else None
    if (row is None or row.get("revoked_at")
            or (row.get("platform") or "ios") != platform
            or str(row.get("tenant_id")) != str(principal.tenant_id)
            or str(row.get("actor_id")) != str(principal.actor_id)):
        return unknown

    if platform == "ios":
        # A batch checks each assertion against the counter the previous
        # one in that batch advanced to. One signature still uses the
        # counter stored for the key.
        if previous_counter is None:
            previous_counter = row.get("sign_count") or 0
        checked = app_attest.verify_assertion(
            blob, public_key=_b64(row.get("public_key")),
            previous_counter=previous_counter,
            environment=row.get("environment") or "production", **kw)
    else:
        checked = android_attest.verify_signature(
            blob, challenge=kw["challenge"],
            payload_sha256=kw["payload_sha256"],
            public_key=_b64(row.get("public_key")))
    if not checked["verified"]:
        log.info("App Attest assertion refused: %s", checked["reason"])
    return checked, row, {}


def _advance_counter(key_id, counter):
    """Compare-and-set the key's counter. True only if this call moved it."""
    try:
        res = (_t("attested_keys")
               .update({"sign_count": counter, "last_used_at": _now()})
               .eq("key_id", key_id).lt("sign_count", counter).execute())
    except Exception:
        log.exception("Counter update failed for an attested key")
        return False
    return bool(res.data)


def _touch_key(key_id):
    """Record that a counterless key was used. Best effort; never refuses."""
    try:
        _t("attested_keys").update({"last_used_at": _now()}) \
            .eq("key_id", key_id).execute()
    except Exception:
        log.exception("Could not record use of an attested key")


def _register_key(checked, principal, platform):
    """Keep a verified attestation's public key for the captures after it.

    A failure here does not unrecord the capture -- that photograph was
    attested in full -- it only means the next one must attest again, which
    the response tells the app through `attestation_key_registered`.
    """
    try:
        _t("attested_keys").insert({
            "key_id": base64.b64encode(checked["key_id"]).decode(),
            "tenant_id": principal.tenant_id,
            "actor_id": str(principal.actor_id),
            "public_key": base64.b64encode(checked["public_key"]).decode(),
            "platform": platform,
            "security_level": checked.get("security_level"),
            "environment": checked["environment"],
            "receipt": (base64.b64encode(checked["receipt"]).decode()
                        if checked.get("receipt") else None),
            "sign_count": 0,
            "attested_at": _now(),
        }).execute()
    except Exception:
        log.exception("Could not store an attested key")
        return False
    return True


# --------------------------------------------------------------- job ticket --
def _signing_key_or_refuse():
    """503 when this deployment cannot sign a ticket. Stores nothing."""
    if ticket.load_signing_key() is None:
        log.error("SHIELD_TICKET_SIGNING_KEY_PEM is not set; genesis is closed")
        return _err("This deployment cannot issue a job ticket.", 503)
    return None


def _checkpoint_rows(record_id):
    query = (_t("checkpoints")
             .select("id,point_number,label,description,code_reference,must_show")
             .eq("record_id", record_id))
    return (tenancy.scope(query, _principal()).execute()).data or []


def _play_for(platform, body, ticket_hash_hex):
    """The one Play Integrity reading stored beside this ticket.

    ``verified`` is false here on purpose. Checking a Play Integrity token
    means a call to Google, and this release does not make one. A body the
    client sends is therefore unverifiable, never a pass. iOS ignores a
    body entirely: there is no Play Integrity API, and App Attest does not
    report jailbreak.
    """
    if platform == "android" and body.get("play_integrity") is not None:
        classified = ticket.classify_play_integrity(
            body.get("play_integrity"),
            verified=False,
            expect_nonce=ticket_hash_hex,
            expect_package=config.get("ANDROID_PACKAGE_NAME") or None,
            platform="android")
    else:
        classified = ticket.classify_play_integrity(None, platform=platform)
    return classified


def _offer_genesis(record_id, platform, points):
    """Hand the phone a signed ticket. Do not write a row.

    The phone has to see the bytes before it can sign their hash. The
    signature on the way back is what makes a row. Keeping the offer in
    the per-process challenge jar would hide it from the other gunicorn
    worker; the server signature is what the other worker checks instead.
    """
    principal = _principal()
    try:
        listed = ticket.checkpoint_list_hash(points)
        rough = ticket.outside_clock_ms(
            enabled=config.roughtime_enabled(), fetch=ticket.roughtime_fetch)
        built = ticket.build_ticket(
            record_id=record_id,
            checkpoint_list_sha256=listed,
            actor_id=str(principal.actor_id),
            server_time_ms=ticket.now_ms(),
            roughtime_ms=rough)
        signed = ticket.sign_ticket(built)
    except ticket.TicketKeyError:
        return _signing_key_or_refuse() or _err(
            "This deployment cannot issue a job ticket.", 503)
    except ValueError as exc:
        log.info("Job ticket offer refused: %s", exc)
        return _err("The checkpoint list cannot be committed to.", 409)

    public = ticket.export_public_key()
    return jsonify({
        "stored": False,
        "ticket_id": signed["ticket_hash"],
        "ticket_hash": signed["ticket_hash"],
        "ticket": signed["ticket"],
        "server_signature": signed["server_signature"],
        "server_public_key": public,
        "sign_with_attested_key": {
            "challenge": ticket.GENESIS_CHALLENGE,
            "ticket_hash": signed["ticket_hash"],
            "note": (
                "Measure the phone clocks now and send them back as "
                "ticket_clock: wall_time_ms, monotonic_ms, and boot_id "
                "and/or boot_count. clientData is the UTF-8 bytes of the "
                "challenge followed by SHA-256 of the raw 32-byte ticket "
                "hash concatenated with the canonical JSON of that clock. "
                "The clock JSON uses sorted keys and tight separators. "
                "iOS passes SHA-256(clientData) to generateAssertion. "
                "Android signs clientData with SHA256withECDSA and does not "
                "pre-hash it. Send the ticket, ticket_clock, and this "
                "server_signature back with that signature. Nothing is "
                "stored until that signature verifies."),
        },
    })


def _seal_genesis(record_id, platform, body, points):
    """Store the ticket only after both signatures verify.

    A missing or invalid hardware signature stores nothing. The same rule
    as a photograph: an unverified capture is not a row.
    """
    presented = body.get("ticket")
    assertion = (body.get("assertion") or "").strip()
    server_sig = body.get("server_signature")
    if not isinstance(presented, dict):
        return _err("The job ticket was not presented.", 422)
    try:
        signed = ticket.verify_server_signature(presented, server_sig)
    except ticket.TicketKeyError:
        return _signing_key_or_refuse() or _err(
            "This deployment cannot issue a job ticket.", 503)
    except ValueError as exc:
        log.info("Job ticket rejected: %s", exc)
        return _err("This ticket is not one this service can accept. "
                    "Nothing was stored.", 422)
    if not signed["ok"]:
        log.info("Job ticket signature refused: %s", signed["reason"])
        return _err("This ticket does not match the server signature. "
                    "Nothing was stored.", 422)

    canonical_ticket = signed["ticket"]
    try:
        listed = ticket.checkpoint_list_hash(points)
    except ValueError:
        return _err("The checkpoint list cannot be committed to.", 409)
    blocked = ticket.seal_blocks(
        canonical_ticket,
        record_id=record_id,
        actor_id=_principal().actor_id,
        checkpoint_list_sha256=listed,
        now_ms=ticket.now_ms())
    if blocked:
        return _err(blocked + " Nothing was stored.", 422)
    if not assertion:
        return _err("A hardware signature over the ticket hash is required. "
                    "Nothing was stored.", 422)
    try:
        clock = ticket.normalize_clock(body.get("ticket_clock"))
    except ValueError as exc:
        return _err("The phone clock at ticket time could not be read "
                    f"({exc}). Nothing was stored.", 422)

    challenge, payload_sha256 = ticket.hardware_binding(
        signed["ticket_hash"], clock)
    allow_dev = config.get("APP_ATTEST_ALLOW_DEVELOPMENT") == "1"
    checked, key_row, extra = _check_assertion(
        assertion, body.get("attestation_key_id"), _principal(),
        platform=platform, challenge=challenge,
        payload_sha256=payload_sha256,
        app_id=config.get("APP_ATTEST_APP_ID") or "",
        allow_development=allow_dev)
    if checked["verified"] is not True or key_row is None:
        return jsonify({
            "error": (
                "This job ticket was not accepted: the hardware signature "
                "does not verify. Nothing was stored."),
            "reattest": bool(extra.get("reattest")),
            "stored": False,
        }), 422

    if platform == "ios":
        # Compare-and-set, same as a capture assertion. A failure here means
        # the assertion was already used. Do it before the insert so a lost
        # race does not leave a ticket whose signature can be replayed.
        if not _advance_counter(key_row["key_id"], checked["counter"]):
            return _err("This assertion was already used. Nothing was stored.",
                        422)
    else:
        _touch_key(key_row["key_id"])

    play = _play_for(platform, body, signed["ticket_hash"])
    row = {
        "id": str(uuid.uuid4()),
        "tenant_id": _principal().tenant_id,
        "record_id": record_id,
        "actor_id": str(_principal().actor_id),
        "platform": platform,
        "key_id": key_row["key_id"],
        "ticket_hash": signed["ticket_hash"],
        "checkpoint_list_sha256": canonical_ticket["checkpoint_list_sha256"],
        "server_time_ms": canonical_ticket["server_time_ms"],
        "expires_at_ms": canonical_ticket["expires_at_ms"],
        "roughtime_ms": canonical_ticket.get("roughtime_ms"),
        "ticket_json": canonical_ticket,
        "ticket_clock": clock,
        "server_signature": server_sig.strip() if isinstance(server_sig, str) else server_sig,
        "hardware_signature": assertion,
        "created_at": _now(),
    }
    row.update(ticket.play_integrity_columns(play))
    try:
        shield_db.insert_job_ticket(row)
    except Exception:
        log.exception("Job ticket insert failed for %s", record_id)
        return _err("Could not store the job ticket.", 500)
    return jsonify({
        "stored": True,
        "id": row["id"],
        "ticket_id": row["ticket_hash"],
        "ticket_hash": row["ticket_hash"],
        "ticket": canonical_ticket,
        "ticket_clock": clock,
        "server_signature": row["server_signature"],
        "server_public_key": ticket.export_public_key(),
        "play_integrity": {
            "status": play["status"],
            "tier": play["tier"],
            "reason": play["reason"],
        },
        "chain_version": ledger.CHAIN_VERSION,
    }), 201


@bp.route("/records/<record_id>/genesis", methods=["POST"])
@require_tenant
@require_record()
def genesis(record_id):
    """Issue a job ticket, then store it once the phone has signed it.

    Two calls, one route. The first carries no signature and returns the
    ticket to sign; it writes nothing. The second carries the ticket, the
    server signature, and the hardware signature. A missing or invalid
    hardware signature is refused and writes nothing, the same rule as
    ``upload_photo``.

    The attested install key must already be on file. This route does not
    attest a new key.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _err("The request body must be a JSON object.", 400)
    platform = (body.get("platform") or "").strip().lower()
    if platform not in ("ios", "android"):
        return _err("platform must be ios or android", 400)
    if not g.record.get("checkpoints_locked_at"):
        return _err("Checkpoints must be locked before a job ticket can be "
                    "issued.", 409)

    refused = _signing_key_or_refuse()
    if refused:
        return refused

    try:
        existing = shield_db.find_job_ticket(_principal().tenant_id, record_id)
    except Exception:
        log.exception("Job ticket lookup failed for %s", record_id)
        return _err("Could not load the job ticket", 500)
    if existing:
        return _err("This record already has a job ticket.", 409)

    try:
        points = _checkpoint_rows(record_id)
    except Exception:
        log.exception("Checkpoint read failed for genesis %s", record_id)
        return _err("Could not load the checkpoints", 500)
    if not points:
        return _err("This record has no checkpoints to commit to.", 409)

    presented = body.get("ticket")
    assertion = (body.get("assertion") or "").strip()
    if presented is None and not assertion:
        return _offer_genesis(record_id, platform, points)
    return _seal_genesis(record_id, platform, body, points)


# --------------------------------------------------------------- the queue --
def _queue_signatures(accepted, principal, platform, key_id_field, ticket_key_id):
    """Every capture in the batch, with the verifiers a photograph already uses.

    Returns ``(key_row, last_counter, error)``. ``last_counter`` is the iOS
    counter to persist, or None on Android. A failure means nothing in the
    batch is stored. Counters are not advanced here; the caller does that
    only after every signature has verified.
    """
    previous = None
    key_row = None
    last_counter = None
    allow_dev = config.get("APP_ATTEST_ALLOW_DEVELOPMENT") == "1"
    app_id = config.get("APP_ATTEST_APP_ID") or ""
    for index, item in enumerate(accepted):
        assertion = item.get("assertion")
        if not isinstance(assertion, str) or not assertion.strip():
            return None, None, (
                f"Capture {index + 1} has no hardware signature. "
                f"Nothing was stored.")
        try:
            challenge, payload = queue_ingest.hardware_binding(item["record_hash"])
        except ValueError:
            return None, None, (
                f"Capture {index + 1} has no record hash to bind a signature "
                f"to. Nothing was stored.")
        checked, key_row, extra = _check_assertion(
            assertion.strip(), key_id_field, principal,
            platform=platform, challenge=challenge, payload_sha256=payload,
            app_id=app_id, allow_development=allow_dev,
            previous_counter=previous)
        if checked["verified"] is not True or key_row is None:
            return None, None, (
                f"Capture {index + 1} was not accepted: the hardware "
                f"signature does not verify. Nothing was stored.")
        if str(key_row.get("key_id") or "") != str(ticket_key_id or ""):
            return None, None, (
                "This batch was signed by a different key than the job "
                "ticket. Nothing was stored.")
        if platform == "ios":
            previous = checked["counter"]
            last_counter = checked["counter"]
        # The running counter is what the next assertion in this batch has
        # to pass. Android has no counter; the chain head stops a replay.
        _ = extra
    return key_row, last_counter, None


def _store_batch_photos(record_id, accepted, tiers):
    """Write the photographs. The custody entry for the batch is separate.

    A second photograph of the same checkpoint supersedes the live one, the
    same way a single upload does, but that supersession is recorded inside
    the one batch entry rather than as its own custody event. One batch is
    one link.
    """
    photo_ids = []
    for item, tier in zip(accepted, tiers):
        raw = item["photo"]
        mime = integrity.sniff_mime(raw)
        computed = integrity.sha256(raw)
        claimed = item["record"].get("photo_sha256")
        if (not isinstance(claimed, str) or len(claimed) != len(computed)
                or not hmac.compare_digest(claimed, computed)):
            return None
        assessment = integrity.assess(
            raw, mime, None, None, config.get_int("GPS_TOLERANCE_M"))
        checkpoint_id = item["checkpoint_id"]
        try:
            previous = (_t("photos").select("id")
                        .eq("checkpoint_id", checkpoint_id)
                        .eq("record_id", record_id)
                        .is_("superseded_at", "null")
                        .execute()).data or []
        except Exception:
            log.exception("Live-photo lookup failed for %s", checkpoint_id)
            previous = []
        photo_id = str(uuid.uuid4())
        ext = {"image/jpeg": "jpg", "image/png": "png",
               "image/webp": "webp", "image/heic": "heic",
               "image/heif": "heif"}.get(mime, "bin")
        storage_path = f"{_principal().tenant_id}/{record_id}/{photo_id}.{ext}"
        try:
            db().storage.from_(config.get("SHIELD_BUCKET")).upload(
                storage_path, raw, {"content-type": mime, "upsert": "false"})
        except Exception:
            log.exception("Storage write failed for %s", photo_id)
            return None
        # Supersede before the insert so two live rows for one checkpoint
        # are not both claiming the requirement.
        for old in previous:
            if old.get("id") == photo_id:
                continue
            try:
                _t("photos").update({"superseded_by": photo_id,
                                     "superseded_at": _now()}) \
                    .eq("id", old["id"]).execute()
            except Exception:
                log.exception("Could not mark %s superseded", old.get("id"))
        row = {
            "id": photo_id,
            "tenant_id": _principal().tenant_id,
            "record_id": record_id,
            "checkpoint_id": checkpoint_id,
            "storage_path": storage_path,
            "original_hash": computed,
            "original_size_bytes": len(raw),
            "has_exif": assessment.get("has_exif"),
            "integrity_note": assessment.get("integrity_note"),
            "attestation_tier": tier,
            "received_at": _now(),
        }
        # Rightmost hop. The leftmost entry is whatever the client sent.
        # Render adds one trusted proxy, same rule as routes.client_ip.
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            ip = xff.split(",")[-1].strip()
        else:
            ip = request.remote_addr or ""
        if ip:
            row["upload_ip_hash"] = integrity.hash_ip(
                ip, config.get("IP_HASH_SALT"))
        try:
            _t("photos").insert(row).execute()
        except Exception:
            log.exception("Photo insert failed for %s", photo_id)
            return None
        photo_ids.append(photo_id)
    return photo_ids


def _time_labels(prepared):
    return [{
        "record_hash": item["record_hash"],
        "verdict": item["time"]["verdict"],
        "labels": list(item["time"]["labels"]),
        "flags": item["time"]["flags"],
        "flag_names": list(item["time"]["flag_names"]),
    } for item in prepared["accepted"]]


def _receipt_view(row, token_row):
    """The receipt and timestamp the package and the batch response share."""
    if not row:
        return None, tsa.missing_timestamp("This record has no receipt yet.")
    body = row.get("receipt_json") if isinstance(row.get("receipt_json"), dict) else {}
    signed = body.get("signed") if isinstance(body.get("signed"), dict) else {
        "version": tsa.RECEIPT_VERSION,
        "record_id": row.get("record_id"),
        "head_hash": row.get("head_hash"),
        "accepted_at_ms": row.get("accepted_at_ms"),
    }
    receipt = {
        "signed": signed,
        "signature": row.get("server_signature"),
        "phone_chain_head": row.get("phone_chain_head"),
        "time_labels": body.get("time_labels") or [],
        "head_hash": row.get("head_hash"),
        "accepted_at_ms": row.get("accepted_at_ms"),
        "record_id": row.get("record_id"),
    }
    if token_row and token_row.get("status") == "present" and token_row.get("token_b64"):
        timestamp = {
            "status": "present",
            "forged": False,
            "authority": token_row.get("authority"),
            "token_b64": token_row.get("token_b64"),
            "gen_time": token_row.get("gen_time"),
        }
    else:
        timestamp = tsa.missing_timestamp(
            "No timestamp token is stored for this receipt.")
    return receipt, timestamp


def _prior_receipt(record_id, captures, existing, allowed, stored_clock):
    """The response for a batch whose receipt is already stored, or None.

    The phone retries when a response is lost. The chain head of a batch
    that already has a receipt is that receipt, not a second acceptance.
    A request longer than the cap is not treated as a replay of its prefix:
    the phone still has to send what was not accepted.
    """
    if not captures or len(captures) > queue_ingest.batch_cap():
        return None
    first = captures[0] if isinstance(captures[0], dict) else None
    record = first.get("record") if isinstance(first, dict) else None
    if not isinstance(record, dict):
        return None
    probe = queue_ingest.prepare(
        captures,
        ticket_hash=existing.get("ticket_hash"),
        expected_prev=record.get("prev_hash"),
        ticket_clock=stored_clock,
        allowed_checkpoints=allowed)
    if not probe["ok"]:
        return None
    try:
        row = shield_db.find_receipt_by_phone_head(
            _principal().tenant_id, record_id, probe["phone_chain_head"])
    except Exception:
        log.exception("Receipt replay lookup failed for %s", record_id)
        return None
    if not row:
        return None
    try:
        token_row = shield_db.find_tsa_token(
            _principal().tenant_id, row.get("id"))
    except Exception:
        log.exception("Timestamp replay lookup failed for %s", record_id)
        token_row = None
    if not token_row:
        token_row = {"status": "missing", "token_b64": None}
    receipt_view, timestamp_view = _receipt_view(row, token_row)
    body = row.get("receipt_json") if isinstance(row.get("receipt_json"), dict) else {}
    return jsonify({
        "stored": True,
        "replayed": True,
        "accepted": row.get("batch_size"),
        "refused": 0,
        "send_next_batch": False,
        "phone_chain_head": row.get("phone_chain_head"),
        "custody_head_hash": row.get("head_hash"),
        "chain_version": ledger.CHAIN_VERSION,
        "receipt": receipt_view,
        "timestamp": timestamp_view,
        "signing_key": ticket.export_public_key(),
        "time_labels": body.get("time_labels") or [],
        "photo_ids": [],
    }), 200


@bp.route("/records/<record_id>/queue", methods=["POST"])
@require_tenant
@require_record()
def ingest_queue(record_id):
    """Accept a batch of offline captures and sign a receipt for the head.

    The phone sends each photograph, the capture record it signed, and the
    hardware signature over that record. Every signature is checked. A
    broken or truncated chain stores nothing. One request carries at most
    the batch cap; the rest are not stored, and the response says to send
    the next batch.

    Time labels are judged against the clock stored on the job ticket when
    the phone countersigned it. A clock in this request is not read.

    The receipt is signed even when the timestamp authority does not
    answer. A missing timestamp is reported as missing. It is not forged.
    The iOS assertion counter moves only after that receipt row exists.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _err("The request body must be a JSON object.", 400)

    refused = _signing_key_or_refuse()
    if refused:
        return refused

    try:
        existing = shield_db.find_job_ticket(_principal().tenant_id, record_id)
    except Exception:
        log.exception("Job ticket lookup failed for %s", record_id)
        return _err("Could not load the job ticket", 500)
    if not existing:
        return _err("This record has no job ticket, so an offline batch "
                    "cannot be accepted. Nothing was stored.", 409)

    platform = existing.get("platform")
    if platform not in ("ios", "android"):
        return _err("The job ticket has no platform this service can check. "
                    "Nothing was stored.", 409)
    stated = (body.get("platform") or "").strip().lower()
    if stated and stated != platform:
        return _err("This batch names a different platform than the job "
                    "ticket. Nothing was stored.", 422)
    if str(existing.get("actor_id") or "") != str(_principal().actor_id):
        return _err("This job ticket was issued to a different actor. "
                    "Nothing was stored.", 422)

    raw_captures = body.get("captures")
    if not isinstance(raw_captures, list):
        return _err("captures must be a list. Nothing was stored.", 422)

    captures = []
    for item in raw_captures:
        if not isinstance(item, dict):
            captures.append(item)
            continue
        photo = _b64(item.get("photo_b64") or "")
        captures.append({
            "photo": photo if photo is not None else b"",
            "record": item.get("record"),
            "assertion": item.get("assertion"),
        })

    try:
        points = _checkpoint_rows(record_id)
    except Exception:
        log.exception("Checkpoint read failed for queue %s", record_id)
        return _err("Could not load the checkpoints", 500)
    allowed = [row.get("id") for row in points if row.get("id")]

    stored_clock = existing.get("ticket_clock")
    if not isinstance(stored_clock, dict):
        return _err(
            "This job ticket has no clock observation from when it was "
            "countersigned. Nothing was stored.", 409)
    try:
        stored_clock = ticket.normalize_clock(stored_clock)
    except ValueError:
        return _err(
            "This job ticket's clock observation cannot be read. "
            "Nothing was stored.", 409)

    prior = _prior_receipt(record_id, captures, existing, allowed, stored_clock)
    if prior is not None:
        return prior

    try:
        previous = shield_db.latest_receipt(_principal().tenant_id, record_id)
    except Exception:
        log.exception("Receipt lookup failed for %s", record_id)
        return _err("Could not load the previous receipt", 500)
    expected_prev = (previous.get("phone_chain_head") if previous
                     else existing.get("ticket_hash"))
    batch_index = (int(previous.get("batch_index") or 0) + 1) if previous else 1

    prepared = queue_ingest.prepare(
        captures,
        ticket_hash=existing.get("ticket_hash"),
        expected_prev=expected_prev,
        ticket_clock=stored_clock,
        allowed_checkpoints=allowed,
        claimed_head=body.get("phone_chain_head"))
    if not prepared["ok"]:
        return _err(prepared["error"], 422)

    key_row, last_counter, sig_error = _queue_signatures(
        prepared["accepted"], _principal(), platform,
        body.get("attestation_key_id"), existing.get("key_id"))
    if sig_error:
        return _err(sig_error, 422)

    # verified is True for every capture before any of this is stored.
    if key_row is None:
        return _err("This batch was not accepted: the hardware signature "
                    "does not verify. Nothing was stored.", 422)

    tiers = []
    for _item in prepared["accepted"]:
        if platform == "ios":
            verdict = attestation.interpret_app_attest(
                verified=True, receipt_ok=True,
                token_nonce=queue_ingest.CAPTURE_CHALLENGE,
                expect_nonce=queue_ingest.CAPTURE_CHALLENGE)
        else:
            verdict = attestation.interpret_key_attestation(
                verified=True, receipt_ok=True,
                token_nonce=queue_ingest.CAPTURE_CHALLENGE,
                expect_nonce=queue_ingest.CAPTURE_CHALLENGE,
                security_level=key_row.get("security_level"))
        if verdict.get("tier") not in attestation.TRUSTED_TIERS:
            return _err("This batch was not accepted: the device key is not "
                        "one this service trusts. Nothing was stored.", 422)
        tiers.append(verdict["tier"])

    photo_ids = _store_batch_photos(record_id, prepared["accepted"], tiers)
    if photo_ids is None:
        return _err("Could not store the photographs. Nothing further was "
                    "recorded.", 502)

    event = queue_ingest.custody_event(
        prepared, ticket_hash=existing.get("ticket_hash"))
    if photo_ids:
        event["event_data"] = dict(event["event_data"], photo_ids=photo_ids)
    try:
        head = _head_and_append(record_id, event)
    except Exception:
        log.exception("Custody append failed for %s", record_id)
        return _err("Could not append the batch to the custody chain.", 500)

    accepted_at_ms = ticket.now_ms()
    try:
        signed = tsa.sign_receipt(tsa.build_receipt(
            record_id=record_id, head_hash=head, accepted_at_ms=accepted_at_ms))
    except ticket.TicketKeyError:
        return _signing_key_or_refuse() or _err(
            "This deployment cannot sign a receipt.", 503)
    except ValueError as exc:
        log.info("Receipt refused: %s", exc)
        return _err("The receipt could not be signed. The batch was not "
                    "left without a record of the failure in the log.", 500)

    labels = _time_labels(prepared)
    receipt_id = str(uuid.uuid4())
    receipt_row = {
        "id": receipt_id,
        "tenant_id": _principal().tenant_id,
        "record_id": record_id,
        "ticket_hash": existing.get("ticket_hash"),
        "head_hash": head,
        "phone_chain_head": prepared["phone_chain_head"],
        "accepted_at_ms": accepted_at_ms,
        "batch_index": batch_index,
        "batch_size": prepared["accepted_count"],
        "server_signature": signed["signature"],
        "receipt_json": {
            "signed": signed["signed"],
            "phone_chain_head": prepared["phone_chain_head"],
            "time_labels": labels,
            "ticket_clock": prepared["ticket_clock"],
        },
        "created_at": _now(),
    }
    try:
        shield_db.insert_receipt(receipt_row)
    except Exception:
        log.exception("Receipt insert failed for %s", record_id)
        return _err("Could not store the receipt.", 500)

    # The receipt is the replay lock. The counter moves only after that
    # row exists, so a failed store leaves the assertions usable and the
    # phone can send the batch again. A compare-and-set that loses does
    # not undo the receipt: the next batch still has to extend this head.
    if platform == "ios":
        if not _advance_counter(key_row["key_id"], last_counter):
            log.info("Assertion counter did not advance for %s after the "
                     "receipt was stored", record_id)
    else:
        _touch_key(key_row["key_id"])

    # The receipt is stored before this call. A failure here does not
    # remove it, and it does not become a forgery finding.
    stamped = tsa.stamp(head)
    token_row = {
        "id": str(uuid.uuid4()),
        "tenant_id": _principal().tenant_id,
        "receipt_id": receipt_id,
        "record_id": record_id,
        "head_hash": head,
        "status": stamped["status"] if stamped["status"] == "present" else "missing",
        "authority": stamped.get("authority") if stamped["status"] == "present" else None,
        "token_b64": stamped.get("token_b64") if stamped["status"] == "present" else None,
        "gen_time": stamped.get("gen_time") if stamped["status"] == "present" else None,
        "created_at": _now(),
    }
    try:
        shield_db.insert_tsa_token(token_row)
    except Exception:
        log.exception("Timestamp row insert failed for %s", record_id)
        token_row = {"status": "missing", "token_b64": None}

    receipt_view, timestamp_view = _receipt_view(receipt_row, token_row)
    public = ticket.export_public_key()
    payload = {
        "stored": True,
        "accepted": prepared["accepted_count"],
        "refused": prepared["refused_count"],
        "send_next_batch": prepared["send_next_batch"],
        "phone_chain_head": prepared["phone_chain_head"],
        "custody_head_hash": head,
        "chain_version": ledger.CHAIN_VERSION,
        "receipt": receipt_view,
        "timestamp": timestamp_view,
        "signing_key": public,
        "time_labels": labels,
        "photo_ids": photo_ids,
    }
    if prepared["message"]:
        payload["message"] = prepared["message"]
    return jsonify(payload), 201


# ------------------------------------------------------------------ photos --
@bp.route("/records/<record_id>/photos", methods=["POST"])
@require_tenant
@require_record()
def upload_photo(record_id):
    """Take a file and a checkpoint. Derive everything else.

    The caller sends `file`, `checkpoint_id`, and optionally the coordinates
    their device reported. They do not send a hash, a verdict, an EXIF flag or
    a distance: each is computed here, from the bytes that arrived or from the
    record's own site, and only the computed values are sealed.
    """
    checkpoint_id = (request.form.get("checkpoint_id") or "").strip()
    if not checkpoint_id:
        return _err("checkpoint_id is required", 400)
    upload = request.files.get("file")
    if not upload:
        return _err("file is required", 400)

    try:
        point = (_t("checkpoints").select("id,label,point_number")
                 .eq("id", checkpoint_id).eq("record_id", record_id)
                 .limit(1).execute()).data
    except Exception:
        log.exception("Checkpoint lookup failed")
        return _err("Could not load the checkpoint", 500)
    if not point:
        return _err("That checkpoint does not belong to this record", 404)

    raw = upload.read()
    if not raw:
        return _err("The uploaded file is empty", 400)

    # ---- attest, or be refused -------------------------------------------
    # The owner's rule, 2026-09-28: a capture that cannot prove it came from a
    # camera is not recorded at all.
    #
    # This reverses what attestation.py argues in its own docstring -- that a
    # blocked capture produces no record, and a labelled one is strictly more
    # evidence. That reasoning holds for a system whose job is to document
    # work. It does not hold for one whose entire claim is that the photograph
    # is real: a file-picker upload recorded as `unattested` is indexed,
    # hashed, sealed into a custody chain and exported in a package that says
    # "evidence" on it, and no reader downstream reliably re-reads the tier.
    # A forgeable record dressed in a hash chain is worse than no record,
    # because it is the hash chain that makes people believe it.
    #
    # What can pass it, precisely, as of 2026-09-28. iOS: `app_attest.verify`
    # CBOR-decodes the attestation, walks the X.509 chain to the configured
    # Apple root and checks the nonce binding, so a genuine capture from the
    # Shield app on genuine hardware is recorded. That requires both
    # APPLE_APP_ATTEST_ROOT_PEM and APP_ATTEST_APP_ID to be set: with either
    # missing, verification refuses rather than skipping the chain check, and
    # iOS capture is closed on that deployment.
    #
    # Android, since 2026-09-29: `android_attest.verify` walks the Key
    # Attestation chain to the configured Google roots, checks Google's
    # revocation list, and requires secure hardware, a locked verified-boot
    # device, Shield's package and signing certificate, and the same nonce
    # binding. That requires ANDROID_ATTESTATION_ROOTS_PEM,
    # ANDROID_PACKAGE_NAME and ANDROID_SIGNING_CERT_SHA256; with any missing,
    # Android capture is closed on that deployment. Play Integrity is not
    # used. Web: closed permanently and by design -- a file chosen from
    # storage cannot be attested, so the console offers no capture path at all.
    #
    # And the clients have not run on a device yet. The iOS app compiles; the
    # Android app is not written. Until one ships, this gate is verifiable but
    # unreachable in practice, which is the honest state of the product
    # rather than an outage.
    attested = _attestation_for(request, _principal(),
                                hashlib.sha256(raw).digest())
    if not attested["trusted"]:
        return jsonify({
            "error": (
                f"This capture was not accepted: {attested['reason']} "
                f"Shield records photographs that can prove they came from a "
                f"camera on a genuine device. Capture from the Shield app; a "
                f"file chosen from storage cannot be attested and is not "
                f"recorded."),
            "reattest": bool(attested.get("reattest")),
        }), 422

    mime = integrity.normalize_mime(upload.mimetype or "")
    sniffed = integrity.sniff_mime(raw)
    if sniffed and mime and sniffed != mime:
        # Trust the bytes, not the header. A caller can set any content type.
        mime = sniffed
    mime = sniffed or mime
    if not mime:
        return _err("Unsupported image format", 415)

    # The authoritative hash: these bytes, hashed here, before anything else
    # touches them.
    original_hash = integrity.sha256(raw)

    app_lat = request.form.get("gps_lat")
    app_lng = request.form.get("gps_lng")
    try:
        app_lat = float(app_lat) if app_lat not in (None, "") else None
        app_lng = float(app_lng) if app_lng not in (None, "") else None
    except (TypeError, ValueError):
        return _err("gps_lat and gps_lng must be numbers", 400)

    assessment = integrity.assess(raw, mime, app_lat, app_lng,
                                  config.get_int("GPS_TOLERANCE_M"))

    # Distance is measured against the site on the RECORD -- the one reference
    # point the uploader did not supply. Comparing their EXIF to their own
    # client reading, which is what `gps_self_consistent` does, is not
    # corroboration and is not used for this.
    site_distance = None
    if g.record.get("site_lat") is not None and app_lat is not None:
        site_distance = integrity.haversine_m(
            g.record["site_lat"], g.record["site_lng"], app_lat, app_lng)

    photo_id = str(uuid.uuid4())
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}.get(mime, "bin")
    storage_path = f"{_principal().tenant_id}/{record_id}/{photo_id}.{ext}"

    try:
        db().storage.from_(config.get("SHIELD_BUCKET")).upload(
            storage_path, raw, {"content-type": mime, "upsert": "false"})
    except Exception:
        log.exception("Storage write failed for %s", photo_id)
        return _err("Could not store the photograph", 502)

    row = {
        "id": photo_id,
        "tenant_id": _principal().tenant_id,
        "record_id": record_id,
        "checkpoint_id": checkpoint_id,
        "uploaded_by_ref": (request.form.get("uploaded_by_ref") or "").strip() or None,
        "storage_path": storage_path,
        "original_hash": original_hash,
        "original_size_bytes": len(raw),
        "has_exif": assessment.get("has_exif"),
        "gps_lat": app_lat,
        "gps_lng": app_lng,
        "site_distance_m": site_distance,
        "integrity_note": assessment.get("integrity_note"),
        # Only a trusted tier reaches this line; the gate above refuses
        # everything else, so no unattested row is ever written.
        "attestation_tier": attested["tier"],
        "received_at": _now(),
    }
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if ip:
        row["upload_ip_hash"] = integrity.hash_ip(ip.split(",")[0].strip(),
                                                  config.get("IP_HASH_SALT"))

    try:
        res = _t("photos").insert(row).execute()
    except Exception:
        log.exception("Photo insert failed for %s", photo_id)
        return _err("Could not record the photograph", 500)

    # A retake supersedes the previous live photo for this checkpoint rather
    # than replacing it. The failed attempt stays in the record and in the
    # published statistics; deleting it would make every corrected failure
    # disappear from our own numbers.
    try:
        previous = (_t("photos").select("id")
                    .eq("checkpoint_id", checkpoint_id)
                    .is_("superseded_at", "null")
                    .neq("id", photo_id).execute()).data or []
        for old in previous:
            _t("photos").update({"superseded_by": photo_id,
                                 "superseded_at": _now()}) \
                .eq("id", old["id"]).execute()
            _head_and_append(record_id, {
                "event_type": "superseded", "photo_id": old["id"],
                "event_data": {"superseded_by": photo_id},
            })
    except Exception:
        log.exception("Supersede pass failed for checkpoint %s", checkpoint_id)

    _head_and_append(record_id, {
        "event_type": "uploaded",
        "photo_id": photo_id,
        "file_hash": original_hash,
        "gps_lat": app_lat, "gps_lng": app_lng,
        "integrity_note": assessment.get("integrity_note"),
        "event_data": {
            "checkpoint": point[0]["label"],
            "point_number": point[0]["point_number"],
            "bytes": len(raw),
            "mime": mime,
            "has_exif": bool(assessment.get("has_exif")),
            "site_distance_m": site_distance,
            "attestation_tier": attested["tier"],
        },
    })
    return jsonify({
        "photo": (res.data or [{}])[0],
        # Only an attestation registers a key; an assertion used one that was.
        # The app keeps its key id only when this is true.
        "attestation_key_registered": bool(attested.get("key_registered")),
    }), 201


# ------------------------------------------------------------------ custody --
@bp.route("/records/<record_id>/custody", methods=["GET"])
@require_tenant
@require_record(writable=False)
def custody(record_id):
    """The chain, verified on the way out.

    Verifying here is a convenience, not the guarantee. The guarantee is that
    a recipient can run the same check themselves with `verifier/` or the
    browser client, against the package below, without trusting this response.
    """
    try:
        entries = (_t("custody_log").select("*")
                   .eq("record_id", record_id)
                   .order("recorded_at").execute()).data or []
    except Exception:
        log.exception("Custody read failed for %s", record_id)
        return _err("Could not load the custody chain", 500)

    ordered = chain_in_order(entries, record_id)
    result = ledger.verify_chain(ordered, record_id)
    return jsonify({"custody": ordered, "verification": result})


@bp.route("/records/<record_id>/package", methods=["GET"])
@require_tenant
@require_record(writable=False)
def package(record_id):
    """The evidence package, in the shape the published verifier reads.

    This is the deliverable: the thing a tenant hands to their customer, their
    insurer or their lawyer, who checks it with software we do not control.
    `head_hash` is the single value that commits to the whole history -- hold a
    copy of it and a later rewrite becomes detectable. It is also the only
    thing that detects truncation, because a chain with entries removed from
    the end verifies perfectly otherwise (AR-8).
    """
    try:
        entries = (_t("custody_log").select("*")
                   .eq("record_id", record_id)
                   .order("recorded_at").execute()).data or []
        points = (_t("checkpoints").select("*")
                  .eq("record_id", record_id).order("point_number")
                  .execute()).data or []
        photos = (_t("photos").select("*")
                  .eq("record_id", record_id).order("uploaded_at")
                  .execute()).data or []
    except Exception:
        log.exception("Package build failed for %s", record_id)
        return _err("Could not build the package", 500)

    _head_and_append(record_id, {
        "event_type": "exported",
        "event_data": {"entries": len(entries), "photos": len(photos)},
    })

    # Storage paths are ours, not the recipient's, and a signed URL in an
    # export would expire and look like tampering. The hash is what travels.
    safe_photos = [{k: v for k, v in p.items() if k != "storage_path"}
                   for p in photos]

    ordered = chain_in_order(entries, record_id)
    receipt_row = token_row = None
    try:
        receipt_row = shield_db.latest_receipt(_principal().tenant_id, record_id)
        if receipt_row:
            token_row = shield_db.find_tsa_token(
                _principal().tenant_id, receipt_row.get("id"))
    except Exception:
        log.exception("Receipt read failed for package %s", record_id)
    receipt_view, timestamp_view = _receipt_view(receipt_row, token_row)
    return jsonify({
        "schema": "tradedeck.shield.package.v2",
        "chain_version": ledger.CHAIN_VERSION,
        "generated_at": _now(),
        "record": {k: v for k, v in g.record.items() if k != "tenant_id"},
        "checkpoints": points,
        "photos": safe_photos,
        "custody": ordered,
        "head_hash": ledger.head_of(ordered, record_id),
        "receipt": receipt_view,
        "timestamp": timestamp_view,
        "signing_key": ticket.export_public_key(),
        "verify_with": "https://github.com/Wood1974/Tradedeck-api "
                       "(shield/verifier/shield_verify.py, or "
                       "shield/webapp/shield.html in a browser)",
    })


def _live_for(checkpoint_id, photos):
    """The live photo for a checkpoint, in the shape verdict.grade() reads.

    `verdict.is_live()` decides what counts, so a retaken photo does not grade
    the checkpoint it was replaced on. The rename is the only adaptation.
    """
    for photo in photos:
        if photo.get("checkpoint_id") != checkpoint_id:
            continue
        if verdict_mod.is_live(photo):
            return {**photo, "ai_verdict": photo.get("verdict")}
    return None


# ---------------------------------------------------------------- close out --
@bp.route("/records/<record_id>/complete", methods=["POST"])
@require_tenant
@require_record()
def complete(record_id):
    """Close the record and seal the outcome.

    The grade is computed here from the rows, not taken from the request. The
    parent service built its completion report out of the request body and
    ignored the hash it computed, which meant the close-out of a record said
    whatever the party closing it wanted it to say.
    """
    if g.record.get("status") == "complete":
        return _err("This record is already complete", 409)

    try:
        points = (_t("checkpoints").select("id,label,point_number,status")
                  .eq("record_id", record_id).order("point_number")
                  .execute()).data or []
        photos = (_t("photos").select(
            "id,checkpoint_id,verdict,superseded_by,superseded_at")
            .eq("record_id", record_id).execute()).data or []
    except Exception:
        log.exception("Completion read failed for %s", record_id)
        return _err("Could not load the record", 500)

    if not points:
        return _err("This record has no checkpoints, so there is nothing to "
                    "attest to", 409)

    # verdict.grade() reads one `photo` per point and calls the field
    # `ai_verdict`; this schema stores many photos per checkpoint and calls it
    # `verdict`. Translate here rather than bending either side: the grader is
    # shared with the legacy service and its rules -- incomplete outranks every
    # verdict, superseded photos are not live -- are the part worth reusing.
    graded = verdict_mod.grade([
        {**point, "photo": _live_for(point["id"], photos)} for point in points
    ])

    try:
        _t("records").update({"status": "complete", "completed_at": _now()}) \
            .eq("id", record_id).execute()
    except Exception:
        log.exception("Completion write failed for %s", record_id)
        return _err("Could not complete the record", 500)

    head = _head_and_append(record_id, {
        "event_type": "completed",
        "event_data": {
            "overall_verdict": graded.get("verdict"),
            "score": graded.get("score"),
            "checkpoints": len(points),
            "verified": graded.get("verified"),
        },
    })

    # The outcome has to land in completion_reports, not only in the chain.
    # /public/results counts this table, so a close-out that seals itself into
    # the custody log and writes no row here is an outcome the published
    # failure rate structurally cannot include -- which is the one defect an
    # honesty claim does not survive.
    report = {
        "record_id": record_id,
        "external_ref": g.record.get("external_ref"),
        "overall_verdict": graded.get("verdict"),
        "score": graded.get("score"),
        "coverage_pct": graded.get("coverage_pct"),
        "checkpoints_total": graded.get("checkpoints_total"),
        "checkpoints_verified": graded.get("checkpoints_verified"),
        "missing": graded.get("missing"),
        "failing": graded.get("failing"),
        "summary": graded.get("summary"),
        "custody_head_hash": head,
        "closed_at": _now(),
    }
    # Hash the report the same way the chain hashes an entry: sorted keys,
    # tight separators. A recipient can recompute it from the JSON they were
    # given without guessing at our formatting.
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"),
                           default=str)
    try:
        _t("completion_reports").insert({
            "tenant_id": _principal().tenant_id,
            "record_id": record_id,
            "overall_verdict": graded.get("verdict"),
            "completion_score": float(graded.get("score") or 0.0),
            "coverage_pct": float(graded.get("coverage_pct") or 0.0),
            "report_json": report,
            "report_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "custody_head_hash": head,
        }).execute()
    except Exception:
        # The record is already marked complete and the chain already carries
        # the outcome, so failing the request would report a failure for work
        # that happened. Logged loudly instead: a missing row here shows up as
        # a gap between the chain and the published report, which is exactly
        # what someone should notice.
        log.exception("Completion report insert failed for %s", record_id)

    return jsonify({
        "record_id": record_id,
        "grade": graded,
        "head_hash": head,
        "keep_this": "Store head_hash outside Shield. It is the only thing "
                     "that lets you detect a later rewrite, or entries removed "
                     "from the end of the chain.",
    })
