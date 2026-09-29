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
import json
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

import config
import android_attest
import app_attest
import attestation
import integrity
import ledger
import tenancy
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
    nonce = CHALLENGES.issue(_principal().actor_id)
    CHALLENGES.purge()

    # Store in database for multi-worker persistence.
    try:
        expires_at = (datetime.now(timezone.utc) +
                      __import__('datetime').timedelta(
                          seconds=attestation.CHALLENGE_TTL_S))
        _t("capture_tokens").insert({
            "token": nonce,
            "tenant_id": str(_principal().tenant_id),
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
                  .select("token, used_at, expires_at")
                  .eq("token", nonce)
                  .limit(1).execute()).data
        if result:
            row = result[0]
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


def _check_assertion(assertion, key_id_field, principal, *, platform, **kw):
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
        checked = app_attest.verify_assertion(
            blob, public_key=_b64(row.get("public_key")),
            previous_counter=row.get("sign_count") or 0,
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

    return jsonify({
        "schema": "tradedeck.shield.package.v2",
        "chain_version": ledger.CHAIN_VERSION,
        "generated_at": _now(),
        "record": {k: v for k, v in g.record.items() if k != "tenant_id"},
        "checkpoints": points,
        "photos": safe_photos,
        "custody": chain_in_order(entries, record_id),
        "head_hash": ledger.head_of(chain_in_order(entries, record_id), record_id),
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
