"""The job ticket a phone countersigns before it leaves signal.

Option 1A: genesis happens while the phone is online. This module builds the
ticket, hashes it, and signs it with the service's own ECDSA P-256 key. It
does not talk to a phone and it does not write a row. The route does that,
and only after the phone's attested install key has signed the ticket hash.

What is signed
--------------
The signed bytes are canonical JSON, the same rules as a capture record:
sorted keys, tight separators, UTF-8, null omitted, floats rejected, whole
numbers only. ``chain_version`` is not in here. It stays 2. ``version`` on
the ticket is this contract, and it is 1.

``ticket_hash`` is SHA-256 of those bytes, lowercase hex. A capture record
names that hash as ``ticket_id``. The first record on the phone uses the
same hash as ``prev_hash``.

The server signature is ECDSA P-256 with SHA-256 over the canonical bytes.
The private key is ``SHIELD_TICKET_SIGNING_KEY_PEM``. It is configuration,
the same posture as ``APPLE_APP_ATTEST_ROOT_PEM``: unset means genesis is
closed, and a key in this repository would be a key anyone can read. The
public half is exportable so an evidence package can carry it.

The phone signature is not produced here. The existing verifiers check it.
They already bind ``challenge || payload_sha256``. Genesis uses a fixed
challenge, ``shield-genesis-v1``, and puts the raw 32-byte ticket hash in
the payload position. A capture assertion cannot be replayed as a ticket,
and a ticket assertion cannot be replayed as a photograph: the challenge
is not a capture nonce.

Roughtime is a field, not a client. The flag defaults off. When the outside
clock is absent — the flag, a missing reading, a reading that is not a
whole number of milliseconds — the field is left out and genesis still
completes. Absent and null are the same bytes.

Play Integrity is one verdict per Android job, read by
``attestation.interpret_play_integrity``. This module does not call Google.
A token nobody has verified cannot come back as a pass. iOS has no Play
Integrity API, and App Attest does not report jailbreak; both facts are
the stored reason on an iOS ticket, not a guess a caller can overwrite.

Nothing in this file is the per-process challenge jar. Two gunicorn
workers do not share that jar. A ticket is a database row, written by
``db.insert_job_ticket`` after the signature checks.
"""
import hashlib
import base64
import hmac
import logging
import time

import re

import attestation
import capture_record
import config

log = logging.getLogger(__name__)

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# This ticket's own contract. Not ledger.CHAIN_VERSION, and not
# capture_record.RECORD_VERSION.
TICKET_VERSION = 1

# How long a ticket authorizes, from the server clock on the offer.
# The offer is sealed in the same online session; the window is the job,
# not the HTTP round trip. Whole milliseconds, so it is not a float.
TICKET_TTL_MS = 7 * 24 * 60 * 60 * 1000

# Domain separator for the hardware signature. Fixed length on the right
# (the 32-byte hash) is what makes the concatenation unambiguous.
GENESIS_CHALLENGE = "shield-genesis-v1"

JS_SAFE_INT = capture_record.JS_SAFE_INT

TICKET_FIELDS = (
    "version",
    "record_id",
    "checkpoint_list_sha256",
    "actor_id",
    "expires_at_ms",
    "server_time_ms",
    "roughtime_ms",
)

REQUIRED_FIELDS = (
    "version",
    "record_id",
    "checkpoint_list_sha256",
    "actor_id",
    "expires_at_ms",
    "server_time_ms",
)

# No client is wired. A later change can assign a callable that returns
# whole-number Unix milliseconds. None means the outside clock is absent.
roughtime_fetch = None


class TicketKeyError(Exception):
    """The deployment has no usable ticket signing key."""


def now_ms():
    """Server clock as whole Unix milliseconds.

    ``time.time() * 1000`` is a float. A float in the signed ticket is a
    different byte string on another language's JSON decoder. Nanoseconds
    divided down stay an int.
    """
    return time.time_ns() // 1_000_000


def _whole(value, key):
    if isinstance(value, float):
        raise ValueError(
            f"{key} is a float; the job ticket only signs whole numbers")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be a whole number")
    if value < 0 or value > JS_SAFE_INT:
        raise ValueError(
            f"{key} is outside the range a JSON number can carry exactly")
    return value


def _text(value, key):
    if isinstance(value, float):
        raise ValueError(f"{key} is a float")
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{key} must be a non-empty string")
    if len(value) > 512:
        raise ValueError(f"{key} is longer than 512 characters")
    return value


def _validate(ticket):
    """The signed map. Unknown keys are dropped. Nulls are omitted.

    Dropping an unknown key is safe because the stored ticket is this map,
    not the object a caller posted. A field that is not in it was not
    signed and is not kept.
    """
    if not isinstance(ticket, dict):
        raise ValueError("ticket must be a JSON object")
    out = {}
    for key in TICKET_FIELDS:
        if key not in ticket or ticket[key] is None:
            continue
        value = ticket[key]
        if key == "version":
            value = _whole(value, key)
            if value != TICKET_VERSION:
                raise ValueError(
                    f"unsupported job ticket version {value}; "
                    f"this contract is version {TICKET_VERSION}")
        elif key in ("expires_at_ms", "server_time_ms", "roughtime_ms"):
            value = _whole(value, key)
        elif key == "checkpoint_list_sha256":
            value = _text(value, key)
            if _SHA256_HEX.fullmatch(value) is None:
                raise ValueError(
                    f"{key} must be a 64-character lowercase hex SHA-256")
        else:
            value = _text(value, key)
        out[key] = value
    for key in REQUIRED_FIELDS:
        if key not in out:
            raise ValueError(f"job ticket is missing {key}")
    if out["expires_at_ms"] <= out["server_time_ms"]:
        raise ValueError("expiry must be after the server clock")
    # Same byte rules as the capture record, including the float rejection
    # inside nested values. The ticket itself has no nested values; the
    # call is what keeps the two serializers from drifting.
    capture_record.canonical_whole(out)
    return out


def canonical(ticket) -> bytes:
    """UTF-8 JSON of the signed fields. Rejects a float."""
    return capture_record.canonical_whole(_validate(ticket))


def ticket_hash(ticket) -> str:
    """Lowercase hex SHA-256 of the canonical ticket."""
    return hashlib.sha256(canonical(ticket)).hexdigest()


def hardware_binding(ticket_hash_hex):
    """``(challenge, payload_sha256)`` for the existing signature verifiers.

    ``payload_sha256`` is the raw ticket hash, 32 bytes, not the hex text.
    The verifiers check ``challenge || payload_sha256`` and are not modified.
    """
    if not isinstance(ticket_hash_hex, str) or _SHA256_HEX.fullmatch(
            ticket_hash_hex) is None:
        raise ValueError("ticket hash must be a 64-character lowercase hex SHA-256")
    return GENESIS_CHALLENGE, bytes.fromhex(ticket_hash_hex)


def checkpoint_list_hash(rows) -> str:
    """SHA-256 of the locked checkpoint list, in point order.

    The commitment is the requirements: id, order, label, and the optional
    description, code reference, and what the photo must show. Status is
    not included. Status changes as photos are graded, and a hash that
    moved after genesis would no longer be the list that was locked.

    Rows are sorted here. A caller that hands them over in a different
    order gets the same hash.
    """
    if not isinstance(rows, (list, tuple)) or not rows:
        raise ValueError("checkpoint list must be a non-empty list")

    def sort_key(row):
        if not isinstance(row, dict):
            raise ValueError("checkpoint must be an object")
        number = row.get("point_number")
        if isinstance(number, bool) or not isinstance(number, int):
            raise ValueError("point_number must be a whole number")
        return (number, str(row.get("id") or ""))

    items = []
    for row in sorted(rows, key=sort_key):
        item = {
            "id": str(row.get("id") or ""),
            "point_number": row["point_number"],
            "label": row.get("label") if isinstance(row.get("label"), str) else "",
        }
        if item["id"] == "" or item["label"] == "":
            raise ValueError("checkpoint needs an id and a label")
        for key in ("description", "code_reference", "must_show"):
            value = row.get(key)
            if isinstance(value, str) and value != "":
                item[key] = value
        items.append(item)
    return capture_record.hash_whole({"checkpoints": items})


def build_ticket(*, record_id, checkpoint_list_sha256, actor_id,
                 server_time_ms, ttl_ms=TICKET_TTL_MS, roughtime_ms=None,
                 version=TICKET_VERSION) -> dict:
    """A ticket dict with nulls removed. Not signed, not stored."""
    server_time_ms = _whole(server_time_ms, "server_time_ms")
    ttl_ms = _whole(ttl_ms, "ttl_ms")
    if ttl_ms <= 0:
        raise ValueError("ticket lifetime must be a positive whole number")
    expires_at_ms = server_time_ms + ttl_ms
    if expires_at_ms > JS_SAFE_INT:
        raise ValueError("expiry is outside the range a JSON number can carry")
    ticket = {
        "version": version,
        "record_id": record_id,
        "checkpoint_list_sha256": checkpoint_list_sha256,
        "actor_id": actor_id,
        "server_time_ms": server_time_ms,
        "expires_at_ms": expires_at_ms,
    }
    if roughtime_ms is not None:
        ticket["roughtime_ms"] = roughtime_ms
    # Re-read through canonical so the returned dict is the signed one.
    return _validate(ticket)


def _flag_on(enabled):
    """The config flag, a bool, or the string ``1``. Everything else is off."""
    return enabled is True or enabled == 1 or (
        isinstance(enabled, str) and enabled.strip() in ("1", "true", "True"))


def outside_clock_ms(*, enabled, fetch=None):
    """A Roughtime reading, or None when the outside clock is absent.

    ``enabled`` is the config flag. It defaults off. ``fetch`` is optional
    and is not a client: this release does not open a socket. A missing
    reading, a failed reading, or a value that is not a whole number of
    milliseconds is absent. The caller still builds the ticket.
    """
    if not _flag_on(enabled):
        return None
    if fetch is None:
        return None
    try:
        value = fetch()
    except Exception:
        log.info("roughtime reading failed; the outside clock is absent")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > JS_SAFE_INT:
        return None
    return value


def _pem_text(value):
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if "\\n" in text and "-----BEGIN" in text:
        text = text.replace("\\n", "\n")
    return text


def load_signing_key(pem=None):
    """The ECDSA P-256 private key, or None when genesis must stay closed.

    ``pem`` defaults to the environment. There is no built-in key. A PEM
    that is not an unencrypted P-256 private key is treated as absent.
    """
    if pem is None:
        pem = config.get("SHIELD_TICKET_SIGNING_KEY_PEM")
    text = _pem_text(pem)
    if "-----BEGIN" not in text:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError:  # pragma: no cover
        log.warning("cryptography is not installed; ticket signing is closed")
        return None
    try:
        key = load_pem_private_key(text.encode("utf-8"), password=None)
    except Exception:
        log.warning("ticket signing key could not be read")
        return None
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        return None
    if not isinstance(key.curve, ec.SECP256R1):
        return None
    return key


def export_public_key(pem=None):
    """The public half, for an evidence package. None when no key is set.

    Two forms of the same point: PEM SubjectPublicKeyInfo, and the
    uncompressed P-256 point (``0x04 || X || Y``) as base64. The private
    key is not in the result.
    """
    key = load_signing_key(pem)
    if key is None:
        return None
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    pub = key.public_key()
    raw = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    pem_out = pub.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return {
        "algorithm": "ECDSA-P-256-SHA256",
        "pem": pem_out,
        "uncompressed_point_b64": base64.b64encode(raw).decode("ascii"),
    }


def sign_ticket(ticket, *, pem=None) -> dict:
    """Sign the canonical bytes. Raises TicketKeyError when no key is set."""
    body = canonical(ticket)
    key = load_signing_key(pem)
    if key is None:
        raise TicketKeyError("no ticket signing key is configured")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    signature = key.sign(body, ec.ECDSA(hashes.SHA256()))
    return {
        "ticket": _validate(ticket),
        "ticket_hash": hashlib.sha256(body).hexdigest(),
        "server_signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_server_signature(ticket, signature_b64, *, pem=None) -> dict:
    """Check the server signature over the canonical bytes.

    A bad signature is ``ok: False``. A missing key raises TicketKeyError
    so the route can refuse the deployment rather than call the ticket
    tampered. A ticket that does not parse raises ValueError.
    """
    body = canonical(ticket)
    key = load_signing_key(pem)
    if key is None:
        raise TicketKeyError("no ticket signing key is configured")
    raw = _b64(signature_b64)
    digest = hashlib.sha256(body).hexdigest()
    if raw is None:
        return {"ok": False, "reason": "server signature is not valid base64",
                "ticket": _validate(ticket), "ticket_hash": digest}
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        key.public_key().verify(raw, body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return {"ok": False, "reason": "server signature does not verify",
                "ticket": _validate(ticket), "ticket_hash": digest}
    except Exception:
        return {"ok": False, "reason": "server signature could not be checked",
                "ticket": _validate(ticket), "ticket_hash": digest}
    return {"ok": True, "reason": "server signature verifies",
            "ticket": _validate(ticket), "ticket_hash": digest}


def _b64(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        return None


def seal_blocks(ticket_dict, *, record_id, actor_id, checkpoint_list_sha256,
                now_ms):
    """Why this ticket may not be stored, signatures aside.

    None means the record, the actor, the locked list, and the expiry all
    agree. The route still refuses when either signature is missing or
    invalid; this function does not look at them.
    """
    if not isinstance(ticket_dict, dict):
        return "The ticket is not an object."
    if ticket_dict.get("record_id") != record_id:
        return "This ticket is for a different record."
    if ticket_dict.get("actor_id") != str(actor_id):
        return "This ticket was issued to a different actor."
    got = ticket_dict.get("checkpoint_list_sha256")
    if (not isinstance(got, str) or not isinstance(checkpoint_list_sha256, str)
            or len(got) != len(checkpoint_list_sha256)
            or not hmac.compare_digest(got, checkpoint_list_sha256)):
        return "The locked checkpoint list does not match this ticket."
    expires = ticket_dict.get("expires_at_ms")
    if isinstance(now_ms, bool) or not isinstance(now_ms, int):
        return "The server clock could not be read."
    if isinstance(expires, bool) or not isinstance(expires, int) or now_ms > expires:
        return "This ticket has expired."
    return None


def classify_play_integrity(payload, *, verified=False, expect_nonce=None,
                            expect_package=None, platform="android"):
    """One Play Integrity verdict for a job, or an explicit absence.

    iOS always comes back absent. App Attest does not report jailbreak,
    and there is no Play Integrity API on iOS to ask. A payload sent by
    an iOS client is ignored, so the client cannot supply its own pass.

    Android with no payload is absent. Absence is not a failure and not
    a pass. A payload is read by ``interpret_play_integrity``. ``verified``
    must be exactly True, and the token must be bound to ``expect_nonce``,
    or the status is not a pass. This function does not call Google, so
    the route leaves ``verified`` false and a token on the wire is stored
    as unverifiable.
    """
    if platform != "android":
        return {
            "status": "absent",
            "tier": None,
            "reason": (
                "iOS has no Play Integrity API. App Attest attests the app "
                "and the Secure Enclave; it does not report jailbreak."),
            "labels": None,
            "trusted": False,
        }
    if payload is None:
        return {
            "status": "absent",
            "tier": None,
            "reason": (
                "No Play Integrity token was presented for this job. "
                "Absence is not a failure and it is not a pass."),
            "labels": None,
            "trusted": False,
        }
    verdict = attestation.interpret_play_integrity(
        payload, verified=verified, expect_nonce=expect_nonce,
        expect_package=expect_package)
    tier = verdict.get("tier")
    # A strong label that is not bound to this job is not a pass. Binding
    # is the nonce, and a caller who omits it does not get to skip it.
    if tier in attestation.TRUSTED_TIERS and verdict.get("bound") is True:
        status = "pass"
    elif tier in attestation.TRUSTED_TIERS or tier == attestation.TIER_UNVERIFIABLE:
        status = "unverifiable"
    else:
        status = "fail"
    return {
        "status": status,
        "tier": tier,
        "reason": verdict.get("reason"),
        "labels": verdict.get("labels"),
        "trusted": status == "pass",
    }


def play_integrity_columns(classified):
    """The columns stored beside the ticket. The route writes these."""
    return {
        "play_integrity_status": classified["status"],
        "play_integrity_tier": classified["tier"],
        "play_integrity_reason": classified["reason"],
        "play_integrity_labels": classified["labels"],
    }
