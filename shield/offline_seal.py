"""Judge an offline seal from the bytes in a package.

The custody chain is a different card and a different check. This one reads
the phone chain, the hardware signatures, the job ticket, the receipt, and
the RFC 3161 token, and it does that from the package alone. It does not
open a socket. The timestamp roots are the certificates pinned in
``webapp/tsa_roots.pem``, the same ones the page bundles.

Labels, one of them
-------------------
TAMPERED
    A phone-chain byte or link does not reproduce, the phone chain is not
    the one inside the custody entry, or the receipt's head is not the
    custody head.
FORGED
    A hardware signature does not verify, the key is missing or not the
    point it claims to be, the ticket signature does not verify, the
    receipt signature does not verify, or a timestamp token is present and
    does not check.
DEVICE CLOCK MISMATCH
    The time rules say so. Signatures and bytes already checked.
UNVERIFIED TIME
    The time rules say so, and they do not also say a mismatch.
receipt present, timestamp absent
    Everything else that SEALED requires is true, and there is no token.
    A missing token is not FORGED.
SEALED
    The phone chain recomputes, every hardware signature checks, the ticket
    signature checks, the time rules pass, and the token checks against the
    pinned roots.

Flags are words beside the label. They never change it. ``chain_version``
is not a field of this result. It stays 2 on the custody chain.
"""
import base64
import hashlib
import json
from pathlib import Path

import capture_record
import ledger
import queue_ingest
import ticket
import time_audit
import tsa

LABEL_SEALED = "SEALED"
LABEL_TAMPERED = "TAMPERED"
LABEL_FORGED = "FORGED"
LABEL_UNVERIFIED = "UNVERIFIED TIME"
LABEL_MISMATCH = "DEVICE CLOCK MISMATCH"
LABEL_TIMESTAMP_ABSENT = "receipt present, timestamp absent"
LABEL_NONE = None

_RANK = {
    LABEL_SEALED: 0,
    LABEL_TIMESTAMP_ABSENT: 10,
    LABEL_UNVERIFIED: 20,
    LABEL_MISMATCH: 30,
    LABEL_FORGED: 40,
    LABEL_TAMPERED: 50,
}

# Words a person can read. The bit values are capture_record's. Unknown
# bits stay in the integer and are named rather than dropped.
_FLAG_WORDS = (
    (capture_record.FLAG_SCREEN_CAPTURED, "screen captured"),
    (capture_record.FLAG_DEBUGGER, "debugger attached"),
    (capture_record.FLAG_MOCK_LOCATION, "mock location"),
    (capture_record.FLAG_ROOT_TRACES, "root traces"),
)

_ROOTS = Path(__file__).resolve().parent / "webapp" / "tsa_roots.pem"


def pinned_roots() -> str:
    """The PEM bundle the page also ships. Public roots, not a secret."""
    return _ROOTS.read_text()


def flag_words(flags) -> list:
    """The bits of ``flags``, lowest first, as words."""
    try:
        value = capture_record._whole(flags, "flags", non_negative=True)
    except ValueError:
        return []
    names = [word for bit, word in _FLAG_WORDS if value & bit]
    known = 0
    for bit, _word in _FLAG_WORDS:
        known |= bit
    extra = value & ~known
    index = 0
    while extra:
        if extra & 1:
            names.append(f"bit {index}")
        extra >>= 1
        index += 1
    return names


def block_from_stored(*, entries, ticket_row=None, public_key_b64=None,
                      app_id=None):
    """The ``offline`` object a package carries, from rows already stored.

    Capture assertions were written beside each phone-chain record when the
    batch was accepted. The ticket row holds the server signature and the
    hardware signature over the ticket. Nothing here is fetched.
    """
    captures = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        data = entry.get("event_data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                data = None
        if not isinstance(data, dict):
            continue
        for record in data.get("phone_chain") or []:
            if not isinstance(record, dict):
                continue
            assertion = record.get("hardware_signature") or record.get("assertion")
            cleaned = {
                key: record[key] for key in record
                if key not in ("hardware_signature", "assertion")
            }
            captures.append({"record": cleaned, "assertion": assertion})
    row = ticket_row if isinstance(ticket_row, dict) else {}
    if not captures and not row:
        return None
    block = {
        "platform": row.get("platform"),
        "app_id": app_id or None,
        "key_id": row.get("key_id"),
        "hardware_key_b64": public_key_b64,
        "ticket": row.get("ticket_json"),
        "ticket_signature": row.get("server_signature"),
        "ticket_assertion": row.get("hardware_signature"),
        "ticket_clock": row.get("ticket_clock"),
        "captures": captures,
    }
    return {key: value for key, value in block.items() if value is not None}


def judge(package, *, roots_pem=None) -> dict:
    """The seal label for one package. Does not raise on a bad package."""
    if roots_pem is None:
        roots_pem = pinned_roots()
    if not isinstance(package, dict):
        return _done(LABEL_NONE, [], [], "This package has no offline seal.")
    offline = package.get("offline")
    if not isinstance(offline, dict) or not offline.get("captures"):
        return _done(LABEL_NONE, [], [], "This package has no offline seal.")

    label = LABEL_SEALED
    reasons = []

    def worsen(name, reason):
        nonlocal label
        if _RANK[name] > _RANK[label]:
            label = name
        if reason:
            reasons.append(reason)

    flags = []
    try:
        flags = _flags(offline["captures"])
    except Exception:
        flags = []

    records = []
    for item in offline["captures"]:
        if not isinstance(item, dict) or not isinstance(item.get("record"), dict):
            worsen(LABEL_TAMPERED, "A capture in the package is not a record.")
            records = None
            break
        records.append(item["record"])
    if records is None:
        return _finish(label, flags, reasons, False, False)

    entries = _entries(package)
    job_id = _job_id(package)
    custody_head = None
    custody_intact = False
    if not entries or not job_id:
        worsen(LABEL_TAMPERED,
               "The package has no custody chain to anchor the receipt to.")
    else:
        ordered = sorted(entries, key=lambda e: str(
            (e or {}).get("recorded_at") or "") if isinstance(e, dict) else "")
        try:
            chain = ledger.verify_chain(ordered, job_id)
        except Exception as exc:
            worsen(LABEL_TAMPERED, f"The custody chain could not be read ({exc}).")
            chain = None
        if chain is not None:
            if chain.get("ambiguous"):
                worsen(LABEL_TAMPERED,
                       "The custody head could not be recomputed from these bytes.")
            elif not chain.get("intact"):
                worsen(LABEL_TAMPERED,
                       "The custody chain does not reproduce, so the receipt "
                       "is not anchored to these bytes.")
            else:
                custody_intact = True
                custody_head = chain.get("head_hash")
        _cross_check_phone_chain(ordered if entries else [], records, worsen)

    ticket_body = offline.get("ticket")
    clock = offline.get("ticket_clock")
    ticket_hash = None
    if not isinstance(ticket_body, dict):
        worsen(LABEL_FORGED, "The package has no job ticket.")
    else:
        try:
            ticket_hash = ticket.ticket_hash(ticket_body)
        except ValueError as exc:
            worsen(LABEL_FORGED, f"The job ticket could not be read ({exc}).")
        else:
            signing = _signing_key(package, offline)
            if not _ecdsa_ok(signing, ticket.canonical(ticket_body),
                             offline.get("ticket_signature")):
                worsen(LABEL_FORGED, "The job ticket signature does not verify.")
            record_id = _job_id(package)
            if record_id and str(ticket_body.get("record_id") or "") not in (
                    "", record_id):
                worsen(LABEL_FORGED, "The job ticket is not for this record.")

    if ticket_hash is None:
        worsen(LABEL_TAMPERED, "The phone chain has no ticket hash to start from.")
    else:
        checked = capture_record.verify_chain(records, ticket_hash)
        if checked["verdict"] != capture_record.VERDICT_INTACT:
            worsen(LABEL_TAMPERED, checked["summary"])
        for record in records:
            if str(record.get("ticket_id") or "") != ticket_hash:
                worsen(LABEL_TAMPERED,
                       "A capture was not made under this job ticket.")
                break

    point = _point(offline.get("hardware_key_b64"))
    if point is None:
        worsen(LABEL_FORGED, "The package has no hardware key, or the key is not a P-256 point.")
    elif not _key_id_matches(offline.get("key_id"), point):
        worsen(LABEL_FORGED, "The hardware key id is not the key in the package.")
    else:
        _check_signatures(offline, records, point, ticket_hash, clock, worsen)

    if isinstance(clock, dict) and records:
        for index, record in enumerate(records):
            try:
                audit = time_audit.assess(clock, record)
            except ValueError as exc:
                worsen(LABEL_TAMPERED,
                       f"A capture clock could not be read ({exc}).")
                break
            if audit["verdict"] == time_audit.VERDICT_DEVICE_CLOCK_MISMATCH:
                worsen(LABEL_MISMATCH, audit["detail"])
            elif audit["verdict"] == time_audit.VERDICT_UNVERIFIED_TIME:
                worsen(LABEL_UNVERIFIED, audit["detail"])
    elif records:
        worsen(LABEL_UNVERIFIED, "The ticket clock is missing, so the time rules cannot run.")

    receipt_ok, receipt_present, claimed_head = _check_receipt(
        package, custody_head, custody_intact, records, worsen)
    timestamp_absent = _check_timestamp(
        package, custody_head if custody_intact else claimed_head, roots_pem, worsen)

    if label == LABEL_SEALED and timestamp_absent and receipt_present and receipt_ok:
        label = LABEL_TIMESTAMP_ABSENT
    notes = []
    if (timestamp_absent and receipt_present and label != LABEL_TIMESTAMP_ABSENT
            and label != LABEL_FORGED):
        # A missing token is said out loud, and it is not a forgery finding.
        # A forged signature is the finding; the missing token is not added
        # on top of that accusation.
        notes.append(LABEL_TIMESTAMP_ABSENT)
    if label == LABEL_TIMESTAMP_ABSENT:
        notes = []
    return _done(label, flags, notes, " ".join(reasons) if reasons else _ok_detail(label))


def _ok_detail(label):
    if label == LABEL_SEALED:
        return ("The phone chain recomputes, the hardware signatures check, "
                "the ticket signature checks, the time rules pass, and the "
                "timestamp checks against the pinned certificates.")
    if label == LABEL_TIMESTAMP_ABSENT:
        return ("The receipt is present and its signature checks. "
                "The timestamp is absent. A missing timestamp is not a forgery.")
    return ""


def _finish(label, flags, reasons, timestamp_absent, receipt_present):
    notes = []
    if timestamp_absent and receipt_present and label not in (
            LABEL_TIMESTAMP_ABSENT, LABEL_FORGED):
        notes.append(LABEL_TIMESTAMP_ABSENT)
    return _done(label, flags, notes, " ".join(reasons))


def _done(label, flags, notes, detail):
    return {
        "label": label,
        "flags": list(flags),
        "notes": list(notes),
        "detail": detail,
    }


def _flags(captures):
    bits = 0
    for item in captures:
        record = item.get("record") if isinstance(item, dict) else None
        if not isinstance(record, dict) or "flags" not in record:
            continue
        value = record.get("flags")
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        bits |= value
    return flag_words(bits)


def _entries(package):
    if isinstance(package.get("custody_entries"), list):
        return package["custody_entries"]
    if isinstance(package.get("custody"), list):
        return package["custody"]
    return None


def _job_id(package):
    job = package.get("job")
    if isinstance(job, dict) and job.get("shield_job_id"):
        return str(job["shield_job_id"])
    record = package.get("record")
    if isinstance(record, dict) and record.get("id"):
        return str(record["id"])
    if package.get("record_id"):
        return str(package["record_id"])
    return None


def _phone_records(entries):
    found = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        data = entry.get("event_data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                continue
        if isinstance(data, dict) and isinstance(data.get("phone_chain"), list):
            found.extend(item for item in data["phone_chain"] if isinstance(item, dict))
    return found


def _cross_check_phone_chain(entries, records, worsen):
    stored = _phone_records(entries)
    if not stored:
        worsen(LABEL_TAMPERED,
               "The phone chain is not inside a custody entry, so the receipt "
               "does not cover it.")
        return
    left = [item.get("record_hash") for item in stored]
    right = [item.get("record_hash") for item in records]
    if left != right:
        worsen(LABEL_TAMPERED,
               "The phone chain in the package is not the phone chain in the "
               "custody entry.")


def _signing_key(package, offline):
    for source in (package.get("signing_key"), (package.get("receipt") or {}).get("signing_key"),
                   offline.get("signing_key")):
        if isinstance(source, dict):
            return source
    return None


def _b64(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=False)
    except Exception:
        return None


def _point(value):
    raw = _b64(value)
    if raw is None or len(raw) != 65 or raw[0] != 4:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except Exception:
        return None
    return raw


def _public_key(signing):
    if not isinstance(signing, dict):
        return None
    raw = _point(signing.get("uncompressed_point_b64"))
    if raw is not None:
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    pem = signing.get("pem") or ""
    if "PRIVATE" in pem or "BEGIN" not in pem:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key = load_pem_public_key(pem.encode("utf-8"))
    except Exception:
        return None
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return None
    return key


def _ecdsa_ok(signing, body, signature_b64):
    key = _public_key(signing)
    raw = _b64(signature_b64)
    if key is None or raw is None or not isinstance(body, (bytes, bytearray)):
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        key.verify(raw, bytes(body), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _key_id_matches(key_id, point):
    if not key_id:
        return True
    digest = base64.b64encode(hashlib.sha256(point).digest()).decode("ascii")
    return key_id.strip() == digest


def _check_signatures(offline, records, point, ticket_hash, clock, worsen):
    platform = offline.get("platform")
    if platform not in ("ios", "android"):
        worsen(LABEL_FORGED, "The package does not name ios or android.")
        return
    if not isinstance(clock, dict) or not ticket_hash:
        worsen(LABEL_FORGED, "The ticket signature cannot be checked without the ticket clock.")
        return
    try:
        challenge, payload = ticket.hardware_binding(ticket_hash, clock)
    except ValueError as exc:
        worsen(LABEL_FORGED, f"The ticket clock could not be signed over ({exc}).")
        return
    previous = 0
    ticket_assertion = offline.get("ticket_assertion")
    ok, previous = _one_signature(
        platform, ticket_assertion, challenge, payload, point,
        offline.get("app_id"), previous)
    if not ok:
        worsen(LABEL_FORGED, "The hardware signature on the job ticket does not verify.")
        return
    for index, item in enumerate(offline["captures"]):
        record = records[index]
        assertion = item.get("assertion") or record.get("hardware_signature")
        custody_copy = record.get("hardware_signature")
        if custody_copy and assertion and custody_copy != assertion:
            worsen(LABEL_TAMPERED,
                   "The hardware signature on a capture does not match the "
                   "custody entry.")
            return
        try:
            cap_challenge, cap_payload = queue_ingest.hardware_binding(
                record.get("record_hash"))
        except ValueError:
            worsen(LABEL_FORGED, "A capture has no record hash to sign.")
            return
        ok, previous = _one_signature(
            platform, assertion, cap_challenge, cap_payload, point,
            offline.get("app_id"), previous)
        if not ok:
            worsen(LABEL_FORGED,
                   f"The hardware signature on capture {index + 1} does not verify.")
            return


def _one_signature(platform, assertion_b64, challenge, payload, point, app_id, previous):
    raw = _b64(assertion_b64)
    if raw is None:
        return False, previous
    if platform == "ios":
        import app_attest
        checked = app_attest.verify_assertion(
            raw, challenge=challenge, payload_sha256=payload,
            app_id=app_id or "", public_key=point, previous_counter=previous,
            environment="production", allow_development=False)
        if checked.get("verified") is not True:
            return False, previous
        return True, int(checked["counter"])
    import android_attest
    checked = android_attest.verify_signature(
        raw, challenge=challenge, payload_sha256=payload, public_key=point)
    if checked.get("verified") is not True:
        return False, previous
    return True, previous


def _check_receipt(package, custody_head, custody_intact, records, worsen):
    receipt = package.get("receipt")
    if not isinstance(receipt, dict):
        worsen(LABEL_FORGED, "The package has no receipt.")
        return False, False, None
    signed = receipt.get("signed") if isinstance(receipt.get("signed"), dict) else None
    if signed is None:
        signed = {
            "version": receipt.get("version"),
            "record_id": receipt.get("record_id"),
            "head_hash": receipt.get("head_hash"),
            "accepted_at_ms": receipt.get("accepted_at_ms"),
        }
    signature = receipt.get("signature") or receipt.get("server_signature")
    try:
        body = tsa.canonical(signed)
    except ValueError as exc:
        worsen(LABEL_FORGED, f"The receipt could not be read ({exc}).")
        return False, True, None
    if not _ecdsa_ok(_signing_key(package, package.get("offline") or {}), body, signature):
        worsen(LABEL_FORGED, "The receipt signature does not verify.")
        return False, True, signed.get("head_hash")
    claimed = signed.get("head_hash")
    if custody_intact and claimed != custody_head:
        worsen(LABEL_TAMPERED,
               "The receipt is not over the custody head these bytes produce.")
    job_id = _job_id(package)
    if job_id and str(signed.get("record_id") or "") != job_id:
        worsen(LABEL_FORGED, "The receipt is not for this record.")
    if records:
        phone_head = records[-1].get("record_hash")
        stated = receipt.get("phone_chain_head")
        if stated and stated != phone_head:
            worsen(LABEL_TAMPERED,
                   "The receipt names a phone-chain head these records do not end at.")
    return True, True, claimed


def _check_timestamp(package, head, roots_pem, worsen):
    block = package.get("timestamp")
    if not isinstance(block, dict):
        return True
    token = block.get("token_b64")
    present = block.get("status") == "present" and isinstance(token, str) and token.strip()
    if not present:
        return True
    raw = _b64(token)
    if raw is None or not head:
        worsen(LABEL_FORGED, "The timestamp token could not be checked.")
        return False
    checked = tsa.verify_token(raw, head_hash=head, roots_pem=roots_pem)
    if not checked.get("ok"):
        worsen(LABEL_FORGED,
               "The timestamp does not check against the pinned certificates. "
               + checked.get("reason", ""))
        return False
    return False
