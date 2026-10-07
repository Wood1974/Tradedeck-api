"""Opt-in extras. All off unless the tenant turns one on. None is SEALED.

Three extras, each independent:

* A short GNSS fix: time, satellite count, accuracy in millimetres, and the
  platform mock flag. The phone hashes the canonical JSON of that object
  into the capture record as ``gnss_fix_hash``. This module checks the
  object against that hash. It does not grade the photograph.

* A micro-clip of about a second. The phone hashes the bytes into the
  record as ``clip_sha256``. The bytes are stored under a clip path, not
  as the photograph. A clip larger than ``MAX_CLIP_BYTES`` is refused.

* A second phone countersigns the record hash. The server accepts that
  signature only when the tenant has turned countersign on, the second key
  is an attested key of the same tenant, and it is not the key that signed
  the capture. One key signing twice is not two phones.

A record that omits all three is the record this stack already seals.
SEALED does not read these fields. A missing extra is not TAMPERED, not
FORGED, and not a time label.
"""
import hashlib
import hmac

import capture_record

COUNTERSIGN_CHALLENGE = "shield-countersign-v1"

# About a second of video, with room for a phone that compresses poorly.
# A longer file is not this extra.
MAX_CLIP_BYTES = 2_000_000

_GNSS_INTS = ("time_ms", "sat_count", "accuracy_mm")


def flags_from_row(row):
    """The three switches, defaulting off when the column is absent."""
    row = row if isinstance(row, dict) else {}
    return {
        "gnss_fix": row.get("opt_in_gnss_fix") is True,
        "micro_clip": row.get("opt_in_micro_clip") is True,
        "countersign": row.get("opt_in_countersign") is True,
    }


def gnss_fix_hash(fix):
    """Lowercase hex SHA-256 of the canonical GNSS fix.

    ``time_ms`` is Unix milliseconds. ``sat_count`` is how many satellites
    the fix used. ``accuracy_mm`` is the reported accuracy in millimetres,
    so a metre is ``1000`` and a float never enters the signed bytes.
    ``mock`` is the platform's own simulated-location flag.
    """
    if not isinstance(fix, dict):
        raise ValueError("gnss fix must be an object")
    out = {}
    for key in _GNSS_INTS:
        if key not in fix or fix[key] is None:
            raise ValueError(f"gnss fix needs {key}")
        out[key] = capture_record._whole(
            fix[key], key, non_negative=(key != "time_ms"))
    if "mock" not in fix or fix["mock"] is None:
        raise ValueError("gnss fix needs mock")
    if not isinstance(fix["mock"], bool):
        raise ValueError("mock must be true or false")
    out["mock"] = fix["mock"]
    return capture_record.hash_whole(out)


def clip_sha256(data):
    """Lowercase hex SHA-256 of the micro-clip bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
        raise ValueError("micro-clip must be bytes")
    if len(data) > MAX_CLIP_BYTES:
        raise ValueError(
            "micro-clip is longer than about a second of video")
    return hashlib.sha256(bytes(data)).hexdigest()


def clip_path(tenant_id, record_id, record_hash):
    """Bucket path for a clip. Not the photograph's path."""
    return f"{tenant_id}/{record_id}/clips/{record_hash}.mp4"


def countersign_binding(record_hash_hex):
    """``(challenge, payload)`` for the second phone's signature.

    The payload is the raw record hash. The challenge is not the capture
    challenge and not the genesis challenge, so a capture assertion does
    not verify as a countersignature and the reverse is also refused.
    """
    if (not isinstance(record_hash_hex, str)
            or capture_record._SHA256_HEX.fullmatch(record_hash_hex) is None):
        raise ValueError("record hash must be a 64-character lowercase hex SHA-256")
    return COUNTERSIGN_CHALLENGE, bytes.fromhex(record_hash_hex)


def distinct_keys(capture_key_id, countersign_key_id):
    """True when the two ids are present and not the same key."""
    if not capture_key_id or not countersign_key_id:
        return False
    if not isinstance(capture_key_id, str) or not isinstance(countersign_key_id, str):
        return False
    return not hmac.compare_digest(capture_key_id, countersign_key_id)


def check_record_extras(record, gnss_fix, clip):
    """Refuse a batch item whose extra does not match the signed hash.

    Returns ``None`` when the item may be stored, or a sentence when it
    must not. An omitted extra is ``None`` here and is not a refusal.
    A present hash with no bytes, or bytes with no hash, is a refusal:
    the signed record and the upload have to describe the same thing.
    """
    if not isinstance(record, dict):
        return "A capture has no record. Nothing was stored."
    claimed_fix = record.get("gnss_fix_hash")
    if claimed_fix:
        try:
            digest = gnss_fix_hash(gnss_fix)
        except ValueError as exc:
            return f"The GNSS fix could not be read ({exc}). Nothing was stored."
        if not hmac.compare_digest(digest, claimed_fix):
            return "The GNSS fix does not match the capture record. Nothing was stored."
    elif gnss_fix not in (None, {}):
        return ("A GNSS fix was sent that the capture record does not sign. "
                "Nothing was stored.")

    claimed_clip = record.get("clip_sha256")
    if claimed_clip:
        try:
            digest = clip_sha256(clip)
        except ValueError as exc:
            return f"The micro-clip could not be read ({exc}). Nothing was stored."
        if not hmac.compare_digest(digest, claimed_clip):
            return "The micro-clip does not match the capture record. Nothing was stored."
    elif clip:
        return ("A micro-clip was sent that the capture record does not sign. "
                "Nothing was stored.")
    return None
