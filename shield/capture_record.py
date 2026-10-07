"""Canonical bytes for one on-phone capture record.

What this is, and what it is not
--------------------------------
The custody ledger in ``ledger.py`` is the server's chain. It stays on
``chain_version`` 2, and this module does not touch it. A phone that keeps
working with no signal needs its own record: a small JSON object the hardware
key will sign, linked to the previous record the phone already signed.

This file is only the byte rules. It does not talk to a phone, a database, or
a route. Later work verifies the hardware signature, the job ticket, and the
timestamp. A record that passes here is internally consistent. It is not yet
a sealed capture.

The signing contract
--------------------
Today's app binds an attestation to ``SHA256(challenge ‖ SHA256(photo))``.
Signing this record instead is a different contract. ``version`` is inside
the hashed bytes so the two can be told apart. Version 1 is the record
described here. It is not ``ledger.CHAIN_VERSION``.

Canonical form
--------------
The JSON rules are the ones SPEC.md already publishes for the custody chain:

  * only the fields listed in ``RECORD_FIELDS``
  * keys sorted, separators tight, UTF-8
  * null and absent are the same thing
  * non-ASCII is escaped the way ``json.dumps`` escapes it by default

One rule is stronger than the custody chain, on purpose. The custody chain
renders two coordinates with ``repr()`` because those fields were already
floats. This record has no float fields. Coordinates are microdegrees,
angles are hundredths of a degree, durations are milliseconds, counts and
flags are whole numbers, hashes are lowercase hex. A float is rejected.
Accepting one and rendering it would bring back the bug SPEC.md §7 records:
two languages looking at the same JSON token and hashing different bytes.

Booleans are JSON ``true`` / ``false``, not ``0`` / ``1``. Those are
different bytes, and a reader cannot be asked to guess which one was signed.

The link
--------
Same formula as the custody chain::

    record_hash = SHA256( canonical(record) || "|" || prev_hash )

``prev_hash`` and ``record_hash`` travel on the record and are not inside
the canonical JSON. The first record's ``prev_hash`` is the ticket hash.
This module does not define the ticket; the caller passes that hash in.

Verification reports TAMPERED when the stored hash does not reproduce, or
when a record does not name the hash of the record before it. It reports
INTACT otherwise. INTACT is not SEALED: the signature, the ticket, and the
timestamp are checked elsewhere.
"""
import hashlib
import json
import re

# This record's own contract version. Not ledger.CHAIN_VERSION.
RECORD_VERSION = 1

# Whole numbers in the record must survive a JavaScript verifier. JSON has
# one number type, and every integer past this stops being exact in IEEE-754.
JS_SAFE_INT = 2**53 - 1

# How a phone scales a quantity before it is allowed into a signed object.
# The canonicalizer does not convert. A float means the caller skipped this.
MICRODEGREES_PER_DEGREE = 1_000_000
HUNDREDTHS_PER_DEGREE = 100
MILLISECONDS_PER_SECOND = 1_000

# Fixed membership. Order here is not the byte order; json.dumps sorts keys,
# which is the published rule. Membership is what must never drift.
RECORD_FIELDS = (
    "version",
    "checkpoint_id",
    "photo_sha256",
    "ticket_id",
    "wall_time_ms",
    "monotonic_ms",
    "boot_id",
    "boot_count",
    "gnss_time_ms",
    "location_simulated",
    "sensor_hash",
    "depth_hash",
    "depth_present",
    "gnss_fix_hash",
    "clip_sha256",
    "flags",
)

# Always present. Omitting one of these is a different record, not a null.
REQUIRED_FIELDS = (
    "version",
    "checkpoint_id",
    "photo_sha256",
    "ticket_id",
    "wall_time_ms",
    "monotonic_ms",
    "flags",
)

_INT_FIELDS = frozenset({
    "version",
    "wall_time_ms",
    "monotonic_ms",
    "boot_count",
    "gnss_time_ms",
    "flags",
})
_NON_NEGATIVE_INTS = frozenset({
    "version",
    "monotonic_ms",
    "boot_count",
    "flags",
})
_BOOL_FIELDS = frozenset({"location_simulated", "depth_present"})
_HEX_FIELDS = frozenset({
    "photo_sha256", "sensor_hash", "depth_hash",
    "gnss_fix_hash", "clip_sha256",
})
_TEXT_FIELDS = frozenset({"checkpoint_id", "ticket_id", "boot_id"})

# Screen captured, debugger, mock location, root traces. Higher bits are
# reserved for a later flag and must not be stripped: dropping an unknown
# bit would be an edit to a signed integer.
FLAG_SCREEN_CAPTURED = 1 << 0
FLAG_DEBUGGER = 1 << 1
FLAG_MOCK_LOCATION = 1 << 2
FLAG_ROOT_TRACES = 1 << 3

_FLAG_NAMES = (
    (FLAG_SCREEN_CAPTURED, "screen_captured"),
    (FLAG_DEBUGGER, "debugger"),
    (FLAG_MOCK_LOCATION, "mock_location"),
    (FLAG_ROOT_TRACES, "root_traces"),
)

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 512

VERDICT_INTACT = "INTACT"
VERDICT_TAMPERED = "TAMPERED"


def _reject_float(value, key):
    """Floats are a contract violation, not a value to render.

    ``bool`` is not a float. ``int`` is not a float. Everything else numeric
    is, including NaN and the infinities, which ``repr()`` would otherwise
    turn into the strings ``nan`` and ``inf``.
    """
    if isinstance(value, float):
        raise ValueError(
            f"{key} is a float; the capture record only signs whole numbers "
            f"(microdegrees, hundredths of a degree, milliseconds, counts)")


def _whole(value, key, *, non_negative=False):
    _reject_float(value, key)
    # bool is an int subclass. JSON renders true and 1 differently, so a
    # boolean in an integer field is a different record, not a convenience.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be a whole number")
    if abs(value) > JS_SAFE_INT:
        raise ValueError(
            f"{key} is outside the range a JSON number can carry exactly")
    if non_negative and value < 0:
        raise ValueError(f"{key} cannot be negative")
    return value


def _text(value, key):
    _reject_float(value, key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    if value == "":
        raise ValueError(f"{key} must not be empty")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"{key} is longer than {_MAX_TEXT} characters")
    return value


def _sha256_hex(value, key):
    text = _text(value, key)
    if _SHA256_HEX.fullmatch(text) is None:
        raise ValueError(
            f"{key} must be a 64-character lowercase hex SHA-256")
    return text


def _field(key, value):
    if key in _BOOL_FIELDS:
        _reject_float(value, key)
        if not isinstance(value, bool):
            raise ValueError(
                f"{key} must be a JSON boolean, not {type(value).__name__}")
        return value
    if key in _HEX_FIELDS:
        return _sha256_hex(value, key)
    if key in _INT_FIELDS:
        return _whole(value, key, non_negative=key in _NON_NEGATIVE_INTS)
    if key in _TEXT_FIELDS:
        return _text(value, key)
    raise ValueError(f"unknown capture-record field {key!r}")


def _check_shape(record):
    """Rules that are about the fields together, not one field at a time."""
    if record.get("version") != RECORD_VERSION:
        raise ValueError(
            f"unsupported capture record version {record.get('version')!r}; "
            f"this contract is version {RECORD_VERSION}")
    for key in REQUIRED_FIELDS:
        if key not in record or record[key] is None:
            raise ValueError(f"capture record is missing {key}")
    present = record.get("depth_present")
    digest = record.get("depth_hash")
    if present is True and digest is None:
        raise ValueError("depth_present is true but depth_hash is missing")
    if digest is not None and present is not True:
        raise ValueError("depth_hash is set but depth_present is not true")


def _walk_whole(value, key):
    """A sensor snapshot or depth payload: JSON of whole numbers only."""
    _reject_float(value, key)
    if value is None or isinstance(value, str):
        if isinstance(value, str) and len(value) > _MAX_TEXT:
            raise ValueError(f"{key} is longer than {_MAX_TEXT} characters")
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _whole(value, key)
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError(f"{key} has a non-string key")
        return {k: _walk_whole(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_walk_whole(v, key) for v in value]
    raise ValueError(
        f"{key} has type {type(value).__name__}, which the capture record "
        f"cannot sign")


def canonical(record: dict) -> bytes:
    """UTF-8 JSON of the signed fields. Rejects a float anywhere in them.

    Missing and null are omitted, so an optional field left out and the same
    field set to null hash alike. ``0``, ``false``, and ``""`` are not null
    and are not omitted. An empty string is rejected rather than omitted,
    because it is not the same statement as "the phone did not report this".
    """
    if not isinstance(record, dict):
        raise ValueError("capture record must be a JSON object")
    _check_shape(record)
    out = {}
    for key in RECORD_FIELDS:
        if key not in record or record[key] is None:
            continue
        out[key] = _field(key, record[key])
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def canonical_whole(payload) -> bytes:
    """Canonical JSON for a snapshot that will be hashed into the record.

    Angles in the payload are hundredths of a degree. Coordinates are
    microdegrees. Durations are milliseconds. This function checks that
    they are whole numbers; it does not scale them. A float is rejected,
    including inside nested objects and lists.
    """
    if not isinstance(payload, dict):
        raise ValueError("snapshot must be a JSON object")
    # Drop nulls at every object level so absent and null stay identical.
    # A null inside a list stays: position in a list is data.
    walked = _drop_nulls(_walk_whole(payload, "payload"))
    return json.dumps(walked, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _drop_nulls(value):
    if isinstance(value, dict):
        return {k: _drop_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_nulls(v) for v in value]
    return value


def hash_whole(payload) -> str:
    """Lowercase hex SHA-256 of a whole-number snapshot."""
    return hashlib.sha256(canonical_whole(payload)).hexdigest()


def photo_sha256(data) -> str:
    """SHA-256 of the original photo bytes.

    ``data`` may be the whole buffer or an iterable of chunks, so a phone
    can update the hash as the JPEG is produced without a second copy of
    the file. The hex is what ``photo_sha256`` on the record holds.
    """
    digest = hashlib.sha256()
    if isinstance(data, (bytes, bytearray, memoryview)):
        digest.update(data)
    else:
        # An empty iterator hashes as a zero-byte photo. That is a real
        # input, not a missing one.
        for chunk in data:
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                raise TypeError("photo chunks must be bytes")
            digest.update(chunk)
    return digest.hexdigest()


def link(record: dict, prev_hash: str) -> str:
    """Hash of one record given the hash of the record before it."""
    if not isinstance(prev_hash, str):
        raise ValueError("prev_hash must be a string")
    return hashlib.sha256(
        canonical(record) + b"|" + prev_hash.encode("utf-8")).hexdigest()


def build(*, checkpoint_id, photo_sha256, ticket_id, wall_time_ms,
          monotonic_ms, flags=0, boot_id=None, boot_count=None,
          gnss_time_ms=None, location_simulated=None, sensor_hash=None,
          depth_hash=None, depth_present=None, gnss_fix_hash=None,
          clip_sha256=None, version=RECORD_VERSION) -> dict:
    """A record dict with nulls removed, validated, not yet linked.

    ``flags`` defaults to 0 because "no flag bits set" is a real statement
    and must be the integer 0, not an omitted field. The mock-location
    field does not default: omitted means the phone did not report it,
    which is not the same byte string as false.
    """
    record = {
        "version": version,
        "checkpoint_id": checkpoint_id,
        "photo_sha256": photo_sha256,
        "ticket_id": ticket_id,
        "wall_time_ms": wall_time_ms,
        "monotonic_ms": monotonic_ms,
        "boot_id": boot_id,
        "boot_count": boot_count,
        "gnss_time_ms": gnss_time_ms,
        "location_simulated": location_simulated,
        "sensor_hash": sensor_hash,
        "depth_hash": depth_hash,
        "depth_present": depth_present,
        "gnss_fix_hash": gnss_fix_hash,
        "clip_sha256": clip_sha256,
        "flags": flags,
    }
    record = {k: v for k, v in record.items() if v is not None}
    canonical(record)  # validate; the bytes are recomputed by seal/link
    return record


def seal(record: dict, prev_hash: str) -> dict:
    """The record plus ``prev_hash`` and ``record_hash``.

    Chain metadata is stored beside the signed fields, not inside them.
    Unknown keys on ``record`` are kept so a caller can carry metadata,
    and they are not covered by the hash.
    """
    if not isinstance(prev_hash, str) or _SHA256_HEX.fullmatch(prev_hash) is None:
        raise ValueError(
            "prev_hash must be a 64-character lowercase hex SHA-256")
    digest = link(record, prev_hash)
    sealed = dict(record)
    for key in list(sealed):
        if key in RECORD_FIELDS and sealed[key] is None:
            del sealed[key]
    sealed["prev_hash"] = prev_hash
    sealed["record_hash"] = digest
    return sealed


def flag_names(flags) -> list:
    """Names of the bits set in ``flags``, lowest bit first.

    A bit this version does not name is reported as ``bit_N`` rather than
    dropped. Display only: nothing in this list changes a verdict.
    """
    value = _whole(flags, "flags", non_negative=True)
    names = [name for bit, name in _FLAG_NAMES if value & bit]
    known = 0
    for bit, _name in _FLAG_NAMES:
        known |= bit
    extra = value & ~known
    bit_index = 0
    while extra:
        if extra & 1:
            names.append(f"bit_{bit_index}")
        extra >>= 1
        bit_index += 1
    return names


def verify_chain(records, first_prev, expect_head=None) -> dict:
    """Walk records in chain order and check every byte and every link.

    ``first_prev`` is the hash the first record must name. For a phone
    chain that is the ticket hash, which a later document defines. This
    function does not derive it.

    ``expect_head``, when passed, is a head the holder already has. Dropping
    records off the end leaves a shorter chain whose remaining links still
    verify; only this comparison catches it. That is the same property the
    custody chain has, and it is why a head that has left the phone matters.

    A malformed record is TAMPERED. Raising would turn a bad upload into an
    unhandled error, and an unhandled error is not a verdict.
    """
    if not isinstance(records, (list, tuple)):
        raise ValueError("records must be a list")
    expected_prev = first_prev
    broken_at = None
    reason = None

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            broken_at = index
            reason = "record is not an object, so its bytes cannot be reproduced"
            break
        stored_prev = record.get("prev_hash")
        stored_hash = record.get("record_hash")
        if not isinstance(stored_hash, str) or not stored_hash:
            broken_at = index
            reason = "record carries no hash (never linked, or the hash was stripped)"
            break
        if stored_prev != expected_prev:
            broken_at = index
            reason = (
                "link broken: this record does not name the hash of the "
                "record before it")
            break
        try:
            recomputed = link(record, stored_prev)
        except ValueError as exc:
            broken_at = index
            reason = f"bytes do not reproduce the hash ({exc})"
            break
        if recomputed != stored_hash:
            broken_at = index
            reason = (
                "bytes do not reproduce the hash: a signed field was edited "
                "after the record was hashed")
            break
        expected_prev = stored_hash

    head = expected_prev
    intact = broken_at is None
    if intact and expect_head is not None and head != expect_head:
        intact = False
        reason = (
            "head does not match the head the holder was given; the chain "
            "was extended, shortened, or rewritten")

    verdict = VERDICT_INTACT if intact else VERDICT_TAMPERED
    count = len(records)
    return {
        "verdict": verdict,
        "intact": intact,
        "records": count,
        "verified": count if broken_at is None else broken_at,
        "broken_at_index": broken_at,
        "reason": reason,
        "head_hash": head,
        "record_version": RECORD_VERSION,
        "summary": (
            f"All {count} capture records reproduce their hashes and links."
            if intact else
            (f"Capture chain is TAMPERED at record {broken_at + 1} of {count}: {reason}"
             if broken_at is not None else
             f"Capture chain is TAMPERED: {reason}")),
    }
