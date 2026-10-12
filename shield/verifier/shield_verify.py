#!/usr/bin/env python3
"""Independent verifier for a TradeDeck Shield evidence package.

Standard library only. No network. No Shield code. Copy this one file
anywhere and run it against a package you were given:

    python shield_verify.py manifest.json
    python shield_verify.py manifest.json --files ./photos

Why this file exists
--------------------
Shield's export claims a recipient can check it "without trusting us". That
claim is worth nothing if checking it requires running Shield's own code
against Shield's own database — you would only be asking the accused to
re-examine themselves.

So this is a *reimplementation from the published specification* (SPEC.md),
not an import of the production module. It shares no code with the service
that produced the package. When the two agree, that agreement means something:
two independent implementations of a written spec reached the same hash. If
Shield's `ledger.py` ever develops a bug, this file does not inherit it.

A test in Shield's own suite runs both against the same generated data and
asserts they agree, so the divergence gets caught by us before it gets found
by an opposing expert.

What it establishes
-------------------
  * Each custody entry hashes to the value it stores, given its predecessor.
  * The chain runs unbroken from a genesis value derived from the job id.
  * The head hash you were handed matches the head this chain computes.
  * Where photo files are supplied, their SHA-256 matches the manifest.
  * A receipt, when the package has one, is an ECDSA P-256 signature over
    the record id, the head this file just computed, and the time it was
    signed. A receipt over a different head fails with no --expect-head.
  * An RFC 3161 token, when present, carries that same head as the TSTInfo
    message imprint. This file checks the imprint. It does not check the
    token's certificate chain; the verify page does, against pinned roots.

What it cannot establish
------------------------
  * That any photo came off a camera sensor rather than a file picker.
  * That the AI verdicts are correct.
  * That the work complies with any building code.
  * That no entry was *deleted before the chain was ever written* — the chain
    proves nothing was altered after the fact, not that everything that
    happened was recorded.
  * That the chain has not been TRUNCATED. Dropping entries from the end
    leaves a shorter chain in which every remaining link still verifies.
    Only a head hash you were given earlier detects it — pass --expect-head.

A package can verify perfectly and still describe work that was never done.
This tool checks integrity, not truth.
"""
import argparse
import hashlib
import json
import os
import sys

SPEC_VERSION = 2
GENESIS_PREFIX = "shield-custody-genesis-v1:"

# Fixed order. The hash covers these fields and nothing else — see SPEC.md.
SIGNED_FIELDS = (
    "shield_job_id",
    "photo_id",
    "event_type",
    "actor_id",
    "actor_type",
    "event_data",
    "gps_lat",
    "gps_lng",
    "file_hash",
    "integrity_note",
    "recorded_at",
)

# NOT signed since v2 (AR-11): exif_captured_at. The uploader writes EXIF
# DateTimeOriginal, so sealing it proved only that we had not changed it since
# recording -- which reads as though the capture time were established. It is
# still in the record; the chain simply does not vouch for it.


# --------------------------------------------------------------- hashing ---
def _finite(value, key):
    """repr() a float, refusing NaN and Infinity rather than sealing them."""
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite value for %r" % key)
    return repr(value)


def genesis_hash(shield_job_id):
    """The value the first entry's prev_hash must equal."""
    return hashlib.sha256((GENESIS_PREFIX + str(shield_job_id)).encode()).hexdigest()


def canonical(entry):
    """Deterministic bytes for one entry's signed fields.

    Per SPEC.md: signed fields only, absent and null are identical, floats via
    repr(), nested structures as compact sorted JSON, then the whole thing as
    compact sorted JSON. Non-finite numbers are refused rather than rendered.
    """
    out = {}
    for key in SIGNED_FIELDS:
        value = entry.get(key)
        if value is None:
            continue
        if isinstance(value, float):
            value = _finite(value, key)
        elif isinstance(value, (dict, list)):
            # Not normalised: normalisation is a write-time step in the
            # ledger, because only the writer knows whether 100 was an int or
            # a float. A verifier hashes the row exactly as the package
            # carries it.
            value = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               default=str, allow_nan=False)
        out[key] = value
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      default=str, allow_nan=False).encode()


def link(entry, prev_hash):
    """SHA-256 over canonical(entry) || "|" || prev_hash."""
    return hashlib.sha256(canonical(entry) + b"|" + prev_hash.encode()).hexdigest()


# ------------------------------------------------------------ the checks ---
def verify_chain(entries, shield_job_id):
    """Walk the chain oldest-first. Reports where it breaks, not just that."""
    expected_prev = genesis_hash(shield_job_id)
    for index, entry in enumerate(entries):
        stored_prev = entry.get("prev_hash")
        stored_hash = entry.get("entry_hash")
        if stored_hash is None:
            return _break(index, entries, expected_prev, "entry carries no hash")
        if stored_prev != expected_prev:
            return _break(index, entries, expected_prev,
                          "link mismatch — an entry was inserted, removed or "
                          "reordered here")
        if link(entry, stored_prev) != stored_hash:
            return _break(index, entries, expected_prev,
                          "content altered — a signed field was edited after "
                          "the entry was written")
        expected_prev = stored_hash
    return {"intact": True, "entries": len(entries), "verified": len(entries),
            "broken_at_index": None, "reason": None, "head_hash": expected_prev}


def _break(index, entries, head, reason):
    return {"intact": False, "entries": len(entries), "verified": index,
            "broken_at_index": index, "reason": reason, "head_hash": head}


def verify_files(manifest, file_bytes):
    """Match supplied bytes against the manifest's hashes.

    `file_bytes` maps photo_id -> bytes. Anything absent is reported as not
    supplied rather than as a failure — a recipient may hold only some files.
    """
    results = []
    for item in manifest.get("checkpoints", []):
        photo_id, expected = item.get("photo_id"), item.get("sha256_original")
        if not photo_id or not expected:
            results.append({"checkpoint": item.get("checkpoint_number"),
                            "photo_id": photo_id, "status": "no photo in package"})
            continue
        if photo_id not in file_bytes:
            results.append({"checkpoint": item.get("checkpoint_number"),
                            "photo_id": photo_id, "status": "file not supplied"})
            continue
        actual = hashlib.sha256(file_bytes[photo_id]).hexdigest()
        results.append({
            "checkpoint": item.get("checkpoint_number"),
            "photo_id": photo_id,
            "status": "match" if actual == expected else "MISMATCH",
            "expected": expected, "actual": actual,
        })
    return results


# --------------------------------------------------------------- receipt ---
# P-256. The receipt signature is ECDSA with SHA-256 over the canonical
# receipt. The public point travels in the package. This file does not
# import a cryptography library: a recipient's interpreter may have none.

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_SHA256_OID = "2.16.840.1.101.3.4.2.1"
_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"


def _b64decode(value):
    if not isinstance(value, str):
        return None
    text = "".join(value.split()).replace("-", "+").replace("_", "/")
    if not text:
        return None
    text += "=" * ((-len(text)) % 4)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = bytearray()
    buf = bits = 0
    for ch in text:
        if ch == "=":
            break
        idx = alphabet.find(ch)
        if idx < 0:
            return None
        buf = (buf << 6) | idx
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def _der_items(data):
    items = []
    i = 0
    view = data
    while i < len(view):
        tag = view[i]
        i += 1
        if i >= len(view):
            raise ValueError("truncated DER")
        length = view[i]
        i += 1
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4 or i + count > len(view):
                raise ValueError("bad DER length")
            length = int.from_bytes(view[i:i + count], "big")
            i += count
        if i + length > len(view):
            raise ValueError("truncated DER value")
        items.append((tag, view[i:i + length]))
        i += length
    return items


def _oid_str(content):
    if not content:
        raise ValueError("empty oid")
    parts = [str(content[0] // 40), str(content[0] % 40)]
    i = 1
    while i < len(content):
        n = 0
        while True:
            if i >= len(content):
                raise ValueError("truncated oid")
            byte = content[i]
            i += 1
            n = (n << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        parts.append(str(n))
    return ".".join(parts)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _on_curve(x, y):
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _der_signature(signature):
    items = _der_items(signature)
    if len(items) != 1 or items[0][0] != 0x30:
        raise ValueError("signature is not a sequence")
    inner = _der_items(items[0][1])
    if len(inner) < 2 or inner[0][0] != 0x02 or inner[1][0] != 0x02:
        raise ValueError("signature is not two integers")
    return (int.from_bytes(inner[0][1], "big"), int.from_bytes(inner[1][1], "big"))


def _ecdsa_p256(point, signature, message):
    if not point or len(point) != 65 or point[0] != 4:
        return False
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    if not _on_curve(x, y):
        return False
    try:
        r, s = _der_signature(signature)
    except ValueError:
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, _N - 2, _N)
    u1 = (e * w) % _N
    u2 = (r * w) % _N
    combined = _point_add(_point_mul(u1, (_GX, _GY)), _point_mul(u2, (x, y)))
    if combined is None:
        return False
    return (combined[0] % _N) == r


def _spki_point(der):
    items = _der_items(der)
    if len(items) != 1 or items[0][0] != 0x30:
        return None
    for tag, content in _der_items(items[0][1]):
        if tag == 0x03 and len(content) == 66 and content[0] == 0 and content[1] == 4:
            return content[1:]
    return None


def _public_point(manifest):
    sources = [manifest.get("signing_key")]
    receipt = manifest.get("receipt")
    if isinstance(receipt, dict):
        sources.append(receipt.get("signing_key"))
    offline = manifest.get("offline")
    if isinstance(offline, dict):
        sources.append(offline.get("signing_key"))
    for source in sources:
        if not isinstance(source, dict):
            continue
        raw = _b64decode(source.get("uncompressed_point_b64") or "")
        if raw and len(raw) == 65 and raw[0] == 4:
            return raw
        pem = source.get("pem") if isinstance(source.get("pem"), str) else ""
        if "BEGIN PUBLIC KEY" not in pem or "PRIVATE" in pem:
            continue
        body = "".join(
            line.strip() for line in pem.splitlines()
            if not line.startswith("-----"))
        der = _b64decode(body)
        if not der:
            continue
        try:
            point = _spki_point(der)
        except ValueError:
            point = None
        if point:
            return point
    return None


def _receipt_bytes(signed):
    version = signed.get("version")
    record_id = signed.get("record_id")
    head = signed.get("head_hash")
    at = signed.get("accepted_at_ms")
    if isinstance(version, bool) or version != 1:
        raise ValueError("unsupported receipt version")
    if not isinstance(record_id, str) or record_id == "":
        raise ValueError("record_id")
    if not isinstance(head, str) or len(head) != 64:
        raise ValueError("head_hash")
    try:
        raw = bytes.fromhex(head)
    except ValueError as exc:
        raise ValueError("head_hash") from exc
    if head != raw.hex():
        raise ValueError("head_hash")
    if isinstance(at, bool) or not isinstance(at, int) or at < 0:
        raise ValueError("accepted_at_ms")
    body = {
        "accepted_at_ms": at,
        "head_hash": head,
        "record_id": record_id,
        "version": version,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_receipt(receipt):
    signed = receipt.get("signed") if isinstance(receipt.get("signed"), dict) else receipt
    return signed, receipt.get("signature") or receipt.get("server_signature")


def _job_id(manifest):
    job = manifest.get("job") if isinstance(manifest.get("job"), dict) else {}
    record = manifest.get("record") if isinstance(manifest.get("record"), dict) else {}
    return job.get("shield_job_id") or record.get("id") or None


def _custody_entries(manifest):
    entries = manifest.get("custody_entries")
    if isinstance(entries, list):
        return entries
    custody = manifest.get("custody")
    if isinstance(custody, list):
        return custody
    return None


def _timestamp_imprint(token):
    """The 32-byte SHA-256 imprint, read as the third field of TSTInfo.

    Searching the token for the head bytes would pass a token that merely
    contained them. The certificate chain is not checked here. A token an
    attacker signed themselves can still carry the right imprint; the
    receipt signature is what they cannot produce. The verify page checks
    the chain against the pinned roots.
    """
    outer = _der_items(token)
    if len(outer) != 1 or outer[0][0] != 0x30:
        raise ValueError("no timestamp")
    fields = _der_items(outer[0][1])
    if not fields or fields[0][0] != 0x30:
        raise ValueError("no status")
    if len(fields) < 2:
        raise ValueError("no token")
    if fields[1][0] == 0xA0:
        wrapped = _der_items(fields[1][1])
        if len(wrapped) != 1 or wrapped[0][0] != 0x30:
            raise ValueError("no token")
        info = _der_items(wrapped[0][1])
    elif fields[1][0] == 0x30:
        info = _der_items(fields[1][1])
    else:
        raise ValueError("no token")
    if len(info) < 2 or info[0][0] != 0x06 or _oid_str(info[0][1]) != _SIGNED_DATA_OID:
        raise ValueError("not SignedData")
    if info[1][0] != 0xA0:
        raise ValueError("SignedData is missing")
    # [0] EXPLICIT carries the SignedData SEQUENCE. The imprint lives in
    # encapContentInfo, which is the SEQUENCE after the digest algorithms.
    signed_outer = _der_items(info[1][1])
    if len(signed_outer) != 1 or signed_outer[0][0] != 0x30:
        raise ValueError("SignedData is missing")
    encap = None
    for tag, content in _der_items(signed_outer[0][1]):
        if tag == 0x02:
            continue
        if tag == 0x31 and encap is None:
            continue
        if tag == 0x30 and encap is None:
            encap = content
            break
    if encap is None:
        raise ValueError("TSTInfo is missing")
    encap_fields = _der_items(encap)
    if len(encap_fields) < 2 or encap_fields[1][0] != 0xA0:
        raise ValueError("TSTInfo is missing")
    octet = _der_items(encap_fields[1][1])
    if len(octet) != 1 or octet[0][0] != 0x04:
        raise ValueError("TSTInfo wrapper")
    # The octet string carries the TSTInfo SEQUENCE. The imprint is its
    # third field, MessageImprint, not an octet string found anywhere else.
    tst_outer = _der_items(octet[0][1])
    if len(tst_outer) != 1 or tst_outer[0][0] != 0x30:
        raise ValueError("TSTInfo wrapper")
    tst = _der_items(tst_outer[0][1])
    if len(tst) < 3 or tst[2][0] != 0x30:
        raise ValueError("no imprint")
    oid = hashed = None
    for tag, content in _der_items(tst[2][1]):
        if tag == 0x30 and oid is None:
            alg = _der_items(content)
            if alg and alg[0][0] == 0x06:
                oid = _oid_str(alg[0][1])
        elif tag == 0x04:
            hashed = content
    if hashed is None or oid != _SHA256_OID or len(hashed) != 32:
        raise ValueError("imprint")
    return hashed


def _check_anchor(manifest, chain, job_id):
    """Problems fail the package. Notes do not.

    No receipt is "receipt absent". A receipt whose signature fails, or
    whose head is not the head just computed, is a problem, so a rewritten
    chain that keeps the original receipt fails with no --expect-head.
    No token is "timestamp missing", which is not a problem.
    """
    problems = []
    notes = []
    head = chain.get("head_hash") if chain else None
    receipt = manifest.get("receipt")
    if not isinstance(receipt, dict):
        notes.append("receipt absent")
        return problems, notes
    signed, signature = _signed_receipt(receipt)
    point = _public_point(manifest)
    raw_sig = _b64decode(signature) if isinstance(signature, str) else None
    try:
        body = _receipt_bytes(signed)
    except ValueError:
        body = None
    if not point or not raw_sig or body is None or not _ecdsa_p256(point, raw_sig, body):
        problems.append("The receipt signature does not verify.")
    else:
        if signed.get("head_hash") != head:
            problems.append(
                "The receipt is not over the custody head these bytes produce.")
        elif signed.get("record_id") and str(signed.get("record_id")) != str(job_id):
            problems.append("The receipt is not for this record.")
    block = manifest.get("timestamp") if isinstance(manifest.get("timestamp"), dict) else {}
    token = block.get("token_b64") if block.get("status") == "present" else None
    if not isinstance(token, str) or not token.strip():
        notes.append("timestamp missing")
        return problems, notes
    raw = _b64decode(token)
    try:
        expected = bytes.fromhex(head) if isinstance(head, str) and len(head) == 64 else None
    except ValueError:
        expected = None
    if raw is None or expected is None:
        problems.append("The timestamp token could not be read.")
        return problems, notes
    try:
        imprint = _timestamp_imprint(raw)
    except ValueError:
        problems.append("The timestamp token could not be read.")
        return problems, notes
    if imprint != expected:
        problems.append("The timestamp is not over this custody head.")
    return problems, notes


_LOCK_SKEW_SECONDS = 300
_ANCHORED_EVENTS = frozenset({
    "uploaded", "offline_batch", "superseded", "integrity_flag",
})


def _civil_unix(year, month, day, hour, minute, second, micro=0):
    """Seconds since the Unix epoch. No datetime import: this file stays stdlib-minimal."""
    y = year
    m = month
    if m <= 2:
        y -= 1
        m += 9
    else:
        m -= 3
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * m + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + minute * 60 + second + micro / 1000000.0


def _lock_object_key(anchor):
    key = anchor.get("object_key")
    if isinstance(key, str) and key:
        return key
    record = anchor.get("record_id") or "record"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(record))
    seq = anchor.get("seq")
    try:
        n = int(seq)
    except (TypeError, ValueError):
        n = 0
    if n < 0:
        n = 0
    return "anchors/%s/%08d-%s.json" % (safe, n, anchor.get("head_hash") or "")


def combine_locked_anchors(bundled, extra):
    """Union by object key. A second, different body is a problem.

    The first body stays. A phone backup does not replace it.
    """
    problems = []
    chosen = []
    seen = {}
    for item in list(bundled or []) + list(extra or []):
        if not isinstance(item, dict):
            continue
        key = _lock_object_key(item)
        proof = (item.get("record_id"), item.get("seq"), item.get("head_hash"),
                 item.get("token_b64"))
        if key in seen:
            if seen[key] != proof:
                problems.append("A phone copy does not match the locked anchor.")
            continue
        seen[key] = proof
        chosen.append(item)
    return chosen, problems


def _lock_parse_iso(value):
    """ISO-8601 with a Z or numeric offset, as a Unix second count."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) < 19:
        return None
    if text[4] != "-" or text[7] != "-" or text[10] not in "Tt" or text[13] != ":" or text[16] != ":":
        return None
    try:
        year = int(text[0:4])
        month = int(text[5:7])
        day = int(text[8:10])
        hour = int(text[11:13])
        minute = int(text[14:16])
        second = int(text[17:19])
    except ValueError:
        return None
    micro = 0
    rest = text[19:]
    if rest.startswith("."):
        frac = []
        for ch in rest[1:]:
            if not ch.isdigit():
                break
            frac.append(ch)
        if not frac or len(frac) > 12:
            return None
        micro = int(("".join(frac) + "000000")[:6])
        rest = rest[1 + len(frac):]
    offset = 0
    if rest in ("Z", "z", ""):
        offset = 0
    elif len(rest) >= 6 and rest[0] in "+-" and rest[3] == ":":
        try:
            sign = 1 if rest[0] == "+" else -1
            offset = sign * (int(rest[1:3]) * 3600 + int(rest[4:6]) * 60)
        except ValueError:
            return None
    else:
        return None
    if not (1 <= month <= 12 and 1 <= day <= 31 and 0 <= hour <= 23
            and 0 <= minute <= 59 and 0 <= second <= 60):
        return None
    return _civil_unix(year, month, day, hour, minute, second, micro) - offset


def _lock_parse_gen(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    body = value[:-1]
    frac = ""
    if "." in body:
        body, frac = body.split(".", 1)
        if not frac.isdigit() or len(frac) > 12:
            return None
    if len(body) != 14 or not body.isdigit():
        return None
    year = int(body[0:4])
    month = int(body[4:6])
    day = int(body[6:8])
    hour = int(body[8:10])
    minute = int(body[10:12])
    second = int(body[12:14])
    micro = int((frac + "000000")[:6]) if frac else 0
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return None
    return _civil_unix(year, month, day, hour, minute, second, micro)


def _lock_token_covers(token_b64, head_hash):
    raw = _b64decode(token_b64) if isinstance(token_b64, str) else None
    try:
        expected = bytes.fromhex(head_hash) if isinstance(head_hash, str) else None
    except ValueError:
        expected = None
    if raw is None or expected is None or len(expected) != 32:
        return False
    try:
        imprint = _timestamp_imprint(raw)
    except ValueError:
        return False
    return imprint == expected


def _lock_time_fits(anchor, entry):
    recorded = _lock_parse_iso(entry.get("recorded_at") if isinstance(entry, dict) else None)
    stamped = _lock_parse_gen(anchor.get("gen_time")) or _lock_parse_iso(anchor.get("anchored_at"))
    if recorded is None or stamped is None:
        return False
    return stamped >= recorded - _LOCK_SKEW_SECONDS


def _check_locked(entries, anchors):
    """Locked-anchor problems. An empty set is the note anchor absent.

    This is a separate copy of the rule in anchor_lock.assess_anchors. The
    independent verifier does not import that module. The two are compared
    by test_anchor_lock.
    """
    problems = []
    notes = []
    locked = []
    for anchor in anchors or []:
        if not isinstance(anchor, dict):
            continue
        if anchor.get("timestamp_status") not in (None, "present"):
            continue
        if not anchor.get("token_b64") or not anchor.get("head_hash"):
            continue
        locked.append(anchor)
    if not locked:
        notes.append("anchor absent")
        return problems, notes
    index_of = {}
    for index, entry in enumerate(entries or []):
        if isinstance(entry, dict) and entry.get("entry_hash"):
            index_of.setdefault(entry["entry_hash"], index)
    missed = False
    matched = 0
    for anchor in locked:
        head = anchor.get("head_hash")
        idx = index_of.get(head)
        seq = anchor.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or idx is None or seq != idx:
            missed = True
            continue
        entry = entries[idx]
        if not _lock_token_covers(anchor.get("token_b64"), head):
            problems.append("The locked anchor token does not cover this head.")
            continue
        if not _lock_time_fits(anchor, entry):
            problems.append("The locked anchor time does not fit this entry.")
            continue
        receipt = anchor.get("receipt")
        if isinstance(receipt, dict):
            signed = receipt.get("signed") if isinstance(receipt.get("signed"), dict) else receipt
            claimed = signed.get("head_hash") if isinstance(signed, dict) else None
            if claimed and claimed != head:
                problems.append("The locked anchor receipt is not over this head.")
                continue
        matched += 1
    if missed:
        problems.append("A locked anchor names a head that is not in this chain.")
    head = None
    head_type = None
    if entries and isinstance(entries[-1], dict):
        head = entries[-1].get("entry_hash")
        head_type = entries[-1].get("event_type")
    covered = any(anchor.get("head_hash") == head for anchor in locked)
    if head and not covered and (head_type in _ANCHORED_EVENTS or matched == 0):
        problems.append("no locked anchor for this head")
    return problems, notes


def verify_package(manifest, file_bytes=None, expect_head=None, anchors=None):
    """Everything checkable from a manifest, plus any files supplied.

    `expect_head` is a head hash you were given EARLIER, from your own records
    — not the one inside this package. An operator who truncates the chain and
    re-signs a receipt over the shorter head still verifies; comparing it
    against a head you already held catches that. A rewrite that keeps the
    receipt over the original head does not: the receipt is checked against
    the head these entries compute, with no --expect-head required.

    An evidence manifest names `job.shield_job_id` and `custody_entries`.
    The record package from the API names `record.id` and carries `custody`
    as the entry list. Either shape is checked. A package with neither id
    still reports `manifest has no job.shield_job_id`.
    """
    problems = []
    job_id = _job_id(manifest)
    if not job_id:
        return {"ok": False, "problems": ["manifest has no job.shield_job_id"],
                "notes": [], "chain": None, "files": []}

    entries = _custody_entries(manifest)
    if entries is None:
        problems.append(
            "package carries no custody_entries — the chain cannot be "
            "recomputed, so its integrity is this vendor's assertion rather "
            "than something you verified")
        chain = None
    else:
        chain = verify_chain(entries, job_id)
        if not chain["intact"]:
            problems.append("custody chain breaks at entry %d of %d: %s" % (
                chain["broken_at_index"] + 1, chain["entries"], chain["reason"]))

        claimed = manifest.get("custody") if isinstance(
            manifest.get("custody"), dict) else {}
        stated = []
        if claimed.get("head_hash"):
            stated.append(claimed["head_hash"])
        if manifest.get("head_hash"):
            stated.append(manifest["head_hash"])
        for value in stated:
            if value != chain["head_hash"]:
                problems.append(
                    "head hash disagreement — the package states %s… but its own "
                    "entries compute to %s…" % (str(value)[:16],
                                                chain["head_hash"][:16]))
                break
        if claimed.get("chain_intact") is True and not chain["intact"]:
            problems.append(
                "the package asserts chain_intact: true and it is not")
        if claimed.get("entries") is not None and \
                claimed["entries"] != chain["entries"]:
            problems.append(
                "entry count disagreement — package states %s, carries %d"
                % (claimed["entries"], chain["entries"]))

    if expect_head and chain:
        if chain["head_hash"] != expect_head:
            problems.append(
                "head does not match the one you were given — you hold %s… and "
                "this package computes %s…. Entries have been removed from the "
                "end, or the history was rewritten. Both verify perfectly on "
                "their own; only your copy of the head detects this."
                % (str(expect_head)[:16], chain["head_hash"][:16]))
    notes = []
    if chain and not expect_head:
        notes.append(
            "No expected head supplied. A chain truncated at the end verifies "
            "perfectly — pass --expect-head with the head hash you were given "
            "when the record was closed out.")
    anchor_problems, anchor_notes = _check_anchor(manifest, chain, job_id)
    problems.extend(anchor_problems)
    notes.extend(anchor_notes)
    bundled = manifest.get("locked_anchors")
    if not isinstance(bundled, list):
        bundled = []
    chosen, copy_problems = combine_locked_anchors(bundled, anchors)
    problems.extend(copy_problems)
    locked_problems, locked_notes = _check_locked(
        entries if isinstance(entries, list) else [], chosen)
    problems.extend(locked_problems)
    notes.extend(locked_notes)

    files = verify_files(manifest, file_bytes or {})
    for f in files:
        if f["status"] == "MISMATCH":
            problems.append("photo %s does not match its recorded hash"
                            % f["photo_id"])

    return {"ok": not problems, "problems": problems, "notes": notes,
            "chain": chain, "files": files}


# ------------------------------------------------------------------ cli ----
def _load_files(directory):
    """photo_id -> bytes, taking the photo id from the filename stem."""
    out = {}
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                out[os.path.splitext(name)[0]] = fh.read()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify a TradeDeck Shield evidence package. "
                    "Standard library only; nothing is sent anywhere.")
    ap.add_argument("manifest", help="path to the manifest JSON")
    ap.add_argument("--files", help="directory of photos named <photo_id>.<ext>")
    ap.add_argument("--expect-head", dest="expect_head",
                    help="the head hash you were given earlier, from your own "
                         "records — this is what detects truncation")
    ap.add_argument("--anchors",
                    help="JSON file of locked anchors, from `python -m "
                         "anchor_lock export` or a phone backup. Unioned with "
                         "locked_anchors in the package. Two bodies for one "
                         "object key fail closed. The package list alone is "
                         "not the deciding set: the exporter can omit an object.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    with open(args.manifest) as fh:
        manifest = json.load(fh)
    extra_anchors = None
    if args.anchors:
        with open(args.anchors) as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            extra_anchors = loaded.get("anchors")
        elif isinstance(loaded, list):
            extra_anchors = loaded
        else:
            extra_anchors = []
    report = verify_package(manifest,
                            _load_files(args.files) if args.files else None,
                            expect_head=args.expect_head,
                            anchors=extra_anchors)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    job = manifest.get("job") if isinstance(manifest.get("job"), dict) else {}
    record = manifest.get("record") if isinstance(manifest.get("record"), dict) else {}
    print("Shield evidence package — independent verification")
    print("  job                %s" % (job.get("shield_job_id") or record.get("id")))
    print("  reference          %s" % (job.get("external_reference") or "—"))
    if report["chain"]:
        c = report["chain"]
        print("  custody chain      %s (%d/%d entries)"
              % ("INTACT" if c["intact"] else "BROKEN", c["verified"], c["entries"]))
        print("  head hash          %s" % c["head_hash"])
        if args.expect_head:
            print("  vs the head you hold %s"
                  % ("MATCHES" if c["head_hash"] == args.expect_head else "DIFFERS"))
        else:
            print("  (no --expect-head given: a chain truncated at the end")
            print("   verifies perfectly. Your own copy of the head detects that.)")
    else:
        print("  custody chain      NOT VERIFIABLE — no entries in package")
    supplied = [f for f in report["files"] if f["status"] in ("match", "MISMATCH")]
    if supplied:
        matched = sum(1 for f in supplied if f["status"] == "match")
        print("  photos checked     %d of %d match" % (matched, len(supplied)))
    else:
        print("  photos checked     none supplied (pass --files to check them)")

    print()
    for note in report.get("notes") or []:
        print("  note: %s" % note)
    print()
    if report["ok"]:
        print("PASS — everything checkable in this package checks out.")
    else:
        print("FAIL")
        for p in report["problems"]:
            print("  - %s" % p)
    print()
    print("This establishes integrity, not truth. It does not show that a photo")
    print("came off a camera, that the assessments are correct, or that the work")
    print("complies with any code. A package can verify perfectly and still")
    print("describe work that was never done.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
