"""Accept a batch of captures a phone made while it had no signal.

The phone already has a job ticket (see ``ticket.py``) and a chain of
capture records (see ``capture_record.py``). Each record is signed by the
same attested install key, with the fixed challenge ``shield-capture-v1``
and the raw record hash in the payload slot the capture verifiers already
check. A server nonce is not part of this path: the phone was offline, and
the per-process challenge jar is not shared across workers anyway.

What this module does
---------------------
It checks the bytes, the links, and the time labels. It does not talk to
the database and it does not check the hardware signature. The route does
that, with ``app_attest.verify_assertion`` and ``android_attest.verify_signature``,
and it refuses the batch if any signature fails.

One request may carry at most ``MAX_BATCH_PHOTOS`` photographs. Anything
past that is not accepted. The response tells the phone to send the next
batch. The prefix that was accepted is a chain of its own, and the next
batch has to start at that prefix's head.

A chain that does not reproduce, or does not connect to the ticket (or to
the head of the batch already stored), is refused. Nothing is written.
Time labels are computed by ``time_audit`` and returned with the batch so
the custody entry and the receipt can carry them. A reboot is UNVERIFIED
TIME. A clock jump is DEVICE CLOCK MISMATCH. Flags do not change either
label, and neither label is a reason to refuse the photographs.

This does not replace the custody chain. The route appends one custody
entry. ``chain_version`` stays 2. The phone chain sits in that entry's
signed ``event_data``, under the head the receipt signs.
"""
import hmac

import capture_record
import config
import integrity
import time_audit

# How many photographs one HTTP request may carry. The rest are not
# accepted; the phone sends another request.
MAX_BATCH_PHOTOS = 8

# Domain separator for the hardware signature over a capture record.
# Distinct from ``ticket.GENESIS_CHALLENGE`` and from a capture nonce, so
# none of the three signatures verifies as one of the others.
CAPTURE_CHALLENGE = "shield-capture-v1"

EVENT_TYPE = "offline_batch"

_SHA256_HEX = capture_record._SHA256_HEX


def batch_cap():
    """The configured cap, or ``MAX_BATCH_PHOTOS`` when the setting is unusable."""
    raw = config.get("SHIELD_QUEUE_BATCH_CAP")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return MAX_BATCH_PHOTOS
    if n < 1:
        return MAX_BATCH_PHOTOS
    return n


def hardware_binding(record_hash_hex):
    """``(challenge, payload_sha256)`` for the existing signature verifiers.

    ``payload_sha256`` is the raw record hash, 32 bytes, not the hex text.
    The record hash covers the photo hash. The route still recomputes the
    photo hash from the bytes and refuses the batch when they disagree.
    """
    if (not isinstance(record_hash_hex, str)
            or _SHA256_HEX.fullmatch(record_hash_hex) is None):
        raise ValueError(
            "record hash must be a 64-character lowercase hex SHA-256")
    return CAPTURE_CHALLENGE, bytes.fromhex(record_hash_hex)


def _hex(value, key):
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise ValueError(f"{key} must be a 64-character lowercase hex SHA-256")
    return value


def _clock(observation):
    """The phone's clocks at ticket time, limited to what time_audit reads."""
    if not isinstance(observation, dict):
        raise ValueError("ticket_clock must be an object")
    out = {}
    for key in ("wall_time_ms", "monotonic_ms", "boot_count"):
        if key in observation and observation[key] is not None:
            out[key] = observation[key]
    if observation.get("boot_id"):
        out["boot_id"] = observation["boot_id"]
    # Validate by asking time_audit to read it against itself. A float or a
    # boolean here is a bad request, not a time label.
    time_audit.assess(out, dict(out, wall_time_ms=out.get("wall_time_ms"),
                                 monotonic_ms=out.get("monotonic_ms")))
    return out


def prepare(captures, *, ticket_hash, expected_prev, ticket_clock,
            allowed_checkpoints, cap=None, claimed_head=None):
    """Check one batch. No signatures, no writes.

    ``expected_prev`` is the ticket hash for the first batch on a record,
    and the previous batch's phone-chain head after that. ``claimed_head``,
    when the whole request fits in the cap, is a head the phone says this
    batch ends at. A shorter chain that still links does not match it, and
    that is the truncation a hash chain cannot see on its own.

    Returns ``ok: False`` with nothing the route should store, or the
    accepted prefix plus a count of photographs the cap left behind.
    """
    if cap is None:
        cap = batch_cap()
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        cap = MAX_BATCH_PHOTOS
    try:
        ticket_hash = _hex(ticket_hash, "ticket hash")
        expected_prev = _hex(expected_prev, "expected previous hash")
    except ValueError as exc:
        return _no(str(exc))
    if not isinstance(captures, list) or not captures:
        return _no("A batch must include at least one capture. Nothing was stored.")
    if not isinstance(allowed_checkpoints, (set, frozenset, list, tuple)):
        return _no("This record has no checkpoints to attach a photograph to.")
    allowed = {str(c) for c in allowed_checkpoints}
    try:
        clock = _clock(ticket_clock)
    except ValueError as exc:
        return _no(f"The phone's ticket-time clocks could not be read ({exc}). "
                   f"Nothing was stored.")

    total = len(captures)
    if total > cap:
        working = captures[:cap]
        refused = total - cap
        # The claimed head was about the whole request. The prefix has a
        # different head. Applying the claim here would refuse a batch the
        # cap is supposed to split.
        head_claim = None
    else:
        working = captures
        refused = 0
        head_claim = claimed_head

    if head_claim is not None:
        try:
            head_claim = _hex(head_claim, "phone_chain_head")
        except ValueError as exc:
            return _no(str(exc) + " Nothing was stored.")

    records = []
    prepared = []
    for index, item in enumerate(working):
        if not isinstance(item, dict):
            return _no("A capture must be an object. Nothing was stored.")
        photo = item.get("photo")
        record = item.get("record")
        if not isinstance(photo, (bytes, bytearray)) or not photo:
            return _no(f"Capture {index + 1} has no photograph. Nothing was stored.")
        if not isinstance(record, dict):
            return _no(f"Capture {index + 1} has no capture record. Nothing was stored.")
        photo = bytes(photo)
        if integrity.sniff_mime(photo) is None:
            return _no(f"Capture {index + 1} is not a photograph this service "
                       f"can read. Nothing was stored.")
        probed = integrity.probe(photo)
        if not probed.get("ok"):
            return _no(f"Capture {index + 1} is not a readable photograph. "
                       f"Nothing was stored.")
        computed = integrity.sha256(photo)
        claimed = record.get("photo_sha256")
        if (not isinstance(claimed, str) or len(claimed) != len(computed)
                or not hmac.compare_digest(claimed, computed)):
            return _no(f"Capture {index + 1} does not match its photograph. "
                       f"Nothing was stored.")
        if str(record.get("ticket_id") or "") != ticket_hash:
            return _no(f"Capture {index + 1} was not made under this record's "
                       f"job ticket. Nothing was stored.")
        checkpoint_id = str(record.get("checkpoint_id") or "")
        if checkpoint_id not in allowed:
            return _no(f"Capture {index + 1} names a checkpoint that is not "
                       f"on this record. Nothing was stored.")
        records.append(record)
        prepared.append({
            "photo": photo,
            "record": record,
            "assertion": item.get("assertion"),
            "checkpoint_id": checkpoint_id,
            "photo_sha256": computed,
        })

    chain = capture_record.verify_chain(
        records, expected_prev, expect_head=head_claim)
    if chain["verdict"] != capture_record.VERDICT_INTACT:
        return _no("This batch was not accepted: the phone chain is "
                   f"{chain['verdict']}. {chain['summary']} Nothing was stored.")

    accepted = []
    for item in prepared:
        record = item["record"]
        try:
            audit = time_audit.assess(clock, record)
        except ValueError as exc:
            return _no(f"A capture clock could not be read ({exc}). "
                       f"Nothing was stored.")
        flags = record.get("flags")
        if isinstance(flags, bool) or not isinstance(flags, int):
            flags = 0
        item = dict(item)
        item["record_hash"] = record.get("record_hash")
        item["time"] = {
            "verdict": audit["verdict"],
            "labels": list(audit["labels"]),
            "flags": flags,
            "flag_names": capture_record.flag_names(flags),
            "detail": audit["detail"],
            "boot_changed": audit["boot_changed"],
            "gnss": audit["gnss"],
        }
        if audit["monotonic_delta_ms"] is not None:
            item["time"]["monotonic_delta_ms"] = audit["monotonic_delta_ms"]
        accepted.append(item)

    message = None
    if refused:
        message = (f"This request carried {total} photos and one batch accepts "
                   f"{cap}. {refused} were not accepted. Send the next batch.")
    return {
        "ok": True,
        "accepted": accepted,
        "accepted_count": len(accepted),
        "refused_count": refused,
        "send_next_batch": refused > 0,
        "message": message,
        "phone_chain_head": chain["head_hash"],
        "ticket_clock": clock,
        "chain_verdict": chain["verdict"],
    }


def custody_event(prepared, *, ticket_hash):
    """The one custody entry for this batch.

    ``file_hash`` and ``event_data.phone_chain_head`` are the phone-chain
    head. Both are signed fields of the custody entry (``file_hash`` itself,
    and ``event_data``). The phone chain is nested there. It is not a new
    custody chain, and this dict does not carry ``chain_version``. ``seal``
    stamps version 2 when the route appends the entry.
    """
    phone_chain = []
    summaries = []
    for item in prepared["accepted"]:
        record = item["record"]
        stored = {}
        for key in capture_record.RECORD_FIELDS:
            if key in record and record[key] is not None:
                stored[key] = record[key]
        stored["prev_hash"] = record.get("prev_hash")
        stored["record_hash"] = record.get("record_hash")
        # The hardware signature is not a signed field of the capture
        # record. It sits beside the record so a package can be checked
        # without asking this service. The custody hash covers it because
        # it lives in event_data. It is not a second chain.
        if item.get("assertion"):
            stored["hardware_signature"] = item["assertion"]
        phone_chain.append(stored)
        summaries.append({
            "record_hash": item["record_hash"],
            "photo_sha256": item["photo_sha256"],
            "checkpoint_id": item["checkpoint_id"],
            "time_verdict": item["time"]["verdict"],
            "time_labels": list(item["time"]["labels"]),
            "flags": item["time"]["flags"],
            "flag_names": list(item["time"]["flag_names"]),
        })
    return {
        "event_type": EVENT_TYPE,
        "file_hash": prepared["phone_chain_head"],
        "event_data": {
            "phone_chain_head": prepared["phone_chain_head"],
            "ticket_hash": ticket_hash,
            "phone_chain": phone_chain,
            "captures": summaries,
            "ticket_clock": prepared["ticket_clock"],
        },
    }


def _no(message):
    return {
        "ok": False,
        "error": message,
        "accepted": [],
        "accepted_count": 0,
        "refused_count": 0,
        "send_next_batch": False,
        "message": None,
        "phone_chain_head": None,
    }
