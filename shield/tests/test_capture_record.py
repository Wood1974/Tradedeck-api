"""Byte rules for the on-phone capture record.

The custody chain is a different contract and stays on chain_version 2.
These tests pin the capture record: whole numbers only, a version field,
stable canonical bytes, and TAMPERED when a hash or a link does not reproduce.
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import capture_record as cr  # noqa: E402
import ledger  # noqa: E402
import time_audit  # noqa: E402

PHOTO = hashlib.sha256(b"shield-capture-record-fixture-photo").hexdigest()
PREV = "cd" * 32

# Frozen from the canonicalizer. A formatting change has to fail here on
# purpose, not ride through because the test rebuilt the bytes the same way.
CANONICAL_REQUIRED = (
    '{"boot_count":4,"checkpoint_id":"cp-1","flags":0,"monotonic_ms":5000,'
    '"photo_sha256":"cfe8a5966f9ced4e33a1cf652c0aef5c9fec6e629d3d7cacec5b9cc794316aa3",'
    '"ticket_id":"ticket-1","version":1,"wall_time_ms":1700000000000}'
)
CANONICAL_FULL = (
    '{"boot_count":4,"boot_id":"BOOT-SESSION","checkpoint_id":"caf\\u00e9",'
    '"depth_hash":"684da0b2d29666189e6d969244e96218928f8f838956b7036e784667edfd83a5",'
    '"depth_present":true,"flags":15,"gnss_time_ms":1700000000500,'
    '"location_simulated":false,"monotonic_ms":5000,'
    '"photo_sha256":"cfe8a5966f9ced4e33a1cf652c0aef5c9fec6e629d3d7cacec5b9cc794316aa3",'
    '"sensor_hash":"e332899a9037fbffc4792ef03a765477336af15155e708872add90efac49443c",'
    '"ticket_id":"ticket-1","version":1,"wall_time_ms":1700000000000}'
)
SNAPSHOT_BYTES = (
    '{"accel_milli_g":[0,0,1000],"duration_ms":200,"heading_hundredths":18450}'
)


def required(**overrides):
    record = cr.build(
        checkpoint_id="cp-1",
        photo_sha256=PHOTO,
        ticket_id="ticket-1",
        wall_time_ms=1_700_000_000_000,
        monotonic_ms=5_000,
        boot_count=4,
        flags=0,
    )
    record.update(overrides)
    return record


def sensor_hash():
    return cr.hash_whole({
        "heading_hundredths": 18450,
        "duration_ms": 200,
        "accel_milli_g": [0, 0, 1000],
    })


def depth_hash():
    return cr.hash_whole({
        "width": 4,
        "height": 4,
        "millimetres": [1000, 1001, 1002, 1003],
    })


def full_record():
    return cr.build(
        checkpoint_id="café",
        photo_sha256=PHOTO,
        ticket_id="ticket-1",
        wall_time_ms=1_700_000_000_000,
        monotonic_ms=5_000,
        boot_id="BOOT-SESSION",
        boot_count=4,
        gnss_time_ms=1_700_000_000_500,
        location_simulated=False,
        sensor_hash=sensor_hash(),
        depth_hash=depth_hash(),
        depth_present=True,
        flags=(cr.FLAG_SCREEN_CAPTURED | cr.FLAG_DEBUGGER
               | cr.FLAG_MOCK_LOCATION | cr.FLAG_ROOT_TRACES),
    )


def chain(n=4, flags=0):
    records = []
    prev = PREV
    for i in range(n):
        raw = cr.build(
            checkpoint_id=f"cp-{i}",
            photo_sha256=hashlib.sha256(f"photo-{i}".encode()).hexdigest(),
            ticket_id="ticket-1",
            wall_time_ms=1_700_000_000_000 + i * 1000,
            monotonic_ms=5_000 + i * 1000,
            boot_count=4,
            flags=flags,
        )
        sealed = cr.seal(raw, prev)
        records.append(sealed)
        prev = sealed["record_hash"]
    return records


# --------------------------------------------------------------- version ---
def test_record_version_is_not_the_custody_chain_version():
    """The custody chain stays on version 2. This record has its own."""
    assert ledger.CHAIN_VERSION == 2
    assert cr.RECORD_VERSION == 1
    assert cr.JS_SAFE_INT == time_audit.JS_SAFE_INT
    assert cr.seal(required(), PREV)["version"] == 1
    assert "chain_version" not in cr.seal(required(), PREV)


def test_spec_still_says_custody_chain_version_is_two():
    spec = open(os.path.join(os.path.dirname(__file__), "..", "SPEC.md"),
                encoding="utf-8").read()
    assert "`chain_version` is **2**" in spec
    assert "It remains 2." in spec


# ------------------------------------------------------- canonical bytes ---
def test_required_record_matches_the_fixture():
    assert cr.canonical(required()).decode("ascii") == CANONICAL_REQUIRED


def test_full_record_matches_the_fixture():
    body = cr.canonical(full_record())
    # Escaped JSON is ASCII. A raw UTF-8 é would mean ensure_ascii drifted
    # from the custody canonical form.
    assert body.decode("ascii") == CANONICAL_FULL
    assert "\\u00e9" in body.decode("ascii")


def test_snapshot_bytes_match_the_fixture():
    assert cr.canonical_whole({
        "heading_hundredths": 18450,
        "duration_ms": 200,
        "accel_milli_g": [0, 0, 1000],
    }).decode("ascii") == SNAPSHOT_BYTES


def test_canonical_bytes_ignore_key_order():
    a = required()
    b = {k: a[k] for k in reversed(list(a))}
    assert cr.canonical(a) == cr.canonical(b)


def test_absent_and_null_hash_identically():
    a = required()
    b = dict(a)
    b["gnss_time_ms"] = None
    b["boot_id"] = None
    assert cr.canonical(a) == cr.canonical(b)


def test_zero_and_false_are_not_null():
    """0 and false are statements. Omitting the field is a different one."""
    without_flags = required()
    del without_flags["flags"]
    with pytest.raises(ValueError):
        cr.canonical(without_flags)

    explicit_false = full_record()
    omitted = dict(explicit_false)
    del omitted["location_simulated"]
    assert cr.canonical(explicit_false) != cr.canonical(omitted)
    assert b'"location_simulated":false' in cr.canonical(explicit_false)


def test_unsigned_fields_do_not_change_the_hash():
    base = required()
    noisy = dict(base, note="hello", chain_version=2, prev_hash=PREV)
    assert cr.canonical(base) == cr.canonical(noisy)


def test_prev_hash_is_outside_the_canonical_bytes():
    """The link uses the published concatenation, so prev_hash is metadata."""
    raw = required()
    body = cr.canonical(raw)
    assert b"prev_hash" not in body
    sealed = cr.seal(raw, PREV)
    assert cr.canonical(sealed) == body
    assert sealed["record_hash"] == hashlib.sha256(
        body + b"|" + PREV.encode("ascii")).hexdigest()


def test_sealing_is_deterministic():
    raw = required()
    assert cr.seal(raw, PREV)["record_hash"] == cr.seal(dict(raw), PREV)["record_hash"]


def test_photo_chunks_hash_like_the_whole_buffer():
    whole = cr.photo_sha256(b"shield-capture-record-fixture-photo")
    chunked = cr.photo_sha256([b"shield-capture-", b"record-fixture-photo"])
    assert whole == chunked == PHOTO
    assert cr.photo_sha256(b"") == cr.photo_sha256([])


# ---------------------------------------------------------- float refusal ---
@pytest.mark.parametrize("field,value", [
    ("wall_time_ms", 1.0),
    ("wall_time_ms", 120.001),
    ("monotonic_ms", 5000.0),
    ("flags", 1.5),
    ("boot_count", 4.0),
    ("gnss_time_ms", float("nan")),
    ("gnss_time_ms", float("inf")),
    ("gnss_time_ms", float("-inf")),
    ("version", 1.0),
])
def test_a_float_in_a_signed_field_is_rejected(field, value):
    record = required()
    record[field] = value
    with pytest.raises(ValueError):
        cr.canonical(record)


@pytest.mark.parametrize("payload", [
    {"heading_hundredths": 180.0},
    {"latitude_microdeg": 40.76056},
    {"samples": [1, 2, 3.0]},
    {"nested": {"ms": float("nan")}},
    {"nested": {"angle": float("inf")}},
])
def test_a_float_in_a_snapshot_is_rejected(payload):
    with pytest.raises(ValueError):
        cr.hash_whole(payload)


def test_a_boolean_is_not_an_integer_field():
    record = required()
    record["wall_time_ms"] = True
    with pytest.raises(ValueError):
        cr.canonical(record)
    record = required()
    record["flags"] = False
    with pytest.raises(ValueError):
        cr.canonical(record)


def test_a_boolean_field_rejects_zero_and_one():
    """true and 1 are different JSON, so 1 must not be accepted as true."""
    record = full_record()
    record["location_simulated"] = 1
    with pytest.raises(ValueError):
        cr.canonical(record)
    record = full_record()
    record["location_simulated"] = False
    record["depth_present"] = 0
    record.pop("depth_hash")
    with pytest.raises(ValueError):
        cr.canonical(record)


def test_whole_numbers_in_a_snapshot_hash():
    digest = cr.hash_whole({
        "latitude_microdeg": 40_760_560,
        "longitude_microdeg": -111_890_830,
        "heading_hundredths": 18_450,
    })
    assert cr._SHA256_HEX.fullmatch(digest)
    again = cr.hash_whole({
        "heading_hundredths": 18_450,
        "longitude_microdeg": -111_890_830,
        "latitude_microdeg": 40_760_560,
    })
    assert digest == again


def test_integer_past_the_json_safe_range_is_rejected():
    record = required()
    record["wall_time_ms"] = cr.JS_SAFE_INT + 1
    with pytest.raises(ValueError):
        cr.canonical(record)
    record["wall_time_ms"] = cr.JS_SAFE_INT
    cr.canonical(record)


def test_uppercase_hash_is_rejected():
    record = required()
    record["photo_sha256"] = PHOTO.upper()
    with pytest.raises(ValueError):
        cr.canonical(record)


def test_depth_hash_without_the_present_flag_is_rejected():
    record = required()
    record["depth_hash"] = depth_hash()
    with pytest.raises(ValueError):
        cr.canonical(record)
    record["depth_present"] = False
    with pytest.raises(ValueError):
        cr.canonical(record)


# ----------------------------------------------------------------- chain ---
def test_an_untampered_chain_is_intact():
    records = chain(4)
    result = cr.verify_chain(records, PREV)
    assert result["verdict"] == cr.VERDICT_INTACT
    assert result["intact"] is True
    assert result["broken_at_index"] is None
    assert result["verified"] == 4
    assert result["head_hash"] == records[-1]["record_hash"]
    assert result["record_version"] == 1


def test_empty_chain_heads_at_the_predecessor_it_was_given():
    result = cr.verify_chain([], PREV)
    assert result["verdict"] == cr.VERDICT_INTACT
    assert result["head_hash"] == PREV


def test_each_record_names_the_one_before_it():
    records = chain(3)
    assert records[0]["prev_hash"] == PREV
    assert records[1]["prev_hash"] == records[0]["record_hash"]
    assert records[2]["prev_hash"] == records[1]["record_hash"]


def test_editing_a_signed_field_is_tampered_at_that_record():
    records = chain(4)
    records[2]["wall_time_ms"] += 1
    result = cr.verify_chain(records, PREV)
    assert result["verdict"] == cr.VERDICT_TAMPERED
    assert result["intact"] is False
    assert result["broken_at_index"] == 2
    assert "bytes do not reproduce" in result["reason"]


def test_editing_the_photo_hash_is_tampered():
    records = chain(3)
    records[1]["photo_sha256"] = "ab" * 32
    assert cr.verify_chain(records, PREV)["broken_at_index"] == 1


def test_stripping_the_hash_is_tampered():
    records = chain(3)
    records[1]["record_hash"] = None
    result = cr.verify_chain(records, PREV)
    assert result["broken_at_index"] == 1
    assert "no hash" in result["reason"]


def test_a_broken_link_is_tampered():
    records = chain(3)
    records[1]["prev_hash"] = "ee" * 32
    result = cr.verify_chain(records, PREV)
    assert result["verdict"] == cr.VERDICT_TAMPERED
    assert result["broken_at_index"] == 1
    assert "link broken" in result["reason"]


def test_deleting_a_record_breaks_the_link_at_the_gap():
    records = chain(5)
    del records[2]
    result = cr.verify_chain(records, PREV)
    assert result["broken_at_index"] == 2


def test_reordering_records_is_tampered():
    records = chain(4)
    records[1], records[3] = records[3], records[1]
    assert cr.verify_chain(records, PREV)["verdict"] == cr.VERDICT_TAMPERED


def test_a_float_written_into_a_sealed_record_is_tampered():
    """Hostile input is a verdict, not an exception out of verify_chain."""
    records = chain(2)
    records[0]["monotonic_ms"] = 1.0
    result = cr.verify_chain(records, PREV)
    assert result["verdict"] == cr.VERDICT_TAMPERED
    assert result["broken_at_index"] == 0
    assert "float" in result["reason"]


def test_flags_do_not_make_an_honest_record_tampered():
    flags = (cr.FLAG_SCREEN_CAPTURED | cr.FLAG_DEBUGGER
             | cr.FLAG_MOCK_LOCATION | cr.FLAG_ROOT_TRACES | (1 << 10))
    records = chain(3, flags=flags)
    result = cr.verify_chain(records, PREV)
    assert result["verdict"] == cr.VERDICT_INTACT
    assert cr.flag_names(flags) == [
        "screen_captured", "debugger", "mock_location", "root_traces", "bit_10",
    ]


def test_a_full_rewrite_verifies_and_moves_the_head():
    """The chain alone cannot see a rewrite that recomputes every link.

    A head the holder already kept can. Same honest limit as the custody chain.
    """
    original = chain(4)
    original_head = cr.verify_chain(original, PREV)["head_hash"]
    rewritten = []
    prev = PREV
    for record in original:
        raw = {k: record[k] for k in cr.RECORD_FIELDS if k in record}
        raw["checkpoint_id"] = raw["checkpoint_id"] + "-edited"
        sealed = cr.seal(raw, prev)
        rewritten.append(sealed)
        prev = sealed["record_hash"]
    assert cr.verify_chain(rewritten, PREV)["verdict"] == cr.VERDICT_INTACT
    assert cr.verify_chain(rewritten, PREV)["head_hash"] != original_head
    caught = cr.verify_chain(rewritten, PREV, expect_head=original_head)
    assert caught["verdict"] == cr.VERDICT_TAMPERED
    assert "head does not match" in caught["reason"]


def test_dropping_the_tail_verifies_until_a_held_head_is_supplied():
    original = chain(4)
    head = original[-1]["record_hash"]
    short = original[:-1]
    assert cr.verify_chain(short, PREV)["verdict"] == cr.VERDICT_INTACT
    caught = cr.verify_chain(short, PREV, expect_head=head)
    assert caught["verdict"] == cr.VERDICT_TAMPERED
    assert caught["broken_at_index"] is None


def test_the_wrong_first_predecessor_is_tampered_at_the_start():
    records = chain(2)
    result = cr.verify_chain(records, "ab" * 32)
    assert result["broken_at_index"] == 0
    assert result["verdict"] == cr.VERDICT_TAMPERED
