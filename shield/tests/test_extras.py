"""Opt-in extras. Off by default. None of them is required for a seal.

These tests run on Linux. They do not talk to a phone. A GNSS fix and a
clip are checked as bytes. A countersignature is checked as a signature
from a second key. A record that omits all three is the record the rest
of the suite already seals.
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import capture_record as cr  # noqa: E402
import extras  # noqa: E402
import test_capture_record as pinned  # noqa: E402

FIX = {
    "time_ms": 1_700_000_000_500,
    "sat_count": 8,
    "accuracy_mm": 3500,
    "mock": False,
}


def test_omitted_extras_do_not_change_a_sealed_record():
    """The records this suite already pins do not grow a new field."""
    assert cr.canonical(pinned.required()).decode("ascii") == pinned.CANONICAL_REQUIRED
    assert cr.canonical(pinned.full_record()).decode("ascii") == pinned.CANONICAL_FULL
    assert "gnss_fix_hash" not in pinned.CANONICAL_FULL
    assert "clip_sha256" not in pinned.CANONICAL_FULL


def test_a_gnss_fix_is_whole_numbers_and_a_bool():
    digest = extras.gnss_fix_hash(FIX)
    assert digest == cr.hash_whole({
        "accuracy_mm": 3500,
        "mock": False,
        "sat_count": 8,
        "time_ms": 1_700_000_000_500,
    })
    assert '"mock":false' in cr.canonical_whole({
        "accuracy_mm": 3500, "mock": False, "sat_count": 8,
        "time_ms": 1_700_000_000_500,
    }).decode()


def test_a_float_in_the_gnss_fix_is_refused():
    bad = dict(FIX, accuracy_mm=3.5)
    with pytest.raises(ValueError):
        extras.gnss_fix_hash(bad)


def test_a_clip_is_hashed_and_a_long_one_is_refused():
    blob = b"about-one-second"
    assert extras.clip_sha256(blob) == hashlib.sha256(blob).hexdigest()
    path = extras.clip_path("tenant", "record", "ab" * 32)
    assert "/clips/" in path
    assert not path.endswith(".jpg")
    with pytest.raises(ValueError):
        extras.clip_sha256(b"x" * (extras.MAX_CLIP_BYTES + 1))


def test_a_countersign_is_not_a_capture_signature():
    challenge, payload = extras.countersign_binding("cd" * 32)
    assert challenge == "shield-countersign-v1"
    assert challenge != "shield-capture-v1"
    assert payload == bytes.fromhex("cd" * 32)


def test_one_key_signing_twice_is_not_two_phones():
    assert extras.distinct_keys("same", "same") is False
    assert extras.distinct_keys("capture-key", "other-key") is True
    assert extras.distinct_keys("", "other-key") is False


def test_the_switches_default_off():
    assert extras.flags_from_row({}) == {
        "gnss_fix": False, "micro_clip": False, "countersign": False}
    assert extras.flags_from_row({"opt_in_gnss_fix": False})["gnss_fix"] is False
    assert extras.flags_from_row({"opt_in_countersign": True})["countersign"] is True


def test_a_present_extra_has_to_match_and_an_absent_one_is_fine():
    record = {"photo_sha256": "ab" * 32}
    assert extras.check_record_extras(record, None, None) is None
    hashed = dict(record, gnss_fix_hash=extras.gnss_fix_hash(FIX))
    assert extras.check_record_extras(hashed, FIX, None) is None
    assert extras.check_record_extras(hashed, dict(FIX, sat_count=1), None)
    clip = b"clip"
    with_clip = dict(record, clip_sha256=extras.clip_sha256(clip))
    assert extras.check_record_extras(with_clip, None, clip) is None
    assert extras.check_record_extras(with_clip, None, b"other")
    assert extras.check_record_extras(record, FIX, None)
