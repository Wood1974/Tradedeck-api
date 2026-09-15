"""Custody-chain tests.

Every test here is an attack. The chain's only job is to make tampering
detectable, so the suite tries to tamper and asserts it gets caught — and
names where.
"""
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ledger  # noqa: E402

JOB = "11111111-2222-3333-4444-555555555555"


def build(n=5, job=JOB):
    """A sealed chain of n entries, as the service would write it."""
    entries, prev = [], ledger.genesis_hash(job)
    for i in range(n):
        raw = {
            "shield_job_id": job,
            "photo_id": f"photo-{i}",
            "event_type": ["uploaded", "ai_analyzed", "flagged"][i % 3],
            "actor_id": "contractor-1",
            "actor_type": "contractor",
            "event_data": {"seq": i, "note": "checkpoint"},
            "gps_lat": 40.76056,
            "gps_lng": -111.89083,
            "file_hash": f"{i:064x}",
            "recorded_at": f"2026-09-14T1{i}:00:00+00:00",
        }
        sealed = ledger.seal(raw, prev)
        entries.append(sealed)
        prev = sealed["entry_hash"]
    return entries


# --------------------------------------------------------------- baseline ---
def test_an_untampered_chain_verifies():
    r = ledger.verify_chain(build(5), JOB)
    assert r["intact"] is True
    assert r["verified"] == 5
    assert r["broken_at_index"] is None
    assert "All 5 custody entries verify" in r["summary"]


def test_empty_chain_is_intact_and_heads_at_genesis():
    r = ledger.verify_chain([], JOB)
    assert r["intact"] is True
    assert r["head_hash"] == ledger.genesis_hash(JOB)


def test_each_job_has_its_own_genesis():
    assert ledger.genesis_hash("job-a") != ledger.genesis_hash("job-b")


def test_a_chain_will_not_verify_against_another_job():
    """A whole job's history transplanted onto another job is rejected."""
    r = ledger.verify_chain(build(3, job="job-a"), "job-b")
    assert r["intact"] is False
    assert r["broken_at_index"] == 0


# ------------------------------------------------------- tampering attacks ---
def test_editing_a_verdict_is_caught_at_that_entry():
    """The motivating attack: quietly flip a 'flagged' event to something
    harmless after the fact."""
    chain = build(5)
    chain[2]["event_type"] = "uploaded"
    r = ledger.verify_chain(chain, JOB)
    assert r["intact"] is False
    assert r["broken_at_index"] == 2
    assert "content altered" in r["reason"]


def test_editing_a_file_hash_is_caught():
    chain = build(5)
    chain[1]["file_hash"] = "d" * 64
    r = ledger.verify_chain(chain, JOB)
    assert r["broken_at_index"] == 1


def test_moving_gps_is_caught():
    chain = build(5)
    chain[3]["gps_lat"] = 41.0
    assert ledger.verify_chain(chain, JOB)["broken_at_index"] == 3


def test_editing_nested_event_data_is_caught():
    chain = build(5)
    chain[4]["event_data"]["seq"] = 99
    assert ledger.verify_chain(chain, JOB)["broken_at_index"] == 4


def test_deleting_an_entry_is_caught():
    chain = build(5)
    del chain[2]
    r = ledger.verify_chain(chain, JOB)
    assert r["intact"] is False
    assert r["broken_at_index"] == 2
    assert "inserted, removed, or reordered" in r["reason"]


def test_reordering_entries_is_caught():
    chain = build(5)
    chain[1], chain[3] = chain[3], chain[1]
    assert ledger.verify_chain(chain, JOB)["intact"] is False


def test_inserting_a_forged_entry_is_caught():
    """Splicing in a fabricated 'pass' mid-history."""
    chain = build(5)
    forged = ledger.seal({"shield_job_id": JOB, "event_type": "ai_analyzed",
                          "actor_type": "ai", "recorded_at": "2026-09-14T12:30:00+00:00"},
                         chain[1]["entry_hash"])
    chain.insert(2, forged)
    r = ledger.verify_chain(chain, JOB)
    assert r["intact"] is False
    assert r["broken_at_index"] == 3, "the entry AFTER the splice is where the link fails"


def test_appending_a_forged_entry_is_caught_without_the_real_tail():
    """An attacker who appends must chain from the true head; if they guess, it breaks."""
    chain = build(3)
    chain.append(ledger.seal({"shield_job_id": JOB, "event_type": "completed",
                              "actor_type": "system", "recorded_at": "x"},
                             "0" * 64))
    assert ledger.verify_chain(chain, JOB)["broken_at_index"] == 3


def test_stripping_the_hash_is_caught():
    chain = build(3)
    chain[1]["entry_hash"] = None
    r = ledger.verify_chain(chain, JOB)
    assert r["broken_at_index"] == 1
    assert "no hash" in r["reason"]


def test_full_rewrite_is_possible_but_changes_the_head():
    """The honest limit of the design, asserted rather than hand-waved.

    An operator CAN recompute the whole tail. What they cannot do is preserve
    the head hash — so any previously exported head detects the rewrite."""
    original = build(5)
    original_head = ledger.head_of(original, JOB)

    rewritten, prev = [], ledger.genesis_hash(JOB)
    for e in original:
        raw = {k: e[k] for k in ledger.SIGNED_FIELDS if k in e}
        if raw.get("event_type") == "flagged":
            raw["event_type"] = "uploaded"          # the forgery
        sealed = ledger.seal(raw, prev)
        rewritten.append(sealed)
        prev = sealed["entry_hash"]

    assert ledger.verify_chain(rewritten, JOB)["intact"] is True, \
        "a full rewrite is internally consistent — the chain alone cannot stop it"
    assert ledger.head_of(rewritten, JOB) != original_head, \
        "but the head changes, so anyone holding the old head detects it"


# ------------------------------------------------ canonical-form stability ---
def test_canonical_form_is_stable_across_key_order():
    a = {"event_type": "uploaded", "shield_job_id": JOB, "gps_lat": 1.5}
    b = {"gps_lat": 1.5, "shield_job_id": JOB, "event_type": "uploaded"}
    assert ledger.canonical(a) == ledger.canonical(b)


def test_absent_and_null_hash_identically():
    """So adding a column and leaving it null cannot invalidate old entries."""
    a = {"event_type": "uploaded", "shield_job_id": JOB}
    b = {"event_type": "uploaded", "shield_job_id": JOB, "photo_id": None}
    assert ledger.canonical(a) == ledger.canonical(b)


def test_unsigned_fields_do_not_affect_the_hash():
    base = {"event_type": "uploaded", "shield_job_id": JOB}
    assert ledger.canonical(base) == ledger.canonical({**base, "id": "row-1", "extra": "x"})


def test_float_representation_is_deterministic():
    assert ledger.canonical({"gps_lat": 40.1}) == ledger.canonical({"gps_lat": 40.1})
    assert ledger.canonical({"gps_lat": 40.1}) != ledger.canonical({"gps_lat": 40.10001})


def test_nan_is_refused_rather_than_serialised():
    with pytest.raises(ValueError):
        ledger.canonical({"gps_lat": float("nan")})


def test_chain_version_is_pinned():
    """Bumping this silently invalidates every chain ever written."""
    assert ledger.CHAIN_VERSION == 1
    assert ledger.seal({"event_type": "x"}, "0" * 64)["chain_version"] == 1


def test_hashes_are_sha256_hex():
    e = ledger.seal({"event_type": "uploaded", "shield_job_id": JOB}, ledger.genesis_hash(JOB))
    assert len(e["entry_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in e["entry_hash"])


def test_sealing_is_deterministic():
    raw = {"event_type": "uploaded", "shield_job_id": JOB, "recorded_at": "2026-01-01T00:00:00+00:00"}
    prev = ledger.genesis_hash(JOB)
    assert ledger.seal(copy.deepcopy(raw), prev)["entry_hash"] == ledger.seal(copy.deepcopy(raw), prev)["entry_hash"]
