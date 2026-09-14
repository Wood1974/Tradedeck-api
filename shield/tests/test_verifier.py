"""The independent verifier, and whether it agrees with the thing it checks.

The point of this file is not that the verifier works. It is that a
*reimplementation from the written spec*, sharing no code with the service,
reaches the same hashes — which is the only thing that makes "verify without
trusting us" mean anything. If these two ever disagree, the spec is wrong or
one of them is, and we want to find that before an opposing expert does.
"""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "verifier"))

import evidence          # noqa: E402
import ledger            # noqa: E402
import shield_verify     # noqa: E402

JOB_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
JOB = {"id": JOB_ID, "external_ref": "WO-9001", "trade": "framing",
       "site_lat": 40.76056, "site_lng": -111.89083, "site_radius_m": 250}

POINTS = [
    {"id": "p1", "point_number": 1, "label": "Sill Plate",
     "description": "Bolt spacing", "irc_code": "IRC R403.1.6"},
    {"id": "p2", "point_number": 2, "label": "Wall Framing",
     "description": "Stud spacing", "irc_code": "IRC R602.3"},
]

PHOTO_BYTES = {"ph1": b"photo-one-bytes", "ph2": b"photo-two-bytes"}
PHOTOS = [
    {"id": "ph1", "point_id": "p1", "original_hash_algo": "SHA-256",
     "original_hash": hashlib.sha256(PHOTO_BYTES["ph1"]).hexdigest(),
     "uploaded_at": "2026-09-02T15:00:00+00:00", "ai_verdict": "pass"},
    {"id": "ph2", "point_id": "p2", "original_hash_algo": "SHA-256",
     "original_hash": hashlib.sha256(PHOTO_BYTES["ph2"]).hexdigest(),
     "uploaded_at": "2026-09-03T09:00:00+00:00", "ai_verdict": "pass"},
]


def build_chain(n=5, job=JOB_ID):
    """A realistic chain: mixed field types, including floats and nested data."""
    out, prev = [], ledger.genesis_hash(job)
    for i in range(n):
        raw = {
            "shield_job_id": job,
            "event_type": ["uploaded", "ai_analyzed", "viewed"][i % 3],
            "actor_type": "contractor",
            "actor_id": f"user-{i}",
            "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
            "gps_lat": 40.76056, "gps_lng": -111.89083,
            "file_hash": "a" * 64,
            "event_data": {"b": 2, "a": [1, 2, 3], "note": "nested"},
        }
        sealed = ledger.seal(raw, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


def make_package(chain=None):
    return evidence.build_manifest(
        job=JOB, points=POINTS, photos=PHOTOS,
        custody=chain if chain is not None else build_chain())


# ------------------------------------------- the cross-implementation check --
def test_the_two_implementations_agree_on_genesis():
    assert shield_verify.genesis_hash(JOB_ID) == ledger.genesis_hash(JOB_ID)


def test_the_two_implementations_agree_on_canonical_bytes():
    for entry in build_chain(6):
        assert shield_verify.canonical(entry) == ledger.canonical(entry), \
            "the spec and the service disagree on canonicalisation"


def test_the_two_implementations_agree_on_every_link():
    prev = ledger.genesis_hash(JOB_ID)
    for entry in build_chain(6):
        assert shield_verify.link(entry, prev) == ledger.link(entry, prev)
        prev = entry["entry_hash"]


def test_absent_and_null_hash_identically_in_both():
    """The rule that stops an added-then-nulled column rewriting history."""
    a = {"shield_job_id": JOB_ID, "event_type": "uploaded",
         "recorded_at": "2026-09-01T10:00:00+00:00"}
    b = {**a, "photo_id": None, "integrity_note": None}
    assert shield_verify.canonical(a) == shield_verify.canonical(b)
    assert shield_verify.canonical(a) == ledger.canonical(b)


def test_both_refuse_a_non_finite_value():
    bad = {"shield_job_id": JOB_ID, "event_type": "uploaded",
           "gps_lat": float("nan")}
    with pytest.raises(ValueError):
        shield_verify.canonical(bad)
    with pytest.raises(ValueError):
        ledger.canonical(bad)


def test_the_verifier_shares_no_code_with_the_service():
    """Reading this file must not reach into shield/."""
    path = os.path.join(os.path.dirname(__file__), "..", "verifier",
                        "shield_verify.py")
    with open(path) as fh:
        src = fh.read()
    for forbidden in ("import ledger", "import evidence", "from ledger",
                      "from evidence", "import integrity", "import config"):
        assert forbidden not in src, \
            f"the verifier imports {forbidden!r} — it is no longer independent"


# ------------------------------------------------------- the package check --
def test_a_good_package_passes():
    report = shield_verify.verify_package(make_package(), PHOTO_BYTES)
    assert report["ok"], report["problems"]
    assert report["chain"]["intact"]
    assert report["chain"]["entries"] == 5


def test_head_hash_matches_the_service():
    chain = build_chain()
    report = shield_verify.verify_package(make_package(chain))
    assert report["chain"]["head_hash"] == ledger.head_of(chain, JOB_ID)


def test_supplied_photos_are_matched():
    report = shield_verify.verify_package(make_package(), PHOTO_BYTES)
    checked = [f for f in report["files"] if f["status"] == "match"]
    assert len(checked) == 2


def test_a_swapped_photo_is_caught():
    swapped = {"ph1": b"a completely different image", "ph2": PHOTO_BYTES["ph2"]}
    report = shield_verify.verify_package(make_package(), swapped)
    assert not report["ok"]
    assert any("does not match its recorded hash" in p for p in report["problems"])


def test_missing_files_are_reported_but_not_a_failure():
    """A recipient may hold only some of the photos."""
    report = shield_verify.verify_package(make_package(), {})
    assert report["ok"], report["problems"]
    assert all(f["status"] == "file not supplied" for f in report["files"])


# ---------------------------------------------------------- tampering -------
def test_an_edited_field_is_caught_at_the_right_entry():
    chain = build_chain()
    chain[2] = {**chain[2], "actor_id": "somebody-else"}
    report = shield_verify.verify_package(make_package(chain))
    assert not report["ok"]
    assert report["chain"]["broken_at_index"] == 2
    assert "content altered" in report["chain"]["reason"]


def test_a_removed_entry_is_caught():
    chain = build_chain()
    del chain[2]
    report = shield_verify.verify_package(make_package(chain))
    assert not report["ok"]
    assert report["chain"]["broken_at_index"] == 2


def test_a_reordered_chain_is_caught():
    chain = build_chain()
    chain[1], chain[3] = chain[3], chain[1]
    report = shield_verify.verify_package(make_package(chain))
    assert not report["ok"]


def test_a_package_lying_about_its_own_head_is_caught():
    """The attack the export's summary block invites if nobody recomputes."""
    pkg = make_package()
    pkg["custody"]["head_hash"] = "f" * 64
    report = shield_verify.verify_package(pkg)
    assert not report["ok"]
    assert any("head hash disagreement" in p for p in report["problems"])


def test_a_package_claiming_intact_over_a_broken_chain_is_caught():
    chain = build_chain()
    chain[1] = {**chain[1], "file_hash": "b" * 64}
    pkg = make_package(chain)
    pkg["custody"]["chain_intact"] = True          # the vendor insists
    report = shield_verify.verify_package(pkg)
    assert not report["ok"]
    assert any("asserts chain_intact: true and it is not" in p
               for p in report["problems"])


def test_a_full_rewrite_is_internally_consistent_but_moves_the_head():
    """The honest limit, stated by a test rather than only in prose.

    An attacker who recomputes the whole chain produces something that
    verifies. What they cannot do is make it agree with a head hash somebody
    already holds.
    """
    original_head = ledger.head_of(build_chain(), JOB_ID)
    forged, prev = [], ledger.genesis_hash(JOB_ID)
    for i in range(5):
        sealed = ledger.seal({"shield_job_id": JOB_ID, "event_type": "uploaded",
                              "actor_type": "contractor",
                              "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
                              "integrity_note": "nothing to see"}, prev)
        forged.append(sealed)
        prev = sealed["entry_hash"]

    report = shield_verify.verify_package(make_package(forged))
    assert report["ok"], "a full rewrite IS internally consistent — this is the limit"
    assert report["chain"]["head_hash"] != original_head, \
        "but it cannot reproduce a head hash the recipient already holds"


# ------------------------------------------------------- the export itself --
def test_the_export_carries_what_a_recipient_needs_to_recompute():
    pkg = make_package()
    assert "custody_entries" in pkg, \
        "without raw entries the chain is our assertion, not their check"
    assert len(pkg["custody_entries"]) == pkg["custody"]["entries"]
    for e in pkg["custody_entries"]:
        assert e["entry_hash"] and e["prev_hash"]


def test_a_package_without_entries_is_reported_as_unverifiable():
    """Not silently 'fine' — the recipient must be told what they cannot check."""
    pkg = make_package()
    del pkg["custody_entries"]
    report = shield_verify.verify_package(pkg)
    assert not report["ok"]
    assert any("cannot be recomputed" in p for p in report["problems"])


def test_the_package_round_trips_through_json():
    """A recipient gets a file, not a Python object."""
    pkg = json.loads(json.dumps(make_package(), default=str))
    report = shield_verify.verify_package(pkg, PHOTO_BYTES)
    assert report["ok"], report["problems"]
