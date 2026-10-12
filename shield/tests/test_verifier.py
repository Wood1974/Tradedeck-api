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


# The first two `uploaded` slots carry the real photo id, the real hash, and
# the checkpoint number. A chain of "a"*64 with no photo_id is not an honest
# package: the verifier would correctly refuse to call those photos sealed.
_UPLOADS = (
    ("ph1", PHOTOS[0]["original_hash"], 1),
    ("ph2", PHOTOS[1]["original_hash"], 2),
)


def build_chain(n=5, job=JOB_ID):
    """A realistic chain: mixed field types, including floats and nested data."""
    out, prev = [], ledger.genesis_hash(job)
    upload_i = 0
    for i in range(n):
        event_type = ["uploaded", "ai_analyzed", "viewed"][i % 3]
        event_data = {"b": 2, "a": [1, 2, 3], "note": "nested"}
        file_hash = "a" * 64
        extra = {}
        if event_type == "uploaded" and upload_i < len(_UPLOADS):
            photo_id, file_hash, point = _UPLOADS[upload_i]
            upload_i += 1
            extra["photo_id"] = photo_id
            event_data = {**event_data, "point_number": point}
        raw = {
            "shield_job_id": job,
            "event_type": event_type,
            "actor_type": "contractor",
            "actor_id": f"user-{i}",
            "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
            "gps_lat": 40.76056, "gps_lng": -111.89083,
            "file_hash": file_hash,
            "event_data": event_data,
            **extra,
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
    assert any("ph1" in p and "does not match the sealed upload record" in p
               for p in report["problems"])


def test_a_swap_that_also_rewrites_the_manifest_hash_is_caught():
    """The attack the old check missed.

    On main at 827a9df this returned ok True with an empty problem list:
    the verifier compared the new bytes to the manifest hash the attacker
    had just rewritten, and never looked at the sealed upload. The chain
    was untouched, so it still verified.
    """
    swapped = b"a completely different image"
    pkg = make_package()
    pkg["checkpoints"][0]["sha256_original"] = hashlib.sha256(swapped).hexdigest()
    report = shield_verify.verify_package(
        pkg, {"ph1": swapped, "ph2": PHOTO_BYTES["ph2"]})
    assert report["verdict"] == "FAIL"
    assert not report["ok"]
    assert report["chain"]["intact"]
    assert any(p == "photo ph1 does not match the sealed upload record"
               for p in report["problems"])
    assert any("ph1" in p and "manifest hash does not match the sealed upload record" in p
               for p in report["problems"])


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
    assert report["chain"]["intact"], \
        "a full rewrite of the links IS internally consistent"
    assert report["verdict"] == "UNVERIFIED", \
        "but it dropped the sealed photo records, so the photos cannot pass"
    assert report["ok"] is False
    assert report["chain"]["head_hash"] != original_head, \
        "and it cannot reproduce a head hash the recipient already holds"


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


# ------------------------------------------------- truncation, and its cure --
# Found by audit/fuzz.py in under a minute: deleting entries from the END of a
# chain leaves a shorter chain in which every remaining link verifies. It is a
# property of hash chains, not a defect — but it is a cheaper attack than the
# documented "full rewrite", and it was not written down anywhere.

def _truncate(chain, n=1):
    return chain[:-n]


def test_tail_truncation_is_not_detectable_from_the_chain_alone():
    """The uncomfortable half. Stated by a test so it cannot be forgotten."""
    chain = build_chain(6)
    report = shield_verify.verify_package(make_package(_truncate(chain, 2)))
    assert report["ok"], \
        "truncation leaves a valid chain — if this fails the docs are now wrong"
    assert report["chain"]["intact"]
    assert report["chain"]["entries"] == 4


def test_the_package_cannot_be_used_to_detect_its_own_truncation():
    """An operator who truncates also updates the package's own head claim."""
    chain = build_chain(6)
    pkg = make_package(_truncate(chain, 2))
    assert pkg["custody"]["head_hash"] == shield_verify.verify_package(pkg)["chain"]["head_hash"]


def test_a_head_you_already_hold_detects_truncation():
    """The cure. This is why SPEC.md says keep the head you were given."""
    chain = build_chain(6)
    held = ledger.head_of(chain, JOB_ID)
    report = shield_verify.verify_package(make_package(_truncate(chain, 2)),
                                          expect_head=held)
    assert not report["ok"]
    assert any("head does not match the one you were given" in p
               for p in report["problems"])


def test_a_head_you_hold_also_detects_a_full_rewrite():
    forged, prev = [], ledger.genesis_hash(JOB_ID)
    for i in range(5):
        sealed = ledger.seal({"shield_job_id": JOB_ID, "event_type": "uploaded",
                              "actor_type": "contractor",
                              "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00"}, prev)
        forged.append(sealed)
        prev = sealed["entry_hash"]
    held = ledger.head_of(build_chain(5), JOB_ID)
    report = shield_verify.verify_package(make_package(forged), expect_head=held)
    assert not report["ok"]


def test_a_matching_held_head_still_passes():
    chain = build_chain(5)
    report = shield_verify.verify_package(
        make_package(chain), expect_head=ledger.head_of(chain, JOB_ID))
    assert report["ok"], report["problems"]


def test_verification_without_a_held_head_says_what_it_could_not_check():
    """Silence about a limit is how a recipient is misled."""
    report = shield_verify.verify_package(make_package())
    assert report["ok"]
    assert any("truncated at the end" in n for n in report["notes"]), \
        "a passing verification must disclose what it did not establish"


# ------------------------------------------------ photo bound to the seal --
def _seal_rows(rows, job=JOB_ID):
    out, prev = [], ledger.genesis_hash(job)
    for raw in rows:
        sealed = ledger.seal(raw, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


def test_an_honest_package_passes_against_the_sealed_upload():
    report = shield_verify.verify_package(make_package(), PHOTO_BYTES)
    assert report["verdict"] == "PASS", report["problems"]
    assert report["ok"]
    checked = {f["photo_id"]: f for f in report["files"]}
    assert checked["ph1"]["status"] == "match"
    assert checked["ph1"]["sealed_hash"] == PHOTOS[0]["original_hash"]
    assert checked["ph2"]["status"] == "match"


def test_a_manifest_only_edit_fails_with_no_files_supplied():
    pkg = make_package()
    pkg["checkpoints"][0]["sha256_original"] = "f" * 64
    report = shield_verify.verify_package(pkg)
    assert report["verdict"] == "FAIL"
    assert any(p == "photo ph1 manifest hash does not match the sealed upload record"
               for p in report["problems"])


def test_editing_the_sealed_hash_to_match_a_swap_breaks_the_chain():
    chain = build_chain()
    assert chain[0]["photo_id"] == "ph1"
    chain[0] = {**chain[0], "file_hash": hashlib.sha256(
        b"a completely different image").hexdigest()}
    report = shield_verify.verify_package(
        make_package(chain),
        {"ph1": b"a completely different image", "ph2": PHOTO_BYTES["ph2"]})
    assert not report["ok"]
    assert report["chain"]["broken_at_index"] == 0
    assert "content altered" in report["chain"]["reason"]


def test_a_full_rewrite_around_a_swap_passes_until_a_held_head():
    """The limit that remains. Rewriting the chain so the seal matches the
    swapped bytes produces a package that verifies. The original head does not.
    """
    swapped = b"a completely different image"
    swapped_hash = hashlib.sha256(swapped).hexdigest()
    held = ledger.head_of(build_chain(), JOB_ID)
    rows = []
    upload_i = 0
    uploads = (("ph1", swapped_hash, 1), ("ph2", PHOTOS[1]["original_hash"], 2))
    for i in range(5):
        event_type = ["uploaded", "ai_analyzed", "viewed"][i % 3]
        event_data = {"b": 2, "a": [1, 2, 3], "note": "rewritten"}
        file_hash = "b" * 64
        extra = {}
        if event_type == "uploaded":
            photo_id, file_hash, point = uploads[upload_i]
            upload_i += 1
            extra["photo_id"] = photo_id
            event_data = {**event_data, "point_number": point}
        rows.append({
            "shield_job_id": JOB_ID, "event_type": event_type,
            "actor_type": "contractor", "actor_id": f"user-{i}",
            "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
            "file_hash": file_hash, "event_data": event_data, **extra,
        })
    pkg = make_package(_seal_rows(rows))
    pkg["checkpoints"][0]["sha256_original"] = swapped_hash
    files = {"ph1": swapped, "ph2": PHOTO_BYTES["ph2"]}
    report = shield_verify.verify_package(pkg, files)
    assert report["ok"], report["problems"]
    assert report["chain"]["head_hash"] != held
    caught = shield_verify.verify_package(pkg, files, expect_head=held)
    assert not caught["ok"]
    assert any("head does not match the one you were given" in p
               for p in caught["problems"])


def test_a_photo_with_no_sealed_upload_is_unverified_not_a_failure():
    chain = build_chain()
    # Drop ph2's upload (index 3) and reseal the tail so the chain is intact
    # but that photo has no sealed record. The other entries stay honest.
    kept = [dict(chain[0]), dict(chain[1]), dict(chain[2]), dict(chain[4])]
    resealed = _seal_rows([{k: e[k] for k in (
        "shield_job_id", "photo_id", "event_type", "actor_id", "actor_type",
        "event_data", "gps_lat", "gps_lng", "file_hash", "recorded_at")
        if e.get(k) is not None} for e in kept])
    report = shield_verify.verify_package(make_package(resealed), PHOTO_BYTES)
    assert report["chain"]["intact"]
    assert report["verdict"] == "UNVERIFIED"
    assert report["ok"] is False
    assert report["problems"] == []
    assert any(u == "photo ph2 has no sealed upload record" for u in report["unverified"])
    ph2 = next(f for f in report["files"] if f["photo_id"] == "ph2")
    assert ph2["status"] == "UNVERIFIED"
    ph1 = next(f for f in report["files"] if f["photo_id"] == "ph1")
    assert ph1["status"] == "match"


def test_a_photo_filed_under_the_wrong_checkpoint_fails():
    pkg = make_package()
    # ph2 was sealed for checkpoint 2. Filing it as checkpoint 1's photo,
    # and pointing checkpoint 2 at nothing, is the binding failure.
    pkg["checkpoints"][0]["photo_id"] = "ph2"
    pkg["checkpoints"][0]["sha256_original"] = PHOTOS[1]["original_hash"]
    pkg["checkpoints"][1]["photo_id"] = None
    pkg["checkpoints"][1]["sha256_original"] = None
    report = shield_verify.verify_package(pkg, {"ph2": PHOTO_BYTES["ph2"]})
    assert report["verdict"] == "FAIL"
    assert any(
        p == "photo ph2 is filed under checkpoint 1 but the sealed upload "
             "records checkpoint 2"
        for p in report["problems"])


def test_a_legacy_upload_without_a_checkpoint_number_still_passes():
    """Legacy /shield uploads seal photo_id and file_hash, not point_number."""
    rows = []
    for photo, point_unused in ((PHOTOS[0], 1), (PHOTOS[1], 2)):
        rows.append({
            "shield_job_id": JOB_ID, "event_type": "uploaded",
            "photo_id": photo["id"], "actor_type": "contractor",
            "file_hash": photo["original_hash"],
            "event_data": {"original_bytes": 12, "content_type": "image/jpeg"},
            "recorded_at": "2026-09-02T15:00:00+00:00"
            if photo["id"] == "ph1" else "2026-09-03T09:00:00+00:00",
        })
    report = shield_verify.verify_package(make_package(_seal_rows(rows)), PHOTO_BYTES)
    assert report["verdict"] == "PASS", report["problems"]
    assert any("does not seal a checkpoint number" in n for n in report["notes"])
    assert not any("checkpoint" in p for p in report["problems"])


def test_two_sealed_uploads_for_one_photo_that_disagree_fail():
    rows = [
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph1",
         "file_hash": PHOTOS[0]["original_hash"], "actor_type": "contractor",
         "event_data": {"point_number": 1},
         "recorded_at": "2026-09-02T15:00:00+00:00"},
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph1",
         "file_hash": "b" * 64, "actor_type": "contractor",
         "event_data": {"point_number": 1},
         "recorded_at": "2026-09-02T16:00:00+00:00"},
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph2",
         "file_hash": PHOTOS[1]["original_hash"], "actor_type": "contractor",
         "event_data": {"point_number": 2},
         "recorded_at": "2026-09-03T09:00:00+00:00"},
    ]
    report = shield_verify.verify_package(make_package(_seal_rows(rows)), PHOTO_BYTES)
    assert report["verdict"] == "FAIL"
    assert any(p == "photo ph1 has sealed upload records that disagree"
               for p in report["problems"])


def test_an_edited_superseded_attempt_hash_is_caught():
    old = b"the attempt that was replaced"
    old_hash = hashlib.sha256(old).hexdigest()
    photos = [
        PHOTOS[0],
        {"id": "ph0", "point_id": "p2", "original_hash": old_hash,
         "original_hash_algo": "SHA-256", "ai_verdict": "fail",
         "superseded_by": "ph2", "superseded_at": "2026-09-03T08:00:00+00:00",
         "uploaded_at": "2026-09-02T12:00:00+00:00"},
        {**PHOTOS[1], "uploaded_at": "2026-09-03T09:00:00+00:00"},
    ]
    rows = [
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph0",
         "file_hash": old_hash, "actor_type": "contractor",
         "event_data": {"point_number": 2},
         "recorded_at": "2026-09-02T12:00:00+00:00"},
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph1",
         "file_hash": PHOTOS[0]["original_hash"], "actor_type": "contractor",
         "event_data": {"point_number": 1},
         "recorded_at": "2026-09-02T15:00:00+00:00"},
        {"shield_job_id": JOB_ID, "event_type": "uploaded", "photo_id": "ph2",
         "file_hash": PHOTOS[1]["original_hash"], "actor_type": "contractor",
         "event_data": {"point_number": 2},
         "recorded_at": "2026-09-03T09:00:00+00:00"},
    ]
    pkg = evidence.build_manifest(
        job=JOB, points=POINTS, photos=photos, custody=_seal_rows(rows))
    attempt = pkg["checkpoints"][1]["superseded_attempts"][0]
    assert attempt["photo_id"] == "ph0"
    attempt["sha256_original"] = "d" * 64
    report = shield_verify.verify_package(pkg)
    assert report["verdict"] == "FAIL"
    assert any(p == "photo ph0 manifest hash does not match the sealed upload record"
               for p in report["problems"])


def _api_package(chain, photos=None, checkpoints=None):
    """The shape tenant_api.package() already returns. No server change."""
    photos = photos if photos is not None else [
        {"id": "ph1", "checkpoint_id": "p1",
         "original_hash": PHOTOS[0]["original_hash"]},
        {"id": "ph2", "checkpoint_id": "p2",
         "original_hash": PHOTOS[1]["original_hash"]},
    ]
    checkpoints = checkpoints if checkpoints is not None else [
        {"id": "p1", "point_number": 1, "label": "Sill Plate"},
        {"id": "p2", "point_number": 2, "label": "Wall Framing"},
    ]
    return {
        "schema": "tradedeck.shield.package.v2",
        "chain_version": 2,
        "record": {"id": JOB_ID, "external_ref": "WO-9001"},
        "checkpoints": checkpoints,
        "photos": photos,
        "custody": chain,
        "head_hash": chain[-1]["entry_hash"] if chain else None,
    }


def _api_chain(photo_hashes=None):
    """Sealed the way tenant_api._head_and_append seals: record_id, not
    shield_job_id. photo_id and file_hash are the fields the hash covers.
    """
    photo_hashes = photo_hashes or {
        "ph1": (PHOTOS[0]["original_hash"], 1),
        "ph2": (PHOTOS[1]["original_hash"], 2),
    }
    out, prev = [], ledger.genesis_hash(JOB_ID)
    created = ledger.seal({
        "record_id": JOB_ID, "event_type": "created",
        "actor_ref": "key-1", "actor_kind": "api_key",
        "event_data": {"external_ref": "WO-9001"},
        "recorded_at": "2026-09-01T10:00:00+00:00",
    }, prev)
    out.append(created)
    prev = created["entry_hash"]
    for i, (photo_id, (digest, point)) in enumerate(photo_hashes.items()):
        sealed = ledger.seal({
            "record_id": JOB_ID, "event_type": "uploaded", "photo_id": photo_id,
            "actor_ref": "key-1", "actor_kind": "api_key",
            "file_hash": digest,
            "gps_lat": 40.76056, "gps_lng": -111.89083,
            "event_data": {"checkpoint": "point", "point_number": point,
                           "bytes": 16, "mime": "image/jpeg"},
            "recorded_at": f"2026-09-0{i + 2}T15:00:00+00:00",
        }, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


def test_an_api_package_passes_through_the_same_photo_check():
    report = shield_verify.verify_package(_api_package(_api_chain()), PHOTO_BYTES)
    assert report["verdict"] == "PASS", report["problems"]
    assert report["chain"]["intact"]
    assert {f["photo_id"] for f in report["files"] if f["status"] == "match"} == {"ph1", "ph2"}


def test_an_api_package_swap_that_rewrites_original_hash_is_caught():
    swapped = b"a completely different image"
    chain = _api_chain()
    pkg = _api_package(chain)
    pkg["photos"][0]["original_hash"] = hashlib.sha256(swapped).hexdigest()
    report = shield_verify.verify_package(
        pkg, {"ph1": swapped, "ph2": PHOTO_BYTES["ph2"]})
    assert report["verdict"] == "FAIL"
    assert report["chain"]["intact"]
    assert any(p == "photo ph1 does not match the sealed upload record"
               for p in report["problems"])


def test_an_api_package_filed_under_the_wrong_checkpoint_fails():
    pkg = _api_package(_api_chain())
    pkg["photos"][1]["checkpoint_id"] = "p1"
    report = shield_verify.verify_package(pkg, PHOTO_BYTES)
    assert report["verdict"] == "FAIL"
    assert any("photo ph2 is filed under checkpoint 1" in p for p in report["problems"])


def test_an_api_photo_with_no_sealed_upload_is_unverified():
    chain = _api_chain(photo_hashes={"ph1": (PHOTOS[0]["original_hash"], 1)})
    report = shield_verify.verify_package(_api_package(chain), PHOTO_BYTES)
    assert report["verdict"] == "UNVERIFIED"
    assert report["problems"] == []
    assert any(u == "photo ph2 has no sealed upload record" for u in report["unverified"])
