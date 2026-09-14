"""Evidence-package tests.

The package's whole purpose is to be checkable by someone who does not trust
us, so these assert on what a recipient can verify and on what the
certification is careful NOT to claim.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import evidence  # noqa: E402
import ledger    # noqa: E402

JOB_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

JOB = {"id": JOB_ID, "external_ref": "WO-4471", "site_address": "88 Pine St, Salt Lake City UT",
       "site_lat": 40.76056, "site_lng": -111.89083, "site_radius_m": 250,
       "trade": "framing", "created_at": "2026-09-01T10:00:00+00:00",
       "activated_at": "2026-09-01T10:05:00+00:00",
       "checkpoints_locked_at": "2026-09-01T10:06:00+00:00",
       "completed_at": "2026-09-14T18:00:00+00:00"}

POINTS = [
    {"id": "p1", "point_number": 1, "label": "Sill Plate and Anchor Bolts",
     "description": "Full sill run with bolt spacing", "irc_code": "IRC R403.1.6",
     "must_show": "Bolt spacing measured"},
    {"id": "p2", "point_number": 2, "label": "Wall Framing",
     "description": "Stud spacing and headers", "irc_code": "IRC R602.3",
     "must_show": "Stud spacing"},
]

PHOTOS = [
    {"id": "ph1", "point_id": "p1", "original_hash": "a" * 64, "original_hash_algo": "SHA-256",
     "original_size_bytes": 2_400_000, "server_received_at": "2026-09-02T15:00:00+00:00",
     "exif_captured_at": "2026-09-02T14:58:00+00:00", "has_exif": True,
     "site_distance_m": 12.4, "ai_verdict": "pass", "ai_confidence": 0.91,
     "ai_model": "claude-sonnet-5", "ai_notes": "Bolts at 5ft centres.",
     "superseded_by": None},
    # a retake: the first attempt failed and must still appear in the package
    {"id": "ph0", "point_id": "p2", "original_hash": "b" * 64, "ai_verdict": "fail",
     "superseded_by": "ph2", "superseded_at": "2026-09-03T09:00:00+00:00"},
    {"id": "ph2", "point_id": "p2", "original_hash": "c" * 64, "original_hash_algo": "SHA-256",
     "server_received_at": "2026-09-03T09:05:00+00:00", "has_exif": True,
     "site_distance_m": 8.0, "ai_verdict": "pass", "ai_confidence": 0.88,
     "ai_model": "claude-sonnet-5", "superseded_by": None},
]


def build_chain(n=4, job=JOB_ID):
    out, prev = [], ledger.genesis_hash(job)
    for i in range(n):
        raw = {"shield_job_id": job, "event_type": "uploaded",
               "actor_type": "contractor", "recorded_at": f"2026-09-0{i+1}T10:00:00+00:00"}
        sealed = ledger.seal(raw, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


REPORT = {"overall_verdict": "pass", "completion_score": 100.0, "report_sha256": "d" * 64}


# ---------------------------------------------------------------- manifest --
def test_manifest_lists_one_live_photo_per_checkpoint():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    assert len(m["checkpoints"]) == 2
    assert m["checkpoints"][0]["sha256_original"] == "a" * 64
    assert m["checkpoints"][1]["sha256_original"] == "c" * 64


def test_superseded_attempts_are_disclosed_not_hidden():
    """A checkpoint reshot until it passed is a fact about the job. Concealing
    it invites exactly the impeachment the package exists to survive."""
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    attempts = m["checkpoints"][1]["superseded_attempts"]
    assert len(attempts) == 1
    assert attempts[0]["verdict"] == "fail"
    assert attempts[0]["sha256_original"] == "b" * 64


def test_manifest_carries_every_field_a_recipient_needs_to_check():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    cp = m["checkpoints"][0]
    for field in ("sha256_original", "hash_algorithm", "size_bytes",
                  "received_utc", "code_section", "verdict", "confidence", "model"):
        assert field in cp
    assert m["custody"]["head_hash"]
    assert m["job"]["checkpoints_locked_utc"] == JOB["checkpoints_locked_at"]


def test_manifest_reports_an_intact_chain_as_intact():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(6), report=REPORT)
    assert m["custody"]["chain_intact"] is True
    assert m["custody"]["entries"] == 6


def test_manifest_reports_a_tampered_chain_as_broken():
    """The package must expose its own problems rather than paper over them."""
    chain = build_chain(5)
    chain[2]["event_type"] = "ai_analyzed"
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=chain, report=REPORT)
    assert m["custody"]["chain_intact"] is False
    assert "breaks at entry 3" in m["custody"]["chain_summary"]


def test_missing_photo_produces_a_null_hash_not_a_silent_omission():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=[PHOTOS[0]],
                                custody=build_chain(), report=REPORT)
    assert len(m["checkpoints"]) == 2
    assert m["checkpoints"][1]["sha256_original"] is None
    assert m["checkpoints"][1]["photo_id"] is None


# ----------------------------------------------------------- certification --
def test_certification_cites_the_rules_and_the_hash_mechanism():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    text = evidence.certification_text(m)
    assert "902(13)" in text and "902(14)" in text
    assert "exact duplicate of the original as received" in text
    assert "SHA-256" in text
    assert "penalty of perjury" in text
    assert "Rule 902(11)" in text and "reasonable written notice" in text


def test_certification_disclaims_what_it_cannot_certify():
    """Overclaiming here is what gets a certification torn apart on cross."""
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    text = evidence.certification_text(m)
    assert "does not certify" in text
    assert "complies with any building code" in text
    assert "offered as opinion, not as a finding of compliance" in text


def test_certification_is_left_unsigned_for_a_human():
    """A certification is a sworn statement by someone cross-examinable.
    Auto-signing one would be the hollow assurance this product replaces."""
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    blank = evidence.certification_text(m)
    assert "Signature: ______" in blank
    assert "_________________________________" in blank

    filled = evidence.certification_text(
        m, certifier_name="J. Woodall", certifier_title="Operations Lead",
        certifier_qualifications="Five years operating this system")
    assert "J. Woodall" in filled
    assert "Signature: ______" in filled, "still requires a wet signature"


def test_certification_reports_a_broken_chain_honestly():
    chain = build_chain(5)
    del chain[1]
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=chain, report=REPORT)
    text = evidence.certification_text(m)
    assert "Chain breaks at entry" in text


# ---------------------------------------------------------- verifiability --
def test_instructions_let_a_recipient_verify_without_trusting_us():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    how = evidence.verification_instructions(m)
    assert "shasum -a 256" in how
    assert ledger.genesis_hash(JOB_ID) in how
    assert m["custody"]["head_hash"] in how
    for field in ledger.SIGNED_FIELDS:
        assert field in how, f"recipient cannot recompute without knowing {field}"


def test_published_genesis_actually_matches_the_chain():
    """The instructions must be correct, not merely present."""
    chain = build_chain(3)
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=chain, report=REPORT)
    assert chain[0]["prev_hash"] == ledger.genesis_hash(JOB_ID)
    assert m["custody"]["head_hash"] == chain[-1]["entry_hash"]
