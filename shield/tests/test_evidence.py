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


# ----------------------------------------------------- field notes in the ---
# ----------------------------------------------------- evidence package   ---
from datetime import datetime, timedelta, timezone  # noqa: E402

SHOT = datetime(2026, 9, 2, 15, 0, tzinfo=timezone.utc)

NOTES = [
    {"id": "n1", "shield_job_id": JOB_ID, "photo_id": "ph1", "point_id": None,
     "author_id": "c1", "author_role": "contractor", "medium": "typed",
     "body": 'Bolt spacing 5\'2" measured, 14 bolts, tape in frame.',
     "observed_at": SHOT.isoformat(),
     "written_at": (SHOT + timedelta(minutes=2)).isoformat(), "amends_note_id": None},
    {"id": "n2", "shield_job_id": JOB_ID, "photo_id": "ph1", "point_id": None,
     "author_id": "c1", "author_role": "contractor", "medium": "typed",
     "body": 'Correction: 5\'8" on the NE bolt.',
     "observed_at": SHOT.isoformat(),
     "written_at": (SHOT + timedelta(hours=1)).isoformat(),
     "amends_note_id": "n1", "amendment_reason": "Misread the tape"},
    {"id": "n3", "shield_job_id": JOB_ID, "photo_id": None, "point_id": None,
     "author_id": "h1", "author_role": "homeowner", "medium": "dictated",
     "body": "Walked the site at 4pm, rain started around 3.",
     "observed_at": SHOT.isoformat(),
     "written_at": (SHOT + timedelta(days=2)).isoformat(), "amends_note_id": None},
]


def test_notes_attach_to_their_checkpoint():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    attached = m["checkpoints"][0]["field_notes"]
    assert len(attached) == 1
    assert attached[0]["note_id"] == "n1"


def test_each_note_carries_the_exception_its_delay_supports():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    prompt_note = m["checkpoints"][0]["field_notes"][0]
    assert prompt_note["strongest_exception"] == "FRE 803(1)"
    assert "minutes after" in prompt_note["delay"]

    late = m["field_notes"]["unattached"][0]
    assert late["contemporaneity"] == "reconstructed"
    assert late["strongest_exception"] is None, \
        "a two-day-old note must not be presented as contemporaneous"


def test_an_amended_note_shows_both_versions():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    n = m["checkpoints"][0]["field_notes"][0]
    assert n["was_amended"] is True
    assert '5\'2"' in n["original"]["body"]
    assert '5\'8"' in n["current_body"]
    assert n["amendments"][0]["reason"] == "Misread the tape"


def test_unattached_notes_still_appear_in_the_package():
    """A daily-log note with no photo is still part of the record."""
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    assert len(m["field_notes"]["unattached"]) == 1
    assert m["field_notes"]["unattached"][0]["author_role"] == "homeowner"


def test_note_totals_count_threads_not_rows():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    fn = m["field_notes"]
    assert fn["total"] == 2, "an amendment is part of its note, not a second note"
    assert fn["contemporaneous"] == 1
    assert fn["amended"] == 1


def test_certification_states_the_note_position_honestly():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=NOTES)
    text = evidence.certification_text(m)
    assert "CONTEMPORANEOUS FIELD NOTES" in text
    assert "set by the system" in text
    assert "not supplied by its author" in text
    assert "Notes cannot be edited" in text
    assert "I offer no view on whether any note is accurate" in text


def test_a_package_with_no_notes_does_not_claim_any():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT, notes=[])
    assert m["field_notes"]["total"] == 0
    assert "includes 0 field note(s)" in evidence.certification_text(m)


def test_notes_are_optional_for_backwards_compatibility():
    m = evidence.build_manifest(job=JOB, points=POINTS, photos=PHOTOS,
                                custody=build_chain(), report=REPORT)
    assert m["field_notes"]["total"] == 0
