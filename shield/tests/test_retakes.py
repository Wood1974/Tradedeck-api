"""Retakes: one live photo per checkpoint, chosen the same way everywhere.

Two defects meet here.

The first was silent. Close-out and the evidence export each selected the live
photo for a checkpoint with their own inline expression, and they disagreed:
close-out kept the LAST row of an `uploaded_at` ordering, the export kept the
FIRST. With two photos on one checkpoint the sealed packet and the Rule 902(14)
manifest could cite different images for the same requirement — which is the
kind of thing an opposing party reads aloud.

The second was total. Nothing anywhere ever wrote `superseded_by`, while the
schema carried a unique index admitting one non-superseded photo per
checkpoint. So the second photo on any checkpoint collided with that index and
the API answered 500 "please retry" — advice that could not work. Retakes did
not exist, and the export's retake disclosure was permanently empty.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import evidence      # noqa: E402
import verdict       # noqa: E402

POINTS = [{"id": "p1", "point_number": 1, "label": "Sill Plate",
           "description": "Bolt spacing", "irc_code": "IRC R403.1.6"}]

FIRST = {"id": "ph1", "point_id": "p1", "original_hash": "a" * 64,
         "uploaded_at": "2026-09-02T15:00:00+00:00", "ai_verdict": "fail",
         "superseded_by": "ph2", "superseded_at": "2026-09-03T09:00:00+00:00"}
SECOND = {"id": "ph2", "point_id": "p1", "original_hash": "b" * 64,
          "uploaded_at": "2026-09-03T09:05:00+00:00", "ai_verdict": "pass",
          "superseded_by": None, "superseded_at": None}


def test_liveness_needs_both_markers_clear():
    assert verdict.is_live(SECOND)
    assert not verdict.is_live(FIRST)
    # superseded_at alone is a retake mid-flight: the row has left the live set
    # but its replacement does not have an id yet.
    assert not verdict.is_live({"superseded_at": "2026-09-03T09:00:00+00:00"})
    assert not verdict.is_live({})


def test_the_retake_is_the_evidence_and_the_attempt_is_kept():
    photos = [FIRST, SECOND]
    assert verdict.live_photo_for("p1", photos)["id"] == "ph2"
    assert [p["id"] for p in verdict.superseded_for("p1", photos)] == ["ph1"]


def test_close_out_and_the_export_choose_the_same_photo():
    """The regression that mattered: two callers, one checkpoint, two answers."""
    photos = [FIRST, SECOND]

    # what complete_job seals
    enriched = [{**pt, "photo": verdict.live_photo_for(pt["id"], photos) or {}}
                for pt in POINTS]
    sealed_id = enriched[0]["photo"]["id"]

    # what the 902(14) manifest publishes
    manifest = evidence.build_manifest(
        job={"id": "job-1", "trade": "framing"},
        points=POINTS, photos=photos, custody=[])
    exported_id = manifest["checkpoints"][0]["photo_id"]

    assert sealed_id == exported_id == "ph2"


def test_arrival_order_does_not_decide_the_evidence():
    """Selection must not inherit whatever order the rows came back in."""
    for photos in ([FIRST, SECOND], [SECOND, FIRST]):
        assert verdict.live_photo_for("p1", photos)["id"] == "ph2"


def test_a_retake_cannot_erase_the_failure_it_replaces():
    manifest = evidence.build_manifest(
        job={"id": "job-1", "trade": "framing"},
        points=POINTS, photos=[FIRST, SECOND], custody=[])
    item = manifest["checkpoints"][0]
    assert item["verdict"] == "pass"
    assert item["superseded_attempts"], "the earlier attempt must be disclosed, not dropped"
    assert item["superseded_attempts"][0]["verdict"] == "fail"


def test_grading_ignores_a_superseded_photo():
    graded = verdict.grade([{**POINTS[0], "photo": FIRST}])
    assert graded["verdict"] == "incomplete", \
        "a superseded photo backs no checkpoint"
