"""Grading tests — every one is a fraud scenario the old logic let through."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import verdict  # noqa: E402


def pt(n, v=None, label=None, superseded=False):
    p = {"point_number": n, "label": label or f"Checkpoint {n}"}
    if v is not None or superseded:
        p["photo"] = {"ai_verdict": v}
        if superseded:
            p["photo"]["superseded_by"] = "some-newer-photo"
    return p


# ------------------------------------------------------- the headline bug ---
def test_one_photo_of_five_checkpoints_is_not_a_pass():
    """Regression, C1. The old derive_verdict filtered unphotographed points
    out of the vote, so they could not contribute a failure — one passing photo
    out of five returned 'pass' with a score of 20."""
    g = verdict.grade([pt(1, "pass"), pt(2), pt(3), pt(4), pt(5)])
    assert g["verdict"] == "incomplete"
    assert g["verdict"] != "pass"
    assert g["checkpoints_verified"] == 1
    assert g["coverage_pct"] == 20.0
    assert len(g["missing"]) == 4
    assert "1 of 5 checkpoints verified" in g["summary"]


def test_missing_evidence_outranks_passing_evidence():
    """Four perfect photos and one absent checkpoint is not a pass."""
    g = verdict.grade([pt(1, "pass"), pt(2, "pass"), pt(3, "pass"), pt(4, "pass"), pt(5)])
    assert g["verdict"] == "incomplete"
    assert g["coverage_pct"] == 80.0


def test_a_superseded_photo_does_not_count_as_evidence():
    """A retake that was replaced must not satisfy its checkpoint."""
    g = verdict.grade([pt(1, "pass"), pt(2, "pass", superseded=True)])
    assert g["verdict"] == "incomplete"
    assert g["checkpoints_verified"] == 1


# ------------------------------------------------------------- severity ----
def test_full_coverage_all_passing():
    g = verdict.grade([pt(i, "pass") for i in range(1, 6)])
    assert g["verdict"] == "pass"
    assert g["score"] == 100.0
    assert g["coverage_pct"] == 100.0
    assert g["missing"] == []


def test_worst_verdict_wins_and_is_not_averaged_away():
    """One faked photo among four honest ones is not diluted to 'pass'."""
    g = verdict.grade([pt(1, "pass"), pt(2, "pass"), pt(3, "pass"), pt(4, "fake")])
    assert g["verdict"] == "fake"
    assert "Checkpoint 4" in g["failing"]


def test_fake_outranks_fail_outranks_flag():
    assert verdict.grade([pt(1, "fail"), pt(2, "fake")])["verdict"] == "fake"
    assert verdict.grade([pt(1, "flag"), pt(2, "fail")])["verdict"] == "fail"
    assert verdict.grade([pt(1, "pass"), pt(2, "flag")])["verdict"] == "flag"


def test_fake_is_reportable_and_not_collapsed_into_fail():
    """The old code mapped fake->fail, making a forged photo indistinguishable
    from merely substandard work in the headline a homeowner reads."""
    assert verdict.grade([pt(1, "fake")])["verdict"] == "fake"
    assert "genuine capture" in verdict.grade([pt(1, "fake")])["summary"]


def test_empty_job_is_incomplete_not_passing():
    g = verdict.grade([])
    assert g["verdict"] == "incomplete"
    assert g["score"] == 0.0


# ----------------------------------------------------------- close-out -----
def test_cannot_close_out_with_an_unphotographed_checkpoint():
    assert verdict.is_complete_enough([pt(1, "pass"), pt(2)]) is False
    assert verdict.is_complete_enough([pt(1, "pass"), pt(2, "fail")]) is True
    assert verdict.is_complete_enough([]) is False


def test_only_a_full_clean_job_builds_contractor_standing():
    """Regression, C1's tail: the badge counted completion rows, so repeated
    close-outs of one partial job could mint the verified badge."""
    full_pass = verdict.grade([pt(i, "pass") for i in range(1, 6)])
    partial = verdict.grade([pt(1, "pass"), pt(2)])
    flagged = verdict.grade([pt(1, "pass"), pt(2, "flag")])
    assert verdict.counts_toward_badge(full_pass) is True
    assert verdict.counts_toward_badge(partial) is False
    assert verdict.counts_toward_badge(flagged) is False


# -------------------------------------------------------------- scoring ----
def test_score_reflects_missing_evidence_as_zero():
    g = verdict.grade([pt(1, "pass"), pt(2)])
    assert g["score"] == 50.0


def test_score_and_verdict_never_disagree_about_completeness():
    """The old pairing reported verdict='pass' alongside score=20.0."""
    for n_pass in range(0, 5):
        pts = [pt(i, "pass") for i in range(1, n_pass + 1)]
        pts += [pt(i) for i in range(n_pass + 1, 6)]
        g = verdict.grade(pts)
        if g["score"] < 100.0:
            assert g["verdict"] != "pass", f"{g['score']} scored but verdict said pass"
