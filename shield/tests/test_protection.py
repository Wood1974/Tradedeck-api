"""Guidance tests — the advice must be correct for the job in front of it."""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import protection  # noqa: E402

NOW = datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)
SHOT = NOW - timedelta(hours=2)


def iso(dt):
    return dt.isoformat()


def job(**kw):
    base = {"id": "j1", "site_lat": 40.76, "site_lng": -111.89, "site_radius_m": 250,
            "checkpoints_locked_at": iso(SHOT - timedelta(days=1))}
    base.update(kw)
    return base


PTS = [{"id": f"p{i}", "point_number": i, "label": f"Checkpoint {i}"} for i in (1, 2)]


def photo(pid, point, when=SHOT):
    return {"id": pid, "point_id": point, "exif_captured_at": iso(when),
            "server_received_at": iso(when), "superseded_by": None}


def note(pid, delay_min=2, strength="strong"):
    return {"id": f"n-{pid}", "photo_id": pid, "amends_note_id": None,
            "observed_at": iso(SHOT), "strength": strength,
            "written_at": iso(SHOT + timedelta(minutes=delay_min))}


def assess(**kw):
    return protection.assess_record(now=NOW, **kw)


# ------------------------------------------------------------- the ideal ---
def test_a_complete_record_reports_no_gaps():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")],
               notes=[note("ph1"), note("ph2")])
    assert a["gaps"] == []
    assert "Strong on every practice" in a["posture"]
    assert "chain head" in a["next_action"]


def test_a_complete_record_names_its_strengths():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")],
               notes=[note("ph1"), note("ph2")])
    ids = {s["practice"] for s in a["strengths"]}
    assert {"site_location", "lock_before_work", "every_time", "note_within_five"} <= ids


# ----------------------------------------------------------- structural ----
def test_a_missing_site_location_is_high_severity():
    a = assess(job=job(site_lat=None, site_lng=None), points=PTS,
               photos=[photo("ph1", "p1")], notes=[note("ph1")])
    gap = next(g for g in a["gaps"] if g["practice"] == "site_location")
    assert gap["severity"] == "high"
    assert "cannot be retrofitted" in gap["fix"]


def test_an_unlocked_schedule_is_high_severity():
    a = assess(job=job(checkpoints_locked_at=None), points=PTS,
               photos=[photo("ph1", "p1")], notes=[note("ph1")])
    assert any(g["practice"] == "lock_before_work" and g["severity"] == "high"
               for g in a["gaps"])


def test_photos_predating_the_lock_are_caught():
    """A schedule fixed after the photographs is a schedule that could have been
    chosen to fit them — and no later action repairs it."""
    a = assess(job=job(checkpoints_locked_at=iso(SHOT + timedelta(hours=1))),
               points=PTS, photos=[photo("ph1", "p1")], notes=[note("ph1")])
    gap = next(g for g in a["gaps"] if g["practice"] == "lock_before_work")
    assert "predate" in gap["state"]
    assert "Nothing can change this now" in gap["fix"]


def test_gaps_are_ordered_worst_first():
    a = assess(job=job(site_lat=None, site_lng=None, checkpoints_locked_at=None),
               points=PTS, photos=[], notes=[])
    severities = [g["severity"] for g in a["gaps"]]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])
    assert a["gaps"][0]["severity"] == "high"


# -------------------------------------------------------------- coverage ---
def test_undocumented_checkpoints_are_named():
    a = assess(job=job(), points=PTS, photos=[photo("ph1", "p1")], notes=[note("ph1")])
    gap = next(g for g in a["gaps"] if g["practice"] == "every_time")
    assert "1 of 2 checkpoints have no photo" in gap["state"]
    assert "Checkpoint 2" in gap["state"]


def test_unannotated_photos_are_high_severity_when_none_are_annotated():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")], notes=[])
    gap = next(g for g in a["gaps"] if g["practice"] == "note_within_five")
    assert gap["severity"] == "high"


def test_partially_annotated_is_medium_not_high():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")], notes=[note("ph1")])
    gap = next(g for g in a["gaps"] if g["practice"] == "note_within_five")
    assert gap["severity"] == "medium"


# ---------------------------------------------------------------- timing ---
def test_late_notes_are_flagged_but_not_condemned():
    """A late note still stands under 803(6). The advice should say so rather
    than implying the record is ruined."""
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")],
               notes=[note("ph1", delay_min=600), note("ph2", delay_min=600)])
    gap = next(g for g in a["gaps"] if g["practice"] == "note_within_five")
    assert "803(1)" in gap["state"]
    assert "still stand as business records" in gap["fix"]
    assert gap["severity"] == "medium"


def test_prompt_notes_are_credited_with_the_rule_they_earn():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")],
               notes=[note("ph1"), note("ph2")])
    s = next(s for s in a["strengths"] if s["practice"] == "note_within_five")
    assert "803(1)" in s["state"]


def test_thin_notes_are_flagged_with_an_achievable_fix():
    a = assess(job=job(), points=PTS,
               photos=[photo("ph1", "p1"), photo("ph2", "p2")],
               notes=[note("ph1", strength="thin"), note("ph2", strength="thin")])
    gap = next(g for g in a["gaps"] if g["practice"] == "observe_dont_conclude")
    assert "cannot edit them, but you can amend" in gap["fix"]


# ---------------------------------------------------------------- posture --
def test_posture_escalates_with_structural_damage():
    clean = assess(job=job(), points=PTS,
                   photos=[photo("ph1", "p1"), photo("ph2", "p2")],
                   notes=[note("ph1"), note("ph2")])
    one_gap = assess(job=job(site_lat=None, site_lng=None), points=PTS,
                     photos=[photo("ph1", "p1"), photo("ph2", "p2")],
                     notes=[note("ph1"), note("ph2")])
    wrecked = assess(job=job(site_lat=None, site_lng=None, checkpoints_locked_at=None),
                     points=PTS, photos=[], notes=[])
    assert "Strong on every practice" in clean["posture"]
    assert "one structural gap" in one_gap["posture"]
    assert "would not hold up well" in wrecked["posture"]


# ------------------------------------------------------------- next step ---
def test_next_step_names_the_worst_gap_and_why_it_matters():
    n = protection.next_step(job=job(checkpoints_locked_at=None), points=PTS,
                             photos=[], notes=[], now=NOW)
    assert n["severity"] == "high"
    assert n["because"]
    assert n["for"] in ("homeowner", "contractor")


def test_next_step_on_a_clean_record_points_at_the_chain_head():
    """The one practice that protects the buyer against the operator."""
    n = protection.next_step(job=job(), points=PTS,
                             photos=[photo("ph1", "p1"), photo("ph2", "p2")],
                             notes=[note("ph1"), note("ph2")], now=NOW)
    assert n["severity"] == "none"
    assert "chain head" in n["action"]
    assert "rewritten" in n["because"]


# -------------------------------------------------------------- practices --
def test_every_practice_states_what_skipping_it_costs():
    for p in protection.PRACTICES:
        for field in ("id", "stage", "do", "why", "if_skipped", "who"):
            assert p.get(field), f"{p.get('id')} missing {field}"
        assert p["who"] in ("homeowner", "contractor")


def test_practices_filter_by_role():
    assert all(p["who"] == "contractor" for p in protection.practices_for("contractor"))
    assert all(p["who"] == "homeowner" for p in protection.practices_for("homeowner"))
    assert len(protection.practices_for()) == len(protection.PRACTICES)


def test_an_empty_job_does_not_crash():
    a = assess(job={"id": "j1"}, points=[], photos=[], notes=[])
    assert a["gaps"]
    assert a["posture"]
