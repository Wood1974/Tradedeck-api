"""Field-note tests.

The contemporaneity bands map to hearsay exceptions, so the boundaries are
asserted explicitly — drifting one silently would change what the export can
claim about a note's standing.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import notes  # noqa: E402

SHOT = datetime(2026, 9, 14, 15, 0, 0, tzinfo=timezone.utc)


def after(**kw):
    return (SHOT + timedelta(**kw)).isoformat()


# ------------------------------------------------------- contemporaneity ----
@pytest.mark.parametrize("delta,band,rule", [
    ({"seconds": 20}, "immediate", "FRE 803(1)"),
    ({"minutes": 4},  "immediate", "FRE 803(1)"),
    ({"minutes": 25}, "prompt",    "FRE 803(1)"),
    ({"hours": 1},    "delayed",   "FRE 803(5) / 803(6)"),
    ({"hours": 6},    "same_day",  "FRE 803(6)"),
    ({"days": 3},     "reconstructed", None),
])
def test_delay_maps_to_the_exception_it_can_actually_support(delta, band, rule):
    r = notes.classify_contemporaneity(SHOT, after(**delta))
    assert r["band"] == band
    assert r["strongest_exception"] == rule


def test_the_803_1_boundary_is_minutes_not_hours():
    """803(1) tolerates seconds to minutes and grows hostile at hours. Claiming
    it for a four-hour-old note is how an exhibit gets excluded."""
    assert notes.classify_contemporaneity(SHOT, after(minutes=29))["strongest_exception"] == "FRE 803(1)"
    assert notes.classify_contemporaneity(SHOT, after(hours=4))["strongest_exception"] != "FRE 803(1)"


def test_a_note_written_before_the_event_is_flagged_not_graded():
    r = notes.classify_contemporaneity(SHOT, (SHOT - timedelta(hours=1)).isoformat())
    assert r["band"] == "before_observation"
    assert r["strongest_exception"] is None
    assert "cannot describe something that had not happened" in r["note"]


def test_clock_skew_of_a_few_seconds_is_not_treated_as_time_travel():
    r = notes.classify_contemporaneity(SHOT, (SHOT - timedelta(seconds=30)).isoformat())
    assert r["band"] == "immediate"


def test_naive_timestamps_are_refused_rather_than_guessed():
    """Reading a naive timestamp as server-local would shift every band."""
    r = notes.classify_contemporaneity(SHOT, datetime(2026, 9, 14, 15, 1))
    assert r["band"] == "unknown"
    assert r["strongest_exception"] is None


def test_delay_is_stated_in_human_terms_for_the_export():
    assert "seconds after" in notes.classify_contemporaneity(SHOT, after(seconds=30))["delay_human"]
    assert "minutes after" in notes.classify_contemporaneity(SHOT, after(minutes=20))["delay_human"]
    assert "hours after" in notes.classify_contemporaneity(SHOT, after(hours=5))["delay_human"]
    assert "days after" in notes.classify_contemporaneity(SHOT, after(days=2))["delay_human"]


# -------------------------------------------------------------- quality ----
def test_a_conclusion_is_caught_because_803_1_does_not_reach_opinions():
    q = notes.assess_quality("Framing looks good, all to code.")
    assert q["cautions"]
    assert "conclusion, not an observation" in q["cautions"][0]
    assert q["strength"] == "thin"


def test_a_real_observation_scores_well():
    q = notes.assess_quality(
        'Measured anchor bolt spacing at 5\'2" and 5\'8" along the north sill, '
        'tape visible in frame. 14 bolts total. Inspector Dan Reyes on site at '
        '14:30 and said "spacing is fine, show me the washers."')
    assert q["strength"] == "strong"
    assert "measurement with units" in q["specifics_found"]
    assert "a counted quantity" in q["specifics_found"]
    assert "a time of day" in q["specifics_found"]
    assert "something someone said, quoted" in q["specifics_found"]
    assert not q["cautions"]


def test_hedging_is_flagged_separately_from_conclusions():
    q = notes.assess_quality("I think the spacing is probably around 6 feet.")
    assert any("signals uncertainty" in c for c in q["cautions"])


def test_a_short_note_is_told_it_is_short():
    q = notes.assess_quality("done")
    assert q["word_count"] == 1
    assert any("Too short" in s for s in q["suggestions"])
    assert q["strength"] == "thin"


def test_an_empty_note_does_not_crash():
    for empty in ("", None, "   "):
        q = notes.assess_quality(empty)
        assert q["word_count"] == 0
        assert q["strength"] == "thin"


def test_guidance_never_blocks_a_save():
    """A contractor on a roof must be able to save and move on. Guidance that
    refuses produces no note at all, which is the worst available outcome."""
    for text in ("", "done", "looks fine", "I think probably ok"):
        assert notes.assess_quality(text)["blocking"] is False


def test_prompts_lead_with_the_checkpoint_requirement():
    p = notes.prompts_for({"must_show": "Bolt spacing measured, washers torqued"})
    assert "Bolt spacing measured" in p[0]
    assert len(p) == 4
    assert len(notes.prompts_for(None)) == 4
    assert len(notes.prompts_for({})) == 4


# ----------------------------------------------------------- amendments ----
ORIGINAL = {"id": "n1", "shield_job_id": "job-1", "photo_id": "ph1",
            "point_id": "p1", "author_id": "contractor-1",
            "body": "Bolt spacing 6'0\" throughout.", "medium": "typed",
            "observed_at": SHOT.isoformat(), "written_at": after(minutes=2)}


def test_an_amendment_preserves_the_original_and_states_why():
    a = notes.build_amendment(ORIGINAL, 'Bolt spacing 5\'2" — misread the tape.',
                              reason="Transcription error", author_id="contractor-1",
                              written_at=after(hours=1))
    assert a["amends_note_id"] == "n1"
    assert a["amendment_reason"] == "Transcription error"
    assert a["observed_at"] == ORIGINAL["observed_at"], \
        "an amendment describes the same observation, so the band is measured from it"


def test_the_thread_shows_both_versions_not_just_the_latest():
    """The first question on cross is whether the note says what it said at the
    time. A record that cannot answer that takes the rest down with it."""
    a = notes.build_amendment(ORIGINAL, 'Corrected to 5\'2".', reason="Misread",
                              author_id="contractor-1", written_at=after(hours=1))
    t = notes.thread_of(ORIGINAL, [{**a, "id": "n2"}])
    assert t["was_amended"] is True
    assert t["original"]["body"] == ORIGINAL["body"]
    assert t["current_body"] == 'Corrected to 5\'2".'
    assert t["amendments"][0]["reason"] == "Misread"


def test_an_unamended_note_reads_as_unamended():
    t = notes.thread_of(ORIGINAL, [])
    assert t["was_amended"] is False
    assert t["current_body"] == ORIGINAL["body"]


def test_amendments_are_ordered_oldest_first():
    a1 = {**notes.build_amendment(ORIGINAL, "first", reason="r1", author_id="c",
                                  written_at=after(hours=1)), "id": "n2"}
    a2 = {**notes.build_amendment(ORIGINAL, "second", reason="r2", author_id="c",
                                  written_at=after(hours=3)), "id": "n3"}
    t = notes.thread_of(ORIGINAL, [a2, a1])
    assert [x["body"] for x in t["amendments"]] == ["first", "second"]
    assert t["current_body"] == "second"


def test_supported_media_include_a_photographed_handwritten_page():
    """Handwritten field notes photographed on site are a real construction
    artefact and carry the same contemporaneity argument."""
    assert "photographed_handwritten" in notes.MEDIA
    assert "dictated" in notes.MEDIA
