"""The public outcome report, and the ways it must refuse to flatter us.

Why this file exists
--------------------
Publishing results is only worth something if the publication cannot be tuned.
Every statistic a company puts out about itself is subject to the same three
temptations, and each one has a test here:

1. **Report the good categories and omit the bad.** Prevented by fixing the
   category list: every verdict is always present, at zero if need be, so a
   reader can see there were no failures rather than being unable to tell
   whether failures are absent or merely unreported.

2. **Quote a rate off a sample too small to carry one.** "100% pass rate" on
   one job is true and worthless, and it is the single most likely sentence to
   end up on a landing page. Below the minimum sample the report refuses to
   compute a percentage at all — the field is None and the reason is stated.

3. **Let failures disappear through the side door.** A photo that failed and
   was retaken is superseded, not deleted. Counting only live photos would
   quietly drop every failure that was ever fixed, producing an honest-looking
   number from honest-looking code. Superseded photos stay in the denominator
   *and* the numerator.

The fourth property is privacy: this is served to anonymous callers, so no row
identifier, address or user id may appear in it.
"""
import json
import re

import pytest

import transparency as tr


def reports(*verdicts):
    """Completion-report rows as the database stores them."""
    return [{"id": f"r{i}", "shield_job_id": f"j{i}", "contractor_id": f"c{i}",
             "homeowner_id": f"h{i}", "overall_verdict": v,
             "completion_score": 100.0 if v == "pass" else 0.0}
            for i, v in enumerate(verdicts)]


def photos(*specs):
    """Photo rows. Each spec is (ai_verdict, has_exif, superseded)."""
    out = []
    for i, (verdict, has_exif, superseded) in enumerate(specs):
        out.append({"id": f"p{i}", "shield_job_id": "j0", "point_id": f"pt{i}",
                    "ai_verdict": verdict, "has_exif": has_exif,
                    "superseded_by": f"p{i}x" if superseded else None,
                    "superseded_at": "2026-09-01" if superseded else None})
    return out


class TestCategoriesAreFixed:
    def test_every_verdict_appears_even_at_zero(self):
        """A reader can tell "no failures" from "failures not reported"."""
        rep = tr.report(reports("pass", "pass"), [], [])
        assert set(rep["job_verdicts"]) == set(tr.JOB_VERDICTS)
        assert rep["job_verdicts"]["fail"] == 0
        assert rep["job_verdicts"]["fake"] == 0

    def test_photo_categories_include_unanalysed(self):
        rep = tr.report([], photos((None, True, False)), [])
        assert set(rep["photo_verdicts"]) == set(tr.PHOTO_VERDICTS)
        assert rep["photo_verdicts"]["unanalysed"] == 1

    def test_an_unknown_verdict_is_surfaced_not_dropped(self):
        """A value the report does not recognise must not vanish silently.

        Dropping it would shrink the denominator and flatter every rate in the
        payload, which is the same failure as omitting a category — just
        arriving by accident rather than by choice.
        """
        rep = tr.report(reports("pass", "wat"), [], [])
        assert rep["job_verdicts"]["unrecognised"] == 1
        assert sum(rep["job_verdicts"].values()) == 2


class TestSmallSamplesRefuseToProduceRates:
    def test_no_percentage_below_the_minimum(self):
        rep = tr.report(reports("pass"), [], [])
        assert rep["sufficient_sample"] is False
        assert rep["job_verdict_rates_pct"] is None
        assert "1" in rep["sample_note"] and str(tr.MIN_SAMPLE) in rep["sample_note"]

    def test_rates_appear_once_the_sample_is_large_enough(self):
        rep = tr.report(reports(*(["pass"] * 30)), [], [])
        assert rep["sufficient_sample"] is True
        assert rep["job_verdict_rates_pct"]["pass"] == 100.0

    def test_rates_are_computed_over_every_category(self):
        rows = reports(*(["pass"] * 27 + ["fail", "fake", "flag"]))
        rep = tr.report(rows, [], [])
        rates = rep["job_verdict_rates_pct"]
        assert rates["pass"] == 90.0
        assert rates["fail"] == rates["fake"] == rates["flag"] == pytest.approx(3.3)
        assert sum(rates.values()) == pytest.approx(100.0, abs=0.2)

    def test_empty_input_is_reported_as_empty_not_as_perfect(self):
        """Zero jobs must never render as a 100% anything."""
        rep = tr.report([], [], [])
        assert rep["sample"]["jobs_closed"] == 0
        assert rep["job_verdict_rates_pct"] is None
        assert rep["sufficient_sample"] is False


class TestFailuresCannotBeBuriedByRetakes:
    def test_superseded_photos_stay_in_the_count(self):
        """The retake path must not double as a way to delete a failure."""
        rows = photos(("fail", True, True), ("pass", True, False))
        rep = tr.report([], rows, [])
        assert rep["photo_verdicts"]["fail"] == 1
        assert rep["photo_verdicts"]["pass"] == 1
        assert rep["sample"]["photos_recorded"] == 2

    def test_superseded_count_is_published_separately(self):
        rows = photos(("fail", True, True), ("pass", True, False))
        rep = tr.report([], rows, [])
        assert rep["sample"]["photos_superseded"] == 1

    def test_a_job_of_all_retakes_does_not_read_as_clean(self):
        rows = photos(*[("fail", True, True)] * 5, ("pass", True, False))
        rep = tr.report([], rows, [])
        assert rep["photo_verdicts"]["fail"] == 5


class TestIntegrityAndAttestationAreReported:
    def test_integrity_flags_are_counted_from_the_custody_log(self):
        events = [{"event_type": "integrity_flag"}, {"event_type": "uploaded"},
                  {"event_type": "integrity_flag"}]
        rep = tr.report([], [], events)
        assert rep["integrity_flags"] == 2

    def test_exif_presence_is_split_both_ways(self):
        rows = photos(("pass", True, False), ("pass", False, False))
        rep = tr.report([], rows, [])
        assert rep["exif"]["present"] == 1
        assert rep["exif"]["absent"] == 1

    def test_attestation_reports_zero_rather_than_omitting_itself(self):
        """Every upload today is unattested. The report says so out loud.

        Leaving the section out would let a reader assume attestation is
        working and simply not broken out.
        """
        rep = tr.report([], photos(("pass", True, False)), [])
        assert rep["attestation"]["hardware_attested"] == 0
        assert "native app" in rep["attestation"]["note"].lower()


class TestTheReportStatesItsOwnLimits:
    def test_limits_are_never_empty(self):
        assert tr.report([], [], [])["limits"]

    def test_limits_disclose_that_we_computed_them_ourselves(self):
        text = " ".join(tr.report([], [], [])["limits"]).lower()
        assert "not" in text and "audit" in text

    def test_method_names_the_source_tables(self):
        method = tr.report([], [], [])["method"].lower()
        for table in ("shield_completion_reports", "shield_photos",
                      "shield_custody_log"):
            assert table in method


class TestNothingIdentifyingLeaks:
    ID_KEYS = ("shield_job_id", "contractor_id", "homeowner_id", "point_id",
               "site_address", "gps_lat", "gps_lng", "external_ref")

    def test_no_row_identifiers_in_the_payload(self):
        rep = tr.report(reports("pass", "fail"),
                        photos(("pass", True, False)),
                        [{"event_type": "integrity_flag"}])
        blob = json.dumps(rep)
        for key in self.ID_KEYS:
            assert key not in blob
        assert not re.search(r'"[cjhp]\d+"', blob), "a row id reached the payload"

    def test_payload_is_json_serialisable(self):
        json.loads(json.dumps(tr.report(reports("pass"), photos(("pass", True, False)), [])))

    def test_generated_at_is_present_and_utc(self):
        rep = tr.report([], [], [])
        assert rep["generated_at"].endswith("+00:00") or rep["generated_at"].endswith("Z")
