"""The public outcome report — our own numbers, including the bad ones.

Why this exists
---------------
Publishing a method is cheap. `SPEC.md` describes how a record is sealed and
`verifier/` lets a recipient check one, but neither says anything about how
often this system actually says no. A buyer's risk team does not ask how the
hash chain works. It asks what the failure rate is, and whether the number was
produced by someone with an interest in it being low.

We cannot fix the second half — these are our numbers about our own product.
What we can do is publish them in a shape that cannot be tuned, and say plainly
that they are unaudited.

The three ways a self-published statistic flatters its author
-------------------------------------------------------------
Each is closed here by construction rather than by policy, because a policy is
a thing a future release can quietly stop following.

**Omitting the bad categories.** `JOB_VERDICTS` and `PHOTO_VERDICTS` are fixed
tuples and every one of them appears in every report, at zero if that is the
count. A reader can then distinguish "no failures occurred" from "failures were
not reported" — which a payload listing only the categories that happened to be
non-empty does not allow. A verdict we do not recognise lands in
`unrecognised` rather than being dropped, because dropping it would shrink the
denominator and improve every rate in the payload by accident.

**Quoting a rate the sample cannot carry.** "100% pass rate" over one job is
arithmetically true and completely worthless, and it is the sentence most
likely to end up on a landing page. Below `MIN_SAMPLE` the rate fields are
`None` and `sample_note` says why. This is the same discipline the claims
ledger applies to language: a number that would not survive a risk team's first
question does not get published in a form that invites the question.

**Losing failures through the retake door.** A photo that failed and was
retaken is superseded, not deleted — `verdict.is_live()` exists precisely so
the live one is the evidence. Counting only live photos here would drop every
failure that was ever corrected and produce a flattering number from
innocent-looking code. Superseded photos stay in both the numerator and the
denominator; `photos_superseded` is published beside the total so the reader
can see how much of the history involved a second attempt.

Privacy
-------
This is served to anonymous callers. The report is aggregate only: it takes
rows in and emits counts out, and no job id, user id, address or coordinate
appears in the payload. `test_transparency.py` asserts that by scanning the
serialised output for identifiers rather than trusting this paragraph.
"""
from datetime import datetime, timezone

# Fixed category lists. Every one appears in every report, at zero if need be.
JOB_VERDICTS = ("pass", "flag", "fail", "fake", "unrecognised")
PHOTO_VERDICTS = ("pass", "flag", "fail", "fake", "unanalysed", "unrecognised")

# Below this, no percentage is published. Thirty is not a magic number — it is
# the point at which a single outcome stops moving the headline rate by more
# than a few points. State it rather than hiding it, so a reader can disagree.
MIN_SAMPLE = 30

SCHEMA = "tradedeck.shield.transparency.v1"

METHOD = (
    "Counts are exact count(*) over three tables: shield_completion_reports "
    "(one row per closed-out job, carrying overall_verdict), shield_photos "
    "(every photo ever recorded, including superseded retakes), and "
    "shield_custody_log (append-only event history, filtered to "
    "integrity_flag events). No row is excluded by any filter other than the "
    "ones named here."
)

LIMITS = (
    "These are our own numbers about our own product. They are computed by "
    "the same party that issues the records and they are not audited by "
    "anyone else. Treat them as a disclosure, not as an attestation.",
    "A verdict reflects what our analysis concluded, not ground truth. We do "
    "not know how many photographs were accepted that should not have been — "
    "that figure would require an independent review of the underlying work "
    "and it does not exist.",
    "Rebroadcast thresholds are calibrated on synthetic scenes only. No "
    "false-positive or false-negative rate has been measured against real "
    "phones, real displays or real jobsites, so none is published here.",
    "No photograph in this dataset carries hardware attestation. Nothing in "
    "these numbers establishes that any image came from a camera.",
)

ATTESTATION_NOTE = (
    "Zero, and not because captures are failing attestation. Apple App Attest "
    "and Google Play Integrity both require a native app; both TradeDeck "
    "front ends are web pages, so every upload is recorded as unattested. "
    "This line reports zero rather than being omitted so it cannot be read as "
    "attestation quietly working."
)


def _is_superseded(photo) -> bool:
    """Mirrors verdict.is_live(), inverted, without importing the grader.

    Kept local on purpose. This module must count what the database holds, and
    a future change to how the grader picks live evidence should not silently
    change what the public statistics include.
    """
    return bool(photo.get("superseded_by") or photo.get("superseded_at"))


def _tally(values, categories, *, none_bucket=None):
    """Count `values` into `categories`, with every category present.

    Anything unrecognised lands in 'unrecognised' rather than disappearing.
    """
    counts = {name: 0 for name in categories}
    for value in values:
        if value is None and none_bucket:
            counts[none_bucket] += 1
        elif value in counts and value != "unrecognised":
            counts[value] += 1
        else:
            counts["unrecognised"] += 1
    return counts


def _rates(counts, total):
    """Percentages, or None when the sample is too small to carry one."""
    if total < MIN_SAMPLE or total == 0:
        return None
    return {name: round(100.0 * n / total, 1) for name, n in counts.items()}


def report(completion_reports, photos, custody_events, *, generated_at=None) -> dict:
    """Build the public outcome report from raw rows.

    Pure: rows in, counts out, no database and no network. That keeps it
    testable without a provisioned environment — the same reason the invariants
    read source rather than exercising routes.
    """
    jobs_total = len(completion_reports)
    photos_total = len(photos)

    job_counts = _tally((r.get("overall_verdict") for r in completion_reports),
                        JOB_VERDICTS)
    photo_counts = _tally((p.get("ai_verdict") for p in photos),
                          PHOTO_VERDICTS, none_bucket="unanalysed")

    superseded = sum(1 for p in photos if _is_superseded(p))
    flags = sum(1 for e in custody_events
                if e.get("event_type") == "integrity_flag")

    with_exif = sum(1 for p in photos if p.get("has_exif"))

    sufficient = jobs_total >= MIN_SAMPLE
    note = (f"{jobs_total} closed job(s) on record. Rates are withheld below "
            f"{MIN_SAMPLE} because a percentage over a sample this size would "
            f"move by tens of points on a single outcome.")
    if sufficient:
        note = (f"{jobs_total} closed job(s) on record, at or above the "
                f"{MIN_SAMPLE}-job minimum, so rates are published.")

    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat()
                        if generated_at is None else generated_at,
        "sample": {
            "jobs_closed": jobs_total,
            "photos_recorded": photos_total,
            "photos_superseded": superseded,
            "custody_events": len(custody_events),
        },
        "sufficient_sample": sufficient,
        "minimum_sample": MIN_SAMPLE,
        "sample_note": note,
        "job_verdicts": job_counts,
        "job_verdict_rates_pct": _rates(job_counts, jobs_total),
        "photo_verdicts": photo_counts,
        "photo_verdict_rates_pct": _rates(photo_counts, photos_total),
        "exif": {"present": with_exif, "absent": photos_total - with_exif},
        "integrity_flags": flags,
        "attestation": {"hardware_attested": 0, "note": ATTESTATION_NOTE},
        "method": METHOD,
        "limits": list(LIMITS),
    }
