"""Completion grading.

Extracted from routes.py because the original was quietly wrong in a way that
inverted the product's meaning, and grading logic that decides whether someone
gets paid deserves to be unit-testable on its own.

The bug it replaces
-------------------
    verdicts = [p.get("ai_verdict") for p in points if p.get("ai_verdict")]
    if not verdicts: return "flag"
    ...
    return "pass"

Checkpoints that were never photographed were filtered out before the vote, so
they could not contribute a failure. One passing photo out of five checkpoints
returned **"pass"** — on a job where eighty percent of the evidence was never
produced. The score said 20.0 and the verdict said pass, and it is the verdict
a homeowner reads.

Missing evidence is not neutral. In a record whose entire purpose is to show
the work was done, an absent checkpoint is the most informative thing in the
file.

Grading model
-------------
Rather than a single word doing too much work, completion carries a verdict, a
score, and a coverage figure — because "4 of 5 checkpoints verified, all
passing" and "5 of 5 verified, one failing" are different outcomes that a
single label cannot distinguish.
"""

# Severity order, worst first. A job is as good as its worst verified
# checkpoint — one faked photo is not averaged away by four honest ones.
SEVERITY = ("fake", "fail", "flag", "pass")

SCORE_WEIGHTS = {
    "pass": 100,
    "flag": 60,
    "fail": 0,
    "fake": 0,
    None:   0,      # never photographed, or photographed and never analysed
}


def _verdict_of(point):
    """A checkpoint's verdict, or None when no live analysed photo backs it."""
    photo = point.get("photo") or {}
    if photo.get("superseded_by"):
        return None
    return photo.get("ai_verdict")


def grade(points) -> dict:
    """Grade a completed job from its checkpoint rows.

    `points` are checkpoint dicts, each optionally carrying a `photo` dict with
    `ai_verdict`. Returns the full grading record rather than a bare label.
    """
    total = len(points)
    if total == 0:
        return {
            "verdict": "incomplete", "score": 0.0,
            "checkpoints_total": 0, "checkpoints_verified": 0,
            "coverage_pct": 0.0, "missing": [], "failing": [],
            "summary": "No checkpoints were defined for this job.",
        }

    verdicts = [_verdict_of(p) for p in points]
    missing = [p.get("label") or f"checkpoint {p.get('point_number', '?')}"
               for p, v in zip(points, verdicts) if v is None]
    failing = [p.get("label") or f"checkpoint {p.get('point_number', '?')}"
               for p, v in zip(points, verdicts) if v in ("fail", "fake")]

    verified = total - len(missing)
    coverage = round(100.0 * verified / total, 1)
    score = round(sum(SCORE_WEIGHTS.get(v, 0) for v in verdicts) / total, 1)

    # Incomplete evidence outranks every verdict: a job that was not fully
    # documented cannot be reported as passing, however good the photos that
    # do exist. This is the inversion the old implementation had backwards.
    if missing:
        verdict = "incomplete"
    else:
        present = [v for v in verdicts if v is not None]
        verdict = next(v for v in SEVERITY if v in present)

    return {
        "verdict": verdict,
        "score": score,
        "checkpoints_total": total,
        "checkpoints_verified": verified,
        "coverage_pct": coverage,
        "missing": missing,
        "failing": failing,
        "summary": _summarise(verdict, verified, total, missing, failing),
    }


def _summarise(verdict, verified, total, missing, failing):
    if verdict == "incomplete":
        names = ", ".join(missing[:3]) + ("…" if len(missing) > 3 else "")
        return (f"Incomplete: {verified} of {total} checkpoints verified. "
                f"No accepted photo for: {names}.")
    if verdict == "fake":
        return (f"All {total} checkpoints documented, but at least one photo "
                f"could not be accepted as a genuine capture: {', '.join(failing[:3])}.")
    if verdict == "fail":
        return (f"All {total} checkpoints documented. Work did not meet the "
                f"cited requirement at: {', '.join(failing[:3])}.")
    if verdict == "flag":
        return (f"All {total} checkpoints documented. Some need review before "
                f"sign-off.")
    return f"All {total} checkpoints documented and verified against the cited code."


def is_complete_enough(points) -> bool:
    """Whether a job may be closed out at all.

    Closing a job mints a signed packet and counts toward a contractor's
    verified badge, so it requires a live analysed photo on every checkpoint.
    Without this a contractor could photograph one checkpoint, close out, and
    repeat until the badge threshold was met.
    """
    return bool(points) and all(_verdict_of(p) is not None for p in points)


def counts_toward_badge(grade_result) -> bool:
    """Only a fully documented, fully passing job builds contractor standing."""
    return (grade_result["verdict"] == "pass"
            and grade_result["coverage_pct"] == 100.0)
