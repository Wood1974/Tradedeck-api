"""Contemporaneous field notes — the thing that makes a photograph mean something.

Why notes matter more than the photograph
-----------------------------------------
A photograph shows a state. It does not show what the light was like, what the
inspector said, which of three subs did the work, that the slab was poured in
the rain, or that the homeowner stood there and approved the change. Those are
the facts disputes actually turn on, and only the person on site can record
them.

They also travel differently in court. A photograph is authenticated and then
speaks for itself. A note is hearsay — an out-of-court statement offered for
its truth — and needs an exception to come in at all. Three apply, and which
one you get depends almost entirely on **when the note was written**:

  FRE 803(1), present sense impression — a statement describing or explaining
  an event, made while or immediately after perceiving it. The permissible gap
  is seconds to minutes, and probably not hours. It is the strongest of the
  three because it does not depend on the writer being available to testify:
  contemporaneity itself is what negates the likelihood of deliberate
  misrepresentation. Crucially, the rule reaches **descriptions and
  explanations only** — opinions, inferences and conclusions are not present
  sense impressions.

  FRE 803(5), recorded recollection — made while the matter was fresh in the
  writer's memory. Requires the witness, and requires that they no longer
  recall well enough to testify fully. Read into evidence; not received as an
  exhibit.

  FRE 803(6), business records — made at or near the time, in the course of a
  regularly conducted activity, where making the record was a **regular
  practice**.

That last phrase is the one with product consequences. A note written on some
jobs and not others is not a regular practice. A system that prompts for a note
on every checkpoint, every time, and records whether one was written, is what
establishes the practice. The discipline is the evidence.

Three design decisions follow, and each is a refusal
----------------------------------------------------
1. **The model never writes or rewrites a note.** Not to tidy it, not to expand
   it, not to "make it more professional." A note is the writer's own words or
   it is contaminated — and a note the writer cannot swear to on the stand is
   worth less than no note. Guidance here is deterministic text analysis that
   tells the author what a reader will find thin. They decide.

2. **Notes are append-only.** An editable note is worthless: the first question
   on cross is whether it says what it said at the time. Corrections are
   amendments — both versions kept, both timestamped, both in the chain. A
   visible correction is credible; a silent one destroys the whole record.

3. **The delay is recorded and reported, not hidden.** A note written four
   hours later is still useful under 803(6). Presenting it as though it were
   contemporaneous is what gets an exhibit excluded and a witness impeached.
"""
import re
from datetime import datetime, timedelta, timezone

# 803(1) turns on "substantial contemporaneity". The case law tolerates
# seconds to minutes and grows hostile at hours, so the boundaries below are
# deliberately conservative — the cost of understating a note's standing is
# nothing, and the cost of overstating it is an excluded exhibit.
IMMEDIATE = timedelta(minutes=5)
PROMPT    = timedelta(minutes=30)
SAME_HOUR = timedelta(hours=2)
SAME_DAY  = timedelta(hours=18)

MEDIA = ("typed", "dictated", "photographed_handwritten")


def _aware(dt):
    """Parse to an aware datetime, or None. Never guesses a zone."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt if dt.tzinfo else None
    try:
        parsed = datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else None


def classify_contemporaneity(observed_at, written_at) -> dict:
    """How close to the event the note was written, and what that buys.

    `observed_at` is when the thing described happened — the photo's capture
    time where there is one, falling back to when the server received it.
    """
    observed, written = _aware(observed_at), _aware(written_at)
    if observed is None or written is None:
        return {
            "band": "unknown", "delay_seconds": None, "delay_human": "unknown",
            "strongest_exception": None,
            "note": "The time of the observation could not be established, so "
                    "the note's contemporaneity cannot be characterised.",
        }

    delta = written - observed
    secs = delta.total_seconds()

    if secs < -60:
        band, rule = "before_observation", None
        note = ("Written before the observation it describes. This is a "
                "sequencing problem, not a note: it cannot describe something "
                "that had not happened.")
    elif delta <= IMMEDIATE:
        band, rule = "immediate", "FRE 803(1)"
        note = ("Written while or immediately after the observation. This is "
                "the window a present sense impression contemplates.")
    elif delta <= PROMPT:
        band, rule = "prompt", "FRE 803(1)"
        note = ("Written shortly after the observation. Within the range "
                "courts have accepted as a present sense impression, though "
                "further from the event than the strongest cases.")
    elif delta <= SAME_HOUR:
        band, rule = "delayed", "FRE 803(5) / 803(6)"
        note = ("Written a couple of hours after the observation. Likely past "
                "what a present sense impression will carry; the matter was "
                "plausibly still fresh in memory.")
    elif delta <= SAME_DAY:
        band, rule = "same_day", "FRE 803(6)"
        note = ("Written the same day. Consistent with a record made at or "
                "near the time, in the course of a regularly kept practice.")
    else:
        band, rule = "reconstructed", None
        note = ("Written more than a day after the observation. This is "
                "recollection, not contemporaneous record. It may still be "
                "useful; it should not be presented as a field note.")

    return {"band": band, "delay_seconds": int(secs),
            "delay_human": _humanise(secs), "strongest_exception": rule,
            "note": note}


def _humanise(seconds):
    s = abs(int(seconds))
    sign = "before the observation" if seconds < 0 else "after the observation"
    if s < 90:
        return f"{s} seconds {sign}"
    if s < 5400:
        return f"{round(s / 60)} minutes {sign}"
    if s < 172800:
        return f"{round(s / 3600, 1)} hours {sign}"
    return f"{round(s / 86400, 1)} days {sign}"


# ---------------------------------------------------------------------------
# Quality guidance — deterministic, advisory, never blocking
# ---------------------------------------------------------------------------

# Conclusions dressed as observations. 803(1) reaches descriptions and
# explanations; it does not reach opinions or inferences, so a note built
# entirely from these words has nothing a present sense impression can carry.
CONCLUSORY = (
    "looks good", "looks fine", "looks right", "looks ok", "looks okay",
    "seems fine", "seems ok", "seems good", "seems right", "appears fine",
    "all good", "all fine", "no issues", "no problems", "everything fine",
    "everything ok", "to code", "up to code", "code compliant", "compliant",
    "proper", "properly", "correctly", "done right", "as required", "as needed",
    "satisfactory", "acceptable", "good to go", "nothing to report",
)

HEDGES = ("i think", "i believe", "probably", "should be", "must have",
          "presumably", "i assume", "pretty sure", "more or less", "roughly")

# Signals that a note contains something a reader can check.
MEASUREMENT = re.compile(
    r"""(\d+\s*(?:'|"|ft|feet|foot|in\b|inch|inches|mm|cm|m\b|metre|meter
        |lb|lbs|psi|deg|°|f\b|c\b|gauge|ga\b|oc\b|o\.c\.|percent|%))""",
    re.I | re.X)
FRACTION   = re.compile(r"\d+\s*[-/]\s*\d+\s*(?:'|\"|in\b|inch)", re.I)
QUANTITY   = re.compile(r"\b\d+\s*(?:bolts?|studs?|joists?|nails?|screws?|"
                        r"courses?|sheets?|bags?|yards?|rows?|anchors?|"
                        r"hangers?|straps?|pieces?|units?)\b", re.I)
CLOCK      = re.compile(r"\b(?:[01]?\d|2[0-3])[:.][0-5]\d\s*(?:am|pm)?\b", re.I)
QUOTED     = re.compile(r"[\"“'‘].{6,}?[\"”'’]")
PROPER_N   = re.compile(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?\b")


def assess_quality(text: str) -> dict:
    """What a reader will find thin. Advisory only — never blocks a save.

    A contractor on a roof in the wind must be able to write a note and move
    on. Guidance that refuses to save is guidance that stops the note being
    written at all, and no note is the worst outcome available.
    """
    body = (text or "").strip()
    words = body.split()
    lower = body.lower()

    specifics, missing, cautions = [], [], []

    if MEASUREMENT.search(body) or FRACTION.search(body):
        specifics.append("measurement with units")
    if QUANTITY.search(body):
        specifics.append("a counted quantity")
    if CLOCK.search(body):
        specifics.append("a time of day")
    if QUOTED.search(body):
        specifics.append("something someone said, quoted")
    named = [m for m in PROPER_N.findall(body) if m.lower() not in ("i", "the")]
    if named:
        specifics.append("a named person, product or place")

    found = [p for p in CONCLUSORY if p in lower]
    if found:
        cautions.append(
            f"“{found[0]}” is a conclusion, not an observation. A present "
            f"sense impression covers what you saw, not what you inferred from "
            f"it — and a reader cannot check a conclusion. What did you "
            f"actually see that led you there?")

    hedged = [h for h in HEDGES if h in lower]
    if hedged:
        cautions.append(
            f"“{hedged[0]}” signals uncertainty about your own observation. If "
            f"you are unsure, say what you are sure of and what you are not — "
            f"that reads as careful. Hedging a fact you witnessed reads as "
            f"unreliable.")

    if len(words) < 5:
        missing.append("Too short to describe anything. A reader eighteen "
                       "months from now has only these words.")
    if not specifics:
        missing.append("Nothing here can be checked against the photograph — "
                       "no measurement, count, time, name or quotation.")
    if len(words) >= 5 and not MEASUREMENT.search(body) and not QUANTITY.search(body):
        missing.append("No numbers. Dimensions, spacings and counts are what "
                       "make a note corroborate a photograph rather than "
                       "restate it.")

    score = min(100, 20 * len(specifics) + (20 if len(words) >= 15 else 0)
                - 15 * len(found) - 10 * len(hedged))
    score = max(0, score)

    return {
        "word_count": len(words),
        "specifics_found": specifics,
        "suggestions": missing,
        "cautions": cautions,
        "strength": ("strong" if score >= 70 else
                     "adequate" if score >= 40 else "thin"),
        "strength_score": score,
        "blocking": False,      # always. see the docstring.
    }


# Prompts shown beside the field. A blank box gets "done" typed into it; a
# prompted box gets facts. Kept short because they are read on a phone, in
# gloves, in sunlight.
PROMPTS = (
    "What did you measure, and what did it read?",
    "Who was on site, and what did they say?",
    "What were the conditions — weather, temperature, light?",
    "What did you have to do differently from the plan, and why?",
    "What is in the frame that a stranger would not recognise?",
)


def prompts_for(checkpoint=None) -> list:
    """Prompts, with the checkpoint's own must-show requirement first."""
    must_show = (checkpoint or {}).get("must_show")
    if must_show:
        return [f"This checkpoint requires: {must_show} — what did you observe?",
                *PROMPTS[:3]]
    return list(PROMPTS[:4])


# ---------------------------------------------------------------------------
# Amendments
# ---------------------------------------------------------------------------
def build_amendment(original: dict, new_text: str, *, reason: str,
                    author_id: str, written_at: str) -> dict:
    """A correction that keeps the original.

    Overwriting is the failure mode this exists to prevent. A note whose
    history is visible survives cross-examination; a note that was silently
    changed takes the rest of the record down with it.
    """
    return {
        "shield_job_id": original["shield_job_id"],
        "photo_id":      original.get("photo_id"),
        "point_id":      original.get("point_id"),
        "author_id":     author_id,
        "body":          new_text,
        "medium":        original.get("medium", "typed"),
        "amends_note_id": original["id"],
        "amendment_reason": reason,
        "observed_at":   original.get("observed_at"),
        "written_at":    written_at,
    }


def thread_of(note: dict, amendments: list) -> dict:
    """One note plus its corrections, oldest first, for the export."""
    chain = sorted(amendments, key=lambda a: a.get("written_at") or "")
    return {
        "note_id":   note["id"],
        "original":  {"body": note.get("body"),
                      "written_at": note.get("written_at"),
                      "author_id": note.get("author_id")},
        "amendments": [{"body": a.get("body"),
                        "reason": a.get("amendment_reason"),
                        "written_at": a.get("written_at"),
                        "author_id": a.get("author_id")} for a in chain],
        "current_body": chain[-1]["body"] if chain else note.get("body"),
        "was_amended": bool(chain),
    }
