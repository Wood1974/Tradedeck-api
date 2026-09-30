"""How to build a record that survives a hostile reading.

The problem with documentation
------------------------------
Every practice below raises the evidentiary strength of a Shield record. None
of them helps if it lives in a README. A contractor on a roof does not read
documentation; a homeowner buying Shield for the first time does not know what
a present sense impression is and should not have to.

So the guidance is computed against the job as it actually stands, and the
service hands it back at the moment it can still be acted on. "Write the note
now" is useful at minute two and worthless at hour six.

What actually moves the needle, in order
----------------------------------------
These are ranked by how much they change what the record can withstand, not by
how much work they are. The first four cost seconds and matter enormously; the
last few are habits.

  1. Set the site location when you buy. It is the only geographic reference
     the audited party cannot move. Without it there is nothing to geofence
     against and a photo from another city satisfies every check.

  2. Lock the checkpoints before work starts. A schedule fixed afterwards is
     a schedule chosen to fit the photographs. This is the single strongest
     structural property of the record and it is free.

  3. Photograph at the moment, not at the end of the day. The capture time in
     the file is what the solar check and the note window are measured from.

  4. Write the note within five minutes. This is the FRE 803(1) window — a
     present sense impression is admissible *without the writer testifying*,
     because contemporaneity itself is what makes deliberate misrepresentation
     unlikely. At six hours you are relying on a different, weaker rule.

  5. Write what you saw, not what you concluded. 803(1) reaches descriptions
     and explanations and explicitly not opinions. "Looks good, all to code"
     is inadmissible under it *and* uncheckable by a reader. "5'2" between
     bolts, 14 bolts, tape in frame" is both.

  6. Do it on every checkpoint, every time. FRE 803(6) requires that making
     the record was a *regular practice*. Notes on some checkpoints and not
     others is not one — and the gaps are the first thing an opposing expert
     will point at.

  7. Export the package early and keep the chain head. A head hash you were
     given last month is what proves the history you were shown has not been
     rewritten since — including by us. This is the one practice that protects
     you against the operator, and almost nobody thinks to do it.

  8. Correct by amendment, never by rewriting. A visible correction reads as
     careful. A silent one, once discovered, discredits the entire record.
"""
from datetime import datetime, timedelta, timezone

import notes as field_notes

# Each practice: what to do, why it matters, and what it costs you to skip.
PRACTICES = (
    {
        "id": "site_location",
        "stage": "at purchase",
        "do": "Set the job site address and coordinates when you buy Shield.",
        "why": "It is the only geographic reference the contractor cannot move. "
               "Every later photo is measured against it.",
        "if_skipped": "There is nothing to geofence against. A photo taken in "
                      "another city passes every location check.",
        "who": "homeowner",
    },
    {
        "id": "lock_before_work",
        "stage": "before work starts",
        "do": "Generate and lock the checkpoint schedule before the contractor "
              "begins.",
        "why": "Requirements fixed in advance cannot have been chosen to fit the "
               "photographs. This is the strongest structural property of the "
               "record, and it costs nothing.",
        "if_skipped": "An opposing party will argue the criteria were written "
                      "around the evidence. It is a difficult argument to answer.",
        "who": "homeowner",
    },
    {
        "id": "shoot_in_the_moment",
        "stage": "at each checkpoint",
        "do": "Take the photo while the work is in front of you, not from memory "
              "at the end of the day.",
        "why": "The capture time in the file is what the solar check and the note "
               "window are both measured from.",
        "if_skipped": "Shadow geometry stops corroborating, and every note is "
                      "pushed into a weaker hearsay exception.",
        "who": "contractor",
    },
    {
        "id": "note_within_five",
        "stage": "at each checkpoint",
        "do": "Write the note within five minutes of the photo.",
        "why": "FRE 803(1) — a present sense impression is admissible without "
               "the writer testifying, because contemporaneity is what makes "
               "deliberate misrepresentation unlikely.",
        "if_skipped": "After roughly half an hour you are relying on recorded "
                      "recollection or the business-records rule instead, both "
                      "of which need you available and credible.",
        "who": "contractor",
    },
    {
        "id": "observe_dont_conclude",
        "stage": "at each checkpoint",
        "do": "Record what you saw and measured. Leave conclusions out.",
        "why": "803(1) covers descriptions and explanations, not opinions — so a "
               "conclusion is inadmissible under it and uncheckable by a reader.",
        "if_skipped": "\"Looks good, all to code\" carries no weight and invites "
                      "the question of what you actually observed.",
        "who": "contractor",
    },
    {
        "id": "every_time",
        "stage": "throughout",
        "do": "Photograph and annotate every checkpoint, including the boring ones.",
        "why": "FRE 803(6) requires that making the record was a regular practice. "
               "Consistency is the qualification.",
        "if_skipped": "Gaps are the first thing an opposing expert points at, and "
                      "a partial record invites the inference that the missing "
                      "ones were unfavourable.",
        "who": "contractor",
    },
    {
        "id": "export_and_keep_the_head",
        "stage": "periodically, and at close-out",
        "do": "Export the evidence package and keep the chain head hash somewhere "
              "outside this service — an email to yourself is enough.",
        "why": "A head hash you held last month proves the history you were shown "
               "has not been rewritten since, including by us.",
        "if_skipped": "You are trusting the operator's copy of the record. That "
                      "is precisely the assumption a dispute will test.",
        "who": "homeowner",
    },
    {
        "id": "amend_never_rewrite",
        "stage": "when you get something wrong",
        "do": "Correct a note by amending it, and say why.",
        "why": "A visible correction reads as careful. Notes here cannot be "
               "edited, so this is the only route — and it is the better one.",
        "if_skipped": "Nothing: the system will not let you rewrite. But asking "
                      "for an edit signals a misunderstanding worth correcting.",
        "who": "contractor",
    },
)

NOTE_WINDOW = timedelta(minutes=5)


def _aware(ts):
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else None
    try:
        p = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return p if p.tzinfo else None


def assess_record(*, job, points, photos, notes, now=None) -> dict:
    """Grade the record as it stands, and say exactly what would strengthen it.

    Deliberately not a score out of ten. Each finding names the practice, what
    is currently true, and what it costs — because a number tells a homeowner
    nothing about what to do next.
    """
    now = _aware(now) or datetime.now(timezone.utc)
    live = [p for p in photos if not p.get("superseded_by")]
    threads = [n for n in notes if not n.get("amends_note_id")]
    by_photo = {n["photo_id"]: n for n in threads if n.get("photo_id")}

    strengths, gaps = [], []

    # 1. site location
    if job.get("site_lat") is not None:
        strengths.append({
            "practice": "site_location",
            "state": f"Photos are geofenced against the job site "
                     f"(±{job.get('site_radius_m') or 250} m).",
        })
    else:
        gaps.append({
            "practice": "site_location", "severity": "high",
            "state": "No site location was set, so no photo can be placed.",
            "fix": "Set it on the job. Photos taken from now on will be measured "
                   "against it; earlier ones cannot be retrofitted.",
        })

    # 2. schedule locked, and locked before the photos
    locked = _aware(job.get("checkpoints_locked_at"))
    if locked:
        first_shot = min((_aware(p.get("exif_captured_at") or p.get("server_received_at"))
                          for p in live), default=None)
        if first_shot and first_shot < locked:
            gaps.append({
                "practice": "lock_before_work", "severity": "high",
                "state": "Photographs predate the checkpoint schedule.",
                "fix": "Nothing can change this now. Expect the argument that the "
                       "requirements were written around the evidence, and be "
                       "ready to explain the sequence.",
            })
        else:
            strengths.append({
                "practice": "lock_before_work",
                "state": "The checkpoint schedule was fixed before any photograph "
                         "was taken.",
            })
    else:
        gaps.append({
            "practice": "lock_before_work", "severity": "high",
            "state": "The checkpoint schedule has not been locked.",
            "fix": "Lock it before work begins. Afterwards it is a schedule that "
                   "could have been chosen to fit the photographs.",
        })

    # 6. coverage
    documented = {p.get("point_id") for p in live}
    missing = [pt for pt in points if pt["id"] not in documented]
    if points and not missing:
        strengths.append({
            "practice": "every_time",
            "state": f"All {len(points)} checkpoints are documented.",
        })
    elif missing:
        gaps.append({
            "practice": "every_time", "severity": "high",
            "state": f"{len(missing)} of {len(points)} checkpoints have no photo: "
                     + ", ".join(m.get("label", "?") for m in missing[:3])
                     + ("…" if len(missing) > 3 else ""),
            "fix": "Photograph them before the stage is covered up. A checkpoint "
                   "missed is usually missed permanently.",
        })

    # 4/5. notes: coverage, timing, quality
    annotated = [p for p in live if p["id"] in by_photo]
    unannotated = [p for p in live if p["id"] not in by_photo]
    if live and not unannotated:
        strengths.append({
            "practice": "every_time",
            "state": f"Every photograph carries a field note.",
        })
    elif unannotated:
        gaps.append({
            "practice": "note_within_five",
            "severity": "high" if len(unannotated) == len(live) else "medium",
            "state": f"{len(unannotated)} of {len(live)} photographs have no note.",
            "fix": "Add one now for anything recent. A note minutes old is worth "
                   "far more than one written next week, and an unannotated photo "
                   "shows a state without explaining it.",
        })

    prompt_notes, late_notes, thin_notes = [], [], []
    for n in threads:
        timing = field_notes.classify_contemporaneity(n.get("observed_at"),
                                                      n.get("written_at"))
        (prompt_notes if timing["band"] in ("immediate", "prompt")
         else late_notes).append(n)
        if n.get("strength") == "thin":
            thin_notes.append(n)

    if threads and len(prompt_notes) == len(threads):
        strengths.append({
            "practice": "note_within_five",
            "state": f"All {len(threads)} notes were written promptly enough to "
                     f"qualify as present sense impressions (FRE 803(1)).",
        })
    elif late_notes:
        gaps.append({
            "practice": "note_within_five", "severity": "medium",
            "state": f"{len(late_notes)} note(s) were written too long after the "
                     f"observation to carry FRE 803(1).",
            "fix": "They still stand as business records. For future checkpoints, "
                   "write while you are still standing there.",
        })

    if thin_notes:
        gaps.append({
            "practice": "observe_dont_conclude", "severity": "medium",
            "state": f"{len(thin_notes)} note(s) contain nothing a reader can "
                     f"check — no measurement, count, time, name or quotation.",
            "fix": "You cannot edit them, but you can amend: add the measurement "
                   "you took, or write a fuller note on the next checkpoint.",
        })

    # 7. has the record ever left the building?
    # (Caller supplies this from the custody log; absent means never exported.)
    return {
        "assessed_at": now.isoformat(),
        "strengths": strengths,
        "gaps": sorted(gaps, key=lambda g: {"high": 0, "medium": 1, "low": 2}[g["severity"]]),
        "posture": _posture(strengths, gaps),
        "next_action": gaps[0]["fix"] if gaps else
                       "Export the package and keep the chain head hash somewhere "
                       "outside this service.",
    }


def _posture(strengths, gaps):
    high = sum(1 for g in gaps if g["severity"] == "high")
    if high >= 2:
        return ("This record has structural gaps. It documents work; it would "
                "not hold up well as evidence in a contested dispute.")
    if high == 1:
        return ("Solid, with one structural gap worth closing before the job "
                "goes further.")
    if gaps:
        return ("Strong. The remaining items are refinements, not weaknesses.")
    return ("Strong on every practice that matters. Export the package and keep "
            "the chain head somewhere outside this service.")


def next_step(*, job, points, photos, notes, now=None) -> dict:
    """The single most useful thing to do right now, for an in-app prompt."""
    a = assess_record(job=job, points=points, photos=photos, notes=notes, now=now)
    top = a["gaps"][0] if a["gaps"] else None
    practice = next((p for p in PRACTICES if p["id"] == top["practice"]), None) if top else None
    return {
        "action": a["next_action"],
        "because": practice["why"] if practice else
                   "Holding an exported chain head is what proves the record "
                   "was not rewritten later.",
        "severity": top["severity"] if top else "none",
        "for": practice["who"] if practice else "homeowner",
    }


def practices_for(role=None) -> list:
    """The full guide, optionally filtered to one party's responsibilities."""
    if role in ("homeowner", "contractor"):
        return [p for p in PRACTICES if p["who"] == role]
    return list(PRACTICES)
