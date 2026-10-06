"""Decide what a capture may say about its own clock.

Pure function. No clock is read here, no phone is queried, and nothing is
stored. The caller passes the observation taken when the job ticket was
issued and the observation stored on the capture record.

The rules, in the order a single label is chosen
-------------------------------------------------
1. Boot id or boot count changed between the ticket and the photo, or either
   observation is missing a clock reading the comparison needs: the monotonic
   interval does not exist, so the label is UNVERIFIED TIME. A reboot is not
   tampering. The bytes can still be intact.
2. Same boot, and monotonic time on the photo is earlier than monotonic
   time on the ticket: UNVERIFIED TIME. A monotonic clock does not run
   backward across one boot, so there is no interval to judge. Moving the
   wall clock by the same amount does not make that interval reappear.
   This is not a device-clock mismatch and it is not a forgery finding.
3. Same boot, and the wall clock disagrees with "ticket wall time plus
   monotonic elapsed" by more than ``CLOCK_MISMATCH_LIMIT_MS``: DEVICE CLOCK
   MISMATCH. The comparison is absolute, so a clock set backward is the same
   label as a clock set forward. The boundary is strict: 120.000 seconds
   agrees, 120.001 seconds does not. Elapsed here is never negative; that
   case was rule 2.
4. GNSS time present on the photo and more than the same limit away from
   that photo's wall clock: DEVICE CLOCK MISMATCH as well. This applies
   whether or not the boot changed. A measured disagreement is reported
   even when the monotonic interval cannot be checked.
5. No GNSS time: the verdict from the monotonic clock stands, and the
   result says GNSS was absent. A basement, a slab, and an indoor job have
   no sky. Missing GNSS is not a mismatch and not unverified time.

``labels`` lists every label that applies. ``verdict`` is the one to show
when there is only room for one: DEVICE CLOCK MISMATCH if it applies,
otherwise UNVERIFIED TIME, otherwise CONSISTENT. A reboot plus a GNSS
disagreement therefore keeps both labels, and the single verdict is the
mismatch, because that one was measured.

Flags do not enter this function's decision. Screen capture, a debugger,
mock location, and root traces are reported beside the verdict by whoever
displays the record. They must not create a mismatch, clear one, or turn a
reboot into a consistent clock.

The limit is its own constant
-----------------------------
``CLOCK_MISMATCH_LIMIT_MS`` is 120 seconds, expressed in milliseconds so the
boundary is an integer and not a float. The capture-challenge lifetime in
``attestation.py`` is also 120 seconds. That one is how long a nonce may be
spent. This one is how far a device clock may drift from its own monotonic
clock, and from GNSS, before the record is labeled. They are different
knobs. This module does not read the other one.
"""

# 120 seconds, in milliseconds. Not the capture-challenge lifetime.
CLOCK_MISMATCH_LIMIT_MS = 120_000

# Same bound the capture record uses. A JSON number past this is not exact
# in a JavaScript verifier, so it is not a time this function will judge.
JS_SAFE_INT = 2**53 - 1

VERDICT_CONSISTENT = "CONSISTENT"
VERDICT_UNVERIFIED_TIME = "UNVERIFIED TIME"
VERDICT_DEVICE_CLOCK_MISMATCH = "DEVICE CLOCK MISMATCH"

_BOOT_ID = "boot_id"
_BOOT_COUNT = "boot_count"


def _whole(value, key, *, non_negative=False):
    if isinstance(value, float):
        raise ValueError(
            f"{key} is a float; times and counts in this check are whole "
            f"milliseconds")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be a whole number")
    if abs(value) > JS_SAFE_INT:
        raise ValueError(
            f"{key} is outside the range a JSON number can carry exactly")
    if non_negative and value < 0:
        raise ValueError(f"{key} cannot be negative")
    return value


def _optional_int(obs, key, *, non_negative=False):
    if not isinstance(obs, dict):
        raise ValueError("clock observation must be an object")
    if key not in obs or obs[key] is None:
        return None
    return _whole(obs[key], key, non_negative=non_negative)


def _optional_text(obs, key):
    if key not in obs or obs[key] is None:
        return None
    value = obs[key]
    if isinstance(value, float):
        raise ValueError(f"{key} is a float")
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{key} must be a non-empty string when it is present")
    return value


def boot_changed(ticket, capture) -> bool:
    """True when the two observations are not shown to be the same boot.

    Every boot identifier that appears on either side has to appear on both
    and be equal. iOS reports a boot-session id. Android reports a boot
    count. One matching identifier is enough when the other identifier is
    on neither side. One side reporting an identifier the other lacks is a
    change: the monotonic interval would depend on a fact we do not have.

    Neither side reporting any identifier is also a change, in the only
    sense that matters here: the same boot has not been shown, so rule 2
    must not run.
    """
    ticket_id = _optional_text(ticket, _BOOT_ID)
    capture_id = _optional_text(capture, _BOOT_ID)
    ticket_count = _optional_int(ticket, _BOOT_COUNT, non_negative=True)
    capture_count = _optional_int(capture, _BOOT_COUNT, non_negative=True)

    saw = False
    if ticket_id is not None or capture_id is not None:
        saw = True
        if ticket_id is None or capture_id is None or ticket_id != capture_id:
            return True
    if ticket_count is not None or capture_count is not None:
        saw = True
        if (ticket_count is None or capture_count is None
                or ticket_count != capture_count):
            return True
    return not saw


def _gnss(capture, wall):
    """How GNSS time sits against the photo's wall clock.

    Returns ``(status, delta_ms)``. Status is ``absent``, ``agrees``, or
    ``mismatch``. ``delta_ms`` is None when GNSS is absent or there is no
    wall clock to compare it with.
    """
    gnss = _optional_int(capture, "gnss_time_ms")
    if gnss is None:
        return "absent", None
    if wall is None:
        return "uncompared", None
    delta = abs(gnss - wall)
    status = "mismatch" if delta > CLOCK_MISMATCH_LIMIT_MS else "agrees"
    return status, delta


def assess(ticket, capture) -> dict:
    """The time label for one photo against the ticket it was taken under.

    ``ticket`` and ``capture`` both carry ``wall_time_ms`` and
    ``monotonic_ms`` from the phone, plus ``boot_id`` and/or ``boot_count``.
    ``capture`` may also carry ``gnss_time_ms``. Any other key, including
    ``flags`` and ``location_simulated``, is ignored.

    Ticket time is the phone's wall clock when the ticket was issued, not a
    server timestamp. The monotonic elapsed time is only meaningful against
    the same phone clock it was measured on.
    """
    if not isinstance(ticket, dict) or not isinstance(capture, dict):
        raise ValueError("ticket and capture must be objects")

    changed = boot_changed(ticket, capture)
    ticket_wall = _optional_int(ticket, "wall_time_ms")
    capture_wall = _optional_int(capture, "wall_time_ms")
    ticket_mono = _optional_int(ticket, "monotonic_ms", non_negative=True)
    capture_mono = _optional_int(capture, "monotonic_ms", non_negative=True)
    gnss_status, gnss_delta = _gnss(capture, capture_wall)

    monotonic_delta = None
    unverified_reason = None
    mismatch_reason = None

    if changed:
        unverified_reason = (
            "The boot identity changed between the ticket and the photo, "
            "so the monotonic interval cannot be checked.")
    elif (ticket_wall is None or capture_wall is None
          or ticket_mono is None or capture_mono is None):
        unverified_reason = (
            "A wall-clock or monotonic reading is missing, so the monotonic "
            "interval cannot be checked.")
    else:
        elapsed = capture_mono - ticket_mono
        # elapsedRealtime and mach_continuous_time do not run backward on
        # one boot. A negative elapsed means the interval is not a duration,
        # even when the wall clock was moved by the same amount so the
        # absolute formula would otherwise agree. That is unverified time,
        # not a device-clock mismatch and not a forgery finding.
        if elapsed < 0:
            unverified_reason = (
                "The monotonic clock moved backward between the ticket and "
                "the photo, so the monotonic interval cannot be checked.")
        else:
            monotonic_delta = abs(capture_wall - (ticket_wall + elapsed))
            if monotonic_delta > CLOCK_MISMATCH_LIMIT_MS:
                mismatch_reason = (
                    f"The wall clock differs from the ticket time plus monotonic "
                    f"elapsed by {monotonic_delta} ms, which is more than "
                    f"{CLOCK_MISMATCH_LIMIT_MS} ms.")

    gnss_note = None
    if gnss_status == "mismatch":
        gnss_reason = (
            f"GNSS time differs from the wall clock by {gnss_delta} ms, "
            f"which is more than {CLOCK_MISMATCH_LIMIT_MS} ms.")
        mismatch_reason = (f"{mismatch_reason} {gnss_reason}"
                           if mismatch_reason else gnss_reason)
    elif gnss_status == "absent":
        # Only claim the monotonic result when that comparison actually ran.
        # A reboot has no monotonic interval, so "stands on the monotonic
        # clock" would be the wrong sentence there.
        if unverified_reason is None:
            gnss_note = (
                "No GNSS time was present; the time verdict stands on the "
                "monotonic clock.")
        else:
            gnss_note = "No GNSS time was present."
    elif gnss_status == "uncompared":
        gnss_note = (
            "GNSS time was present, but the wall clock was not, so it was "
            "not compared.")
    else:
        gnss_note = (
            f"GNSS time is within {CLOCK_MISMATCH_LIMIT_MS} ms of the "
            f"wall clock.")

    labels = []
    if unverified_reason is not None:
        labels.append(VERDICT_UNVERIFIED_TIME)
    if mismatch_reason is not None:
        labels.append(VERDICT_DEVICE_CLOCK_MISMATCH)

    if VERDICT_DEVICE_CLOCK_MISMATCH in labels:
        verdict = VERDICT_DEVICE_CLOCK_MISMATCH
    elif VERDICT_UNVERIFIED_TIME in labels:
        verdict = VERDICT_UNVERIFIED_TIME
    else:
        verdict = VERDICT_CONSISTENT

    parts = [p for p in (unverified_reason, mismatch_reason) if p]
    if verdict == VERDICT_CONSISTENT:
        parts.append(
            "The boot did not change, and the wall clock is within "
            f"{CLOCK_MISMATCH_LIMIT_MS} ms of the ticket time plus "
            "monotonic elapsed.")
    if gnss_note:
        parts.append(gnss_note)

    return {
        "verdict": verdict,
        "labels": tuple(labels),
        "boot_changed": changed,
        "monotonic_delta_ms": monotonic_delta,
        "gnss": gnss_status,
        "gnss_delta_ms": gnss_delta,
        "detail": " ".join(parts),
    }
