"""Time labels for one capture against the ticket it was taken under.

The boundary is integer milliseconds. 120.000 seconds is 120000 ms and
agrees. 120.001 seconds is 120001 ms and is a device-clock mismatch.
A reboot is a different label from a jump, and neither label moves when
a flag bit is set.
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import attestation  # noqa: E402
import capture_record as cr  # noqa: E402
import time_audit as ta  # noqa: E402

T0 = 1_700_000_000_000
M0 = 10_000
LIMIT = 120_000  # 120.000 seconds


def ticket(**overrides):
    obs = {
        "wall_time_ms": T0,
        "monotonic_ms": M0,
        "boot_count": 7,
        "boot_id": "boot-a",
    }
    obs.update(overrides)
    return obs


def photo(elapsed_ms=60_000, wall_slip_ms=0, **overrides):
    """A photo taken ``elapsed_ms`` of monotonic time after the ticket.

    ``wall_slip_ms`` is how far the wall clock moved *beyond* that elapsed
    time. Zero means the two clocks tell the same story.
    """
    obs = {
        "wall_time_ms": T0 + elapsed_ms + wall_slip_ms,
        "monotonic_ms": M0 + elapsed_ms,
        "boot_count": 7,
        "boot_id": "boot-a",
    }
    obs.update(overrides)
    return obs


ALL_FLAGS = (cr.FLAG_SCREEN_CAPTURED | cr.FLAG_DEBUGGER
             | cr.FLAG_MOCK_LOCATION | cr.FLAG_ROOT_TRACES | (1 << 10))


# ----------------------------------------------------------------- table ---
# name, ticket overrides, photo kwargs, verdict, gnss, monotonic delta
CASES = [
    ("clocks agree", {}, {}, ta.VERDICT_CONSISTENT, "absent", 0),
    ("120.000 s forward", {}, {"wall_slip_ms": LIMIT},
     ta.VERDICT_CONSISTENT, "absent", LIMIT),
    ("120.001 s forward", {}, {"wall_slip_ms": LIMIT + 1},
     ta.VERDICT_DEVICE_CLOCK_MISMATCH, "absent", LIMIT + 1),
    ("120.000 s backward", {}, {"wall_slip_ms": -LIMIT},
     ta.VERDICT_CONSISTENT, "absent", LIMIT),
    ("120.001 s backward", {}, {"wall_slip_ms": -(LIMIT + 1)},
     ta.VERDICT_DEVICE_CLOCK_MISMATCH, "absent", LIMIT + 1),
    ("119.999 s", {}, {"wall_slip_ms": LIMIT - 1},
     ta.VERDICT_CONSISTENT, "absent", LIMIT - 1),
    ("three minute jump", {}, {"wall_slip_ms": 180_000},
     ta.VERDICT_DEVICE_CLOCK_MISMATCH, "absent", 180_000),
    ("reboot by boot count", {"boot_count": 7},
     {"overrides": {"boot_count": 8}},
     ta.VERDICT_UNVERIFIED_TIME, "absent", None),
    ("reboot by boot id", {},
     {"overrides": {"boot_id": "boot-b"}},
     ta.VERDICT_UNVERIFIED_TIME, "absent", None),
]


@pytest.mark.parametrize("name,ticket_over,photo_kw,verdict,gnss,delta", CASES,
                         ids=[c[0] for c in CASES])
def test_time_label_table(name, ticket_over, photo_kw, verdict, gnss, delta):
    photo_kw = dict(photo_kw)
    # Identity fields arrive through overrides so they replace the defaults
    # rather than being passed twice.
    overrides = photo_kw.pop("overrides", {})
    slip = photo_kw.get("wall_slip_ms", 0)
    elapsed = photo_kw.get("elapsed_ms", 60_000)
    result = ta.assess(ticket(**ticket_over), photo(elapsed, slip, **overrides))
    assert result["verdict"] == verdict
    assert result["gnss"] == gnss
    assert result["monotonic_delta_ms"] == delta
    if verdict == ta.VERDICT_UNVERIFIED_TIME:
        assert result["boot_changed"] is True
        assert ta.VERDICT_UNVERIFIED_TIME in result["labels"]
        assert ta.VERDICT_DEVICE_CLOCK_MISMATCH not in result["labels"]
    elif verdict == ta.VERDICT_DEVICE_CLOCK_MISMATCH:
        assert result["boot_changed"] is False
        assert result["labels"] == (ta.VERDICT_DEVICE_CLOCK_MISMATCH,)
    else:
        assert result["labels"] == ()
        assert "No GNSS" in result["detail"]


def test_boundary_at_120_seconds_is_strict():
    """120.000 s agrees. 120.001 s does not. Both directions."""
    agree = ta.assess(ticket(), photo(wall_slip_ms=120_000))
    past = ta.assess(ticket(), photo(wall_slip_ms=120_001))
    assert agree["verdict"] == ta.VERDICT_CONSISTENT
    assert agree["monotonic_delta_ms"] == 120_000
    assert past["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    assert past["monotonic_delta_ms"] == 120_001

    agree_back = ta.assess(ticket(), photo(wall_slip_ms=-120_000))
    past_back = ta.assess(ticket(), photo(wall_slip_ms=-120_001))
    assert agree_back["verdict"] == ta.VERDICT_CONSISTENT
    assert past_back["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH


def test_reboot_is_unverified_time_and_not_a_clock_mismatch():
    """A new boot has no monotonic interval to disagree with."""
    rebooted = photo()
    rebooted["boot_count"] = 8
    result = ta.assess(ticket(), rebooted)
    assert result["verdict"] == ta.VERDICT_UNVERIFIED_TIME
    assert result["boot_changed"] is True
    assert result["monotonic_delta_ms"] is None
    assert result["gnss"] == "absent"
    assert "No GNSS" in result["detail"]
    # The wall clock also jumped. That jump is not judged across a reboot.
    rebooted["wall_time_ms"] += 180_000
    jumped = ta.assess(ticket(), rebooted)
    assert jumped["verdict"] == ta.VERDICT_UNVERIFIED_TIME
    assert jumped["monotonic_delta_ms"] is None


def test_clock_jump_on_the_same_boot_is_a_mismatch():
    result = ta.assess(ticket(), photo(wall_slip_ms=180_000))
    assert result["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    assert result["boot_changed"] is False
    assert result["gnss"] == "absent"
    assert "No GNSS" in result["detail"]
    assert result["monotonic_delta_ms"] == 180_000


def test_android_boot_count_and_ios_boot_id_each_suffice():
    android_ticket = ticket()
    del android_ticket["boot_id"]
    android_photo = photo()
    del android_photo["boot_id"]
    assert ta.assess(android_ticket, android_photo)["verdict"] == ta.VERDICT_CONSISTENT

    ios_ticket = ticket()
    del ios_ticket["boot_count"]
    ios_photo = photo()
    del ios_photo["boot_count"]
    assert ta.assess(ios_ticket, ios_photo)["verdict"] == ta.VERDICT_CONSISTENT


def test_a_boot_identifier_on_only_one_side_is_unverified():
    ios = ticket()
    del ios["boot_count"]
    android = photo()
    del android["boot_id"]
    result = ta.assess(ios, android)
    assert result["verdict"] == ta.VERDICT_UNVERIFIED_TIME
    assert result["boot_changed"] is True


def test_no_boot_identity_is_unverified():
    bare_ticket = ticket()
    bare_photo = photo()
    for obs in (bare_ticket, bare_photo):
        obs.pop("boot_id")
        obs.pop("boot_count")
    result = ta.assess(bare_ticket, bare_photo)
    assert result["verdict"] == ta.VERDICT_UNVERIFIED_TIME


# -------------------------------------------------------------------- gnss ---
def test_gnss_within_120_seconds_agrees():
    shot = photo()
    shot["gnss_time_ms"] = shot["wall_time_ms"] + 120_000
    result = ta.assess(ticket(), shot)
    assert result["verdict"] == ta.VERDICT_CONSISTENT
    assert result["gnss"] == "agrees"
    assert result["gnss_delta_ms"] == 120_000


def test_gnss_past_120_seconds_is_a_mismatch():
    shot = photo()
    shot["gnss_time_ms"] = shot["wall_time_ms"] + 120_001
    result = ta.assess(ticket(), shot)
    assert result["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    assert result["gnss"] == "mismatch"
    assert result["gnss_delta_ms"] == 120_001
    assert result["monotonic_delta_ms"] == 0


def test_gnss_absent_leaves_the_monotonic_verdict_standing():
    consistent = ta.assess(ticket(), photo())
    mismatch = ta.assess(ticket(), photo(wall_slip_ms=180_000))
    assert consistent["gnss"] == "absent"
    assert consistent["verdict"] == ta.VERDICT_CONSISTENT
    assert mismatch["gnss"] == "absent"
    assert mismatch["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    for result in (consistent, mismatch):
        assert "No GNSS" in result["detail"]

    explicit = photo()
    explicit["gnss_time_ms"] = None
    assert ta.assess(ticket(), explicit)["gnss"] == "absent"


def test_gnss_agreement_does_not_clear_a_monotonic_mismatch():
    shot = photo(wall_slip_ms=180_000)
    shot["gnss_time_ms"] = shot["wall_time_ms"]
    result = ta.assess(ticket(), shot)
    assert result["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    assert result["gnss"] == "agrees"


def test_reboot_plus_gnss_mismatch_keeps_both_labels():
    shot = photo()
    shot["boot_count"] = 8
    shot["gnss_time_ms"] = shot["wall_time_ms"] + 180_000
    result = ta.assess(ticket(), shot)
    assert result["verdict"] == ta.VERDICT_DEVICE_CLOCK_MISMATCH
    assert result["labels"] == (
        ta.VERDICT_UNVERIFIED_TIME,
        ta.VERDICT_DEVICE_CLOCK_MISMATCH,
    )
    assert result["boot_changed"] is True
    assert result["monotonic_delta_ms"] is None
    assert result["gnss"] == "mismatch"


def test_a_missing_clock_reading_is_unverified_not_a_mismatch():
    shot = photo()
    del shot["wall_time_ms"]
    result = ta.assess(ticket(), shot)
    assert result["verdict"] == ta.VERDICT_UNVERIFIED_TIME
    assert result["boot_changed"] is False
    assert result["monotonic_delta_ms"] is None


# ------------------------------------------------------------------- flags ---
def test_flags_never_flip_the_time_verdict():
    """The same clocks, every flag bit, both directions.

    Flags must not create a mismatch, and they must not clear one. The
    mock-location field is the same kind of signal and does not either.
    """
    agreed = photo()
    jumped = photo(wall_slip_ms=180_000)
    rebooted = photo()
    rebooted["boot_id"] = "boot-b"

    for base in (agreed, jumped, rebooted):
        plain = ta.assess(ticket(), base)
        flagged = dict(base)
        flagged["flags"] = ALL_FLAGS
        flagged["location_simulated"] = True
        flagged["sensor_hash"] = "ab" * 32
        flagged["depth_present"] = False
        out = ta.assess(ticket(), flagged)
        assert out["verdict"] == plain["verdict"]
        assert out["labels"] == plain["labels"]
        assert out["boot_changed"] == plain["boot_changed"]
        assert out["monotonic_delta_ms"] == plain["monotonic_delta_ms"]
        assert out["gnss"] == plain["gnss"]
        assert out["gnss_delta_ms"] == plain["gnss_delta_ms"]

    # Flags on the ticket observation are not a clock either.
    noisy = dict(ticket(), flags=ALL_FLAGS, location_simulated=True)
    assert ta.assess(noisy, photo())["verdict"] == ta.VERDICT_CONSISTENT
    assert ta.assess(noisy, photo(wall_slip_ms=180_000))["verdict"] == (
        ta.VERDICT_DEVICE_CLOCK_MISMATCH)


def test_a_float_time_is_rejected_rather_than_labeled():
    shot = photo()
    shot["wall_time_ms"] = float(shot["wall_time_ms"])
    with pytest.raises(ValueError):
        ta.assess(ticket(), shot)
    shot = photo()
    shot["gnss_time_ms"] = 120.001
    with pytest.raises(ValueError):
        ta.assess(ticket(), shot)


def test_the_120_second_limit_is_not_the_challenge_ttl():
    """Two knobs that are both 120 seconds today, and must be free to diverge.

    The challenge lifetime is how long a nonce may be spent. The clock limit
    is how far the device clock may drift before the record is labeled.
    """
    assert ta.CLOCK_MISMATCH_LIMIT_MS == 120_000
    assert attestation.CHALLENGE_TTL_S == 120
    assert ta.CLOCK_MISMATCH_LIMIT_MS != attestation.CHALLENGE_TTL_S
    assert "attestation" not in ta.__dict__
    source = inspect.getsource(ta.assess) + inspect.getsource(ta.boot_changed)
    assert "CHALLENGE_TTL" not in source
    module = inspect.getsource(ta)
    # The name may appear in the module docstring, explaining the split.
    # It must not appear in executable code.
    code = module.split('"""', 2)[-1]
    assert "CHALLENGE_TTL" not in code
    assert "import attestation" not in code
