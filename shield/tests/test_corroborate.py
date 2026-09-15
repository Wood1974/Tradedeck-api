"""Solar geometry tests.

These assert against geometric identities, not against a reference
implementation — the identities are true regardless of algorithm, so the tests
stay meaningful if the implementation is ever swapped for a library.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from corroborate import (SUNRISE_ELEVATION, corroborate_capture,  # noqa: E402
                         daylight_window, shadow_expectation, solar_position)

SLC = (40.76056, -111.89083)
AXIAL_TILT = 23.44


def utc(y, m, d, h=0, mi=0):
    return datetime(y, m, d, h, mi, tzinfo=timezone.utc)


def solar_noon(lat, lng, day):
    """Minute of maximum elevation — solar noon by definition."""
    base = day.replace(hour=0, minute=0, second=0, microsecond=0)
    return max((base + timedelta(minutes=m) for m in range(24 * 60)),
               key=lambda t: solar_position(lat, lng, t)["elevation_deg"])


# --------------------------------------------------------------- elevation --
@pytest.mark.parametrize("lat,day,expected", [
    (40.0, utc(2026, 6, 21), 90 - 40 + AXIAL_TILT),   # summer solstice
    (40.0, utc(2026, 12, 21), 90 - 40 - AXIAL_TILT),  # winter solstice
    (0.0,  utc(2026, 3, 20), 90.0),                   # equinox at the equator
])
def test_noon_elevation_matches_geometry(lat, day, expected):
    """Solar-noon elevation is 90 - |latitude - declination|. Pure geometry."""
    t = solar_noon(lat, 0.0, day)
    assert solar_position(lat, 0.0, t)["elevation_deg"] == pytest.approx(expected, abs=0.5)


def test_declination_never_exceeds_axial_tilt():
    decls = [solar_position(0, 0, utc(2026, m, 21, 12))["declination_deg"]
             for m in range(1, 13)]
    assert max(abs(d) for d in decls) <= AXIAL_TILT + 0.05
    assert max(decls) == pytest.approx(AXIAL_TILT, abs=0.1)
    assert min(decls) == pytest.approx(-AXIAL_TILT, abs=0.1)


# ----------------------------------------------------------------- azimuth --
@pytest.mark.parametrize("name,lat,lng", [
    ("Salt Lake City", 40.76056, -111.89083),
    ("London", 51.5074, -0.1278),
    ("Anchorage", 61.2181, -149.9003),
])
def test_northern_noon_sun_bears_south(name, lat, lng):
    """Regression: the azimuth was 180deg out, pointing every shadow the wrong
    way. NOAA measures the acos term from due south and rotates by 180."""
    t = solar_noon(lat, lng, utc(2026, 6, 21))
    assert solar_position(lat, lng, t)["azimuth_deg"] == pytest.approx(180, abs=2)


def test_southern_noon_sun_bears_north():
    t = solar_noon(-33.8688, 151.2093, utc(2026, 6, 21))
    az = solar_position(-33.8688, 151.2093, t)["azimuth_deg"]
    assert min(az, 360 - az) < 2


def test_sun_rises_in_the_east_and_sets_in_the_west():
    day = utc(2026, 9, 14)
    noon = solar_noon(*SLC, day)
    morning = solar_position(*SLC, noon - timedelta(hours=4))
    evening = solar_position(*SLC, noon + timedelta(hours=4))
    assert 45 < morning["azimuth_deg"] < 135, "morning sun should be easterly"
    assert 225 < evening["azimuth_deg"] < 315, "evening sun should be westerly"


def test_azimuth_advances_monotonically_through_daylight():
    day = utc(2026, 9, 14)
    seen = [solar_position(*SLC, day + timedelta(minutes=m))["azimuth_deg"]
            for m in range(13 * 60, 26 * 60, 20)
            if solar_position(*SLC, day + timedelta(minutes=m))["elevation_deg"] > 0]
    assert seen == sorted(seen)


# ---------------------------------------------------------------- daylight --
def test_daylight_window_is_a_local_day_not_a_utc_day():
    """Regression: scanning the UTC day at -111deg longitude straddled two local
    days and returned a sunset earlier than its own sunrise."""
    w = daylight_window(*SLC, utc(2026, 9, 14, 20))
    assert w["sunrise_utc"] < w["sunset_utc"]
    rise = datetime.fromisoformat(w["sunrise_utc"]) - timedelta(hours=6)
    sets = datetime.fromisoformat(w["sunset_utc"]) - timedelta(hours=6)
    assert 6 <= rise.hour <= 7, f"SLC mid-September sunrise ~07:03 local, got {rise}"
    assert 19 <= sets.hour <= 20, f"SLC mid-September sunset ~19:45 local, got {sets}"


def test_polar_day_and_night():
    assert daylight_window(78.2, 15.6, utc(2026, 6, 21, 12))["polar_day"] is True
    assert daylight_window(78.2, 15.6, utc(2026, 12, 21, 12))["polar_night"] is True


def test_night_is_reported_as_night():
    r = solar_position(*SLC, utc(2026, 9, 14, 9))       # 03:00 local
    assert r["elevation_deg"] < SUNRISE_ELEVATION
    assert r["is_daylight"] is False


# -------------------------------------------------------------- expectation --
def test_shadow_runs_opposite_the_sun():
    s = shadow_expectation(*SLC, utc(2026, 9, 14, 15))
    assert s["shadow_azimuth_deg"] == pytest.approx((s["azimuth_deg"] + 180) % 360, abs=0.1)
    assert s["shadow_direction"]
    assert "Shadows must run toward" in s["expectation"]


def test_low_sun_casts_long_shadows_and_high_sun_short():
    day = utc(2026, 6, 21)
    noon = solar_noon(*SLC, day)
    high = shadow_expectation(*SLC, noon)
    low = shadow_expectation(*SLC, noon - timedelta(hours=5))
    assert low["shadow_ratio"] > high["shadow_ratio"]


def test_darkness_contradicts_a_daylight_frame():
    s = shadow_expectation(*SLC, utc(2026, 9, 15, 6))    # midnight local
    assert s["shadow_direction"] is None
    assert "BELOW the horizon" in s["expectation"]
    assert "contradicts" in s["expectation"]


def test_near_zenith_abstains_rather_than_guessing():
    """Within ~2deg of the zenith the azimuth is numerically unstable and
    shadows carry no direction. Asserting one would be a confident falsehood."""
    t = solar_noon(25.7617, -80.1918, utc(2026, 6, 21))  # Miami, sun ~2.3deg off zenith
    s = shadow_expectation(25.7617, -80.1918, t)
    assert s["elevation_deg"] > 87
    assert s["shadow_direction"] is None
    assert "no usable direction" in s["expectation"]


def test_corroboration_payload_is_reproducible_and_complete():
    when = utc(2026, 9, 14, 19, 30)
    a = corroborate_capture(*SLC, when)
    b = corroborate_capture(*SLC, when)
    assert a == b, "same inputs must give the same record — it goes in the audit trail"
    for field in ("signal", "claimed_lat", "claimed_lng", "claimed_time_utc",
                  "sun_elevation_deg", "sun_azimuth_deg", "is_daylight",
                  "expectation", "method"):
        assert field in a


def test_naive_datetime_is_rejected_rather_than_silently_misread():
    with pytest.raises((TypeError, ValueError)):
        solar_position(*SLC, datetime(2026, 9, 14, 12))   # no tzinfo
