"""Independent corroboration signals.

Why this module exists
----------------------
EXIF is not evidence. Shield reads EXIF with piexif; piexif also *writes* it.
A contractor who wants a pass on work they never did can take a stock photo,
stamp it with the job site's coordinates and a plausible timestamp in about a
dozen lines, and every check in integrity.py returns clean — the hash is
computed correctly, the original is sealed, the custody log is written, and the
service certifies a downloaded image. Metadata the adversary controls can only
ever catch lazy fraud.

So corroboration has to come from facts the contractor does not control. This
module computes what the world *must* have looked like at the claimed place and
time, so the claim can be checked against the photograph rather than against
its own metadata.

Signal 1 — solar geometry. Given latitude, longitude and an instant, the sun's
azimuth and elevation are determined. Shadow direction and length in the frame
are a consequence of them. Claim a 2pm capture and submit a photo with long
east-running shadows and the geometry contradicts you. This is free,
deterministic, offline, and there is nothing in the file an attacker can edit
to change what the sky was doing.

Signal 2 — daylight bounds. A photo claimed after dark that shows an
unlit exterior in daylight is a contradiction the model can be asked about
directly.

Implementation follows the NOAA solar position algorithm (General Solar
Position Calculations, NOAA Global Monitoring Laboratory). Accurate to roughly
a minute of arc for years 1900-2100 — far finer than needed to catch a photo
taken on a different day or several hours off.
"""
import math
from datetime import datetime, timedelta, timezone

# Refraction at the horizon plus the solar semi-diameter: the geometric
# elevation at which the disc appears to touch the horizon.
SUNRISE_ELEVATION = -0.833


def _require_aware(dt: datetime) -> datetime:
    """Reject naive datetimes rather than guessing at their zone.

    `.astimezone()` on a naive value silently assumes the *server's* local
    time. A deployment in a non-UTC zone would then shift the sun by hours and
    start flagging honest photos as fraudulent — a wrong answer delivered
    confidently, which is the worst failure mode an evidence system has.
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            "capture time must be timezone-aware; a naive datetime would be "
            "read as server-local time and silently move the sun")
    return dt


def _julian_day(dt: datetime) -> float:
    dt = _require_aware(dt).astimezone(timezone.utc)
    y, m = dt.year, dt.month
    d = (dt.day + dt.hour / 24 + dt.minute / 1440 + dt.second / 86400)
    if m <= 2:
        y, m = y - 1, m + 12
    a = y // 100
    b = 2 - a + a // 4
    return (math.floor(365.25 * (y + 4716)) + math.floor(30.6001 * (m + 1))
            + d + b - 1524.5)


def solar_position(lat: float, lng: float, when: datetime) -> dict:
    """Sun azimuth and elevation in degrees for a place and instant.

    azimuth is measured clockwise from true north (0=N, 90=E, 180=S, 270=W).
    elevation is degrees above the horizon; negative means below it.
    """
    jd = _julian_day(when)
    t = (jd - 2451545.0) / 36525.0                       # Julian centuries

    # Geometric mean longitude and anomaly of the sun
    L0 = (280.46646 + t * (36000.76983 + t * 0.0003032)) % 360
    M = 357.52911 + t * (35999.05029 - 0.0001537 * t)
    Mr = math.radians(M)

    # Equation of centre -> true longitude -> apparent longitude
    C = (math.sin(Mr) * (1.914602 - t * (0.004817 + 0.000014 * t))
         + math.sin(2 * Mr) * (0.019993 - 0.000101 * t)
         + math.sin(3 * Mr) * 0.000289)
    true_long = L0 + C
    omega = 125.04 - 1934.136 * t
    app_long = true_long - 0.00569 - 0.00478 * math.sin(math.radians(omega))

    # Obliquity of the ecliptic, with nutation correction
    seconds = 21.448 - t * (46.8150 + t * (0.00059 - t * 0.001813))
    e0 = 23 + (26 + seconds / 60) / 60
    e = e0 + 0.00256 * math.cos(math.radians(omega))
    er, alr = math.radians(e), math.radians(app_long)

    # Declination and right ascension
    decl = math.degrees(math.asin(math.sin(er) * math.sin(alr)))
    ra = math.degrees(math.atan2(math.cos(er) * math.sin(alr), math.cos(alr)))

    # Equation of time (minutes)
    y = math.tan(er / 2) ** 2
    e0r, L0r = math.radians(e0), math.radians(L0)
    eot = 4 * math.degrees(
        y * math.sin(2 * L0r) - 2 * 0.016708634 * math.sin(Mr)
        + 4 * 0.016708634 * y * math.sin(Mr) * math.cos(2 * L0r)
        - 0.5 * y * y * math.sin(4 * L0r)
        - 1.25 * 0.016708634 ** 2 * math.sin(2 * Mr))

    utc = when.astimezone(timezone.utc)
    minutes = utc.hour * 60 + utc.minute + utc.second / 60
    true_solar_time = (minutes + eot + 4 * lng) % 1440
    hour_angle = true_solar_time / 4 - 180
    if hour_angle < -180:
        hour_angle += 360

    latr, declr, har = map(math.radians, (lat, decl, hour_angle))
    cos_zenith = (math.sin(latr) * math.sin(declr)
                  + math.cos(latr) * math.cos(declr) * math.cos(har))
    cos_zenith = max(-1.0, min(1.0, cos_zenith))
    zenith = math.degrees(math.acos(cos_zenith))
    elevation = 90 - zenith

    # Azimuth from the spherical triangle. The acos term is measured from due
    # south, so NOAA rotates it by 180 to land on a north-referenced bearing:
    # +180 after noon, 540-x before it. Omitting that rotation silently points
    # every shadow the wrong way, which is worse than reporting no signal.
    denom = math.cos(latr) * math.sin(math.radians(zenith))
    if abs(denom) < 1e-9:                      # sun at the zenith or the pole
        azimuth = 180.0
    else:
        cos_az = ((math.sin(latr) * cos_zenith) - math.sin(declr)) / denom
        cos_az = max(-1.0, min(1.0, cos_az))
        acos_az = math.degrees(math.acos(cos_az))
        azimuth = (acos_az + 180) if hour_angle > 0 else (540 - acos_az)
    azimuth %= 360

    return {
        "azimuth_deg":     round(azimuth, 2),
        "elevation_deg":   round(elevation, 2),
        "declination_deg": round(decl, 4),
        "is_daylight":     elevation > SUNRISE_ELEVATION,
    }


def _compass(azimuth: float) -> str:
    points = ("north", "north-east", "east", "south-east",
              "south", "south-west", "west", "north-west")
    return points[int((azimuth + 22.5) % 360 // 45)]


def shadow_expectation(lat, lng, when) -> dict:
    """What the light must have been doing — phrased for a vision model.

    Shadows fall opposite the sun. Their length relative to the object's height
    is cot(elevation), which is the quantity actually visible in a photograph.
    """
    sun = solar_position(lat, lng, when)
    elev, azi = sun["elevation_deg"], sun["azimuth_deg"]

    if not sun["is_daylight"]:
        return {**sun, "shadow_direction": None, "shadow_ratio": None,
                "expectation": (
                    f"The sun was {abs(elev):.1f}deg BELOW the horizon at this "
                    f"place and time — it was dark. Any daylight in this frame "
                    f"contradicts the claimed capture time.")}

    # Within a couple of degrees of the zenith the azimuth is numerically
    # unstable and physically close to meaningless — shadows collapse under the
    # object and point nowhere in particular. Claiming a direction here would
    # hand the model a confident falsehood, so the signal abstains instead.
    if elev > 87.0:
        return {**sun, "shadow_direction": None, "shadow_ratio": None,
                "expectation": (
                    f"Sun almost directly overhead ({elev:.1f}deg elevation). "
                    f"Shadows fall nearly straight down and carry no usable "
                    f"direction — judge this frame on content alone.")}

    shadow_azimuth = (azi + 180) % 360
    ratio = 1 / math.tan(math.radians(elev)) if elev > 0.5 else None

    if elev < 10:
        length = "very long (low sun near the horizon)"
    elif elev < 30:
        length = "long"
    elif elev < 60:
        length = "moderate"
    else:
        length = "short (high sun)"

    detail = (f" A vertical object should cast a shadow about "
              f"{ratio:.1f}x its own height." if ratio and ratio < 20 else "")

    return {
        **sun,
        "shadow_direction": _compass(shadow_azimuth),
        "shadow_azimuth_deg": round(shadow_azimuth, 2),
        "shadow_ratio": round(ratio, 2) if ratio else None,
        "expectation": (
            f"Sun at {elev:.1f}deg elevation, bearing {azi:.0f}deg "
            f"({_compass(azi)}). Shadows must run toward the "
            f"{_compass(shadow_azimuth)} and appear {length}.{detail}"),
    }


def daylight_window(lat, lng, day: datetime) -> dict:
    """Sunrise and sunset (UTC) by scanning for the horizon crossing.

    A scan rather than a closed form: it costs ~2ms, handles polar day and
    polar night without special cases, and cannot disagree with
    solar_position() the way a second algorithm could.
    """
    # Scan the LOCAL solar day, not the UTC day. Longitude is the only offset
    # that matters here — political time zones are irrelevant to where the sun
    # is. Scanning a UTC day at, say, -111 deg longitude straddles two local
    # days and returns a sunset that precedes its own sunrise.
    solar_offset = timedelta(hours=lng / 15.0)
    start = (_require_aware(day).astimezone(timezone.utc) + solar_offset).replace(
        hour=0, minute=0, second=0, microsecond=0) - solar_offset
    prev = solar_position(lat, lng, start)["elevation_deg"]
    rise = sets = None
    for i in range(1, 24 * 60 + 1):
        cur = solar_position(lat, lng, start + timedelta(minutes=i))["elevation_deg"]
        if prev <= SUNRISE_ELEVATION < cur and rise is None:
            rise = start + timedelta(minutes=i)
        if prev > SUNRISE_ELEVATION >= cur and sets is None:
            sets = start + timedelta(minutes=i)
        prev = cur
    return {
        "sunrise_utc": rise.isoformat() if rise else None,
        "sunset_utc":  sets.isoformat() if sets else None,
        "polar_day":   rise is None and sets is None and prev > SUNRISE_ELEVATION,
        "polar_night": rise is None and sets is None and prev <= SUNRISE_ELEVATION,
    }


def corroborate_capture(lat, lng, captured_at: datetime) -> dict:
    """The full solar corroboration payload for one claimed capture.

    Returns a description the vision model can test the image against, and a
    machine-readable record that goes into the custody log so the check is
    reproducible by anyone later holding the same coordinates and timestamp.
    """
    sun = shadow_expectation(lat, lng, captured_at)
    return {
        "signal": "solar_geometry",
        "claimed_lat": lat,
        "claimed_lng": lng,
        "claimed_time_utc": captured_at.astimezone(timezone.utc).isoformat(),
        "sun_elevation_deg": sun["elevation_deg"],
        "sun_azimuth_deg": sun["azimuth_deg"],
        "shadow_direction": sun["shadow_direction"],
        "shadow_ratio": sun["shadow_ratio"],
        "is_daylight": sun["is_daylight"],
        "expectation": sun["expectation"],
        "method": "NOAA General Solar Position Calculations",
    }
