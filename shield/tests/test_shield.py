"""Shield unit tests.

Focus is the integrity layer and the pricing table — the two places where a
regression silently destroys the product's guarantee rather than throwing.
Several tests are explicit regressions against defects in the original
implementation; those name the defect they guard.
"""
import io
import os
import sys

import piexif
import pytest
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import codes          # noqa: E402
import integrity      # noqa: E402
import pricing        # noqa: E402

SLC = (40.76056, -111.89083)      # 40 45 38 N, 111 53 27 W


def make_jpeg(gps=True, size=(2400, 1600)):
    buf = io.BytesIO()
    Image.new("RGB", size, (120, 120, 120)).save(buf, "JPEG")
    exif = {"0th": {piexif.ImageIFD.Make: b"Apple",
                    piexif.ImageIFD.Model: b"iPhone 15 Pro"},
            "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:09:14 10:30:00"},
            "GPS": {}}
    if gps:
        exif["GPS"] = {
            piexif.GPSIFD.GPSLatitude: [(40, 1), (45, 1), (38, 1)],
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLongitude: [(111, 1), (53, 1), (27, 1)],
            piexif.GPSIFD.GPSLongitudeRef: b"W"}
    out = io.BytesIO()
    piexif.insert(piexif.dump(exif), buf.getvalue(), out)
    return out.getvalue()


# ------------------------------------------------------------------ hashing --
def test_hash_is_stable_and_content_addressed():
    a, b = make_jpeg(), make_jpeg()
    assert integrity.sha256(a) == integrity.sha256(b)
    assert integrity.sha256(a) != integrity.sha256(a + b"\x00")
    assert len(integrity.sha256(a)) == 64


def test_ip_hash_requires_a_salt():
    """Regression: IP_HASH_SALT had an in-code fallback, so the 'hashed, not
    stored' claim was false — IPv4 is brute-forceable against a known salt."""
    with pytest.raises(ValueError):
        integrity.hash_ip("203.0.113.9", "")
    assert integrity.hash_ip("", "salt") is None
    assert integrity.hash_ip("203.0.113.9", "a") != integrity.hash_ip("203.0.113.9", "b")


# ---------------------------------------------------------------- distance --
def test_haversine_matches_known_distance():
    assert integrity.haversine_m(40.7608, -111.8910, 40.7743, -111.8910) == pytest.approx(1500, abs=30)


def test_fixed_degree_threshold_was_latitude_dependent():
    """Regression: the original compared raw degrees against 0.005 and called it
    ~500m. The same delta is 556m at the equator and 278m at 60N."""
    equator = integrity.haversine_m(0, 0, 0, 0.005)
    high    = integrity.haversine_m(60, 0, 60, 0.005)
    assert equator > 500 and high < 300
    assert integrity.haversine_m(None, 0, 0, 0) is None


# -------------------------------------------------------------------- EXIF --
def test_jpeg_gps_is_extracted_and_corroborates():
    r = integrity.assess(make_jpeg(), "image/jpeg", *SLC, 500)
    assert r["exif_status"] == "present"
    assert r["has_exif"] is True
    assert r["gps_corroborated"] is True
    assert r["gps_mismatch"] is False
    assert r["integrity_note"] is None
    assert r["exif"]["device_model"] == "iPhone 15 Pro"


def test_spoofed_position_is_flagged():
    r = integrity.assess(make_jpeg(), "image/jpeg", 41.12, -111.89, 500)
    assert r["gps_mismatch"] is True
    assert r["gps_corroborated"] is False
    assert "GPS mismatch" in r["integrity_note"]


def test_exif_without_gps_is_not_treated_as_corroboration():
    r = integrity.assess(make_jpeg(gps=False), "image/jpeg", *SLC, 500)
    assert r["has_exif"] is True
    assert r["gps_corroborated"] is False
    assert "not independently corroborated" in r["integrity_note"]


def test_unreadable_container_is_not_evidence_of_tampering():
    """Regression: piexif reads JPEG/TIFF only, but HEIC was an accepted type.
    Every iPhone HEIC upload was stamped 'possible screenshot'."""
    _, status = integrity.extract_exif(b"not an image at all", "image/heic")
    assert status == "unsupported"
    r = integrity.assess(b"not an image at all", "image/heic", *SLC, 500)
    assert r["has_exif"] is False
    assert "not evidence either way" in r["integrity_note"]
    assert "screenshot" not in r["integrity_note"]


def test_readable_container_with_no_exif_is_a_real_signal():
    buf = io.BytesIO(); Image.new("RGB", (800, 600)).save(buf, "PNG")
    r = integrity.assess(buf.getvalue(), "image/png", *SLC, 500)
    assert r["exif_status"] == "absent"
    assert "screenshot" in r["integrity_note"]


# ------------------------------------------------------------- compression --
def test_compression_strips_metadata_and_downscales():
    src = make_jpeg()
    out = integrity.compress_for_model(src)
    assert Image.open(io.BytesIO(out)).size == (1200, 800)
    assert not Image.open(io.BytesIO(out)).getexif(), "model copy must carry no EXIF"
    assert len(out) < len(src)


def test_compression_never_mutates_the_original():
    src = make_jpeg()
    before = integrity.sha256(src)
    integrity.compress_for_model(src)
    assert integrity.sha256(src) == before, "the evidentiary bytes must be untouched"


def test_small_image_is_not_upscaled():
    buf = io.BytesIO(); Image.new("RGB", (400, 300)).save(buf, "JPEG")
    assert Image.open(io.BytesIO(integrity.compress_for_model(buf.getvalue()))).size == (400, 300)


# ------------------------------------------------------------------- mime ---
@pytest.mark.parametrize("raw,expected", [
    ("image/jpg", "image/jpeg"),
    ("image/JPEG; charset=binary", "image/jpeg"),
    ("image/png", "image/png"),
    (None, "application/octet-stream"),
])
def test_mime_normalisation(raw, expected):
    assert integrity.normalize_mime(raw) == expected


# ---------------------------------------------------------------- pricing ---
@pytest.mark.parametrize("budget,tier,price", [
    (0,          "standard",  7_900),
    (499_999,    "standard",  7_900),
    (500_000,    "standard",  7_900),
    (500_001,    "extended", 12_900),
    (2_000_000,  "extended", 12_900),
    (2_000_001,  "major",    19_900),
    (99_000_000, "major",    19_900),
])
def test_price_tiers(budget, tier, price):
    assert pricing.quote(budget) == (tier, price)


def test_price_ignores_hostile_input():
    """Regression: amount_cents came from the request body with no price table,
    so any authenticated caller could buy Shield for one cent."""
    for hostile in (None, -1, "1", -99_999_999):
        tier, price = pricing.quote(hostile)
        assert price in pricing.VALID_PRICES
        assert price >= 7_900


# ------------------------------------------------------------------ codes ---
def test_every_trade_has_five_complete_checkpoints():
    assert len(codes.TRADES) == 9
    for trade, points in codes.TRADES.items():
        assert len(points) == 5, trade
        for p in points:
            for field in ("label", "irc", "ibc", "photo_instruction", "must_show"):
                assert p.get(field), f"{trade}: missing {field}"


@pytest.mark.parametrize("text,trade", [
    ("reshingle the roof and replace flashing", "roofing"),
    ("pour a new foundation slab with rebar",   "concrete"),
    ("rewire the panel and add GFCI outlets",   "electrical"),
    ("frame an addition with new joists",       "framing"),
    ("",                                        "general"),
    ("something entirely unrelated",            "general"),
])
def test_trade_detection(text, trade):
    assert codes.detect_trade(text) == trade


def test_checkpoint_overflow_returns_empty_not_wrong_codes():
    """Regression: the original indexed trade_codes[point_number-1] with no
    bound, so a 6th point silently got no citation."""
    assert codes.code_entry("roofing", 6) == {}
    assert codes.code_entry("roofing", 0) == {}
    assert codes.code_entry("roofing", 1)["irc"].startswith("IRC R803.2")


