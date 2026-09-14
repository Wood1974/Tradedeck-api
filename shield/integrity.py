"""Photo integrity: hashing, EXIF extraction, GPS corroboration, compression.

The one rule this module exists to enforce: the SHA-256 is computed over the
bytes as received, before anything touches them, and the original is stored
unmodified. Everything downstream — the verdict, the custody log, the close-out
packet — is only worth what that anchor is worth.

Two fixes relative to the parent's implementation:

  1. EXIF for non-JPEG. piexif reads JPEG/TIFF only, but HEIC, PNG and WebP were
     all in the allowed MIME list. Anything else threw, returned {}, and the
     photo was stamped "No EXIF -- possible screenshot or downloaded image."
     iPhones shoot HEIC by default, so the most common contractor device
     produced an integrity flag on every upload. Pillow's getexif() is now the
     fallback, and a format we genuinely cannot read is reported as
     'unsupported' rather than as evidence of tampering.

  2. GPS comparison. The parent compared raw degrees against a fixed 0.005
     threshold and called it "~500m". A degree of longitude is 111km at the
     equator and 85km at 40N, so the real tolerance moved with latitude. This
     uses haversine and an explicit metre threshold.
"""
import hashlib
import io
import logging
import math
import os
from datetime import datetime, timezone

log = logging.getLogger(__name__)

try:
    import piexif
    PIEXIF = True
except ImportError:
    PIEXIF = False
    log.warning("piexif unavailable — JPEG EXIF extraction degraded")

try:
    from PIL import Image
    PILLOW = True
except ImportError:
    PILLOW = False
    log.warning("Pillow unavailable — non-JPEG EXIF and compression disabled")

ALLOWED_MIME = {"image/jpeg", "image/png", "image/heic", "image/heif", "image/webp"}
EXIF_NATIVE  = {"image/jpeg"}                      # piexif territory
COMPRESS_PX  = 1200
COMPRESS_Q   = 80
EARTH_M      = 6_371_000


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_ip(ip: str, salt: str) -> str:
    """One-way, salted. The salt is required config — see config.REQUIRED."""
    if not ip:
        return None
    if not salt:
        raise ValueError("IP_HASH_SALT is required to hash uploader IPs")
    return hashlib.sha256((salt + ip).encode()).hexdigest()[:32]


def normalize_mime(content_type: str) -> str:
    ct = (content_type or "application/octet-stream").split(";")[0].strip().lower()
    return "image/jpeg" if ct == "image/jpg" else ct


def haversine_m(lat1, lng1, lat2, lng2):
    """Great-circle distance in metres. None if either point is incomplete."""
    if None in (lat1, lng1, lat2, lng2):
        return None
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_M * math.asin(math.sqrt(a))


def _dms_to_decimal(dms, ref):
    try:
        d = dms[0][0] / dms[0][1]
        m = dms[1][0] / dms[1][1]
        s = dms[2][0] / dms[2][1]
        val = d + m / 60 + s / 3600
        return round(-val if ref in (b"S", b"W", "S", "W") else val, 8)
    except Exception:
        return None


def _decode(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace").strip("\x00")
    if isinstance(v, (list, tuple)):
        return [_decode(x) for x in v]
    return v


def _parse_dt(raw):
    try:
        s = _decode(raw)
        return datetime.strptime(s, "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return None


def _exif_piexif(raw: bytes) -> dict:
    out = {}
    try:
        d = piexif.load(raw)
    except Exception:
        return out
    ifd0, exif, gps = d.get("0th", {}), d.get("Exif", {}), d.get("GPS", {})
    for tag, key in ((piexif.ImageIFD.Make, "device_make"),
                     (piexif.ImageIFD.Model, "device_model"),
                     (piexif.ImageIFD.Software, "software")):
        if ifd0.get(tag):
            out[key] = _decode(ifd0[tag])
    if ifd0.get(piexif.ImageIFD.Orientation):
        out["orientation"] = int(ifd0[piexif.ImageIFD.Orientation])
    if exif.get(piexif.ExifIFD.DateTimeOriginal):
        out["captured_at"] = _parse_dt(exif[piexif.ExifIFD.DateTimeOriginal])
    lat = _dms_to_decimal(gps.get(piexif.GPSIFD.GPSLatitude), gps.get(piexif.GPSIFD.GPSLatitudeRef))
    lng = _dms_to_decimal(gps.get(piexif.GPSIFD.GPSLongitude), gps.get(piexif.GPSIFD.GPSLongitudeRef))
    if lat is not None:
        out["gps_lat"] = lat
    if lng is not None:
        out["gps_lng"] = lng
    alt = gps.get(piexif.GPSIFD.GPSAltitude)
    if alt:
        try:
            out["gps_altitude_m"] = round(alt[0] / alt[1], 2)
        except Exception:
            pass
    out["exif_raw"] = {
        name: {str(k): _decode(v) for k, v in block.items()}
        for name, block in d.items() if isinstance(block, dict)
    }
    return out


def _exif_pillow(raw: bytes) -> dict:
    """Fallback for HEIC/PNG/WebP. Requires pillow-heif for HEIC."""
    out = {}
    try:
        img = Image.open(io.BytesIO(raw))
        ex = img.getexif()
        if not ex:
            return out
        from PIL.ExifTags import TAGS, GPSTAGS
        flat = {TAGS.get(k, k): v for k, v in ex.items()}
        for src, dst in (("Make", "device_make"), ("Model", "device_model"),
                         ("Software", "software")):
            if flat.get(src):
                out[dst] = str(flat[src]).strip("\x00")
        if flat.get("Orientation"):
            out["orientation"] = int(flat["Orientation"])
        if flat.get("DateTimeOriginal"):
            out["captured_at"] = _parse_dt(flat["DateTimeOriginal"])
        gps_ifd = ex.get_ifd(0x8825) or {}
        g = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
        if g.get("GPSLatitude") and g.get("GPSLatitudeRef"):
            lat = _dms_to_decimal([(x.numerator, x.denominator) for x in g["GPSLatitude"]],
                                  g["GPSLatitudeRef"])
            if lat is not None:
                out["gps_lat"] = lat
        if g.get("GPSLongitude") and g.get("GPSLongitudeRef"):
            lng = _dms_to_decimal([(x.numerator, x.denominator) for x in g["GPSLongitude"]],
                                  g["GPSLongitudeRef"])
            if lng is not None:
                out["gps_lng"] = lng
        out["exif_raw"] = {"pillow": {str(k): str(v)[:512] for k, v in flat.items()}}
    except Exception:
        log.debug("Pillow EXIF extraction failed", exc_info=True)
    return out


def extract_exif(raw: bytes, mime: str) -> tuple:
    """Return (exif dict, status).

    status is 'present', 'absent' (readable format, genuinely no EXIF — a real
    authenticity signal) or 'unsupported' (we could not read this container, so
    absence proves nothing and must not be reported as a red flag).
    """
    if mime in EXIF_NATIVE and PIEXIF:
        data = _exif_piexif(raw)
        if data:
            return data, "present"
        data = _exif_pillow(raw) if PILLOW else {}
        return (data, "present") if data else ({}, "absent")

    if PILLOW:
        data = _exif_pillow(raw)
        if data:
            return data, "present"
        # Pillow opened it but found nothing -> genuinely absent.
        try:
            Image.open(io.BytesIO(raw)).verify()
            return {}, "absent"
        except Exception:
            return {}, "unsupported"
    return {}, "unsupported"


def compress_for_model(raw: bytes) -> bytes:
    """Downscale, re-encode as JPEG, strip all metadata.

    This copy is what the model sees. The original is never handed to it — so
    the model cannot be steered by embedded metadata, and the evidentiary bytes
    are never transmitted anywhere.
    """
    if not PILLOW:
        return raw
    try:
        img = Image.open(io.BytesIO(raw))
        if img.mode != "RGB":
            img = img.convert("RGB")
        w, h = img.size
        if max(w, h) > COMPRESS_PX:
            scale = COMPRESS_PX / max(w, h)
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=COMPRESS_Q, exif=b"", optimize=True)
        return buf.getvalue()
    except Exception:
        log.exception("Compression failed — falling back to original bytes")
        return raw


def assess(raw: bytes, mime: str, app_lat, app_lng, tolerance_m: int) -> dict:
    """Everything derivable from the bytes plus the client's claimed position."""
    exif, status = extract_exif(raw, mime)
    e_lat, e_lng = exif.get("gps_lat"), exif.get("gps_lng")
    distance = haversine_m(e_lat, e_lng, app_lat, app_lng)
    mismatch = distance is not None and distance > tolerance_m

    notes = []
    if mismatch:
        notes.append(f"GPS mismatch: EXIF and app-reported position differ by "
                     f"{distance:,.0f} m (tolerance {tolerance_m} m).")
    if status == "absent":
        notes.append("No EXIF in a readable container — possible screenshot or "
                     "re-saved image.")
    if status == "unsupported":
        notes.append(f"EXIF not readable for {mime}; absence is not evidence "
                     "either way.")
    if e_lat is None and status == "present":
        notes.append("EXIF present but carries no GPS — location is "
                     "app-reported only and not independently corroborated.")

    return {
        "exif": exif,
        "exif_status": status,
        "has_exif": status == "present",
        "gps_distance_m": round(distance, 1) if distance is not None else None,
        "gps_mismatch": mismatch,
        # True only when EXIF independently agrees with the reported position.
        "gps_corroborated": distance is not None and not mismatch,
        "integrity_note": " ".join(notes) or None,
    }
