"""
TRADEDECK SHIELD — shield_api.py  (v3 — photo integrity + upload route)

What this file does:
  - TradeDeck Shield product: AI checkpoints, GPS-verified photo verdicts,
    IRC/IBC code references, SHA-256 audit trail, contractor credentialing
  - Revenue Stream Shield payment infrastructure: proper Supabase client
    (supabase_admin), real escrow state machine, webhook deduplication,
    production-quality auth using the shared require_auth from auth.py

v3 additions:
  - /shield/upload-photo (Route 2b): receives raw multipart file, extracts
    EXIF server-side (piexif), computes SHA-256 of original bytes before any
    processing, stores unmodified original to shield-photos bucket, stores
    compressed copy separately for Claude Vision, writes all integrity
    columns to shield_photos, logs custody event, returns photo_id +
    original_hash to caller. The original is NEVER touched after upload.

  - _extract_exif(): server-side EXIF extraction. Pulls GPS, timestamp,
    device make/model, software, orientation. Stored verbatim in exif_raw.

  - _compress_for_claude(): resizes to max 1200px, converts to JPEG at
    quality 80, strips ALL metadata. Compressed copy is what Claude sees.

  - _hash_ip(): one-way SHA-256 of upload IP -- logs without storing PII.

pip dependency additions (add to requirements.txt):
    piexif>=1.1.3
    Pillow>=10.0.0
"""

import base64
import hashlib
import io
import json
import logging
import os
import uuid
import requests
from datetime import datetime, timezone
from functools import wraps

import anthropic
import stripe
from flask import Blueprint, g, jsonify, request

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False
    logging.warning("piexif not installed -- add piexif>=1.1.3 to requirements.txt")

try:
    from PIL import Image as PilImage
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logging.warning("Pillow not installed -- add Pillow>=10.0.0 to requirements.txt")

from auth import require_auth, utc_now_iso

log = logging.getLogger(__name__)

shield_bp = Blueprint('shield', __name__, url_prefix='/shield')

stripe.api_key         = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_SHIELD_PRICE_ID = os.environ.get('STRIPE_SHIELD_PRICE_ID')
ANTHROPIC_API_KEY      = os.environ.get('ANTHROPIC_API_KEY')
SUPABASE_URL           = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY   = os.environ.get('SUPABASE_SERVICE_KEY')
ADMIN_EMAIL            = 'woodalljosh128@gmail.com'

SHIELD_BUCKET      = 'shield-photos'
MAX_UPLOAD_BYTES   = 50 * 1024 * 1024
COMPRESS_MAX_PX    = 1200
COMPRESS_QUALITY   = 80
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/jpg', 'image/png',
    'image/heic', 'image/heif', 'image/webp',
}


def _db():
    return g.supabase


# ---------------------------------------------------------------------------
# EXIF EXTRACTION
# ---------------------------------------------------------------------------
def _extract_exif(raw_bytes: bytes) -> dict:
    result = {}
    if not PIEXIF_AVAILABLE:
        return result
    try:
        exif_dict = piexif.load(raw_bytes)
    except Exception:
        return result

    try:
        ifd0 = exif_dict.get('0th', {})
        exif = exif_dict.get('Exif', {})
        gps  = exif_dict.get('GPS', {})

        make  = ifd0.get(piexif.ImageIFD.Make)
        model = ifd0.get(piexif.ImageIFD.Model)
        sw    = ifd0.get(piexif.ImageIFD.Software)
        ori   = ifd0.get(piexif.ImageIFD.Orientation)

        if make:  result['device_make']  = make.decode('utf-8', errors='replace').strip('\x00')
        if model: result['device_model'] = model.decode('utf-8', errors='replace').strip('\x00')
        if sw:    result['software']     = sw.decode('utf-8', errors='replace').strip('\x00')
        if ori:   result['orientation']  = int(ori)

        dt_orig = exif.get(piexif.ExifIFD.DateTimeOriginal)
        if dt_orig:
            try:
                dt_str = dt_orig.decode('utf-8', errors='replace').strip('\x00')
                dt_obj = datetime.strptime(dt_str, '%Y:%m:%d %H:%M:%S').replace(tzinfo=timezone.utc)
                result['captured_at'] = dt_obj.isoformat()
            except Exception:
                pass

        def _dms_to_decimal(dms, ref):
            try:
                d = dms[0][0] / dms[0][1]
                m = dms[1][0] / dms[1][1]
                s = dms[2][0] / dms[2][1]
                v = d + m / 60 + s / 3600
                if ref in (b'S', b'W'):
                    v = -v
                return round(v, 8)
            except Exception:
                return None

        lat_raw = gps.get(piexif.GPSIFD.GPSLatitude)
        lat_ref = gps.get(piexif.GPSIFD.GPSLatitudeRef)
        lng_raw = gps.get(piexif.GPSIFD.GPSLongitude)
        lng_ref = gps.get(piexif.GPSIFD.GPSLongitudeRef)
        alt_raw = gps.get(piexif.GPSIFD.GPSAltitude)

        if lat_raw and lat_ref:
            lat = _dms_to_decimal(lat_raw, lat_ref)
            if lat is not None: result['gps_lat'] = lat
        if lng_raw and lng_ref:
            lng = _dms_to_decimal(lng_raw, lng_ref)
            if lng is not None: result['gps_lng'] = lng
        if alt_raw:
            try: result['gps_altitude_m'] = round(alt_raw[0] / alt_raw[1], 2)
            except Exception: pass

        def _safe(v):
            if isinstance(v, bytes): return v.decode('utf-8', errors='replace').strip('\x00')
            if isinstance(v, (list, tuple)): return [_safe(i) for i in v]
            return v

        safe_raw = {}
        for ifd_name, ifd_data in exif_dict.items():
            if isinstance(ifd_data, dict):
                safe_raw[ifd_name] = {str(k): _safe(v) for k, v in ifd_data.items()}
        result['exif_raw'] = safe_raw

    except Exception:
        log.exception("EXIF field parse error")

    return result


# ---------------------------------------------------------------------------
# COMPRESS FOR CLAUDE  (strips all EXIF, resizes, returns JPEG bytes)
# ---------------------------------------------------------------------------
def _compress_for_claude(raw_bytes: bytes, content_type: str) -> bytes:
    if not PILLOW_AVAILABLE:
        return raw_bytes
    try:
        img = PilImage.open(io.BytesIO(raw_bytes))
        if img.mode not in ('RGB',):
            img = img.convert('RGB')
        w, h = img.size
        if max(w, h) > COMPRESS_MAX_PX:
            if w >= h:
                img = img.resize((COMPRESS_MAX_PX, int(h * COMPRESS_MAX_PX / w)), PilImage.LANCZOS)
            else:
                img = img.resize((int(w * COMPRESS_MAX_PX / h), COMPRESS_MAX_PX), PilImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=COMPRESS_QUALITY, exif=b'', optimize=True)
        return buf.getvalue()
    except Exception:
        log.exception("Compression failed -- using raw bytes")
        return raw_bytes


# ---------------------------------------------------------------------------
# IP HASH
# ---------------------------------------------------------------------------
def _hash_ip(ip: str) -> str:
    salt = os.environ.get('IP_HASH_SALT', 'tradedeck-shield-ip-salt-2026')
    return hashlib.sha256((salt + ip).encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# IRC / IBC CODE MAP
# ---------------------------------------------------------------------------
IRC_CODE_MAP = {
    "framing": [
        {"label": "Foundation Sill Plate and Anchor Bolts", "irc": "IRC R403.1.6 -- Anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of plate end, 7 inch embedment", "ibc": "IBC 1905.1.8", "photo_instruction": "Photograph full sill plate run showing anchor bolt locations and spacing with tape measure.", "must_show": "Bolt spacing measured, washers and nuts torqued"},
        {"label": "Wall Framing -- Studs, Headers and Bracing", "irc": "IRC R602.3 stud spacing/size, R602.7 header spans, R602.10 wall bracing", "ibc": "IBC 2308.4", "photo_instruction": "Photograph full wall section showing stud spacing, header at each opening, bracing or sheathing.", "must_show": "Stud spacing, header size, bracing method"},
        {"label": "Fireblocking and Draftstopping", "irc": "IRC R302.11 -- fireblocking at ceiling/floor lines, stair stringers, around chimneys", "ibc": "IBC 718", "photo_instruction": "Photograph each fireblocking location before drywall covers it. Include all penetrations.", "must_show": "Fireblock material in place, all gaps sealed"},
        {"label": "Floor Joists -- Notching, Boring and Connections", "irc": "IRC R502.8 -- notches max 1/6 depth; bored holes max 1/3 depth, min 2 inches from edge", "ibc": "IBC 2308.8", "photo_instruction": "Photograph notched or bored joists with tape showing notch depth vs joist depth. Photograph joist hangers.", "must_show": "Notch and bore measurements, joist hanger fastening, bearing length"},
        {"label": "Roof Framing -- Rafters, Ridge and Connectors", "irc": "IRC R802.4 rafter spans, R802.3 ridge board, R802.11 rafter ties, R301.2.1 wind uplift connectors", "ibc": "IBC 2308.10", "photo_instruction": "Photograph rafter-to-ridge and rafter-to-top-plate connections. Include hurricane straps and span measurement.", "must_show": "Connector type and installation, rafter spacing, ridge board size"},
    ],
    "roofing": [
        {"label": "Roof Deck and Sheathing", "irc": "IRC R803.2 -- wood structural panel per span rating; R803.2.4 -- H-clips for spans over 24 inches", "ibc": "IBC 2304.8", "photo_instruction": "Photograph sheathing grade stamp on panels. Photograph H-clips at unsupported edges.", "must_show": "APA grade stamp visible, H-clips or blocking at edges"},
        {"label": "Ice and Water Barrier plus Underlayment", "irc": "IRC R905.1.2 -- ice barrier min 24 inches inside exterior wall where Jan avg temp 25F or below; R905.2.7 -- underlayment required", "ibc": "IBC 1507.2.8", "photo_instruction": "Photograph ice barrier at eaves showing extent past interior wall. Photograph overlapping underlayment rows.", "must_show": "Ice barrier extends min 24 inches past wall line, underlayment overlap min 2 inches"},
        {"label": "Drip Edge and Flashing", "irc": "IRC R905.2.8.5 -- drip edge min 1/4 inch below sheathing, min 2 inches up deck; R905.2.8.3 -- valley flashing min 24 inches wide", "ibc": "IBC 1507.2.9", "photo_instruction": "Photograph drip edge at eave showing overlap. Photograph each valley and step flashing at wall intersections.", "must_show": "Drip edge overlap measured, valley flashing width, step flashing at all intersections"},
        {"label": "Shingle Installation and Nailing Pattern", "irc": "IRC R905.2.5 -- minimum 4 fasteners per strip shingle (6 in high-wind); R905.2.4.1 -- starter strip at eaves", "ibc": "IBC 1507.2.5", "photo_instruction": "Lift a shingle to photograph nail placement. Photograph starter course at eave and offset pattern.", "must_show": "Nails in manufacturer nailing zone, minimum 4 nails visible, starter strip in place"},
        {"label": "Ridge Cap, Vents and Final Weathertight Inspection", "irc": "IRC R806.2 -- ventilation min 1/150 of insulated ceiling area (or 1/300 with balanced intake/exhaust)", "ibc": "IBC 1503.4", "photo_instruction": "Photograph completed ridge cap. Photograph each vent location. Photograph all pipe boot flashings.", "must_show": "Ridge cap fully installed, vent locations visible, all penetration flashings sealed"},
    ],
    "plumbing": [
        {"label": "DWV Rough-In -- Drain Slope and Pipe Support", "irc": "IRC P3005.3 -- slope: 1/4 inch per foot for pipe 3 inches or smaller, 1/8 inch per foot for 4 inch and larger; P2605.1 -- support intervals", "ibc": "IPC 308 support, 704 slope", "photo_instruction": "Use level and ruler on horizontal drain runs to show slope. Photograph pipe hangers showing spacing.", "must_show": "Slope measurement visible, hanger spacing within limits, pipe size stamps"},
        {"label": "DWV Air and Water Pressure Test", "irc": "IRC P2503.5.1 -- air test: 5 psi for 15 minutes; water test: min 10ft head for 15 minutes", "ibc": "IPC 312.2", "photo_instruction": "Photograph test gauge showing pressure at start and end of 15-minute hold.", "must_show": "Gauge reading at start and end, no visible moisture at joints"},
        {"label": "Water Supply Lines -- Material, Sizing and Pressure Test", "irc": "IRC P2903.5 -- static pressure test at 1.5 times working pressure for 15 minutes; P2903.1 -- min 3/4 inch building supply", "ibc": "IPC 604, 312.5", "photo_instruction": "Photograph pressure gauge on supply system. Photograph pipe material markings and main shutoff.", "must_show": "Test pressure gauge reading, pipe material stamp, shutoff valve accessible"},
        {"label": "Vent Stack and Air Admittance Valves", "irc": "IRC P3103.1 -- vent through roof min 6 inches above roof surface (min 24 inches in snow country); P3105 -- each trap must be vented", "ibc": "IPC 903, 917", "photo_instruction": "Photograph vent stack from exterior showing height above roof. Photograph each trap-to-vent connection.", "must_show": "Vent height above roof surface measured, all traps connected to vent system"},
        {"label": "Fixture Rough-In and Cleanout Locations", "irc": "IRC P3005.2.7 -- cleanouts at base of each stack and runs over 100ft; P2708 shower, P2705 lavatory rough-in requirements", "ibc": "IPC 708", "photo_instruction": "Photograph each rough-in location with measurement from finished floor. Photograph cleanout plugs.", "must_show": "Rough-in measurements matching fixture specs, cleanout locations accessible"},
    ],
    "electrical": [
        {"label": "Panel, Service Entry and Grounding Electrode", "irc": "NEC 250.52(A)(3) -- Ufer: min 20ft of min 1/2 inch rebar or #4 bare copper encased in min 2 inches concrete; NEC 250.50 -- all electrodes bonded", "ibc": "NEC Article 250, 230", "photo_instruction": "Photograph Ufer electrode BEFORE concrete pour showing rebar length and pigtail. Photograph GEC connection at panel.", "must_show": "Ufer rebar length and pigtail visible, GEC connection at panel, service conductor size"},
        {"label": "Branch Circuit Rough-In -- Box Fill and Wire Routing", "irc": "NEC 314.16 -- box fill: 2.0 cu in per #14, 2.25 cu in per #12; NEC 300.4 -- nail plate required if cable within 1-1/4 inches of stud edge", "ibc": "NEC Article 314, 300", "photo_instruction": "Photograph each box showing wire count and cubic-inch rating stamped on box. Photograph nail plates at stud edges.", "must_show": "Box cu-in rating stamp, nail plates where required, staple spacing max 4.5 feet"},
        {"label": "GFCI and AFCI Protection", "irc": "NEC 210.8 -- GFCI at bathrooms, garages, outdoors, kitchens within 6 feet of sink; NEC 210.12 -- AFCI all 15/20A 120V circuits in dwelling", "ibc": "NEC 210.8, 210.12", "photo_instruction": "Photograph GFCI outlet or breaker at each required location. Photograph AFCI breakers in panel.", "must_show": "GFCI at all wet and outdoor locations, AFCI breakers for bedroom and living circuits"},
        {"label": "Rough-In Inspection -- All Circuits, Working Clearances", "irc": "NEC 110.26 -- working clearance: min 30 inches wide, min 36 inches deep, min 6.5 feet high in front of panel", "ibc": "NEC 110.26", "photo_instruction": "Photograph panel working clearance with tape showing 36-inch depth from panel face. Photograph service disconnect label.", "must_show": "36-inch clearance measured in photo, service disconnect labeled, no obstructions"},
        {"label": "Final -- Devices, Fixtures and Load Center Labeling", "irc": "NEC 408.4 -- every circuit breaker must be legibly identified; NEC 110.12 -- no open knockouts", "ibc": "NEC 408.4, 110.12", "photo_instruction": "Photograph completed panel directory. Photograph outlet and switch installations. Check for open knockouts.", "must_show": "Complete panel directory, all boxes covered, no open knockouts, circuit labels legible"},
    ],
    "hvac": [
        {"label": "Equipment Installation and Clearances", "irc": "IRC M1306 -- clearances to combustibles per equipment listing label; M1305.1 -- access passageway min 22 by 30 inches", "ibc": "IMC 304, 306", "photo_instruction": "Photograph equipment label showing required clearances. Photograph measured distance from unit to nearest combustible.", "must_show": "Equipment label clearance requirements visible, measured clearance in photo, access path dimensions"},
        {"label": "Duct Installation -- Support, Joints and Sealing", "irc": "IRC M1601.4.1 -- joints and seams sealed with mastic or UL 181A/B tape; M1601.4.4 -- round duct support max 10ft, rectangular max 4ft", "ibc": "IMC 603", "photo_instruction": "Photograph duct joints showing mastic or approved tape. Photograph duct hangers showing spacing.", "must_show": "Mastic or UL 181 tape at all joints, hanger spacing within limits, flex duct not kinked"},
        {"label": "Combustion Air and Gas Piping", "irc": "IRC G2407 -- combustion air: min 50 cu ft per 1,000 BTU/hr; G2417 -- gas piping test: 10 psi air for 15 min before appliances connected", "ibc": "IMC 701, 303.3", "photo_instruction": "Photograph combustion air opening size with measurement. Photograph gas piping pressure gauge during test.", "must_show": "Combustion air opening dimensions, gas test gauge reading, shutoff valve accessible and labeled"},
        {"label": "Condensate Drainage and Secondary Drain", "irc": "IRC M1411.3 -- secondary drain or auxiliary pan required for equipment above finished ceiling; pan min 1.5 inches deep, min 3 inches wider than unit", "ibc": "IMC 307.2", "photo_instruction": "Photograph primary drain connection and routing. Photograph secondary drain pan dimensions or float switch.", "must_show": "Primary drain connection, secondary pan or float switch installed, drain terminates visible"},
        {"label": "Final -- Duct Insulation, Filter, and System Test", "irc": "IRC N1103.3.3 -- ducts in unconditioned space: R-8 insulation minimum", "ibc": "IECC C403.2.2, IMC 607", "photo_instruction": "Photograph duct insulation in attic or crawl space showing R-value label. Photograph filter installed. Photograph thermostat set to test with system running.", "must_show": "R-8 or higher insulation label visible, filter in place, system operational"},
    ],
    "concrete": [
        {"label": "Footing Excavation and Soil Bearing", "irc": "IRC R403.1 -- footings bear on undisturbed soil; R301.2(7) -- frost depth per Table R301.2(1); R403.1.1 -- min 12 inches below grade", "ibc": "IBC 1809.4", "photo_instruction": "Photograph footing trench showing depth measurement from grade to bottom. Include tape showing frost-depth compliance.", "must_show": "Footing depth measurement, undisturbed soil visible at base"},
        {"label": "Rebar Placement and Concrete-Encased Electrode", "irc": "IRC R403.1.3 -- footing reinforcement per Table R403.1.3(1); NEC 250.52(A)(3) -- Ufer: min 20ft of min 1/2 inch rebar in min 2 inches concrete", "ibc": "IBC 1905, ACI 318 20.6.1 -- cover: 3 inches cast against earth", "photo_instruction": "Photograph rebar chairs or supports showing minimum concrete cover. Photograph Ufer pigtail extending from footing form.", "must_show": "Rebar chairs maintaining minimum cover, Ufer pigtail visible and tagged, rebar size and spacing per plan"},
        {"label": "Vapor Retarder and Sub-Slab Preparation", "irc": "IRC R506.2.3 -- vapor retarder min 10-mil Class A per ASTM E1745, joints lapped min 6 inches, extended up stem walls", "ibc": "IBC 1805.4.1", "photo_instruction": "Photograph vapor barrier material showing 10-mil spec or ASTM E1745 markings. Photograph joint laps showing min 6 inch overlap.", "must_show": "Vapor barrier spec marking, 6-inch lap at joints, edges turned up at stem walls"},
        {"label": "Concrete Pour -- Mix, Placement and Consolidation", "irc": "IRC R402.2 -- min f'c: 2,500 psi interior slabs, 3,000 psi exposed to weather, 3,500 psi severe freeze-thaw", "ibc": "IBC 1905.3, ACI 318 Table 19.3.3.1", "photo_instruction": "Photograph concrete delivery ticket showing mix design and PSI strength. Photograph vibrator being used during pour.", "must_show": "Concrete ticket with f'c and w/c ratio, vibration occurring during pour"},
        {"label": "Anchor Bolts, Curing and Slab Tolerances", "irc": "IRC R403.1.6 -- anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of plate ends, min 7 inch embedment; R506.2.4 -- slab min 3.5 inches thick", "ibc": "IBC 1905.1.8, ACI 117 -- slab tolerance 1/4 inch in 10ft", "photo_instruction": "Photograph anchor bolts set in wet concrete while still plastic. Measure and photograph bolt spacing. Photograph curing compound applied.", "must_show": "Anchor bolt spacing measured, embedment depth marker, curing compound application"},
    ],
    "flooring": [
        {"label": "Subfloor Condition and Moisture Testing", "irc": "IRC R503.2 -- wood structural panel subfloor: APA rated sheathing per span table; MC max 14 percent for wood or max 3 lbs per 1000 sf per 24hr for concrete", "ibc": "IBC 2304.9", "photo_instruction": "Photograph moisture meter reading in multiple locations. Photograph flatness measurement with 10-foot straightedge.", "must_show": "Moisture meter reading visible, flatness measurement, any repairs noted"},
        {"label": "Underlayment Installation", "irc": "IRC R503 -- subfloor per span table; manufacturer installation instructions govern underlayment type and thickness", "ibc": "IBC 2304.9", "photo_instruction": "Photograph underlayment material label showing specification. Photograph seam treatment (tape or stapling).", "must_show": "Underlayment spec label, seams properly treated, no voids or bubbles"},
        {"label": "Flooring Layout and Acclimation", "irc": "NWFA Installation Guidelines: acclimate 3 to 5 days at job-site conditions", "ibc": "NWFA Installation Guidelines; ANSI A108 for tile", "photo_instruction": "Photograph flooring material open and acclimating on-site. Photograph chalk line layout and room temperature and humidity reading.", "must_show": "Flooring open and acclimating, temp and humidity reading, layout lines established"},
        {"label": "Flooring Installation -- Fastening and Pattern", "irc": "NWFA: 3/4 inch solid hardwood -- cleat or staple every 6 to 8 inches; expansion gap 3/4 inch at all walls; ANSI A108.02 -- tile: thin-set coverage min 80 percent interior", "ibc": "NWFA and ANSI A108 and manufacturer specs", "photo_instruction": "Photograph expansion gap at wall with spacer in place. For tile: lift a tile immediately after setting to check mortar coverage.", "must_show": "Expansion gap at perimeter, fastener spacing visible, mortar coverage on tile back"},
        {"label": "Transitions, Thresholds and Final Inspection", "irc": "IRC R311.7.5 -- stair treads: rise max 7-3/4 inches, run min 10 inches", "ibc": "IBC 1003.3", "photo_instruction": "Photograph all threshold transitions room to room. Photograph any change-in-level measurements.", "must_show": "All transitions in place, level changes measured, no protruding fasteners or gaps"},
    ],
    "painting": [
        {"label": "Surface Preparation -- Drywall and Substrate", "irc": "GA-214 Recommended Levels of Gypsum Board Finish -- Level 4 minimum for flat paint; Level 5 for gloss or semi-gloss or critical lighting", "ibc": "GA-214 and ASTM C840", "photo_instruction": "Photograph drywall seams under raking light to show finish level. Document finish level before primer.", "must_show": "Seams smooth under raking light, no mud ridges, corner bead straight"},
        {"label": "Primer Application", "irc": "Manufacturer specs and PDCA Standards P1 through P4 series", "ibc": "PDCA and MPI Architectural Painting Specification Manual", "photo_instruction": "Photograph primed surfaces showing even coverage. Photograph primer product label showing manufacturer and type.", "must_show": "Even primer coverage, no bare spots, product label visible"},
        {"label": "First Coat -- Application and Coverage", "irc": "PDCA P4 and MPI Standards -- spread rate per manufacturer; mil thickness per spec sheet", "ibc": "MPI Architectural Painting Specification Manual 9", "photo_instruction": "Photograph any areas with thin coverage or holidays. Photograph product label and batch number.", "must_show": "Even sheen across surface, product batch number recorded"},
        {"label": "Second Coat and Finish Inspection", "irc": "PDCA P12 -- uniform color and sheen, no defects visible at 5 feet in normal light", "ibc": "MPI 9; ASTM D3730", "photo_instruction": "Photograph finished walls under normal lighting and under raking light. Photograph final coat product label.", "must_show": "Uniform sheen at 5-foot viewing distance, no drips or laps, final coat label"},
        {"label": "Trim, Cut Lines and Cleanup", "irc": "PDCA P5 protection of adjacent surfaces; PDCA P1 workmanship standard", "ibc": "PDCA Standards", "photo_instruction": "Photograph trim cut lines at ceiling and floor. Photograph hardware reinstalled. Photograph overall room showing clean site.", "must_show": "Straight cut lines, hardware in place, no paint on floors or fixtures"},
    ],
    "general": [
        {"label": "Site Safety and Permit Posted", "irc": "IRC R105.7 -- permit must be posted on site and visible from street until final inspection", "ibc": "IBC 105.7", "photo_instruction": "Photograph building permit posted at front of property. Photograph crew wearing PPE.", "must_show": "Permit visible and readable, PPE in use, no obvious safety violations"},
        {"label": "Work-in-Progress Milestone", "irc": "Contractual milestone -- specific IRC section depends on trade being performed", "ibc": "Contractual as applicable", "photo_instruction": "Photograph wide view of work area showing scope in progress. Include reference objects for scale.", "must_show": "Clear progress visible, scope matches contract, work area identified"},
        {"label": "Materials On-Site and Specification", "irc": "IRC R101.2 -- materials must meet referenced standards; specific section per material type", "ibc": "IBC 1703 product approval", "photo_instruction": "Photograph material specification labels for all major materials. Photograph materials stored properly off ground and covered.", "must_show": "Grade stamps and spec labels visible, materials protected from weather, quantities match scope"},
        {"label": "Subcontractor Work Complete", "irc": "IRC R109 -- required inspections must be completed before concealment of any work", "ibc": "IBC 110", "photo_instruction": "Photograph any rough-in work before walls are closed. Photograph required inspection approval cards posted on site.", "must_show": "All rough-in work visible before concealment, inspection tags if applicable"},
        {"label": "Final Walkthrough and Punch List", "irc": "IRC R110 -- Certificate of Occupancy required before occupancy; final inspection must pass", "ibc": "IBC 111", "photo_instruction": "Photograph each completed area of agreed scope. Photograph final cleanup. Photograph any outstanding items for homeowner.", "must_show": "All contracted work visible and complete, site clean, no materials left behind"},
    ],
}


def detect_trade(description: str) -> str:
    text = description.lower()
    keywords = {
        "framing":    ["frame","framing","stud","joist","rafter","lumber","addition","truss","beam","header"],
        "roofing":    ["roof","roofing","shingle","gutter","soffit","fascia","flashing","ridge","underlayment"],
        "plumbing":   ["plumbing","pipe","drain","water heater","sewer","fixture","toilet","sink","shower","faucet"],
        "electrical": ["electrical","wiring","panel","circuit","outlet","switch","breaker","volt","amp","conduit"],
        "hvac":       ["hvac","furnace","ac","air conditioning","ductwork","heat pump","mechanical","heating","cooling"],
        "concrete":   ["concrete","foundation","slab","driveway","patio","footing","cement","masonry","rebar"],
        "flooring":   ["floor","flooring","hardwood","lvp","tile","carpet","laminate","subfloor","vinyl"],
        "painting":   ["paint","painting","primer","drywall","finish","stain","caulk","interior","exterior"],
    }
    best, score = "general", 0
    for trade, kws in keywords.items():
        s = sum(1 for k in kws if k in text)
        if s > score:
            best, score = trade, s
    return best


# ---------------------------------------------------------------------------
# CHAIN-OF-CUSTODY LOGGER
# ---------------------------------------------------------------------------
def log_custody(photo_id, shield_job_id, event_type, actor_id=None,
                actor_type="system", event_data=None, gps_lat=None,
                gps_lng=None, file_hash=None, integrity_note=None,
                exif_captured_at=None):
    try:
        _db().table("shield_custody_log").insert({
            "photo_id":         photo_id,
            "shield_job_id":    shield_job_id,
            "event_type":       event_type,
            "actor_id":         actor_id,
            "actor_type":       actor_type,
            "event_data":       json.dumps(event_data or {}),
            "gps_lat":          gps_lat,
            "gps_lng":          gps_lng,
            "file_hash":        file_hash,
            "integrity_note":   integrity_note,
            "exif_captured_at": exif_captured_at,
            "recorded_at":      utc_now_iso(),
        }).execute()
    except Exception:
        log.exception("log_custody failed -- event_type=%s photo_id=%s", event_type, photo_id)


# ===========================================================================
# ROUTE 1 -- Homeowner: create PaymentIntent
# ===========================================================================
@shield_bp.route('/create-payment-intent', methods=['POST'])
@require_auth
def create_payment_intent():
    data         = request.get_json(silent=True) or {}
    job_id       = data.get('job_id')
    amount_cents = data.get('amount_cents')
    if not job_id or not amount_cents:
        return jsonify({'error': 'job_id and amount_cents required'}), 400
    try:
        intent = stripe.PaymentIntent.create(
            amount=int(amount_cents), currency='usd',
            capture_method='automatic',
            metadata={'job_id': job_id, 'product': 'shield_per_job'},
            description='TradeDeck Shield -- Job ' + str(job_id),
            idempotency_key='shield-pi-' + str(job_id),
        )
        return jsonify({'client_secret': intent.client_secret})
    except stripe.error.StripeError as e:
        log.exception("Stripe error creating Shield PaymentIntent")
        return jsonify({'error': str(e)}), 502


# ===========================================================================
# ROUTE 2 -- Contractor: start Stripe Checkout subscription
# ===========================================================================
@shield_bp.route('/contractor-subscribe', methods=['POST'])
@require_auth
def contractor_subscribe():
    data          = request.get_json(silent=True) or {}
    contractor_id = data.get('contractor_id') or g.user_id
    try:
        existing = _db().table('shield_subscriptions').select('stripe_customer_id').eq('contractor_id', contractor_id).limit(1).execute()
        if existing.data and existing.data[0].get('stripe_customer_id'):
            customer_id = existing.data[0]['stripe_customer_id']
        else:
            customer    = stripe.Customer.create(metadata={'contractor_id': contractor_id})
            customer_id = customer.id
        checkout = stripe.checkout.Session.create(
            customer=customer_id, mode='subscription',
            line_items=[{'price': STRIPE_SHIELD_PRICE_ID, 'quantity': 1}],
            success_url='https://tradedeckapp.com/app.html?shield_sub=success',
            cancel_url='https://tradedeckapp.com/app.html?shield_sub=cancelled',
            metadata={'contractor_id': contractor_id, 'product': 'shield_pro'},
        )
        return jsonify({'stripe_url': checkout.url})
    except stripe.error.StripeError as e:
        log.exception("Stripe error creating Shield subscription checkout")
        return jsonify({'error': str(e)}), 502


# ===========================================================================
# ROUTE 2b -- Photo Upload Integrity Proxy  <<< CRITICAL ROUTE
# POST /shield/upload-photo
#
# Accepts multipart/form-data:
#   file           -- raw image (required)
#   shield_job_id  -- UUID (required)
#   point_id       -- UUID (required)
#   contractor_id  -- UUID (required)
#   gps_lat        -- float from Geolocation API (required)
#   gps_lng        -- float from Geolocation API (required)
#   gps_accuracy_m -- float, metres (optional)
#
# Processing order (immutable):
#   1. Validate inputs and MIME type
#   2. Read raw bytes
#   3. Enforce 50 MB size limit
#   4. SHA-256 of original raw bytes         <-- INTEGRITY ANCHOR
#   5. Extract EXIF server-side (piexif)     <-- CHAIN OF CUSTODY
#   6. Store ORIGINAL unmodified bytes       <-- NEVER TOUCHED AGAIN
#   7. Compress copy for Claude              <-- EXIF STRIPPED
#   8. Write shield_photos row
#   9. Log custody event
#  10. Return photo_id + original_hash + exif summary
# ===========================================================================
@shield_bp.route('/upload-photo', methods=['POST'])
@require_auth
def upload_photo():
    # 1. Validate inputs
    shield_job_id = request.form.get('shield_job_id', '').strip()
    point_id      = request.form.get('point_id', '').strip()
    contractor_id = request.form.get('contractor_id', '').strip() or g.user_id
    gps_lat_raw   = request.form.get('gps_lat', '').strip()
    gps_lng_raw   = request.form.get('gps_lng', '').strip()
    gps_acc_raw   = request.form.get('gps_accuracy_m', '').strip()

    if not all([shield_job_id, point_id, contractor_id]):
        return jsonify({'error': 'shield_job_id, point_id, and contractor_id are required'}), 400

    if not gps_lat_raw or not gps_lng_raw:
        return jsonify({
            'error': 'GPS coordinates are required for Shield photo verification. '
                     'Ensure location permission is granted.'
        }), 400

    try:
        gps_lat = float(gps_lat_raw)
        gps_lng = float(gps_lng_raw)
    except ValueError:
        return jsonify({'error': 'gps_lat and gps_lng must be valid numbers'}), 400

    gps_accuracy_m = None
    if gps_acc_raw:
        try: gps_accuracy_m = float(gps_acc_raw)
        except ValueError: pass

    if 'file' not in request.files:
        return jsonify({'error': 'No file in request. Send as multipart/form-data with field name "file"'}), 400

    file         = request.files['file']
    content_type = (file.content_type or 'application/octet-stream').split(';')[0]
    if content_type == 'image/jpg':
        content_type = 'image/jpeg'
    if content_type not in ALLOWED_MIME_TYPES:
        return jsonify({'error': f'File type "{content_type}" not allowed. Accepted: JPEG, PNG, HEIC, HEIF, WebP'}), 415

    # 2. Read raw bytes
    raw_bytes = file.read()

    # 3. Size limit
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return jsonify({'error': f'File size {len(raw_bytes)//(1024*1024)} MB exceeds 50 MB limit'}), 413

    # 4. SHA-256 of original  (INTEGRITY ANCHOR -- must be first computation)
    original_hash      = hashlib.sha256(raw_bytes).hexdigest()
    server_received_at = utc_now_iso()

    # 5. EXIF extraction (server-side, original bytes, before any processing)
    exif = _extract_exif(raw_bytes)

    exif_gps_lat     = exif.get('gps_lat')
    exif_gps_lng     = exif.get('gps_lng')
    exif_captured_at = exif.get('captured_at')
    has_exif         = bool(exif)

    # Detect GPS mismatch (>~500m between EXIF GPS and app-reported GPS)
    gps_mismatch = False
    if exif_gps_lat and exif_gps_lng:
        if abs(exif_gps_lat - gps_lat) > 0.005 or abs(exif_gps_lng - gps_lng) > 0.005:
            gps_mismatch = True
            log.warning("GPS mismatch: EXIF (%s,%s) vs app (%s,%s) job=%s",
                        exif_gps_lat, exif_gps_lng, gps_lat, gps_lng, shield_job_id)

    photo_id = str(uuid.uuid4())

    # 6. Store ORIGINAL to Supabase Storage (unmodified bytes, never overwrite)
    orig_path = f"{shield_job_id}/{contractor_id}/orig/{photo_id}.jpg"
    try:
        _db().storage.from_(SHIELD_BUCKET).upload(
            path=orig_path, file=raw_bytes,
            file_options={'content-type': content_type, 'cache-control': 'no-cache', 'x-upsert': 'false'}
        )
    except Exception:
        log.exception("Failed to store original to %s/%s", SHIELD_BUCKET, orig_path)
        return jsonify({'error': 'Failed to store photo. Please try again.'}), 500

    # 7. Compress (strips EXIF) and store the Claude copy
    compressed_bytes = _compress_for_claude(raw_bytes, content_type)
    comp_path        = f"{shield_job_id}/{contractor_id}/comp/{photo_id}.jpg"
    try:
        _db().storage.from_(SHIELD_BUCKET).upload(
            path=comp_path, file=compressed_bytes,
            file_options={'content-type': 'image/jpeg', 'cache-control': 'no-cache', 'x-upsert': 'false'}
        )
    except Exception:
        log.exception("Failed to store compressed copy to %s/%s", SHIELD_BUCKET, comp_path)
        comp_path = None

    # Build 1-hour signed URL for the compressed copy
    comp_signed_url = None
    if comp_path:
        try:
            url_resp = _db().storage.from_(SHIELD_BUCKET).create_signed_url(path=comp_path, expires_in=3600)
            comp_signed_url = url_resp.get('signedURL') or url_resp.get('signedUrl')
        except Exception:
            log.exception("Could not generate signed URL for %s", comp_path)

    # 8. Write shield_photos row
    upload_ip  = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    ip_hash    = _hash_ip(upload_ip) if upload_ip else None
    user_agent = request.headers.get('User-Agent', '')

    integrity_note = None
    if gps_mismatch:
        integrity_note = (f"GPS mismatch: EXIF ({exif_gps_lat:.5f},{exif_gps_lng:.5f}) "
                          f"vs app ({gps_lat:.5f},{gps_lng:.5f}).")
    if not has_exif:
        integrity_note = (integrity_note or '') + " No EXIF -- possible screenshot or downloaded image."

    photo_row = {
        'id':                      photo_id,
        'point_id':                point_id,
        'shield_job_id':           shield_job_id,
        'contractor_id':           contractor_id,
        'original_hash':           original_hash,
        'original_hash_algo':      'SHA-256',
        'original_size_bytes':     len(raw_bytes),
        'original_storage_path':   orig_path,
        'compressed_storage_path': comp_path,
        'gps_lat':                 gps_lat,
        'gps_lng':                 gps_lng,
        'gps_accuracy_m':          gps_accuracy_m,
        'exif_gps_lat':            exif_gps_lat,
        'exif_gps_lng':            exif_gps_lng,
        'exif_gps_altitude_m':     exif.get('gps_altitude_m'),
        'exif_captured_at':        exif_captured_at,
        'exif_device_make':        exif.get('device_make'),
        'exif_device_model':       exif.get('device_model'),
        'exif_software':           exif.get('software'),
        'exif_orientation':        exif.get('orientation'),
        'exif_raw':                json.dumps(exif.get('exif_raw', {})),
        'has_exif':                has_exif,
        'file_size_bytes':         len(raw_bytes),
        'server_received_at':      server_received_at,
        'integrity_sealed_at':     utc_now_iso(),
        'upload_user_agent':       user_agent,
        'upload_ip_hash':          ip_hash,
        'device_user_agent':       user_agent,
        'upload_ip':               ip_hash,
        'uploaded_at':             server_received_at,
    }
    try:
        _db().table('shield_photos').insert(photo_row).execute()
    except Exception:
        log.exception("DB write failed for photo_id=%s", photo_id)
        try: _db().storage.from_(SHIELD_BUCKET).remove([orig_path])
        except Exception: pass
        return jsonify({'error': 'Database write failed. Photo not saved.'}), 500

    # 9. Chain-of-custody log
    log_custody(
        photo_id=photo_id, shield_job_id=shield_job_id,
        event_type='uploaded', actor_id=contractor_id, actor_type='contractor',
        file_hash=original_hash, integrity_note=integrity_note,
        exif_captured_at=exif_captured_at,
        event_data={
            'original_path':    orig_path, 'compressed_path': comp_path,
            'original_bytes':   len(raw_bytes), 'compressed_bytes': len(compressed_bytes),
            'has_exif':         has_exif, 'exif_gps_present': bool(exif_gps_lat),
            'gps_mismatch':     gps_mismatch,
            'app_gps':          [gps_lat, gps_lng],
            'exif_gps':         [exif_gps_lat, exif_gps_lng] if exif_gps_lat else None,
            'device_make':      exif.get('device_make'), 'device_model': exif.get('device_model'),
            'content_type':     content_type, 'ip_hash': ip_hash,
        },
        gps_lat=exif_gps_lat or gps_lat, gps_lng=exif_gps_lng or gps_lng,
    )
    if gps_mismatch or not has_exif:
        log_custody(
            photo_id=photo_id, shield_job_id=shield_job_id,
            event_type='integrity_flag', actor_type='system',
            file_hash=original_hash, integrity_note=integrity_note,
            event_data={'gps_mismatch': gps_mismatch, 'has_exif': has_exif, 'reason': integrity_note},
        )

    # 10. Return to caller
    return jsonify({
        'photo_id':         photo_id,
        'original_hash':    original_hash,
        'comp_url':         comp_signed_url,
        'has_exif':         has_exif,
        'exif_gps':         {'lat': exif_gps_lat, 'lng': exif_gps_lng} if exif_gps_lat else None,
        'exif_captured_at': exif_captured_at,
        'device':           (exif.get('device_make','') + ' ' + exif.get('device_model','')).strip(),
        'gps_mismatch':     gps_mismatch,
        'integrity_note':   integrity_note,
    })


# ===========================================================================
# ROUTE 3 -- AI Photo Analysis (Claude Vision)
# POST /shield/analyze-photo
# Receives photo_id + comp_url (from upload-photo). Fetches COMPRESSED copy.
# ===========================================================================
@shield_bp.route('/analyze-photo', methods=['POST'])
@require_auth
def analyze_photo():
    data           = request.get_json(silent=True) or {}
    photo_id       = data.get('photo_id')
    comp_url       = data.get('comp_url')
    point_id       = data.get('point_id')
    gps_lat        = data.get('gps_lat')
    gps_lng        = data.get('gps_lng')
    has_exif       = data.get('has_exif', False)
    code_reference = data.get('code_reference')
    original_hash  = data.get('original_hash')

    if not all([photo_id, comp_url, point_id]):
        return jsonify({'error': 'photo_id, comp_url, and point_id required'}), 400
    if gps_lat is None or gps_lng is None:
        return jsonify({'error': 'GPS coordinates required'}), 400

    point_row   = _db().table('shield_pivotal_points').select('label, description').eq('id', point_id).limit(1).execute()
    point       = point_row.data[0] if point_row.data else {}
    point_label = point.get('label', 'Checkpoint')
    point_desc  = point.get('description', '')

    try:
        img_r = requests.get(comp_url, timeout=20)
        img_r.raise_for_status()
    except Exception:
        log.exception("Could not fetch compressed photo from %s", comp_url)
        return jsonify({'error': 'Could not fetch photo for analysis'}), 502

    image_b64 = base64.b64encode(img_r.content).decode('utf-8')
    comp_hash = hashlib.sha256(img_r.content).hexdigest()

    client   = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    gps_str  = f"{float(gps_lat):.6f}, {float(gps_lng):.6f}"
    exif_str = "YES -- device identity and capture time confirmed" if has_exif else "NO -- strong authenticity concern"

    prompt_text = (
        f"Checkpoint: {point_label}\n"
        f"Required condition: {point_desc}\n\n"
        "METADATA (server-extracted before processing):\n"
        f"- GPS at upload: {gps_str}\n"
        f"- Code requirement: {code_reference or 'See checkpoint description'}\n"
        f"- Camera EXIF present: {exif_str}\n\n"
        "STEP 1 -- AUTHENTICITY CHECK:\n"
        "- Real on-site construction photo, or stock/screenshot/render/AI image?\n"
        "- Genuine construction conditions visible (dust, tools, materials, real shadows)?\n"
        "- Signs of digital manipulation, compositing, watermarks, or screen capture?\n"
        "- If EXIF absent: strong authenticity concern -- note it.\n\n"
        "STEP 2 -- QUALITY CHECK (only if authentic):\n"
        "- Does photo show exactly what this checkpoint requires?\n"
        "- Work complete, correct, meeting trade standard?\n"
        "- Visible defects, shortcuts, or missing elements?\n\n"
        "Respond ONLY with this JSON -- no markdown, no text outside it:\n"
        '{"authentic":true|false,"authenticity_note":"<one sentence>","verdict":"pass"|"flag"|"fail"|"fake","confidence":<0.0-1.0>,"findings":["<finding>"],"notes":"<2-3 sentences for homeowner>","required_action":"<action or null>"}\n\n'
        "fake=not authentic(confidence=1.0) fail=wrong/incomplete flag=concern pass=approved"
    )

    try:
        msg = client.messages.create(
            model='claude-sonnet-4-6', max_tokens=700,
            system=(
                'You are a licensed building inspector and fraud detection analyst evaluating '
                'contractor checkpoint photos for homeowner protection. '
                'Mandate 1: verify authenticity (real on-site photo). '
                'Mandate 2: verify work meets checkpoint requirement. '
                'Be specific. Reference what you see. '
                'Respond ONLY with valid JSON. No markdown. Nothing outside the JSON.'
            ),
            messages=[{'role': 'user', 'content': [
                {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/jpeg', 'data': image_b64}},
                {'type': 'text', 'text': prompt_text}
            ]}]
        )
        raw    = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
        result = json.loads(raw)
    except json.JSONDecodeError:
        log.exception("Claude returned invalid JSON for photo %s", photo_id)
        return jsonify({'error': 'AI returned invalid JSON'}), 500
    except Exception:
        log.exception("Claude Vision call failed for photo %s", photo_id)
        return jsonify({'error': 'AI analysis failed'}), 500

    authentic  = result.get('authentic', True)
    verdict    = result.get('verdict', 'flag')
    confidence = float(result.get('confidence', 0.7))
    notes      = result.get('notes', '')
    findings   = result.get('findings', [])
    auth_note  = result.get('authenticity_note', '')
    req_action = result.get('required_action')

    if not authentic or verdict == 'fake':
        verdict    = 'fake'
        confidence = 1.0
        notes      = f"Photo flagged as inauthentic: {auth_note} This checkpoint has not been verified."

    _db().table('shield_photos').update({
        'ai_verdict':         verdict,
        'ai_confidence':      confidence,
        'ai_notes':           notes,
        'ai_authentic':       authentic,
        'ai_model':           'claude-sonnet-4-6',
        'photo_hash':         comp_hash,
        'hash_algorithm':     'SHA-256',
        'server_received_at': utc_now_iso(),
        **(({'code_reference': code_reference}) if code_reference else {}),
    }).eq('id', photo_id).execute()

    point_status = 'approved' if verdict == 'pass' else 'flagged'
    _db().table('shield_pivotal_points').update({'status': point_status}).eq('id', point_id).execute()

    photo_meta = _db().table('shield_photos').select('shield_job_id,contractor_id').eq('id', photo_id).limit(1).execute()
    meta       = photo_meta.data[0] if photo_meta.data else {}
    s_job_id   = meta.get('shield_job_id')
    contractor = meta.get('contractor_id')

    log_custody(
        photo_id=photo_id, shield_job_id=s_job_id, event_type='ai_analyzed',
        actor_id=contractor, actor_type='ai', file_hash=original_hash,
        integrity_note=auth_note if not authentic else None,
        event_data={
            'verdict': verdict, 'confidence': confidence, 'authentic': authentic,
            'authenticity_note': auth_note, 'original_hash': original_hash,
            'comp_hash': comp_hash, 'findings': findings,
            'required_action': req_action, 'ai_model': 'claude-sonnet-4-6',
        },
        gps_lat=gps_lat, gps_lng=gps_lng,
    )
    if verdict in ('flagged', 'fake', 'fail'):
        log_custody(photo_id=photo_id, shield_job_id=s_job_id, event_type='flagged',
                    actor_type='ai', file_hash=original_hash, integrity_note=auth_note or notes,
                    event_data={'reason': auth_note or notes, 'verdict': verdict})

    return jsonify({'verdict': verdict, 'confidence': confidence, 'notes': notes,
                    'findings': findings, 'required_action': req_action, 'authentic': authentic})


# ===========================================================================
# ROUTE 4 -- Generate AI Pivotal Points
# ===========================================================================
@shield_bp.route('/generate-points', methods=['POST'])
@require_auth
def generate_points():
    data          = request.get_json(silent=True) or {}
    shield_job_id = data.get('shield_job_id')
    job_id        = data.get('job_id')
    job_desc      = data.get('job_description', '')
    if not all([shield_job_id, job_id, job_desc]):
        return jsonify({'error': 'shield_job_id, job_id, and job_description required'}), 400

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        msg = client.messages.create(
            model='claude-sonnet-4-6', max_tokens=600,
            messages=[{'role': 'user', 'content': (
                'You are a senior contractor and licensed building inspector.\n\n'
                'Job description: """' + job_desc + '"""\n\n'
                'Identify exactly 5 pivotal checkpoints -- the moments where a photo proves '
                'whether the work was done correctly before it is too late to fix. '
                'These are the moments a bad contractor would most want to skip.\n\n'
                'Return ONLY a valid JSON array, no markdown:\n'
                '[{"point_number":1,"label":"<short name>","description":"<one sentence: exactly what the photo must show>"},...]'
            )}]
        )
        raw    = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
        points = json.loads(raw)
    except json.JSONDecodeError:
        return jsonify({'error': 'AI returned invalid JSON'}), 500
    except Exception:
        return jsonify({'error': 'AI checkpoint generation failed'}), 500

    trade       = detect_trade(job_desc)
    trade_codes = IRC_CODE_MAP.get(trade, IRC_CODE_MAP['general'])

    for p in points:
        idx          = p['point_number'] - 1
        code_entry   = trade_codes[idx] if idx < len(trade_codes) else {}
        update_fields = {
            'label': p['label'], 'description': p['description'],
            'irc_code': code_entry.get('irc'), 'ibc_code': code_entry.get('ibc'),
            'photo_instruction': code_entry.get('photo_instruction'),
            'must_show': code_entry.get('must_show'),
        }
        existing = _db().table('shield_pivotal_points').select('id').eq('shield_job_id', shield_job_id).eq('point_number', p['point_number']).limit(1).execute()
        if existing.data:
            _db().table('shield_pivotal_points').update(update_fields).eq('id', existing.data[0]['id']).execute()
        else:
            _db().table('shield_pivotal_points').insert({'shield_job_id': shield_job_id, 'job_id': job_id, 'point_number': p['point_number'], **update_fields}).execute()

    return jsonify({'points': points, 'trade': trade})


# ===========================================================================
# ROUTE 5 -- Complete Job
# ===========================================================================
@shield_bp.route('/complete-job', methods=['POST'])
@require_auth
def complete_job():
    packet        = request.get_json(silent=True) or {}
    shield_job_id = packet.get('shield_job_id')
    if not shield_job_id:
        return jsonify({'error': 'shield_job_id required'}), 400

    submitted_hash = packet.pop('sha256', None)
    clean_packet   = {k: packet[k] for k in sorted(packet.keys())}
    packet_string  = json.dumps(clean_packet, sort_keys=True, separators=(',',':'))
    expected_hash  = hashlib.sha256(packet_string.encode()).hexdigest()

    _db().table('shield_completion_reports').insert({
        'shield_job_id':    shield_job_id,
        'job_id':           packet.get('job_id'),
        'contractor_id':    packet.get('closed_by'),
        'homeowner_id':     packet.get('homeowner_id'),
        'overall_verdict':  _derive_verdict(packet.get('points', [])),
        'completion_score': _derive_score(packet.get('points', [])),
        'report_json':      json.dumps({**packet, 'sha256': submitted_hash}),
    }).execute()
    _db().table('shield_jobs').update({'status': 'complete', 'completed_at': utc_now_iso()}).eq('id', shield_job_id).execute()
    _check_contractor_verification(packet.get('closed_by'))
    _send_completion_email(packet, submitted_hash or expected_hash)
    return jsonify({'ok': True, 'sha256': submitted_hash or expected_hash})


def _derive_verdict(points):
    verdicts = [p.get('photo', {}).get('ai_verdict') for p in points if p.get('photo')]
    if not verdicts:       return 'flag'
    if 'fail' in verdicts: return 'fail'
    if 'flag' in verdicts: return 'flag'
    return 'pass'


def _derive_score(points):
    if not points: return 0.0
    score_map = {'pass': 100, 'flag': 60, 'fail': 0, 'fake': 0}
    total = sum(score_map.get(p.get('photo', {}).get('ai_verdict', 'flag'), 60) for p in points)
    return round(total / len(points), 1)


def _check_contractor_verification(contractor_id):
    if not contractor_id: return
    try:
        results     = _db().table('shield_completion_reports').select('overall_verdict').eq('contractor_id', contractor_id).eq('overall_verdict', 'pass').execute()
        clean_count = len(results.data) if results.data else 0
        if clean_count >= 3:
            _db().table('profiles').update({'tradedeck_verified': True, 'verified_at': utc_now_iso()}).eq('id', contractor_id).execute()
    except Exception:
        log.exception("Verification badge check failed for %s", contractor_id)


def _send_completion_email(packet, sha256):
    resend_key = os.environ.get('RESEND_API_KEY', '')
    from_email = os.environ.get('SHIELD_FROM_EMAIL', 'TradeDeck Shield <onboarding@resend.dev>')
    if not resend_key:
        log.warning('RESEND_API_KEY not set — skipping completion email')
        return
    try:
        job_id_str = str(packet.get('job_id', ''))[-6:].upper()
        points     = packet.get('points', [])
        score      = _derive_score(points)
        pts_html   = ''.join(
            f'<tr><td style="padding:6px 12px;border-bottom:1px solid #eee;">'
            f'<strong>{p.get("label","")}</strong></td>'
            f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
            f'{(p.get("photo") or {}).get("ai_verdict","pending").upper()}</td></tr>'
            for p in points
        )
        html = f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
<h2 style="color:#0BBCD4;">&#x1F6E1;&#xFE0F; TradeDeck Shield &#x2014; Job Complete</h2>
<table style="width:100%;border-collapse:collapse;">
  <tr><td style="padding:8px;"><strong>Job ID</strong></td><td>{packet.get('job_id','')}</td></tr>
  <tr><td style="padding:8px;"><strong>Shield Job</strong></td><td>{packet.get('shield_job_id','')}</td></tr>
  <tr><td style="padding:8px;"><strong>Score</strong></td><td>{score}%</td></tr>
  <tr><td style="padding:8px;"><strong>Closed by</strong></td><td>{(packet.get('closed_by') or {}).get('display_name','')}</td></tr>
  <tr><td style="padding:8px;"><strong>Closed at</strong></td><td>{packet.get('closed_at','')}</td></tr>
</table>
<h3>Checkpoints</h3>
<table style="width:100%;border-collapse:collapse;border:1px solid #eee;">
  <tr style="background:#f5f5f5;"><th style="padding:8px 12px;text-align:left;">Point</th><th style="padding:8px 12px;text-align:left;">Verdict</th></tr>
  {pts_html}
</table>
<p style="margin-top:16px;font-family:monospace;font-size:12px;color:#888;">SHA-256: {sha256}</p>
<p style="color:#888;font-size:12px;">TradeDeck Shield &#x2014; tradedeckapp.com</p>
</body></html>"""
        requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {resend_key}', 'Content-Type': 'application/json'},
            json={'from': from_email, 'to': [ADMIN_EMAIL], 'subject': f'Shield Complete \u2014 Job #{job_id_str} ({score}%)', 'html': html},
            timeout=15,
        )
        log.info('Completion email sent for job %s', packet.get('job_id'))
    except Exception:
        log.warning('Completion email failed', exc_info=True)


# ===========================================================================
# ROUTE 6 -- Stripe Webhook
# ===========================================================================
@shield_bp.route('/webhook', methods=['POST'])
def shield_stripe_webhook():
    payload    = request.data
    sig_header = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    event_id = event.get('id', '')
    evt_type = event['type']
    obj      = event['data']['object']

    try:
        already = _db().table('stripe_webhook_events').select('event_id').eq('event_id', event_id).limit(1).execute()
        if already.data:
            return jsonify({'received': True, 'duplicate': True})
    except Exception:
        pass

    if evt_type == 'customer.subscription.created':
        contractor_id = obj.get('metadata', {}).get('contractor_id')
        if contractor_id:
            _db().table('shield_subscriptions').insert({
                'contractor_id': contractor_id, 'stripe_customer_id': obj['customer'],
                'stripe_sub_id': obj['id'], 'status': 'active',
                'current_period_end': obj.get('current_period_end'),
            }).execute()
    elif evt_type == 'customer.subscription.updated':
        _db().table('shield_subscriptions').update({'status': obj['status'], 'current_period_end': obj.get('current_period_end')}).eq('stripe_sub_id', obj['id']).execute()
    elif evt_type in ('customer.subscription.deleted', 'customer.subscription.paused'):
        _db().table('shield_subscriptions').update({'status': 'cancelled'}).eq('stripe_sub_id', obj['id']).execute()
    elif evt_type == 'payment_intent.succeeded':
        meta   = obj.get('metadata', {})
        job_id = meta.get('job_id')
        if job_id and meta.get('product') == 'shield_per_job':
            # Activate the shield job — payment confirmed, webhook is source of truth
            _db().table('shield_jobs').update({
                'stripe_payment_id': obj['id'],
                'status':            'active',
                'activated_at':      utc_now_iso(),
            }).eq('job_id', job_id).eq('status', 'pending').execute()
            log.info('Shield job activated via webhook for job_id %s', job_id)
    elif evt_type == 'invoice.paid':
        # Subscription renewal — keep sub marked active
        sub_id = obj.get('subscription')
        if sub_id:
            _db().table('shield_subscriptions').update({
                'status':             'active',
                'current_period_end': obj.get('lines', {}).get('data', [{}])[0].get('period', {}).get('end'),
            }).eq('stripe_sub_id', sub_id).execute()

    try:
        _db().table('stripe_webhook_events').insert({'event_id': event_id, 'event_type': evt_type, 'processed_at': utc_now_iso()}).execute()
    except Exception:
        log.warning("Could not record webhook event %s", event_id)

    return jsonify({'received': True})
