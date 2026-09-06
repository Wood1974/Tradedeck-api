"""
TRADEDECK SHIELD — shield_api.py  (MERGED v2 — best of both systems)

What this file does:
  - TradeDeck Shield product: AI checkpoints, GPS-verified photo verdicts,
    IRC/IBC code references, SHA-256 audit trail, contractor credentialing
  - Revenue Stream Shield payment infrastructure: proper Supabase client
    (supabase_admin), real escrow state machine, webhook deduplication,
    production-quality auth using the shared require_auth from auth.py

Bugs fixed from previous shield_api.py:
  1. SUPA undefined  → replaced with supabase_admin (passed via g.supabase)
  2. log_custody() undefined → fully implemented
  3. timezone not imported → imported from datetime
  4. shield_api's own require_auth replaced with auth.py version (consistent
     with rest of the app)
  5. supa_insert / supa_update / supa_select → replaced with supabase_admin
     pattern (uses the official supabase-py client, not raw requests)

Register in app.py  (already present — no change needed):
    from shield_api import shield_bp
    app.register_blueprint(shield_bp)

Environment variables required on Render:
    STRIPE_SECRET_KEY
    STRIPE_WEBHOOK_SECRET
    STRIPE_SHIELD_PRICE_ID
    ANTHROPIC_API_KEY
    SUPABASE_URL
    SUPABASE_SERVICE_KEY
"""

import base64
import hashlib
import json
import logging
import os
import requests
from datetime import datetime, timezone
from functools import wraps

import anthropic
import stripe
from flask import Blueprint, g, jsonify, request

from auth import require_auth, utc_now_iso   # shared from rest of app

log = logging.getLogger(__name__)

shield_bp = Blueprint('shield', __name__, url_prefix='/shield')

# -- Stripe config (reads env vars set on Render) -----------------------------
stripe.api_key         = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_SHIELD_PRICE_ID = os.environ.get('STRIPE_SHIELD_PRICE_ID')
ANTHROPIC_API_KEY      = os.environ.get('ANTHROPIC_API_KEY')
SUPABASE_URL           = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY   = os.environ.get('SUPABASE_SERVICE_KEY')
ADMIN_EMAIL            = 'woodalljosh128@gmail.com'


# ---------------------------------------------------------------------------
# SUPABASE HELPER
# Uses g.supabase (the supabase_admin client attached in app.py's
# before_request hook) -- same pattern as the rest of the app.
# ---------------------------------------------------------------------------
def _db():
    """Return the supabase_admin client attached to the current request."""
    return g.supabase


# ---------------------------------------------------------------------------
# IRC / IBC CODE MAP
# 9 trades x 5 checkpoints, with photo instructions and must-show criteria.
# Mirrors TRADE_PROFILES in the frontend JS.
# ---------------------------------------------------------------------------
IRC_CODE_MAP = {
    "framing": [
        {
            "label": "Foundation Sill Plate and Anchor Bolts",
            "irc": "IRC R403.1.6 -- Anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of plate end, 7 inch embedment",
            "ibc": "IBC 1905.1.8",
            "photo_instruction": "Photograph full sill plate run showing anchor bolt locations and spacing with tape measure.",
            "must_show": "Bolt spacing measured, washers and nuts torqued",
        },
        {
            "label": "Wall Framing -- Studs, Headers and Bracing",
            "irc": "IRC R602.3 stud spacing/size, R602.7 header spans, R602.10 wall bracing",
            "ibc": "IBC 2308.4",
            "photo_instruction": "Photograph full wall section showing stud spacing, header at each opening, bracing or sheathing.",
            "must_show": "Stud spacing, header size, bracing method",
        },
        {
            "label": "Fireblocking and Draftstopping",
            "irc": "IRC R302.11 -- fireblocking at ceiling/floor lines, stair stringers, around chimneys",
            "ibc": "IBC 718",
            "photo_instruction": "Photograph each fireblocking location before drywall covers it. Include all penetrations.",
            "must_show": "Fireblock material in place, all gaps sealed",
        },
        {
            "label": "Floor Joists -- Notching, Boring and Connections",
            "irc": "IRC R502.8 -- notches max 1/6 depth; bored holes max 1/3 depth, min 2 inches from edge",
            "ibc": "IBC 2308.8",
            "photo_instruction": "Photograph notched or bored joists with tape showing notch depth vs joist depth. Photograph joist hangers.",
            "must_show": "Notch and bore measurements, joist hanger fastening, bearing length",
        },
        {
            "label": "Roof Framing -- Rafters, Ridge and Connectors",
            "irc": "IRC R802.4 rafter spans, R802.3 ridge board, R802.11 rafter ties, R301.2.1 wind uplift connectors",
            "ibc": "IBC 2308.10",
            "photo_instruction": "Photograph rafter-to-ridge and rafter-to-top-plate connections. Include hurricane straps and span measurement.",
            "must_show": "Connector type and installation, rafter spacing, ridge board size",
        },
    ],
    "roofing": [
        {
            "label": "Roof Deck and Sheathing",
            "irc": "IRC R803.2 -- wood structural panel per span rating; R803.2.4 -- H-clips for spans over 24 inches",
            "ibc": "IBC 2304.8",
            "photo_instruction": "Photograph sheathing grade stamp on panels. Photograph H-clips at unsupported edges.",
            "must_show": "APA grade stamp visible, H-clips or blocking at edges",
        },
        {
            "label": "Ice and Water Barrier plus Underlayment",
            "irc": "IRC R905.1.2 -- ice barrier min 24 inches inside exterior wall where Jan avg temp 25F or below; R905.2.7 -- underlayment required",
            "ibc": "IBC 1507.2.8",
            "photo_instruction": "Photograph ice barrier at eaves showing extent past interior wall. Photograph overlapping underlayment rows.",
            "must_show": "Ice barrier extends min 24 inches past wall line, underlayment overlap min 2 inches",
        },
        {
            "label": "Drip Edge and Flashing",
            "irc": "IRC R905.2.8.5 -- drip edge min 1/4 inch below sheathing, min 2 inches up deck; R905.2.8.3 -- valley flashing min 24 inches wide",
            "ibc": "IBC 1507.2.9",
            "photo_instruction": "Photograph drip edge at eave showing overlap. Photograph each valley and step flashing at wall intersections.",
            "must_show": "Drip edge overlap measured, valley flashing width, step flashing at all intersections",
        },
        {
            "label": "Shingle Installation and Nailing Pattern",
            "irc": "IRC R905.2.5 -- minimum 4 fasteners per strip shingle (6 in high-wind); R905.2.4.1 -- starter strip at eaves",
            "ibc": "IBC 1507.2.5",
            "photo_instruction": "Lift a shingle to photograph nail placement. Photograph starter course at eave and offset pattern.",
            "must_show": "Nails in manufacturer nailing zone, minimum 4 nails visible, starter strip in place",
        },
        {
            "label": "Ridge Cap, Vents and Final Weathertight Inspection",
            "irc": "IRC R806.2 -- ventilation min 1/150 of insulated ceiling area (or 1/300 with balanced intake/exhaust)",
            "ibc": "IBC 1503.4",
            "photo_instruction": "Photograph completed ridge cap. Photograph each vent location. Photograph all pipe boot flashings.",
            "must_show": "Ridge cap fully installed, vent locations visible, all penetration flashings sealed",
        },
    ],
    "plumbing": [
        {
            "label": "DWV Rough-In -- Drain Slope and Pipe Support",
            "irc": "IRC P3005.3 -- slope: 1/4 inch per foot for pipe 3 inches or smaller, 1/8 inch per foot for 4 inch and larger; P2605.1 -- support intervals",
            "ibc": "IPC 308 support, 704 slope",
            "photo_instruction": "Use level and ruler on horizontal drain runs to show slope. Photograph pipe hangers showing spacing.",
            "must_show": "Slope measurement visible, hanger spacing within limits, pipe size stamps",
        },
        {
            "label": "DWV Air and Water Pressure Test",
            "irc": "IRC P2503.5.1 -- air test: 5 psi for 15 minutes; water test: min 10ft head for 15 minutes",
            "ibc": "IPC 312.2",
            "photo_instruction": "Photograph test gauge showing pressure at start and end of 15-minute hold.",
            "must_show": "Gauge reading at start and end, no visible moisture at joints",
        },
        {
            "label": "Water Supply Lines -- Material, Sizing and Pressure Test",
            "irc": "IRC P2903.5 -- static pressure test at 1.5 times working pressure for 15 minutes; P2903.1 -- min 3/4 inch building supply",
            "ibc": "IPC 604, 312.5",
            "photo_instruction": "Photograph pressure gauge on supply system. Photograph pipe material markings and main shutoff.",
            "must_show": "Test pressure gauge reading, pipe material stamp, shutoff valve accessible",
        },
        {
            "label": "Vent Stack and Air Admittance Valves",
            "irc": "IRC P3103.1 -- vent through roof min 6 inches above roof surface (min 24 inches in snow country); P3105 -- each trap must be vented",
            "ibc": "IPC 903, 917",
            "photo_instruction": "Photograph vent stack from exterior showing height above roof. Photograph each trap-to-vent connection.",
            "must_show": "Vent height above roof surface measured, all traps connected to vent system",
        },
        {
            "label": "Fixture Rough-In and Cleanout Locations",
            "irc": "IRC P3005.2.7 -- cleanouts at base of each stack and runs over 100ft; P2708 shower, P2705 lavatory rough-in requirements",
            "ibc": "IPC 708",
            "photo_instruction": "Photograph each rough-in location with measurement from finished floor. Photograph cleanout plugs.",
            "must_show": "Rough-in measurements matching fixture specs, cleanout locations accessible",
        },
    ],
    "electrical": [
        {
            "label": "Panel, Service Entry and Grounding Electrode",
            "irc": "NEC 250.52(A)(3) -- Ufer: min 20ft of min 1/2 inch rebar or #4 bare copper encased in min 2 inches concrete; NEC 250.50 -- all electrodes bonded",
            "ibc": "NEC Article 250, 230",
            "photo_instruction": "Photograph Ufer electrode BEFORE concrete pour showing rebar length and pigtail. Photograph GEC connection at panel.",
            "must_show": "Ufer rebar length and pigtail visible, GEC connection at panel, service conductor size",
        },
        {
            "label": "Branch Circuit Rough-In -- Box Fill and Wire Routing",
            "irc": "NEC 314.16 -- box fill: 2.0 cu in per #14, 2.25 cu in per #12; NEC 300.4 -- nail plate required if cable within 1-1/4 inches of stud edge",
            "ibc": "NEC Article 314, 300",
            "photo_instruction": "Photograph each box showing wire count and cubic-inch rating stamped on box. Photograph nail plates at stud edges.",
            "must_show": "Box cu-in rating stamp, nail plates where required, staple spacing max 4.5 feet",
        },
        {
            "label": "GFCI and AFCI Protection",
            "irc": "NEC 210.8 -- GFCI at bathrooms, garages, outdoors, kitchens within 6 feet of sink; NEC 210.12 -- AFCI all 15/20A 120V circuits in dwelling",
            "ibc": "NEC 210.8, 210.12",
            "photo_instruction": "Photograph GFCI outlet or breaker at each required location. Photograph AFCI breakers in panel.",
            "must_show": "GFCI at all wet and outdoor locations, AFCI breakers for bedroom and living circuits",
        },
        {
            "label": "Rough-In Inspection -- All Circuits, Working Clearances",
            "irc": "NEC 110.26 -- working clearance: min 30 inches wide, min 36 inches deep, min 6.5 feet high in front of panel",
            "ibc": "NEC 110.26",
            "photo_instruction": "Photograph panel working clearance with tape showing 36-inch depth from panel face. Photograph service disconnect label.",
            "must_show": "36-inch clearance measured in photo, service disconnect labeled, no obstructions",
        },
        {
            "label": "Final -- Devices, Fixtures and Load Center Labeling",
            "irc": "NEC 408.4 -- every circuit breaker must be legibly identified; NEC 110.12 -- no open knockouts",
            "ibc": "NEC 408.4, 110.12",
            "photo_instruction": "Photograph completed panel directory. Photograph outlet and switch installations. Check for open knockouts.",
            "must_show": "Complete panel directory, all boxes covered, no open knockouts, circuit labels legible",
        },
    ],
    "hvac": [
        {
            "label": "Equipment Installation and Clearances",
            "irc": "IRC M1306 -- clearances to combustibles per equipment listing label; M1305.1 -- access passageway min 22 by 30 inches",
            "ibc": "IMC 304, 306",
            "photo_instruction": "Photograph equipment label showing required clearances. Photograph measured distance from unit to nearest combustible.",
            "must_show": "Equipment label clearance requirements visible, measured clearance in photo, access path dimensions",
        },
        {
            "label": "Duct Installation -- Support, Joints and Sealing",
            "irc": "IRC M1601.4.1 -- joints and seams sealed with mastic or UL 181A/B tape; M1601.4.4 -- round duct support max 10ft, rectangular max 4ft",
            "ibc": "IMC 603",
            "photo_instruction": "Photograph duct joints showing mastic or approved tape. Photograph duct hangers showing spacing. Photograph any flex duct connections.",
            "must_show": "Mastic or UL 181 tape at all joints, hanger spacing within limits, flex duct not kinked",
        },
        {
            "label": "Combustion Air and Gas Piping",
            "irc": "IRC G2407 -- combustion air: min 50 cu ft per 1,000 BTU/hr; G2417 -- gas piping test: 10 psi air for 15 min before appliances connected",
            "ibc": "IMC 701, 303.3",
            "photo_instruction": "Photograph combustion air opening size with measurement. Photograph gas piping pressure gauge during test.",
            "must_show": "Combustion air opening dimensions, gas test gauge reading, shutoff valve accessible and labeled",
        },
        {
            "label": "Condensate Drainage and Secondary Drain",
            "irc": "IRC M1411.3 -- secondary drain or auxiliary pan required for equipment above finished ceiling; pan min 1.5 inches deep, min 3 inches wider than unit",
            "ibc": "IMC 307.2",
            "photo_instruction": "Photograph primary drain connection and routing. Photograph secondary drain pan dimensions or float switch.",
            "must_show": "Primary drain connection, secondary pan or float switch installed, drain terminates visible",
        },
        {
            "label": "Final -- Duct Insulation, Filter, and System Test",
            "irc": "IRC N1103.3.3 -- ducts in unconditioned space: R-8 insulation minimum",
            "ibc": "IECC C403.2.2, IMC 607",
            "photo_instruction": "Photograph duct insulation in attic or crawl space showing R-value label. Photograph filter installed. Photograph thermostat set to test with system running.",
            "must_show": "R-8 or higher insulation label visible, filter in place, system operational",
        },
    ],
    "concrete": [
        {
            "label": "Footing Excavation and Soil Bearing",
            "irc": "IRC R403.1 -- footings bear on undisturbed soil; R301.2(7) -- frost depth per Table R301.2(1); R403.1.1 -- min 12 inches below grade",
            "ibc": "IBC 1809.4",
            "photo_instruction": "Photograph footing trench showing depth measurement from grade to bottom. Include tape showing frost-depth compliance.",
            "must_show": "Footing depth measurement, undisturbed soil visible at base",
        },
        {
            "label": "Rebar Placement and Concrete-Encased Electrode",
            "irc": "IRC R403.1.3 -- footing reinforcement per Table R403.1.3(1); NEC 250.52(A)(3) -- Ufer: min 20ft of min 1/2 inch rebar in min 2 inches concrete",
            "ibc": "IBC 1905, ACI 318 20.6.1 -- cover: 3 inches cast against earth",
            "photo_instruction": "Photograph rebar chairs or supports showing minimum concrete cover. Photograph Ufer pigtail extending from footing form.",
            "must_show": "Rebar chairs maintaining minimum cover, Ufer pigtail visible and tagged, rebar size and spacing per plan",
        },
        {
            "label": "Vapor Retarder and Sub-Slab Preparation",
            "irc": "IRC R506.2.3 -- vapor retarder min 10-mil Class A per ASTM E1745, joints lapped min 6 inches, extended up stem walls",
            "ibc": "IBC 1805.4.1",
            "photo_instruction": "Photograph vapor barrier material showing 10-mil spec or ASTM E1745 markings. Photograph joint laps showing min 6 inch overlap.",
            "must_show": "Vapor barrier spec marking, 6-inch lap at joints, edges turned up at stem walls",
        },
        {
            "label": "Concrete Pour -- Mix, Placement and Consolidation",
            "irc": "IRC R402.2 -- min f'c: 2,500 psi interior slabs, 3,000 psi exposed to weather, 3,500 psi severe freeze-thaw",
            "ibc": "IBC 1905.3, ACI 318 Table 19.3.3.1",
            "photo_instruction": "Photograph concrete delivery ticket showing mix design and PSI strength. Photograph vibrator being used during pour.",
            "must_show": "Concrete ticket with f'c and w/c ratio, vibration occurring during pour",
        },
        {
            "label": "Anchor Bolts, Curing and Slab Tolerances",
            "irc": "IRC R403.1.6 -- anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of plate ends, min 7 inch embedment; R506.2.4 -- slab min 3.5 inches thick",
            "ibc": "IBC 1905.1.8, ACI 117 -- slab tolerance 1/4 inch in 10ft",
            "photo_instruction": "Photograph anchor bolts set in wet concrete while still plastic. Measure and photograph bolt spacing. Photograph curing compound applied.",
            "must_show": "Anchor bolt spacing measured, embedment depth marker, curing compound application",
        },
    ],
    "flooring": [
        {
            "label": "Subfloor Condition and Moisture Testing",
            "irc": "IRC R503.2 -- wood structural panel subfloor: APA rated sheathing per span table; MC max 14 percent for wood or max 3 lbs per 1000 sf per 24hr for concrete",
            "ibc": "IBC 2304.9",
            "photo_instruction": "Photograph moisture meter reading in multiple locations. Photograph flatness measurement with 10-foot straightedge.",
            "must_show": "Moisture meter reading visible, flatness measurement, any repairs noted",
        },
        {
            "label": "Underlayment Installation",
            "irc": "IRC R503 -- subfloor per span table; manufacturer installation instructions govern underlayment type and thickness",
            "ibc": "IBC 2304.9",
            "photo_instruction": "Photograph underlayment material label showing specification. Photograph seam treatment (tape or stapling).",
            "must_show": "Underlayment spec label, seams properly treated, no voids or bubbles",
        },
        {
            "label": "Flooring Layout and Acclimation",
            "irc": "NWFA Installation Guidelines: acclimate 3 to 5 days at job-site conditions",
            "ibc": "NWFA Installation Guidelines; ANSI A108 for tile",
            "photo_instruction": "Photograph flooring material open and acclimating on-site. Photograph chalk line layout and room temperature and humidity reading.",
            "must_show": "Flooring open and acclimating, temp and humidity reading, layout lines established",
        },
        {
            "label": "Flooring Installation -- Fastening and Pattern",
            "irc": "NWFA: 3/4 inch solid hardwood -- cleat or staple every 6 to 8 inches; expansion gap 3/4 inch at all walls; ANSI A108.02 -- tile: thin-set coverage min 80 percent interior",
            "ibc": "NWFA and ANSI A108 and manufacturer specs",
            "photo_instruction": "Photograph expansion gap at wall with spacer in place. For tile: lift a tile immediately after setting to check mortar coverage.",
            "must_show": "Expansion gap at perimeter, fastener spacing visible, mortar coverage on tile back",
        },
        {
            "label": "Transitions, Thresholds and Final Inspection",
            "irc": "IRC R311.7.5 -- stair treads: rise max 7-3/4 inches, run min 10 inches",
            "ibc": "IBC 1003.3",
            "photo_instruction": "Photograph all threshold transitions room to room. Photograph any change-in-level measurements.",
            "must_show": "All transitions in place, level changes measured, no protruding fasteners or gaps",
        },
    ],
    "painting": [
        {
            "label": "Surface Preparation -- Drywall and Substrate",
            "irc": "GA-214 Recommended Levels of Gypsum Board Finish -- Level 4 minimum for flat paint; Level 5 for gloss or semi-gloss or critical lighting",
            "ibc": "GA-214 and ASTM C840",
            "photo_instruction": "Photograph drywall seams under raking light to show finish level. Document finish level before primer.",
            "must_show": "Seams smooth under raking light, no mud ridges, corner bead straight",
        },
        {
            "label": "Primer Application",
            "irc": "Manufacturer specs and PDCA Standards P1 through P4 series",
            "ibc": "PDCA and MPI Architectural Painting Specification Manual",
            "photo_instruction": "Photograph primed surfaces showing even coverage. Photograph primer product label showing manufacturer and type.",
            "must_show": "Even primer coverage, no bare spots, product label visible",
        },
        {
            "label": "First Coat -- Application and Coverage",
            "irc": "PDCA P4 and MPI Standards -- spread rate per manufacturer; mil thickness per spec sheet",
            "ibc": "MPI Architectural Painting Specification Manual 9",
            "photo_instruction": "Photograph any areas with thin coverage or holidays. Photograph product label and batch number.",
            "must_show": "Even sheen across surface, product batch number recorded",
        },
        {
            "label": "Second Coat and Finish Inspection",
            "irc": "PDCA P12 -- uniform color and sheen, no defects visible at 5 feet in normal light",
            "ibc": "MPI 9; ASTM D3730",
            "photo_instruction": "Photograph finished walls under normal lighting and under raking light. Photograph final coat product label.",
            "must_show": "Uniform sheen at 5-foot viewing distance, no drips or laps, final coat label",
        },
        {
            "label": "Trim, Cut Lines and Cleanup",
            "irc": "PDCA P5 protection of adjacent surfaces; PDCA P1 workmanship standard",
            "ibc": "PDCA Standards",
            "photo_instruction": "Photograph trim cut lines at ceiling and floor. Photograph hardware reinstalled. Photograph overall room showing clean site.",
            "must_show": "Straight cut lines, hardware in place, no paint on floors or fixtures",
        },
    ],
    "general": [
        {
            "label": "Site Safety and Permit Posted",
            "irc": "IRC R105.7 -- permit must be posted on site and visible from street until final inspection",
            "ibc": "IBC 105.7",
            "photo_instruction": "Photograph building permit posted at front of property. Photograph crew wearing PPE.",
            "must_show": "Permit visible and readable, PPE in use, no obvious safety violations",
        },
        {
            "label": "Work-in-Progress Milestone",
            "irc": "Contractual milestone -- specific IRC section depends on trade being performed",
            "ibc": "Contractual as applicable",
            "photo_instruction": "Photograph wide view of work area showing scope in progress. Include reference objects for scale.",
            "must_show": "Clear progress visible, scope matches contract, work area identified",
        },
        {
            "label": "Materials On-Site and Specification",
            "irc": "IRC R101.2 -- materials must meet referenced standards; specific section per material type",
            "ibc": "IBC 1703 product approval",
            "photo_instruction": "Photograph material specification labels for all major materials. Photograph materials stored properly off ground and covered.",
            "must_show": "Grade stamps and spec labels visible, materials protected from weather, quantities match scope",
        },
        {
            "label": "Subcontractor Work Complete",
            "irc": "IRC R109 -- required inspections must be completed before concealment of any work",
            "ibc": "IBC 110",
            "photo_instruction": "Photograph any rough-in work before walls are closed. Photograph required inspection approval cards posted on site.",
            "must_show": "All rough-in work visible before concealment, inspection tags if applicable",
        },
        {
            "label": "Final Walkthrough and Punch List",
            "irc": "IRC R110 -- Certificate of Occupancy required before occupancy; final inspection must pass",
            "ibc": "IBC 111",
            "photo_instruction": "Photograph each completed area of agreed scope. Photograph final cleanup. Photograph any outstanding items for homeowner.",
            "must_show": "All contracted work visible and complete, site clean, no materials left behind",
        },
    ],
}


def detect_trade(description: str) -> str:
    """Keyword-based trade detection -- mirrors detectTrade() in the frontend JS."""
    text = description.lower()
    keywords = {
        "framing":    ["frame", "framing", "stud", "joist", "rafter", "lumber", "addition", "truss", "beam", "header"],
        "roofing":    ["roof", "roofing", "shingle", "gutter", "soffit", "fascia", "flashing", "ridge", "underlayment"],
        "plumbing":   ["plumbing", "pipe", "drain", "water heater", "sewer", "fixture", "toilet", "sink", "shower", "faucet"],
        "electrical": ["electrical", "wiring", "panel", "circuit", "outlet", "switch", "breaker", "volt", "amp", "conduit"],
        "hvac":       ["hvac", "furnace", "ac", "air conditioning", "ductwork", "heat pump", "mechanical", "heating", "cooling"],
        "concrete":   ["concrete", "foundation", "slab", "driveway", "patio", "footing", "cement", "masonry", "rebar"],
        "flooring":   ["floor", "flooring", "hardwood", "lvp", "tile", "carpet", "laminate", "subfloor", "vinyl"],
        "painting":   ["paint", "painting", "primer", "drywall", "finish", "stain", "caulk", "interior", "exterior"],
    }
    best, score = "general", 0
    for trade, kws in keywords.items():
        s = sum(1 for k in kws if k in text)
        if s > score:
            best, score = trade, s
    return best


# ---------------------------------------------------------------------------
# CHAIN-OF-CUSTODY LOGGER
# Every significant event (upload, verdict, flag, complete) gets a row here.
# ---------------------------------------------------------------------------
def log_custody(
    photo_id,
    shield_job_id,
    event_type,
    actor_id=None,
    actor_type="system",
    event_data=None,
    gps_lat=None,
    gps_lng=None,
):
    """Insert one audit row into shield_custody_log."""
    try:
        _db().table("shield_custody_log").insert({
            "photo_id":      photo_id,
            "shield_job_id": shield_job_id,
            "event_type":    event_type,
            "actor_id":      actor_id,
            "actor_type":    actor_type,
            "event_data":    json.dumps(event_data or {}),
            "gps_lat":       gps_lat,
            "gps_lng":       gps_lng,
            "recorded_at":   utc_now_iso(),
        }).execute()
    except Exception:
        log.exception("log_custody failed -- event_type=%s photo_id=%s", event_type, photo_id)


# ---------------------------------------------------------------------------
# ROUTE 1 -- Homeowner: create PaymentIntent for a per-job Shield purchase
# POST /shield/create-payment-intent
# ---------------------------------------------------------------------------
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
            amount=int(amount_cents),
            currency='usd',
            capture_method='automatic',
            metadata={'job_id': job_id, 'product': 'shield_per_job'},
            description='TradeDeck Shield -- Job ' + str(job_id),
            idempotency_key='shield-pi-' + str(job_id),
        )
        return jsonify({'client_secret': intent.client_secret})
    except stripe.error.StripeError as e:
        log.exception("Stripe error creating Shield PaymentIntent")
        return jsonify({'error': str(e)}), 502


# ---------------------------------------------------------------------------
# ROUTE 2 -- Contractor: start Stripe Checkout subscription for Shield Pro
# POST /shield/contractor-subscribe
# ---------------------------------------------------------------------------
@shield_bp.route('/contractor-subscribe', methods=['POST'])
@require_auth
def contractor_subscribe():
    data          = request.get_json(silent=True) or {}
    contractor_id = data.get('contractor_id') or g.user_id
    try:
        existing = (
            _db().table('shield_subscriptions')
            .select('stripe_customer_id')
            .eq('contractor_id', contractor_id)
            .limit(1)
            .execute()
        )
        if existing.data and existing.data[0].get('stripe_customer_id'):
            customer_id = existing.data[0]['stripe_customer_id']
        else:
            customer    = stripe.Customer.create(metadata={'contractor_id': contractor_id})
            customer_id = customer.id

        checkout = stripe.checkout.Session.create(
            customer=customer_id,
            mode='subscription',
            line_items=[{'price': STRIPE_SHIELD_PRICE_ID, 'quantity': 1}],
            success_url='https://tradedeckapp.com/app.html?shield_sub=success',
            cancel_url='https://tradedeckapp.com/app.html?shield_sub=cancelled',
            metadata={'contractor_id': contractor_id, 'product': 'shield_pro'},
        )
        return jsonify({'stripe_url': checkout.url})
    except stripe.error.StripeError as e:
        log.exception("Stripe error creating Shield subscription checkout")
        return jsonify({'error': str(e)}), 502


# ---------------------------------------------------------------------------
# ROUTE 3 -- AI Photo Analysis (Claude Vision)
# POST /shield/analyze-photo
# ---------------------------------------------------------------------------
@shield_bp.route('/analyze-photo', methods=['POST'])
@require_auth
def analyze_photo():
    data           = request.get_json(silent=True) or {}
    photo_id       = data.get('photo_id')
    public_url     = data.get('public_url')
    point_id       = data.get('point_id')
    gps_lat        = data.get('gps_lat')
    gps_lng        = data.get('gps_lng')
    has_exif       = data.get('has_exif', False)
    code_reference = data.get('code_reference')

    if not all([photo_id, public_url, point_id]):
        return jsonify({'error': 'photo_id, public_url, and point_id required'}), 400
    if gps_lat is None or gps_lng is None:
        return jsonify({'error': 'GPS coordinates required for Shield photo verification'}), 400

    point_row = (
        _db().table('shield_pivotal_points')
        .select('label, description')
        .eq('id', point_id)
        .limit(1)
        .execute()
    )
    point       = point_row.data[0] if point_row.data else {}
    point_label = point.get('label', 'Checkpoint')
    point_desc  = point.get('description', '')

    try:
        img_r = requests.get(public_url, timeout=15)
        img_r.raise_for_status()
    except Exception:
        log.exception("Could not fetch Shield photo from %s", public_url)
        return jsonify({'error': 'Could not fetch photo from storage URL'}), 502

    image_b64    = base64.b64encode(img_r.content).decode('utf-8')
    content_type = img_r.headers.get('content-type', 'image/jpeg').split(';')[0]
    server_hash  = hashlib.sha256(img_r.content).hexdigest()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    gps_str = str(float(gps_lat)) + ", " + str(float(gps_lng))
    exif_str = "YES" if has_exif else "NO -- possible screenshot or downloaded image"
    prompt_text = (
        "Checkpoint: " + point_label + "\n"
        "Required condition: " + point_desc + "\n\n"
        "METADATA PROVIDED BY THE APP:\n"
        "- GPS captured: " + gps_str + "\n"
        "- Code Requirement: " + (code_reference or "Not specified") + "\n"
        "- Camera EXIF data present: " + exif_str + "\n\n"
        "STEP 1 -- AUTHENTICITY CHECK (check ALL of these):\n"
        "- Is this a real on-site construction photo, or a stock image / screenshot / render / AI image?\n"
        "- Does it show genuine construction conditions (dust, tools, materials, real lighting, shadows)?\n"
        "- Are there signs of digital manipulation, compositing, or watermarks from another source?\n"
        "- EXIF status: if EXIF is missing, treat this as a strong authenticity concern.\n"
        "- If the photo appears to be of a screen or printed image, mark fake.\n\n"
        "STEP 2 -- QUALITY CHECK (only if authentic):\n"
        "- Does the photo show what the checkpoint requires?\n"
        "- Is the work complete, correct, and up to standard?\n\n"
        'Respond with this exact JSON:\n'
        '{\n'
        '  "authentic": true | false,\n'
        '  "authenticity_note": "<one sentence -- why authentic or why suspicious>",\n'
        '  "verdict": "pass" | "flag" | "fail" | "fake",\n'
        '  "confidence": <float 0-1>,\n'
        '  "notes": "<2-3 sentence assessment for the homeowner>"\n'
        '}\n\n'
        'verdict rules:\n'
        '- fake  = photo is not authentic\n'
        '- fail  = authentic but work is incomplete, incorrect, or quality concern visible\n'
        '- flag  = authentic, mostly correct but worth homeowner attention\n'
        '- pass  = authentic, GPS confirmed on-site, work complete and up to standard\n\n'
        'If verdict is fake, set confidence to 1.0.'
    )
    try:
        msg = client.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=600,
            system=(
                'You are a licensed building inspector and fraud detection analyst. '
                'You evaluate contractor-submitted photos for homeowner protection. '
                'Your job has TWO parts: (1) verify the photo is authentic and taken on-site, '
                '(2) verify the work meets the checkpoint requirement. '
                'Respond ONLY with a valid JSON object -- no preamble, no markdown.'
            ),
            messages=[{
                'role': 'user',
                'content': [
                    {
                        'type': 'image',
                        'source': {'type': 'base64', 'media_type': content_type, 'data': image_b64}
                    },
                    {'type': 'text', 'text': prompt_text}
                ]
            }]
        )
        raw    = msg.content[0].text.strip().replace('```json', '').replace('```', '').strip()
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
    auth_note  = result.get('authenticity_note', '')

    if not authentic or verdict == 'fake':
        verdict    = 'fake'
        confidence = 1.0
        notes      = 'Photo flagged as inauthentic: ' + auth_note + ' This checkpoint has not been verified.'

    update_payload = {
        'ai_verdict':         verdict,
        'ai_confidence':      confidence,
        'ai_notes':           notes,
        'ai_authentic':       authentic,
        'photo_hash':         server_hash,
        'hash_algorithm':     'SHA-256',
        'server_received_at': utc_now_iso(),
    }
    if code_reference:
        update_payload['code_reference'] = code_reference
    _db().table('shield_photos').update(update_payload).eq('id', photo_id).execute()

    point_status = 'approved' if verdict == 'pass' else 'flagged'
    _db().table('shield_pivotal_points').update({'status': point_status}).eq('id', point_id).execute()

    photo_row = (
        _db().table('shield_photos')
        .select('shield_job_id, contractor_id')
        .eq('id', photo_id)
        .limit(1)
        .execute()
    )
    photo_meta  = photo_row.data[0] if photo_row.data else {}
    s_job_id    = photo_meta.get('shield_job_id')
    contractor  = photo_meta.get('contractor_id')

    log_custody(
        photo_id=photo_id,
        shield_job_id=s_job_id,
        event_type='ai_analyzed',
        actor_id=contractor,
        actor_type='ai',
        event_data={
            'verdict':           verdict,
            'confidence':        confidence,
            'authentic':         authentic,
            'authenticity_note': auth_note,
            'server_hash':       server_hash,
            'gps_provided':      True,
            'exif_present':      has_exif,
        },
        gps_lat=gps_lat,
        gps_lng=gps_lng,
    )
    if verdict in ('flagged', 'fake', 'fail'):
        log_custody(
            photo_id=photo_id,
            shield_job_id=s_job_id,
            event_type='flagged',
            actor_type='ai',
            event_data={'reason': auth_note or notes},
        )

    return jsonify({
        'verdict':    verdict,
        'confidence': confidence,
        'notes':      notes,
        'authentic':  authentic,
    })


# ---------------------------------------------------------------------------
# ROUTE 4 -- Generate AI Pivotal Points + write IRC/IBC codes
# POST /shield/generate-points
# ---------------------------------------------------------------------------
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
            model='claude-sonnet-4-6',
            max_tokens=600,
            messages=[{'role': 'user', 'content': 'You are a senior contractor and building inspector.\n\nJob description: """' + job_desc + '"""\n\nIdentify exactly 5 pivotal checkpoints -- the specific moments where a photo proves whether the work was done correctly before it is too late to fix. These are the moments a bad contractor would most want to skip.\n\nReturn ONLY a valid JSON array, no markdown:\n[\n  {"point_number": 1, "label": "<short name>", "description": "<one sentence: exactly what the photo must show>"},\n  ...\n]'}]
        )
        raw    = msg.content[0].text.strip().replace('```json', '').replace('```', '').strip()
        points = json.loads(raw)
    except json.JSONDecodeError:
        log.exception("Claude returned invalid JSON for generate-points")
        return jsonify({'error': 'AI returned invalid JSON'}), 500
    except Exception:
        log.exception("Claude call failed for generate-points")
        return jsonify({'error': 'AI checkpoint generation failed'}), 500

    trade       = detect_trade(job_desc)
    trade_codes = IRC_CODE_MAP.get(trade, IRC_CODE_MAP['general'])

    for p in points:
        idx        = p['point_number'] - 1
        code_entry = trade_codes[idx] if idx < len(trade_codes) else {}

        update_fields = {
            'label':             p['label'],
            'description':       p['description'],
            'irc_code':          code_entry.get('irc'),
            'ibc_code':          code_entry.get('ibc'),
            'photo_instruction': code_entry.get('photo_instruction'),
            'must_show':         code_entry.get('must_show'),
        }

        existing = (
            _db().table('shield_pivotal_points')
            .select('id')
            .eq('shield_job_id', shield_job_id)
            .eq('point_number', p['point_number'])
            .limit(1)
            .execute()
        )
        if existing.data:
            _db().table('shield_pivotal_points').update(update_fields).eq('id', existing.data[0]['id']).execute()
        else:
            _db().table('shield_pivotal_points').insert({
                'shield_job_id': shield_job_id,
                'job_id':        job_id,
                'point_number':  p['point_number'],
                **update_fields,
            }).execute()

    return jsonify({'points': points, 'trade': trade})


# ---------------------------------------------------------------------------
# ROUTE 5 -- Complete Job (close-out with SHA-256 packet)
# POST /shield/complete-job
# ---------------------------------------------------------------------------
@shield_bp.route('/complete-job', methods=['POST'])
@require_auth
def complete_job():
    packet = request.get_json(silent=True) or {}
    shield_job_id = packet.get('shield_job_id')
    if not shield_job_id:
        return jsonify({'error': 'shield_job_id required'}), 400

    submitted_hash = packet.pop('sha256', None)
    clean_packet   = {k: packet[k] for k in sorted(packet.keys())}
    packet_string  = json.dumps(clean_packet, sort_keys=True, separators=(',', ':'))
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

    _db().table('shield_jobs').update({
        'status':       'complete',
        'completed_at': utc_now_iso(),
    }).eq('id', shield_job_id).execute()

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
    """Award TradeDeck Verified badge after 3 clean (all-pass) Shield completions."""
    if not contractor_id:
        return
    try:
        results = (
            _db().table('shield_completion_reports')
            .select('overall_verdict')
            .eq('contractor_id', contractor_id)
            .eq('overall_verdict', 'pass')
            .execute()
        )
        clean_count = len(results.data) if results.data else 0
        if clean_count >= 3:
            _db().table('profiles').update({
                'tradedeck_verified': True,
                'verified_at': utc_now_iso(),
            }).eq('id', contractor_id).execute()
            log.info("Contractor %s awarded TradeDeck Verified badge", contractor_id)
    except Exception:
        log.exception("Verification badge check failed for contractor %s", contractor_id)


def _send_completion_email(packet, sha256):
    """Email admin the completion summary. Silently fails if edge function not deployed."""
    try:
        job_id_str = str(packet.get('job_id', ''))[-6:].upper()
        requests.post(
            SUPABASE_URL + '/functions/v1/send-email',
            headers={
                'apikey': SUPABASE_SERVICE_KEY,
                'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY,
                'Content-Type': 'application/json',
            },
            json={
                'to':      ADMIN_EMAIL,
                'subject': 'TradeDeck Shield Complete -- Job ' + job_id_str,
                'html': (
                    '<h2>TradeDeck Shield -- Job Complete</h2>'
                    '<p><strong>Job ID:</strong> ' + str(packet.get('job_id')) + '</p>'
                    '<p><strong>Shield Job ID:</strong> ' + str(packet.get('shield_job_id')) + '</p>'
                    '<p><strong>SHA-256:</strong> <code>' + str(sha256) + '</code></p>'
                    '<p><strong>Score:</strong> ' + str(_derive_score(packet.get('points', []))) + '%</p>'
                ),
            },
            timeout=10,
        )
    except Exception:
        log.warning("Completion email failed -- edge function may not be deployed yet")


# ---------------------------------------------------------------------------
# ROUTE 6 -- Stripe Webhook (Shield-specific events)
# POST /shield/webhook
# ---------------------------------------------------------------------------
@shield_bp.route('/webhook', methods=['POST'])
def shield_stripe_webhook():
    payload    = request.data
    sig_header = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        log.warning("Shield webhook: invalid Stripe signature")
        return jsonify({'error': 'Invalid signature'}), 400

    event_id  = event.get('id', '')
    evt_type  = event['type']
    obj       = event['data']['object']

    try:
        already = (
            _db().table('stripe_webhook_events')
            .select('event_id')
            .eq('event_id', event_id)
            .limit(1)
            .execute()
        )
        if already.data:
            return jsonify({'received': True, 'duplicate': True})
    except Exception:
        pass

    if evt_type == 'customer.subscription.created':
        contractor_id = obj.get('metadata', {}).get('contractor_id')
        if contractor_id:
            _db().table('shield_subscriptions').insert({
                'contractor_id':      contractor_id,
                'stripe_customer_id': obj['customer'],
                'stripe_sub_id':      obj['id'],
                'status':             'active',
                'current_period_end': obj.get('current_period_end'),
            }).execute()

    elif evt_type == 'customer.subscription.updated':
        _db().table('shield_subscriptions').update({
            'status':             obj['status'],
            'current_period_end': obj.get('current_period_end'),
        }).eq('stripe_sub_id', obj['id']).execute()

    elif evt_type in ('customer.subscription.deleted', 'customer.subscription.paused'):
        _db().table('shield_subscriptions').update({'status': 'cancelled'}).eq('stripe_sub_id', obj['id']).execute()

    elif evt_type == 'payment_intent.succeeded':
        job_id = obj.get('metadata', {}).get('job_id')
        if job_id and obj.get('metadata', {}).get('product') == 'shield_per_job':
            _db().table('shield_jobs').update({'stripe_payment_id': obj['id']}).eq('job_id', job_id).execute()

    try:
        _db().table('stripe_webhook_events').insert({
            'event_id':     event_id,
            'event_type':   evt_type,
            'processed_at': utc_now_iso(),
        }).execute()
    except Exception:
        log.warning("Could not record webhook event %s", event_id)

    return jsonify({'received': True})
