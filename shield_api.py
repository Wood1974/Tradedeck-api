"""
TRADEDECK SHIELD — shield_api.py (MERGED COMPLETE VERSION)
Add to your tradedeck-api repo alongside app.py.

Register in app.py:
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

import os, json, base64, hashlib, requests
import stripe
import anthropic
from flask import Blueprint, request, jsonify
from datetime import datetime

shield_bp = Blueprint('shield', __name__, url_prefix='/shield')

stripe.api_key         = os.environ.get('STRIPE_SECRET_KEY')
ANTHROPIC_API_KEY      = os.environ.get('ANTHROPIC_API_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_SHIELD_PRICE_ID = os.environ.get('STRIPE_SHIELD_PRICE_ID')
SUPABASE_URL           = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY   = os.environ.get('SUPABASE_SERVICE_KEY')
ADMIN_EMAIL            = 'woodalljosh128@gmail.com'

# ─────────────────────────────────────────────────
# SUPABASE HELPERS (service role — bypasses RLS)
# ─────────────────────────────────────────────────
def _headers():
    return {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
    }

def supa_insert(table, data):
    r = requests.post(f'{SUPABASE_URL}/rest/v1/{table}', headers=_headers(), json=data)
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else rows

def supa_update(table, match_col, match_val, data):
    r = requests.patch(
        f'{SUPABASE_URL}/rest/v1/{table}?{match_col}=eq.{match_val}',
        headers=_headers(), json=data
    )
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else rows

def supa_select(table, filters: dict):
    params = '&'.join(f'{k}=eq.{v}' for k, v in filters.items())
    r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{params}', headers=_headers())
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else None

# ─────────────────────────────────────────────────
# JWT VALIDATION
# Verifies the Supabase access token on every request.
# ─────────────────────────────────────────────────
def get_user_from_token():
    """Extract and verify the user from the Bearer token."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ', 1)[1]
    # Verify token against Supabase auth
    r = requests.get(
        f'{SUPABASE_URL}/auth/v1/user',
        headers={
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {token}'
        }
    )
    if r.status_code != 200:
        return None
    return r.json()

def require_auth(f):
    """Decorator — returns 401 if no valid token."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────
# IRC/IBC CODE MAP  (mirrors TRADE_PROFILES in JS)
# generate-points uses this to write code references
# ─────────────────────────────────────────────────
import json as _json
IRC_CODE_MAP = _json.loads("{\"framing\": [{\"label\": \"Foundation Sill Plate & Anchor Bolts\", \"irc\": \"IRC R403.1.6 \\u2014 Anchor bolts min 1/2\\\" dia., max 6ft o.c., within 12\\\" of plate end, 7\\\" embedment\", \"ibc\": \"IBC \\u00a71905.1.8\", \"photo_instruction\": \"Photograph full sill plate run showing anchor bolt locations and spacing with tape measure.\", \"must_show\": \"Bolt spacing measured, washers and nuts torqued\"}, {\"label\": \"Wall Framing \\u2014 Studs, Headers & Bracing\", \"irc\": \"IRC R602.3 stud spacing/size, R602.7 header spans, R602.10 wall bracing\", \"ibc\": \"IBC \\u00a72308.4\", \"photo_instruction\": \"Photograph full wall section showing stud spacing, header at each opening, bracing or sheathing.\", \"must_show\": \"Stud spacing, header size, bracing method\"}, {\"label\": \"Fireblocking & Draftstopping\", \"irc\": \"IRC R302.11 \\u2014 fireblocking at ceiling/floor lines, stair stringers, around chimneys\", \"ibc\": \"IBC \\u00a7718\", \"photo_instruction\": \"Photograph each fireblocking location before drywall covers it. Include all penetrations.\", \"must_show\": \"Fireblock material in place, all gaps sealed\"}, {\"label\": \"Floor Joists \\u2014 Notching, Boring & Connections\", \"irc\": \"IRC R502.8 \\u2014 notches max 1/6 depth; bored holes max 1/3 depth, min 2 inches from edge\", \"ibc\": \"IBC \\u00a72308.8\", \"photo_instruction\": \"Photograph notched or bored joists with tape showing notch depth vs joist depth. Photograph joist hangers.\", \"must_show\": \"Notch and bore measurements, joist hanger fastening, bearing length\"}, {\"label\": \"Roof Framing \\u2014 Rafters, Ridge & Connectors\", \"irc\": \"IRC R802.4 rafter spans, R802.3 ridge board, R802.11 rafter ties, R301.2.1 wind uplift connectors\", \"ibc\": \"IBC \\u00a72308.10\", \"photo_instruction\": \"Photograph rafter-to-ridge and rafter-to-top-plate connections. Include hurricane straps and span measurement.\", \"must_show\": \"Connector type and installation, rafter spacing, ridge board size\"}], \"roofing\": [{\"label\": \"Roof Deck & Sheathing\", \"irc\": \"IRC R803.2 \\u2014 wood structural panel per span rating; R803.2.4 \\u2014 H-clips for spans over 24 inches\", \"ibc\": \"IBC \\u00a72304.8\", \"photo_instruction\": \"Photograph sheathing grade stamp on panels. Photograph H-clips at unsupported edges.\", \"must_show\": \"APA grade stamp visible, H-clips or blocking at edges\"}, {\"label\": \"Ice & Water Barrier + Underlayment\", \"irc\": \"IRC R905.1.2 \\u2014 ice barrier min 24 inches inside exterior wall where Jan avg temp 25F or below; R905.2.7 \\u2014 underlayment required\", \"ibc\": \"IBC \\u00a71507.2.8\", \"photo_instruction\": \"Photograph ice barrier at eaves showing extent past interior wall. Photograph overlapping underlayment rows.\", \"must_show\": \"Ice barrier extends min 24 inches past wall line, underlayment overlap min 2 inches\"}, {\"label\": \"Drip Edge & Flashing\", \"irc\": \"IRC R905.2.8.5 \\u2014 drip edge min 1/4 inch below sheathing, min 2 inches up deck; R905.2.8.3 \\u2014 valley flashing min 24 inches wide\", \"ibc\": \"IBC \\u00a71507.2.9\", \"photo_instruction\": \"Photograph drip edge at eave showing overlap. Photograph each valley and step flashing at wall intersections.\", \"must_show\": \"Drip edge overlap measured, valley flashing width, step flashing at all intersections\"}, {\"label\": \"Shingle Installation & Nailing Pattern\", \"irc\": \"IRC R905.2.5 \\u2014 minimum 4 fasteners per strip shingle (6 in high-wind); R905.2.4.1 \\u2014 starter strip at eaves\", \"ibc\": \"IBC \\u00a71507.2.5\", \"photo_instruction\": \"Lift a shingle to photograph nail placement. Photograph starter course at eave and offset pattern.\", \"must_show\": \"Nails in manufacturer nailing zone, minimum 4 nails visible, starter strip in place\"}, {\"label\": \"Ridge Cap, Vents & Final Weathertight Inspection\", \"irc\": \"IRC R806.2 \\u2014 ventilation min 1/150 of insulated ceiling area (or 1/300 with balanced intake/exhaust)\", \"ibc\": \"IBC \\u00a71503.4\", \"photo_instruction\": \"Photograph completed ridge cap. Photograph each vent location. Photograph all pipe boot flashings.\", \"must_show\": \"Ridge cap fully installed, vent locations visible, all penetration flashings sealed\"}], \"plumbing\": [{\"label\": \"DWV Rough-In \\u2014 Drain Slope & Pipe Support\", \"irc\": \"IRC P3005.3 \\u2014 slope: 1/4 inch per foot for pipe 3 inches or smaller, 1/8 inch per foot for 4 inch and larger; P2605.1 \\u2014 support intervals\", \"ibc\": \"IPC \\u00a7308 support, \\u00a7704 slope\", \"photo_instruction\": \"Use level and ruler on horizontal drain runs to show slope. Photograph pipe hangers showing spacing.\", \"must_show\": \"Slope measurement visible, hanger spacing within limits, pipe size stamps\"}, {\"label\": \"DWV Air / Water Pressure Test\", \"irc\": \"IRC P2503.5.1 \\u2014 air test: 5 psi for 15 minutes; water test: min 10ft head for 15 minutes\", \"ibc\": \"IPC \\u00a7312.2\", \"photo_instruction\": \"Photograph test gauge showing pressure at start and end of 15-minute hold.\", \"must_show\": \"Gauge reading at start and end, no visible moisture at joints\"}, {\"label\": \"Water Supply Lines \\u2014 Material, Sizing & Pressure Test\", \"irc\": \"IRC P2903.5 \\u2014 static pressure test at 1.5 times working pressure for 15 minutes; P2903.1 \\u2014 min 3/4 inch building supply\", \"ibc\": \"IPC \\u00a7604, \\u00a7312.5\", \"photo_instruction\": \"Photograph pressure gauge on supply system. Photograph pipe material markings and main shutoff.\", \"must_show\": \"Test pressure gauge reading, pipe material stamp, shutoff valve accessible\"}, {\"label\": \"Vent Stack & Air Admittance Valves\", \"irc\": \"IRC P3103.1 \\u2014 vent through roof min 6 inches above roof surface (min 24 inches in snow country); P3105 \\u2014 each trap must be vented\", \"ibc\": \"IPC \\u00a7903, \\u00a7917\", \"photo_instruction\": \"Photograph vent stack from exterior showing height above roof. Photograph each trap-to-vent connection.\", \"must_show\": \"Vent height above roof surface measured, all traps connected to vent system\"}, {\"label\": \"Fixture Rough-In & Cleanout Locations\", \"irc\": \"IRC P3005.2.7 \\u2014 cleanouts at base of each stack and runs over 100ft; P2708 shower, P2705 lavatory rough-in requirements\", \"ibc\": \"IPC \\u00a7708\", \"photo_instruction\": \"Photograph each rough-in location with measurement from finished floor. Photograph cleanout plugs.\", \"must_show\": \"Rough-in measurements matching fixture specs, cleanout locations accessible\"}], \"electrical\": [{\"label\": \"Panel, Service Entry & Grounding Electrode\", \"irc\": \"NEC 250.52(A)(3) \\u2014 Ufer: min 20ft of min 1/2 inch rebar or #4 bare copper encased in min 2 inches concrete; NEC 250.50 \\u2014 all electrodes bonded\", \"ibc\": \"NEC Article 250, \\u00a7230\", \"photo_instruction\": \"Photograph Ufer electrode BEFORE concrete pour showing rebar length and pigtail. Photograph GEC connection at panel.\", \"must_show\": \"Ufer rebar length and pigtail visible, GEC connection at panel, service conductor size\"}, {\"label\": \"Branch Circuit Rough-In \\u2014 Box Fill & Wire Routing\", \"irc\": \"NEC 314.16 \\u2014 box fill: 2.0 cu in per #14, 2.25 cu in per #12; NEC 300.4 \\u2014 nail plate required if cable within 1-1/4 inches of stud edge\", \"ibc\": \"NEC Article 314, 300\", \"photo_instruction\": \"Photograph each box showing wire count and cubic-inch rating stamped on box. Photograph nail plates at stud edges.\", \"must_show\": \"Box cu-in rating stamp, nail plates where required, staple spacing max 4.5 feet\"}, {\"label\": \"GFCI & AFCI Protection\", \"irc\": \"NEC 210.8 \\u2014 GFCI at bathrooms, garages, outdoors, kitchens within 6 feet of sink; NEC 210.12 \\u2014 AFCI all 15/20A 120V circuits in dwelling\", \"ibc\": \"NEC \\u00a7210.8, \\u00a7210.12\", \"photo_instruction\": \"Photograph GFCI outlet or breaker at each required location. Photograph AFCI breakers in panel.\", \"must_show\": \"GFCI at all wet and outdoor locations, AFCI breakers for bedroom and living circuits\"}, {\"label\": \"Rough-In Inspection \\u2014 All Circuits, Working Clearances\", \"irc\": \"NEC 110.26 \\u2014 working clearance: min 30 inches wide, min 36 inches deep, min 6.5 feet high in front of panel\", \"ibc\": \"NEC \\u00a7110.26\", \"photo_instruction\": \"Photograph panel working clearance with tape showing 36-inch depth from panel face. Photograph service disconnect label.\", \"must_show\": \"36-inch clearance measured in photo, service disconnect labeled, no obstructions\"}, {\"label\": \"Final \\u2014 Devices, Fixtures & Load Center Labeling\", \"irc\": \"NEC 408.4 \\u2014 every circuit breaker must be legibly identified; NEC 110.12 \\u2014 no open knockouts\", \"ibc\": \"NEC \\u00a7408.4, \\u00a7110.12\", \"photo_instruction\": \"Photograph completed panel directory. Photograph outlet and switch installations. Check for open knockouts.\", \"must_show\": \"Complete panel directory, all boxes covered, no open knockouts, circuit labels legible\"}], \"hvac\": [{\"label\": \"Equipment Installation & Clearances\", \"irc\": \"IRC M1306 \\u2014 clearances to combustibles per equipment listing label; M1305.1 \\u2014 access passageway min 22 by 30 inches\", \"ibc\": \"IMC \\u00a7304, \\u00a7306\", \"photo_instruction\": \"Photograph equipment label showing required clearances. Photograph measured distance from unit to nearest combustible.\", \"must_show\": \"Equipment label clearance requirements visible, measured clearance in photo, access path dimensions\"}, {\"label\": \"Duct Installation \\u2014 Support, Joints & Sealing\", \"irc\": \"IRC M1601.4.1 \\u2014 joints and seams sealed with mastic or UL 181A/B tape; M1601.4.4 \\u2014 round duct support max 10ft, rectangular max 4ft\", \"ibc\": \"IMC \\u00a7603\", \"photo_instruction\": \"Photograph duct joints showing mastic or approved tape. Photograph duct hangers showing spacing. Photograph any flex duct connections.\", \"must_show\": \"Mastic or UL 181 tape at all joints, hanger spacing within limits, flex duct not kinked\"}, {\"label\": \"Combustion Air & Gas Piping\", \"irc\": \"IRC G2407 \\u2014 combustion air: min 50 cu ft per 1,000 BTU/hr; G2417 \\u2014 gas piping test: 10 psi air for 15 min before appliances connected\", \"ibc\": \"IMC \\u00a7701, \\u00a7303.3\", \"photo_instruction\": \"Photograph combustion air opening size with measurement. Photograph gas piping pressure gauge during test.\", \"must_show\": \"Combustion air opening dimensions, gas test gauge reading, shutoff valve accessible and labeled\"}, {\"label\": \"Condensate Drainage & Secondary Drain\", \"irc\": \"IRC M1411.3 \\u2014 secondary drain or auxiliary pan required for equipment above finished ceiling; pan min 1.5 inches deep, min 3 inches wider than unit\", \"ibc\": \"IMC \\u00a7307.2\", \"photo_instruction\": \"Photograph primary drain connection and routing. Photograph secondary drain pan dimensions or float switch.\", \"must_show\": \"Primary drain connection, secondary pan or float switch installed, drain terminates visible\"}, {\"label\": \"Final \\u2014 Duct Insulation, Filter, & System Test\", \"irc\": \"IRC N1103.3.3 \\u2014 ducts in unconditioned space: R-8 insulation minimum\", \"ibc\": \"IECC C403.2.2, IMC \\u00a7607\", \"photo_instruction\": \"Photograph duct insulation in attic or crawl space showing R-value label. Photograph filter installed. Photograph thermostat set to test with system running.\", \"must_show\": \"R-8 or higher insulation label visible, filter in place, system operational\"}], \"concrete\": [{\"label\": \"Footing Excavation & Soil Bearing\", \"irc\": \"IRC R403.1 \\u2014 footings bear on undisturbed soil; R301.2(7) \\u2014 frost depth per Table R301.2(1); R403.1.1 \\u2014 min 12 inches below grade\", \"ibc\": \"IBC \\u00a71809.4\", \"photo_instruction\": \"Photograph footing trench showing depth measurement from grade to bottom. Include tape showing frost-depth compliance.\", \"must_show\": \"Footing depth measurement, undisturbed soil visible at base\"}, {\"label\": \"Rebar Placement & Concrete-Encased Electrode\", \"irc\": \"IRC R403.1.3 \\u2014 footing reinforcement per Table R403.1.3(1); NEC 250.52(A)(3) \\u2014 Ufer: min 20ft of min 1/2 inch rebar in min 2 inches concrete\", \"ibc\": \"IBC \\u00a71905, ACI 318 \\u00a720.6.1 \\u2014 cover: 3 inches cast against earth\", \"photo_instruction\": \"Photograph rebar chairs or supports showing minimum concrete cover. Photograph Ufer pigtail extending from footing form.\", \"must_show\": \"Rebar chairs maintaining minimum cover, Ufer pigtail visible and tagged, rebar size and spacing per plan\"}, {\"label\": \"Vapor Retarder & Sub-Slab Preparation\", \"irc\": \"IRC R506.2.3 \\u2014 vapor retarder min 10-mil Class A per ASTM E1745, joints lapped min 6 inches, extended up stem walls\", \"ibc\": \"IBC \\u00a71805.4.1\", \"photo_instruction\": \"Photograph vapor barrier material showing 10-mil spec or ASTM E1745 markings. Photograph joint laps showing min 6 inch overlap.\", \"must_show\": \"Vapor barrier spec marking, 6-inch lap at joints, edges turned up at stem walls\"}, {\"label\": \"Concrete Pour \\u2014 Mix, Placement & Consolidation\", \"irc\": \"IRC R402.2 \\u2014 min f'c: 2,500 psi interior slabs, 3,000 psi exposed to weather, 3,500 psi severe freeze-thaw\", \"ibc\": \"IBC \\u00a71905.3, ACI 318 Table 19.3.3.1\", \"photo_instruction\": \"Photograph concrete delivery ticket showing mix design and PSI strength. Photograph vibrator being used during pour.\", \"must_show\": \"Concrete ticket with f'c and w/c ratio, vibration occurring during pour\"}, {\"label\": \"Anchor Bolts, Curing & Slab Tolerances\", \"irc\": \"IRC R403.1.6 \\u2014 anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of plate ends, min 7 inch embedment; R506.2.4 \\u2014 slab min 3.5 inches thick\", \"ibc\": \"IBC \\u00a71905.1.8, ACI 117 \\u2014 slab tolerance 1/4 inch in 10ft\", \"photo_instruction\": \"Photograph anchor bolts set in wet concrete while still plastic. Measure and photograph bolt spacing. Photograph curing compound applied.\", \"must_show\": \"Anchor bolt spacing measured, embedment depth marker, curing compound application\"}], \"flooring\": [{\"label\": \"Subfloor Condition & Moisture Testing\", \"irc\": \"IRC R503.2 \\u2014 wood structural panel subfloor: APA rated sheathing per span table; MC max 14 percent for wood or max 3 lbs per 1000 sf per 24hr for concrete\", \"ibc\": \"IBC \\u00a72304.9\", \"photo_instruction\": \"Photograph moisture meter reading in multiple locations. Photograph flatness measurement with 10-foot straightedge.\", \"must_show\": \"Moisture meter reading visible, flatness measurement, any repairs noted\"}, {\"label\": \"Underlayment Installation\", \"irc\": \"IRC R503 \\u2014 subfloor per span table; manufacturer installation instructions govern underlayment type and thickness\", \"ibc\": \"IBC \\u00a72304.9\", \"photo_instruction\": \"Photograph underlayment material label showing specification. Photograph seam treatment (tape or stapling).\", \"must_show\": \"Underlayment spec label, seams properly treated, no voids or bubbles\"}, {\"label\": \"Flooring Layout & Acclimation\", \"irc\": \"NWFA Installation Guidelines: acclimate 3 to 5 days at job-site conditions\", \"ibc\": \"NWFA Installation Guidelines; ANSI A108 for tile\", \"photo_instruction\": \"Photograph flooring material open and acclimating on-site. Photograph chalk line layout and room temperature and humidity reading.\", \"must_show\": \"Flooring open and acclimating, temp and humidity reading, layout lines established\"}, {\"label\": \"Flooring Installation \\u2014 Fastening & Pattern\", \"irc\": \"NWFA: 3/4 inch solid hardwood \\u2014 cleat or staple every 6 to 8 inches; expansion gap 3/4 inch at all walls; ANSI A108.02 \\u2014 tile: thin-set coverage min 80 percent interior\", \"ibc\": \"NWFA and ANSI A108 and manufacturer specs\", \"photo_instruction\": \"Photograph expansion gap at wall with spacer in place. For tile: lift a tile immediately after setting to check mortar coverage.\", \"must_show\": \"Expansion gap at perimeter, fastener spacing visible, mortar coverage on tile back\"}, {\"label\": \"Transitions, Thresholds & Final Inspection\", \"irc\": \"IRC R311.7.5 \\u2014 stair treads: rise max 7-3/4 inches, run min 10 inches\", \"ibc\": \"IBC \\u00a71003.3\", \"photo_instruction\": \"Photograph all threshold transitions room to room. Photograph any change-in-level measurements.\", \"must_show\": \"All transitions in place, level changes measured, no protruding fasteners or gaps\"}], \"painting\": [{\"label\": \"Surface Preparation \\u2014 Drywall & Substrate\", \"irc\": \"GA-214 Recommended Levels of Gypsum Board Finish \\u2014 Level 4 minimum for flat paint; Level 5 for gloss or semi-gloss or critical lighting\", \"ibc\": \"GA-214 and ASTM C840\", \"photo_instruction\": \"Photograph drywall seams under raking light to show finish level. Document finish level before primer.\", \"must_show\": \"Seams smooth under raking light, no mud ridges, corner bead straight\"}, {\"label\": \"Primer Application\", \"irc\": \"Manufacturer specs and PDCA Standards P1 through P4 series\", \"ibc\": \"PDCA and MPI Architectural Painting Specification Manual\", \"photo_instruction\": \"Photograph primed surfaces showing even coverage. Photograph primer product label showing manufacturer and type.\", \"must_show\": \"Even primer coverage, no bare spots, product label visible\"}, {\"label\": \"First Coat \\u2014 Application & Coverage\", \"irc\": \"PDCA P4 and MPI Standards \\u2014 spread rate per manufacturer; mil thickness per spec sheet\", \"ibc\": \"MPI Architectural Painting Specification Manual \\u00a79\", \"photo_instruction\": \"Photograph any areas with thin coverage or holidays. Photograph product label and batch number.\", \"must_show\": \"Even sheen across surface, product batch number recorded\"}, {\"label\": \"Second Coat & Finish Inspection\", \"irc\": \"PDCA P12 \\u2014 uniform color and sheen, no defects visible at 5 feet in normal light\", \"ibc\": \"MPI \\u00a79; ASTM D3730\", \"photo_instruction\": \"Photograph finished walls under normal lighting and under raking light. Photograph final coat product label.\", \"must_show\": \"Uniform sheen at 5-foot viewing distance, no drips or laps, final coat label\"}, {\"label\": \"Trim, Cut Lines & Cleanup\", \"irc\": \"PDCA P5 protection of adjacent surfaces; PDCA P1 workmanship standard\", \"ibc\": \"PDCA Standards\", \"photo_instruction\": \"Photograph trim cut lines at ceiling and floor. Photograph hardware reinstalled. Photograph overall room showing clean site.\", \"must_show\": \"Straight cut lines, hardware in place, no paint on floors or fixtures\"}], \"general\": [{\"label\": \"Site Safety & Permit Posted\", \"irc\": \"IRC R105.7 \\u2014 permit must be posted on site and visible from street until final inspection\", \"ibc\": \"IBC \\u00a7105.7\", \"photo_instruction\": \"Photograph building permit posted at front of property. Photograph crew wearing PPE.\", \"must_show\": \"Permit visible and readable, PPE in use, no obvious safety violations\"}, {\"label\": \"Work-in-Progress Milestone\", \"irc\": \"Contractual milestone \\u2014 specific IRC section depends on trade being performed\", \"ibc\": \"Contractual as applicable\", \"photo_instruction\": \"Photograph wide view of work area showing scope in progress. Include reference objects for scale.\", \"must_show\": \"Clear progress visible, scope matches contract, work area identified\"}, {\"label\": \"Materials On-Site & Specification\", \"irc\": \"IRC R101.2 \\u2014 materials must meet referenced standards; specific section per material type\", \"ibc\": \"IBC \\u00a71703 product approval\", \"photo_instruction\": \"Photograph material specification labels for all major materials. Photograph materials stored properly off ground and covered.\", \"must_show\": \"Grade stamps and spec labels visible, materials protected from weather, quantities match scope\"}, {\"label\": \"Subcontractor Work Complete\", \"irc\": \"IRC R109 \\u2014 required inspections must be completed before concealment of any work\", \"ibc\": \"IBC \\u00a7110\", \"photo_instruction\": \"Photograph any rough-in work before walls are closed. Photograph required inspection approval cards posted on site.\", \"must_show\": \"All rough-in work visible before concealment, inspection tags if applicable\"}, {\"label\": \"Final Walkthrough & Punch List\", \"irc\": \"IRC R110 \\u2014 Certificate of Occupancy required before occupancy; final inspection must pass\", \"ibc\": \"IBC \\u00a7111\", \"photo_instruction\": \"Photograph each completed area of agreed scope. Photograph final cleanup. Photograph any outstanding items for homeowner.\", \"must_show\": \"All contracted work visible and complete, site clean, no materials left behind\"}]}")

def detect_trade_python(description):
    """Keyword-based trade detection — matches JS detectTrade()."""
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

# ─────────────────────────────────────────────────
# ROUTE 1 — Create PaymentIntent (homeowner per-job)
# POST /shield/create-payment-intent
# ─────────────────────────────────────────────────
@shield_bp.route('/create-payment-intent', methods=['POST'])
@require_auth
def create_payment_intent():
    data         = request.get_json()
    job_id       = data.get('job_id')
    amount_cents = data.get('amount_cents')
    if not job_id or not amount_cents:
        return jsonify({'error': 'job_id and amount_cents required'}), 400

    intent = stripe.PaymentIntent.create(
        amount=int(amount_cents),
        currency='usd',
        metadata={'job_id': job_id, 'product': 'shield_per_job'},
        description=f'TradeDeck Shield — Job {job_id}'
    )
    return jsonify({'client_secret': intent.client_secret})


# ─────────────────────────────────────────────────
# ROUTE 2 — Contractor Stripe Checkout subscription
# POST /shield/contractor-subscribe
# ─────────────────────────────────────────────────
@shield_bp.route('/contractor-subscribe', methods=['POST'])
@require_auth
def contractor_subscribe():
    data          = request.get_json()
    contractor_id = data.get('contractor_id')
    if not contractor_id:
        return jsonify({'error': 'contractor_id required'}), 400

    existing = supa_select('shield_subscriptions', {'contractor_id': contractor_id})
    if existing and existing.get('stripe_customer_id'):
        customer_id = existing['stripe_customer_id']
    else:
        customer    = stripe.Customer.create(metadata={'contractor_id': contractor_id})
        customer_id = customer.id

    checkout = stripe.checkout.Session.create(
        customer=customer_id,
        mode='subscription',
        line_items=[{'price': STRIPE_SHIELD_PRICE_ID, 'quantity': 1}],
        success_url='https://tradedeckapp.com/app.html?shield_sub=success',
        cancel_url='https://tradedeckapp.com/app.html?shield_sub=cancelled',
        metadata={'contractor_id': contractor_id, 'product': 'shield_pro'}
    )
    return jsonify({'stripe_url': checkout.url})


# ─────────────────────────────────────────────────
# ROUTE 3 — AI Photo Analysis (Claude Vision)
# POST /shield/analyze-photo
# ─────────────────────────────────────────────────
@shield_bp.route('/analyze-photo', methods=['POST'])
@require_auth
def analyze_photo():
    data       = request.get_json()
    photo_id   = data.get('photo_id')
    public_url = data.get('public_url')
    point_id   = data.get('point_id')
    gps_lat    = data.get('gps_lat')
    gps_lng    = data.get('gps_lng')
    has_exif       = data.get('has_exif', False)
    code_reference = data.get('code_reference', None)
    if not all([photo_id, public_url, point_id]):
        return jsonify({'error': 'photo_id, public_url, and point_id required'}), 400
    # GPS required — reject if missing
    if gps_lat is None or gps_lng is None:
        return jsonify({'error': 'GPS coordinates required for Shield photo verification'}), 400

    point       = supa_select('shield_pivotal_points', {'id': point_id})
    point_label = point.get('label', 'Checkpoint') if point else 'Checkpoint'
    point_desc  = point.get('description', '') if point else ''

    code_ref_line = code_reference if code_reference else 'Not specified'
    img_r = requests.get(public_url, timeout=15)
    if img_r.status_code != 200:
        return jsonify({'error': 'Could not fetch photo'}), 502

    image_b64    = base64.b64encode(img_r.content).decode('utf-8')
    content_type = img_r.headers.get('content-type', 'image/jpeg').split(';')[0]

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=600,
        system=(
            'You are a licensed building inspector and fraud detection analyst. '
            'You evaluate contractor-submitted photos for homeowner protection. '
            'Your job has TWO parts: (1) verify the photo is authentic and taken on-site, '
            '(2) verify the work meets the checkpoint requirement. '
            'Respond ONLY with a valid JSON object — no preamble, no markdown.'
        ),
        messages=[{
            'role': 'user',
            'content': [
                {
                    'type': 'image',
                    'source': {'type': 'base64', 'media_type': content_type, 'data': image_b64}
                },
                {
                    'type': 'text',
                    'text': f'''Checkpoint: {point_label}
Required condition: {point_desc}

METADATA PROVIDED BY THE APP:
- GPS captured: {f"{gps_lat:.5f}, {gps_lng:.5f}" if gps_lat else "NOT PROVIDED"}
- Code Requirement: {code_ref_line}
- Camera EXIF data present: {"YES" if has_exif else "NO — possible screenshot or downloaded image"}

STEP 1 — AUTHENTICITY CHECK (check ALL of these):
- Is this a real on-site construction photo, or a stock image / screenshot / render / AI image?
- Does it show genuine construction conditions (dust, tools, materials, real lighting, shadows)?
- Are there signs of digital manipulation, compositing, or watermarks from another source?
- Look for: unnatural lighting, impossible shadows, blurred/sharp edges where objects meet, repeated texture patterns, unnatural noise, AI rendering artifacts, or inconsistent image quality across regions?
- Does the image content appear consistent with a real active job site?
- EXIF status: if EXIF is missing, treat this as a strong authenticity concern.
- Screens/monitors in frame: if the photo appears to be of a screen or printed image, mark fake.

STEP 2 — QUALITY CHECK (only if authentic):
- Does the photo show what the checkpoint requires?
- Is the work complete, correct, and up to standard?

Respond with this exact JSON:
{{
  "authentic": true | false,
  "authenticity_note": "<one sentence — why authentic or why suspicious>",
  "verdict": "pass" | "flag" | "fail" | "fake",
  "confidence": <float 0-1>,
  "notes": "<2-3 sentence assessment for the homeowner>"
}}

verdict rules:
- fake  = photo is not authentic (stock image, screenshot, render, photo of screen, manipulated, EXIF absent)
- fail  = authentic but work is incomplete, incorrect, or quality concern visible
- flag  = authentic, mostly correct but worth homeowner attention
- pass  = authentic, GPS confirmed on-site, work complete and up to standard

If verdict is fake, set confidence to 1.0 and notes must explain specifically what gave it away.'''
                }
            ]
        }]
    )

    raw = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
    result     = json.loads(raw)
    authentic  = result.get('authentic', True)
    verdict    = result.get('verdict', 'flag')
    confidence = float(result.get('confidence', 0.7))
    notes      = result.get('notes', '')
    auth_note  = result.get('authenticity_note', '')

    # Force fail if fake — override any other verdict
    if not authentic or verdict == 'fake':
        verdict    = 'fake'
        confidence = 1.0
        notes      = f'⚠️ Photo flagged as inauthentic: {auth_note} This checkpoint has not been verified.'

    # ── Server-side hash of the fetched image bytes ──
    server_hash = hashlib.sha256(img_r.content).hexdigest()

    # ── Get the shield_job_id from the photo record ──
    photo_row  = SUPA.table('shield_photos').select('shield_job_id, contractor_id').eq('id', photo_id).single().execute().data or {}
    s_job_id   = photo_row.get('shield_job_id')
    contractor = photo_row.get('contractor_id')

    supa_update('shield_photos', 'id', photo_id, {
        'ai_verdict':        verdict,
        'ai_confidence':     confidence,
        'ai_notes':          notes,
        'ai_authentic':      authentic,
        'photo_hash':        server_hash,
        'hash_algorithm':    'SHA-256',
        'server_received_at': datetime.now(timezone.utc).isoformat(),
        **(({'code_reference': code_reference}) if code_reference else {}),
    })
    point_status = 'approved' if verdict == 'pass' else 'flagged'
    supa_update('shield_pivotal_points', 'id', point_id, {'status': point_status})

    # ── Log chain-of-custody event ──
    log_custody(
        photo_id    = photo_id,
        shield_job_id = s_job_id,
        event_type  = 'ai_analyzed',
        actor_id    = contractor,
        actor_type  = 'ai',
        event_data  = {
            'verdict':          verdict,
            'confidence':       confidence,
            'authentic':        authentic,
            'authenticity_note': auth_note,
            'server_hash':      server_hash,
            'gps_provided':     gps_lat is not None,
            'exif_present':     has_exif,
        },
        gps_lat = gps_lat,
        gps_lng = gps_lng,
    )
    if verdict == 'flagged' or verdict == 'fake':
        log_custody(
            photo_id=photo_id, shield_job_id=s_job_id,
            event_type='flagged', actor_type='ai',
            event_data={'reason': auth_note or notes}
        )

    return jsonify({'verdict': verdict, 'confidence': confidence, 'notes': notes, 'authentic': authentic})


# ─────────────────────────────────────────────────
# ROUTE 4 — Generate AI Pivotal Points
# POST /shield/generate-points
# Called after local points are inserted — enhances them with Claude
# ─────────────────────────────────────────────────
@shield_bp.route('/generate-points', methods=['POST'])
@require_auth
def generate_points():
    data          = request.get_json()
    shield_job_id = data.get('shield_job_id')
    job_id        = data.get('job_id')
    job_desc      = data.get('job_description', '')
    if not all([shield_job_id, job_id, job_desc]):
        return jsonify({'error': 'shield_job_id, job_id, and job_description required'}), 400

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=600,
        messages=[{'role': 'user', 'content': f'''You are a senior contractor and building inspector.

Job description: """{job_desc}"""

Identify exactly 5 pivotal checkpoints — the specific moments where a photo proves whether the work was done correctly before it is too late to fix. These are the moments a bad contractor would most want to skip.

Return ONLY a valid JSON array, no markdown:
[
  {{"point_number": 1, "label": "<short name>", "description": "<one sentence: exactly what the photo must show>"}},
  ...
]'''}]
    )

    raw    = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
    points = json.loads(raw)

    # Detect trade from description to pull IRC codes
    trade       = detect_trade_python(job_desc)
    trade_codes = IRC_CODE_MAP.get(trade, IRC_CODE_MAP['general'])

    # Upsert — update the local points already inserted by the frontend,
    # adding IRC/IBC code references to each checkpoint
    for p in points:
        # Match Claude's label to the IRC code entry (by position, then by label substring)
        idx     = p['point_number'] - 1
        code_entry = trade_codes[idx] if idx < len(trade_codes) else {}

        update_fields = {
            'label':              p['label'],
            'description':        p['description'],
            'irc_code':           code_entry.get('irc'),
            'ibc_code':           code_entry.get('ibc'),
            'photo_instruction':  code_entry.get('photo_instruction'),
            'must_show':          code_entry.get('must_show'),
        }

        existing = requests.get(
            f'{SUPABASE_URL}/rest/v1/shield_pivotal_points?shield_job_id=eq.{shield_job_id}&point_number=eq.{p["point_number"]}',
            headers=_headers()
        ).json()

        if existing:
            supa_update('shield_pivotal_points', 'id', existing[0]['id'], update_fields)
        else:
            supa_insert('shield_pivotal_points', {
                'shield_job_id': shield_job_id,
                'job_id':        job_id,
                'point_number':  p['point_number'],
                **update_fields
            })

    return jsonify({'points': points, 'trade': trade})


# ─────────────────────────────────────────────────
# ROUTE 5 — Complete Job (close-out)
# POST /shield/complete-job
# Receives the SHA-256 completion packet from the frontend,
# stores it, freezes the shield_job row, emails admin
# ─────────────────────────────────────────────────
@shield_bp.route('/complete-job', methods=['POST'])
@require_auth
def complete_job():
    packet = request.get_json()
    shield_job_id = packet.get('shield_job_id')
    if not shield_job_id:
        return jsonify({'error': 'shield_job_id required'}), 400

    # Verify the SHA-256 hash matches the packet contents
    submitted_hash = packet.pop('sha256', None)
    packet_string  = json.dumps({k: packet[k] for k in sorted(packet.keys())}, sort_keys=True, separators=(',', ':'))
    expected_hash  = hashlib.sha256(packet_string.encode()).hexdigest()

    # Store the completion record
    supa_insert('shield_completion_reports', {
        'shield_job_id':    shield_job_id,
        'job_id':           packet.get('job_id'),
        'contractor_id':    packet.get('closed_by'),   # whoever closed it
        'homeowner_id':     packet.get('homeowner_id'),
        'overall_verdict':  _derive_verdict(packet.get('points', [])),
        'completion_score': _derive_score(packet.get('points', [])),
        'report_json':      json.dumps({**packet, 'sha256': submitted_hash}),
    })

    # Freeze the shield_job row
    supa_update('shield_jobs', 'id', shield_job_id, {
        'status':       'complete',
        'completed_at': datetime.utcnow().isoformat()
    })

    # Email admin
    _send_completion_email(packet, submitted_hash)

    return jsonify({'ok': True, 'sha256': submitted_hash})


def _derive_verdict(points):
    verdicts = [p.get('photo', {}).get('ai_verdict') for p in points if p.get('photo')]
    if not verdicts:             return 'flag'
    if 'fail' in verdicts:       return 'fail'
    if 'flag' in verdicts:       return 'flag'
    return 'pass'

def _derive_score(points):
    if not points: return 0.0
    scores = {'pass': 100, 'flag': 60, 'fail': 0}
    total  = sum(scores.get(p.get('photo', {}).get('ai_verdict', 'flag'), 60) for p in points)
    return round(total / len(points), 1)

def _send_completion_email(packet, sha256):
    """Send completion record to admin email via Supabase Edge Function or SMTP."""
    try:
        r = requests.post(
            f'{SUPABASE_URL}/functions/v1/send-email',
            headers={
                'apikey': SUPABASE_SERVICE_KEY,
                'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'to':      ADMIN_EMAIL,
                'subject': f'TradeDeck Shield Completion — Job {str(packet.get("job_id",""))[-6:].upper()}',
                'html': f'''
<h2>🛡️ TradeDeck Shield — Job Complete</h2>
<p><strong>Job ID:</strong> {packet.get("job_id")}</p>
<p><strong>Shield Job ID:</strong> {packet.get("shield_job_id")}</p>
<p><strong>Closed at:</strong> {packet.get("closed_at")}</p>
<p><strong>SHA-256:</strong> <code>{sha256}</code></p>
<h3>Checkpoint Summary</h3>
<table border="1" cellpadding="6" style="border-collapse:collapse">
  <tr><th>#</th><th>Label</th><th>AI Verdict</th><th>Confidence</th></tr>
  {"".join(f'''<tr>
    <td>{p["point_number"]}</td>
    <td>{p["label"]}</td>
    <td>{p.get("photo", {}).get("ai_verdict", "NO PHOTO") if p.get("photo") else "NO PHOTO"}</td>
    <td>{str(round(p.get("photo", {}).get("ai_confidence", 0) * 100)) + "%" if p.get("photo") else "—"}</td>
  </tr>''' for p in packet.get("points", []))}
</table>
''',
            },
            timeout=10
        )
        return r.status_code == 200
    except Exception as e:
        print(f'Shield: completion email failed — {e}')
        return False


# ─────────────────────────────────────────────────
# ROUTE 6 — Stripe Webhook
# POST /shield/webhook
# ─────────────────────────────────────────────────
@shield_bp.route('/webhook', methods=['POST'])
def shield_stripe_webhook():
    payload    = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    obj      = event['data']['object']
    evt_type = event['type']

    if evt_type == 'customer.subscription.created':
        contractor_id = obj.get('metadata', {}).get('contractor_id')
        if contractor_id:
            supa_insert('shield_subscriptions', {
                'contractor_id':      contractor_id,
                'stripe_customer_id': obj['customer'],
                'stripe_sub_id':      obj['id'],
                'status':             'active',
                'current_period_end': obj.get('current_period_end')
            })

    elif evt_type == 'customer.subscription.updated':
        supa_update('shield_subscriptions', 'stripe_sub_id', obj['id'], {
            'status':             obj['status'],
            'current_period_end': obj.get('current_period_end')
        })

    elif evt_type in ('customer.subscription.deleted', 'customer.subscription.paused'):
        supa_update('shield_subscriptions', 'stripe_sub_id', obj['id'], {'status': 'cancelled'})

    elif evt_type == 'payment_intent.succeeded':
        job_id = obj.get('metadata', {}).get('job_id')
        if job_id and obj.get('metadata', {}).get('product') == 'shield_per_job':
            supa_update('shield_jobs', 'job_id', job_id, {'stripe_payment_id': obj['id']})

    return jsonify({'received': True})
