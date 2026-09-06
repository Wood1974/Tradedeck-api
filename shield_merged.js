// ============================================================
// TRADEDECK SHIELD — shield.js (MERGED COMPLETE VERSION)
// Combines: real Stripe Elements payment, trade-aware job brief,
// local point generation, close-out system, AI photo analysis
// ============================================================
//
// INTEGRATION POINTS IN YOUR EXISTING APP:
//   1. Post a Job form      → renderShieldBrief(container, onReady)
//   2. Pay button           → purchaseShieldPerJob(jobId, amount, description)
//   3. Homeowner nav tab    → renderShieldDashboard(container)
//   4. Contractor job view  → renderContractorUploadFlow(container, shieldJobId, pointId)
//   5. Contractor profile   → subscribeContractorToShield(container)
//   6. Contractor job card  → renderShieldBadge(contractorId, container)
//   7. Job close-out        → renderShieldCloseOut(container, shieldJobId)
//
// Requires: Supabase client (sb) available globally
// Stripe.js is lazy-loaded only when payment is about to happen

const STRIPE_PK        = 'pk_test_51TLWkTDNZcAJj6Kyd84RVIQ0qPO1iHP109ccBL4P9OQvShE21T291c4BhhtC8Z6CEYQKqmtjj2b6UZQe1n1CusGC00KNY7CwAl'
const API_BASE         = 'https://tradedeck-api.onrender.com'
const CONTRACTOR_SUB_PRICE = 49

// ─────────────────────────────────────────────────
// SHIELD PRICING
// ─────────────────────────────────────────────────
const SHIELD_TIERS = [
  { label: 'Under $15,000',     max: 15000,    price: 79  },
  { label: '$15,000–$50,000',   max: 50000,    price: 129 },
  { label: 'Over $50,000',      max: Infinity, price: 199 },
]

function getShieldPrice(budget) {
  return (SHIELD_TIERS.find(t => budget <= t.max) || SHIELD_TIERS[2]).price
}

// ─────────────────────────────────────────────────
// LAZY STRIPE LOADER
// ─────────────────────────────────────────────────
function loadStripeScript() {
  return new Promise((resolve, reject) => {
    if (document.getElementById('stripe-js')) { resolve(); return }
    const s  = document.createElement('script')
    s.id     = 'stripe-js'
    s.src    = 'https://js.stripe.com/v3/'
    s.onload  = resolve
    s.onerror = () => reject(new Error('Failed to load Stripe.js'))
    document.head.appendChild(s)
  })
}

// ============================================================
// PART 1 — JOB BRIEF ENGINE
// Trade detection, description scoring, local point generation
// ============================================================

const TRADE_PROFILES = {
  "framing": {
    name:     "Framing / Structural",
    keywords: ["framing","addition","room","wall","joist","beam","header","stud","lumber","structure"],
    points: [
      {
        label:             "Foundation Sill Plate & Anchor Bolts",
        description:       "Sill plate installed, anchor bolts in place and correctly spaced",
        irc:               "IRC R403.1.6 — Anchor bolts ≥½\" dia., ≤6ft o.c., within 12\" of each plate end, ≥7\" embedment, 3\"×3\" plate washer",
        ibc:               "IBC §1905.1.8 / ACI 318",
        photo_instruction: "Photograph the full sill plate run showing anchor bolt locations, nuts, and washers. Include a tape measure showing bolt spacing.",
        must_show:         "Bolt spacing, embedment depth marker if visible, washers and nuts torqued",
      },
      {
        label:             "Wall Framing — Studs, Headers & Bracing",
        description:       "Studs plumb, headers sized correctly, wall bracing installed per plan",
        irc:               "IRC R602.3 (stud spacing/size), R602.7 (header spans), R602.10 (wall bracing) — studs ≤16\" or 24\" o.c. per table",
        ibc:               "IBC §2308.4",
        photo_instruction: "Photograph full wall section showing stud spacing, header at each opening, and diagonal bracing or sheathing. Include corner assembly.",
        must_show:         "Stud spacing, header size visible, bracing method",
      },
      {
        label:             "Fireblocking & Draftstopping",
        description:       "Fireblocking installed at all required horizontal and vertical locations before concealment",
        irc:               "IRC R302.11 — fireblocking required at ceiling/floor lines, stair stringers, around chimneys; R302.12 — draftstopping in floor-ceiling concealed spaces ≤1,000 sq ft",
        ibc:               "IBC §718",
        photo_instruction: "Photograph each fireblocking location — between studs at floor/ceiling lines, around penetrations. Take before drywall covers it.",
        must_show:         "Fireblock material in place, all gaps sealed, location matches IRC R302.11 requirements",
      },
      {
        label:             "Floor Joists — Notching, Boring & Connections",
        description:       "Floor joists sized per span table, notches and bores within code limits, joist hangers installed",
        irc:               "IRC R502.8 — joist notches ≤1/6 depth, not in middle ⅓ of span; bored holes ≤⅓ depth, ≥2\" from edge; R502.6 (bearing), R602.3(1) (fastening table)",
        ibc:               "IBC §2308.8",
        photo_instruction: "Photograph any notched or bored joists with tape measure showing notch depth vs joist depth. Photograph joist hanger connections at bearing points.",
        must_show:         "Notch/bore measurements, joist hanger fastening, bearing length",
      },
      {
        label:             "Roof Framing — Rafters, Ridge & Connectors",
        description:       "Rafters at correct spacing, ridge board sized, hurricane/seismic connectors installed",
        irc:               "IRC R802.4 (rafter spans), R802.3 (ridge board ≥1\" nominal depth greater than rafter cut), R802.11 (rafter ties), R301.2.1 (wind uplift connectors per SDC)",
        ibc:               "IBC §2308.10",
        photo_instruction: "Photograph rafter-to-ridge connections, rafter-to-top-plate connections, and any hurricane straps or clips. Include span measurement.",
        must_show:         "Connector type and installation, rafter spacing, ridge board size",
      },
    ]
  },
  "roofing": {
    name:     "Roofing",
    keywords: ["roof","roofing","shingle","flashing","gutter","fascia","soffit","ridge","underlayment","decking"],
    points: [
      {
        label:             "Roof Deck & Sheathing",
        description:       "Roof sheathing installed, thickness correct, edges supported",
        irc:               "IRC R803.2 — wood structural panel sheathing per span rating; R803.2.4 — edge support (H-clips or blocking) for panels with span > 24\"",
        ibc:               "IBC §2304.8",
        photo_instruction: "Photograph sheathing grade stamp visible on panels. Photograph H-clips or blocking at unsupported edges. Include any gaps or damage.",
        must_show:         "APA grade stamp, H-clips or blocking at edges, no visible gaps >⅛\"",
      },
      {
        label:             "Ice & Water Barrier + Underlayment",
        description:       "Ice barrier installed in required climate zones; felt/synthetic underlayment covering entire deck",
        irc:               "IRC R905.1.2 — ice barrier required where Jan avg temp ≤25°F, extending ≥24\" inside exterior wall line; R905.2.7 — No. 15 felt underlayment or approved synthetic",
        ibc:               "IBC §1507.2.8",
        photo_instruction: "Photograph ice barrier at eaves showing it extends past interior wall line. Photograph overlapping underlayment rows. Include any valleys.",
        must_show:         "Ice barrier extent (measure 24\" past wall line), underlayment overlap ≥2\", valley coverage",
      },
      {
        label:             "Drip Edge & Flashing",
        description:       "Drip edge installed at eaves and rakes; step, counter, and valley flashing installed",
        irc:               "IRC R905.2.8.5 — drip edge ≥¼\" below sheathing, ≥2\" up deck, fastened ≤12\" o.c.; R905.2.8.3 — valley flashing ≥24\" wide with ≥36\" underlayment beneath",
        ibc:               "IBC §1507.2.9",
        photo_instruction: "Photograph drip edge at eave showing overlap onto sheathing. Photograph each valley with flashing in place. Photograph step flashing at any wall/chimney intersections.",
        must_show:         "Drip edge overlap measurements, valley flashing width, step flashing at all wall intersections",
      },
      {
        label:             "Shingle Installation & Nailing Pattern",
        description:       "Shingles installed with correct exposure, offset, and fastener pattern",
        irc:               "IRC R905.2.5 — fasteners: minimum 4 per strip shingle, 6 in high-wind zones; R905.2.6 — exposure per manufacturer; R905.2.4.1 — starter strip at eaves",
        ibc:               "IBC §1507.2.5",
        photo_instruction: "Photograph a lifted shingle showing nail placement (must be in nailing zone, not above). Photograph starter course at eave. Photograph offset pattern.",
        must_show:         "Nail placement in manufacturer nailing zone, 4 nails minimum visible, starter strip in place",
      },
      {
        label:             "Ridge Cap, Vents & Final Weathertight Inspection",
        description:       "Ridge cap installed; ridge/soffit vents in place; all penetrations flashed and sealed",
        irc:               "IRC R806.2 — ventilation area ≥1/150 of insulated ceiling area (or 1/300 with balanced intake/exhaust); R905.2 — all penetrations flashed per manufacturer",
        ibc:               "IBC §1503.4",
        photo_instruction: "Photograph completed ridge cap. Photograph each vent location. Photograph all pipe boot flashings and any skylight or chimney flashing.",
        must_show:         "Ridge cap fully installed, vent locations, all penetration flashings sealed",
      },
    ]
  },
  "plumbing": {
    name:     "Plumbing",
    keywords: ["plumbing","pipe","drain","water heater","sewer","leak","fixture","supply line","shutoff","pressure"],
    points: [
      {
        label:             "DWV Rough-In — Drain Slope & Pipe Support",
        description:       "Drain, waste, and vent pipes installed with correct slope and support spacing",
        irc:               "IRC P3005.3 — horizontal drainage pipe slope: ¼\"/ft for ≤3\" pipe, ⅛\"/ft for 4\"+ pipe; P2605.1 — support intervals per pipe material (PVC: 4ft horizontal, 10ft vertical)",
        ibc:               "IPC §308 (support), §704 (slope)",
        photo_instruction: "Place a level and ruler on horizontal drain runs to show slope. Photograph pipe hangers/straps showing spacing. Include pipe size markings.",
        must_show:         "Slope measurement (level + measurement), hanger spacing, pipe size stamps",
      },
      {
        label:             "DWV Air / Water Pressure Test",
        description:       "DWV system tested and holding pressure before concealment",
        irc:               "IRC P2503.5.1 — water test: fill to ≥10ft head above highest fitting, hold 15 minutes with no leaks; OR air test: 5 psi, 15 minutes",
        ibc:               "IPC §312.2",
        photo_instruction: "Photograph test gauge showing 5 psi (air) or water level at test plug. Photograph the timer/clock showing test start and end. Photograph each visible joint.",
        must_show:         "Gauge reading at start and end of 15-minute hold, no visible moisture at joints",
      },
      {
        label:             "Water Supply Lines — Material, Sizing & Pressure Test",
        description:       "Supply lines installed in correct material, sized per fixture count, pressure tested",
        irc:               "IRC P2903.5 — static pressure test at 1.5× working pressure (min 50 psi) for 15 minutes; P2905 — approved pipe materials; P2903.1 — minimum ¾\" building supply",
        ibc:               "IPC §604, §312.5",
        photo_instruction: "Photograph pressure gauge on supply system showing test pressure. Photograph pipe material markings. Photograph main shutoff valve location.",
        must_show:         "Test pressure gauge reading, pipe material stamp/marking, shutoff valve accessible",
      },
      {
        label:             "Vent Stack & Air Admittance Valves",
        description:       "Vent stack extends through roof; all fixtures properly vented per code",
        irc:               "IRC P3103.1 — vent through roof ≥6\" above roof surface (≥24\" in snow country); P3114 — AAVs permitted only where code allows; P3105 — each trap must be vented",
        ibc:               "IPC §903, §917",
        photo_instruction: "Photograph vent stack penetration through roof from exterior showing height above roof. Photograph each trap-to-vent connection. If AAVs used, photograph their location and accessibility.",
        must_show:         "Vent height above roof surface (measure it), all traps connected to vent system",
      },
      {
        label:             "Fixture Rough-In & Cleanout Locations",
        description:       "Fixture rough-in heights correct; cleanouts accessible per code",
        irc:               "IRC P3005.2.7 — cleanouts required at base of each stack and each horizontal run >100ft; P2708 (shower), P2705 (lavatory), P2711 (kitchen sink) rough-in requirements",
        ibc:               "IPC §708",
        photo_instruction: "Photograph each rough-in location with measurement from finished floor. Photograph cleanout plugs showing they are accessible (not behind permanent wall).",
        must_show:         "Rough-in measurements matching fixture specs, cleanout locations accessible",
      },
    ]
  },
  "electrical": {
    name:     "Electrical",
    keywords: ["electrical","wiring","panel","circuit","outlet","switch","breaker","lighting","generator","EV charger"],
    points: [
      {
        label:             "Panel, Service Entry & Grounding Electrode",
        description:       "Panel installed, service conductors sized correctly, grounding electrode system complete",
        irc:               "IRC E3607 / NEC 250.50 — all grounding electrodes present must be bonded; NEC 250.52(A)(3) — Ufer/concrete-encased electrode: ≥20ft rebar ≥½\" dia. or #4 bare copper in ≥2\" concrete",
        ibc:               "NEC Article 250, §230",
        photo_instruction: "Photograph the Ufer electrode BEFORE concrete pour showing rebar continuity and pigtail. Photograph the grounding electrode conductor connection at panel. Photograph service entrance conductors and meter.",
        must_show:         "Ufer rebar length and pigtail visible, GEC connection at panel, service conductor size marking",
      },
      {
        label:             "Branch Circuit Rough-In — Box Fill & Wire Routing",
        description:       "All boxes installed, wire fill within limits, cables secured and protected",
        irc:               "NEC 314.16 — box fill calculation (2.0 cu in per #14, 2.25 per #12); NEC 314.20 — box front within ¼\" of finished surface; NEC 300.4 — cable protection through studs (nail plate if ≤1¼\" from edge)",
        ibc:               "NEC Article 314, 300",
        photo_instruction: "Photograph each box showing wire count and box cubic-inch rating marked. Photograph nail plates on any cable within 1¼\" of stud edge. Photograph cable stapling at correct intervals.",
        must_show:         "Box cu-in rating stamp, nail plates where required, staple spacing ≤4.5ft (NEC 334.30)",
      },
      {
        label:             "GFCI & AFCI Protection",
        description:       "GFCI protection at all required locations; AFCI protection on all required circuits",
        irc:               "NEC 210.8 — GFCI required: bathrooms, garages, outdoors, crawl spaces, unfinished basements, kitchens within 6ft of sink, laundry, boathouses; NEC 210.12 — AFCI required on all 15A/20A 120V branch circuits in dwelling units (bedrooms, living areas, kitchens, etc.)",
        ibc:               "NEC §210.8, §210.12",
        photo_instruction: "Photograph GFCI outlet or breaker at each required location. Photograph AFCI breakers in panel. Test button visible on GFCI devices.",
        must_show:         "GFCI devices at all wet/outdoor locations, AFCI breakers for bedroom/living circuits, test buttons visible",
      },
      {
        label:             "Rough-In Inspection — All Circuits, Working Clearances",
        description:       "All rough wiring complete, panel working clearances maintained, ready for inspection",
        irc:               "NEC 110.26 — working clearance in front of panel: ≥30\" wide, ≥36\" deep, ≥6.5ft high; NEC 230.70 — service disconnect accessible and labeled",
        ibc:               "NEC §110.26",
        photo_instruction: "Photograph panel working clearance with tape showing 36\" depth from panel face. Photograph service disconnect label. Photograph completed rough-in from multiple angles.",
        must_show:         "36\" clearance measured in photo, service disconnect labeled, no obstructions in clearance zone",
      },
      {
        label:             "Final — Devices, Fixtures & Load Center Labeling",
        description:       "All outlets, switches, fixtures installed; panel circuits labeled; no open knockouts",
        irc:               "NEC 408.4 — every circuit breaker must be legibly identified; NEC 110.12 — no open knockouts in panels or boxes; NEC 410 — luminaire installation",
        ibc:               "NEC §408.4, §110.12",
        photo_instruction: "Photograph completed panel directory. Photograph representative outlet and switch installations. Photograph any junction box covers in place. Check for open knockouts.",
        must_show:         "Complete panel directory, all boxes covered, no open knockouts, circuit labels legible",
      },
    ]
  },
  "hvac": {
    name:     "HVAC / Mechanical",
    keywords: ["HVAC","furnace","AC","air conditioning","ductwork","heat pump","thermostat","ventilation","mini split","boiler"],
    points: [
      {
        label:             "Equipment Installation & Clearances",
        description:       "Furnace/air handler installed with required clearances to combustibles",
        irc:               "IRC M1306 — clearances to combustibles per equipment listing label; M1305.1 — appliance access: passageway ≥22\"×30\", solid flooring, lighting and outlet within 25ft",
        ibc:               "IMC §304, §306",
        photo_instruction: "Photograph equipment label showing required clearances. Photograph measured distance from unit to nearest combustible. Photograph access passageway dimensions.",
        must_show:         "Equipment label clearance requirements, measured clearance in photo, access path dimensions",
      },
      {
        label:             "Duct Installation — Support, Joints & Sealing",
        description:       "Ducts supported at correct intervals, all joints sealed with mastic or UL 181 tape",
        irc:               "IRC M1601.4.1 — joints and seams sealed with mastic, mastic-plus-mesh, or UL 181A/B tape (NOT standard duct tape); M1601.4.4 — round duct supported ≤10ft, rectangular ≤4ft",
        ibc:               "IMC §603",
        photo_instruction: "Photograph duct joints showing mastic or approved tape (not gray duct tape). Photograph duct hangers showing spacing. Photograph any flex duct connections.",
        must_show:         "Mastic or UL 181 tape at all joints, hanger spacing within limits, flex duct not kinked",
      },
      {
        label:             "Combustion Air & Gas Piping",
        description:       "Adequate combustion air provided; gas piping installed and pressure tested",
        irc:               "IRC G2407 — combustion air: ≥50 cu ft per 1,000 BTU/hr input for indoor air; M1703 — combustion air openings; G2417 — gas piping test: 10 psi air for 15 min (or 3 psi for ≥½ hr) before appliances connected",
        ibc:               "IMC §701, §303.3; IFC §6303",
        photo_instruction: "Photograph combustion air opening size with measurement. Photograph gas piping pressure gauge showing test pressure. Photograph gas shutoff valve location.",
        must_show:         "Combustion air opening dimensions, gas test gauge reading, shutoff valve accessible and labeled",
      },
      {
        label:             "Condensate Drainage & Secondary Drain",
        description:       "Primary condensate drain installed; secondary/overflow drain or float switch in place",
        irc:               "IRC M1411.3 — secondary drain or auxiliary drain pan required for equipment in attic or above finished ceiling; pan ≥1.5\" deep, ≥3\" wider than unit on all sides",
        ibc:               "IMC §307.2",
        photo_instruction: "Photograph primary drain connection and routing to exterior or drain. Photograph secondary drain pan dimensions. Photograph float switch or secondary drain line if used.",
        must_show:         "Primary drain connection, secondary pan or float switch installed, drain terminates visible",
      },
      {
        label:             "Final — Duct Insulation, Filter, & System Test",
        description:       "Ducts in unconditioned space insulated to R-8; filter installed; system operates correctly",
        irc:               "IRC N1103.3.3 — ducts in unconditioned space: R-8 insulation; M1401.3 — equipment installed per listing and manufacturer instructions",
        ibc:               "IECC C403.2.2, IMC §607",
        photo_instruction: "Photograph duct insulation in attic/crawl space showing R-value label. Photograph filter installed in correct slot. Photograph thermostat set to test with system running.",
        must_show:         "R-8 or higher insulation label visible, filter in place, system operational (thermostat and supply air)",
      },
    ]
  },
  "concrete": {
    name:     "Concrete / Foundation",
    keywords: ["concrete","foundation","slab","driveway","patio","footing","pour","rebar","form","sidewalk"],
    points: [
      {
        label:             "Footing Excavation & Soil Bearing",
        description:       "Footings at correct depth, bearing on undisturbed soil, frost depth met",
        irc:               "IRC R403.1 — footings bear on undisturbed soil; R301.2(7) — frost depth per Table R301.2(1) (varies by location); R403.1.1 — footing depth ≥12\" below undisturbed ground surface",
        ibc:               "IBC §1809.4",
        photo_instruction: "Photograph footing trench showing depth measurement from grade to bottom. Photograph undisturbed soil at footing base. Include tape measure showing frost-depth compliance.",
        must_show:         "Footing depth measurement, undisturbed soil visible at base, no loose backfill under footing",
      },
      {
        label:             "Rebar Placement & Concrete-Encased Electrode",
        description:       "Rebar sized and positioned per plan; Ufer electrode in place before pour",
        irc:               "IRC R403.1.3 — footing reinforcement per Table R403.1.3(1); NEC 250.52(A)(3) — Ufer: ≥20ft of ≥½\" rebar or #4 bare copper encased in ≥2\" concrete",
        ibc:               "IBC §1905 / ACI 318 §20.6.1 — minimum cover: 3\" cast against earth, 2\" exposed to weather",
        photo_instruction: "Photograph rebar chairs/supports showing minimum concrete cover. Photograph Ufer pigtail extending from footing form. Include tape showing rebar size and spacing.",
        must_show:         "Rebar chairs maintaining minimum cover, Ufer pigtail visible and tagged, rebar size and spacing per plan",
      },
      {
        label:             "Vapor Retarder & Sub-Slab Preparation",
        description:       "Vapor retarder installed over compacted fill before slab pour",
        irc:               "IRC R506.2.3 — vapor retarder: ≥10-mil Class A per ASTM E1745 (2021 IRC), joints lapped ≥6\", extended up stem walls",
        ibc:               "IBC §1805.4.1",
        photo_instruction: "Photograph vapor barrier material showing 10-mil specification or ASTM E1745 markings. Photograph joint laps with tape showing ≥6\" overlap. Photograph edges turned up at walls.",
        must_show:         "Vapor barrier material spec marking, 6\" lap at joints, edges turned up at stem walls",
      },
      {
        label:             "Concrete Pour — Mix, Placement & Consolidation",
        description:       "Correct concrete mix design; proper placement and vibration/consolidation",
        irc:               "IRC R402.2 — minimum f'c per exposure: 2,500 psi interior slabs, 3,000 psi exposed to weather, 3,500 psi in severe freeze-thaw; R402.2 Table — w/c ratio per exposure",
        ibc:               "IBC §1905.3 / ACI 318 Table 19.3.3.1",
        photo_instruction: "Photograph concrete delivery ticket showing mix design and PSI strength. Photograph vibrator being used during pour. Photograph finished surface before curing compound applied.",
        must_show:         "Concrete ticket with f'c and w/c ratio, vibration occurring during pour, surface finish",
      },
      {
        label:             "Anchor Bolts, Curing & Slab Tolerances",
        description:       "Anchor bolts set while concrete is wet; curing compound applied; slab level within tolerance",
        irc:               "IRC R403.1.6 — anchor bolts ≥½\" dia., ≤6ft o.c., within 12\" of plate ends, ≥7\" embedment, 3\"×3\"×0.229\" plate washer; R506.2.4 — slab thickness ≥3.5\" (IRC residential)",
        ibc:               "IBC §1905.1.8 / ACI 117 — slab tolerance: flatness F-number or ¼\" in 10ft",
        photo_instruction: "Photograph anchor bolts set in wet concrete while still plastic. Measure and photograph bolt spacing and distance from plate ends. Photograph curing compound being applied.",
        must_show:         "Anchor bolt spacing measured, embedment depth marker, curing compound application",
      },
    ]
  },
  "flooring": {
    name:     "Flooring / Subfloor",
    keywords: ["floor","flooring","hardwood","LVP","tile","carpet","laminate","subfloor","underlayment","install"],
    points: [
      {
        label:             "Subfloor Condition & Moisture Testing",
        description:       "Subfloor flat, structurally sound, moisture content within limits before flooring",
        irc:               "IRC R503.2 — wood structural panel subfloor: APA rated sheathing per span table; most flooring manufacturers require MC ≤14% (wood flooring) or ≤3 lbs/1000 sf/24hr MVER (concrete)",
        ibc:               "IBC §2304.9",
        photo_instruction: "Photograph moisture meter reading on subfloor in multiple locations. Photograph any high-spot/low-spot measurements with straightedge. Document any squeaks or soft spots found.",
        must_show:         "Moisture meter reading visible, flatness measurement with 10ft straightedge, any repairs made",
      },
      {
        label:             "Underlayment Installation",
        description:       "Correct underlayment installed per flooring manufacturer and code",
        irc:               "IRC R503 — subfloor per span table; manufacturer installation instructions govern underlayment type and thickness for warranty compliance",
        ibc:               "IBC §2304.9",
        photo_instruction: "Photograph underlayment material label showing specification. Photograph seam treatment (tape, stapling). Photograph any transitions between underlayment sections.",
        must_show:         "Underlayment spec label, seams properly treated, no voids or bubbles",
      },
      {
        label:             "Flooring Layout & Acclimation",
        description:       "Flooring material acclimated on-site; layout lines established",
        irc:               "Manufacturer installation requirements (NWFA for hardwood: acclimate 3–5 days at job-site conditions); IRC R302.7 — under-stair space protection",
        ibc:               "NWFA Installation Guidelines; ANSI A108 (tile)",
        photo_instruction: "Photograph flooring material stored and acclimating on-site (not sealed in boxes). Photograph chalk line layout. Photograph room temperature and humidity reading.",
        must_show:         "Flooring open and acclimating, temp/humidity reading, layout lines established",
      },
      {
        label:             "Flooring Installation — Fastening & Pattern",
        description:       "Flooring fastened correctly, pattern consistent, expansion gaps maintained",
        irc:               "NWFA Installation Guidelines: ¾\" solid hardwood — cleat/staple every 6–8\"; expansion gap ¾\" at all walls; ANSI A108.02 — tile: thin-set coverage ≥80% interior (≥95% wet areas)",
        ibc:               "NWFA / ANSI A108 / manufacturer specs",
        photo_instruction: "Photograph expansion gap at wall with spacer in place. Photograph fastening pattern (pull back carpet/lift a plank where accessible). For tile: lift a tile immediately after setting to check mortar coverage.",
        must_show:         "Expansion gap at perimeter, fastener spacing visible, mortar coverage on tile back",
      },
      {
        label:             "Transitions, Thresholds & Final Inspection",
        description:       "All transitions installed; no trip hazards; floor flat and clean",
        irc:               "IRC R311.7.5 — stair treads: uniform rise ≤7¾\", run ≥10\"; R311.8 — ramp slope; ADA 303.3 — vertical change ≤¼\" without bevel (if ADA applies)",
        ibc:               "IBC §1003.3 (floor surfaces)",
        photo_instruction: "Photograph all threshold transitions from room to room. Photograph any change-in-level measurement. Photograph finished floor surface overall condition.",
        must_show:         "All transitions in place, level changes measured, no protruding fasteners or gaps",
      },
    ]
  },
  "painting": {
    name:     "Painting / Finishes",
    keywords: ["paint","painting","primer","coat","drywall","finish","stain","caulk","texture"],
    points: [
      {
        label:             "Surface Preparation — Drywall & Substrate",
        description:       "Drywall taped, mudded, and sanded to correct level before paint",
        irc:               "GA-214 Recommended Levels of Gypsum Board Finish — Level 4 minimum for flat paint; Level 5 for gloss/semi-gloss or critical lighting",
        ibc:               "GA-214 / ASTM C840",
        photo_instruction: "Photograph drywall seams under raking (side) light to show finish level. Photograph any remaining imperfections before primer. Document finish level agreed on with homeowner.",
        must_show:         "Seams smooth under raking light, no mud ridges, corner bead straight",
      },
      {
        label:             "Primer Application",
        description:       "Correct primer applied to all surfaces; coverage even; no bare spots",
        irc:               "Manufacturer specs and PDCA Standards (P1, P2, P3, P4 series)",
        ibc:               "PDCA / MPI Architectural Painting Specification Manual",
        photo_instruction: "Photograph primed surfaces showing even coverage. Photograph primer product label (manufacturer, type). Note any areas with bleed-through staining requiring second primer coat.",
        must_show:         "Even primer coverage, no bare spots, product label visible, tinted to topcoat color if specified",
      },
      {
        label:             "First Coat — Application & Coverage",
        description:       "First coat applied at correct spread rate; even coverage, no holidays",
        irc:               "PDCA P4 / MPI Standards — spread rate per manufacturer; mil thickness per spec sheet",
        ibc:               "MPI Architectural Painting Specification Manual §9",
        photo_instruction: "Photograph first coat wet mil thickness using a wet film gauge if specified. Photograph any areas with thin coverage or holidays (misses). Photograph product label and batch number.",
        must_show:         "Wet mil reading if gauged, even sheen, product batch number recorded",
      },
      {
        label:             "Second Coat & Finish Inspection",
        description:       "Final coat applied; uniform sheen; no drips, laps, or brush marks visible",
        irc:               "PDCA P12 — inspection standard: uniform color and sheen, no defects visible at 5ft in normal light",
        ibc:               "MPI §9; ASTM D3730 (paint film testing)",
        photo_instruction: "Photograph finished walls under normal lighting and under raking light. Photograph any defects found. Photograph final coat product label.",
        must_show:         "Uniform sheen at 5ft viewing distance, no drips or laps, final coat label",
      },
      {
        label:             "Trim, Cut Lines & Cleanup",
        description:       "Trim painted cleanly; cut lines straight; hardware replaced; job site clean",
        irc:               "PDCA P5 (protection of adjacent surfaces); PDCA P1 (workmanship standard)",
        ibc:               "PDCA Standards",
        photo_instruction: "Photograph trim cut lines at ceiling and floor. Photograph hardware reinstalled. Photograph overall room condition showing clean job site.",
        must_show:         "Straight cut lines (no bleed onto trim or ceiling), hardware in place, no paint on floors or fixtures",
      },
    ]
  },
  "general": {
    name:     "General Contractor / Other",
    keywords: ["general","renovation","remodel","repair","installation","construction","project"],
    points: [
      {
        label:             "Site Safety & Permit Posted",
        description:       "Building permit posted visibly; PPE in use; site safe and organized",
        irc:               "IRC R105.7 — permit must be posted on site and visible from street until final inspection",
        ibc:               "IBC §105.7",
        photo_instruction: "Photograph building permit posted at front of property (readable). Photograph crew wearing PPE. Photograph overall site organization.",
        must_show:         "Permit visible and readable, PPE in use, no obvious safety violations",
      },
      {
        label:             "Work-in-Progress Milestone",
        description:       "Substantial progress on agreed scope of work visible",
        irc:               "Contractual milestone — specific IRC section depends on trade being performed",
        ibc:               "Contractual / as applicable",
        photo_instruction: "Photograph wide view of work area showing scope of work in progress. Photograph specific work completed since last checkpoint. Include reference objects for scale.",
        must_show:         "Clear progress visible, scope matches contract, work area identified",
      },
      {
        label:             "Materials On-Site & Specification",
        description:       "Specified materials on site; product labels confirm correct specification",
        irc:               "IRC R101.2 — materials must meet referenced standards; specific IRC section per material",
        ibc:               "IBC §1703 — product approval",
        photo_instruction: "Photograph material specification labels for all major materials (lumber grade stamps, concrete bags, etc.). Photograph materials stored properly off ground and covered.",
        must_show:         "Grade stamps and spec labels visible, materials protected from weather, quantities match scope",
      },
      {
        label:             "Subcontractor Work Complete",
        description:       "Specialist trade work (mechanical, electrical, plumbing) completed and inspected",
        irc:               "IRC R109 — required inspections must be completed before concealment",
        ibc:               "IBC §110",
        photo_instruction: "Photograph any rough-in work by subcontractors before walls are closed. Photograph any required inspection approval cards or certificates posted on site.",
        must_show:         "All rough-in work visible before concealment, inspection tags if applicable",
      },
      {
        label:             "Final Walkthrough & Punch List",
        description:       "All agreed work complete; punch list items resolved; site cleaned",
        irc:               "IRC R110 — Certificate of Occupancy required before occupancy; final inspection must pass",
        ibc:               "IBC §111",
        photo_instruction: "Photograph each completed area of agreed scope. Photograph final cleanup. Photograph any outstanding items noted for the homeowner.",
        must_show:         "All contracted work visible and complete, site clean, no materials left behind",
      },
    ]
  },
}

function detectTrade(description) {
  const text = description.toLowerCase()
  let bestTrade = 'general'
  let bestScore = 0
  for (const [trade, profile] of Object.entries(TRADE_PROFILES)) {
    if (trade === 'general') continue
    const score = profile.keywords.filter(k => text.includes(k)).length
    if (score > bestScore) { bestScore = score; bestTrade = trade }
  }
  return bestTrade
}

function scoreDescription(description) {
  const text = description.toLowerCase()
  let score = 0
  const feedback = []

  // Length
  const words = text.split(/\s+/).filter(Boolean).length
  if (words >= 30) score += 20
  else if (words >= 15) { score += 10; feedback.push('Add more detail about the work needed') }
  else { feedback.push('Description is too short — add what needs to be done and where') }

  // Measurements
  if (/\d+\s*(sq|square|sf|ft|foot|feet|inch|meter|m²|yard)/.test(text)) score += 20
  else feedback.push('Include square footage or dimensions')

  // Materials mentioned
  if (/\b(wood|tile|concrete|drywall|pex|copper|asphalt|vinyl|hardwood|metal|brick|stucco|lvp|granite|quartz)\b/.test(text)) score += 20
  else feedback.push('Mention the materials to be used')

  // Action verbs
  if (/\b(install|replace|repair|remove|build|add|upgrade|remodel|renovate|fix|seal|paint|demo|demolish)\b/.test(text)) score += 20
  else feedback.push('Describe the action — install, replace, repair, etc.')

  // Trade specifics
  const trade = detectTrade(description)
  if (trade !== 'general') score += 20

  return { score: Math.min(score, 100), feedback, trade }
}

function getLocalPoints(description) {
  const trade = detectTrade(description)
  return TRADE_PROFILES[trade].points
}

// ─────────────────────────────────────────────────
// SHIELD BRIEF UI
// Drop into Post a Job form — scores description live,
// asks follow-up questions, previews the 5 checkpoints
// onReady(description) is called when the description
// is good enough (score >= 70) and the user confirms
// ─────────────────────────────────────────────────
function renderShieldBrief(container, onReady) {
  const wrap = document.createElement('div')
  wrap.className = 'shield-brief-wrap'
  wrap.innerHTML = `
    <div class="shield-brief-header">
      <span class="shield-icon">🛡️</span>
      <div>
        <strong class="shield-brief-title">TradeDeck Shield</strong>
        <span class="shield-brief-sub">AI monitors 5 critical checkpoints on your job</span>
      </div>
    </div>
    <textarea
      id="shield-brief-input"
      class="shield-brief-textarea"
      placeholder="Describe your project in detail. The more specific you are, the more accurate your AI checkpoints will be."
      rows="4"
    ></textarea>
    <div id="shield-brief-score-bar-wrap" class="shield-score-bar-wrap" style="display:none">
      <div id="shield-brief-score-bar" class="shield-score-bar"></div>
    </div>
    <div id="shield-brief-feedback" class="shield-brief-feedback"></div>
    <div id="shield-brief-questions" class="shield-brief-questions"></div>
    <div id="shield-brief-points-preview" class="shield-brief-points-preview" style="display:none"></div>
    <button id="shield-brief-confirm" class="shield-pay-btn" style="display:none">
      Confirm — Generate My 5 Checkpoints
    </button>
  `

  container.appendChild(wrap)

  const textarea   = wrap.querySelector('#shield-brief-input')
  const scoreBar   = wrap.querySelector('#shield-brief-score-bar')
  const scoreWrap  = wrap.querySelector('#shield-brief-score-bar-wrap')
  const feedbackEl = wrap.querySelector('#shield-brief-feedback')
  const questionsEl = wrap.querySelector('#shield-brief-questions')
  const pointsEl   = wrap.querySelector('#shield-brief-points-preview')
  const confirmBtn = wrap.querySelector('#shield-brief-confirm')

  let debounceTimer = null

  textarea.addEventListener('input', () => {
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => updateBrief(textarea.value), 400)
  })

  function updateBrief(text) {
    if (text.trim().length < 10) {
      scoreWrap.style.display = 'none'
      feedbackEl.innerHTML = ''
      questionsEl.innerHTML = ''
      pointsEl.style.display = 'none'
      confirmBtn.style.display = 'none'
      return
    }

    const { score, feedback, trade } = scoreDescription(text)
    const points = TRADE_PROFILES[trade].points
    const questions = TRADE_PROFILES[trade].questions

    // Score bar
    scoreWrap.style.display = 'block'
    scoreBar.style.width = score + '%'
    scoreBar.style.background = score >= 70 ? '#2d7a4f' : score >= 40 ? '#d4a017' : '#c0392b'
    scoreBar.title = `Description quality: ${score}/100`

    // Feedback
    feedbackEl.innerHTML = feedback.length
      ? `<ul class="shield-feedback-list">${feedback.map(f => `<li>${f}</li>`).join('')}</ul>`
      : `<p class="shield-feedback-ok">✅ Great description — ${trade} project detected</p>`

    // Follow-up questions if score is low
    if (score < 70 && questions.length) {
      questionsEl.innerHTML = `
        <p class="shield-questions-label">Answer these to improve your checkpoints:</p>
        <ul class="shield-questions-list">
          ${questions.map(q => `<li>${q}</li>`).join('')}
        </ul>
      `
    } else {
      questionsEl.innerHTML = ''
    }

    // Points preview
    pointsEl.style.display = 'block'
    pointsEl.innerHTML = `
      <p class="shield-points-label">Your 5 AI checkpoints:</p>
      ${points.map((p, i) => `
        <div class="shield-point-preview">
          <span class="shield-point-num-sm">${i + 1}</span>
          <div>
            <strong>${p.label}</strong>
            <p>${p.description}</p>
          </div>
        </div>
      `).join('')}
    `

    // Confirm button
    if (score >= 50) {
      confirmBtn.style.display = 'block'
      confirmBtn.textContent = score >= 70
        ? 'Confirm — Generate My 5 Checkpoints'
        : 'Continue with current description'
    } else {
      confirmBtn.style.display = 'none'
    }
  }

  confirmBtn.addEventListener('click', () => {
    const description = textarea.value.trim()
    if (description && onReady) onReady(description)
  })

  // Return textarea reference so Post a Job form can read the value
  return {
    getValue: () => textarea.value.trim(),
    getPoints: () => getLocalPoints(textarea.value.trim()),
  }
}

// ============================================================
// PART 2 — PAYMENT FLOW
// ============================================================

// ─────────────────────────────────────────────────
// SHIELD TOGGLE (simpler alternative to the Brief UI)
// Use renderShieldBrief() above for the full experience.
// This is a lightweight toggle for minimal Post a Job forms.
// ─────────────────────────────────────────────────
function renderShieldToggle(container, jobId, jobBudget = 0, jobDescription = '') {
  const price   = getShieldPrice(jobBudget)
  const elected = { value: false }

  const box = document.createElement('div')
  box.className = 'shield-toggle-box'
  box.innerHTML = `
    <div class="shield-toggle-header">
      <span class="shield-icon">🛡️</span>
      <div class="shield-toggle-title">
        <strong>Add TradeDeck Shield</strong>
        <span class="shield-subtitle">AI monitors your project at the 5 moments that determine the outcome</span>
      </div>
      <label class="shield-switch">
        <input type="checkbox" id="shield-toggle-input">
        <span class="shield-slider"></span>
      </label>
    </div>
    <div class="shield-details" id="shield-details" style="display:none">
      <ul class="shield-list">
        <li>Contractor uploads photos at each of 5 AI-designated checkpoints</li>
        <li>AI reviews each upload for quality and code compliance</li>
        <li>You see everything in real time on your Shield dashboard</li>
        <li>Full photo record protects you if anything goes wrong</li>
        <li>Completion report issued on job close</li>
      </ul>
      <div class="shield-price-row">
        <span class="shield-price">$${price}</span>
        <span class="shield-price-note">one-time · best for jobs over $5,000</span>
      </div>
      <button class="shield-pay-btn" id="shield-pay-btn">Add Shield — $${price}</button>
      <p class="shield-contractor-note">
        If your contractor subscribes to Shield Pro, you get Shield free on this job.
      </p>
    </div>
  `

  const toggle  = box.querySelector('#shield-toggle-input')
  const details = box.querySelector('#shield-details')
  const payBtn  = box.querySelector('#shield-pay-btn')

  toggle.addEventListener('change', () => {
    details.style.display = toggle.checked ? 'block' : 'none'
    elected.value = toggle.checked
  })

  payBtn.addEventListener('click', async () => {
    payBtn.disabled = true
    payBtn.textContent = 'Processing…'
    try {
      await purchaseShieldPerJob(jobId, price, jobDescription)
      payBtn.textContent = '✅ Shield Active'
      payBtn.style.background = 'var(--success, #2d7a4f)'
    } catch (err) {
      payBtn.disabled = false
      payBtn.textContent = `Add Shield — $${price}`
      if (err.message !== 'Payment cancelled') alert('Payment failed: ' + err.message)
    }
  })

  container.appendChild(box)
  return { elected }
}

// ─────────────────────────────────────────────────
// PER-JOB PURCHASE — full real Stripe charge
// ─────────────────────────────────────────────────
async function purchaseShieldPerJob(jobId, amount, jobDescription) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) throw new Error('Not signed in')

  if (typeof Stripe === 'undefined') await loadStripeScript()
  const stripe = Stripe(STRIPE_PK)

  // Collect card — opens the bottom-sheet modal
  let paymentMethod
  try {
    paymentMethod = await collectCard(stripe, amount, 'AI milestone monitoring for this job')
  } catch (err) {
    throw err  // 'Payment cancelled' or card error — handled by caller
  }

  // Create PaymentIntent on backend AFTER card collected
  const res = await fetch(`${API_BASE}/shield/create-payment-intent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.access_token}`
    },
    body: JSON.stringify({ job_id: jobId, amount_cents: amount * 100 })
  })
  if (!res.ok) throw new Error('Could not create payment: ' + await res.text())
  const { client_secret } = await res.json()

  // Confirm with the collected PaymentMethod
  const { error: confirmError, paymentIntent } = await stripe.confirmCardPayment(
    client_secret,
    { payment_method: paymentMethod.id }
  )
  if (confirmError) throw new Error(confirmError.message)
  if (paymentIntent.status !== 'succeeded') {
    throw new Error(`Payment status: ${paymentIntent.status}. Please try again.`)
  }

  // Write Shield job to DB — capture the UUID
  const { data: shieldJobRow, error: dbErr } = await sb
    .from('shield_jobs')
    .insert({
      job_id:            jobId,
      homeowner_id:      session.user.id,
      payment_type:      'per_job',
      stripe_payment_id: paymentIntent.id,
      covered_by:        'homeowner',
      status:            'active'
    })
    .select('id')
    .single()
  if (dbErr) throw new Error('Shield activated but DB record failed: ' + dbErr.message)

  const shieldJobId = shieldJobRow.id

  // Insert local points immediately (instant) then sync to backend
  if (jobDescription) {
    const localPoints = getLocalPoints(jobDescription)

    // Write points directly to Supabase (no backend round trip needed)
    const pointRows = localPoints.map((p, i) => ({
      shield_job_id: shieldJobId,
      job_id:        jobId,
      point_number:  i + 1,
      label:         p.label,
      description:   p.description,
    }))

    await sb.from('shield_pivotal_points').insert(pointRows)

    // Also call backend to get Claude-enhanced versions asynchronously
    fetch(`${API_BASE}/shield/generate-points`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.access_token}`
      },
      body: JSON.stringify({
        shield_job_id:   shieldJobId,
        job_id:          jobId,
        job_description: jobDescription
      })
    }).catch(err => console.warn('Shield: backend point enhancement deferred —', err.message))
  }

  return shieldJobId
}

// ─────────────────────────────────────────────────
// CONTRACTOR SUBSCRIPTION ($49/month)
// ─────────────────────────────────────────────────
async function subscribeContractorToShield(containerEl) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) throw new Error('Not signed in')

  const { data: existing } = await sb
    .from('shield_subscriptions')
    .select('id, status, verified_jobs_count, is_verified_contractor')
    .eq('contractor_id', session.user.id)
    .single()

  if (existing && existing.status === 'active') {
    containerEl.innerHTML = `
      <div class="shield-badge-full">
        🛡️ <strong>Shield Pro Active</strong>
        ${existing.is_verified_contractor
          ? '<span class="shield-verified-tag">TradeDeck Verified ✓</span>'
          : `<span class="shield-progress-tag">${existing.verified_jobs_count}/3 verified jobs</span>`
        }
      </div>
    `
    return
  }

  const box = document.createElement('div')
  box.className = 'shield-sub-box'
  box.innerHTML = `
    <div class="shield-sub-header">
      <span class="shield-icon">🛡️</span>
      <strong>TradeDeck Shield Pro</strong>
    </div>
    <ul class="shield-list">
      <li>Shield badge on your profile</li>
      <li>Homeowners on your jobs get Shield free — they'll choose you over the next guy</li>
      <li>AI photo analysis builds your quality portfolio automatically</li>
      <li>Verified completion certificate per job</li>
      <li>Priority placement on Shield job listings</li>
      <li>3 clean completions = TradeDeck Verified Contractor status</li>
    </ul>
    <div class="shield-price-row">
      <span class="shield-price">$${CONTRACTOR_SUB_PRICE}/mo</span>
    </div>
    <button class="shield-pay-btn" id="contractor-sub-btn">
      Subscribe — $${CONTRACTOR_SUB_PRICE}/month
    </button>
  `

  const btn = box.querySelector('#contractor-sub-btn')
  btn.addEventListener('click', async () => {
    btn.disabled = true
    btn.textContent = 'Processing…'
    try {
      const res = await fetch(`${API_BASE}/shield/contractor-subscribe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.access_token}`
        },
        body: JSON.stringify({ contractor_id: session.user.id })
      })
      if (!res.ok) throw new Error(await res.text())
      const { stripe_url } = await res.json()
      window.location.href = stripe_url
    } catch (err) {
      btn.disabled = false
      btn.textContent = `Subscribe — $${CONTRACTOR_SUB_PRICE}/month`
      alert('Subscription error: ' + err.message)
    }
  })

  containerEl.appendChild(box)
}

// ============================================================
// PART 3 — HOMEOWNER DASHBOARD
// ============================================================

async function renderShieldDashboard(containerEl) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) {
    containerEl.innerHTML = '<p class="shield-empty">Sign in to view your Shield jobs.</p>'
    return
  }
  containerEl.innerHTML = '<p class="shield-loading">Loading Shield…</p>'

  const { data: shieldJobs, error } = await sb
    .from('shield_jobs')
    .select(`
      id, status, activated_at, job_id,
      shield_pivotal_points (
        id, point_number, label, description, status,
        shield_photos (
          id, public_url, ai_verdict, ai_confidence, ai_notes, uploaded_at
        )
      )
    `)
    .eq('homeowner_id', session.user.id)
    .order('activated_at', { ascending: false })

  if (error || !shieldJobs?.length) {
    containerEl.innerHTML = `
      <div class="shield-empty">
        <span style="font-size:2rem">🛡️</span>
        <p>No Shield-monitored jobs yet.</p>
        <p style="color:var(--muted)">Add Shield when posting your next job.</p>
      </div>
    `
    return
  }

  containerEl.innerHTML = `<h2 class="shield-dash-title">🛡️ TradeDeck Shield</h2>`

  for (const sj of shieldJobs) {
    const points = (sj.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)
    const completedCount = points.filter(p => p.status === 'approved').length
    const totalPoints    = points.length || 5
    const progressPct   = Math.round((completedCount / totalPoints) * 100)
    const allDone        = completedCount === totalPoints && totalPoints === 5

    const card = document.createElement('div')
    card.className = 'shield-job-card'
    card.innerHTML = `
      <div class="shield-job-header">
        <span class="shield-job-id">Job #${(sj.job_id || '').slice(-6).toUpperCase()}</span>
        <span class="shield-status shield-status--${sj.status}">${sj.status}</span>
      </div>
      <div class="shield-progress-bar-wrap">
        <div class="shield-progress-bar" style="width:${progressPct}%"></div>
      </div>
      <p class="shield-progress-label">${completedCount} of ${totalPoints} checkpoints complete</p>
      <div class="shield-points-list">
        ${points.map(p => renderPointCard(p)).join('')}
      </div>
      ${allDone && sj.status === 'active' ? `
        <button class="shield-closeout-btn" onclick="renderShieldCloseOutModal('${sj.id}')">
          🏁 Close Out This Job
        </button>
      ` : ''}
    `
    containerEl.appendChild(card)
  }
}

function renderPointCard(point) {
  const photo = point.shield_photos?.[0]
  const statusIcon = { pending:'⏳', uploaded:'📸', approved:'✅', flagged:'⚠️' }[point.status] || '⏳'
  const verdictColor = { pass:'#2d7a4f', flag:'#d4a017', fail:'#c0392b' }[photo?.ai_verdict] || 'inherit'

  return `
    <div class="shield-point shield-point--${point.status}">
      <div class="shield-point-header">
        <span class="shield-point-num">${statusIcon} Point ${point.point_number}</span>
        <span class="shield-point-label">${point.label}</span>
      </div>
      <p class="shield-point-desc">${point.description}</p>
      ${photo ? `
        <div class="shield-photo-block">
          <img class="shield-photo-thumb" src="${photo.public_url}" alt="Checkpoint photo" />
          <div class="shield-ai-verdict" style="color:${verdictColor}">
            <strong>AI: ${photo.ai_verdict?.toUpperCase() || '—'}</strong>
            ${photo.ai_confidence ? `<span>(${Math.round(photo.ai_confidence * 100)}%)</span>` : ''}
          </div>
          ${photo.ai_notes ? `<p class="shield-ai-notes">${photo.ai_notes}</p>` : ''}
        </div>
      ` : `<p class="shield-awaiting">Awaiting contractor photo upload</p>`}
    </div>
  `
}

// ============================================================
// PART 4 — CONTRACTOR PHOTO UPLOAD
// ============================================================

// ─────────────────────────────────────────────────
// SHIELD PHOTO VALIDATION HELPERS
// GPS, EXIF, and originality enforcement
// ─────────────────────────────────────────────────

/** Request GPS from browser. Returns {lat, lng, accuracy} or throws. */
function getGpsLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('GPS is not available on this device.'))
      return
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve({
        lat:      pos.coords.latitude,
        lng:      pos.coords.longitude,
        accuracy: pos.coords.accuracy   // metres
      }),
      err => {
        const msgs = {
          1: 'Location permission denied. Enable GPS in your browser settings to upload Shield photos.',
          2: 'Could not get GPS signal. Step outside or check your signal and try again.',
          3: 'GPS timed out. Try again.'
        }
        reject(new Error(msgs[err.code] || 'GPS error.'))
      },
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
    )
  })
}

/** Compute SHA-256 hash of a File using Web Crypto API.
 *  Returns hex string. Used for tamper-evident chain of custody. */
async function computeSHA256(file) {
  const buf    = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Read EXIF data from a File. Returns parsed tags or empty object. */
function readExif(file) {
  return new Promise(resolve => {
    // Use FileReader to get ArrayBuffer, then parse EXIF manually (lightweight)
    const reader = new FileReader()
    reader.onload = e => {
      try {
        const buf  = e.target.result
        const view = new DataView(buf)
        // JPEG starts with FFD8
        if (view.getUint16(0) !== 0xFFD8) { resolve({}); return }
        const tags = {}
        let offset = 2
        while (offset < buf.byteLength - 2) {
          const marker = view.getUint16(offset)
          offset += 2
          if (marker === 0xFFE1) {   // APP1 — EXIF block
            const segLen = view.getUint16(offset)
            const exifStr = String.fromCharCode(...new Uint8Array(buf, offset + 2, 6))
            if (exifStr.startsWith('Exif')) {
              // We have EXIF — note its presence and rough size
              tags.hasExif     = true
              tags.exifBytes   = segLen
              // Check for DateTimeOriginal marker (0x9003) — presence indicates camera metadata
              const segData = new Uint8Array(buf, offset, segLen)
              tags.hasDateTime = segData.includes(0x90) // rough heuristic
            }
            offset += segLen
          } else if ((marker & 0xFF00) === 0xFF00) {
            if (offset + 1 >= buf.byteLength) break
            offset += view.getUint16(offset)
          } else {
            break
          }
        }
        resolve(tags)
      } catch {
        resolve({})
      }
    }
    reader.onerror = () => resolve({})
    reader.readAsArrayBuffer(file)
  })
}

/** Check if file looks like a screenshot or re-photo of a screen */
function checkOriginality(file, exifTags) {
  const issues = []
  // Screenshots typically have no EXIF at all
  if (!exifTags.hasExif) {
    issues.push('No camera metadata found — this may be a screenshot or downloaded image.')
  }
  // PNG is almost always a screenshot (real cameras save JPEG)
  if (file.type === 'image/png') {
    issues.push('PNG format detected. Shield requires a direct camera photo (JPEG/HEIC), not a screenshot.')
  }
  // Very small file size for an "on-site" photo is suspicious
  if (file.size < 150 * 1024) {   // under 150KB
    issues.push('Photo file size is unusually small for an on-site construction photo.')
  }
  return issues
}

async function renderContractorUploadFlow(containerEl, shieldJobId, pointId) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) { containerEl.innerHTML = '<p style="color:var(--steel)">Sign in to upload.</p>'; return }

  // Load pivotal points if no specific pointId given
  let points = []
  if (!pointId) {
    const { data } = await sb
      .from('shield_pivotal_points')
      .select('id, point_number, label, description, status')
      .eq('shield_job_id', shieldJobId)
      .order('point_number')
    points = data || []
  }

  const box = document.createElement('div')
  box.className = 'shield-upload-box'

  const pointsHtml = points.length > 0
    ? points.map(p => `
        <div class="shield-point-row" data-point-id="${p.id}" style="border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px;margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <span style="font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:0.85rem;color:var(--white);">${p.point_number}. ${p.label}</span>
            <span class="shield-point-status" style="font-size:0.7rem;padding:2px 8px;border-radius:4px;background:${p.status === 'approved' ? 'rgba(74,222,128,0.15)' : 'rgba(245,158,11,0.12)'};color:${p.status === 'approved' ? '#4ADE80' : 'var(--amber)'};">${p.status || 'pending'}</span>
          </div>
          <div style="font-size:0.78rem;color:var(--steel);margin-bottom:6px;">${p.description}</div>
          ${p.irc ? `
          <div style="background:rgba(245,158,11,0.05);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:8px 10px;margin-bottom:8px;">
            <div style="font-size:0.68rem;color:rgba(245,158,11,0.7);font-weight:700;margin-bottom:3px;">📋 CODE REQUIREMENT</div>
            <div style="font-size:0.72rem;color:rgba(255,255,255,0.55);margin-bottom:4px;">${p.irc}</div>
            ${p.ibc ? `<div style="font-size:0.68rem;color:rgba(255,255,255,0.3);">IBC: ${p.ibc}</div>` : ''}
          </div>
          ` : ''}
          ${p.photo_instruction ? `
          <div style="background:rgba(255,255,255,0.03);border-left:2px solid rgba(245,158,11,0.3);padding:6px 10px;margin-bottom:8px;">
            <div style="font-size:0.68rem;color:rgba(245,158,11,0.6);font-weight:700;margin-bottom:2px;">📷 WHAT TO PHOTOGRAPH</div>
            <div style="font-size:0.72rem;color:rgba(255,255,255,0.5);">${p.photo_instruction}</div>
          </div>
          ` : ''}
          ${p.must_show ? `
          <div style="font-size:0.68rem;color:rgba(74,222,128,0.6);margin-bottom:8px;">✓ Must show: ${p.must_show}</div>
          ` : ''}
          ${p.status === 'approved'
            ? '<div style="font-size:0.78rem;color:#4ADE80;">✓ Photo approved</div>'
            : `<div style="font-size:0.72rem;color:rgba(255,255,255,0.35);margin-bottom:6px;">
                  📋 Take a wide shot (whole area) then a close-up detail shot. Both required.
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:6px 10px;">
                    <span style="font-size:0.78rem;color:var(--amber);font-weight:600;">📷 Wide Shot</span>
                    <input type="file" class="shield-point-file shield-wide-file" accept="image/jpeg,image/heic,image/heif" capture="environment" style="display:none;" data-point-id="${p.id}" data-shot-type="wide" />
                  </label>
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:6px 10px;">
                    <span style="font-size:0.78rem;color:var(--amber);font-weight:600;">🔍 Detail Shot</span>
                    <input type="file" class="shield-point-file shield-detail-file" accept="image/jpeg,image/heic,image/heif" capture="environment" style="display:none;" data-point-id="${p.id}" data-shot-type="detail" />
                  </label>
                </div>
                <div class="shield-point-status-msg" style="margin-top:8px;font-size:0.78rem;"></div>`
          }
        </div>`).join('')
    : `<div style="font-size:0.85rem;color:var(--steel);padding:12px 0;">Loading checkpoints…</div>`

  box.innerHTML = `
    <div style="margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:0.85rem;">📍</span>
        <span id="shield-gps-status" style="font-size:0.78rem;color:var(--steel);">Requesting GPS location…</span>
      </div>
      <div style="font-size:0.72rem;color:rgba(255,255,255,0.3);">GPS is required for all Shield photos. Enable location in your browser.</div>
    </div>
    <div id="shield-points-list">${pointsHtml}</div>
  `
  containerEl.appendChild(box)

  // ── Get GPS first ──
  const gpsStatusEl = box.querySelector('#shield-gps-status')
  let gpsData = null
  try {
    gpsData = await getGpsLocation()
    gpsStatusEl.textContent = `✅ GPS locked (±${Math.round(gpsData.accuracy)}m)`
    gpsStatusEl.style.color = '#4ADE80'
  } catch (err) {
    gpsStatusEl.textContent = '❌ ' + err.message
    gpsStatusEl.style.color = '#EF4444'
    // Block uploads — GPS required
    box.querySelectorAll('.shield-point-file').forEach(inp => inp.disabled = true)
    return
  }

  // ── Wire up each checkpoint file input ──
  box.querySelectorAll('.shield-point-file').forEach(fileInput => {
    fileInput.addEventListener('change', async function() {
      const file      = this.files[0]
      if (!file) return
      const thisPointId = this.dataset.pointId
      const shotType    = this.dataset.shotType || 'detail'  // 'wide' or 'detail'
      const row         = box.querySelector(`.shield-point-row[data-point-id="${thisPointId}"]`)
      const statusMsg   = row.querySelector('.shield-point-status-msg')
      const statusBadge = row.querySelector('.shield-point-status')

      statusMsg.style.color = 'var(--steel)'
      statusMsg.textContent = '🔍 Checking photo…'

      // ── Layer 1: EXIF + Originality ──
      const exifTags = await readExif(file)
      const issues   = checkOriginality(file, exifTags)
      if (issues.length > 0) {
        statusMsg.style.color = '#EF4444'
        statusMsg.innerHTML = '❌ ' + issues.join('<br>❌ ')
        this.value = ''
        return
      }

      // ── Layer 2: Compute SHA-256 hash (tamper-evident proof of file contents) ──
      statusMsg.textContent = '🔒 Computing integrity hash…'
      let fileHash = null
      try {
        fileHash = await computeSHA256(file)
      } catch (hashErr) {
        console.warn('SHA-256 failed (non-blocking):', hashErr)
      }

      statusMsg.textContent = '📤 Uploading…'

      try {
        const ts   = Date.now()
        const path = `shield-photos/${shieldJobId}/${thisPointId}/${ts}_${shotType}_${file.name}`

        const { error: storageErr } = await sb.storage
          .from('draw-photos')
          .upload(path, file, { contentType: file.type })
        if (storageErr) throw new Error(storageErr.message)

        const { data: { publicUrl } } = sb.storage.from('draw-photos').getPublicUrl(path)

        // ── Store photo with full chain-of-custody metadata ──
        const photoInsert = {
          point_id:        thisPointId,
          shield_job_id:   shieldJobId,
          contractor_id:   session.user.id,
          storage_path:    path,
          public_url:      publicUrl,
          gps_lat:         gpsData.lat,
          gps_lng:         gpsData.lng,
          gps_accuracy_m:  gpsData.accuracy,
          has_exif:        exifTags.hasExif || false,
          file_size_bytes: file.size,
          captured_at:     new Date(ts).toISOString(),
          device_user_agent: navigator.userAgent,
        }
        if (fileHash) {
          photoInsert.photo_hash      = fileHash
          photoInsert.hash_algorithm  = 'SHA-256'
        }
        // Store wide vs detail shot in correct column
        if (shotType === 'wide')   photoInsert.wide_shot_url   = publicUrl
        if (shotType === 'detail') photoInsert.detail_shot_url = publicUrl

        const { data: photoRow, error: dbErr } = await sb
          .from('shield_photos')
          .insert(photoInsert)
          .select('id')
          .single()
        if (dbErr) throw new Error(dbErr.message)

        // ── Only run AI analysis on the detail shot ──
        // (Wide shot is just an anchor — AI judges the detail)
        if (shotType === 'wide') {
          statusMsg.style.color = '#4ADE80'
          statusMsg.textContent = '✅ Wide shot saved. Now take the detail shot.'
          return
        }

        statusMsg.textContent = '🤖 Running AI analysis…'

        const analysisRes = await fetch(`${API_BASE}/shield/analyze-photo`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}`
          },
          body: JSON.stringify({
            photo_id:       photoRow.id,
            public_url:     publicUrl,
            point_id:       thisPointId,
            gps_lat:        gpsData.lat,
            gps_lng:        gpsData.lng,
            has_exif:       exifTags.hasExif || false,
            photo_hash:     fileHash,
            shot_type:      shotType,
            code_reference: p.irc || null,
          })
        })
        if (!analysisRes.ok) throw new Error('AI analysis failed')
        const result = await analysisRes.json()
        const { verdict, confidence, notes, authentic } = result

        const colors = { pass: '#4ADE80', flag: '#F59E0B', fail: '#EF4444', fake: '#EF4444' }
        const icons  = { pass: '✅', flag: '⚠️', fail: '❌', fake: '🚫' }
        statusMsg.style.color = colors[verdict] || 'var(--steel)'
        statusMsg.innerHTML = `
          ${icons[verdict] || '?'} <strong>${verdict.toUpperCase()}</strong> (${Math.round(confidence * 100)}% confidence)<br>
          <span style="opacity:0.85">${notes}</span>
        `
        if (statusBadge) {
          statusBadge.textContent = verdict
          statusBadge.style.background = verdict === 'pass' ? 'rgba(74,222,128,0.15)' : 'rgba(245,158,11,0.12)'
          statusBadge.style.color = colors[verdict]
        }

      } catch (err) {
        statusMsg.style.color = '#EF4444'
        statusMsg.textContent = '❌ ' + err.message
        this.value = ''
      }
    })
  })
}

// ============================================================
// PART 5 — CLOSE-OUT SYSTEM
// Tamper-evident SHA-256 completion packet
// ============================================================

async function renderShieldCloseOutModal(shieldJobId) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) return

  // Fetch everything needed for the packet
  const { data: shieldJob } = await sb
    .from('shield_jobs')
    .select(`
      id, job_id, homeowner_id, payment_type, stripe_payment_id,
      status, activated_at,
      shield_pivotal_points (
        id, point_number, label, description, status,
        shield_photos (
          id, public_url, ai_verdict, ai_confidence, ai_notes, uploaded_at
        )
      )
    `)
    .eq('id', shieldJobId)
    .single()

  if (!shieldJob) { alert('Could not load Shield job data.'); return }

  const points        = (shieldJob.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)
  const approvedCount = points.filter(p => p.status === 'approved').length
  const allApproved   = approvedCount === 5

  // Build modal
  const overlay = document.createElement('div')
  overlay.id = 'shield-closeout-overlay'
  overlay.innerHTML = `
    <div class="scm-backdrop"></div>
    <div class="scm-sheet" style="max-height:85vh;overflow-y:auto">
      <div class="scm-handle"></div>
      <div class="scm-header">
        <span class="shield-icon">🏁</span>
        <div class="scm-title-group">
          <strong class="scm-title">Close Out This Job</strong>
          <span class="scm-desc">Creates a tamper-evident completion record</span>
        </div>
      </div>

      <div class="shield-closeout-summary">
        <p>${approvedCount}/5 checkpoints approved</p>
        ${!allApproved ? `
          <div class="shield-closeout-warning">
            ⚠️ Not all checkpoints are approved.
            <label class="shield-closeout-override">
              <input type="checkbox" id="closeout-override" />
              Close anyway
            </label>
          </div>
        ` : '<p class="shield-feedback-ok">✅ All checkpoints approved</p>'}
      </div>

      <div class="shield-closeout-points">
        ${points.map(p => {
          const photo = p.shield_photos?.[0]
          return `
            <div class="shield-closeout-point shield-closeout-point--${p.status}">
              <span>${p.point_number}. ${p.label}</span>
              <span class="shield-closeout-verdict">
                ${photo ? photo.ai_verdict?.toUpperCase() : 'NO PHOTO'}
              </span>
            </div>
          `
        }).join('')}
      </div>

      <p id="closeout-status" class="shield-upload-status"></p>

      <button class="scm-submit-btn" id="closeout-confirm-btn"
        ${!allApproved ? 'disabled' : ''}>
        Generate Completion Record
      </button>
      <button class="scm-cancel-btn" id="closeout-cancel-btn">Cancel</button>
    </div>
  `

  document.body.appendChild(overlay)
  requestAnimationFrame(() => overlay.classList.add('scm-visible'))

  function closeModal() {
    overlay.classList.remove('scm-visible')
    overlay.addEventListener('transitionend', () => overlay.remove(), { once: true })
  }

  overlay.querySelector('.scm-backdrop').addEventListener('click', closeModal)
  overlay.querySelector('#closeout-cancel-btn').addEventListener('click', closeModal)

  // Enable confirm button if override is checked
  const overrideCheck = overlay.querySelector('#closeout-override')
  const confirmBtn    = overlay.querySelector('#closeout-confirm-btn')
  if (overrideCheck) {
    overrideCheck.addEventListener('change', () => {
      confirmBtn.disabled = !overrideCheck.checked
    })
  }

  confirmBtn.addEventListener('click', async () => {
    confirmBtn.disabled = true
    confirmBtn.textContent = 'Generating record…'
    const statusEl = overlay.querySelector('#closeout-status')

    try {
      await generateCloseOutRecord(shieldJob, session)
      statusEl.textContent = '✅ Completion record created and emailed.'
      statusEl.style.color = '#2d7a4f'
      confirmBtn.textContent = 'Done'

      // Refresh the dashboard after 2 seconds
      setTimeout(() => { closeModal(); renderShieldDashboard(document.querySelector('#shield-dashboard-root') || document.body) }, 2000)
    } catch (err) {
      confirmBtn.disabled = false
      confirmBtn.textContent = 'Generate Completion Record'
      statusEl.textContent = 'Error: ' + err.message
      statusEl.style.color = '#c0392b'
    }
  })
}

async function generateCloseOutRecord(shieldJob, session) {
  const points = (shieldJob.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)

  // Build the completion packet
  const packet = {
    shield_job_id:    shieldJob.id,
    job_id:           shieldJob.job_id,
    homeowner_id:     shieldJob.homeowner_id,
    payment_type:     shieldJob.payment_type,
    stripe_payment_id: shieldJob.stripe_payment_id,
    activated_at:     shieldJob.activated_at,
    closed_at:        new Date().toISOString(),
    closed_by:        session.user.id,
    points: points.map(p => ({
      point_number: p.point_number,
      label:        p.label,
      description:  p.description,
      status:       p.status,
      photo:        p.shield_photos?.[0] ? {
        public_url:    p.shield_photos[0].public_url,
        ai_verdict:    p.shield_photos[0].ai_verdict,
        ai_confidence: p.shield_photos[0].ai_confidence,
        ai_notes:      p.shield_photos[0].ai_notes,
        uploaded_at:   p.shield_photos[0].uploaded_at,
      } : null
    }))
  }

  // SHA-256 hash the packet — makes it tamper-evident
  const packetString = JSON.stringify(packet)
  const hashBuffer   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(packetString))
  const hashHex      = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')

  const fullRecord = { ...packet, sha256: hashHex }

  // Send to backend for storage + email
  const res = await fetch(`${API_BASE}/shield/complete-job`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.access_token}`
    },
    body: JSON.stringify(fullRecord)
  })
  if (!res.ok) throw new Error(await res.text())

  // Mark shield_job as complete in Supabase
  await sb.from('shield_jobs').update({ status: 'complete', completed_at: new Date().toISOString() }).eq('id', shieldJob.id)

  return fullRecord
}

// ============================================================
// PART 6 — SHIELD BADGE (contractor profile)
// ============================================================

async function renderShieldBadge(contractorId, containerEl) {
  const { data: sub } = await sb
    .from('shield_subscriptions')
    .select('status, is_verified_contractor, verified_jobs_count')
    .eq('contractor_id', contractorId)
    .single()

  if (!sub || sub.status !== 'active') return

  const badge = document.createElement('div')
  badge.className = 'shield-badge'
  badge.innerHTML = sub.is_verified_contractor
    ? `🛡️ <strong>TradeDeck Verified Contractor</strong>`
    : `🛡️ <strong>Shield Pro</strong> · ${sub.verified_jobs_count}/3 verified jobs`
  containerEl.appendChild(badge)
}

// ============================================================
// PART 7 — CARD COLLECTION MODAL (real Stripe Elements)
// ============================================================

function collectCard(stripe, amount, description) {
  return new Promise((resolve, reject) => {
    const overlay = document.createElement('div')
    overlay.id = 'shield-card-overlay'
    overlay.innerHTML = `
      <div class="scm-backdrop"></div>
      <div class="scm-sheet" role="dialog" aria-modal="true" aria-label="Payment">
        <div class="scm-handle"></div>
        <div class="scm-header">
          <span class="scm-icon">🛡️</span>
          <div class="scm-title-group">
            <strong class="scm-title">TradeDeck Shield</strong>
            <span class="scm-desc">${description || 'AI milestone monitoring'}</span>
          </div>
          <span class="scm-amount">$${amount}</span>
        </div>
        <div class="scm-section-label">Card details</div>
        <div id="scm-card-element" class="scm-card-input"></div>
        <div id="scm-card-error" class="scm-error" role="alert"></div>
        <div class="scm-secure-note">
          <span class="scm-lock">🔒</span>
          Secured by Stripe · Your card is never stored on TradeDeck servers
        </div>
        <button class="scm-submit-btn" id="scm-submit-btn">Pay $${amount}</button>
        <button class="scm-cancel-btn" id="scm-cancel-btn">Cancel</button>
      </div>
    `
    document.body.appendChild(overlay)
    requestAnimationFrame(() => overlay.classList.add('scm-visible'))

    const elements = stripe.elements()
    const cardEl   = elements.create('card', {
      style: {
        base: {
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          fontSize: '16px',
          color: '#1a1a1a',
          '::placeholder': { color: '#aab7c4' },
        },
        invalid: { color: '#c0392b', iconColor: '#c0392b' },
      },
      hidePostalCode: false,
    })
    cardEl.mount('#scm-card-element')
    cardEl.on('change', ({ error }) => {
      document.getElementById('scm-card-error').textContent = error ? error.message : ''
    })

    function closeModal() {
      overlay.classList.remove('scm-visible')
      overlay.addEventListener('transitionend', () => overlay.remove(), { once: true })
      cardEl.destroy()
    }

    document.getElementById('scm-cancel-btn').addEventListener('click', () => {
      closeModal()
      reject(new Error('Payment cancelled'))
    })
    overlay.querySelector('.scm-backdrop').addEventListener('click', () => {
      closeModal()
      reject(new Error('Payment cancelled'))
    })

    const submitBtn = document.getElementById('scm-submit-btn')
    submitBtn.addEventListener('click', async () => {
      submitBtn.disabled = true
      submitBtn.textContent = 'Processing…'
      document.getElementById('scm-card-error').textContent = ''

      const { paymentMethod, error } = await stripe.createPaymentMethod({ type: 'card', card: cardEl })
      if (error) {
        document.getElementById('scm-card-error').textContent = error.message
        submitBtn.disabled = false
        submitBtn.textContent = `Pay $${amount}`
        return
      }
      closeModal()
      resolve(paymentMethod)
    })
  })
}

// ============================================================
// PART 8 — CSS
// ============================================================

const SHIELD_CSS = `
/* ── Base ─────────────────────────────────────── */
.shield-toggle-box, .shield-sub-box {
  border: 1px solid var(--brass, #b8860b);
  border-radius: 0.75rem;
  padding: 1rem;
  margin: 1rem 0;
  background: var(--surface, #fff);
}
.shield-toggle-header, .shield-sub-header {
  display: flex; align-items: center; gap: 0.75rem;
}
.shield-icon { font-size: 1.5rem; flex-shrink: 0; }
.shield-toggle-title { flex: 1; }
.shield-toggle-title strong { display: block; font-size: 0.95rem; color: var(--brass, #b8860b); }
.shield-subtitle { font-size: 0.78rem; color: var(--muted, #666); }
.shield-list { padding-left: 1.25rem; margin: 0.5rem 0; font-size: 0.85rem; }
.shield-list li { margin-bottom: 0.35rem; }
.shield-price-row { display: flex; align-items: baseline; gap: 0.5rem; margin: 0.75rem 0; }
.shield-price { font-size: 1.5rem; font-weight: 700; color: var(--spruce, #2d5a4f); }
.shield-price-note { font-size: 0.78rem; color: var(--muted, #666); }
.shield-pay-btn {
  width: 100%; padding: 0.75rem;
  background: var(--brass, #b8860b); color: white;
  border: none; border-radius: 0.5rem;
  font-size: 0.95rem; font-weight: 600; cursor: pointer;
}
.shield-pay-btn:disabled { opacity: 0.6; cursor: default; }
.shield-contractor-note { font-size: 0.75rem; color: var(--muted, #666); margin-top: 0.5rem; text-align: center; }

/* ── Toggle Switch ────────────────────────────── */
.shield-switch { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
.shield-switch input { opacity: 0; width: 0; height: 0; }
.shield-slider { position: absolute; inset: 0; border-radius: 34px; background: #ccc; cursor: pointer; transition: 0.3s; }
.shield-slider:before { content: ''; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; border-radius: 50%; background: white; transition: 0.3s; }
.shield-switch input:checked + .shield-slider { background: var(--brass, #b8860b); }
.shield-switch input:checked + .shield-slider:before { transform: translateX(20px); }

/* ── Dashboard ────────────────────────────────── */
.shield-dash-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.75rem; }
.shield-job-card { border: 1px solid var(--border, #ddd); border-radius: 0.75rem; padding: 0.9rem; margin-bottom: 1rem; }
.shield-job-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
.shield-job-id { font-weight: 600; font-size: 0.85rem; }
.shield-status { font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 1rem; font-weight: 600; }
.shield-status--active  { background: #e6f4ec; color: #2d7a4f; }
.shield-status--complete { background: #e8f0fe; color: #1a56db; }
.shield-progress-bar-wrap { height: 6px; background: var(--border, #ddd); border-radius: 3px; margin: 0.5rem 0; }
.shield-progress-bar { height: 6px; background: var(--brass, #b8860b); border-radius: 3px; transition: width 0.4s; }
.shield-progress-label { font-size: 0.78rem; color: var(--muted, #666); margin-bottom: 0.5rem; }
.shield-point { border: 1px solid var(--border, #eee); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; }
.shield-point--approved { border-color: #2d7a4f; background: #f0faf4; }
.shield-point--flagged  { border-color: #d4a017; background: #fffbec; }
.shield-point-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; }
.shield-point-num { font-size: 0.75rem; font-weight: 700; }
.shield-point-label { font-size: 0.85rem; font-weight: 600; }
.shield-point-desc { font-size: 0.78rem; color: var(--muted, #666); margin: 0.25rem 0; }
.shield-photo-thumb { width: 100%; border-radius: 0.4rem; margin: 0.5rem 0; max-height: 200px; object-fit: cover; }
.shield-ai-verdict { font-size: 0.85rem; }
.shield-ai-notes { font-size: 0.78rem; color: var(--muted, #666); }
.shield-awaiting { font-size: 0.78rem; color: var(--muted, #666); font-style: italic; }
.shield-empty { text-align: center; padding: 2rem; color: var(--muted, #666); }
.shield-closeout-btn {
  width: 100%; margin-top: 0.75rem; padding: 0.65rem;
  background: var(--spruce, #2d5a4f); color: white;
  border: none; border-radius: 0.5rem; font-size: 0.88rem; font-weight: 600; cursor: pointer;
}

/* ── Badge ────────────────────────────────────── */
.shield-badge {
  display: inline-flex; align-items: center; gap: 0.4rem;
  background: #fffbec; border: 1px solid var(--brass, #b8860b);
  color: var(--brass, #b8860b); border-radius: 1rem;
  padding: 0.25rem 0.75rem; font-size: 0.78rem;
}
.shield-badge-full { padding: 0.75rem; background: #fffbec; border-radius: 0.5rem; border: 1px solid var(--brass, #b8860b); }
.shield-verified-tag { margin-left: 0.5rem; color: #2d7a4f; font-weight: 600; font-size: 0.82rem; }
.shield-progress-tag { margin-left: 0.5rem; color: var(--muted, #888); font-size: 0.82rem; }

/* ── Upload ───────────────────────────────────── */
.shield-upload-box { margin: 0.75rem 0; }
.shield-upload-label { font-size: 0.85rem; font-weight: 600; margin-bottom: 0.5rem; }
.shield-upload-status { margin-top: 0.5rem; font-size: 0.82rem; }

/* ── Brief Engine ─────────────────────────────── */
.shield-brief-wrap { margin: 1rem 0; }
.shield-brief-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
.shield-brief-title { display: block; font-size: 0.95rem; font-weight: 700; color: var(--brass, #b8860b); }
.shield-brief-sub { font-size: 0.78rem; color: var(--muted, #666); }
.shield-brief-textarea {
  width: 100%; box-sizing: border-box;
  border: 1.5px solid var(--border, #ddd); border-radius: 0.6rem;
  padding: 0.75rem; font-size: 0.9rem; line-height: 1.5;
  resize: vertical; font-family: inherit;
}
.shield-brief-textarea:focus { outline: none; border-color: var(--brass, #b8860b); }
.shield-score-bar-wrap { height: 6px; background: #eee; border-radius: 3px; margin: 0.5rem 0; }
.shield-score-bar { height: 6px; border-radius: 3px; transition: width 0.4s, background 0.4s; }
.shield-brief-feedback { font-size: 0.82rem; margin: 0.4rem 0; }
.shield-feedback-list { margin: 0; padding-left: 1.1rem; color: var(--muted, #777); }
.shield-feedback-ok { color: #2d7a4f; margin: 0; }
.shield-questions-label { font-size: 0.8rem; font-weight: 600; margin: 0.5rem 0 0.25rem; }
.shield-questions-list { padding-left: 1.1rem; font-size: 0.8rem; color: var(--muted, #666); margin: 0; }
.shield-points-label { font-size: 0.8rem; font-weight: 600; margin: 0.75rem 0 0.4rem; }
.shield-brief-points-preview { margin: 0.5rem 0; }
.shield-point-preview {
  display: flex; gap: 0.6rem; align-items: flex-start;
  padding: 0.5rem 0; border-bottom: 1px solid #f0f0f0;
  font-size: 0.82rem;
}
.shield-point-preview:last-child { border-bottom: none; }
.shield-point-num-sm {
  flex-shrink: 0; width: 1.4rem; height: 1.4rem;
  background: var(--brass, #b8860b); color: white;
  border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-size: 0.7rem; font-weight: 700;
}
.shield-point-preview p { margin: 0.15rem 0 0; color: var(--muted, #666); }

/* ── Close-out ────────────────────────────────── */
.shield-closeout-summary { margin-bottom: 0.75rem; font-size: 0.88rem; }
.shield-closeout-warning { background: #fff8ec; border: 1px solid #d4a017; border-radius: 0.4rem; padding: 0.6rem; margin-top: 0.4rem; font-size: 0.82rem; }
.shield-closeout-override { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem; cursor: pointer; }
.shield-closeout-points { margin-bottom: 1rem; }
.shield-closeout-point { display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid #f0f0f0; font-size: 0.82rem; }
.shield-closeout-point--approved .shield-closeout-verdict { color: #2d7a4f; font-weight: 600; }
.shield-closeout-point--flagged .shield-closeout-verdict  { color: #d4a017; font-weight: 600; }
.shield-closeout-point--pending .shield-closeout-verdict  { color: #888; }

/* ── Card Modal ───────────────────────────────── */
#shield-card-overlay, #shield-closeout-overlay {
  position: fixed; inset: 0; z-index: 9000;
  display: flex; flex-direction: column; justify-content: flex-end;
  pointer-events: none;
}
#shield-card-overlay.scm-visible, #shield-closeout-overlay.scm-visible { pointer-events: all; }
.scm-backdrop {
  position: absolute; inset: 0;
  background: rgba(0,0,0,0); transition: background 0.3s ease; cursor: pointer;
}
#shield-card-overlay.scm-visible .scm-backdrop,
#shield-closeout-overlay.scm-visible .scm-backdrop { background: rgba(0,0,0,0.55); }
.scm-sheet {
  position: relative; background: #fff;
  border-radius: 1.25rem 1.25rem 0 0;
  padding: 1.25rem 1.25rem 2rem;
  max-width: 480px; width: 100%; margin: 0 auto;
  transform: translateY(100%);
  transition: transform 0.35s cubic-bezier(0.32,0.72,0,1);
  box-shadow: 0 -4px 32px rgba(0,0,0,0.15);
}
#shield-card-overlay.scm-visible .scm-sheet,
#shield-closeout-overlay.scm-visible .scm-sheet { transform: translateY(0); }
.scm-handle { width: 40px; height: 4px; background: #ddd; border-radius: 2px; margin: 0 auto 1rem; }
.scm-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid #eee; }
.scm-icon { font-size: 1.5rem; flex-shrink: 0; }
.scm-title-group { flex: 1; }
.scm-title { display: block; font-size: 0.95rem; font-weight: 700; color: var(--brass, #b8860b); }
.scm-desc { font-size: 0.75rem; color: var(--muted, #777); }
.scm-amount { font-size: 1.4rem; font-weight: 700; color: var(--spruce, #2d5a4f); flex-shrink: 0; }
.scm-section-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted, #888); margin-bottom: 0.5rem; }
.scm-card-input { border: 1.5px solid #d1d5db; border-radius: 0.6rem; padding: 0.85rem 0.9rem; background: #fafafa; transition: border-color 0.2s; margin-bottom: 0.5rem; }
.scm-card-input.StripeElement--focus { border-color: var(--brass, #b8860b); background: #fff; }
.scm-card-input.StripeElement--invalid { border-color: #c0392b; }
.scm-error { min-height: 1.2rem; font-size: 0.8rem; color: #c0392b; margin-bottom: 0.75rem; }
.scm-secure-note { display: flex; align-items: center; gap: 0.35rem; font-size: 0.73rem; color: var(--muted, #888); margin-bottom: 1rem; }
.scm-submit-btn {
  width: 100%; padding: 0.9rem;
  background: var(--brass, #b8860b); color: #fff;
  border: none; border-radius: 0.65rem;
  font-size: 1rem; font-weight: 700; cursor: pointer;
  transition: opacity 0.2s, transform 0.1s; margin-bottom: 0.6rem;
}
.scm-submit-btn:hover:not(:disabled) { opacity: 0.92; }
.scm-submit-btn:active:not(:disabled) { transform: scale(0.98); }
.scm-submit-btn:disabled { opacity: 0.6; cursor: default; }
.scm-cancel-btn { width: 100%; padding: 0.6rem; background: none; border: none; color: var(--muted, #888); font-size: 0.88rem; cursor: pointer; }
.scm-cancel-btn:hover { color: #333; }
`

// Inject CSS once on load
;(function injectShieldCSS() {
  if (document.getElementById('shield-styles')) return
  const style = document.createElement('style')
  style.id = 'shield-styles'
  style.textContent = SHIELD_CSS
  document.head.appendChild(style)
})()

// Expose functions globally for onclick attributes and external calls
window.renderShieldBrief              = renderShieldBrief
window.renderShieldToggle             = renderShieldToggle
window.purchaseShieldPerJob           = purchaseShieldPerJob
window.subscribeContractorToShield    = subscribeContractorToShield
window.renderShieldDashboard          = renderShieldDashboard
window.renderContractorUploadFlow     = renderContractorUploadFlow
window.renderShieldBadge              = renderShieldBadge
window.renderShieldCloseOutModal      = renderShieldCloseOutModal
