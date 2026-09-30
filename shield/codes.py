"""
Building-code checkpoint map — the domain asset this whole service exists around.

Nine trades, five checkpoints each, anchored to real IRC / IBC / NEC / NWFA /
PDCA sections. Each entry carries the citation, what the photo must frame, and
what the frame has to prove.

Extracted verbatim from shield_api.py's IRC_CODE_MAP (programmatically, not
retyped) so nothing drifted in the move. This is data, not logic — it is kept
in its own module so it can be reviewed by a licensed contractor, versioned,
and eventually moved into the database without touching request handling.

CODE CURRENCY: citations reflect the 2021 IRC / 2020 NEC family. Jurisdictions
adopt on their own schedule and amend locally. Before selling into a new market,
have someone licensed there confirm the adopted edition and local amendments.
"""

TRADES = {'framing': [{'label': 'Foundation Sill Plate and Anchor Bolts',
              'irc': 'IRC R403.1.6 -- Anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of '
                     'plate end, 7 inch embedment',
              'ibc': 'IBC 1905.1.8',
              'photo_instruction': 'Photograph full sill plate run showing anchor bolt locations and spacing '
                                   'with tape measure.',
              'must_show': 'Bolt spacing measured, washers and nuts torqued'},
             {'label': 'Wall Framing -- Studs, Headers and Bracing',
              'irc': 'IRC R602.3 stud spacing/size, R602.7 header spans, R602.10 wall bracing',
              'ibc': 'IBC 2308.4',
              'photo_instruction': 'Photograph full wall section showing stud spacing, header at each '
                                   'opening, bracing or sheathing.',
              'must_show': 'Stud spacing, header size, bracing method'},
             {'label': 'Fireblocking and Draftstopping',
              'irc': 'IRC R302.11 -- fireblocking at ceiling/floor lines, stair stringers, around chimneys',
              'ibc': 'IBC 718',
              'photo_instruction': 'Photograph each fireblocking location before drywall covers it. Include '
                                   'all penetrations.',
              'must_show': 'Fireblock material in place, all gaps sealed'},
             {'label': 'Floor Joists -- Notching, Boring and Connections',
              'irc': 'IRC R502.8 -- notches max 1/6 depth; bored holes max 1/3 depth, min 2 inches from edge',
              'ibc': 'IBC 2308.8',
              'photo_instruction': 'Photograph notched or bored joists with tape showing notch depth vs '
                                   'joist depth. Photograph joist hangers.',
              'must_show': 'Notch and bore measurements, joist hanger fastening, bearing length'},
             {'label': 'Roof Framing -- Rafters, Ridge and Connectors',
              'irc': 'IRC R802.4 rafter spans, R802.3 ridge board, R802.11 rafter ties, R301.2.1 wind uplift '
                     'connectors',
              'ibc': 'IBC 2308.10',
              'photo_instruction': 'Photograph rafter-to-ridge and rafter-to-top-plate connections. Include '
                                   'hurricane straps and span measurement.',
              'must_show': 'Connector type and installation, rafter spacing, ridge board size'}],
 'roofing': [{'label': 'Roof Deck and Sheathing',
              'irc': 'IRC R803.2 -- wood structural panel per span rating; R803.2.4 -- H-clips for spans '
                     'over 24 inches',
              'ibc': 'IBC 2304.8',
              'photo_instruction': 'Photograph sheathing grade stamp on panels. Photograph H-clips at '
                                   'unsupported edges.',
              'must_show': 'APA grade stamp visible, H-clips or blocking at edges'},
             {'label': 'Ice and Water Barrier plus Underlayment',
              'irc': 'IRC R905.1.2 -- ice barrier min 24 inches inside exterior wall where Jan avg temp 25F '
                     'or below; R905.2.7 -- underlayment required',
              'ibc': 'IBC 1507.2.8',
              'photo_instruction': 'Photograph ice barrier at eaves showing extent past interior wall. '
                                   'Photograph overlapping underlayment rows.',
              'must_show': 'Ice barrier extends min 24 inches past wall line, underlayment overlap min 2 '
                           'inches'},
             {'label': 'Drip Edge and Flashing',
              'irc': 'IRC R905.2.8.5 -- drip edge min 1/4 inch below sheathing, min 2 inches up deck; '
                     'R905.2.8.3 -- valley flashing min 24 inches wide',
              'ibc': 'IBC 1507.2.9',
              'photo_instruction': 'Photograph drip edge at eave showing overlap. Photograph each valley and '
                                   'step flashing at wall intersections.',
              'must_show': 'Drip edge overlap measured, valley flashing width, step flashing at all '
                           'intersections'},
             {'label': 'Shingle Installation and Nailing Pattern',
              'irc': 'IRC R905.2.5 -- minimum 4 fasteners per strip shingle (6 in high-wind); R905.2.4.1 -- '
                     'starter strip at eaves',
              'ibc': 'IBC 1507.2.5',
              'photo_instruction': 'Lift a shingle to photograph nail placement. Photograph starter course '
                                   'at eave and offset pattern.',
              'must_show': 'Nails in manufacturer nailing zone, minimum 4 nails visible, starter strip in '
                           'place'},
             {'label': 'Ridge Cap, Vents and Final Weathertight Inspection',
              'irc': 'IRC R806.2 -- ventilation min 1/150 of insulated ceiling area (or 1/300 with balanced '
                     'intake/exhaust)',
              'ibc': 'IBC 1503.4',
              'photo_instruction': 'Photograph completed ridge cap. Photograph each vent location. '
                                   'Photograph all pipe boot flashings.',
              'must_show': 'Ridge cap fully installed, vent locations visible, all penetration flashings '
                           'sealed'}],
 'plumbing': [{'label': 'DWV Rough-In -- Drain Slope and Pipe Support',
               'irc': 'IRC P3005.3 -- slope: 1/4 inch per foot for pipe 3 inches or smaller, 1/8 inch per '
                      'foot for 4 inch and larger; P2605.1 -- support intervals',
               'ibc': 'IPC 308 support, 704 slope',
               'photo_instruction': 'Use level and ruler on horizontal drain runs to show slope. Photograph '
                                    'pipe hangers showing spacing.',
               'must_show': 'Slope measurement visible, hanger spacing within limits, pipe size stamps'},
              {'label': 'DWV Air and Water Pressure Test',
               'irc': 'IRC P2503.5.1 -- air test: 5 psi for 15 minutes; water test: min 10ft head for 15 '
                      'minutes',
               'ibc': 'IPC 312.2',
               'photo_instruction': 'Photograph test gauge showing pressure at start and end of 15-minute '
                                    'hold.',
               'must_show': 'Gauge reading at start and end, no visible moisture at joints'},
              {'label': 'Water Supply Lines -- Material, Sizing and Pressure Test',
               'irc': 'IRC P2903.5 -- static pressure test at 1.5 times working pressure for 15 minutes; '
                      'P2903.1 -- min 3/4 inch building supply',
               'ibc': 'IPC 604, 312.5',
               'photo_instruction': 'Photograph pressure gauge on supply system. Photograph pipe material '
                                    'markings and main shutoff.',
               'must_show': 'Test pressure gauge reading, pipe material stamp, shutoff valve accessible'},
              {'label': 'Vent Stack and Air Admittance Valves',
               'irc': 'IRC P3103.1 -- vent through roof min 6 inches above roof surface (min 24 inches in '
                      'snow country); P3105 -- each trap must be vented',
               'ibc': 'IPC 903, 917',
               'photo_instruction': 'Photograph vent stack from exterior showing height above roof. '
                                    'Photograph each trap-to-vent connection.',
               'must_show': 'Vent height above roof surface measured, all traps connected to vent system'},
              {'label': 'Fixture Rough-In and Cleanout Locations',
               'irc': 'IRC P3005.2.7 -- cleanouts at base of each stack and runs over 100ft; P2708 shower, '
                      'P2705 lavatory rough-in requirements',
               'ibc': 'IPC 708',
               'photo_instruction': 'Photograph each rough-in location with measurement from finished floor. '
                                    'Photograph cleanout plugs.',
               'must_show': 'Rough-in measurements matching fixture specs, cleanout locations accessible'}],
 'electrical': [{'label': 'Panel, Service Entry and Grounding Electrode',
                 'irc': 'NEC 250.52(A)(3) -- Ufer: min 20ft of min 1/2 inch rebar or #4 bare copper encased '
                        'in min 2 inches concrete; NEC 250.50 -- all electrodes bonded',
                 'ibc': 'NEC Article 250, 230',
                 'photo_instruction': 'Photograph Ufer electrode BEFORE concrete pour showing rebar length '
                                      'and pigtail. Photograph GEC connection at panel.',
                 'must_show': 'Ufer rebar length and pigtail visible, GEC connection at panel, service '
                              'conductor size'},
                {'label': 'Branch Circuit Rough-In -- Box Fill and Wire Routing',
                 'irc': 'NEC 314.16 -- box fill: 2.0 cu in per #14, 2.25 cu in per #12; NEC 300.4 -- nail '
                        'plate required if cable within 1-1/4 inches of stud edge',
                 'ibc': 'NEC Article 314, 300',
                 'photo_instruction': 'Photograph each box showing wire count and cubic-inch rating stamped '
                                      'on box. Photograph nail plates at stud edges.',
                 'must_show': 'Box cu-in rating stamp, nail plates where required, staple spacing max 4.5 '
                              'feet'},
                {'label': 'GFCI and AFCI Protection',
                 'irc': 'NEC 210.8 -- GFCI at bathrooms, garages, outdoors, kitchens within 6 feet of sink; '
                        'NEC 210.12 -- AFCI all 15/20A 120V circuits in dwelling',
                 'ibc': 'NEC 210.8, 210.12',
                 'photo_instruction': 'Photograph GFCI outlet or breaker at each required location. '
                                      'Photograph AFCI breakers in panel.',
                 'must_show': 'GFCI at all wet and outdoor locations, AFCI breakers for bedroom and living '
                              'circuits'},
                {'label': 'Rough-In Inspection -- All Circuits, Working Clearances',
                 'irc': 'NEC 110.26 -- working clearance: min 30 inches wide, min 36 inches deep, min 6.5 '
                        'feet high in front of panel',
                 'ibc': 'NEC 110.26',
                 'photo_instruction': 'Photograph panel working clearance with tape showing 36-inch depth '
                                      'from panel face. Photograph service disconnect label.',
                 'must_show': '36-inch clearance measured in photo, service disconnect labeled, no '
                              'obstructions'},
                {'label': 'Final -- Devices, Fixtures and Load Center Labeling',
                 'irc': 'NEC 408.4 -- every circuit breaker must be legibly identified; NEC 110.12 -- no '
                        'open knockouts',
                 'ibc': 'NEC 408.4, 110.12',
                 'photo_instruction': 'Photograph completed panel directory. Photograph outlet and switch '
                                      'installations. Check for open knockouts.',
                 'must_show': 'Complete panel directory, all boxes covered, no open knockouts, circuit '
                              'labels legible'}],
 'hvac': [{'label': 'Equipment Installation and Clearances',
           'irc': 'IRC M1306 -- clearances to combustibles per equipment listing label; M1305.1 -- access '
                  'passageway min 22 by 30 inches',
           'ibc': 'IMC 304, 306',
           'photo_instruction': 'Photograph equipment label showing required clearances. Photograph measured '
                                'distance from unit to nearest combustible.',
           'must_show': 'Equipment label clearance requirements visible, measured clearance in photo, access '
                        'path dimensions'},
          {'label': 'Duct Installation -- Support, Joints and Sealing',
           'irc': 'IRC M1601.4.1 -- joints and seams sealed with mastic or UL 181A/B tape; M1601.4.4 -- '
                  'round duct support max 10ft, rectangular max 4ft',
           'ibc': 'IMC 603',
           'photo_instruction': 'Photograph duct joints showing mastic or approved tape. Photograph duct '
                                'hangers showing spacing.',
           'must_show': 'Mastic or UL 181 tape at all joints, hanger spacing within limits, flex duct not '
                        'kinked'},
          {'label': 'Combustion Air and Gas Piping',
           'irc': 'IRC G2407 -- combustion air: min 50 cu ft per 1,000 BTU/hr; G2417 -- gas piping test: 10 '
                  'psi air for 15 min before appliances connected',
           'ibc': 'IMC 701, 303.3',
           'photo_instruction': 'Photograph combustion air opening size with measurement. Photograph gas '
                                'piping pressure gauge during test.',
           'must_show': 'Combustion air opening dimensions, gas test gauge reading, shutoff valve accessible '
                        'and labeled'},
          {'label': 'Condensate Drainage and Secondary Drain',
           'irc': 'IRC M1411.3 -- secondary drain or auxiliary pan required for equipment above finished '
                  'ceiling; pan min 1.5 inches deep, min 3 inches wider than unit',
           'ibc': 'IMC 307.2',
           'photo_instruction': 'Photograph primary drain connection and routing. Photograph secondary drain '
                                'pan dimensions or float switch.',
           'must_show': 'Primary drain connection, secondary pan or float switch installed, drain terminates '
                        'visible'},
          {'label': 'Final -- Duct Insulation, Filter, and System Test',
           'irc': 'IRC N1103.3.3 -- ducts in unconditioned space: R-8 insulation minimum',
           'ibc': 'IECC C403.2.2, IMC 607',
           'photo_instruction': 'Photograph duct insulation in attic or crawl space showing R-value label. '
                                'Photograph filter installed. Photograph thermostat set to test with system '
                                'running.',
           'must_show': 'R-8 or higher insulation label visible, filter in place, system operational'}],
 'concrete': [{'label': 'Footing Excavation and Soil Bearing',
               'irc': 'IRC R403.1 -- footings bear on undisturbed soil; R301.2(7) -- frost depth per Table '
                      'R301.2(1); R403.1.1 -- min 12 inches below grade',
               'ibc': 'IBC 1809.4',
               'photo_instruction': 'Photograph footing trench showing depth measurement from grade to '
                                    'bottom. Include tape showing frost-depth compliance.',
               'must_show': 'Footing depth measurement, undisturbed soil visible at base'},
              {'label': 'Rebar Placement and Concrete-Encased Electrode',
               'irc': 'IRC R403.1.3 -- footing reinforcement per Table R403.1.3(1); NEC 250.52(A)(3) -- '
                      'Ufer: min 20ft of min 1/2 inch rebar in min 2 inches concrete',
               'ibc': 'IBC 1905, ACI 318 20.6.1 -- cover: 3 inches cast against earth',
               'photo_instruction': 'Photograph rebar chairs or supports showing minimum concrete cover. '
                                    'Photograph Ufer pigtail extending from footing form.',
               'must_show': 'Rebar chairs maintaining minimum cover, Ufer pigtail visible and tagged, rebar '
                            'size and spacing per plan'},
              {'label': 'Vapor Retarder and Sub-Slab Preparation',
               'irc': 'IRC R506.2.3 -- vapor retarder min 10-mil Class A per ASTM E1745, joints lapped min 6 '
                      'inches, extended up stem walls',
               'ibc': 'IBC 1805.4.1',
               'photo_instruction': 'Photograph vapor barrier material showing 10-mil spec or ASTM E1745 '
                                    'markings. Photograph joint laps showing min 6 inch overlap.',
               'must_show': 'Vapor barrier spec marking, 6-inch lap at joints, edges turned up at stem '
                            'walls'},
              {'label': 'Concrete Pour -- Mix, Placement and Consolidation',
               'irc': "IRC R402.2 -- min f'c: 2,500 psi interior slabs, 3,000 psi exposed to weather, 3,500 "
                      'psi severe freeze-thaw',
               'ibc': 'IBC 1905.3, ACI 318 Table 19.3.3.1',
               'photo_instruction': 'Photograph concrete delivery ticket showing mix design and PSI '
                                    'strength. Photograph vibrator being used during pour.',
               'must_show': "Concrete ticket with f'c and w/c ratio, vibration occurring during pour"},
              {'label': 'Anchor Bolts, Curing and Slab Tolerances',
               'irc': 'IRC R403.1.6 -- anchor bolts min 1/2 inch dia., max 6ft o.c., within 12 inches of '
                      'plate ends, min 7 inch embedment; R506.2.4 -- slab min 3.5 inches thick',
               'ibc': 'IBC 1905.1.8, ACI 117 -- slab tolerance 1/4 inch in 10ft',
               'photo_instruction': 'Photograph anchor bolts set in wet concrete while still plastic. '
                                    'Measure and photograph bolt spacing. Photograph curing compound '
                                    'applied.',
               'must_show': 'Anchor bolt spacing measured, embedment depth marker, curing compound '
                            'application'}],
 'flooring': [{'label': 'Subfloor Condition and Moisture Testing',
               'irc': 'IRC R503.2 -- wood structural panel subfloor: APA rated sheathing per span table; MC '
                      'max 14 percent for wood or max 3 lbs per 1000 sf per 24hr for concrete',
               'ibc': 'IBC 2304.9',
               'photo_instruction': 'Photograph moisture meter reading in multiple locations. Photograph '
                                    'flatness measurement with 10-foot straightedge.',
               'must_show': 'Moisture meter reading visible, flatness measurement, any repairs noted'},
              {'label': 'Underlayment Installation',
               'irc': 'IRC R503 -- subfloor per span table; manufacturer installation instructions govern '
                      'underlayment type and thickness',
               'ibc': 'IBC 2304.9',
               'photo_instruction': 'Photograph underlayment material label showing specification. '
                                    'Photograph seam treatment (tape or stapling).',
               'must_show': 'Underlayment spec label, seams properly treated, no voids or bubbles'},
              {'label': 'Flooring Layout and Acclimation',
               'irc': 'NWFA Installation Guidelines: acclimate 3 to 5 days at job-site conditions',
               'ibc': 'NWFA Installation Guidelines; ANSI A108 for tile',
               'photo_instruction': 'Photograph flooring material open and acclimating on-site. Photograph '
                                    'chalk line layout and room temperature and humidity reading.',
               'must_show': 'Flooring open and acclimating, temp and humidity reading, layout lines '
                            'established'},
              {'label': 'Flooring Installation -- Fastening and Pattern',
               'irc': 'NWFA: 3/4 inch solid hardwood -- cleat or staple every 6 to 8 inches; expansion gap '
                      '3/4 inch at all walls; ANSI A108.02 -- tile: thin-set coverage min 80 percent '
                      'interior',
               'ibc': 'NWFA and ANSI A108 and manufacturer specs',
               'photo_instruction': 'Photograph expansion gap at wall with spacer in place. For tile: lift a '
                                    'tile immediately after setting to check mortar coverage.',
               'must_show': 'Expansion gap at perimeter, fastener spacing visible, mortar coverage on tile '
                            'back'},
              {'label': 'Transitions, Thresholds and Final Inspection',
               'irc': 'IRC R311.7.5 -- stair treads: rise max 7-3/4 inches, run min 10 inches',
               'ibc': 'IBC 1003.3',
               'photo_instruction': 'Photograph all threshold transitions room to room. Photograph any '
                                    'change-in-level measurements.',
               'must_show': 'All transitions in place, level changes measured, no protruding fasteners or '
                            'gaps'}],
 'painting': [{'label': 'Surface Preparation -- Drywall and Substrate',
               'irc': 'GA-214 Recommended Levels of Gypsum Board Finish -- Level 4 minimum for flat paint; '
                      'Level 5 for gloss or semi-gloss or critical lighting',
               'ibc': 'GA-214 and ASTM C840',
               'photo_instruction': 'Photograph drywall seams under raking light to show finish level. '
                                    'Document finish level before primer.',
               'must_show': 'Seams smooth under raking light, no mud ridges, corner bead straight'},
              {'label': 'Primer Application',
               'irc': 'Manufacturer specs and PDCA Standards P1 through P4 series',
               'ibc': 'PDCA and MPI Architectural Painting Specification Manual',
               'photo_instruction': 'Photograph primed surfaces showing even coverage. Photograph primer '
                                    'product label showing manufacturer and type.',
               'must_show': 'Even primer coverage, no bare spots, product label visible'},
              {'label': 'First Coat -- Application and Coverage',
               'irc': 'PDCA P4 and MPI Standards -- spread rate per manufacturer; mil thickness per spec '
                      'sheet',
               'ibc': 'MPI Architectural Painting Specification Manual 9',
               'photo_instruction': 'Photograph any areas with thin coverage or holidays. Photograph product '
                                    'label and batch number.',
               'must_show': 'Even sheen across surface, product batch number recorded'},
              {'label': 'Second Coat and Finish Inspection',
               'irc': 'PDCA P12 -- uniform color and sheen, no defects visible at 5 feet in normal light',
               'ibc': 'MPI 9; ASTM D3730',
               'photo_instruction': 'Photograph finished walls under normal lighting and under raking light. '
                                    'Photograph final coat product label.',
               'must_show': 'Uniform sheen at 5-foot viewing distance, no drips or laps, final coat label'},
              {'label': 'Trim, Cut Lines and Cleanup',
               'irc': 'PDCA P5 protection of adjacent surfaces; PDCA P1 workmanship standard',
               'ibc': 'PDCA Standards',
               'photo_instruction': 'Photograph trim cut lines at ceiling and floor. Photograph hardware '
                                    'reinstalled. Photograph overall room showing clean site.',
               'must_show': 'Straight cut lines, hardware in place, no paint on floors or fixtures'}],
 'general': [{'label': 'Site Safety and Permit Posted',
              'irc': 'IRC R105.7 -- permit must be posted on site and visible from street until final '
                     'inspection',
              'ibc': 'IBC 105.7',
              'photo_instruction': 'Photograph building permit posted at front of property. Photograph crew '
                                   'wearing PPE.',
              'must_show': 'Permit visible and readable, PPE in use, no obvious safety violations'},
             {'label': 'Work-in-Progress Milestone',
              'irc': 'Contractual milestone -- specific IRC section depends on trade being performed',
              'ibc': 'Contractual as applicable',
              'photo_instruction': 'Photograph wide view of work area showing scope in progress. Include '
                                   'reference objects for scale.',
              'must_show': 'Clear progress visible, scope matches contract, work area identified'},
             {'label': 'Materials On-Site and Specification',
              'irc': 'IRC R101.2 -- materials must meet referenced standards; specific section per material '
                     'type',
              'ibc': 'IBC 1703 product approval',
              'photo_instruction': 'Photograph material specification labels for all major materials. '
                                   'Photograph materials stored properly off ground and covered.',
              'must_show': 'Grade stamps and spec labels visible, materials protected from weather, '
                           'quantities match scope'},
             {'label': 'Subcontractor Work Complete',
              'irc': 'IRC R109 -- required inspections must be completed before concealment of any work',
              'ibc': 'IBC 110',
              'photo_instruction': 'Photograph any rough-in work before walls are closed. Photograph '
                                   'required inspection approval cards posted on site.',
              'must_show': 'All rough-in work visible before concealment, inspection tags if applicable'},
             {'label': 'Final Walkthrough and Punch List',
              'irc': 'IRC R110 -- Certificate of Occupancy required before occupancy; final inspection must '
                     'pass',
              'ibc': 'IBC 111',
              'photo_instruction': 'Photograph each completed area of agreed scope. Photograph final '
                                   'cleanup. Photograph any outstanding items for homeowner.',
              'must_show': 'All contracted work visible and complete, site clean, no materials left behind'}]}

TRADE_KEYWORDS = {'framing': ['frame', 'framing', 'stud', 'joist', 'rafter', 'lumber', 'addition', 'truss', 'beam', 'header'],
 'roofing': ['roof', 'roofing', 'shingle', 'gutter', 'soffit', 'fascia', 'flashing', 'ridge', 'underlayment'],
 'plumbing': ['plumbing',
              'pipe',
              'drain',
              'water heater',
              'sewer',
              'fixture',
              'toilet',
              'sink',
              'shower',
              'faucet'],
 'electrical': ['electrical',
                'wiring',
                'panel',
                'circuit',
                'outlet',
                'switch',
                'breaker',
                'volt',
                'amp',
                'conduit'],
 'hvac': ['hvac',
          'furnace',
          'ac',
          'air conditioning',
          'ductwork',
          'heat pump',
          'mechanical',
          'heating',
          'cooling'],
 'concrete': ['concrete', 'foundation', 'slab', 'driveway', 'patio', 'footing', 'cement', 'masonry', 'rebar'],
 'flooring': ['floor', 'flooring', 'hardwood', 'lvp', 'tile', 'carpet', 'laminate', 'subfloor', 'vinyl'],
 'painting': ['paint', 'painting', 'primer', 'drywall', 'finish', 'stain', 'caulk', 'interior', 'exterior']}


def detect_trade(description: str) -> str:
    """Highest keyword-hit trade, or 'general' when nothing scores."""
    text = (description or "").lower()
    best, score = "general", 0
    for trade, words in TRADE_KEYWORDS.items():
        hits = sum(1 for w in words if w in text)
        if hits > score:
            best, score = trade, hits
    return best


def checkpoints_for(trade: str) -> list:
    return TRADES.get(trade, TRADES["general"])


def code_entry(trade: str, point_number: int) -> dict:
    """Code entry for a 1-indexed checkpoint number.

    Returns {} when the model hands back more points than the trade has
    checkpoints. The original silently mismatched here; callers should treat
    an empty dict as "no citation available" rather than assume alignment.
    """
    entries = checkpoints_for(trade)
    idx = point_number - 1
    return entries[idx] if 0 <= idx < len(entries) else {}
