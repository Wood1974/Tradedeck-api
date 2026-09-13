"""
ksl_scraper.py — KSL Jobs scraper for TradeDeck
Filters: Wasatch-surrounding counties only, construction jobs only
Categories: 14 individual trades
"""

# ── COUNTIES (Wasatch + surrounding) ──────────────────────────────────────────
# Tight circle around the Wasatch Back market. Weber/Davis excluded.
COUNTY_CITIES = {
    'Summit':   ['park city', 'coalville', 'kimball junction', 'snyderville',
                 'kamas', 'oakley', 'peoa', 'henefer', 'echo', 'francis'],
    'Wasatch':  ['heber', 'midway', 'daniel', 'charleston', 'wallsburg',
                 'center creek', 'soldier hollow'],
    'Utah':     ['provo', 'orem', 'american fork', 'lehi', 'saratoga springs',
                 'pleasant grove', 'lindon', 'springville', 'spanish fork',
                 'payson', 'salem', 'mapleton', 'santaquin'],
    'Salt Lake': ['salt lake', 'slc', 'draper', 'sandy', 'south jordan',
                  'west jordan', 'midvale', 'murray', 'taylorsville', 'herriman',
                  'riverton', 'bluffdale', 'cottonwood', 'holladay', 'millcreek'],
    'Morgan':   ['morgan'],
}
TARGET_COUNTIES = set(COUNTY_CITIES)

# ── CONSTRUCTION FILTER ────────────────────────────────────────────────────────
# Job title/description must contain at least one of these to pass.
CONSTRUCTION_MUST_MATCH = {
    'framing', 'framer', 'concrete', 'cement', 'foundation', 'flatwork',
    'roofer', 'roofing', 'shingles', 'membrane',
    'electrician', 'electrical', 'wiring',
    'plumber', 'plumbing', 'pipefitter', 'pipe fitter',
    'hvac', 'heating', 'cooling', 'refrigeration', 'furnace',
    'drywall', 'sheetrock', 'taper', 'mudding',
    'flooring', 'tile setter', 'tile', 'hardwood', 'laminate',
    'excavat', 'dozer', 'grading', 'sitework', 'earthwork',
    'landscap', 'hardscape', 'irrigation',
    'paint', 'painter',
    'carpenter', 'carpentry', 'cabinet', 'millwork', 'trim',
    'welder', 'welding', 'ironworker',
    'mason', 'masonry', 'brick', 'block',
    'insulation', 'waterproof', 'window install', 'door install', 'glazier',
    'construction', 'contractor', 'builder', 'general contractor',
    'laborer', 'construction labor', 'construction worker',
    'superintendent', 'construction manager', 'project manager',
    'estimator', 'construction estimat',
    'demo', 'demolition', 'deconstruct',
    'foreman', 'crew lead', 'site supervisor',
    'apprentice', 'journeyman', 'helper',
    'handyman', 'maintenance tech', 'facilities',
    'land survey', 'civil engineer',
    'steel erect', 'structural',
    'solar install', 'solar panel',
}

# ── TRADE CATEGORIES ──────────────────────────────────────────────────────────
# Ordered — first match wins.
TRADE_RULES = [
    ('Framing',           ['framing', 'framer', 'wood frame', 'stick frame']),
    ('Concrete',          ['concrete', 'cement', 'foundation', 'flatwork', 'mud work']),
    ('Roofing',           ['roofing', 'roofer', 'shingles', 'membrane', 'flat roof']),
    ('Electrical',        ['electrician', 'electrical', 'wiring', 'wire pull', 'low voltage']),
    ('Plumbing',          ['plumber', 'plumbing', 'pipefitter', 'pipe fitter', 'sewer', 'water main']),
    ('HVAC',              ['hvac', 'heating', 'cooling', 'refrigeration', 'ac ', 'furnace', 'ductwork']),
    ('Drywall',           ['drywall', 'sheetrock', 'taper', 'mudding', 'gypsum']),
    ('Flooring',          ['flooring', 'tile', 'hardwood', 'laminate', 'vinyl plank', 'carpet']),
    ('Excavation',        ['excavat', 'dozer', 'grading', 'sitework', 'earthwork', 'operator']),
    ('Landscaping',       ['landscap', 'hardscape', 'irrigation', 'sprinkler', 'lawn']),
    ('Painting',          ['paint', 'painter', 'stain', 'coat', 'spray finish']),
    ('Carpentry',         ['carpenter', 'carpentry', 'cabinet', 'millwork', 'trim', 'finish wood']),
    ('Welding',           ['weld', 'ironworker', 'structural steel', 'fabricat']),
    ('General Laborer',   ['laborer', 'labor crew', 'construction worker', 'general help',
                           'helper', 'apprentice', 'handyman', 'maintenance']),
    ('General Contractor',['general contractor', 'superintendent', 'project manager',
                           'estimator', 'site supervisor', 'construction manager']),
]


def _text(title, description=''):
    return (title + ' ' + (description or '')).lower()


def is_construction(title, description=''):
    """Return True only if job is construction-related."""
    t = _text(title, description)
    return any(kw in t for kw in CONSTRUCTION_MUST_MATCH)


def categorize_trade(title, description=''):
    t = _text(title, description)
    for trade, keywords in TRADE_RULES:
        if any(kw in t for kw in keywords):
            return trade
    return 'General Contractor'


def categorize_county(location=''):
    loc = location.lower()
    for county, cities in COUNTY_CITIES.items():
        if any(city in loc for city in cities):
            return county
    return None   # None = out of area, caller should reject


def process_job(title, description, location):
    """
    Returns dict with trade + county, or None if job should be excluded.
    Exclusion: not construction, or not in a target county.
    """
    if not is_construction(title, description):
        return None
    county = categorize_county(location)
    if county is None:
        return None
    return {
        'trade':  categorize_trade(title, description),
        'county': county,
    }
