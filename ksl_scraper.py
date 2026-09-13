"""
ksl_scraper.py — KSL Jobs scraper for TradeDeck
Filters: Wasatch-surrounding counties only, construction jobs only
Categories: 15 individual trades

KSL API URL is configurable via KSL_API_URL env var.
Falls back to HTML scraping if JSON API fails.
"""
import logging
import os
import re

log = logging.getLogger(__name__)

# ── COUNTIES (Wasatch + surrounding) ──────────────────────────────────────────
COUNTY_CITIES = {
    'Summit':    ['park city', 'coalville', 'kimball junction', 'snyderville',
                  'oakley', 'peoa', 'henefer', 'echo', 'francis', 'kamas'],
    'Wasatch':   ['heber', 'midway', 'daniel', 'charleston', 'wallsburg',
                  'soldier hollow', 'wasatch'],
    'Utah':      ['provo', 'orem', 'american fork', 'lehi', 'saratoga springs',
                  'pleasant grove', 'lindon', 'springville', 'spanish fork',
                  'payson', 'salem', 'mapleton', 'santaquin', 'alpine', 'highland'],
    'Salt Lake': ['salt lake', 'slc', 'draper', 'sandy', 'south jordan',
                  'west jordan', 'midvale', 'murray', 'taylorsville', 'herriman',
                  'riverton', 'bluffdale', 'cottonwood', 'holladay', 'millcreek',
                  'west valley', 'kearns', 'magna'],
    'Morgan':    ['morgan'],
}

# ── CONSTRUCTION FILTER ────────────────────────────────────────────────────────
CONSTRUCTION_KEYWORDS = {
    'framing', 'framer', 'concrete', 'cement', 'foundation', 'flatwork',
    'roofer', 'roofing', 'shingles', 'membrane',
    'electrician', 'electrical', 'wiring', 'low voltage',
    'plumber', 'plumbing', 'pipefitter', 'pipe fitter', 'sewer', 'water main',
    'hvac', 'heating', 'cooling', 'refrigeration', 'furnace', 'ductwork',
    'drywall', 'sheetrock', 'taper', 'mudding', 'gypsum',
    'flooring', 'tile', 'hardwood', 'laminate', 'vinyl plank', 'carpet install',
    'excavat', 'dozer', 'grading', 'sitework', 'earthwork', 'heavy equipment',
    'landscap', 'hardscape', 'irrigation', 'sprinkler',
    'paint', 'painter', 'stain finish', 'spray coat',
    'carpenter', 'carpentry', 'cabinet', 'millwork', 'trim carpenter',
    'welder', 'welding', 'ironworker', 'structural steel', 'fabricat',
    'mason', 'masonry', 'brick', 'block layer',
    'insulation', 'waterproof', 'window install', 'door install', 'glazier',
    'construction', 'contractor', 'builder', 'general contractor',
    'laborer', 'construction labor', 'construction worker', 'job site',
    'superintendent', 'construction manager', 'project manager construction',
    'estimator', 'construction estimat', 'takeoff',
    'demo', 'demolition', 'deconstruct',
    'foreman', 'crew lead', 'site supervisor',
    'apprentice', 'journeyman', 'helper construction',
    'handyman', 'maintenance tech', 'facilities maintenance',
    'solar install', 'solar panel install',
    'land survey', 'civil engineer', 'civil construction',
}

# ── TRADE CATEGORIES (ordered — first match wins) ─────────────────────────────
TRADE_RULES = [
    ('Framing',             ['framing', 'framer', 'wood frame', 'stick frame']),
    ('Concrete',            ['concrete', 'cement', 'foundation', 'flatwork', 'mud work', 'concrete finish']),
    ('Roofing',             ['roofing', 'roofer', 'shingles', 'membrane', 'flat roof', 'roof repair']),
    ('Electrical',          ['electrician', 'electrical', 'wiring', 'wire pull', 'low voltage', 'lineman']),
    ('Plumbing',            ['plumber', 'plumbing', 'pipefitter', 'pipe fitter', 'sewer', 'water main', 'gas line']),
    ('HVAC',                ['hvac', 'heating', 'cooling', 'refrigeration', ' ac ', 'furnace', 'ductwork', 'sheet metal']),
    ('Drywall',             ['drywall', 'sheetrock', 'taper', 'mudding', 'gypsum', 'wallboard']),
    ('Flooring',            ['flooring', 'tile setter', 'hardwood floor', 'laminate', 'vinyl plank', 'carpet install']),
    ('Excavation',          ['excavat', 'dozer', 'grading', 'sitework', 'earthwork', 'heavy equipment operator', 'backhoe', 'skid steer']),
    ('Landscaping',         ['landscap', 'hardscape', 'irrigation', 'sprinkler', 'lawn care', 'snow removal']),
    ('Painting',            ['painter', 'painting', ' paint ', 'stain', 'spray finish', 'coating']),
    ('Carpentry',           ['carpenter', 'carpentry', 'cabinet', 'millwork', 'trim', 'finish carpentry', 'rough carpentry']),
    ('Welding',             ['weld', 'ironworker', 'structural steel', 'fabricat', 'metal work']),
    ('General Laborer',     ['laborer', 'labor crew', 'construction worker', 'general help',
                             'helper', 'apprentice', 'handyman', 'maintenance tech', 'facilities']),
    ('General Contractor',  ['general contractor', 'superintendent', 'project manager',
                             'estimator', 'site supervisor', 'construction manager', 'foreman']),
]


def _text(title, description=''):
    return (title + ' ' + (description or '')).lower()


def is_construction(title, description=''):
    """Return True only if the job is construction-related."""
    t = _text(title, description)
    return any(kw in t for kw in CONSTRUCTION_KEYWORDS)


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
    return None  # None = out of target area


def process_job(title, description, location):
    """
    Returns {'trade': ..., 'county': ...} or None if job should be excluded.
    Exclusion reasons: not construction, or not in a target county.
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


# ── KSL FETCH ─────────────────────────────────────────────────────────────────
KSL_SEARCH_URL = "https://classifieds.ksl.com/search/cat/Jobs/sub/Construction+%26+Skilled+Trades"
KSL_PAGE_SIZE  = 24   # KSL shows ~24 listings per page


def fetch_ksl_jobs(requests_lib):
    """
    Scrape KSL classifieds Construction & Skilled Trades search results.
    Paginates via ?start=N until results drop off.
    Returns list of dicts with keys: title, description, location, url, company, pay.
    """
    import os
    from bs4 import BeautifulSoup

    # Allow env override of base URL
    base_url = os.getenv('KSL_API_URL', KSL_SEARCH_URL)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    all_jobs = []
    seen_ids = set()
    start = 0

    while True:
        url = f"{base_url}?start={start}" if start > 0 else base_url
        try:
            r = requests_lib.get(url, headers=headers, timeout=20)
            r.raise_for_status()
        except Exception as e:
            if start == 0:
                raise RuntimeError(f"KSL fetch failed: {e}")
            break  # End of pages

        soup = BeautifulSoup(r.text, 'html.parser')
        cards = soup.find_all('a', attrs={'data-item-id': True})
        if not cards:
            break

        new_this_page = 0
        for card in cards:
            item_id = card.get('data-item-id', '')
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)
            new_this_page += 1

            title    = card.get('aria-label', '').strip()
            href     = card.get('href', '').strip()

            # Location: span with role=link
            loc_el   = card.find('span', attrs={'role': 'link'})
            location = loc_el.get_text(strip=True) if loc_el else ''

            # Pay: div with aria-label containing "Price"
            pay_els  = card.find_all(attrs={'aria-label': lambda x: x and 'Price' in str(x)})
            pay      = pay_els[0].get_text(strip=True) if pay_els else ''

            # Company: sometimes in a smaller text element
            company_el = card.find('p', class_=lambda c: c and 'company' in c.lower()) or \
                         card.find('div', class_=lambda c: c and 'employer' in c.lower())
            company  = company_el.get_text(strip=True) if company_el else ''

            if not title or not href:
                continue

            all_jobs.append({
                'title':       title,
                'description': f"{title} — {pay}".strip(' —'),
                'location':    location,
                'company':     company,
                'pay':         pay,
                'url':         href,
            })

        log.info("KSL page start=%d: %d new listings (total so far: %d)", start, new_this_page, len(all_jobs))

        # Stop if we got significantly fewer than expected (last page)
        if new_this_page < KSL_PAGE_SIZE // 2:
            break

        start += KSL_PAGE_SIZE

    return all_jobs
