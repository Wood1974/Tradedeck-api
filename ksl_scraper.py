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
def fetch_ksl_jobs(requests_lib):
    """
    Attempt to pull jobs from KSL. Tries JSON API first, falls back to HTML.
    Returns list of dicts with keys: title, description, location, url, company.
    """
    # Override URL via env var if KSL changes their API
    api_url = os.getenv('KSL_API_URL', '')
    headers = {'User-Agent': 'Mozilla/5.0 (TradeDeck/2.0; +https://tradedeckapp.com)'}

    # ── Try 1: JSON API (configurable via env) ────────────────────────────────
    candidates = []
    if api_url:
        candidates.append(api_url)

    # Common KSL API patterns to try in order
    candidates += [
        'https://jobs.ksl.com/api/search?category=Construction+%26+Trades&state=UT&perPage=500',
        'https://jobs.ksl.com/api/jobs?category=construction&state=UT&limit=500',
        'https://api.ksl.com/classified/v1/search?type=jobs&category=construction&state=UT',
    ]

    for url in candidates:
        try:
            r = requests_lib.get(url, headers=headers, timeout=15)
            if r.status_code == 200 and r.content:
                data = r.json()
                jobs = data.get('jobs') or data.get('results') or data.get('data') or []
                if jobs:
                    log.info("KSL JSON API success: %s (%d jobs)", url, len(jobs))
                    return [_normalize_json_job(j) for j in jobs]
        except Exception as e:
            log.debug("KSL API %s failed: %s", url, e)

    # ── Try 2: HTML scrape ────────────────────────────────────────────────────
    try:
        from bs4 import BeautifulSoup
        html_url = 'https://jobs.ksl.com/search?category=Construction+%26+Trades&state=UT'
        r = requests_lib.get(html_url, headers=headers, timeout=20)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            jobs = _parse_html_jobs(soup, html_url)
            if jobs:
                log.info("KSL HTML scrape success: %d jobs", len(jobs))
                return jobs
    except Exception as e:
        log.warning("KSL HTML scrape failed: %s", e)

    raise RuntimeError(
        "All KSL fetch methods failed. "
        "Set KSL_API_URL env var on Render with the correct endpoint. "
        "Check Render logs for attempted URLs."
    )


def _normalize_json_job(j):
    """Normalize a raw KSL JSON job dict to standard keys."""
    return {
        'title':       j.get('title') or j.get('name') or '',
        'description': j.get('description') or j.get('body') or '',
        'location':    j.get('location') or j.get('city') or j.get('area') or '',
        'company':     j.get('company') or j.get('employer') or j.get('business') or '',
        'url':         j.get('url') or j.get('applyUrl') or j.get('link') or '',
    }


def _parse_html_jobs(soup, base_url):
    """Parse job listings from KSL HTML. Adjust selectors if KSL changes markup."""
    jobs = []
    # KSL Jobs typically renders cards with class 'job-listing' or similar
    for card in soup.select('[class*="job"], [class*="listing"], article'):
        title_el = card.select_one('h2, h3, [class*="title"], [class*="name"]')
        loc_el   = card.select_one('[class*="location"], [class*="city"], [class*="area"]')
        comp_el  = card.select_one('[class*="company"], [class*="employer"], [class*="business"]')
        link_el  = card.select_one('a[href]')
        if not title_el:
            continue
        href = link_el['href'] if link_el else ''
        if href and not href.startswith('http'):
            href = 'https://jobs.ksl.com' + href
        jobs.append({
            'title':       title_el.get_text(strip=True),
            'description': card.get_text(' ', strip=True)[:500],
            'location':    loc_el.get_text(strip=True) if loc_el else '',
            'company':     comp_el.get_text(strip=True) if comp_el else '',
            'url':         href,
        })
    return jobs
