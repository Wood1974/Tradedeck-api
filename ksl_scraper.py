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


def fetch_ksl_jobs(requests_lib):
    """
    Scrape KSL classifieds via RSC (React Server Components) payload.
    Each page SSR contains JSON data in SearchStoreProvider initialState.
    Cursor-based pagination via endCursor from pageInfo.
    Returns list of dicts: title, description, location, url, company, pay.
    """
    import os, re, json as _json

    base_url = os.getenv('KSL_API_URL', KSL_SEARCH_URL)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    all_jobs = []
    seen_ids = set()
    cursor = None
    page = 0

    while True:
        url = f"{base_url}?endCursor={cursor}" if cursor else base_url
        try:
            r = requests_lib.get(url, headers=headers, timeout=25)
            r.raise_for_status()
        except Exception as e:
            if page == 0:
                raise RuntimeError(f"KSL fetch failed: {e}")
            break

        # Parse RSC payload from <script>self.__next_f.push(...)</script> blocks
        # The SearchStoreProvider initialState contains results + pageInfo
        jobs, next_cursor, has_next = _parse_rsc_payload(r.text)

        new_count = 0
        for job in jobs:
            jid = str(job.get('id', ''))
            if jid in seen_ids:
                continue
            seen_ids.add(jid)
            new_count += 1

            city  = job.get('location', {}).get('city', '') if isinstance(job.get('location'), dict) else ''
            state = job.get('location', {}).get('state', '') if isinstance(job.get('location'), dict) else ''
            pay_from = job.get('jobsPayFrom', 0) or 0
            pay_to   = job.get('jobsPayTo', 0) or 0
            pay_type = job.get('jobsPayRangeType', '') or ''

            # Build pay string  (cents → dollars)
            if pay_from or pay_to:
                pf = pay_from / 100 if pay_from > 1000 else pay_from
                pt = pay_to   / 100 if pay_to   > 1000 else pay_to
                pay = f"${pf:.0f}–${pt:.0f}/{pay_type}" if pf and pt else f"${pf:.0f}/{pay_type}" if pf else ''
            else:
                pay = ''

            all_jobs.append({
                'title':       (job.get('title') or '').strip(),
                'description': (job.get('title') or '').strip(),
                'location':    f"{city}, {state}".strip(', '),
                'company':     '',
                'pay':         pay,
                'url':         f"https://classifieds.ksl.com/listing/{jid}",
            })

        log.info("KSL page %d: %d new jobs (total: %d, cursor: %s)",
                 page, new_count, len(all_jobs), cursor)

        if not has_next or not next_cursor or new_count == 0:
            break

        cursor = next_cursor
        page  += 1

        # Safety cap: 460 jobs ÷ ~11 per page = ~42 pages max
        if page > 50:
            log.warning("KSL: safety cap reached at 50 pages")
            break

    return all_jobs


def _parse_rsc_payload(html):
    """
    Extract job results and pageInfo from the RSC streaming payload.
    Finds the initialState with 'results' and 'pageInfo' keys.
    Returns (jobs_list, end_cursor, has_next_page).
    """
    import re, json as _json

    jobs, end_cursor, has_next = [], None, False

    # Get the single large RSC chunk
    chunks = re.findall(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)', html, re.DOTALL)
    if not chunks:
        return jobs, end_cursor, has_next

    # Decode JS unicode escapes
    try:
        raw = chunks[0].encode('raw_unicode_escape').decode('unicode_escape')
    except Exception:
        raw = chunks[0]

    # Find the initialState that has 'results' followed soon by 'pageInfo'
    # (not the filter-options initialState which comes first)
    for m in re.finditer(r'"initialState"\s*:', raw):
        pos = m.end()
        segment = raw[pos:pos + 200]
        if not ('"results"' in segment or '"pageInfo"' in segment):
            continue

        # Locate the opening brace
        brace_start = raw.index('{', pos)

        # Walk braces to find matching close
        depth = 0
        end_pos = brace_start
        for i, ch in enumerate(raw[brace_start:], brace_start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break

        try:
            state = _json.loads(raw[brace_start:end_pos])
        except Exception:
            continue

        if 'results' not in state or 'pageInfo' not in state:
            continue

        # results is [[...items...]]
        raw_results = state.get('results', [])
        if raw_results and isinstance(raw_results[0], list):
            raw_results = raw_results[0]
        jobs = raw_results

        # pageInfo is [{...}]
        page_info = state.get('pageInfo', [])
        if page_info and isinstance(page_info, list):
            page_info = page_info[0]
        if isinstance(page_info, dict):
            has_next   = page_info.get('hasNextPage', False)
            end_cursor = page_info.get('endCursor', None)

        break

    return jobs, end_cursor, has_next
