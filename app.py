import os
import sqlite3
import requests
import xml.etree.ElementTree as ET
import hashlib
import hmac
import base64
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get('DB_PATH', 'tradedeck.db')
PERMITSTACK_KEY = os.environ.get('PERMITSTACK_KEY', '')
SAM_API_KEY = os.environ.get('SAM_API_KEY', '')
ZIPRECRUITER_KEY = os.environ.get('ZIPRECRUITER_KEY', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
SECRET_KEY = os.environ.get('SECRET_KEY', 'tradedeck-secret-2026')

TRADE_KEYWORDS = {
    'Framing':         ['framing', 'frame', 'framer', 'structural', 'wood frame'],
    'Concrete':        ['concrete', 'flatwork', 'foundation', 'slab', 'cement', 'paving'],
    'Roofing':         ['roofing', 'roof', 'shingle', 'metal roof', 'reroof', 'roofer'],
    'Electrical':      ['electrical', 'electrician', 'electric', 'wiring', 'panel', 'journeyman'],
    'Plumbing':        ['plumbing', 'plumber', 'pipe', 'pipefitter', 'water heater', 'sewer'],
    'HVAC':            ['hvac', 'mechanical', 'heating', 'cooling', 'ductwork', 'boiler'],
    'Excavation':      ['excavation', 'excavator', 'grading', 'earthwork', 'site prep', 'demolition'],
    'Flooring':        ['flooring', 'floor installer', 'tile', 'hardwood', 'carpet'],
    'Siding':          ['siding', 'exterior', 'cladding', 'stucco'],
    'Painting':        ['painting', 'painter', 'paint', 'coating'],
    'Finish Carpentry':['finish carpentry', 'trim carpenter', 'finish carpenter', 'millwork'],
    'General':         ['contractor', 'construction', 'builder', 'general labor', 'laborer', 'remodel'],
}

UTAH_CITIES = ['salt lake city', 'park city', 'provo', 'ogden', 'heber', 'heber city', 'kamas',
               'midway', 'francis', 'sandy', 'west jordan', 'orem', 'st george', 'logan',
               'murray', 'draper', 'lehi', 'riverton', 'south jordan', 'taylorsville', 'utah']


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return hashlib.sha256((password + SECRET_KEY).encode()).hexdigest()


def make_token(user_id, email):
    payload = json.dumps({'user_id': user_id, 'email': email, 'exp': (datetime.utcnow() + timedelta(days=30)).isoformat()})
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token = base64.b64encode(f"{payload}|{sig}".encode()).decode()
    return token


def verify_token(token):
    try:
        decoded = base64.b64decode(token.encode()).decode()
        payload_str, sig = decoded.rsplit('|', 1)
        expected = hmac.new(SECRET_KEY.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(payload_str)
        if datetime.fromisoformat(payload['exp']) < datetime.utcnow():
            return None
        return payload
    except:
        return None


def get_current_user():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return verify_token(auth[7:])
    return None


def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        phone TEXT,
        role TEXT DEFAULT 'sub',
        trade TEXT,
        license_number TEXT,
        license_type TEXT,
        license_state TEXT DEFAULT 'UT',
        years_experience INTEGER,
        looking_for TEXT,
        pay_min INTEGER,
        pay_max INTEGER,
        pay_type TEXT,
        bio TEXT,
        verified INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL, trade TEXT NOT NULL,
        city TEXT NOT NULL, state TEXT NOT NULL,
        rate TEXT, duration TEXT, crew_size TEXT,
        start_date TEXT, description TEXT,
        status TEXT DEFAULT 'open',
        applicants INTEGER DEFAULT 0,
        posted_by INTEGER,
        posted_at TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        message TEXT,
        applied_at TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS gc_leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        permit_number TEXT, address TEXT, city TEXT, state TEXT,
        category TEXT, trade TEXT, description TEXT, est_value TEXT,
        contractor TEXT, permit_date TEXT, status TEXT,
        source TEXT DEFAULT 'permitstack', fetched_at TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS live_leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, company TEXT, location TEXT, city TEXT,
        state TEXT DEFAULT 'UT', trade TEXT, description TEXT,
        url TEXT UNIQUE, source TEXT, posted_date TEXT, fetched_at TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS fetch_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT, fetched_at TEXT, count INTEGER, status TEXT)''')

    count = conn.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
    if count == 0:
        demo = [
            ('Framing Crew Needed','Framing','Park City','UT','$65-$75/hr','3-4 Weeks','4-6 People','2026-08-04','Experienced framing crew for new luxury custom home. 4,800 sq ft two-story.',7),
            ('Concrete Flatwork - Heated Drive','Concrete','Heber City','UT','$8,500 flat','1 Week','2-3 People','2026-08-11','Flatwork pour for heated driveway. Radiant tubing already laid.',3),
            ('Metal Roofing - Custom Home','Roofing','Kamas','UT','$55-$65/hr','2 Weeks','2-3 People','2026-08-18','Standing seam metal roof. 3,200 sq ft. Must have insurance.',5),
            ('Site Prep and Excavation','Excavation','Park City','UT','Negotiable','1-2 Months','2-3 People','2026-09-01','Full site prep. Clearing, grading, foundation excavation.',2),
            ('Rough-In Electrical - 4-Plex','Electrical','Salt Lake City','UT','$70-$85/hr','3-4 Weeks','2-3 People','2026-08-25','Rough-in electrical for 4-unit multifamily. Licensed journeyman required.',11),
            ('Finish Carpentry - Luxury Home','Finish Carpentry','Park City','UT','$60-$70/hr','1-2 Months','1 Person','2026-09-08','High-end finish carpentry. Crown, base, built-ins, coffered ceilings.',4),
        ]
        for d in demo:
            conn.execute('INSERT INTO jobs (title,trade,city,state,rate,duration,crew_size,start_date,description,status,applicants,posted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (*d, datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()


def classify_trade(text):
    text = text.lower()
    for trade, keywords in TRADE_KEYWORDS.items():
        if any(k in text for k in keywords):
            return trade
    return 'General'


def is_utah(text):
    text = text.lower()
    return any(c in text for c in UTAH_CITIES) or ' ut ' in text or text.endswith(', ut') or 'utah' in text


def age_label(date_str):
    try:
        dt = datetime.fromisoformat(date_str)
        delta = datetime.utcnow() - dt
        if delta.days == 0:
            return f'{max(1, delta.seconds//3600)}h ago'
        elif delta.days == 1:
            return '1d ago'
        return f'{delta.days}d ago'
    except:
        return 'Recently'


def should_fetch(source, hours=20):
    conn = get_db()
    last = conn.execute("SELECT fetched_at FROM fetch_log WHERE source=? AND status='ok' ORDER BY id DESC LIMIT 1", (source,)).fetchone()
    conn.close()
    if not last:
        return True
    try:
        return datetime.utcnow() - datetime.fromisoformat(last['fetched_at']) > timedelta(hours=hours)
    except:
        return True


def log_fetch(source, count, status):
    conn = get_db()
    conn.execute("INSERT INTO fetch_log (source,fetched_at,count,status) VALUES (?,?,?,?)",
                 (source, datetime.utcnow().isoformat(), count, status))
    conn.commit()
    conn.close()


def fetch_indeed():
    if not should_fetch('indeed'): return 0, 'cached'
    queries = [
        'https://www.indeed.com/rss?q=framing+contractor&l=Utah',
        'https://www.indeed.com/rss?q=concrete+contractor&l=Utah',
        'https://www.indeed.com/rss?q=roofing+contractor&l=Utah',
        'https://www.indeed.com/rss?q=electrician+subcontractor&l=Utah',
        'https://www.indeed.com/rss?q=plumber+contractor&l=Utah',
        'https://www.indeed.com/rss?q=hvac+contractor&l=Utah',
        'https://www.indeed.com/rss?q=excavation+operator&l=Utah',
        'https://www.indeed.com/rss?q=general+contractor+subcontractor&l=Utah',
    ]
    total = 0
    conn = get_db()
    for url in queries:
        try:
            resp = requests.get(url, timeout=10, headers={'User-Agent': 'TradeDeck/1.0'})
            if resp.status_code != 200: continue
            root = ET.fromstring(resp.content)
            for item in root.findall('.//item'):
                title = (item.findtext('title') or '').strip()
                link = (item.findtext('link') or '').strip()
                desc = (item.findtext('description') or '').strip()
                loc = item.findtext('location') or ''
                pub = item.findtext('pubDate') or datetime.utcnow().isoformat()
                if not is_utah(f"{title} {desc} {loc}"): continue
                trade = classify_trade(f"{title} {desc}")
                city = 'Utah'
                for c in UTAH_CITIES:
                    if c in f"{title} {desc} {loc}".lower() and c != 'utah':
                        city = c.title(); break
                if link:
                    try:
                        conn.execute('INSERT OR IGNORE INTO live_leads (title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                            (title, '', loc or 'Utah, UT', city, 'UT', trade, desc[:300], link, 'Indeed', pub[:10], datetime.utcnow().isoformat()))
                        total += 1
                    except: pass
        except: continue
    conn.commit()
    conn.close()
    log_fetch('indeed', total, 'ok')
    return total, 'ok'


def fetch_craigslist():
    if not should_fetch('craigslist'): return 0, 'cached'
    feeds = [
        'https://saltlake.craigslist.org/search/skg?format=rss',
        'https://saltlake.craigslist.org/search/sub?format=rss',
        'https://saltlake.craigslist.org/search/crs?format=rss',
    ]
    total = 0
    conn = get_db()
    for url in feeds:
        try:
            resp = requests.get(url, timeout=10, headers={'User-Agent': 'TradeDeck/1.0'})
            if resp.status_code != 200: continue
            root = ET.fromstring(resp.content)
            ns = 'http://www.w3.org/2005/Atom'
            for item in root.findall(f'{{{ns}}}entry'):
                title_el = item.find(f'{{{ns}}}title')
                link_el = item.find(f'{{{ns}}}link')
                summary_el = item.find(f'{{{ns}}}summary')
                title = title_el.text.strip() if title_el is not None and title_el.text else ''
                link = link_el.get('href', '') if link_el is not None else ''
                desc = summary_el.text.strip() if summary_el is not None and summary_el.text else ''
                trade = classify_trade(f"{title} {desc}")
                if link:
                    try:
                        conn.execute('INSERT OR IGNORE INTO live_leads (title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                            (title, '', 'Salt Lake City, UT', 'Salt Lake City', 'UT', trade, desc[:300], link, 'Craigslist', datetime.utcnow().strftime('%Y-%m-%d'), datetime.utcnow().isoformat()))
                        total += 1
                    except: pass
        except: continue
    conn.commit()
    conn.close()
    log_fetch('craigslist', total, 'ok')
    return total, 'ok'


def fetch_sam():
    if not should_fetch('sam'): return 0, 'cached'
    if not SAM_API_KEY: return 0, 'no_key'
    try:
        resp = requests.get('https://api.sam.gov/opportunities/v2/search',
            headers={'X-Api-Key': SAM_API_KEY},
            params={'limit': 100,
                    'postedFrom': (datetime.utcnow() - timedelta(days=30)).strftime('%m/%d/%Y'),
                    'postedTo': datetime.utcnow().strftime('%m/%d/%Y'),
                    'ptype': 'o', 'state': 'UT', 'ncode': 'Y'}, timeout=15)
        if resp.status_code != 200:
            log_fetch('sam', 0, f'error_{resp.status_code}')
            return 0, f'error_{resp.status_code}'
        total = 0
        conn = get_db()
        for opp in resp.json().get('opportunitiesData', []):
            title = (opp.get('title') or '').strip()
            desc = opp.get('description') or ''
            notice_id = opp.get('noticeId', '')
            url = f"https://sam.gov/opp/{notice_id}/view" if notice_id else 'https://sam.gov'
            posted = (opp.get('postedDate') or datetime.utcnow().strftime('%Y-%m-%d'))[:10]
            trade = classify_trade(f"{title} {desc}")
            try:
                conn.execute('INSERT OR IGNORE INTO live_leads (title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                    (title, opp.get('departmentName', 'Federal Agency'), 'Utah', 'Utah', 'UT', trade, desc[:300], url, 'SAM.gov', posted, datetime.utcnow().isoformat()))
                total += 1
            except: pass
        conn.commit()
        conn.close()
        log_fetch('sam', total, 'ok')
        return total, 'ok'
    except Exception as e:
        log_fetch('sam', 0, str(e)[:100])
        return 0, str(e)


def fetch_ziprecruiter():
    if not should_fetch('ziprecruiter'): return 0, 'cached'
    if not ZIPRECRUITER_KEY: return 0, 'no_key'
    total = 0
    conn = get_db()
    for query in ['contractor', 'framing', 'concrete', 'roofing', 'electrician', 'plumber', 'HVAC', 'excavation']:
        try:
            resp = requests.get('https://api.ziprecruiter.com/jobs/v1',
                params={'search': query, 'location': 'Utah', 'radius_miles': 100, 'days_ago': 30, 'jobs_per_page': 20},
                headers={'Authorization': f'Bearer {ZIPRECRUITER_KEY}'}, timeout=10)
            if resp.status_code != 200: continue
            for job in resp.json().get('jobs', []):
                title = (job.get('name') or '').strip()
                url = job.get('url', '')
                desc = job.get('snippet') or ''
                trade = classify_trade(f"{title} {desc}")
                if url:
                    try:
                        conn.execute('INSERT OR IGNORE INTO live_leads (title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                            (title, (job.get('hiring_company') or {}).get('name', ''), job.get('location', 'Utah'),
                             job.get('city', 'Utah'), 'UT', trade, desc[:300], url, 'ZipRecruiter',
                             datetime.utcnow().strftime('%Y-%m-%d'), datetime.utcnow().isoformat()))
                        total += 1
                    except: pass
        except: continue
    conn.commit()
    conn.close()
    log_fetch('ziprecruiter', total, 'ok')
    return total, 'ok'


def fetch_permitstack():
    if not should_fetch('permitstack'): return 0, 'cached'
    if not PERMITSTACK_KEY: return 0, 'no_key'
    total = 0
    conn = get_db()
    for city in ['Park City', 'Heber City', 'Salt Lake City', 'Provo', 'Ogden', 'Kamas', 'Midway']:
        for cat in ['RESIDENTIAL', 'COMMERCIAL', 'ROOFING', 'ELECTRICAL', 'PLUMBING', 'MECHANICAL', 'FOUNDATION', 'ADDITION']:
            try:
                resp = requests.get('https://api.permit-stack.com/v1/permits/search',
                    headers={'X-API-Key': PERMITSTACK_KEY},
                    params={'city': city, 'state': 'UT', 'category': cat, 'limit': 10, 'days_back': 30}, timeout=10)
                if resp.status_code != 200: continue
                for p in resp.json().get('results', []):
                    trade = classify_trade(f"{p.get('category','')} {p.get('description','')}")
                    val = p.get('estimated_value', '')
                    val_str = f"${val:,.0f}" if isinstance(val, (int, float)) and val > 0 else 'Not listed'
                    try:
                        conn.execute('INSERT OR IGNORE INTO gc_leads (permit_number,address,city,state,category,trade,description,est_value,contractor,permit_date,status,source,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                            (p.get('permit_number',''), p.get('address',''), city, 'UT', p.get('category',cat), trade,
                             p.get('description',''), val_str, p.get('contractor_name',''), p.get('issue_date',''),
                             p.get('status','Issued'), 'permitstack', datetime.utcnow().isoformat()))
                        total += 1
                    except: pass
            except: continue
    conn.commit()
    conn.close()
    log_fetch('permitstack', total, 'ok')
    return total, 'ok'


def run_all_fetches():
    fetch_indeed()
    fetch_craigslist()
    fetch_sam()
    fetch_ziprecruiter()
    fetch_permitstack()


# ── AUTH ROUTES ──

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    first_name = (data.get('first_name') or '').strip()
    last_name = (data.get('last_name') or '').strip()
    if not email or not password or not first_name:
        return jsonify({'error': 'Email, password, and first name required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Email already registered'}), 409
    try:
        cur = conn.execute('''INSERT INTO users
            (email, password_hash, first_name, last_name, phone, role, trade,
             license_number, license_type, license_state, years_experience,
             looking_for, pay_min, pay_max, pay_type, bio, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (email, hash_password(password), first_name,
             data.get('last_name', ''), data.get('phone', ''),
             data.get('role', 'sub'), data.get('trade', ''),
             data.get('license_number', ''), data.get('license_type', ''),
             data.get('license_state', 'UT'), data.get('years_experience', 0),
             data.get('looking_for', ''), data.get('pay_min', 0),
             data.get('pay_max', 0), data.get('pay_type', 'hourly'),
             data.get('bio', ''), datetime.utcnow().isoformat()))
        user_id = cur.lastrowid
        conn.commit()
        conn.close()
        token = make_token(user_id, email)
        return jsonify({'success': True, 'token': token, 'user': {
            'id': user_id, 'email': email, 'first_name': first_name,
            'last_name': data.get('last_name', ''), 'role': data.get('role', 'sub'),
            'trade': data.get('trade', '')}}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if not user or user['password_hash'] != hash_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401
    token = make_token(user['id'], email)
    return jsonify({'success': True, 'token': token, 'user': {
        'id': user['id'], 'email': user['email'],
        'first_name': user['first_name'], 'last_name': user['last_name'],
        'role': user['role'], 'trade': user['trade'],
        'license_number': user['license_number'],
        'years_experience': user['years_experience']}})


@app.route('/api/auth/me', methods=['GET'])
def me():
    user_payload = get_current_user()
    if not user_payload:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_payload['user_id'],)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': {
        'id': user['id'], 'email': user['email'],
        'first_name': user['first_name'], 'last_name': user['last_name'],
        'phone': user['phone'], 'role': user['role'], 'trade': user['trade'],
        'license_number': user['license_number'], 'license_type': user['license_type'],
        'years_experience': user['years_experience'], 'looking_for': user['looking_for'],
        'pay_min': user['pay_min'], 'pay_max': user['pay_max'], 'pay_type': user['pay_type'],
        'bio': user['bio'], 'verified': user['verified']}})


# ── JOB ROUTES ──

@app.route('/')
def index():
    return jsonify({'status': 'TradeDeck API running', 'version': '2.1'})


@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    trade = request.args.get('trade', '')
    location = request.args.get('location', '')
    status = request.args.get('status', 'open')
    conn = get_db()
    query = 'SELECT * FROM jobs WHERE status = ?'
    params = [status]
    if trade:
        query += ' AND trade = ?'
        params.append(trade)
    if location:
        query += ' AND (city LIKE ? OR state = ?)'
        params += [f'%{location}%', location]
    query += ' ORDER BY posted_at DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify({'jobs': [{'id': r['id'], 'title': r['title'], 'trade': r['trade'],
        'city': r['city'], 'state': r['state'], 'location': f"{r['city']}, {r['state']}",
        'rate': r['rate'] or '', 'duration': r['duration'] or '',
        'crew_size': r['crew_size'] or '', 'start_date': r['start_date'] or '',
        'description': r['description'] or '', 'status': r['status'],
        'applicants': r['applicants'], 'posted_at': r['posted_at'],
        'age': age_label(r['posted_at'])} for r in rows], 'count': len(rows)})


@app.route('/api/jobs', methods=['POST'])
def post_job():
    data = request.get_json(silent=True) or {}
    missing = [f for f in ['title', 'trade', 'city', 'state'] if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing: {", ".join(missing)}'}), 400
    user_payload = get_current_user()
    posted_by = user_payload['user_id'] if user_payload else None
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO jobs (title,trade,city,state,rate,duration,crew_size,start_date,description,status,applicants,posted_by,posted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (data['title'], data['trade'], data['city'], data['state'],
         data.get('rate',''), data.get('duration',''), data.get('crew_size',''),
         data.get('start_date',''), data.get('description',''), 'open', 0, posted_by, datetime.utcnow().isoformat()))
    conn.commit()
    job_id = cur.lastrowid
    conn.close()
    return jsonify({'success': True, 'id': job_id}), 201


@app.route('/api/jobs/<int:job_id>/apply', methods=['POST'])
def apply_to_job(job_id):
    data = request.get_json(silent=True) or {}
    user_payload = get_current_user()
    conn = get_db()
    conn.execute('UPDATE jobs SET applicants = applicants + 1 WHERE id = ?', (job_id,))
    if user_payload or data.get('email'):
        conn.execute('INSERT INTO applications (job_id,user_id,name,email,message,applied_at) VALUES (?,?,?,?,?,?)',
            (job_id, user_payload['user_id'] if user_payload else None,
             data.get('name',''), data.get('email',''), data.get('message',''),
             datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/live-leads', methods=['GET'])
def get_live_leads():
    run_all_fetches()
    trade = request.args.get('trade', '')
    source = request.args.get('source', '')
    search = request.args.get('search', '')
    limit = min(int(request.args.get('limit', 100)), 300)
    conn = get_db()
    query = 'SELECT * FROM live_leads WHERE 1=1'
    params = []
    if trade:
        query += ' AND trade = ?'; params.append(trade)
    if source:
        query += ' AND source = ?'; params.append(source)
    if search:
        query += ' AND (title LIKE ? OR description LIKE ? OR location LIKE ?)'; params += [f'%{search}%']*3
    query += ' ORDER BY fetched_at DESC, posted_date DESC LIMIT ?'; params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify({'leads': [{'id': r['id'], 'title': r['title'], 'company': r['company'] or '',
        'location': r['location'], 'city': r['city'], 'trade': r['trade'],
        'description': r['description'] or '', 'url': r['url'], 'source': r['source'],
        'posted_date': r['posted_date'], 'age': age_label(r['fetched_at'])} for r in rows],
        'count': len(rows)})


@app.route('/api/live-leads/refresh', methods=['POST'])
def refresh_live_leads():
    conn = get_db()
    conn.execute("DELETE FROM fetch_log WHERE source IN ('indeed','craigslist','sam','ziprecruiter')")
    conn.commit(); conn.close()
    run_all_fetches()
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM live_leads').fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'total_leads': count})


@app.route('/api/gc-leads', methods=['GET'])
def get_gc_leads():
    fetch_permitstack()
    trade = request.args.get('trade', '')
    city = request.args.get('city', '')
    limit = min(int(request.args.get('limit', 50)), 200)
    conn = get_db()
    query = 'SELECT * FROM gc_leads WHERE 1=1'
    params = []
    if trade:
        query += ' AND trade = ?'; params.append(trade)
    if city:
        query += ' AND city LIKE ?'; params.append(f'%{city}%')
    query += ' ORDER BY fetched_at DESC LIMIT ?'; params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify({'leads': [{'id': r['id'], 'permit_number': r['permit_number'],
        'address': r['address'], 'city': r['city'], 'state': r['state'],
        'category': r['category'], 'trade': r['trade'], 'description': r['description'],
        'est_value': r['est_value'], 'contractor': r['contractor'],
        'permit_date': r['permit_date'], 'status': r['status'],
        'age': age_label(r['fetched_at'])} for r in rows], 'count': len(rows)})


@app.route('/api/gc-leads/refresh', methods=['POST'])
def refresh_gc_leads():
    conn = get_db()
    conn.execute("DELETE FROM fetch_log WHERE source='permitstack'")
    conn.commit(); conn.close()
    fetch_permitstack()
    return jsonify({'success': True})


@app.route('/api/chat', methods=['POST'])
def chat_proxy():
    data = request.get_json(silent=True) or {}
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'AI service not configured'}), 503
    try:
        resp = requests.post('https://api.anthropic.com/v1/messages',
            headers={'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 1000,
                  'system': data.get('system', ''), 'messages': data.get('messages', [])}, timeout=30)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
