import os
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get('DB_PATH', 'tradedeck.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            trade       TEXT NOT NULL,
            city        TEXT NOT NULL,
            state       TEXT NOT NULL,
            rate        TEXT,
            duration    TEXT,
            crew_size   TEXT,
            start_date  TEXT,
            description TEXT,
            status      TEXT DEFAULT 'open',
            applicants  INTEGER DEFAULT 0,
            posted_at   TEXT NOT NULL
        )
    ''')
    count = conn.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
    if count == 0:
        demo_jobs = [
            ('Framing Crew Needed', 'Framing', 'Park City', 'UT', '$65-$75 / hr', '3-4 Weeks', '4-6 People', '2026-08-04', 'Experienced framing crew needed for new luxury custom home build. Must have mountain-modern experience. 4,800 sq ft two-story.', 7),
            ('Concrete Flatwork - Heated Drive', 'Concrete', 'Heber City', 'UT', '$8,500 flat', '1 Week', '2-3 People', '2026-08-11', 'Flatwork pour for heated driveway system. Radiant tubing already laid. Need experienced finishers who have worked with snowmelt systems before.', 3),
            ('Metal Roofing - Custom Home', 'Roofing', 'Kamas', 'UT', '$55-$65 / hr', '2 Weeks', '2-3 People', '2026-08-18', 'Standing seam metal roof on new custom home. Steep pitch, 3,200 sq ft footprint. Must have insurance and references.', 5),
            ('Site Prep and Excavation', 'Excavation', 'Park City', 'UT', 'Negotiable', '1-2 Months', '2-3 People', '2026-09-01', 'Full site prep for new build. Clearing, grading, foundation excavation. Rocky terrain. Equipment must be owner-operated.', 2),
            ('Rough-In Electrical - 4-Plex', 'Electrical', 'Salt Lake City', 'UT', '$70-$85 / hr', '3-4 Weeks', '2-3 People', '2026-08-25', 'Rough-in electrical for 4-unit multifamily. Must be licensed journeyman or higher. Plans available on request.', 11),
            ('Finish Carpentry - Luxury Home', 'Finish Carpentry', 'Park City', 'UT', '$60-$70 / hr', '1-2 Months', '1 Person', '2026-09-08', 'High-end finish carpentry on luxury custom home. Crown, base, built-ins, coffered ceilings. Portfolio required.', 4),
        ]
        for job in demo_jobs:
            conn.execute('''
                INSERT INTO jobs (title, trade, city, state, rate, duration, crew_size, start_date, description, status, applicants, posted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            ''', (*job, datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()


@app.route('/')
def index():
    return jsonify({'status': 'TradeDeck API running', 'version': '1.0'})


@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    trade    = request.args.get('trade', '')
    location = request.args.get('location', '')
    status   = request.args.get('status', 'open')

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

    jobs = []
    for row in rows:
        posted = row['posted_at']
        try:
            dt = datetime.fromisoformat(posted)
            delta = datetime.utcnow() - dt
            if delta.days == 0:
                hrs = max(1, delta.seconds // 3600)
                age = f'{hrs}h ago'
            elif delta.days == 1:
                age = '1d ago'
            else:
                age = f'{delta.days}d ago'
        except Exception:
            age = 'Recently'

        jobs.append({
            'id':          row['id'],
            'title':       row['title'],
            'trade':       row['trade'],
            'city':        row['city'],
            'state':       row['state'],
            'location':    f"{row['city']}, {row['state']}",
            'rate':        row['rate'] or '',
            'duration':    row['duration'] or '',
            'crew_size':   row['crew_size'] or '',
            'start_date':  row['start_date'] or '',
            'description': row['description'] or '',
            'status':      row['status'],
            'applicants':  row['applicants'],
            'posted_at':   posted,
            'age':         age,
        })

    return jsonify({'jobs': jobs, 'count': len(jobs)})


@app.route('/api/jobs', methods=['POST'])
def post_job():
    data = request.get_json(silent=True) or {}

    required = ['title', 'trade', 'city', 'state']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400

    conn = get_db()
    cur = conn.execute('''
        INSERT INTO jobs (title, trade, city, state, rate, duration, crew_size, start_date, description, status, applicants, posted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0, ?)
    ''', (
        data.get('title'),
        data.get('trade'),
        data.get('city'),
        data.get('state'),
        data.get('rate', ''),
        data.get('duration', ''),
        data.get('crew_size', ''),
        data.get('start_date', ''),
        data.get('description', ''),
        datetime.utcnow().isoformat(),
    ))
    conn.commit()
    job_id = cur.lastrowid
    conn.close()

    return jsonify({'success': True, 'id': job_id}), 201


@app.route('/api/jobs/<int:job_id>/apply', methods=['POST'])
def apply_to_job(job_id):
    conn = get_db()
    conn.execute('UPDATE jobs SET applicants = applicants + 1 WHERE id = ?', (job_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/jobs/<int:job_id>/close', methods=['POST'])
def close_job(job_id):
    conn = get_db()
    conn.execute("UPDATE jobs SET status = 'filled' WHERE id = ?", (job_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
