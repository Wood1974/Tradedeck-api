import os
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import requests

DB_PATH = os.environ.get("DB_PATH", "tradedeck.db")
PERMITSTACK_KEY = os.environ.get("PERMITSTACK_KEY", "")
SAM_API_KEY = os.environ.get("SAM_API_KEY", "")
ZIPRECRUITER_KEY = os.environ.get("ZIPRECRUITER_KEY", "")

TRADE_KEYWORDS = {
    "Framing": ["framing", "frame", "framer", "structural", "wood frame"],
    "Concrete": ["concrete", "flatwork", "foundation", "slab", "cement", "paving"],
    "Roofing": ["roofing", "roof", "shingle", "metal roof", "reroof", "roofer"],
    "Electrical": ["electrical", "electrician", "electric", "wiring", "panel", "journeyman"],
    "Plumbing": ["plumbing", "plumber", "pipe", "pipefitter", "water heater", "sewer"],
    "HVAC": ["hvac", "mechanical", "heating", "cooling", "ductwork", "boiler"],
    "Excavation": ["excavation", "excavator", "grading", "earthwork", "site prep", "demolition"],
    "Flooring": ["flooring", "floor installer", "tile", "hardwood", "carpet"],
    "Siding": ["siding", "exterior", "cladding", "stucco"],
    "Painting": ["painting", "painter", "paint", "coating"],
    "Finish Carpentry": ["finish carpentry", "trim carpenter", "finish carpenter", "millwork"],
    "General": ["contractor", "construction", "builder", "general labor", "laborer", "remodel"],
}

UTAH_CITIES = [
    "salt lake city", "park city", "provo", "ogden", "heber", "heber city", "kamas",
    "midway", "francis", "sandy", "west jordan", "orem", "st george", "logan",
    "murray", "draper", "lehi", "riverton", "south jordan", "taylorsville", "utah",
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_leads_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS gc_leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        permit_number TEXT, address TEXT, city TEXT, state TEXT,
        category TEXT, trade TEXT, description TEXT, est_value TEXT,
        contractor TEXT, permit_date TEXT, status TEXT,
        source TEXT DEFAULT 'permitstack', fetched_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS live_leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, company TEXT, location TEXT, city TEXT,
        state TEXT DEFAULT 'UT', trade TEXT, description TEXT,
        url TEXT UNIQUE, source TEXT, posted_date TEXT, fetched_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS fetch_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT, fetched_at TEXT, count INTEGER, status TEXT)""")
    conn.commit()
    conn.close()


def classify_trade(text):
    text = text.lower()
    for trade, keywords in TRADE_KEYWORDS.items():
        if any(k in text for k in keywords):
            return trade
    return "General"


def is_utah(text):
    text = text.lower()
    return any(c in text for c in UTAH_CITIES) or " ut " in text or text.endswith(", ut") or "utah" in text


def age_label(date_str):
    try:
        dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00")[:19])
        delta = datetime.utcnow() - dt
        if delta.days == 0:
            return f"{max(1, delta.seconds // 3600)}h ago"
        if delta.days == 1:
            return "1d ago"
        return f"{delta.days}d ago"
    except Exception:
        return "Recently"


def should_fetch(source, hours=20):
    conn = get_db()
    last = conn.execute(
        "SELECT fetched_at FROM fetch_log WHERE source=? AND status='ok' ORDER BY id DESC LIMIT 1",
        (source,),
    ).fetchone()
    conn.close()
    if not last:
        return True
    try:
        return datetime.utcnow() - datetime.fromisoformat(last["fetched_at"]) > timedelta(hours=hours)
    except Exception:
        return True


def log_fetch(source, count, status):
    conn = get_db()
    conn.execute(
        "INSERT INTO fetch_log (source,fetched_at,count,status) VALUES (?,?,?,?)",
        (source, datetime.utcnow().isoformat(), count, status),
    )
    conn.commit()
    conn.close()


def fetch_indeed():
    if not should_fetch("indeed"):
        return 0, "cached"
    queries = [
        "https://www.indeed.com/rss?q=framing+contractor&l=Utah",
        "https://www.indeed.com/rss?q=concrete+contractor&l=Utah",
        "https://www.indeed.com/rss?q=roofing+contractor&l=Utah",
        "https://www.indeed.com/rss?q=electrician+subcontractor&l=Utah",
        "https://www.indeed.com/rss?q=plumber+contractor&l=Utah",
        "https://www.indeed.com/rss?q=hvac+contractor&l=Utah",
        "https://www.indeed.com/rss?q=excavation+operator&l=Utah",
        "https://www.indeed.com/rss?q=general+contractor+subcontractor&l=Utah",
    ]
    total = 0
    conn = get_db()
    for url in queries:
        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "TradeDeck/1.0"})
            if resp.status_code != 200:
                continue
            root = ET.fromstring(resp.content)
            for item in root.findall(".//item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                desc = (item.findtext("description") or "").strip()
                loc = item.findtext("location") or ""
                pub = item.findtext("pubDate") or datetime.utcnow().isoformat()
                if not is_utah(f"{title} {desc} {loc}"):
                    continue
                trade = classify_trade(f"{title} {desc}")
                city = "Utah"
                for c in UTAH_CITIES:
                    if c in f"{title} {desc} {loc}".lower() and c != "utah":
                        city = c.title()
                        break
                if link:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO live_leads "
                            "(title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (title, "", loc or "Utah, UT", city, "UT", trade, desc[:300], link,
                             "Indeed", pub[:10], datetime.utcnow().isoformat()),
                        )
                        total += 1
                    except Exception:
                        pass
        except Exception:
            continue
    conn.commit()
    conn.close()
    log_fetch("indeed", total, "ok")
    return total, "ok"


def fetch_craigslist():
    if not should_fetch("craigslist"):
        return 0, "cached"
    feeds = [
        "https://saltlake.craigslist.org/search/skg?format=rss",
        "https://saltlake.craigslist.org/search/sub?format=rss",
        "https://saltlake.craigslist.org/search/crs?format=rss",
    ]
    total = 0
    conn = get_db()
    for url in feeds:
        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "TradeDeck/1.0"})
            if resp.status_code != 200:
                continue
            root = ET.fromstring(resp.content)
            ns = "http://www.w3.org/2005/Atom"
            for item in root.findall(f"{{{ns}}}entry"):
                title_el = item.find(f"{{{ns}}}title")
                link_el = item.find(f"{{{ns}}}link")
                summary_el = item.find(f"{{{ns}}}summary")
                title = title_el.text.strip() if title_el is not None and title_el.text else ""
                link = link_el.get("href", "") if link_el is not None else ""
                desc = summary_el.text.strip() if summary_el is not None and summary_el.text else ""
                trade = classify_trade(f"{title} {desc}")
                if link:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO live_leads "
                            "(title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (title, "", "Salt Lake City, UT", "Salt Lake City", "UT", trade,
                             desc[:300], link, "Craigslist", datetime.utcnow().strftime("%Y-%m-%d"),
                             datetime.utcnow().isoformat()),
                        )
                        total += 1
                    except Exception:
                        pass
        except Exception:
            continue
    conn.commit()
    conn.close()
    log_fetch("craigslist", total, "ok")
    return total, "ok"


def fetch_sam():
    if not should_fetch("sam"):
        return 0, "cached"
    if not SAM_API_KEY:
        return 0, "no_key"
    try:
        resp = requests.get(
            "https://api.sam.gov/opportunities/v2/search",
            headers={"X-Api-Key": SAM_API_KEY},
            params={
                "limit": 100,
                "postedFrom": (datetime.utcnow() - timedelta(days=30)).strftime("%m/%d/%Y"),
                "postedTo": datetime.utcnow().strftime("%m/%d/%Y"),
                "ptype": "o",
                "state": "UT",
                "ncode": "Y",
            },
            timeout=15,
        )
        if resp.status_code != 200:
            log_fetch("sam", 0, f"error_{resp.status_code}")
            return 0, f"error_{resp.status_code}"
        total = 0
        conn = get_db()
        for opp in resp.json().get("opportunitiesData", []):
            title = (opp.get("title") or "").strip()
            desc = opp.get("description") or ""
            notice_id = opp.get("noticeId", "")
            url = f"https://sam.gov/opp/{notice_id}/view" if notice_id else "https://sam.gov"
            posted = (opp.get("postedDate") or datetime.utcnow().strftime("%Y-%m-%d"))[:10]
            trade = classify_trade(f"{title} {desc}")
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO live_leads "
                    "(title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (title, opp.get("departmentName", "Federal Agency"), "Utah", "Utah", "UT", trade,
                     desc[:300], url, "SAM.gov", posted, datetime.utcnow().isoformat()),
                )
                total += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
        log_fetch("sam", total, "ok")
        return total, "ok"
    except Exception as e:
        log_fetch("sam", 0, str(e)[:100])
        return 0, str(e)


def fetch_ziprecruiter():
    if not should_fetch("ziprecruiter"):
        return 0, "cached"
    if not ZIPRECRUITER_KEY:
        return 0, "no_key"
    total = 0
    conn = get_db()
    for query in ["contractor", "framing", "concrete", "roofing", "electrician", "plumber", "HVAC", "excavation"]:
        try:
            resp = requests.get(
                "https://api.ziprecruiter.com/jobs/v1",
                params={"search": query, "location": "Utah", "radius_miles": 100, "days_ago": 30, "jobs_per_page": 20},
                headers={"Authorization": f"Bearer {ZIPRECRUITER_KEY}"},
                timeout=10,
            )
            if resp.status_code != 200:
                continue
            for job in resp.json().get("jobs", []):
                title = (job.get("name") or "").strip()
                url = job.get("url", "")
                desc = job.get("snippet") or ""
                trade = classify_trade(f"{title} {desc}")
                if url:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO live_leads "
                            "(title,company,location,city,state,trade,description,url,source,posted_date,fetched_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (title, (job.get("hiring_company") or {}).get("name", ""), job.get("location", "Utah"),
                             job.get("city", "Utah"), "UT", trade, desc[:300], url, "ZipRecruiter",
                             datetime.utcnow().strftime("%Y-%m-%d"), datetime.utcnow().isoformat()),
                        )
                        total += 1
                    except Exception:
                        pass
        except Exception:
            continue
    conn.commit()
    conn.close()
    log_fetch("ziprecruiter", total, "ok")
    return total, "ok"


def fetch_permitstack():
    if not should_fetch("permitstack"):
        return 0, "cached"
    if not PERMITSTACK_KEY:
        return 0, "no_key"
    total = 0
    conn = get_db()
    for city in ["Park City", "Heber City", "Salt Lake City", "Provo", "Ogden", "Kamas", "Midway"]:
        for cat in ["RESIDENTIAL", "COMMERCIAL", "ROOFING", "ELECTRICAL", "PLUMBING", "MECHANICAL", "FOUNDATION", "ADDITION"]:
            try:
                resp = requests.get(
                    "https://api.permit-stack.com/v1/permits/search",
                    headers={"X-API-Key": PERMITSTACK_KEY},
                    params={"city": city, "state": "UT", "category": cat, "limit": 10, "days_back": 30},
                    timeout=10,
                )
                if resp.status_code != 200:
                    continue
                for p in resp.json().get("results", []):
                    trade = classify_trade(f"{p.get('category', '')} {p.get('description', '')}")
                    val = p.get("estimated_value", "")
                    val_str = f"${val:,.0f}" if isinstance(val, (int, float)) and val > 0 else "Not listed"
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO gc_leads "
                            "(permit_number,address,city,state,category,trade,description,est_value,contractor,permit_date,status,source,fetched_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (p.get("permit_number", ""), p.get("address", ""), city, "UT", p.get("category", cat),
                             trade, p.get("description", ""), val_str, p.get("contractor_name", ""),
                             p.get("issue_date", ""), p.get("status", "Issued"), "permitstack",
                             datetime.utcnow().isoformat()),
                        )
                        total += 1
                    except Exception:
                        pass
            except Exception:
                continue
    conn.commit()
    conn.close()
    log_fetch("permitstack", total, "ok")
    return total, "ok"


def run_all_fetches():
    fetch_indeed()
    fetch_craigslist()
    fetch_sam()
    fetch_ziprecruiter()
    fetch_permitstack()


def get_live_leads(trade="", source="", search="", limit=100):
    conn = get_db()
    query = "SELECT * FROM live_leads WHERE 1=1"
    params = []
    if trade:
        query += " AND trade = ?"
        params.append(trade)
    if source:
        query += " AND source = ?"
        params.append(source)
    if search:
        query += " AND (title LIKE ? OR description LIKE ? OR location LIKE ?)"
        params += [f"%{search}%"] * 3
    query += " ORDER BY fetched_at DESC, posted_date DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [{
        "id": r["id"],
        "title": r["title"],
        "company": r["company"] or "",
        "location": r["location"],
        "city": r["city"],
        "trade": r["trade"],
        "description": r["description"] or "",
        "url": r["url"],
        "source": r["source"],
        "posted_date": r["posted_date"],
        "age": age_label(r["fetched_at"]),
    } for r in rows]


def get_gc_leads(trade="", city="", limit=50):
    conn = get_db()
    query = "SELECT * FROM gc_leads WHERE 1=1"
    params = []
    if trade:
        query += " AND trade = ?"
        params.append(trade)
    if city:
        query += " AND city LIKE ?"
        params.append(f"%{city}%")
    query += " ORDER BY fetched_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [{
        "id": r["id"],
        "permit_number": r["permit_number"],
        "address": r["address"],
        "city": r["city"],
        "state": r["state"],
        "category": r["category"],
        "trade": r["trade"],
        "description": r["description"],
        "est_value": r["est_value"],
        "contractor": r["contractor"],
        "permit_date": r["permit_date"],
        "status": r["status"],
        "age": age_label(r["fetched_at"]),
    } for r in rows]


def refresh_live_leads():
    conn = get_db()
    conn.execute("DELETE FROM fetch_log WHERE source IN ('indeed','craigslist','sam','ziprecruiter')")
    conn.commit()
    conn.close()
    run_all_fetches()
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM live_leads").fetchone()[0]
    conn.close()
    return count


def refresh_gc_leads():
    conn = get_db()
    conn.execute("DELETE FROM fetch_log WHERE source='permitstack'")
    conn.commit()
    conn.close()
    fetch_permitstack()
    return True


init_leads_db()
