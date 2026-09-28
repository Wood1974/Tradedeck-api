import json,secrets,sqlite3,time
from pathlib import Path
from .custody_chain import event_hash
class Store:
 def __init__(self,db_path,root):
  self.db_path=db_path.replace("sqlite:///","");self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);Path(self.db_path).parent.mkdir(parents=True,exist_ok=True);self._init()
 def db(self):
  c=sqlite3.connect(self.db_path);c.row_factory=sqlite3.Row;return c
 def _init(self):
  with self.db() as c:c.executescript("""PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY,job_id TEXT,point_id TEXT,account_id TEXT,expires_at REAL,used_at REAL);CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,job_id TEXT,point_id TEXT,account_id TEXT,nonce TEXT UNIQUE,photo_sha256 TEXT,note_sha256 TEXT,bind_hash TEXT,captured_at TEXT,written_at TEXT,location_json TEXT,attestation_json TEXT,original_path TEXT,status TEXT,state TEXT);CREATE TABLE IF NOT EXISTS attestation_keys(key_id TEXT PRIMARY KEY,account_id TEXT,public_key_der_b64 TEXT,environment TEXT,counter INTEGER DEFAULT 0,receipt_b64 TEXT,created_at REAL);CREATE TABLE IF NOT EXISTS attestation_challenges(nonce TEXT PRIMARY KEY,account_id TEXT,expires_at REAL,used_at REAL);CREATE TABLE IF NOT EXISTS custody_events(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id TEXT,event_type TEXT,event_at TEXT,details_json TEXT,event_hash TEXT);CREATE TABLE IF NOT EXISTS state_events(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id TEXT,from_state TEXT,to_state TEXT,event_at TEXT,actor_id TEXT,details_json TEXT);""")
 def attestation_challenge(self,a,ttl):
  n=secrets.token_urlsafe(32);now=time.time()
  with self.db() as c:c.execute("INSERT INTO attestation_challenges VALUES(?,?,?,NULL)",(n,a,now+ttl))
  return n,now+ttl
 def consume_attestation_challenge(self,n,a):
  with self.db() as c:
   r=c.execute("SELECT * FROM attestation_challenges WHERE nonce=?",(n,)).fetchone()
   if not r or r["used_at"] is not None or r["expires_at"]<time.time() or r["account_id"]!=a:raise ValueError("invalid_attestation_nonce")
   c.execute("UPDATE attestation_challenges SET used_at=? WHERE nonce=?",(time.time(),n));return r
 def save_attestation_key(self,k,a,p,e,receipt):
  with self.db() as c:c.execute("INSERT OR IGNORE INTO attestation_keys VALUES(?,?,?,?,0,?,?)",(k,a,p,e,receipt,time.time()))
 def get_attestation_key(self,k):
  with self.db() as c:return c.execute("SELECT * FROM attestation_keys WHERE key_id=?",(k,)).fetchone()
 def update_attestation_counter(self,k,n):
  with self.db() as c:c.execute("UPDATE attestation_keys SET counter=? WHERE key_id=? AND counter<?",(n,k,n));return c.total_changes==1
 def challenge(self,j,p,a,ttl):
  n=secrets.token_urlsafe(32);now=time.time()
  with self.db() as c:c.execute("INSERT INTO challenges VALUES(?,?,?,?,?,NULL)",(n,j,p,a,now+ttl))
  return n,now+ttl
 def consume(self,n,j,p,a):
  with self.db() as c:
   r=c.execute("SELECT * FROM challenges WHERE nonce=?",(n,)).fetchone()
   if not r:raise ValueError("unknown_nonce")
   if r["used_at"] is not None:raise ValueError("nonce_replayed")
   if r["expires_at"]<time.time():raise ValueError("nonce_expired")
   if (r["job_id"],r["point_id"],r["account_id"])!=(j,p,a):raise ValueError("challenge_context_mismatch")
   c.execute("UPDATE challenges SET used_at=? WHERE nonce=?",(time.time(),n));return r
 def save_original(self,e,j,a,raw):
  rel=f"{j}/{a}/orig/{e}.jpg";p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True)
  if p.exists():raise ValueError("original_already_exists")
  p.write_bytes(raw);return rel
 def create_evidence(self,**k):
  cols=["id","job_id","point_id","account_id","nonce","photo_sha256","note_sha256","bind_hash","captured_at","written_at","location_json","attestation_json","original_path","status","state"]
  with self.db() as c:
   c.execute("INSERT INTO evidence VALUES("+",".join("?"*15)+")",tuple(k[x] for x in cols));prev=None
   for st in k.get("state_history",["capture_received","verified","sealed"]):c.execute("INSERT INTO state_events(evidence_id,from_state,to_state,event_at,actor_id,details_json) VALUES(?,?,?,?,?,?)",(k["id"],prev,st,k["written_at"],k.get("actor_id"),"{}"));prev=st
   d={"photo_sha256":k["photo_sha256"],"note_sha256":k["note_sha256"],"bind_hash":k["bind_hash"],"state":k["state"]};h=event_hash(None,"sealed",k["written_at"],k.get("actor_id"),d);c.execute("INSERT INTO custody_events(evidence_id,event_type,event_at,details_json,event_hash) VALUES(?,?,?,?,?)",(k["id"],"sealed",k["written_at"],json.dumps({"actor_id":k.get("actor_id"),**d},sort_keys=True),h))
 def get(self,e):
  with self.db() as c:return c.execute("SELECT * FROM evidence WHERE id=?",(e,)).fetchone()
 def state_history(self,e):
  with self.db() as c:return c.execute("SELECT * FROM state_events WHERE evidence_id=? ORDER BY id",(e,)).fetchall()
 def custody_history(self,e):
  with self.db() as c:return c.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id",(e,)).fetchall()
