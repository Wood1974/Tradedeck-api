"""Server-locked anchors for a custody head.

The deciding proof is an object in S3 with Object Lock in COMPLIANCE mode.
The application role can put an object and set its retention. It cannot
delete one, and it cannot overwrite one before the retention date. A later
rewrite of the chain can put a new object for the new head. It cannot
remove the object that names the old head.

That only helps a verifier who sees the full set. Anchors bundled in an
export are a convenience for an honest package. The exporter chooses that
list, so a package that omits the old object still looks consistent. The
check that catches a rewrite is the full listing, from a separate read
role (`python -m anchor_lock export`) or from a phone backup unioned with
the package. Two bodies for the same object key disagree: the phone copy
never replaces the locked bytes. The check fails closed.

Object Lock has to be turned on when the bucket is created. It cannot be
turned on later. Retention on each object is COMPLIANCE for
SHIELD_ANCHOR_RETENTION_DAYS (2555, seven years of 365 days).

Disabled when SHIELD_ANCHOR_BUCKET is unset. Uploads still succeed, and a
verifier with no anchors says anchor absent. That is not a failure.

A timestamp that cannot be obtained is not written. COMPLIANCE would freeze
the object without the token, and the token could not be added later. The
head stays timestamp pending in a local queue until a retry stamps it.
The queue is SQLite at SHIELD_ANCHOR_QUEUE_PATH. It has to live on the
persistent disk. The container disk is empty after a restart, and a
pending anchor that lived only there is gone.

S3 being down queues the put the same way. The upload is not refused.
Nothing is locked until the put succeeds.
"""
import argparse
import base64
import json
import logging
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import config
import tsa

log = logging.getLogger(__name__)

VERSION = 1
SKEW = timedelta(minutes=5)
ANCHORED_EVENTS = frozenset({
    "uploaded", "offline_batch", "superseded", "integrity_flag",
})
NOTE_ABSENT = "anchor absent"
PROBLEM_NO_HEAD = "no locked anchor for this head"
PROBLEM_MISSING = "A locked anchor names a head that is not in this chain."
PROBLEM_TOKEN = "The locked anchor token does not cover this head."
PROBLEM_TIME = "The locked anchor time does not fit this entry."
PROBLEM_RECEIPT = "The locked anchor receipt is not over this head."
PROBLEM_COPY = "A phone copy does not match the locked anchor."

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queue (
    object_key TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    recorded_at TEXT,
    receipt_json TEXT,
    first_attempt_at TEXT NOT NULL,
    status TEXT NOT NULL,
    token_b64 TEXT,
    authority TEXT,
    gen_time TEXT
);
CREATE TABLE IF NOT EXISTS locked (
    object_key TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    body_json TEXT NOT NULL
);
"""


class ComplianceError(Exception):
    """Object Lock refused a delete or an overwrite that retention still covers."""


class AnchorUnavailable(Exception):
    """The lock store could not be reached. The upload still succeeds."""


def configured():
    """True when a bucket is set. Unset is the disabled mode."""
    return bool((os.environ.get("SHIELD_ANCHOR_BUCKET") or "").strip())


def retention_days():
    raw = os.environ.get("SHIELD_ANCHOR_RETENTION_DAYS")
    if raw is None or raw == "":
        raw = config.get("SHIELD_ANCHOR_RETENTION_DAYS")
    try:
        days = int(raw)
    except (TypeError, ValueError):
        days = 2555
    return days if days > 0 else 2555


def queue_path():
    """Where pending anchors wait. Explicit path, else beside DB_PATH, else tmp.

    The tmp fallback is not durable. A deployment that enables the bucket
    sets SHIELD_ANCHOR_QUEUE_PATH on the persistent disk.
    """
    explicit = (os.environ.get("SHIELD_ANCHOR_QUEUE_PATH") or "").strip()
    if explicit:
        return explicit
    db_path = (os.environ.get("DB_PATH") or "").strip()
    if db_path:
        return os.path.join(os.path.dirname(db_path) or ".", "shield-anchors.db")
    return os.path.join(tempfile.gettempdir(), "shield-anchors.db")


def object_key(record_id, seq, head_hash):
    """One immutable object per head. A different head is a different key."""
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                   for ch in str(record_id or "record"))
    try:
        n = int(seq)
    except (TypeError, ValueError):
        n = 0
    if n < 0:
        n = 0
    return f"anchors/{safe}/{n:08d}-{head_hash or ''}.json"


def _clock(now):
    if now is None:
        return datetime.now(timezone.utc)
    if callable(now):
        return now()
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now


def _iso(when):
    return when.astimezone(timezone.utc).isoformat()


def _parse_iso(value):
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def _parse_gen(value):
    """UTC GeneralizedTime, the form an RFC 3161 token carries."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    body = value[:-1]
    if "." in body:
        whole, frac = body.split(".", 1)
        if not frac.isdigit() or len(frac) > 12:
            return None
    else:
        whole, frac = body, ""
    if len(whole) != 14 or not whole.isdigit():
        return None
    try:
        when = datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if frac:
        when = when.replace(microsecond=int((frac + "000000")[:6]))
    return when


def _present(timestamp):
    return (isinstance(timestamp, dict)
            and timestamp.get("status") == "present"
            and isinstance(timestamp.get("token_b64"), str)
            and timestamp.get("token_b64").strip())


def _connect():
    path = queue_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _lookup_locked(record_id, head_hash):
    try:
        conn = _connect()
    except Exception:
        log.exception("Anchor index could not be opened")
        return None
    try:
        row = conn.execute(
            "SELECT body_json FROM locked WHERE record_id = ? AND head_hash = ?",
            (str(record_id), head_hash)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        return json.loads(row["body_json"])
    except (TypeError, ValueError):
        return None


def _lookup_queue(record_id, head_hash):
    try:
        conn = _connect()
    except Exception:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM queue WHERE record_id = ? AND head_hash = ?",
            (str(record_id), head_hash)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def _enqueue(body_fields):
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO queue (object_key, record_id, seq, head_hash, recorded_at,
                               receipt_json, first_attempt_at, status, token_b64,
                               authority, gen_time)
            VALUES (:object_key, :record_id, :seq, :head_hash, :recorded_at,
                    :receipt_json, :first_attempt_at, :status, :token_b64,
                    :authority, :gen_time)
            ON CONFLICT(object_key) DO UPDATE SET
                status = excluded.status,
                token_b64 = COALESCE(excluded.token_b64, queue.token_b64),
                authority = COALESCE(excluded.authority, queue.authority),
                gen_time = COALESCE(excluded.gen_time, queue.gen_time),
                receipt_json = COALESCE(excluded.receipt_json, queue.receipt_json)
            """,
            body_fields)
        conn.commit()
    finally:
        conn.close()


def _dequeue(key):
    conn = _connect()
    try:
        conn.execute("DELETE FROM queue WHERE object_key = ?", (key,))
        conn.commit()
    finally:
        conn.close()


def _remember(body):
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO locked (object_key, record_id, seq, head_hash, body_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(object_key) DO NOTHING
            """,
            (body["object_key"], str(body["record_id"]), int(body["seq"]),
             body["head_hash"], json.dumps(body, sort_keys=True, separators=(",", ":"))))
        conn.commit()
    finally:
        conn.close()


def anchors_for(record_id):
    """Anchors this process has successfully put. Honest exports include them.

    This is not the deciding set. A deleted index does not delete the
    object. `export` with the read role lists the bucket. Disabled, and
    with no queue file yet, this does not create one.
    """
    if not configured() and not os.path.exists(queue_path()):
        return []
    try:
        conn = _connect()
    except Exception:
        log.exception("Anchor index could not be read")
        return []
    try:
        rows = conn.execute(
            "SELECT body_json FROM locked WHERE record_id = ? ORDER BY seq",
            (str(record_id),)).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        try:
            out.append(json.loads(row["body_json"]))
        except (TypeError, ValueError):
            continue
    return out


def _index_all(record_id=None):
    try:
        conn = _connect()
    except Exception:
        log.exception("Anchor index could not be read")
        return []
    try:
        if record_id is None:
            rows = conn.execute(
                "SELECT body_json FROM locked ORDER BY record_id, seq").fetchall()
        else:
            rows = conn.execute(
                "SELECT body_json FROM locked WHERE record_id = ? ORDER BY seq",
                (str(record_id),)).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        try:
            out.append(json.loads(row["body_json"]))
        except (TypeError, ValueError):
            continue
    return out


def _queue_rows():
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM queue ORDER BY first_attempt_at, object_key").fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


class MemoryLockStore:
    """An in-process bucket that enforces COMPLIANCE retention.

    put and delete of an object whose retain-until is still in the future
    raise ComplianceError. Tests use this so a passing suite does not talk
    to AWS, and so a store that forgot the lock would fail here.
    """

    def __init__(self, now=None):
        self._objects = {}
        self._now = now

    def _current(self):
        return _clock(self._now)

    def put(self, key, body, retain_until):
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        existing = self._objects.get(key)
        if existing and existing["retain_until"] > self._current():
            raise ComplianceError(
                "Object Lock COMPLIANCE refuses to overwrite this object")
        self._objects[key] = {"body": body, "retain_until": retain_until}

    def delete(self, key):
        existing = self._objects.get(key)
        if not existing:
            return
        if existing["retain_until"] > self._current():
            raise ComplianceError(
                "Object Lock COMPLIANCE refuses to delete this object")
        del self._objects[key]

    def get(self, key):
        existing = self._objects.get(key)
        if not existing:
            return None
        return existing["body"]

    def list(self, prefix):
        return sorted(key for key in self._objects if key.startswith(prefix))


class S3LockStore:
    """PutObject with COMPLIANCE retention. Delete is implemented so a test
    double can show the call; the write role's policy does not allow it,
    and the bucket rejects it until retention ends.
    """

    def __init__(self, bucket, client):
        self.bucket = bucket
        self.client = client

    def put(self, key, body, retain_until):
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
        )

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def get(self, key):
        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            response = getattr(exc, "response", None) or {}
            code = (response.get("Error") or {}).get("Code")
            if code in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
        return resp["Body"].read()

    def list(self, prefix):
        keys = []
        token = None
        while True:
            kwargs = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self.client.list_objects_v2(**kwargs)
            for item in resp.get("Contents") or []:
                keys.append(item["Key"])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return keys


def _boto_client(read):
    import boto3
    prefix = "SHIELD_ANCHOR_READ_" if read else "SHIELD_ANCHOR_"
    return boto3.client(
        "s3",
        region_name=config.get("SHIELD_ANCHOR_REGION") or "us-east-1",
        aws_access_key_id=os.environ.get(prefix + "ACCESS_KEY_ID") or None,
        aws_secret_access_key=os.environ.get(prefix + "SECRET_ACCESS_KEY") or None,
        aws_session_token=os.environ.get(prefix + "SESSION_TOKEN") or None,
    )


def write_store():
    if not configured():
        raise AnchorUnavailable("SHIELD_ANCHOR_BUCKET is unset")
    try:
        client = _boto_client(read=False)
    except ImportError as exc:
        raise AnchorUnavailable("boto3 is not installed") from exc
    return S3LockStore(os.environ["SHIELD_ANCHOR_BUCKET"].strip(), client)


def read_store():
    """The auditor's client. The write keys are not used here.

    Listing is what makes a rewrite visible. The application role cannot
    list, on purpose.
    """
    if not configured():
        raise AnchorUnavailable("SHIELD_ANCHOR_BUCKET is unset")
    if not (os.environ.get("SHIELD_ANCHOR_READ_ACCESS_KEY_ID") or "").strip():
        raise AnchorUnavailable("the read role is not configured")
    try:
        client = _boto_client(read=True)
    except ImportError as exc:
        raise AnchorUnavailable("boto3 is not installed") from exc
    return S3LockStore(os.environ["SHIELD_ANCHOR_BUCKET"].strip(), client)


def _resolve_store(store):
    if store is not None:
        return store
    if not configured():
        return None
    return write_store()


def _view(status, record_id, seq, head_hash, key, anchor=None, first=None):
    return {
        "status": status,
        "record_id": str(record_id),
        "seq": int(seq) if seq is not None else 0,
        "head_hash": head_hash,
        "object_key": key,
        "first_attempt_at": first,
        "anchor": anchor,
    }


def _put_body(store, key, body, retain_until):
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        store.put(key, raw, retain_until)
    except ComplianceError:
        current = store.get(key)
        if current == raw:
            return
        raise


def anchor_after_seal(record_id, seq, head_hash, recorded_at, *,
                      receipt=None, timestamp=None, store=None, fetch=None,
                      now=None, first_attempt=None):
    """Lock one sealed head. Never raises. The upload has already succeeded.

    ``store`` is the test double. Production builds an S3 client when the
    bucket is set. ``timestamp`` is a stamp() result already in hand, so a
    batch that just stamped this head does not ask again.
    """
    try:
        return _anchor_after_seal(
            record_id, seq, head_hash, recorded_at, receipt=receipt,
            timestamp=timestamp, store=store, fetch=fetch, now=now,
            first_attempt=first_attempt)
    except Exception:
        log.exception("Anchor lock failed for %s", record_id)
        return _view("anchor_pending", record_id, seq, head_hash,
                     object_key(record_id, seq, head_hash))


def _anchor_after_seal(record_id, seq, head_hash, recorded_at, *,
                       receipt=None, timestamp=None, store=None, fetch=None,
                       now=None, first_attempt=None):
    key = object_key(record_id, seq, head_hash)
    if store is None and not configured():
        return _view("disabled", record_id, seq, head_hash, key)

    held = _lookup_locked(record_id, head_hash)
    if held and held.get("object_key") == key:
        return _view("locked", record_id, held.get("seq", seq), head_hash, key,
                     anchor=held, first=held.get("first_attempt_at"))

    now_dt = _clock(now)
    first_dt = _parse_iso(first_attempt) if isinstance(first_attempt, str) else first_attempt
    if first_dt is None:
        queued = _lookup_queue(record_id, head_hash)
        if queued and queued.get("first_attempt_at"):
            first_dt = _parse_iso(queued["first_attempt_at"])
    if first_dt is None:
        first_dt = now_dt
    first_iso = _iso(first_dt)

    stamped = timestamp
    if stamped is None:
        stamped = tsa.stamp(head_hash, fetch=fetch)
    if not _present(stamped):
        _enqueue({
            "object_key": key,
            "record_id": str(record_id),
            "seq": int(seq),
            "head_hash": head_hash,
            "recorded_at": recorded_at,
            "receipt_json": json.dumps(receipt) if receipt else None,
            "first_attempt_at": first_iso,
            "status": "timestamp_pending",
            "token_b64": None,
            "authority": None,
            "gen_time": None,
        })
        return _view("timestamp_pending", record_id, seq, head_hash, key,
                     first=first_iso)

    delay_ms = int((now_dt - first_dt).total_seconds() * 1000)
    if delay_ms < 0:
        delay_ms = 0
    body = {
        "version": VERSION,
        "record_id": str(record_id),
        "seq": int(seq),
        "head_hash": head_hash,
        "recorded_at": recorded_at,
        "anchored_at": _iso(now_dt),
        "first_attempt_at": first_iso,
        "delay_ms": delay_ms,
        "timestamp_status": "present",
        "token_b64": stamped.get("token_b64"),
        "authority": stamped.get("authority"),
        "gen_time": stamped.get("gen_time"),
        "receipt": receipt,
        "object_key": key,
    }
    try:
        target = _resolve_store(store)
    except AnchorUnavailable as exc:
        log.info("Anchor store unavailable for %s: %s", key, exc)
        target = None
    if target is None:
        _enqueue({
            "object_key": key,
            "record_id": str(record_id),
            "seq": int(seq),
            "head_hash": head_hash,
            "recorded_at": recorded_at,
            "receipt_json": json.dumps(receipt) if receipt else None,
            "first_attempt_at": first_iso,
            "status": "anchor_pending",
            "token_b64": stamped.get("token_b64"),
            "authority": stamped.get("authority"),
            "gen_time": stamped.get("gen_time"),
        })
        return _view("anchor_pending", record_id, seq, head_hash, key,
                     first=first_iso)

    try:
        _put_body(target, key, body, now_dt + timedelta(days=retention_days()))
    except ComplianceError:
        log.info("Anchor %s is already locked", key)
    except Exception as exc:
        log.info("Anchor put failed for %s: %s", key, exc)
        _enqueue({
            "object_key": key,
            "record_id": str(record_id),
            "seq": int(seq),
            "head_hash": head_hash,
            "recorded_at": recorded_at,
            "receipt_json": json.dumps(receipt) if receipt else None,
            "first_attempt_at": first_iso,
            "status": "anchor_pending",
            "token_b64": stamped.get("token_b64"),
            "authority": stamped.get("authority"),
            "gen_time": stamped.get("gen_time"),
        })
        return _view("anchor_pending", record_id, seq, head_hash, key,
                     first=first_iso)

    _remember(body)
    try:
        _dequeue(key)
    except Exception:
        log.exception("Anchor queue row remained after a successful put for %s", key)
    return _view("locked", record_id, seq, head_hash, key, anchor=body,
                 first=first_iso)


def drain(*, store=None, fetch=None, now=None):
    """Stamp what is still timestamp pending, then put what is anchor pending.

    The delay on the object is the time from the first attempt to the put
    that succeeded. A retry that still cannot stamp leaves the row.
    """
    out = []
    for row in _queue_rows():
        timestamp = None
        if row.get("status") == "anchor_pending" and row.get("token_b64"):
            timestamp = {
                "status": "present",
                "forged": False,
                "token_b64": row.get("token_b64"),
                "authority": row.get("authority"),
                "gen_time": row.get("gen_time"),
            }
        receipt = None
        if row.get("receipt_json"):
            try:
                receipt = json.loads(row["receipt_json"])
            except (TypeError, ValueError):
                receipt = None
        out.append(anchor_after_seal(
            row["record_id"], row["seq"], row["head_hash"], row.get("recorded_at"),
            receipt=receipt, timestamp=timestamp, store=store, fetch=fetch,
            now=now, first_attempt=row.get("first_attempt_at")))
    return out


def backfill_record(record_id, entries, *, receipt=None, store=None, fetch=None,
                    now=None, timestamp=None):
    """Anchor the current head of one record, once.

    Historical entries are left alone. A record whose tip is already locked
    is not written again. An empty chain is skipped.
    """
    if not entries:
        return {"status": "skipped", "reason": "empty", "record_id": str(record_id)}
    tip = entries[-1] if isinstance(entries[-1], dict) else None
    if not tip or not tip.get("entry_hash"):
        return {"status": "skipped", "reason": "no head", "record_id": str(record_id)}
    head = tip["entry_hash"]
    seq = len(entries) - 1
    held = _lookup_locked(record_id, head)
    if held:
        return _view("already_locked", record_id, held.get("seq", seq), head,
                     held.get("object_key") or object_key(record_id, seq, head),
                     anchor=held, first=held.get("first_attempt_at"))
    return anchor_after_seal(
        record_id, seq, head, tip.get("recorded_at"), receipt=receipt,
        timestamp=timestamp, store=store, fetch=fetch, now=now)


def backfill_records(records, **kwargs):
    """``records`` is a list of {record_id, entries, receipt?}."""
    out = []
    for item in records or []:
        if not isinstance(item, dict):
            continue
        out.append(backfill_record(
            item.get("record_id"), item.get("entries") or [],
            receipt=item.get("receipt"), **kwargs))
    return out


def status_for(record_id, head_hash):
    """The anchor a retrying phone should store, if this process has one."""
    if not configured() and not os.path.exists(queue_path()):
        return _view("disabled", record_id, 0, head_hash, None)
    held = _lookup_locked(record_id, head_hash)
    if held:
        return _view("locked", record_id, held.get("seq"), head_hash,
                     held.get("object_key"), anchor=held,
                     first=held.get("first_attempt_at"))
    queued = _lookup_queue(record_id, head_hash)
    if queued:
        return _view(queued.get("status") or "anchor_pending", record_id,
                     queued.get("seq"), head_hash, queued.get("object_key"),
                     first=queued.get("first_attempt_at"))
    if not configured():
        return _view("disabled", record_id, 0, head_hash, None)
    return None


def export_anchors(record_id=None, store=None):
    """The set a verifier should be given.

    A read-role store lists the bucket. Without one, the local index is
    returned and the source is ``local-index``. That index is not the
    deciding record: the process that writes it can delete it.
    """
    target = store
    source = "s3"
    if target is None:
        try:
            target = read_store()
        except AnchorUnavailable as exc:
            log.warning("Anchor export is using the local index: %s", exc)
            return _index_all(record_id), "local-index"
    bodies = []
    for key in target.list("anchors/"):
        raw = target.get(key)
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if record_id is not None and str(item.get("record_id")) != str(record_id):
            continue
        bodies.append(item)
    bodies.sort(key=lambda item: (str(item.get("record_id")), int(item.get("seq") or 0)))
    return bodies, source


def combine_anchors(bundled, extra):
    """Union by object key. The first body is kept. A second, different body fails.

    Package anchors are first, then the file passed to the verifier. A phone
    backup that disagrees does not replace the locked body.
    """
    problems = []
    chosen = []
    seen = {}
    for item in list(bundled or []) + list(extra or []):
        if not isinstance(item, dict):
            continue
        key = item.get("object_key") or object_key(
            item.get("record_id"), item.get("seq"), item.get("head_hash"))
        proof = (item.get("record_id"), item.get("seq"), item.get("head_hash"),
                 item.get("token_b64"))
        if key in seen:
            if seen[key] != proof:
                problems.append(PROBLEM_COPY)
            continue
        seen[key] = proof
        chosen.append(item)
    return chosen, problems


def _token_covers(token_b64, head_hash):
    if not isinstance(token_b64, str) or not isinstance(head_hash, str):
        return False
    try:
        expected = bytes.fromhex(head_hash)
    except ValueError:
        return False
    if len(expected) != 32:
        return False
    try:
        raw = base64.b64decode(token_b64)
        parsed = tsa._parse_response(raw)
    except Exception:
        return False
    return (parsed.get("hashed_message") == expected
            and parsed.get("imprint_oid") == tsa.SHA256_OID)


def _time_fits(anchor, entry):
    recorded = _parse_iso(entry.get("recorded_at") if isinstance(entry, dict) else None)
    stamped = _parse_gen(anchor.get("gen_time")) or _parse_iso(anchor.get("anchored_at"))
    if recorded is None or stamped is None:
        return False
    return stamped >= recorded - SKEW


def _locked_rows(anchors):
    rows = []
    for anchor in anchors or []:
        if not isinstance(anchor, dict):
            continue
        if anchor.get("timestamp_status") not in (None, "present"):
            continue
        if not anchor.get("token_b64") or not anchor.get("head_hash"):
            continue
        rows.append(anchor)
    return rows


def assess_anchors(entries, anchors):
    """Problems fail the package. An empty set is the note anchor absent.

    A head the chain claims — the tip, when that tip is an event this
    service locks, or any tip when nothing in the set matches — needs an
    anchor. An anchor whose head is not an entry is a tail that was removed
    or a chain that was rewritten. Entries that were never locked (a
    backfill locks only the tip; a viewed event is not an upload) are not
    required to have one.
    """
    problems = []
    notes = []
    locked = _locked_rows(anchors)
    if not locked:
        notes.append(NOTE_ABSENT)
        return problems, notes
    index_of = {}
    for index, entry in enumerate(entries or []):
        if isinstance(entry, dict) and entry.get("entry_hash"):
            index_of.setdefault(entry["entry_hash"], index)
    missed = False
    matched = 0
    for anchor in locked:
        head = anchor.get("head_hash")
        idx = index_of.get(head)
        seq = anchor.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or idx is None or seq != idx:
            missed = True
            continue
        entry = entries[idx]
        if not _token_covers(anchor.get("token_b64"), head):
            problems.append(PROBLEM_TOKEN)
            continue
        if not _time_fits(anchor, entry):
            problems.append(PROBLEM_TIME)
            continue
        receipt = anchor.get("receipt")
        if isinstance(receipt, dict):
            signed = receipt.get("signed") if isinstance(receipt.get("signed"), dict) else receipt
            claimed = signed.get("head_hash") if isinstance(signed, dict) else None
            if claimed and claimed != head:
                problems.append(PROBLEM_RECEIPT)
                continue
        matched += 1
    if missed:
        problems.append(PROBLEM_MISSING)
    head = None
    head_type = None
    if entries and isinstance(entries[-1], dict):
        head = entries[-1].get("entry_hash")
        head_type = entries[-1].get("event_type")
    covered = any(anchor.get("head_hash") == head for anchor in locked)
    if head and not covered and (head_type in ANCHORED_EVENTS or matched == 0):
        problems.append(PROBLEM_NO_HEAD)
    return problems, notes


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Retry, backfill, or export Shield's server-locked anchors.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("retry", help="Stamp pending heads and write queued anchors")
    back = sub.add_parser(
        "backfill",
        help="Anchor the current head of every record in a JSON file")
    back.add_argument(
        "file",
        help="JSON list of {record_id, entries}. entries are the custody "
             "chain, oldest first. Only the last entry is anchored.")
    exp = sub.add_parser(
        "export",
        help="Write the anchor set a verifier passes as --anchors")
    exp.add_argument("--out", required=True)
    exp.add_argument("--record-id")
    args = parser.parse_args(argv)

    if args.command == "retry":
        results = drain()
        print(json.dumps(results, indent=2))
        return 0
    if args.command == "backfill":
        with open(args.file) as fh:
            records = json.load(fh)
        if isinstance(records, dict):
            records = records.get("records") or []
        results = backfill_records(records)
        print(json.dumps(results, indent=2))
        return 0
    bodies, source = export_anchors(record_id=args.record_id)
    with open(args.out, "w") as fh:
        json.dump({"source": source, "anchors": bodies}, fh, indent=2)
        fh.write("\n")
    print(f"wrote {len(bodies)} anchors from {source} to {args.out}", file=sys.stderr)
    if source != "s3":
        print("This file is the local index, not the bucket listing. "
              "A rewrite that deleted the index and omitted the old object "
              "is not in it. Export with the read role to list S3.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
