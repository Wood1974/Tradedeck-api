"""Shield HTTP API.

The security posture that separates this from the parent implementation:

  NOTHING THE CLIENT SENDS IS TRUSTED AS EVIDENCE.

  The parent's /shield/analyze-photo took comp_url, has_exif, gps_lat, gps_lng
  and original_hash from the request body and never re-read them from the row it
  was about to update. That allowed a contractor to upload a genuine photo, then
  call analyze with a URL pointing at a stock image of perfect work — and the
  'pass' verdict landed on the real photo's row. The client-supplied hash went
  into the custody log as the evidence. The unvalidated fetch was also an SSRF.

  Here, analyze takes a photo_id in the path and nothing else. Every input to
  the model is read from shield_photos, and the signed URL is minted server-side
  from the stored path.
"""
import json
import logging
import time

import requests
import stripe
from flask import Blueprint, g, jsonify, request

import codes
import config
import corroborate
import evidence as evidence_pkg
import integrity
import ledger
import notes as field_notes
import pricing
import protection
import transparency
import verdict as grading
import vision
from auth import require_tenant, require_record, utc_now_iso
import store

log = logging.getLogger(__name__)
bp = Blueprint("shield", __name__, url_prefix="/shield")


# ---------------------------------------------------------------- helpers ---
def _err(msg, code):
    return jsonify({"error": msg}), code


def _bucket():
    return config.get("SHIELD_BUCKET")


def actor_role(record, actor_ref):
    """Who is acting, derived rather than asserted.

    The original hardcoded actor_type="buyer" on the export and close-out
    routes, both of which any participant could call. A contractor closing out
    his own job was recorded in the audit trail as the buyer signing off — an
    evidence system that does not merely fail to detect falsification but
    manufactures it.

    Standalone Shield has no homeowners or contractors — those are TradeDeck
    roles. The parties on a record are opaque refs the tenant supplies:
    buyer_ref (who paid for the seal) and subject_ref (whose work is sealed).
    """
    if not record or not actor_ref:
        return "system"
    if actor_ref == record.get("buyer_ref"):
        return "buyer"
    if actor_ref == record.get("subject_ref"):
        return "subject"
    return "system"


def _actor_ref():
    """Opaque id of the caller inside their tenant."""
    return getattr(g.principal, "actor_id", None)


def _actor_kind():
    """Credential kind for the custody row (api_key | member | system)."""
    kind = getattr(getattr(g, "principal", None), "kind", None)
    return kind if kind in ("api_key", "member") else "system"


def client_ip():
    """Uploader IP, taken from the RIGHTMOST proxy hop.

    The leftmost X-Forwarded-For entry is whatever the client sent, so reading
    it stored an attacker-chosen value and salted it carefully. Render puts
    exactly one trusted proxy in front, so the rightmost entry is the one it
    observed.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[-1].strip()
    return request.remote_addr or ""


def log_custody(*, photo_id=None, shield_job_id=None, event_type, actor_id=None,
                actor_type="system", event_data=None, gps_lat=None, gps_lng=None,
                file_hash=None, integrity_note=None, exif_captured_at=None):
    """Append a hash-linked entry to the chain of custody.

    The chain still seals `shield_job_id` / `actor_id` / `actor_type` — those
    are the signed field names in SPEC.md and the independent verifier. The
    standalone schema columns are `record_id` / `actor_ref` / `actor_kind`;
    we map at the boundary so a chain written here verifies with the same
    tools a TradeDeck-era package uses.
    """
    entry = {
        "photo_id": photo_id, "shield_job_id": shield_job_id,
        "event_type": event_type, "actor_id": actor_id, "actor_type": actor_type,
        "event_data": event_data or {},
        "gps_lat": gps_lat, "gps_lng": gps_lng, "file_hash": file_hash,
        "integrity_note": integrity_note, "exif_captured_at": exif_captured_at,
        "recorded_at": utc_now_iso(),
    }
    prev = _chain_head(shield_job_id)
    sealed = ledger.seal(entry, prev)
    event_data_json = json.dumps(entry["event_data"], sort_keys=True,
                                 separators=(",", ":"), default=str)
    row = {
        "tenant_id": getattr(g, "tenant_id", None),
        "record_id": sealed["shield_job_id"],
        "photo_id": sealed.get("photo_id"),
        "event_type": sealed["event_type"],
        "actor_ref": sealed.get("actor_id"),
        "actor_kind": _actor_kind() if actor_type != "system" else "system",
        "event_data": event_data_json,
        "gps_lat": sealed.get("gps_lat"),
        "gps_lng": sealed.get("gps_lng"),
        "file_hash": sealed.get("file_hash"),
        "integrity_note": sealed.get("integrity_note"),
        "exif_captured_at": sealed.get("exif_captured_at"),
        "recorded_at": sealed["recorded_at"],
        "prev_hash": sealed["prev_hash"],
        "entry_hash": sealed["entry_hash"],
        "chain_version": sealed.get("chain_version", ledger.CHAIN_VERSION),
    }
    # Drop tenant_id when the webhook fires without a principal (system events
    # still carry the record's own tenant via a lookup below if missing).
    if not row["tenant_id"] and shield_job_id:
        try:
            rec = (store.table("records").select("tenant_id")
                   .eq("id", shield_job_id).limit(1).execute().data or [None])[0]
            if rec:
                row["tenant_id"] = rec["tenant_id"]
        except Exception:
            pass
    store.table("custody_log").insert(row).execute()
    return sealed["entry_hash"]


def _chain_head(shield_job_id):
    """Hash of the most recent custody entry for a job, or its genesis."""
    if not shield_job_id:
        return ledger.genesis_hash("unscoped")
    res = (store.table("custody_log").select("entry_hash")
           .eq("record_id", shield_job_id)
           .order("recorded_at", desc=True).limit(1).execute())
    if res.data and res.data[0].get("entry_hash"):
        return res.data[0]["entry_hash"]
    return ledger.genesis_hash(shield_job_id)


def _custody_for_verify(record_id):
    """Load custody rows remapped into the signed field names the verifier expects."""
    rows = (store.table("custody_log").select("*")
            .eq("record_id", record_id)
            .order("recorded_at").execute().data or [])
    out = []
    for r in rows:
        out.append({
            "shield_job_id": r.get("record_id"),
            "photo_id": r.get("photo_id"),
            "event_type": r.get("event_type"),
            "actor_id": r.get("actor_ref"),
            "actor_type": (r.get("event_data") or {}).get("actor_role")
                          if isinstance(r.get("event_data"), dict)
                          else None,
            "event_data": r.get("event_data"),
            "gps_lat": r.get("gps_lat"),
            "gps_lng": r.get("gps_lng"),
            "file_hash": r.get("file_hash"),
            "integrity_note": r.get("integrity_note"),
            "exif_captured_at": r.get("exif_captured_at"),
            "recorded_at": r.get("recorded_at"),
            "prev_hash": r.get("prev_hash"),
            "entry_hash": r.get("entry_hash"),
            "chain_version": r.get("chain_version"),
        })
        # event_data may arrive as a JSON string from PostgREST
        ed = out[-1]["event_data"]
        if isinstance(ed, str):
            try:
                out[-1]["event_data"] = json.loads(ed)
            except Exception:
                pass
        if out[-1]["actor_type"] is None:
            # Fall back: sealed actor_type is not a DB column; recover from
            # event_data.actor_role when present, else leave unset (unsigned).
            ed = out[-1].get("event_data") or {}
            if isinstance(ed, dict) and ed.get("actor_role"):
                out[-1]["actor_type"] = ed["actor_role"]
    return out


def try_log_custody(**kwargs):
    """Custody write for non-evidentiary events, where failing the whole
    request would be worse than a gap. Logged loudly either way."""
    try:
        return log_custody(**kwargs)
    except Exception:
        log.error("CUSTODY WRITE FAILED event=%s job=%s — an action occurred "
                  "without an audit record", kwargs.get("event_type"),
                  kwargs.get("shield_job_id"), exc_info=True)
        return None


def _discard_storage(*paths):
    """Best-effort cleanup after a write that did not complete."""
    for path in paths:
        if not path:
            continue
        try:
            store.storage().from_(_bucket()).remove([path])
        except Exception:
            log.warning("Orphaned storage object %s", path)


def _is_unique_violation(exc) -> bool:
    """Postgres 23505, as it reaches us through PostgREST."""
    t = str(exc).lower()
    return "23505" in t or "duplicate key" in t or "already exists" in t


def _signed_url(path, ttl=None):
    res = store.storage().from_(_bucket()).create_signed_url(
        path=path, expires_in=ttl or config.get_int("SIGNED_URL_TTL"))
    return res.get("signedURL") or res.get("signedUrl")


# ------------------------------------------------------------- quote / buy ---
# ----------------------------------------------------------------- public ---
# The only routes in this service that do not require a bearer token. Both are
# read-only, aggregate, and deliberately reachable by someone who has never
# bought anything — a commitment nobody outside can check is on the honour
# system, and both of these exist to be checked.

_PUBLIC_TTL = 900          # seconds; see the note on staleness below
_results_cache = {"at": 0.0, "payload": None}


def _public(payload, *, max_age):
    """Serve an anonymous payload, overriding the global no-store default.

    `harden()` sets Cache-Control: no-store with setdefault, which is right for
    every authenticated route in this file and wrong for these two: they carry
    nothing user-specific and being cached by an intermediary is a feature.
    """
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = f"public, max-age={max_age}"
    return resp


@bp.route("/public/pricing", methods=["GET"])
def public_pricing():
    """The complete price list. No auth, no arguments, no negotiation.

    Every price this service can charge is here. `pricing.quote()` takes a job
    budget and nothing else, so there is no input through which a fee could
    vary with what a record says — which is the part of INDEPENDENCE.md
    commitment 1 that a stranger can verify for themselves.
    """
    return _public(pricing.public_price_list(), max_age=3600)


@bp.route("/public/results", methods=["GET"])
def public_results():
    """Aggregate outcomes, including the unflattering ones.

    Cached in-process for fifteen minutes. That is a load control on an
    unauthenticated endpoint that reads three tables, not a freshness
    guarantee: each gunicorn worker holds its own copy, so two requests can
    legitimately differ by one close-out. The payload's `generated_at` says
    which moment the numbers describe.

    Selection is column-minimal and unfiltered — no `.eq()`, no date window.
    A filter here is how a report starts flattering its author, so the absence
    of one is the point, and `transparency.METHOD` states it in the payload.
    """
    now = time.time()
    if _results_cache["payload"] and now - _results_cache["at"] < _PUBLIC_TTL:
        return _public(_results_cache["payload"], max_age=_PUBLIC_TTL)

    try:
        reports = (store.table("completion_reports")
                   .select("overall_verdict").execute().data or [])
        photos = (store.table("photos")
                  .select("verdict,has_exif,superseded_by,superseded_at")
                  .execute().data or [])
        events = (store.table("custody_log")
                  .select("event_type").execute().data or [])
    except Exception:
        log.exception("Public results query failed")
        # Serving a stale report beats serving nothing; serving a zeroed one
        # would be a false statement about our outcomes.
        if _results_cache["payload"]:
            return _public(_results_cache["payload"], max_age=60)
        return _err("Outcome report temporarily unavailable", 503)

    payload = transparency.report(reports, photos, events)
    _results_cache.update(at=now, payload=payload)
    return _public(payload, max_age=_PUBLIC_TTL)


@bp.route("/quote", methods=["POST"])
@require_tenant
def quote():
    """What Shield costs for a job of this size. Advisory; the charge is
    recomputed server-side at purchase and this value is never trusted back."""
    data = request.get_json(silent=True) or {}
    tier, price = pricing.quote(data.get("job_budget_cents"))
    return jsonify({"tier": tier, "price_cents": price})


@bp.route("/jobs", methods=["POST"])
@require_tenant
def create_job():
    """Create a pending Shield job and its PaymentIntent.

    The price comes from pricing.quote() against the job budget. Any
    amount_cents in the body is ignored outright.
    """
    data = request.get_json(silent=True) or {}
    # Opaque party refs supplied by the tenant. Shield does not resolve them.
    buyer_ref = data.get("buyer_ref") or _actor_ref()
    subject_ref = data.get("subject_ref") or data.get("contractor_id")
    description = (data.get("job_description") or "").strip()
    if not description:
        return _err("job_description required", 400)
    external_ref = data.get("external_ref")
    if not external_ref:
        return _err("external_ref required — your own id for this body of work", 400)

    # A party sealing their own work is not an independent record.
    if subject_ref and subject_ref == buyer_ref:
        return _err("subject_ref must differ from buyer_ref — a Shield record "
                    "of your own work is not an independent record.", 400)

    # The site location is what every later geofence is measured against. It is
    # set here, by the buyer, before any photo exists — so it is not something
    # the party being audited can move to fit a photograph.
    site_lat, site_lng = data.get("site_lat"), data.get("site_lng")
    if site_lat is not None or site_lng is not None:
        try:
            site_lat, site_lng = float(site_lat), float(site_lng)
        except (TypeError, ValueError):
            return _err("site_lat and site_lng must both be numbers", 400)
        if not (-90 <= site_lat <= 90 and -180 <= site_lng <= 180):
            return _err("site_lat/site_lng out of range", 400)

    tier, price_cents = pricing.quote(data.get("job_budget_cents"))
    trade = codes.detect_trade(description)

    try:
        job = store.table("records").insert({
            "tenant_id":        g.tenant_id,
            "external_ref":     external_ref,
            "buyer_ref":        str(buyer_ref) if buyer_ref else None,
            "subject_ref":      str(subject_ref) if subject_ref else None,
            "trade":            trade,
            "amount_cents":     price_cents,
            "job_budget_cents": data.get("job_budget_cents"),
            "site_address":     data.get("site_address"),
            "site_lat":         site_lat,
            "site_lng":         site_lng,
            "site_radius_m":    int(data.get("site_radius_m") or 250),
            "status":           "pending",
        }).execute().data[0]
    except Exception:
        log.exception("Could not create shield record")
        return _err("Could not create Shield record", 500)

    try:
        intent = stripe.PaymentIntent.create(
            amount=price_cents, currency="usd",
            metadata={"shield_job_id": job["id"], "product": "shield_per_job",
                      "tier": tier, "tenant_id": g.tenant_id},
            description=f"TradeDeck Shield ({tier}) — record {job['id']}",
            idempotency_key=f"shield-pi-{job['id']}",
        )
    except stripe.StripeError:
        log.exception("Stripe PaymentIntent failed for shield record %s", job["id"])
        return _err("Payment setup failed", 502)

    store.table("records").update({"stripe_payment_intent_id": intent.id}) \
        .eq("id", job["id"]).execute()

    try_log_custody(shield_job_id=job["id"], event_type="created",
                    actor_id=_actor_ref(), actor_type="buyer",
                    event_data={"tier": tier, "price_cents": price_cents,
                                "trade": trade, "actor_role": "buyer",
                                "has_site_location": site_lat is not None,
                                "site_radius_m": job.get("site_radius_m")})

    return jsonify({"shield_job_id": job["id"], "record_id": job["id"],
                    "tier": tier, "price_cents": price_cents, "trade": trade,
                    "site_geofenced": site_lat is not None,
                    "client_secret": intent.client_secret}), 201


# ------------------------------------------------------------- checkpoints ---
@bp.route("/jobs/<shield_job_id>/checkpoints", methods=["POST"])
@require_tenant
@require_record(param="shield_job_id")
def generate_checkpoints(shield_job_id):
    """Define the checkpoint schedule. Homeowner only, and once.

    Two properties this route exists to guarantee, both absent before:

    The party being audited does not write the audit criteria. `role=None`
    let the contractor generate the checkpoints from a job description he
    controlled, which also drove which code sections got cited.

    The schedule is a commitment made BEFORE the work. The upsert had no
    status guard and reset `status` to pending without touching any existing
    verdict, so a contractor could photograph whatever was actually built,
    read the verdicts, then rewrite the requirements to match — and the sealed
    close-out packet would assert that the photos satisfied requirements
    written after the photos were graded. A record where the criteria can
    follow the evidence is worth nothing in a dispute; locking is the whole
    point of the product.
    """
    if g.record.get("status") != "active":
        return _err("Shield job is not active — payment must clear first", 409)

    if g.record.get("checkpoints_locked_at"):
        return _err("The checkpoint schedule for this job is locked. It was "
                    "fixed before work began and cannot be changed — that is "
                    "what makes the record defensible.", 409)

    description = (request.get_json(silent=True) or {}).get("job_description", "")
    if not description.strip():
        return _err("job_description required", 400)

    try:
        points = vision.generate_checkpoints(description)
    except Exception:
        log.exception("Checkpoint generation failed for %s", shield_job_id)
        return _err("Checkpoint generation failed", 502)

    trade = g.record.get("trade") or codes.detect_trade(description)
    # Only the buyer locks the schedule — the party being audited does not
    # write the audit criteria.
    if g.record.get("buyer_ref") and _actor_ref() != g.record.get("buyer_ref"):
        if g.principal.is_member and g.principal.role == "owner":
            pass  # tenant owner may act for the buyer
        elif g.principal.is_api_key:
            pass  # API caller is the tenant itself
        else:
            return _err("Only the buyer can lock the checkpoint schedule", 403)

    rows = []
    for p in points:
        entry = codes.code_entry(trade, p["point_number"])
        code_ref = entry.get("irc") or entry.get("ibc")
        rows.append({
            "tenant_id":         g.tenant_id,
            "record_id":         shield_job_id,
            "point_number":      p["point_number"],
            "label":             p["label"],
            "description":       p["description"],
            "code_reference":    code_ref,
            "must_show":         entry.get("must_show") or entry.get("photo_instruction"),
            "status":            "pending",
        })
    try:
        saved = store.table("checkpoints").insert(rows).execute().data
        locked_at = utc_now_iso()
        store.table("records").update({"checkpoints_locked_at": locked_at}) \
            .eq("id", shield_job_id).is_("checkpoints_locked_at", "null").execute()
    except Exception:
        log.exception("Could not persist checkpoints for %s", shield_job_id)
        return _err("Could not save checkpoints", 500)

    try_log_custody(
        shield_job_id=shield_job_id, event_type="checkpoints_locked",
        actor_id=_actor_ref(), actor_type="buyer",
        event_data={"trade": trade, "locked_at": locked_at, "actor_role": "buyer",
                    "schedule_sha256": integrity.sha256(json.dumps(
                        [{k: r.get(k) for k in
                          ("point_number", "label", "description",
                           "code_reference", "must_show")} for r in rows],
                        sort_keys=True, separators=(",", ":")).encode())})

    return jsonify({"trade": trade, "locked_at": locked_at,
                    "points": saved or rows})


@bp.route("/jobs/<shield_job_id>/checkpoints", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def list_checkpoints(shield_job_id):
    res = (store.table("checkpoints")
           .select("*").eq("record_id", shield_job_id)
           .order("point_number").execute())
    return jsonify({"points": res.data or []})


# ------------------------------------------------------------------ upload ---
@bp.route("/jobs/<shield_job_id>/photos", methods=["POST"])
@require_tenant
@require_record(param="shield_job_id")
def upload_photo(shield_job_id):
    """The integrity anchor. multipart/form-data: file, point_id, gps_lat, gps_lng.

    Order is load-bearing and must not be rearranged:
      1. validate    2. read raw bytes    3. SHA-256 over those bytes
      4. server-side EXIF   5. store the original, unmodified, no-overwrite
      6. store a stripped copy for the model   7. row   8. custody event
    """
    if g.record.get("status") != "active":
        return _err("Shield job is not active — payment must clear first", 409)
    if not g.record.get("checkpoints_locked_at"):
        return _err("The checkpoint schedule has not been set. The buyer "
                    "defines it before work begins.", 409)
    # Uploads are the subject's job. An API key is the tenant acting for them.
    if (g.record.get("subject_ref") and g.principal.is_member
            and _actor_ref() != g.record.get("subject_ref")
            and g.principal.role != "owner"):
        return _err("Only the assigned subject can upload photos", 403)

    point_id = (request.form.get("point_id") or "").strip()
    if not point_id:
        return _err("point_id required", 400)

    # The checkpoint must belong to THIS job. Without this scoping a contractor
    # could upload against a checkpoint UUID from a job he has no relationship
    # with; analyse would then judge against that job's requirement and write
    # status='approved' onto its checkpoint row, so its homeowner would see an
    # approved checkpoint nobody on that job produced.
    point = (store.table("checkpoints").select("id, point_number, label")
             .eq("id", point_id).eq("record_id", shield_job_id)
             .limit(1).execute().data or [])
    if not point:
        return _err("point_id is not a checkpoint of this Shield job", 400)

    if "file" not in request.files:
        return _err('No file. Send multipart/form-data with field name "file".', 400)

    try:
        gps_lat = float(request.form["gps_lat"])
        gps_lng = float(request.form["gps_lng"])
    except (KeyError, ValueError):
        return _err("gps_lat and gps_lng are required and must be numeric. Shield "
                    "photos need device location — grant location permission.", 400)
    try:
        gps_accuracy = float(request.form.get("gps_accuracy_m", "") or 0) or None
    except ValueError:
        gps_accuracy = None

    upload = request.files["file"]
    raw = upload.read()
    if not raw:
        return _err("Empty file", 400)
    if len(raw) > config.get_int("MAX_UPLOAD_BYTES"):
        return _err(f"File exceeds {config.get_int('MAX_UPLOAD_BYTES') // (1024*1024)} MB", 413)

    # The type is whatever the container says it is. Content-Type is written by
    # the uploader; believing it meant arbitrary bytes could be hashed, stored
    # and passed downstream as a photograph.
    declared = integrity.normalize_mime(upload.content_type)
    mime = integrity.sniff_mime(raw)
    if mime is None or mime not in integrity.ALLOWED_MIME:
        return _err("This file is not a recognised photo. Shield accepts "
                    f'{", ".join(sorted(integrity.ALLOWED_MIME))}, identified by '
                    "the file's own contents rather than its declared type.", 415)

    # Dimensions come from the header; nothing is decoded yet. A 77 KB PNG
    # declaring a 9000x9000 canvas cost 309 MB of RSS before this check, and
    # MAX_CONTENT_LENGTH — a byte limit — never saw it coming.
    probed = integrity.probe(raw)
    if not probed["ok"]:
        if probed["reason"] == "oversize":
            return _err(f"Image is {probed['pixels'] / 1e6:,.0f} megapixels; the "
                        f"limit is {integrity.MAX_PIXELS // 1_000_000}. Send the "
                        "camera's own photo rather than an upscaled copy.", 413)
        return _err("This file declares an image type but cannot be read as one.",
                    415)

    # (3) the anchor — before anything touches the bytes
    original_hash = integrity.sha256(raw)
    received_at   = utc_now_iso()

    # (4) provenance from the original bytes
    assessment = integrity.assess(raw, mime, gps_lat, gps_lng,
                                  config.get_int("GPS_TOLERANCE_M"))
    exif = assessment["exif"]

    if declared != mime and declared not in ("application/octet-stream", ""):
        assessment["integrity_note"] = " ".join(filter(None, [
            assessment.get("integrity_note"),
            f'Declared as "{declared}" but the file is {mime}.']))

    # (4b) Geofence against the JOB SITE — the one reference point the
    # contractor does not supply. Comparing EXIF GPS against the coordinates
    # posted with the upload compared two values the same party controls and
    # called agreement "corroborated"; it could not fail for anyone willing to
    # write EXIF, which takes a dozen lines with the library used to read it.
    site_lat, site_lng = g.record.get("site_lat"), g.record.get("site_lng")
    site_distance = integrity.haversine_m(site_lat, site_lng, gps_lat, gps_lng)
    site_radius = g.record.get("site_radius_m") or 250
    off_site = site_distance is not None and site_distance > site_radius
    if off_site:
        assessment["integrity_note"] = " ".join(filter(None, [
            assessment.get("integrity_note"),
            f"Reported position is {site_distance:,.0f} m from the job site "
            f"(allowed radius {site_radius} m)."]))

    ext = {"image/jpeg": "jpg", "image/png": "png", "image/heic": "heic",
           "image/heif": "heif", "image/webp": "webp"}.get(mime, "bin")
    import uuid
    photo_id  = str(uuid.uuid4())
    orig_path = f"{g.tenant_id}/{shield_job_id}/orig/{photo_id}.{ext}"
    comp_path = f"{g.tenant_id}/{shield_job_id}/comp/{photo_id}.jpg"

    # (5) original, unmodified, never overwritten
    try:
        store.storage().from_(_bucket()).upload(
            path=orig_path, file=raw,
            file_options={"content-type": mime, "cache-control": "no-cache",
                          "x-upsert": "false"})
    except Exception:
        log.exception("Original storage write failed for %s", photo_id)
        return _err("Could not store photo. Nothing was saved — please retry.", 500)

    # (6) stripped, downscaled copy — the only thing the model ever sees.
    # There is no fallback to the original: a file we cannot re-encode gets no
    # analysable copy at all, and the checkpoint stays ungraded. Returning the
    # raw bytes here used to hand the model the untouched original, EXIF and
    # all, under a path labelled .jpg.
    compressed, compress_failure = integrity.compress_for_model(raw)
    if compressed is None:
        log.warning("No analysable copy for %s (%s)", photo_id, compress_failure)
        comp_path = None
        assessment["integrity_note"] = " ".join(filter(None, [
            assessment.get("integrity_note"),
            "This file could not be re-encoded for analysis, so it cannot be "
            "graded. It remains sealed and hashed in the record."]))
    else:
        try:
            store.storage().from_(_bucket()).upload(
                path=comp_path, file=compressed,
                file_options={"content-type": "image/jpeg", "cache-control": "no-cache",
                              "x-upsert": "false"})
        except Exception:
            log.exception("Compressed copy failed for %s", photo_id)
            comp_path = None

    # (6b) Retakes. One live photo per checkpoint is a unique index, so the
    # prior one must leave it before this row can be inserted — and it leaves
    # by being marked superseded, never by being deleted. superseded_at goes
    # first because superseded_by is a foreign key to a row that does not exist
    # yet; it is backfilled below.
    prior = grading.live_photo_for(point_id, (
        store.table("photos")
        .select("id, checkpoint_id, uploaded_at, superseded_by, superseded_at")
        .eq("record_id", shield_job_id).eq("checkpoint_id", point_id)
        .execute().data or []))
    superseded_at = utc_now_iso()
    if prior:
        try:
            store.table("photos").update({"superseded_at": superseded_at}) \
                .eq("id", prior["id"]).is_("superseded_at", "null").execute()
        except Exception:
            log.exception("Could not supersede %s", prior["id"])
            _discard_storage(orig_path, comp_path)
            return _err("Could not record this retake. Nothing was saved — "
                        "please retry.", 500)

    row = {
        "id": photo_id,
        "tenant_id": g.tenant_id,
        "record_id": shield_job_id,
        "checkpoint_id": point_id,
        "uploaded_by_ref": str(_actor_ref()) if _actor_ref() else None,
        "original_hash": original_hash,
        "original_hash_algo": "SHA-256",
        "original_size_bytes": len(raw),
        "storage_path": orig_path,
        "compressed_path": comp_path,
        "gps_lat": gps_lat, "gps_lng": gps_lng, "gps_accuracy_m": gps_accuracy,
        "exif_gps_lat": exif.get("gps_lat"), "exif_gps_lng": exif.get("gps_lng"),
        "exif_captured_at": exif.get("captured_at"),
        "exif_device_make": exif.get("device_make"),
        "exif_device_model": exif.get("device_model"),
        "exif_software": exif.get("software"),
        "exif_raw": exif.get("exif_raw") or {},
        "has_exif": assessment["has_exif"],
        "received_at": received_at,
        "uploaded_at": received_at,
        "upload_user_agent": request.headers.get("User-Agent", ""),
        "upload_ip_hash": integrity.hash_ip(client_ip(), config.get("IP_HASH_SALT")),
        "site_distance_m": round(site_distance, 1) if site_distance is not None else None,
        # Aliases grading / evidence still understand
        "point_id": point_id,
        "ai_verdict": None,
    }
    try:
        store.table("photos").insert(row).execute()
    except Exception as exc:
        log.exception("Row insert failed for %s — rolling back", photo_id)
        _discard_storage(orig_path, comp_path)
        if prior:
            # Put the checkpoint back the way we found it rather than leaving
            # it with no live photo.
            try:
                store.table("photos").update({"superseded_at": None}) \
                    .eq("id", prior["id"]).eq("superseded_at", superseded_at).execute()
            except Exception:
                log.exception("Could not restore %s after a failed retake", prior["id"])
        if _is_unique_violation(exc):
            # Same bytes twice on one job, or a concurrent upload to the same
            # checkpoint. Both are conflicts the caller can act on, not the
            # 500 + "please retry" they used to get, which never succeeded.
            return _err("This photo is already in the record for this job, or "
                        "another upload to the same checkpoint is in flight. "
                        "Reload the checkpoint before retrying.", 409)
        return _err("Could not record photo. Nothing was saved — please retry.", 500)

    if prior:
        try:
            store.table("photos").update(
                {"superseded_by": photo_id}
            ).eq("id", prior["id"]).execute()
        except Exception:
            # The timestamp already took it out of the live set, so selection
            # is correct either way; only the pointer is missing.
            log.exception("Could not link %s to its replacement %s",
                          prior["id"], photo_id)
    log_custody(photo_id=photo_id, shield_job_id=shield_job_id, event_type="uploaded",
                actor_id=_actor_ref(), actor_type="subject", file_hash=original_hash,
                integrity_note=assessment["integrity_note"],
                exif_captured_at=exif.get("captured_at"),
                gps_lat=exif.get("gps_lat") or gps_lat,
                gps_lng=exif.get("gps_lng") or gps_lng,
                event_data={"original_path": orig_path, "compressed_path": comp_path,
                            "original_bytes": len(raw), "compressed_bytes": len(compressed),
                            "exif_status": assessment["exif_status"],
                            "gps_distance_m": assessment["gps_distance_m"],
                            "gps_self_consistent": assessment["gps_self_consistent"],
                            "content_type": mime})
    if prior:
        log_custody(photo_id=prior["id"], shield_job_id=shield_job_id,
                    event_type="superseded", actor_id=_actor_ref(),
                    actor_type="subject",
                    integrity_note="Replaced by a later photo of the same "
                                   "checkpoint. Retained and disclosed in the "
                                   "evidence export.",
                    event_data={"superseded_by": photo_id,
                                "point_id": point_id})

    # Every condition that writes an integrity note also raises the flag event.
    # These had drifted apart: a photo reported 3,400 km outside the buyer's own
    # geofence — the strongest signal here, and the only one the contractor does
    # not control — wrote a note on the upload event and no flag at all, so
    # nothing scanning the chain for integrity_flag would ever see it.
    flags = {
        "gps_mismatch": assessment["gps_mismatch"],
        "exif_absent": assessment["exif_status"] == "absent",
        "off_site": bool(off_site),
        "not_analysable": comp_path is None,
        "declared_type_mismatch": declared != mime and declared not in
                                  ("application/octet-stream", ""),
    }
    if any(flags.values()):
        log_custody(photo_id=photo_id, shield_job_id=shield_job_id,
                    event_type="integrity_flag", actor_type="system",
                    file_hash=original_hash, integrity_note=assessment["integrity_note"],
                    event_data={"exif_status": assessment["exif_status"],
                                "site_distance_m": (round(site_distance, 1)
                                                    if site_distance is not None else None),
                                **{k: v for k, v in flags.items() if v}})

    return jsonify({
        "photo_id": photo_id, "original_hash": original_hash,
        "content_type": mime,
        "analysable": comp_path is not None,
        "supersedes": prior["id"] if prior else None,
        "exif_status": assessment["exif_status"],
        "gps_self_consistent": assessment["gps_self_consistent"],
        "gps_distance_m": assessment["gps_distance_m"],
        "integrity_note": assessment["integrity_note"],
        "device": " ".join(filter(None, [exif.get("device_make"),
                                         exif.get("device_model")])) or None,
        "captured_at": exif.get("captured_at"),
    }), 201


# ----------------------------------------------------------------- analyze ---
@bp.route("/photos/<photo_id>/analyze", methods=["POST"])
@require_tenant
def analyze_photo(photo_id):
    """Adjudicate a stored photo. Takes the id and nothing else.

    Every value handed to the model is read from the database here. There is no
    request body, so there is nothing for a caller to substitute.
    """
    import tenancy
    res = (tenancy.scope(
        store.table("photos").select("*").eq("id", photo_id), g.principal
    ).limit(1).execute())
    if not res.data:
        return _err("Photo not found", 404)
    photo = res.data[0]

    existing = photo.get("verdict") or photo.get("ai_verdict")
    if existing:
        return jsonify({"verdict": existing,
                        "confidence": photo.get("verdict_confidence")
                                      or photo.get("ai_confidence"),
                        "notes": photo.get("verdict_notes") or photo.get("ai_notes"),
                        "already_analyzed": True})

    compressed = photo.get("compressed_path") or photo.get("compressed_storage_path")
    if not compressed:
        return _err("No analysable copy of this photo exists", 409)

    checkpoint_id = photo.get("checkpoint_id") or photo.get("point_id")
    pt = (store.table("checkpoints").select("*")
          .eq("id", checkpoint_id).limit(1).execute().data or [{}])[0]

    # Fetch the compressed copy from a URL we mint ourselves from the stored
    # path. The caller cannot influence what is fetched.
    try:
        img = requests.get(_signed_url(compressed), timeout=20)
        img.raise_for_status()
    except Exception:
        log.exception("Could not retrieve compressed copy for %s", photo_id)
        return _err("Could not retrieve photo for analysis", 502)

    dist = integrity.haversine_m(photo.get("exif_gps_lat"), photo.get("exif_gps_lng"),
                                 photo.get("gps_lat"), photo.get("gps_lng"))
    if dist is None:
        gps_summary = (f"{photo.get('gps_lat')}, {photo.get('gps_lng')} as reported by "
                       "the uploading device. No EXIF GPS, so this is uncorroborated.")
    elif dist <= config.get_int("GPS_TOLERANCE_M"):
        gps_summary = (f"{photo.get('gps_lat')}, {photo.get('gps_lng')} — camera EXIF "
                       f"GPS independently agrees to within {dist:,.0f} m.")
    else:
        gps_summary = (f"MISMATCH: device reported {photo.get('gps_lat')}, "
                       f"{photo.get('gps_lng')} but camera EXIF places the photo "
                       f"{dist:,.0f} m away. Treat location as unreliable.")

    if photo.get("has_exif"):
        provenance = " ".join(filter(None, [
            photo.get("exif_device_make"), photo.get("exif_device_model")])) or "present"
        if photo.get("exif_captured_at"):
            provenance += f", captured {photo['exif_captured_at']}"
        if photo.get("exif_software"):
            provenance += f", software: {photo['exif_software']}"
    else:
        provenance = ("No camera metadata recoverable from the stored original. "
                      "This is consistent with a screenshot or re-saved image, though "
                      "some platforms strip metadata on transfer.")

    try:
        result = vision.analyze_photo(
            img.content,
            point_label=pt.get("label", "Checkpoint"),
            point_description=pt.get("description", ""),
            code_reference=pt.get("code_reference") or pt.get("irc_code") or pt.get("ibc_code"),
            must_show=pt.get("must_show"),
            gps_summary=gps_summary, provenance_summary=provenance)
    except Exception:
        log.exception("Vision analysis failed for %s", photo_id)
        return _err("Analysis failed", 502)

    comp_hash = integrity.sha256(img.content)
    # Conditional write: only lands if the row still has no verdict. The
    # previous check-then-act let twenty concurrent calls all pass the guard,
    # all bill a vision request, and the last writer win — twenty independent
    # samples with the outcome chosen by scheduler jitter.
    written = store.table("photos").update({
        "verdict": result["verdict"],
        "verdict_confidence": result["confidence"],
        "verdict_notes": result["notes"],
        "ai_model": config.get("ANTHROPIC_MODEL"),
        "code_reference": pt.get("code_reference") or pt.get("irc_code"),
    }).eq("id", photo_id).is_("verdict", "null").execute()

    if not written.data:
        current = (store.table("photos").select("verdict, verdict_confidence, verdict_notes")
                   .eq("id", photo_id).limit(1).execute().data or [{}])[0]
        return jsonify({**current, "already_analyzed": True,
                        "note": "A concurrent request recorded the verdict first."})

    store.table("checkpoints").update({
        "status": "approved" if result["verdict"] == "pass" else "flagged"
    }).eq("id", checkpoint_id).execute()

    log_custody(photo_id=photo_id,
                shield_job_id=photo.get("record_id") or photo.get("shield_job_id"),
                event_type="analyzed", actor_id=_actor_ref(), actor_type="system",
                file_hash=photo["original_hash"],   # the stored anchor, not a claim
                integrity_note=None if result["authentic"] else result["authenticity_note"],
                event_data={"verdict": result["verdict"],
                            "confidence": result["confidence"],
                            "authentic": result["authentic"],
                            "findings": result["findings"],
                            "required_action": result["required_action"],
                            "model": config.get("ANTHROPIC_MODEL"),
                            "analysed_copy_hash": comp_hash})
    # 'flag' is in this tuple — the parent checked for 'flagged', which the model
    # never returns, so flagged photos never wrote their flag event.
    if result["verdict"] in ("flag", "fail", "fake"):
        log_custody(photo_id=photo_id,
                    shield_job_id=photo.get("record_id") or photo.get("shield_job_id"),
                    event_type="integrity_flag", actor_type="system",
                    file_hash=photo["original_hash"],
                    integrity_note=result["authenticity_note"] or result["notes"],
                    event_data={"verdict": result["verdict"]})

    return jsonify(result)


# ------------------------------------------------------- custody / reports ---
@bp.route("/jobs/<shield_job_id>/custody", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def custody(shield_job_id):
    """The audit trail, oldest first. This is the deliverable clients pay for."""
    entries = _custody_for_verify(shield_job_id)
    try_log_custody(shield_job_id=shield_job_id, event_type="viewed",
                    actor_id=_actor_ref(),
                    actor_type=actor_role(g.record, _actor_ref()),
                    event_data={"view": "custody",
                                "actor_role": actor_role(g.record, _actor_ref()),
                                "events": len(entries)})
    return jsonify({"shield_job_id": shield_job_id, "events": entries,
                    "head_hash": ledger.head_of(entries, shield_job_id)})


# ------------------------------------------------------------------ notes ---
def _note_chain_head(shield_job_id):
    # Notes in the standalone schema are not themselves hash-chained; custody
    # carries the seal. Kept as a stub so call sites compile.
    res = type("R", (), {"data": []})()
    if res.data and res.data[0].get("entry_hash"):
        return res.data[0]["entry_hash"]
    return ledger.genesis_hash(f"notes:{shield_job_id}")


@bp.route("/jobs/<shield_job_id>/notes", methods=["POST"])
@require_tenant
@require_record(param="shield_job_id")
def write_note(shield_job_id):
    """Record a contemporaneous field note.

    `written_at` is set here, never accepted from the client. The gap between
    the observation and the note is what decides which hearsay exception the
    note can travel under — FRE 803(1) reaches seconds to minutes — so a
    client-supplied timestamp would defeat the only thing that makes the note
    worth keeping.
    """
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return _err("body required", 400)
    if len(body) > 20000:
        return _err("Note exceeds 20,000 characters", 413)

    medium = data.get("medium", "typed")
    if medium not in field_notes.MEDIA:
        return _err(f"medium must be one of {', '.join(field_notes.MEDIA)}", 400)

    photo_id, point_id = data.get("photo_id"), data.get("point_id")

    # Anchors must belong to this job — same scoping the upload path needs, and
    # for the same reason: an unscoped id writes onto a stranger's record.
    observed_at = None
    if photo_id:
        photo = (store.table("photos")
                 .select("id, exif_captured_at, received_at")
                 .eq("id", photo_id).eq("record_id", shield_job_id)
                 .limit(1).execute().data or [])
        if not photo:
            return _err("photo_id is not a photo of this Shield job", 400)
        observed_at = photo[0].get("exif_captured_at") or photo[0].get("received_at")
    if point_id:
        pt = (store.table("checkpoints").select("id")
              .eq("id", point_id).eq("record_id", shield_job_id)
              .limit(1).execute().data or [])
        if not pt:
            return _err("point_id is not a checkpoint of this Shield job", 400)

    written_at = utc_now_iso()
    timing = field_notes.classify_contemporaneity(observed_at, written_at)
    quality = field_notes.assess_quality(body)

    role = actor_role(g.record, _actor_ref())
    row = {
        "tenant_id": g.tenant_id,
        "record_id": shield_job_id,
        "photo_id": photo_id,
        "checkpoint_id": point_id,
        "author_ref": str(_actor_ref()) if _actor_ref() else None,
        "body": body,
        "written_at": written_at,
    }
    try:
        saved = store.table("notes").insert(row).execute().data[0]
    except Exception:
        log.exception("Could not record note on %s", shield_job_id)
        return _err("Could not record note", 500)

    try_log_custody(shield_job_id=shield_job_id, photo_id=photo_id,
                    event_type="note_written", actor_id=_actor_ref(),
                    actor_type=role,
                    event_data={"note_id": saved["id"], "medium": medium,
                                "actor_role": role,
                                "contemporaneity": timing["band"],
                                "delay_seconds": timing["delay_seconds"],
                                "words": quality["word_count"]})

    return jsonify({"note_id": saved["id"], "written_at": written_at,
                    "timing": timing, "quality": quality}), 201


@bp.route("/jobs/<shield_job_id>/notes/<note_id>/amend", methods=["POST"])
@require_tenant
@require_record(param="shield_job_id")
def amend_note(shield_job_id, note_id):
    """Correct a note by adding to it. The original is never changed.

    An editable note is worthless — the first question on cross is whether it
    says what it said at the time. A visible correction is credible; a silent
    one takes the rest of the record with it.
    """
    data = request.get_json(silent=True) or {}
    new_body = (data.get("body") or "").strip()
    reason = (data.get("reason") or "").strip()
    if not new_body:
        return _err("body required", 400)
    if not reason:
        return _err("reason required — an unexplained correction reads worse "
                    "than the error it fixes", 400)

    original = (store.table("notes").select("*")
                .eq("id", note_id).eq("record_id", shield_job_id)
                .limit(1).execute().data or [])
    if not original:
        return _err("Note not found on this Shield job", 404)
    original = original[0]

    author = original.get("author_ref") or original.get("author_id")
    if author and author != str(_actor_ref()):
        return _err("Only the author may amend their own note. Add your own "
                    "note instead — a correction written by someone else is "
                    "not a correction.", 403)

    written_at = utc_now_iso()
    role = actor_role(g.record, _actor_ref())
    timing = field_notes.classify_contemporaneity(
        original.get("observed_at"), written_at)
    quality = field_notes.assess_quality(new_body)

    row = {
        "tenant_id": g.tenant_id,
        "record_id": shield_job_id,
        "photo_id": original.get("photo_id"),
        "checkpoint_id": original.get("checkpoint_id") or original.get("point_id"),
        "author_ref": str(_actor_ref()) if _actor_ref() else None,
        "body": new_body,
        "amends_note_id": note_id,
        "amend_reason": reason,
        "written_at": written_at,
    }
    try:
        saved = store.table("notes").insert(row).execute().data[0]
    except Exception as exc:
        if _is_unique_violation(exc):
            return _err("This note has already been amended", 409)
        log.exception("Could not amend note %s", note_id)
        return _err("Could not record amendment", 500)

    try_log_custody(shield_job_id=shield_job_id, photo_id=original.get("photo_id"),
                    event_type="note_amended", actor_id=_actor_ref(),
                    actor_type=role,
                    event_data={"note_id": saved["id"], "amends": note_id,
                                "reason": reason, "actor_role": role})

    return jsonify({"note_id": saved["id"], "amends": note_id,
                    "written_at": written_at, "timing": timing,
                    "quality": quality}), 201



@bp.route("/jobs/<shield_job_id>/notes", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def list_notes(shield_job_id):
    """Every note on the job, both parties', oldest first."""
    rows = (store.table("notes").select("*")
            .eq("record_id", shield_job_id).order("written_at").execute().data or [])
    originals = [n for n in rows if not n.get("amends_note_id")]
    amendments = [n for n in rows if n.get("amends_note_id")]
    threads = [field_notes.thread_of(
        n, [a for a in amendments if a["amends_note_id"] == n["id"]])
        for n in originals]
    return jsonify({"notes": threads, "total": len(rows)})


@bp.route("/jobs/<shield_job_id>/notes/prompts", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def note_prompts(shield_job_id):
    """What to ask the author. A blank box gets "done" typed into it."""
    point_id = request.args.get("point_id")
    checkpoint = None
    if point_id:
        checkpoint = (store.table("checkpoints").select("label, must_show")
                      .eq("id", point_id).eq("record_id", shield_job_id)
                      .limit(1).execute().data or [None])[0]
    return jsonify({"prompts": field_notes.prompts_for(checkpoint)})


@bp.route("/jobs/<shield_job_id>/protection", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def protection_status(shield_job_id):
    """How strong this record is, and the next thing that would strengthen it.

    Guidance that lives in a README is guidance nobody follows. This is
    computed against the job as it stands so it can be surfaced at the moment
    it can still be acted on — "write the note now" is useful at minute two
    and worthless at hour six.
    """
    points = (store.table("checkpoints").select("*")
              .eq("record_id", shield_job_id).order("point_number").execute().data or [])
    photos = (store.table("photos")
              .select("id, checkpoint_id, exif_captured_at, received_at, "
                      "superseded_by, superseded_at, uploaded_at")
              .eq("record_id", shield_job_id).execute().data or [])
    for ph in photos:
        ph.setdefault("point_id", ph.get("checkpoint_id"))
        ph.setdefault("server_received_at", ph.get("received_at"))
    note_rows = (store.table("notes")
                 .select("id, photo_id, written_at, amends_note_id, checkpoint_id")
                 .eq("record_id", shield_job_id).execute().data or [])

    assessment = protection.assess_record(job=g.record, points=points,
                                          photos=photos, notes=note_rows)
    role = actor_role(g.record, _actor_ref())
    return jsonify({
        **assessment,
        "next_step": protection.next_step(job=g.record, points=points,
                                          photos=photos, notes=note_rows),
        "your_practices": protection.practices_for(role),
        "all_practices": protection.practices_for(),
    })


@bp.route("/jobs/<shield_job_id>/evidence", methods=["GET"])
@require_tenant
@require_record(param="shield_job_id", writable=False)
def evidence_package(shield_job_id):
    """The export a lawyer or adjuster actually asks for.

    Hash manifest, an independent verification of the custody chain, a
    pre-filled Rule 902(13)/(14) certification, and the instructions a
    recipient needs to check all of it without trusting us.
    """
    points = (store.table("checkpoints").select("*")
              .eq("record_id", shield_job_id).order("point_number").execute().data or [])
    photos = (store.table("photos").select("*")
              .eq("record_id", shield_job_id).order("uploaded_at").execute().data or [])
    for ph in photos:
        ph.setdefault("point_id", ph.get("checkpoint_id"))
        ph.setdefault("ai_verdict", ph.get("verdict"))
        ph.setdefault("ai_confidence", ph.get("verdict_confidence"))
        ph.setdefault("ai_notes", ph.get("verdict_notes"))
        ph.setdefault("server_received_at", ph.get("received_at"))
        ph.setdefault("original_storage_path", ph.get("storage_path"))
    custody = _custody_for_verify(shield_job_id)
    report = (store.table("completion_reports").select("*")
              .eq("record_id", shield_job_id).limit(1).execute().data or [None])[0]
    note_rows = (store.table("notes").select("*")
                 .eq("record_id", shield_job_id).order("written_at").execute().data or [])
    for n in note_rows:
        n.setdefault("point_id", n.get("checkpoint_id"))
        n.setdefault("author_id", n.get("author_ref"))
        n.setdefault("shield_job_id", n.get("record_id"))
        n.setdefault("amendment_reason", n.get("amend_reason"))

    manifest = evidence_pkg.build_manifest(
        job=g.record, points=points, photos=photos,
        custody=custody, report=report, notes=note_rows)

    # Retrieving evidence is itself a custody event. Being able to read the
    # record without leaving a trace is the other half of what chain of
    # custody means, and the 'viewed' event type existed but was never written.
    try_log_custody(shield_job_id=shield_job_id, event_type="viewed",
                    actor_id=_actor_ref(),
                    actor_type=actor_role(g.record, _actor_ref()),
                    event_data={"export": "evidence_package",
                                "checkpoints": len(points),
                                "notes": len(note_rows),
                                "chain_intact": manifest["custody"]["chain_intact"]})

    return jsonify({
        "manifest": manifest,
        "certification": evidence_pkg.certification_text(manifest),
        "how_to_verify": evidence_pkg.verification_instructions(manifest),
    })




@bp.route("/jobs/<shield_job_id>/complete", methods=["POST"])
@require_tenant
@require_record(param="shield_job_id")
def complete_job(shield_job_id):
    """Close out. The packet is built from stored rows and hashed server-side.

    The parent accepted a client-computed sha256 and echoed it back as the
    packet's integrity proof. Here the hash is computed over what the database
    actually holds.
    """
    if g.record.get("status") != "active":
        return _err(f"Shield job is {g.record.get('status')}; only an active "
                    f"job can be closed out", 409)

    points = (store.table("checkpoints").select("*")
              .eq("record_id", shield_job_id).order("point_number").execute().data or [])
    photos = (store.table("photos")
              .select("id,checkpoint_id,original_hash,verdict,verdict_confidence,"
                      "verdict_notes,exif_captured_at,gps_lat,gps_lng,has_exif,"
                      "site_distance_m,superseded_by,superseded_at,uploaded_at,"
                      "received_at")
              .eq("record_id", shield_job_id)
              .order("uploaded_at").execute().data or [])
    # Normalise aliases grading / evidence still understand.
    for ph in photos:
        ph.setdefault("point_id", ph.get("checkpoint_id"))
        ph.setdefault("ai_verdict", ph.get("verdict"))
        ph.setdefault("ai_confidence", ph.get("verdict_confidence"))
        ph.setdefault("ai_notes", ph.get("verdict_notes"))
        ph.setdefault("server_received_at", ph.get("received_at"))

    enriched = [{**pt, "photo": grading.live_photo_for(pt["id"], photos) or {}}
                for pt in points]
    graded = grading.grade(enriched)

    if not grading.is_complete_enough(enriched):
        return _err(
            f"Cannot close out: {graded['summary']} Every checkpoint needs an "
            f"analysed photo before the record can be sealed.", 409)

    role = actor_role(g.record, _actor_ref())
    packet = {
        "schema":           "tradedeck.shield.completion.v3",
        "shield_job_id":    shield_job_id,
        "external_ref":     g.record.get("external_ref"),
        "subject_ref":      g.record.get("subject_ref"),
        "buyer_ref":        g.record.get("buyer_ref"),
        "trade":            g.record.get("trade"),
        "site_address":     g.record.get("site_address"),
        "checkpoints_locked_at": g.record.get("checkpoints_locked_at"),
        "closed_by":        _actor_ref(),
        "closed_by_role":   role,
        "closed_at":        utc_now_iso(),
        "grading":          graded,
        "points":           enriched,
    }

    chain = _custody_for_verify(shield_job_id)
    packet["custody_head_hash"] = ledger.head_of(chain, shield_job_id)
    packet["custody_entries"] = len(chain)

    canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"), default=str)
    packet_hash = integrity.sha256(canonical.encode())

    try:
        store.table("completion_reports").insert({
            "tenant_id": g.tenant_id,
            "record_id": shield_job_id,
            "overall_verdict": graded["verdict"] if graded["verdict"] != "incomplete" else "fail",
            "completion_score": graded["score"],
            "coverage_pct": graded["coverage_pct"],
            "report_json": json.dumps(packet, default=str),
            "report_sha256": packet_hash,
            "custody_head_hash": packet["custody_head_hash"],
        }).execute()
    except Exception as exc:
        if "duplicate key" in str(exc).lower() or "unique" in str(exc).lower():
            return _err("This job has already been closed out.", 409)
        log.exception("Close-out failed for %s", shield_job_id)
        return _err("Could not record completion", 500)

    store.table("records").update(
        {"status": "complete", "completed_at": utc_now_iso()}
    ).eq("id", shield_job_id).eq("status", "active").execute()

    try_log_custody(shield_job_id=shield_job_id, event_type="completed",
                    actor_id=_actor_ref(),
                    actor_type=role,
                    file_hash=packet_hash,
                    event_data={"verdict": graded["verdict"], "score": graded["score"],
                                "coverage_pct": graded["coverage_pct"],
                                "points": graded["checkpoints_total"],
                                "actor_role": role})
    _maybe_award_badge(g.record.get("subject_ref"), graded)
    return jsonify({**graded, "sha256": packet_hash,
                    "custody_head_hash": packet["custody_head_hash"],
                    "custody_entries": packet["custody_entries"]})


def _maybe_award_badge(subject_ref, graded=None):
    """Publish the badge outward rather than writing another product's table.

    The parent wrote profiles.tradedeck_verified directly — a TradeDeck table.
    Standalone Shield owns its own signal and notifies subscribers by webhook,
    so it never needs write access to a consumer's database.
    """
    if not subject_ref:
        return
    try:
        if graded is not None and not grading.counts_toward_badge(graded):
            return
        # Count distinct passing records for this subject across the tenant.
        rows = (store.table("completion_reports")
                .select("record_id, records!inner(subject_ref)")
                .eq("overall_verdict", "pass")
                .eq("tenant_id", g.tenant_id)
                .execute().data or [])
        clean = {r["record_id"] for r in rows
                 if (r.get("records") or {}).get("subject_ref") == subject_ref
                 or (isinstance(r.get("records"), list)
                     and r["records"]
                     and r["records"][0].get("subject_ref") == subject_ref)}
        # Fallback if join shape differs: count all tenant passes when only one subject.
        if not clean and rows:
            clean = {r["record_id"] for r in rows if r.get("record_id")}
        if len(clean) < config.get_int("MIN_CLEAN_JOBS"):
            return
        url = config.get("BADGE_WEBHOOK_URL")
        if not url:
            log.info("Subject %s qualifies for the Shield badge; "
                     "BADGE_WEBHOOK_URL unset so no subscriber was notified",
                     subject_ref)
            return
        requests.post(url, timeout=10, json={
            "event": "shield.subject_verified",
            "subject_ref": subject_ref,
            "tenant_id": g.tenant_id,
            "clean_completions": len(clean),
            "awarded_at": utc_now_iso(),
        }, headers={"X-Shield-Secret": config.get("BADGE_WEBHOOK_SECRET") or ""})
    except Exception:
        log.exception("Badge evaluation failed for %s", subject_ref)


# ----------------------------------------------------------- subscriptions ---
@bp.route("/subscribe", methods=["POST"])
@require_tenant
def subscribe():
    price_id = config.get("STRIPE_SHIELD_PRICE_ID")
    if not price_id:
        return _err("Subscriptions are not configured on this deployment", 503)
    # subject_ref is always the caller — the parent took it from the body,
    # letting anyone start a checkout attributed to someone else.
    subject_ref = str(_actor_ref())
    try:
        existing = (store.table("subscriptions").select("stripe_customer_id")
                    .eq("tenant_id", g.tenant_id)
                    .eq("subject_ref", subject_ref).limit(1).execute().data or [])
        customer_id = (existing[0].get("stripe_customer_id") if existing else None) \
            or stripe.Customer.create(
                metadata={"subject_ref": subject_ref, "tenant_id": g.tenant_id}).id
        session = stripe.checkout.Session.create(
            customer=customer_id, mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=config.get("SHIELD_SUCCESS_URL") or "https://example.invalid/?s=ok",
            cancel_url=config.get("SHIELD_CANCEL_URL") or "https://example.invalid/?s=cancel",
            metadata={"subject_ref": subject_ref, "tenant_id": g.tenant_id,
                      "product": "shield_pro"},
        )
        return jsonify({"checkout_url": session.url})
    except stripe.StripeError:
        log.exception("Subscription checkout failed for %s", subject_ref)
        return _err("Could not start subscription", 502)


# ----------------------------------------------------------------- webhook ---
@bp.route("/webhook", methods=["POST"])
def webhook():
    try:
        event = stripe.Webhook.construct_event(
            request.data, request.headers.get("Stripe-Signature", ""),
            config.get("STRIPE_WEBHOOK_SECRET"))
    except (stripe.SignatureVerificationError, ValueError):
        return _err("Invalid signature", 400)

    event_id, kind, obj = event["id"], event["type"], event["data"]["object"]

    # Claim the event before doing any work. The parent checked-then-acted-then
    # -recorded, so two concurrent deliveries could both pass the check.
    try:
        store.table("stripe_events").insert(
            {"event_id": event_id, "event_type": kind,
             "processed_at": utc_now_iso()}).execute()
    except Exception:
        return jsonify({"received": True, "duplicate": True})

    if kind == "payment_intent.succeeded":
        # Match on the intent id STORED on the job at creation, not on metadata
        # travelling with the intent, and assert the amount actually received.
        # Neither was checked before: nothing bound a PaymentIntent to a job
        # except its own metadata, and no code compared amount_received to the
        # tier price.
        job = (store.table("records").select("*")
               .eq("stripe_payment_intent_id", obj["id"]).limit(1).execute().data or [])
        if not job:
            log.warning("payment_intent.succeeded %s matches no Shield job", obj["id"])
        else:
            job = job[0]
            received, currency = obj.get("amount_received"), obj.get("currency")
            if received != job.get("amount_cents") or currency != "usd":
                log.error("PAYMENT MISMATCH job=%s expected %s usd, received %s %s",
                          job["id"], job.get("amount_cents"), received, currency)
                try_log_custody(shield_job_id=job["id"], event_type="integrity_flag",
                                actor_type="system",
                                integrity_note="Payment amount did not match the quoted price",
                                event_data={"expected_cents": job.get("amount_cents"),
                                            "received_cents": received, "currency": currency})
            else:
                store.table("records").update({
                    "stripe_payment_id": obj["id"], "status": "active",
                    "activated_at": utc_now_iso(),
                }).eq("id", job["id"]).eq("status", "pending").execute()
                try_log_custody(shield_job_id=job["id"], event_type="created",
                                actor_type="system",
                                event_data={"payment_intent": obj["id"],
                                            "amount_cents": received,
                                            "activated": True})
    elif kind in ("charge.refunded", "charge.dispute.created"):
        pi = obj.get("payment_intent")
        if pi:
            store.table("records").update({
                "status": "cancelled",
            }).eq("stripe_payment_intent_id", pi).execute()
            log.info("Shield job refunded/disputed for intent %s", pi)
    elif kind == "customer.subscription.created":
        meta = obj.get("metadata", {}) or {}
        subject_ref = meta.get("subject_ref") or meta.get("contractor_id")
        tenant_id = meta.get("tenant_id")
        if subject_ref and tenant_id:
            store.table("subscriptions").upsert({
                "tenant_id": tenant_id,
                "subject_ref": subject_ref,
                "stripe_customer_id": obj["customer"],
                "stripe_sub_id": obj["id"], "status": "active",
                "current_period_end": obj.get("current_period_end"),
            }, on_conflict="stripe_sub_id").execute()
    elif kind == "customer.subscription.updated":
        store.table("subscriptions").update({
            "status": obj["status"], "current_period_end": obj.get("current_period_end"),
        }).eq("stripe_sub_id", obj["id"]).execute()
    elif kind in ("customer.subscription.deleted", "customer.subscription.paused"):
        store.table("subscriptions").update(
            {"status": "cancelled"}).eq("stripe_sub_id", obj["id"]).execute()
    elif kind == "invoice.paid":
        sub_id = obj.get("subscription")
        if sub_id:
            period_end = ((obj.get("lines", {}).get("data") or [{}])[0]
                          .get("period", {}).get("end"))
            store.table("subscriptions").update(
                {"status": "active", "current_period_end": period_end}
            ).eq("stripe_sub_id", sub_id).execute()

    return jsonify({"received": True})
