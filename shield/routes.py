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

import requests
import stripe
from flask import Blueprint, g, jsonify, request

import codes
import config
import corroborate
import evidence as evidence_pkg
import integrity
import ledger
import pricing
import verdict as grading
import vision
from auth import require_auth, require_shield_job, utc_now_iso
from db import db

log = logging.getLogger(__name__)
bp = Blueprint("shield", __name__, url_prefix="/shield")


# ---------------------------------------------------------------- helpers ---
def _err(msg, code):
    return jsonify({"error": msg}), code


def _bucket():
    return config.get("SHIELD_BUCKET")


def actor_role(job, user_id):
    """Who is acting, derived rather than asserted.

    The original hardcoded actor_type="homeowner" on the export and close-out
    routes, both of which any participant could call. A contractor closing out
    his own job was recorded in the audit trail as the buyer signing off — an
    evidence system that does not merely fail to detect falsification but
    manufactures it.
    """
    if not job or not user_id:
        return "system"
    if user_id == job.get("homeowner_id"):
        return "homeowner"
    if user_id == job.get("contractor_id"):
        return "contractor"
    return "system"


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

    Each entry carries the hash of the one before it, so altering or removing
    history breaks every link after it. The append-only trigger stops an
    application bug; the chain is what makes tampering *detectable* by someone
    who does not trust the operator — which is the only audience that matters
    when the record is contested.

    Raises on failure. An action that happened without an audit record is a
    worse outcome than an action that failed: the caller must decide, and the
    evidentiary routes roll back rather than proceed.
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
    sealed["event_data"] = json.dumps(entry["event_data"], sort_keys=True,
                                      separators=(",", ":"), default=str)
    db().table("shield_custody_log").insert(sealed).execute()
    return sealed["entry_hash"]


def _chain_head(shield_job_id):
    """Hash of the most recent custody entry for a job, or its genesis."""
    if not shield_job_id:
        return ledger.genesis_hash("unscoped")
    res = (db().table("shield_custody_log").select("entry_hash")
           .eq("shield_job_id", shield_job_id)
           .order("recorded_at", desc=True).limit(1).execute())
    if res.data and res.data[0].get("entry_hash"):
        return res.data[0]["entry_hash"]
    return ledger.genesis_hash(shield_job_id)


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


def _signed_url(path, ttl=None):
    res = db().storage.from_(_bucket()).create_signed_url(
        path=path, expires_in=ttl or config.get_int("SIGNED_URL_TTL"))
    return res.get("signedURL") or res.get("signedUrl")


# ------------------------------------------------------------- quote / buy ---
@bp.route("/quote", methods=["POST"])
@require_auth
def quote():
    """What Shield costs for a job of this size. Advisory; the charge is
    recomputed server-side at purchase and this value is never trusted back."""
    data = request.get_json(silent=True) or {}
    tier, price = pricing.quote(data.get("job_budget_cents"))
    return jsonify({"tier": tier, "price_cents": price})


@bp.route("/jobs", methods=["POST"])
@require_auth
def create_job():
    """Create a pending Shield job and its PaymentIntent.

    The price comes from pricing.quote() against the job budget. Any
    amount_cents in the body is ignored outright.
    """
    data = request.get_json(silent=True) or {}
    contractor_id = data.get("contractor_id")
    description   = (data.get("job_description") or "").strip()
    if not description:
        return _err("job_description required", 400)

    # A contractor grading their own work is not an audit. The database
    # enforces this too; rejecting here gives a usable error instead of a 500.
    if contractor_id and contractor_id == g.user_id:
        return _err("The contractor must be a different party from the "
                    "homeowner — a Shield record of your own work is not an "
                    "independent record.", 400)

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
        job = db().table("shield_jobs").insert({
            "external_ref":     data.get("external_ref"),   # caller's own job id
            "homeowner_id":     g.user_id,
            "contractor_id":    contractor_id,
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
        log.exception("Could not create shield job")
        return _err("Could not create Shield job", 500)

    try:
        intent = stripe.PaymentIntent.create(
            amount=price_cents, currency="usd",
            metadata={"shield_job_id": job["id"], "product": "shield_per_job",
                      "tier": tier},
            description=f"TradeDeck Shield ({tier}) — job {job['id']}",
            idempotency_key=f"shield-pi-{job['id']}",   # scoped to this job row,
        )                                               # not a reused external id
    except stripe.StripeError:
        log.exception("Stripe PaymentIntent failed for shield job %s", job["id"])
        return _err("Payment setup failed", 502)

    # Bind the intent to the job here, so activation can match on the stored id
    # and assert the amount rather than trusting metadata carried on the intent.
    db().table("shield_jobs").update({"stripe_payment_intent_id": intent.id}) \
        .eq("id", job["id"]).execute()

    try_log_custody(shield_job_id=job["id"], event_type="created",
                    actor_id=g.user_id, actor_type="homeowner",
                    event_data={"tier": tier, "price_cents": price_cents,
                                "trade": trade, "has_site_location": site_lat is not None,
                                "site_radius_m": job.get("site_radius_m")})

    return jsonify({"shield_job_id": job["id"], "tier": tier,
                    "price_cents": price_cents, "trade": trade,
                    "site_geofenced": site_lat is not None,
                    "client_secret": intent.client_secret}), 201


# ------------------------------------------------------------- checkpoints ---
@bp.route("/jobs/<shield_job_id>/checkpoints", methods=["POST"])
@require_auth
@require_shield_job(role="homeowner")
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
    if g.shield_job.get("status") != "active":
        return _err("Shield job is not active — payment must clear first", 409)

    if g.shield_job.get("checkpoints_locked_at"):
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

    trade = g.shield_job.get("trade") or codes.detect_trade(description)
    rows = []
    for p in points:
        entry = codes.code_entry(trade, p["point_number"])
        rows.append({
            "shield_job_id":     shield_job_id,
            "point_number":      p["point_number"],
            "label":             p["label"],
            "description":       p["description"],
            "irc_code":          entry.get("irc"),
            "ibc_code":          entry.get("ibc"),
            "photo_instruction": entry.get("photo_instruction"),
            "must_show":         entry.get("must_show"),
            "status":            "pending",
        })
    try:
        saved = db().table("shield_pivotal_points").insert(rows).execute().data
        locked_at = utc_now_iso()
        db().table("shield_jobs").update({"checkpoints_locked_at": locked_at}) \
            .eq("id", shield_job_id).is_("checkpoints_locked_at", "null").execute()
    except Exception:
        log.exception("Could not persist checkpoints for %s", shield_job_id)
        return _err("Could not save checkpoints", 500)

    # Seal the schedule into the chain. The requirements are now committed
    # evidence in their own right, so a later substitution is detectable even
    # if the point rows themselves were edited in the database.
    try_log_custody(
        shield_job_id=shield_job_id, event_type="checkpoints_locked",
        actor_id=g.user_id, actor_type="homeowner",
        event_data={"trade": trade, "locked_at": locked_at,
                    "schedule_sha256": integrity.sha256(json.dumps(
                        [{k: r.get(k) for k in
                          ("point_number", "label", "description", "irc_code",
                           "ibc_code", "must_show")} for r in rows],
                        sort_keys=True, separators=(",", ":")).encode())})

    return jsonify({"trade": trade, "locked_at": locked_at,
                    "points": saved or rows})


@bp.route("/jobs/<shield_job_id>/checkpoints", methods=["GET"])
@require_auth
@require_shield_job()
def list_checkpoints(shield_job_id):
    res = (db().table("shield_pivotal_points")
           .select("*").eq("shield_job_id", shield_job_id)
           .order("point_number").execute())
    return jsonify({"points": res.data or []})


# ------------------------------------------------------------------ upload ---
@bp.route("/jobs/<shield_job_id>/photos", methods=["POST"])
@require_auth
@require_shield_job(role="contractor")
def upload_photo(shield_job_id):
    """The integrity anchor. multipart/form-data: file, point_id, gps_lat, gps_lng.

    Order is load-bearing and must not be rearranged:
      1. validate    2. read raw bytes    3. SHA-256 over those bytes
      4. server-side EXIF   5. store the original, unmodified, no-overwrite
      6. store a stripped copy for the model   7. row   8. custody event
    """
    if g.shield_job.get("status") != "active":
        return _err("Shield job is not active — payment must clear first", 409)
    if not g.shield_job.get("checkpoints_locked_at"):
        return _err("The checkpoint schedule has not been set. The homeowner "
                    "defines it before work begins.", 409)

    point_id = (request.form.get("point_id") or "").strip()
    if not point_id:
        return _err("point_id required", 400)

    # The checkpoint must belong to THIS job. Without this scoping a contractor
    # could upload against a checkpoint UUID from a job he has no relationship
    # with; analyse would then judge against that job's requirement and write
    # status='approved' onto its checkpoint row, so its homeowner would see an
    # approved checkpoint nobody on that job produced.
    point = (db().table("shield_pivotal_points").select("id, point_number, label")
             .eq("id", point_id).eq("shield_job_id", shield_job_id)
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
    mime = integrity.normalize_mime(upload.content_type)
    if mime not in integrity.ALLOWED_MIME:
        return _err(f'File type "{mime}" not accepted. '
                    f'Allowed: {", ".join(sorted(integrity.ALLOWED_MIME))}', 415)

    raw = upload.read()
    if not raw:
        return _err("Empty file", 400)
    if len(raw) > config.get_int("MAX_UPLOAD_BYTES"):
        return _err(f"File exceeds {config.get_int('MAX_UPLOAD_BYTES') // (1024*1024)} MB", 413)

    # (3) the anchor — before anything touches the bytes
    original_hash = integrity.sha256(raw)
    received_at   = utc_now_iso()

    # (4) provenance from the original bytes
    assessment = integrity.assess(raw, mime, gps_lat, gps_lng,
                                  config.get_int("GPS_TOLERANCE_M"))
    exif = assessment["exif"]

    # (4b) Geofence against the JOB SITE — the one reference point the
    # contractor does not supply. Comparing EXIF GPS against the coordinates
    # posted with the upload compared two values the same party controls and
    # called agreement "corroborated"; it could not fail for anyone willing to
    # write EXIF, which takes a dozen lines with the library used to read it.
    site_lat, site_lng = g.shield_job.get("site_lat"), g.shield_job.get("site_lng")
    site_distance = integrity.haversine_m(site_lat, site_lng, gps_lat, gps_lng)
    site_radius = g.shield_job.get("site_radius_m") or 250
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
    orig_path = f"{shield_job_id}/{g.user_id}/orig/{photo_id}.{ext}"
    comp_path = f"{shield_job_id}/{g.user_id}/comp/{photo_id}.jpg"

    # (5) original, unmodified, never overwritten
    try:
        db().storage.from_(_bucket()).upload(
            path=orig_path, file=raw,
            file_options={"content-type": mime, "cache-control": "no-cache",
                          "x-upsert": "false"})
    except Exception:
        log.exception("Original storage write failed for %s", photo_id)
        return _err("Could not store photo. Nothing was saved — please retry.", 500)

    # (6) stripped, downscaled copy — the only thing the model ever sees
    compressed = integrity.compress_for_model(raw)
    try:
        db().storage.from_(_bucket()).upload(
            path=comp_path, file=compressed,
            file_options={"content-type": "image/jpeg", "cache-control": "no-cache",
                          "x-upsert": "false"})
    except Exception:
        log.exception("Compressed copy failed for %s", photo_id)
        comp_path = None

    row = {
        "id": photo_id, "point_id": point_id, "shield_job_id": shield_job_id,
        "contractor_id": g.user_id,
        "original_hash": original_hash, "original_hash_algo": "SHA-256",
        "original_size_bytes": len(raw),
        "original_storage_path": orig_path, "compressed_storage_path": comp_path,
        "gps_lat": gps_lat, "gps_lng": gps_lng, "gps_accuracy_m": gps_accuracy,
        "exif_gps_lat": exif.get("gps_lat"), "exif_gps_lng": exif.get("gps_lng"),
        "exif_gps_altitude_m": exif.get("gps_altitude_m"),
        "exif_captured_at": exif.get("captured_at"),
        "exif_device_make": exif.get("device_make"),
        "exif_device_model": exif.get("device_model"),
        "exif_software": exif.get("software"),
        "exif_orientation": exif.get("orientation"),
        "exif_raw": json.dumps(exif.get("exif_raw", {})),
        "has_exif": assessment["has_exif"],
        "server_received_at": received_at, "integrity_sealed_at": utc_now_iso(),
        "uploaded_at": received_at,
        "upload_user_agent": request.headers.get("User-Agent", ""),
        "upload_ip_hash": integrity.hash_ip(client_ip(), config.get("IP_HASH_SALT")),
        "site_distance_m": round(site_distance, 1) if site_distance is not None else None,
    }
    try:
        db().table("shield_photos").insert(row).execute()
    except Exception:
        log.exception("Row insert failed for %s — rolling back storage", photo_id)
        for p in (orig_path, comp_path):
            if p:
                try:
                    db().storage.from_(_bucket()).remove([p])
                except Exception:
                    log.warning("Orphaned storage object %s", p)
        return _err("Could not record photo. Nothing was saved — please retry.", 500)

    log_custody(photo_id=photo_id, shield_job_id=shield_job_id, event_type="uploaded",
                actor_id=g.user_id, actor_type="contractor", file_hash=original_hash,
                integrity_note=assessment["integrity_note"],
                exif_captured_at=exif.get("captured_at"),
                gps_lat=exif.get("gps_lat") or gps_lat,
                gps_lng=exif.get("gps_lng") or gps_lng,
                event_data={"original_path": orig_path, "compressed_path": comp_path,
                            "original_bytes": len(raw), "compressed_bytes": len(compressed),
                            "exif_status": assessment["exif_status"],
                            "gps_distance_m": assessment["gps_distance_m"],
                            "gps_corroborated": assessment["gps_corroborated"],
                            "content_type": mime})
    if assessment["gps_mismatch"] or assessment["exif_status"] == "absent":
        log_custody(photo_id=photo_id, shield_job_id=shield_job_id,
                    event_type="integrity_flag", actor_type="system",
                    file_hash=original_hash, integrity_note=assessment["integrity_note"],
                    event_data={"exif_status": assessment["exif_status"],
                                "gps_mismatch": assessment["gps_mismatch"]})

    return jsonify({
        "photo_id": photo_id, "original_hash": original_hash,
        "exif_status": assessment["exif_status"],
        "gps_corroborated": assessment["gps_corroborated"],
        "gps_distance_m": assessment["gps_distance_m"],
        "integrity_note": assessment["integrity_note"],
        "device": " ".join(filter(None, [exif.get("device_make"),
                                         exif.get("device_model")])) or None,
        "captured_at": exif.get("captured_at"),
    }), 201


# ----------------------------------------------------------------- analyze ---
@bp.route("/photos/<photo_id>/analyze", methods=["POST"])
@require_auth
def analyze_photo(photo_id):
    """Adjudicate a stored photo. Takes the id and nothing else.

    Every value handed to the model is read from the database here. There is no
    request body, so there is nothing for a caller to substitute.
    """
    res = db().table("shield_photos").select("*").eq("id", photo_id).limit(1).execute()
    if not res.data:
        return _err("Photo not found", 404)
    photo = res.data[0]

    from auth import get_shield_job, is_participant
    job = get_shield_job(photo["shield_job_id"])
    if not is_participant(job, g.user_id):
        return _err("Photo not found", 404)

    if photo.get("ai_verdict"):
        return jsonify({"verdict": photo["ai_verdict"],
                        "confidence": photo.get("ai_confidence"),
                        "notes": photo.get("ai_notes"),
                        "already_analyzed": True})

    if not photo.get("compressed_storage_path"):
        return _err("No analysable copy of this photo exists", 409)

    pt = (db().table("shield_pivotal_points").select("*")
          .eq("id", photo["point_id"]).limit(1).execute().data or [{}])[0]

    # Fetch the compressed copy from a URL we mint ourselves from the stored
    # path. The caller cannot influence what is fetched.
    try:
        img = requests.get(_signed_url(photo["compressed_storage_path"]), timeout=20)
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
            code_reference=pt.get("irc_code") or pt.get("ibc_code"),
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
    written = db().table("shield_photos").update({
        "ai_verdict": result["verdict"], "ai_confidence": result["confidence"],
        "ai_notes": result["notes"], "ai_authentic": result["authentic"],
        "ai_model": config.get("ANTHROPIC_MODEL"),
        "photo_hash": comp_hash, "hash_algorithm": "SHA-256",
        "code_reference": pt.get("irc_code"),
    }).eq("id", photo_id).is_("ai_verdict", "null").execute()

    if not written.data:
        current = (db().table("shield_photos").select("ai_verdict, ai_confidence, ai_notes")
                   .eq("id", photo_id).limit(1).execute().data or [{}])[0]
        return jsonify({**current, "already_analyzed": True,
                        "note": "A concurrent request recorded the verdict first."})

    db().table("shield_pivotal_points").update({
        "status": "approved" if result["verdict"] == "pass" else "flagged"
    }).eq("id", photo["point_id"]).execute()

    log_custody(photo_id=photo_id, shield_job_id=photo["shield_job_id"],
                event_type="ai_analyzed", actor_id=g.user_id, actor_type="ai",
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
        log_custody(photo_id=photo_id, shield_job_id=photo["shield_job_id"],
                    event_type="flagged", actor_type="ai",
                    file_hash=photo["original_hash"],
                    integrity_note=result["authenticity_note"] or result["notes"],
                    event_data={"verdict": result["verdict"]})

    return jsonify(result)


# ------------------------------------------------------- custody / reports ---
@bp.route("/jobs/<shield_job_id>/custody", methods=["GET"])
@require_auth
@require_shield_job()
def custody(shield_job_id):
    """The audit trail, oldest first. This is the deliverable clients pay for."""
    res = (db().table("shield_custody_log").select("*")
           .eq("shield_job_id", shield_job_id)
           .order("recorded_at", desc=False).execute())
    try_log_custody(shield_job_id=shield_job_id, event_type="exported",
                    actor_id=g.user_id,
                    actor_type=actor_role(g.shield_job, g.user_id),
                    event_data={"export": "custody_log",
                                "events": len(res.data or [])})
    return jsonify({"shield_job_id": shield_job_id, "events": res.data or []})


@bp.route("/jobs/<shield_job_id>/evidence", methods=["GET"])
@require_auth
@require_shield_job()
def evidence_package(shield_job_id):
    """The export a lawyer or adjuster actually asks for.

    Hash manifest, an independent verification of the custody chain, a
    pre-filled Rule 902(13)/(14) certification, and the instructions a
    recipient needs to check all of it without trusting us.
    """
    points = (db().table("shield_pivotal_points").select("*")
              .eq("shield_job_id", shield_job_id).order("point_number").execute().data or [])
    photos = (db().table("shield_photos").select("*")
              .eq("shield_job_id", shield_job_id).order("uploaded_at").execute().data or [])
    custody = (db().table("shield_custody_log").select("*")
               .eq("shield_job_id", shield_job_id).order("recorded_at").execute().data or [])
    report = (db().table("shield_completion_reports").select("*")
              .eq("shield_job_id", shield_job_id).limit(1).execute().data or [None])[0]

    manifest = evidence_pkg.build_manifest(
        job=g.shield_job, points=points, photos=photos,
        custody=custody, report=report)

    # Retrieving evidence is itself a custody event. Being able to read the
    # record without leaving a trace is the other half of what chain of
    # custody means, and the 'viewed' event type existed but was never written.
    try_log_custody(shield_job_id=shield_job_id, event_type="viewed",
                    actor_id=g.user_id,
                    actor_type=actor_role(g.shield_job, g.user_id),
                    event_data={"export": "evidence_package",
                                "checkpoints": len(points),
                                "chain_intact": manifest["custody"]["chain_intact"]})

    return jsonify({
        "manifest": manifest,
        "certification": evidence_pkg.certification_text(manifest),
        "how_to_verify": evidence_pkg.verification_instructions(manifest),
    })




@bp.route("/jobs/<shield_job_id>/complete", methods=["POST"])
@require_auth
@require_shield_job()
def complete_job(shield_job_id):
    """Close out. The packet is built from stored rows and hashed server-side.

    The parent accepted a client-computed sha256 and echoed it back as the
    packet's integrity proof. Here the hash is computed over what the database
    actually holds.
    """
    if g.shield_job.get("status") != "active":
        return _err(f"Shield job is {g.shield_job.get('status')}; only an active "
                    f"job can be closed out", 409)

    points = (db().table("shield_pivotal_points").select("*")
              .eq("shield_job_id", shield_job_id).order("point_number").execute().data or [])
    photos = (db().table("shield_photos")
              .select("id,point_id,original_hash,ai_verdict,ai_confidence,ai_notes,"
                      "exif_captured_at,gps_lat,gps_lng,has_exif,site_distance_m,"
                      "superseded_by,uploaded_at")
              .eq("shield_job_id", shield_job_id)
              .is_("superseded_by", "null")
              .order("uploaded_at").execute().data or [])
    # Keyed on point, live photos only. The previous dict comprehension ran over
    # an unordered result, so with several photos on one checkpoint whichever
    # row Postgres returned last became the sealed evidence — an honest 'fail'
    # could silently vanish from the deliverable behind a later retake.
    by_point = {p["point_id"]: p for p in photos}

    enriched = [{**pt, "photo": by_point.get(pt["id"], {})} for pt in points]
    graded = grading.grade(enriched)

    # A job with an unphotographed checkpoint cannot be closed. Without this,
    # a contractor could photograph one checkpoint, close out, and repeat —
    # and since the badge counted completion rows rather than distinct jobs,
    # a single self-dealt job could mint the verified badge.
    if not grading.is_complete_enough(enriched):
        return _err(
            f"Cannot close out: {graded['summary']} Every checkpoint needs an "
            f"analysed photo before the record can be sealed.", 409)

    packet = {
        "schema":           "tradedeck.shield.completion.v3",
        "shield_job_id":    shield_job_id,
        "external_ref":     g.shield_job.get("external_ref"),
        "contractor_id":    g.shield_job.get("contractor_id"),
        "homeowner_id":     g.shield_job.get("homeowner_id"),
        "trade":            g.shield_job.get("trade"),
        "site_address":     g.shield_job.get("site_address"),
        "checkpoints_locked_at": g.shield_job.get("checkpoints_locked_at"),
        "closed_by":        g.user_id,
        "closed_by_role":   actor_role(g.shield_job, g.user_id),
        "closed_at":        utc_now_iso(),
        "grading":          graded,
        "points":           enriched,
    }

    # The chain head commits to the whole job history. A holder of this value
    # can later detect any rewrite of the record — including by us.
    chain = (db().table("shield_custody_log").select("*")
             .eq("shield_job_id", shield_job_id)
             .order("recorded_at").execute().data or [])
    packet["custody_head_hash"] = ledger.head_of(chain, shield_job_id)
    packet["custody_entries"] = len(chain)

    canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"), default=str)
    packet_hash = integrity.sha256(canonical.encode())

    try:
        db().table("shield_completion_reports").insert({
            "shield_job_id": shield_job_id, "job_id": g.shield_job.get("external_ref"),
            "contractor_id": g.shield_job.get("contractor_id"),
            "homeowner_id": g.shield_job.get("homeowner_id"),
            "overall_verdict": graded["verdict"] if graded["verdict"] != "incomplete" else "fail",
            "completion_score": graded["score"],
            "report_json": json.dumps(packet, default=str),
            "report_sha256": packet_hash,
            "custody_head_hash": packet["custody_head_hash"],
        }).execute()
    except Exception as exc:
        # A unique index makes the second close-out a conflict rather than a
        # third 'pass' row. Repeated close-outs were how the badge was minted.
        if "duplicate key" in str(exc).lower() or "unique" in str(exc).lower():
            return _err("This job has already been closed out.", 409)
        log.exception("Close-out failed for %s", shield_job_id)
        return _err("Could not record completion", 500)

    db().table("shield_jobs").update(
        {"status": "complete", "completed_at": utc_now_iso()}
    ).eq("id", shield_job_id).eq("status", "active").execute()

    try_log_custody(shield_job_id=shield_job_id, event_type="completed",
                    actor_id=g.user_id,
                    actor_type=actor_role(g.shield_job, g.user_id),
                    file_hash=packet_hash,
                    event_data={"verdict": graded["verdict"], "score": graded["score"],
                                "coverage_pct": graded["coverage_pct"],
                                "points": graded["checkpoints_total"]})
    _maybe_award_badge(g.shield_job.get("contractor_id"), graded)
    return jsonify({**graded, "sha256": packet_hash,
                    "custody_head_hash": packet["custody_head_hash"],
                    "custody_entries": packet["custody_entries"]})


def _maybe_award_badge(contractor_id, graded=None):
    """Publish the badge outward rather than writing another product's table.

    The parent wrote profiles.tradedeck_verified directly — a TradeDeck table.
    Standalone Shield owns its own signal and notifies subscribers by webhook,
    so it never needs write access to a consumer's database.
    """
    if not contractor_id:
        return
    try:
        # Only a fully documented, fully passing job builds standing, and the
        # count is of DISTINCT jobs. Counting rows let three close-outs of one
        # partial job reach the threshold.
        if graded is not None and not grading.counts_toward_badge(graded):
            return
        rows = (db().table("shield_completion_reports").select("shield_job_id")
                .eq("contractor_id", contractor_id)
                .eq("overall_verdict", "pass").execute().data or [])
        clean = {r["shield_job_id"] for r in rows if r.get("shield_job_id")}
        if len(clean) < config.get_int("MIN_CLEAN_JOBS"):
            return
        url = config.get("BADGE_WEBHOOK_URL")
        if not url:
            log.info("Contractor %s qualifies for the Shield badge; "
                     "BADGE_WEBHOOK_URL unset so no subscriber was notified",
                     contractor_id)
            return
        requests.post(url, timeout=10, json={
            "event": "shield.contractor_verified",
            "contractor_id": contractor_id,
            "clean_completions": len(clean),
            "awarded_at": utc_now_iso(),
        }, headers={"X-Shield-Secret": config.get("BADGE_WEBHOOK_SECRET") or ""})
    except Exception:
        log.exception("Badge evaluation failed for %s", contractor_id)


# ----------------------------------------------------------- subscriptions ---
@bp.route("/subscribe", methods=["POST"])
@require_auth
def subscribe():
    price_id = config.get("STRIPE_SHIELD_PRICE_ID")
    if not price_id:
        return _err("Subscriptions are not configured on this deployment", 503)
    # contractor_id is always the caller — the parent took it from the body,
    # letting anyone start a checkout attributed to someone else.
    contractor_id = g.user_id
    try:
        existing = (db().table("shield_subscriptions").select("stripe_customer_id")
                    .eq("contractor_id", contractor_id).limit(1).execute().data or [])
        customer_id = (existing[0].get("stripe_customer_id") if existing else None) \
            or stripe.Customer.create(metadata={"contractor_id": contractor_id}).id
        session = stripe.checkout.Session.create(
            customer=customer_id, mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=config.get("SHIELD_SUCCESS_URL") or "https://example.invalid/?s=ok",
            cancel_url=config.get("SHIELD_CANCEL_URL") or "https://example.invalid/?s=cancel",
            metadata={"contractor_id": contractor_id, "product": "shield_pro"},
        )
        return jsonify({"checkout_url": session.url})
    except stripe.StripeError:
        log.exception("Subscription checkout failed for %s", contractor_id)
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
        db().table("stripe_webhook_events").insert(
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
        job = (db().table("shield_jobs").select("*")
               .eq("stripe_payment_intent_id", obj["id"]).limit(1).execute().data or [])
        if not job:
            log.warning("payment_intent.succeeded %s matches no Shield job", obj["id"])
        else:
            job = job[0]
            received, currency = obj.get("amount_received"), obj.get("currency")
            if received != job.get("amount_cents") or currency != "usd":
                log.error("PAYMENT MISMATCH job=%s expected %s usd, received %s %s",
                          job["id"], job.get("amount_cents"), received, currency)
                try_log_custody(shield_job_id=job["id"], event_type="flagged",
                                actor_type="system",
                                integrity_note="Payment amount did not match the quoted price",
                                event_data={"expected_cents": job.get("amount_cents"),
                                            "received_cents": received, "currency": currency})
            else:
                db().table("shield_jobs").update({
                    "stripe_payment_id": obj["id"], "status": "active",
                    "activated_at": utc_now_iso(),
                }).eq("id", job["id"]).eq("status", "pending").execute()
                try_log_custody(shield_job_id=job["id"], event_type="activated",
                                actor_type="system",
                                event_data={"payment_intent": obj["id"],
                                            "amount_cents": received})
    elif kind in ("charge.refunded", "charge.dispute.created"):
        pi = obj.get("payment_intent")
        if pi:
            db().table("shield_jobs").update({
                "status": "refunded", "cancelled_at": utc_now_iso(),
            }).eq("stripe_payment_intent_id", pi).execute()
            log.info("Shield job refunded/disputed for intent %s", pi)
    elif kind == "customer.subscription.created":
        cid = obj.get("metadata", {}).get("contractor_id")
        if cid:
            db().table("shield_subscriptions").upsert({
                "contractor_id": cid, "stripe_customer_id": obj["customer"],
                "stripe_sub_id": obj["id"], "status": "active",
                "current_period_end": obj.get("current_period_end"),
            }, on_conflict="stripe_sub_id").execute()
    elif kind == "customer.subscription.updated":
        db().table("shield_subscriptions").update({
            "status": obj["status"], "current_period_end": obj.get("current_period_end"),
        }).eq("stripe_sub_id", obj["id"]).execute()
    elif kind in ("customer.subscription.deleted", "customer.subscription.paused"):
        db().table("shield_subscriptions").update(
            {"status": "cancelled"}).eq("stripe_sub_id", obj["id"]).execute()
    elif kind == "invoice.paid":
        sub_id = obj.get("subscription")
        if sub_id:
            period_end = ((obj.get("lines", {}).get("data") or [{}])[0]
                          .get("period", {}).get("end"))
            db().table("shield_subscriptions").update(
                {"status": "active", "current_period_end": period_end}
            ).eq("stripe_sub_id", sub_id).execute()

    return jsonify({"received": True})
