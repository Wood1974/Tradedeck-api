import base64
import binascii
import json
import logging
import os
import re
import anthropic
import stripe
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from supabase import create_client
import config
from auth import (
    draw_payee_id,
    get_draw,
    get_draw_schedule,
    get_escrow_for_draw,
    get_job,
    is_job_owner,
    is_schedule_owner,
    require_auth,
    require_draw_access,
    require_draw_owner,
    require_draw_payee,
    utc_now_iso,
)
from config import get_env, jobs_page_size, max_image_bytes
from escrow import (
    EscrowError,
    create_escrow_payment,
    mark_escrow_held,
    refund_escrow,
    release_escrow,
)
config.validate_env()
config.configure_logging()
log = logging.getLogger(__name__)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = max_image_bytes() * 2
CORS(
    app,
    origins=config.allowed_origins(),
    supports_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "OPTIONS"],
)
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
DRAW_PHOTOS_BUCKET = get_env("DRAW_PHOTOS_BUCKET", "draw-photos")
ANTHROPIC_MODEL = get_env("ANTHROPIC_MODEL", "claude-sonnet-4-6")
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
anthropic_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MIME_BY_EXT = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
@app.before_request
def attach_clients():
    g.supabase = supabase_admin
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response
def _error(message, status_code=400):
    return jsonify({"error": message}), status_code
def _escrow_error_response(exc: EscrowError):
    return jsonify({"error": exc.message}), exc.status_code
def _webhook_already_processed(event_id):
    result = (
        supabase_admin.table("stripe_webhook_events")
        .select("event_id")
        .eq("event_id", event_id)
        .limit(1)
        .execute()
    )
    return bool(result.data)
def _record_webhook_event(event_id, event_type):
    supabase_admin.table("stripe_webhook_events").insert(
        {
            "event_id": event_id,
            "event_type": event_type,
            "processed_at": utc_now_iso(),
        }
    ).execute()
def _decode_image(image_b64):
    if not isinstance(image_b64, str):
        raise ValueError("image_base64 must be a string")
    payload = image_b64.strip()
    if payload.startswith("data:"):
        _, _, payload = payload.partition(",")
        if not payload:
            raise ValueError("Invalid data URL for image_base64")
    try:
        image_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 image data") from exc
    if len(image_bytes) > max_image_bytes():
        raise ValueError(f"Image exceeds max size of {max_image_bytes()} bytes")
    if len(image_bytes) < 32:
        raise ValueError("Image data is too small")
    return image_bytes
def _media_type_for_path(storage_path):
    ext = os.path.splitext(storage_path)[1].lower()
    return MIME_BY_EXT.get(ext, "image/jpeg")
def _safe_storage_path(draw_id, requested_path=None):
    draw_id = str(draw_id)
    if requested_path:
        cleaned = re.sub(r"[^a-zA-Z0-9/_\-.]", "", str(requested_path))
        if cleaned.startswith("draws/") and draw_id in cleaned:
            return cleaned
    timestamp = utc_now_iso().replace(":", "-")
    return f"draws/{draw_id}/{timestamp}.jpg"
def _parse_ai_json(raw_text):
    raw = raw_text.strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())
def _analyze_photo(image_bytes, media_type):
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    prompt = (
        "You are a construction quality inspector reviewing a milestone photo for payment release. "
        'Respond ONLY with valid JSON: {"score":<0-100>,"passed":<true|false>,'
        '"summary":"<one sentence>","flags":[],"recommendations":[]} '
        "Score 80+ = passed. Be strict."
    )
    msg = anthropic_client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": image_b64,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }
        ],
    )
    return _parse_ai_json(msg.content[0].text)
@app.route("/")
def index():
    return jsonify({"status": "TradeDeck API running", "version": "2.1-secure"})
@app.route("/health")
def health():
    try:
        supabase_admin.table("jobs").select("id").limit(1).execute()
        return jsonify({"status": "ok"})
    except Exception:
        log.exception("Health check failed")
        return jsonify({"status": "degraded"}), 503
@app.route("/api/jobs", methods=["GET"])
def get_jobs():
    trade = request.args.get("trade", "")
    location = request.args.get("location", "")
    status = request.args.get("status", "open")
    try:
        limit = min(int(request.args.get("limit", jobs_page_size())), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return _error("limit and offset must be integers")
    try:
        query = (
            supabase_admin.table("jobs")
            .select("*", count="exact")
            .eq("status", status)
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
        )
        if trade:
            query = query.eq("trade", trade)
        if location:
            query = query.ilike("location", f"%{location[:80]}%")
        result = query.execute()
        return jsonify(
            {
                "jobs": result.data,
                "count": len(result.data),
                "total": result.count,
                "limit": limit,
                "offset": offset,
            }
        )
    except Exception:
        log.exception("Failed to fetch jobs")
        return _error("Could not fetch jobs", 503)
@app.route("/api/jobs", methods=["POST"])
@require_auth
def post_job():
    data = request.get_json(silent=True) or {}
    missing = [field for field in ["title", "trade", "location"] if not data.get(field)]
    if missing:
        return _error("Missing: " + ", ".join(missing))
    try:
        result = (
            supabase_admin.table("jobs")
            .insert(
                {
                    "owner_id": g.user_id,
                    "title": str(data["title"])[:200],
                    "trade": str(data["trade"])[:80],
                    "location": str(data["location"])[:200],
                    "description": str(data.get("description", ""))[:5000],
                    "budget": data.get("budget"),
                    "status": "open",
                }
            )
            .execute()
        )
        return jsonify({"success": True, "job": result.data[0]}), 201
    except Exception:
        log.exception("Failed to create job")
        return _error("Could not create job", 500)
@app.route("/stripe/connect/onboard", methods=["POST"])
@require_auth
def stripe_connect_onboard():
    data = request.get_json(silent=True) or {}
    user_id = g.user_id
    try:
        profile = (
            supabase_admin.table("profiles")
            .select("stripe_account_id,email")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        existing_account_id = profile.data[0].get("stripe_account_id") if profile.data else None
        email = data.get("email") or (profile.data[0].get("email") if profile.data else None)
        if existing_account_id:
            account_id = existing_account_id
        else:
            account = stripe.Account.create(
                type="express",
                email=email,
                capabilities={"transfers": {"requested": True}},
                metadata={"user_id": user_id},
                idempotency_key=f"connect-account-{user_id}",
            )
            account_id = account.id
            supabase_admin.table("profiles").update({"stripe_account_id": account_id}).eq(
                "id", user_id
            ).execute()
        base_url = get_env("APP_URL", "https://tradedeckapp.com")
        link = stripe.AccountLink.create(
            account=account_id,
            refresh_url=f"{base_url}/profile",
            return_url=f"{base_url}/profile?stripe=success",
            type="account_onboarding",
        )
        return jsonify({"url": link.url, "account_id": account_id})
    except Exception:
        log.exception("Stripe Connect onboarding failed for user %s", user_id)
        return _error("Could not start Stripe onboarding", 500)
@app.route("/stripe/escrow/create", methods=["POST"])
@require_auth
def escrow_create():
    data = request.get_json(silent=True) or {}
    missing = [field for field in ["job_id", "draw_id", "amount_cents"] if data.get(field) in (None, "")]
    if missing:
        return _error("Missing: " + ", ".join(missing))
    payload = dict(data)
    payload["payer_id"] = g.user_id
    try:
        result = create_escrow_payment(supabase_admin, payload, g.user_id)
        return jsonify(result)
    except EscrowError as exc:
        return _escrow_error_response(exc)
    except Exception:
        log.exception("Escrow create failed")
        return _error("Could not create escrow payment", 500)
@app.route("/stripe/escrow/release", methods=["POST"])
@require_auth
def escrow_release():
    data = request.get_json(silent=True) or {}
    draw_id = data.get("draw_id")
    if not draw_id:
        return _error("draw_id required")
    draw = get_draw(supabase_admin, draw_id)
    if not draw:
        return _error("Draw not found", 404)
    # draw.job_id is actually a draw_schedules id -- ownership is checked
    # against the schedule's own owner_id, not by looking draw.job_id up
    # in the jobs table directly (that table has a different id space).
    schedule = get_draw_schedule(supabase_admin, draw.get("job_id"))
    if not is_schedule_owner(schedule, g.user_id):
        return _error("Only the job owner can release escrow", 403)
    try:
        transfer_id = release_escrow(supabase_admin, draw_id)
        return jsonify({"success": True, "transfer_id": transfer_id})
    except EscrowError as exc:
        return _escrow_error_response(exc)
    except Exception:
        log.exception("Escrow release failed for draw %s", draw_id)
        return _error("Could not release escrow", 500)
@app.route("/stripe/escrow/refund", methods=["POST"])
@require_auth
def escrow_refund():
    data = request.get_json(silent=True) or {}
    draw_id = data.get("draw_id")
    if not draw_id:
        return _error("draw_id required")
    draw = get_draw(supabase_admin, draw_id)
    if not draw:
        return _error("Draw not found", 404)
    schedule = get_draw_schedule(supabase_admin, draw.get("job_id"))
    escrow = get_escrow_for_draw(supabase_admin, draw_id)
    if not is_schedule_owner(schedule, g.user_id) and not (
        escrow and escrow.get("payer_id") == g.user_id
    ):
        return _error("Only the job owner or payer can refund escrow", 403)
    try:
        refund_escrow(supabase_admin, draw_id)
        return jsonify({"success": True})
    except EscrowError as exc:
        return _escrow_error_response(exc)
    except Exception:
        log.exception("Escrow refund failed for draw %s", draw_id)
        return _error("Could not refund escrow", 500)
@app.route("/draws/<draw_id>", methods=["GET"])
@require_auth
@require_draw_access()
def get_draw_detail(draw_id):
    try:
        photos = (
            supabase_admin.table("draw_photos")
            .select("*")
            .eq("draw_id", draw_id)
            .execute()
        )
        return jsonify(
            {
                "draw": g.draw,
                "escrow": g.escrow,
                "photos": photos.data,
            }
        )
    except Exception:
        log.exception("Failed to fetch draw %s", draw_id)
        return _error("Could not fetch draw", 500)
@app.route("/draws/<draw_id>/approve", methods=["POST"])
@require_auth
@require_draw_owner()
def approve_draw(draw_id):
    draw = g.draw
    escrow = g.escrow
    if draw.get("status") != "submitted":
        return _error("Draw must be submitted (with photos) before owner approval", 409)
    if not escrow:
        return _error("No escrow record for this draw", 404)
    if escrow.get("status") != "held":
        return _error("Escrow must be funded and held before release", 409)
    try:
        supabase_admin.table("draws").update(
            {"status": "approved", "approved_at": utc_now_iso()}
        ).eq("id", draw_id).execute()
        transfer_id = release_escrow(supabase_admin, draw_id)
        return jsonify({"success": True, "transfer_id": transfer_id})
    except EscrowError as exc:
        return _escrow_error_response(exc)
    except Exception:
        log.exception("Draw approval failed for %s", draw_id)
        return _error("Could not approve draw", 500)
@app.route("/draws/<draw_id>/photos/upload", methods=["POST"])
@require_auth
@require_draw_payee()
def upload_photo(draw_id):
    data = request.get_json(silent=True) or {}
    image_b64 = data.get("image_base64")
    if not image_b64:
        return _error("image_base64 required")
    if g.draw.get("status") in ("approved", "released"):
        return _error("Cannot upload photos for a closed draw", 409)
    try:
        storage_path = _safe_storage_path(draw_id, data.get("storage_path"))
        image_bytes = _decode_image(image_b64)
        media_type = _media_type_for_path(storage_path)
        supabase_admin.storage.from_(DRAW_PHOTOS_BUCKET).upload(
            storage_path,
            image_bytes,
            {"content-type": media_type, "upsert": "false"},
        )
        ai = _analyze_photo(image_bytes, media_type)
        score = int(ai.get("score", 0))
        passed = bool(ai.get("passed", False))
        flags = ai.get("flags", [])
        photo_result = (
            supabase_admin.table("draw_photos")
            .insert(
                {
                    "draw_id": draw_id,
                    "uploaded_by": g.user_id,
                    "storage_path": storage_path,
                    "ai_analysis": ai,
                    "ai_passed": passed,
                    "ai_score": score,
                    "ai_summary": ai.get("summary", ""),
                    "ai_flags": flags,
                }
            )
            .execute()
        )
        # The AI's verdict lives only on this photo row, above -- it is
        # advisory only. The draw itself only ever moves to "submitted"
        # here (a real, valid status). A human -- the job owner -- still
        # has to review it and explicitly call /draws/<id>/approve to
        # move any money. The AI never approves or flags the draw itself.
        if g.draw.get("status") not in ("approved", "released"):
            supabase_admin.table("draws").update(
                {
                    "status": "submitted",
                    "submitted_at": utc_now_iso(),
                }
            ).eq("id", draw_id).execute()
        return jsonify(
            {
                "success": True,
                "photo_id": photo_result.data[0]["id"],
                "storage_path": storage_path,
                "ai_score": score,
                "ai_passed": passed,
                "ai_summary": ai.get("summary", ""),
                "ai_flags": flags,
                "ai_recommendations": ai.get("recommendations", []),
            }
        )
    except json.JSONDecodeError:
        return _error("AI returned invalid JSON", 500)
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception:
        log.exception("Photo upload failed for draw %s", draw_id)
        return _error("Could not upload photo", 500)
@app.route("/draws/<draw_id>/photos", methods=["GET"])
@require_auth
@require_draw_access()
def get_photos(draw_id):
    try:
        photos = (
            supabase_admin.table("draw_photos")
            .select("*")
            .eq("draw_id", draw_id)
            .execute()
        )
        return jsonify({"photos": photos.data})
    except Exception:
        log.exception("Failed to fetch photos for draw %s", draw_id)
        return _error("Could not fetch photos", 500)
@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    signature = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(
            request.data, signature, STRIPE_WEBHOOK_SECRET
        )
    except Exception:
        log.warning("Invalid Stripe webhook signature", exc_info=True)
        return _error("Invalid webhook signature", 400)
    event_id = event.get("id")
    event_type = event.get("type")
    if not event_id:
        return _error("Missing event id", 400)
    if _webhook_already_processed(event_id):
        return jsonify({"received": True, "duplicate": True})
    obj = event.get("data", {}).get("object", {})
    metadata = obj.get("metadata") or {}
    draw_id = metadata.get("draw_id")
    try:
        if event_type == "payment_intent.amount_capturable_updated" and draw_id:
            mark_escrow_held(supabase_admin, draw_id)
        elif event_type == "payment_intent.payment_failed" and draw_id:
            supabase_admin.table("stripe_escrow").update({"status": "failed"}).eq(
                "draw_id", draw_id
            ).eq("status", "pending").execute()
        elif event_type == "payment_intent.canceled" and draw_id:
            supabase_admin.table("stripe_escrow").update({"status": "refunded"}).eq(
                "draw_id", draw_id
            ).in_("status", ["pending", "held"]).execute()
        _record_webhook_event(event_id, event_type)
    except Exception:
        log.exception("Webhook processing failed for event %s", event_id)
        return _error("Webhook processing failed", 500)
    return jsonify({"received": True})
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
 
