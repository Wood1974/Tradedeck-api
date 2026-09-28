import base64
import binascii
import hashlib
import json
import logging
import os
import re
import anthropic
import requests
import stripe
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from supabase import create_client
import config
from auth import (
    get_job, is_job_owner, require_auth, utc_now_iso,
)
from config import get_env, jobs_page_size, max_image_bytes
try:
    from shield_api import shield_bp
except Exception as _shield_import_err:
    import logging as _log
    _log.getLogger(__name__).error("SHIELD IMPORT FAILED: %s", _shield_import_err, exc_info=True)
    from flask import Blueprint, jsonify
    shield_bp = Blueprint("shield", __name__, url_prefix="/shield")
    @shield_bp.route("/status")
    def _shield_error():
        return jsonify({"error": str(_shield_import_err)}), 500

config.validate_env()
config.configure_logging()
log = logging.getLogger(__name__)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = max_image_bytes() * 2
CORS(app, origins=config.allowed_origins(), supports_credentials=True,
     allow_headers=["Authorization", "Content-Type"], methods=["GET", "POST", "OPTIONS"])
app.register_blueprint(shield_bp)

stripe.api_key            = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET     = os.environ["STRIPE_WEBHOOK_SECRET"]
SUPABASE_URL              = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY      = os.environ["SUPABASE_SERVICE_KEY"]
ANTHROPIC_MODEL           = get_env("ANTHROPIC_MODEL", "claude-sonnet-4-6")


supabase_admin    = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
anthropic_client  = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

MIME_BY_EXT = {".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp"}

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

def _webhook_already_processed(event_id):
    result = supabase_admin.table("stripe_webhook_events").select("event_id").eq("event_id", event_id).limit(1).execute()
    return bool(result.data)

def _record_webhook_event(event_id, event_type):
    supabase_admin.table("stripe_webhook_events").insert({"event_id": event_id, "event_type": event_type, "processed_at": utc_now_iso()}).execute()

def _decode_image(image_b64):
    if not isinstance(image_b64, str): raise ValueError("image_base64 must be a string")
    payload = image_b64.strip()
    if payload.startswith("data:"):
        _, _, payload = payload.partition(",")
        if not payload: raise ValueError("Invalid data URL")
    try:
        image_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 image data") from exc
    if len(image_bytes) > max_image_bytes(): raise ValueError(f"Image exceeds max size")
    if len(image_bytes) < 32: raise ValueError("Image data too small")
    return image_bytes

def _media_type_for_path(storage_path):
    return MIME_BY_EXT.get(os.path.splitext(storage_path)[1].lower(), "image/jpeg")

# ── ROUTES ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"status": "TradeDeck API running", "version": "2.2-shield"})

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
    trade = request.args.get("trade",""); location = request.args.get("location",""); status = request.args.get("status","open")
    try:
        limit = min(int(request.args.get("limit", jobs_page_size())), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return _error("limit and offset must be integers")
    try:
        query = supabase_admin.table("jobs").select("*", count="exact").eq("status", status).order("created_at", desc=True).range(offset, offset+limit-1)
        if trade: query = query.eq("trade", trade)
        if location: query = query.ilike("location", f"%{location[:80]}%")
        result = query.execute()
        return jsonify({"jobs":result.data,"count":len(result.data),"total":result.count,"limit":limit,"offset":offset})
    except Exception:
        log.exception("Failed to fetch jobs")
        return _error("Could not fetch jobs", 503)

@app.route("/api/jobs", methods=["POST"])
@require_auth
def post_job():
    data = request.get_json(silent=True) or {}
    missing = [f for f in ["title","trade","location"] if not data.get(f)]
    if missing: return _error("Missing: " + ", ".join(missing))
    try:
        result = supabase_admin.table("jobs").insert({"owner_id":g.user_id,"title":str(data["title"])[:200],"trade":str(data["trade"])[:80],"location":str(data["location"])[:200],"description":str(data.get("description",""))[:5000],"budget":data.get("budget"),"status":"open"}).execute()
        return jsonify({"success":True,"job":result.data[0]}), 201
    except Exception:
        log.exception("Failed to create job")
        return _error("Could not create job", 500)

@app.route("/stripe/connect/onboard", methods=["POST"])
@require_auth
def stripe_connect_onboard():
    data = request.get_json(silent=True) or {}
    user_id = g.user_id
    try:
        profile = supabase_admin.table("profiles").select("stripe_account_id,email").eq("id",user_id).limit(1).execute()
        existing_account_id = profile.data[0].get("stripe_account_id") if profile.data else None
        email = data.get("email") or (profile.data[0].get("email") if profile.data else None)
        if existing_account_id:
            account_id = existing_account_id
        else:
            account = stripe.Account.create(type="express",email=email,capabilities={"transfers":{"requested":True}},metadata={"user_id":user_id},idempotency_key=f"connect-account-{user_id}")
            account_id = account.id
            supabase_admin.table("profiles").update({"stripe_account_id":account_id}).eq("id",user_id).execute()
        base_url = get_env("APP_URL","https://tradedeckapp.com")
        link = stripe.AccountLink.create(account=account_id,refresh_url=f"{base_url}/profile",return_url=f"{base_url}/profile?stripe=success",type="account_onboarding")
        return jsonify({"url":link.url,"account_id":account_id})
    except Exception:
        log.exception("Stripe Connect onboarding failed for %s", user_id)
        return _error("Could not start Stripe onboarding", 500)

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    signature = request.headers.get("Stripe-Signature","")
    try:
        event = stripe.Webhook.construct_event(request.data, signature, STRIPE_WEBHOOK_SECRET)
    except Exception:
        log.warning("Invalid Stripe webhook signature", exc_info=True)
        return _error("Invalid webhook signature", 400)
    event_id = event.get("id"); event_type = event.get("type")
    if not event_id: return _error("Missing event id", 400)
    if _webhook_already_processed(event_id): return jsonify({"received":True,"duplicate":True})
    try:
        _record_webhook_event(event_id, event_type)
    except Exception:
        log.exception("Webhook processing failed for event %s", event_id)
        return _error("Webhook processing failed", 500)
    return jsonify({"received":True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
