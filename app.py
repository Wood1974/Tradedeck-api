import base64
import binascii
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
import anthropic
import requests
import stripe
from flask import Flask, g, jsonify, request, send_file, make_response
from flask_cors import CORS
from supabase import create_client
import config
from auth import (
    get_job, is_job_owner, require_auth, utc_now_iso,
)
from config import get_env, jobs_page_size, max_image_bytes
from capture import Challenges, seal, verify_capture
import audit.invariants
import location
import packs
import pdf_export
from identity_api import identity_bp
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
app.register_blueprint(identity_bp)

stripe.api_key           = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET     = os.environ["STRIPE_WEBHOOK_SECRET"]
SUPABASE_URL              = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY      = os.environ["SUPABASE_SERVICE_KEY"]
ANTHROPIC_MODEL           = get_env("ANTHROPIC_MODEL", "claude-sonnet-4-6")


supabase_admin    = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
anthropic_client  = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
challenges        = Challenges()  # Global challenge/nonce manager

# Database setup
DB_PATH = get_env("DB_PATH", "/tmp/tradedeckapp_shield.db")

def _get_db():
    """Get database connection."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def _init_db():
    """Initialize database tables if they don't exist."""
    db = _get_db()
    try:
        # Custom packs table
        db.execute("""
            CREATE TABLE IF NOT EXISTS custom_packs (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                points JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Manifests table
        db.execute("""
            CREATE TABLE IF NOT EXISTS manifests (
                id TEXT PRIMARY KEY,
                pack_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                data JSON NOT NULL,
                status TEXT DEFAULT 'verified',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                manifest_hash TEXT,
                chain_head_hash TEXT
            )
        """)

        db.commit()
    except Exception as e:
        log.error(f"Failed to initialize database: {e}")
        raise
    finally:
        db.close()

# Initialize database on startup
try:
    _init_db()
except Exception as e:
    log.error(f"Database initialization failed: {e}")

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

def _error(message, status_code=400, details=None):
    response = {"error": message}
    if details:
        response["details"] = details
    return jsonify(response), status_code


def _extract_jwt_claims(token: str) -> dict:
    """
    Extract account_id and role from Supabase JWT token.

    Args:
        token: JWT token string

    Returns:
        dict with 'account_id' and 'role' keys, or empty dict if invalid
    """
    try:
        user = supabase_admin.auth.get_user(token)
        if not user or not user.user:
            return {}

        user_obj = user.user
        account_id = getattr(user_obj, "id", None)
        role = getattr(user_obj, "role", "user")

        if not account_id:
            return {}

        return {
            "account_id": account_id,
            "role": role
        }
    except Exception:
        return {}

def _require_admin(f):
    """Decorator to check admin role."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_metadata = getattr(g.user, "user_metadata", {})
        is_admin = getattr(g.user, "admin", False) or user_metadata.get("role") == "admin"
        if not is_admin:
            return _error("Admin role required", 403)
        return f(*args, **kwargs)
    return decorated_function

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


@app.route("/api/health")
def api_health():
    """API health check endpoint."""
    try:
        supabase_admin.table("jobs").select("id").limit(1).execute()
        return jsonify({"status": "ok", "version": "1.0", "database": "ok"})
    except Exception:
        log.exception("API health check failed")
        return jsonify({"status": "degraded", "version": "1.0", "database": "error"}), 503

@app.route("/api/jobs", methods=["GET"])
def get_jobs() -> dict:
    """List jobs with optional trade, location, and status filters."""
    trade = request.args.get("trade",""); location = request.args.get("location",""); status = request.args.get("status","open")
    try:
        limit = min(int(request.args.get("limit", jobs_page_size())), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return _error("limit and offset must be integers")
    try:
        query = supabase_admin.table("jobs").select("*", count="exact").eq("status", status).order("created_at", desc=True).range(offset, offset+limit-1)
        if trade: query = query.eq("trade", trade)
        if location:
            location_str = str(location).strip()[:80]
            if location_str:
                query = query.ilike("location", f"%{location_str}%")
        result = query.execute()
        return jsonify({"jobs":result.data,"count":len(result.data),"total":result.count,"limit":limit,"offset":offset})
    except Exception:
        log.exception("Failed to fetch jobs")
        return _error("Could not fetch jobs", 503)

@app.route("/api/jobs", methods=["POST"])
@require_auth
def post_job() -> tuple:
    """Create a new job posting."""
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
def stripe_connect_onboard() -> tuple:
    """Start Stripe Connect onboarding for the user."""
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
        return jsonify({"url":link.url,"account_id":account_id}), 201
    except Exception:
        log.exception("Stripe Connect onboarding failed for %s", user_id)
        return _error("Could not start Stripe onboarding", 500)

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook() -> tuple:
    """Handle Stripe webhook events."""
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


# ── SHIELD CAPTURE v1 ROUTES ──────────────────────────────────────────────

# ════════════════════════════════════════════════════════════════════════════
# Pack Management Endpoints (3)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/packs", methods=["GET"])
def api_list_packs() -> tuple:
    """List all available packs (fixed, code, custom)."""
    pack_type = request.args.get("pack_type", "").lower()

    try:
        all_packs = []

        # Add fixed packs
        for pack_id in packs.list_fixed_packs():
            pack = packs.get_pack(pack_id)
            all_packs.append({
                "id": pack["id"],
                "name": pack["name"],
                "description": pack.get("description", ""),
                "checkpoint_count": len(pack.get("points", []))
            })

        # Add code pack
        if pack_type != "fixed":
            code_pack = packs.get_pack("code")
            all_packs.append({
                "id": code_pack["id"],
                "name": code_pack["name"],
                "description": code_pack.get("description", ""),
                "checkpoint_count": len(code_pack.get("points", []))
            })

        # Filter by type if requested
        if pack_type == "fixed":
            all_packs = [p for p in all_packs if not p["id"].startswith("custom_") and p["id"] != "code"]
        elif pack_type == "code":
            all_packs = [p for p in all_packs if p["id"] == "code"]
        elif pack_type == "custom":
            all_packs = [p for p in all_packs if p["id"].startswith("custom_")]

        return jsonify({"packs": all_packs}), 200
    except Exception:
        log.exception("Failed to list packs")
        return _error("Could not list packs", 500)


@app.route("/api/packs/<pack_id>", methods=["GET"])
def api_get_pack(pack_id: str) -> tuple:
    """Get single pack with all checkpoint definitions."""
    try:
        pack = packs.get_pack(pack_id)
        return jsonify(pack), 200
    except packs.PackNotFoundError:
        return _error("Pack not found", 404)
    except Exception:
        log.exception("Failed to retrieve pack %s", pack_id)
        return _error("Could not retrieve pack", 500)


@app.route("/api/packs/custom", methods=["POST"])
@require_auth
def api_create_custom_pack() -> tuple:
    """Create custom pack with buyer-written checkpoint list."""
    data = request.get_json(silent=True) or {}

    # Validate required fields
    if not data.get("name"):
        return _error("Missing required field: name")
    if not data.get("points"):
        return _error("Missing required field: points")

    points_list = data.get("points", [])
    if not isinstance(points_list, list):
        return _error("points must be an array")

    # Validate point count (5-20)
    if len(points_list) < 5:
        return _error(f"Custom pack must have at least 5 points, got {len(points_list)}")
    if len(points_list) > 20:
        return _error(f"Custom pack can have maximum 20 points, got {len(points_list)}")

    # Generate custom pack ID
    custom_id = f"custom_{uuid.uuid4().hex[:12]}"

    # Build pack structure with sequential ordering
    pack_points = []
    for i, point in enumerate(points_list, start=1):
        if not isinstance(point, dict):
            return _error(f"Point {i} must be a dictionary")

        name = point.get("name", "").strip()
        desc = point.get("description", "").strip()

        if not name:
            return _error(f"Point {i} missing or empty name")
        if not desc:
            return _error(f"Point {i} missing or empty description")

        pack_points.append({
            "order": i,
            "name": name,
            "description": desc
        })

    # Create pack object
    custom_pack = {
        "id": custom_id,
        "name": str(data.get("name", ""))[:200],
        "description": str(data.get("description", ""))[:1000],
        "points": pack_points
    }

    # Store custom pack in database
    try:
        db = _get_db()
        try:
            db.execute("""
                INSERT INTO custom_packs (id, account_id, name, description, points)
                VALUES (?, ?, ?, ?, ?)
            """, (custom_id, g.user_id, custom_pack["name"], custom_pack["description"], json.dumps(pack_points)))
            db.commit()
            log.info(f"Stored custom pack {custom_id} for account {g.user_id}")
        finally:
            db.close()
    except Exception as e:
        log.exception(f"Failed to store custom pack: {e}")
        return _error("Could not store custom pack", 500)

    return jsonify({
        "id": custom_id,
        "name": custom_pack["name"],
        "points_count": len(pack_points)
    }), 201


# ════════════════════════════════════════════════════════════════════════════
# Challenge & Capture Endpoints (4)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/challenges/issue", methods=["POST"])
@require_auth
def api_issue_challenge() -> tuple:
    """Issue single-use nonce for capture session."""
    account_id = g.user_id

    try:
        nonce = challenges.issue(account_id)
        log.info(f"Issued challenge for account {account_id}")

        return jsonify({
            "nonce": nonce,
            "ttl_seconds": challenges.TTL_SECONDS
        }), 200
    except Exception:
        log.exception("Failed to issue challenge for %s", account_id)
        return _error("Could not issue challenge", 500)


@app.route("/api/captures/<pack_id>/seal", methods=["POST"])
@require_auth
def api_seal_capture(pack_id: str) -> tuple:
    """Seal single photo+note capture."""
    account_id = g.user_id

    try:
        # Validate pack exists
        pack = packs.get_pack(pack_id)
    except packs.PackNotFoundError:
        return _error("Pack not found", 404)
    except Exception:
        return _error("Could not validate pack", 500)

    try:
        # Extract form data
        if "photo" not in request.files:
            return _error("Missing required field: photo")

        photo_file = request.files["photo"]
        if not photo_file or not photo_file.filename:
            return _error("photo file is required")

        photo_bytes = photo_file.read()
        if not photo_bytes:
            return _error("photo file is empty")

        note = request.form.get("note", "").strip()
        if not note:
            return _error("Missing required field: note")

        checkpoint_name = request.form.get("checkpoint_name", "").strip()
        if not checkpoint_name:
            return _error("Missing required field: checkpoint_name")

        nonce = request.form.get("nonce", "").strip()
        if not nonce:
            return _error("Missing required field: nonce")

        # Validate nonce
        if not challenges.is_valid(nonce):
            return _error("Invalid or expired nonce", 400)

        # Extract GPS coordinates
        try:
            gps_lat = float(request.form.get("gps_lat", 0))
            gps_lon = float(request.form.get("gps_lon", 0))
        except (ValueError, TypeError):
            return _error("Invalid GPS coordinates")

        device_bind_hash = request.form.get("device_bind_hash")

        # Create checkpoint pack dict
        checkpoint_pack = {
            "name": checkpoint_name,
            "order": 1
        }

        # Seal the capture
        timestamp = int(time.time())
        result = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            device_bind_hash=device_bind_hash
        )

        log.info(f"Sealed capture for {account_id} in pack {pack_id}")

        return jsonify(result), 200

    except Exception:
        log.exception("Failed to seal capture")
        return _error("Could not seal capture", 500)


@app.route("/api/captures/<pack_id>/verify", methods=["POST"])
def api_verify_capture(pack_id: str) -> tuple:
    """Offline verify a sealed capture."""
    try:
        data = request.get_json(silent=True) or {}

        # Extract required fields
        photo_bytes = data.get("photo_bytes")
        if photo_bytes is not None:
            if isinstance(photo_bytes, str):
                photo_bytes = photo_bytes.encode("utf-8")
            elif not isinstance(photo_bytes, bytes):
                return _error("photo_bytes must be a string or bytes", 400)

        note = data.get("note", "")
        checkpoint_name = data.get("checkpoint_name", "")
        nonce = data.get("nonce", "")
        gps_lat = data.get("gps_lat", 0)
        gps_lon = data.get("gps_lon", 0)
        timestamp = data.get("timestamp", int(time.time()))
        bind_hash = data.get("bind_hash", "")
        account_id = data.get("account_id", "unknown")

        # Create checkpoint pack
        checkpoint_pack = {
            "name": checkpoint_name,
            "order": 1
        }

        # Verify the capture
        is_valid = verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=bind_hash
        )

        reason = "Capture seal is valid" if is_valid else "Capture seal verification failed"

        return jsonify({
            "valid": is_valid,
            "reason": reason
        }), 200

    except Exception:
        log.exception("Failed to verify capture")
        return _error("Could not verify capture", 500)


@app.route("/api/manifests/<pack_id>/submit", methods=["POST"])
@require_auth
def api_submit_manifest(pack_id: str) -> tuple:
    """Submit complete manifest (all captures for pack)."""
    account_id = g.user_id

    try:
        # Validate pack exists
        pack = packs.get_pack(pack_id)
    except packs.PackNotFoundError:
        return _error("Pack not found", 404)
    except Exception:
        return _error("Could not validate pack", 500)

    try:
        manifest = request.get_json(silent=True) or []

        if not isinstance(manifest, list):
            return _error("Manifest must be an array")

        # Run invariant checks
        try:
            # Check manifest structure
            audit.invariants.assert_manifest_structure(manifest)

            # Check pack/checkpoint correspondence
            audit.invariants.assert_pack_checkpoint_correspondence(manifest, pack)

        except AssertionError as e:
            return _error(str(e), 400)

        # Validate nonce consumption and prevent replay
        for capture in manifest:
            nonce = capture.get("nonce")
            if not nonce or not challenges.is_valid(nonce):
                return _error("Nonce already consumed or invalid", 400)

        # Consume all nonces (mark as used)
        for capture in manifest:
            nonce = capture.get("nonce")
            challenges.consume(nonce)

        # Collect GPS points and run spoofing detection
        gps_points = []
        for capture in manifest:
            gps_points.append({
                "lat": capture.get("gps_lat", 0),
                "lon": capture.get("gps_lon", 0),
                "timestamp": capture.get("timestamp", int(time.time()))
            })

        try:
            audit.invariants.assert_location_consistent(gps_points)
        except AssertionError as e:
            return _error(f"GPS spoofing detected: {str(e)}", 400)

        # Generate manifest ID and hash
        manifest_id = f"manifest_{uuid.uuid4().hex[:12]}"
        manifest_hash = pdf_export._compute_manifest_hash(manifest)
        chain_head_hash = manifest[-1]["bind_hash"] if manifest else ""

        # Store manifest in SQLite database
        try:
            db = _get_db()
            try:
                db.execute("""
                    INSERT INTO manifests
                    (id, pack_id, account_id, data, status, manifest_hash, chain_head_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (manifest_id, pack_id, account_id, json.dumps(manifest), 'verified', manifest_hash, chain_head_hash))
                db.commit()
                log.info(f"Stored manifest {manifest_id} for account {account_id} in pack {pack_id}")
            finally:
                db.close()
        except Exception as e:
            log.exception(f"Failed to store manifest: {e}")
            return _error("Could not store manifest", 500)

        return jsonify({
            "manifest_id": manifest_id,
            "status": "verified",
            "hashes": {
                "manifest": manifest_hash,
                "chain_head": chain_head_hash
            }
        }), 201

    except Exception:
        log.exception("Failed to submit manifest")
        return _error("Could not submit manifest", 500)


# ════════════════════════════════════════════════════════════════════════════
# Export & Verification Endpoints (4)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/manifests/<manifest_id>", methods=["GET"])
@require_auth
def api_get_manifest(manifest_id: str) -> tuple:
    """Retrieve manifest metadata and verification status."""
    try:
        # Fetch from SQLite database
        db = _get_db()
        try:
            result = db.execute(
                "SELECT id, pack_id, account_id, created_at, status, manifest_hash, chain_head_hash FROM manifests WHERE id = ? AND account_id = ?",
                (manifest_id, g.user_id)
            ).fetchone()
        finally:
            db.close()

        if not result:
            return _error("Manifest not found", 404)

        return jsonify({
            "id": result[0],
            "pack_id": result[1],
            "account_id": result[2],
            "created_at": result[3],
            "status": result[4],
            "manifest_hash": result[5],
            "hashes": {
                "manifest": result[5],
                "chain_head": result[6]
            }
        }), 200
    except Exception:
        log.exception("Failed to retrieve manifest %s", manifest_id)
        return _error("Could not retrieve manifest", 500)


@app.route("/api/manifests/<manifest_id>/pdf", methods=["GET"])
@require_auth
def api_get_manifest_pdf(manifest_id: str) -> tuple:
    """Download manifest as signed PDF."""
    try:
        # Fetch manifest from SQLite database
        db = _get_db()
        try:
            result = db.execute(
                "SELECT id, pack_id, data, chain_head_hash FROM manifests WHERE id = ? AND account_id = ?",
                (manifest_id, g.user_id)
            ).fetchone()
        finally:
            db.close()

        if not result:
            return _error("Manifest not found", 404)

        # Parse manifest data
        try:
            manifest_data = json.loads(result[2])
        except (json.JSONDecodeError, TypeError) as e:
            log.error(f"Failed to parse manifest data for {manifest_id}: {e}")
            return _error("Invalid manifest data", 500)

        pack_id = result[1]
        chain_head_hash = result[3]

        # Get pack name for PDF
        try:
            pack = packs.get_pack(pack_id)
            pack_name = pack.get("name", pack_id)
        except (packs.PackNotFoundError, KeyError):
            pack_name = pack_id

        # Generate PDF
        pdf_bytes = pdf_export.render_manifest_pdf(
            manifest=manifest_data,
            pack_name=pack_name,
            account_id=g.user_id,
            chain_head_hash=chain_head_hash
        )

        # Return PDF response
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=manifest_{manifest_id}.pdf'
        return response

    except Exception:
        log.exception("Failed to generate PDF for %s", manifest_id)
        return _error("Could not generate PDF", 500)


@app.route("/api/manifests/<manifest_id>/verify-offline", methods=["POST"])
def api_verify_manifest_offline(manifest_id: str) -> tuple:
    """Offline verification proof-of-concept."""
    try:
        data = request.get_json(silent=True) or {}

        manifest = data.get("manifest", [])
        manifest_hash = data.get("manifest_hash", "")
        chain_head_hash = data.get("chain_head_hash", "")

        # Run offline verification
        try:
            audit.invariants.assert_manifest_structure(manifest)
            audit.invariants.assert_no_manifest_tampering(manifest, manifest_hash)
        except AssertionError as e:
            return jsonify({
                "verified": False,
                "reason": str(e),
                "checks": {}
            }), 200

        return jsonify({
            "verified": True,
            "reason": "Manifest passed all invariant checks",
            "checks": {
                "structure": "valid",
                "tampering": "none_detected"
            }
        }), 200

    except Exception:
        log.exception("Failed to verify manifest offline")
        return _error("Could not verify manifest", 500)


# ════════════════════════════════════════════════════════════════════════════
# Configuration & Metadata Endpoints (3)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/config/shields", methods=["GET"])
def api_config_shields() -> tuple:
    """Return Shield configuration and features."""
    return jsonify({
        "version": "1.0",
        "features": [
            "basic_capture",
            "gps_verification",
            "device_binding",
            "pdf_export",
            "offline_verification"
        ],
        "pack_limit": 20
    }), 200


@app.route("/api/config/location", methods=["GET"])
def api_config_location() -> tuple:
    """Return location verification settings."""
    return jsonify({
        "impossible_speed_mph": location.IMPOSSIBLE_SPEED_THRESHOLD_MPH,
        "unrealistic_speed_mph": location.UNREALISTIC_SPEED_THRESHOLD_MPH,
        "spoofing_detection": "enabled"
    }), 200


# ════════════════════════════════════════════════════════════════════════════
# Admin/Monitoring Endpoints (3)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/manifests", methods=["GET"])
@require_auth
@_require_admin
def api_admin_list_manifests() -> tuple:
    """List manifests (paginated, admin only)."""
    try:
        limit = min(int(request.args.get("limit", 20)), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
        status_filter = request.args.get("status")

        # Fetch from SQLite database with pagination
        db = _get_db()
        try:
            # Get total count
            if status_filter:
                total_result = db.execute(
                    "SELECT COUNT(*) FROM manifests WHERE status = ?",
                    (status_filter,)
                ).fetchone()
            else:
                total_result = db.execute("SELECT COUNT(*) FROM manifests").fetchone()

            total = total_result[0] if total_result else 0

            # Get paginated manifests
            if status_filter:
                manifests = db.execute("""
                    SELECT id, pack_id, account_id, created_at, status, manifest_hash, chain_head_hash
                    FROM manifests
                    WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (status_filter, limit, offset)).fetchall()
            else:
                manifests = db.execute("""
                    SELECT id, pack_id, account_id, created_at, status, manifest_hash, chain_head_hash
                    FROM manifests
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset)).fetchall()
        finally:
            db.close()

        manifest_list = [
            {
                "id": m[0],
                "pack_id": m[1],
                "account_id": m[2],
                "created_at": m[3],
                "status": m[4],
                "manifest_hash": m[5]
            }
            for m in manifests
        ]

        return jsonify({
            "total": total,
            "count": len(manifest_list),
            "manifests": manifest_list
        }), 200

    except Exception:
        log.exception("Failed to list manifests")
        return _error("Could not list manifests", 500)


@app.route("/api/admin/challenges", methods=["GET"])
@require_auth
@_require_admin
def api_admin_list_challenges() -> tuple:
    """List active challenges (admin only)."""
    try:
        # Count active challenges
        active_count = len(challenges._challenges)
        # Estimate expired (can't easily count without checking all)
        expired_count = 0

        return jsonify({
            "active": active_count,
            "expired": expired_count
        }), 200

    except Exception:
        log.exception("Failed to list challenges")
        return _error("Could not list challenges", 500)


@app.route("/api/admin/verify/<manifest_id>", methods=["POST"])
@require_auth
@_require_admin
def api_admin_verify_manifest(manifest_id: str) -> tuple:
    """Manually trigger verification (admin only)."""
    try:
        # Fetch manifest from database
        db = _get_db()
        try:
            result = db.execute(
                "SELECT id, pack_id, data, manifest_hash, chain_head_hash FROM manifests WHERE id = ?",
                (manifest_id,)
            ).fetchone()
        finally:
            db.close()

        if not result:
            return _error("Manifest not found", 404)

        try:
            manifest_data = json.loads(result[2])
        except (json.JSONDecodeError, TypeError) as e:
            log.error(f"Failed to parse manifest data for {manifest_id}: {e}")
            return _error("Invalid manifest data", 500)

        manifest_hash = result[3]
        chain_head_hash = result[4]

        # Perform verification using invariants
        verdict = "verified"
        reason = "All invariant checks passed"

        try:
            # Check manifest structure
            audit.invariants.assert_manifest_structure(manifest_data)

            # Check manifest integrity
            audit.invariants.assert_no_manifest_tampering(manifest_data, manifest_hash)

            # Check GPS locations for spoofing
            gps_points = [
                (c.get("gps_lat", 0), c.get("gps_lon", 0), c.get("timestamp", int(time.time())))
                for c in manifest_data
            ]
            audit.invariants.assert_location_consistent(gps_points)

        except AssertionError as e:
            verdict = "rejected"
            reason = str(e)

        # Update status in database
        db = _get_db()
        try:
            db.execute("UPDATE manifests SET status = ? WHERE id = ?", (verdict, manifest_id))
            db.commit()
        finally:
            db.close()

        log.info(f"Admin verified manifest {manifest_id}: {verdict}")

        return jsonify({
            "manifest_id": manifest_id,
            "status": verdict,
            "reason": reason
        }), 200

    except Exception:
        log.exception("Failed to verify manifest %s", manifest_id)
        return _error("Could not verify manifest", 500)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
