import os
import json
import base64
import re
from datetime import datetime
from functools import wraps

import anthropic
import stripe
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

app = Flask(__name__)
CORS(app)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "draw-photos")

_supabase = None
_anthropic = None


class ConfigError(Exception):
    pass


def _valid_supabase_url(url):
    return bool(re.match(r"^https://[a-z0-9]+\.supabase\.co/?$", url.rstrip("/")))


def get_supabase():
    global _supabase
    if _supabase is None:
        url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
        key = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
        if not url or not key:
            raise ConfigError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in the environment")
        if not _valid_supabase_url(url):
            raise ConfigError(
                "SUPABASE_URL must be your project API URL (https://<project-ref>.supabase.co), "
                "not the Supabase dashboard URL"
            )
        _supabase = create_client(url, key)
    return _supabase


def get_anthropic():
    global _anthropic
    if _anthropic is None:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            raise ConfigError("ANTHROPIC_API_KEY must be set for photo AI checks")
        _anthropic = anthropic.Anthropic(api_key=key)
    return _anthropic


def _sanitize_error(exc):
    msg = str(exc)
    if "JSON could not be generated" in msg or "<!DOCTYPE html>" in msg:
        return (
            "Supabase request failed — check SUPABASE_URL points to "
            "https://<project-ref>.supabase.co and tables exist (see tradedeck_schema.sql)"
        )
    return msg


def get_auth_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        res = get_supabase().auth.get_user(auth[7:])
        return res.user if res else None
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user = get_auth_user()
        if not user:
            return jsonify({"error": "Authorization required"}), 401
        return f(user, *args, **kwargs)

    return wrapped


def handle_errors(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ConfigError as e:
            return jsonify({"error": str(e)}), 503
        except Exception as e:
            return jsonify({"error": _sanitize_error(e)}), 500

    return wrapped


def _verify_draw_owner(draw_id, user_id):
    dr = get_supabase().table("draws").select("job_id").eq("id", draw_id).execute()
    if not dr.data:
        return False, "Draw not found"
    jr = get_supabase().table("jobs").select("owner_id").eq("id", dr.data[0]["job_id"]).execute()
    if not jr.data:
        return False, "Job not found"
    if str(jr.data[0]["owner_id"]) != str(user_id):
        return False, "Only the job owner can approve this draw"
    return True, None


@app.route("/")
def index():
    return jsonify({"status": "TradeDeck API running", "version": "2.1"})


@app.route("/health")
@handle_errors
def health():
    status = {"status": "ok", "version": "2.1", "checks": {}}

    url = os.environ.get("SUPABASE_URL", "").strip()
    if not url:
        status["checks"]["supabase"] = "missing SUPABASE_URL"
        status["status"] = "degraded"
    elif not _valid_supabase_url(url.rstrip("/")):
        status["checks"]["supabase"] = "invalid SUPABASE_URL (use https://<ref>.supabase.co)"
        status["status"] = "degraded"
    elif not os.environ.get("SUPABASE_SERVICE_KEY", "").strip():
        status["checks"]["supabase"] = "missing SUPABASE_SERVICE_KEY"
        status["status"] = "degraded"
    else:
        get_supabase().table("jobs").select("id").limit(1).execute()
        status["checks"]["supabase"] = "ok"

    if not stripe.api_key:
        status["checks"]["stripe"] = "missing STRIPE_SECRET_KEY"
        status["status"] = "degraded"
    else:
        status["checks"]["stripe"] = "configured"

    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        status["checks"]["anthropic"] = "missing ANTHROPIC_API_KEY"
    else:
        status["checks"]["anthropic"] = "configured"

    code = 200 if status["status"] == "ok" else 503
    return jsonify(status), code


@app.route("/api/jobs", methods=["GET"])
@handle_errors
def get_jobs():
    trade = request.args.get("trade", "")
    location = request.args.get("location", "")
    status = request.args.get("status", "open")
    q = get_supabase().table("jobs").select("*").eq("status", status)
    if trade:
        q = q.eq("trade", trade)
    if location:
        q = q.ilike("location", f"%{location}%")
    r = q.order("created_at", desc=True).execute()
    return jsonify({"jobs": r.data, "count": len(r.data)})


@app.route("/api/jobs", methods=["POST"])
@handle_errors
def post_job():
    data = request.get_json(silent=True) or {}
    missing = [f for f in ["title", "trade", "location", "owner_id"] if not data.get(f)]
    if missing:
        return jsonify({"error": "Missing: " + ", ".join(missing)}), 400
    r = get_supabase().table("jobs").insert({
        "owner_id": data["owner_id"],
        "title": data["title"],
        "trade": data["trade"],
        "location": data["location"],
        "description": data.get("description", ""),
        "budget": data.get("budget"),
        "status": "open",
    }).execute()
    return jsonify({"success": True, "job": r.data[0]}), 201


@app.route("/api/jobs/<job_id>/apply", methods=["POST"])
@handle_errors
def apply_to_job(job_id):
    data = request.get_json(silent=True) or {}
    user = get_auth_user()
    row = {
        "job_id": job_id,
        "user_id": user.id if user else data.get("user_id"),
        "name": data.get("name", ""),
        "email": data.get("email", ""),
        "message": data.get("message", ""),
    }
    if not row["user_id"] and not row["email"]:
        return jsonify({"error": "user_id or email required"}), 400
    get_supabase().table("applications").insert(row).execute()
    return jsonify({"success": True})


@app.route("/stripe/connect/onboard", methods=["POST"])
@require_auth
@handle_errors
def stripe_connect_onboard(user):
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    if str(user.id) != str(user_id):
        return jsonify({"error": "user_id must match authenticated user"}), 403
    acct = stripe.Account.create(
        type="express",
        email=data.get("email") or user.email,
        capabilities={"transfers": {"requested": True}},
    )
    get_supabase().table("profiles").update({"stripe_account_id": acct.id}).eq("id", user_id).execute()
    base_url = os.environ.get("APP_URL", "https://tradedeckapp.com")
    link = stripe.AccountLink.create(
        account=acct.id,
        refresh_url=base_url + "/profile",
        return_url=base_url + "/profile?stripe=success",
        type="account_onboarding",
    )
    return jsonify({"url": link.url, "account_id": acct.id})


@app.route("/stripe/escrow/create", methods=["POST"])
@require_auth
@handle_errors
def escrow_create(user):
    data = request.get_json(silent=True) or {}
    missing = [f for f in ["job_id", "draw_id", "amount_cents", "payer_id"] if not data.get(f)]
    if missing:
        return jsonify({"error": "Missing: " + ", ".join(missing)}), 400
    if str(data["payer_id"]) != str(user.id):
        return jsonify({"error": "payer_id must match authenticated user"}), 403
    intent = stripe.PaymentIntent.create(
        amount=int(data["amount_cents"]),
        currency="usd",
        capture_method="manual",
        metadata={"job_id": str(data["job_id"]), "draw_id": str(data["draw_id"])},
    )
    get_supabase().table("stripe_escrow").insert({
        "job_id": data["job_id"],
        "draw_id": data["draw_id"],
        "payer_id": data["payer_id"],
        "payee_id": data.get("payee_id"),
        "stripe_payment_intent_id": intent.id,
        "amount_cents": int(data["amount_cents"]),
        "status": "pending",
    }).execute()
    return jsonify({"client_secret": intent.client_secret, "payment_intent_id": intent.id})


def _release(draw_id):
    er = get_supabase().table("stripe_escrow").select("*").eq("draw_id", draw_id).execute()
    if not er.data:
        return None, "No escrow record found"
    escrow = er.data[0]
    intent_id = escrow["stripe_payment_intent_id"]
    payee_id = escrow.get("payee_id")
    amount_cents = escrow["amount_cents"]
    acct_id = None
    if payee_id:
        pr = get_supabase().table("profiles").select("stripe_account_id").eq("id", payee_id).execute()
        if pr.data:
            acct_id = pr.data[0].get("stripe_account_id")
    stripe.PaymentIntent.capture(intent_id)
    transfer_id = None
    if acct_id:
        fee = int(amount_cents * 0.02)
        t = stripe.Transfer.create(
            amount=amount_cents - fee,
            currency="usd",
            destination=acct_id,
            transfer_group="draw_" + str(draw_id),
        )
        transfer_id = t.id
    now = datetime.utcnow().isoformat()
    get_supabase().table("stripe_escrow").update({
        "status": "released",
        "released_at": now,
        "stripe_transfer_id": transfer_id,
    }).eq("draw_id", draw_id).execute()
    get_supabase().table("draws").update({"status": "released", "released_at": now}).eq("id", draw_id).execute()
    return transfer_id, None


@app.route("/stripe/escrow/release", methods=["POST"])
@require_auth
@handle_errors
def escrow_release(user):
    data = request.get_json(silent=True) or {}
    draw_id = data.get("draw_id")
    if not draw_id:
        return jsonify({"error": "draw_id required"}), 400
    ok, err = _verify_draw_owner(draw_id, user.id)
    if not ok:
        return jsonify({"error": err}), 403 if err != "Draw not found" else 404
    tid, err = _release(draw_id)
    if err:
        return jsonify({"error": err}), 404
    return jsonify({"success": True, "transfer_id": tid})


@app.route("/stripe/escrow/refund", methods=["POST"])
@require_auth
@handle_errors
def escrow_refund(user):
    data = request.get_json(silent=True) or {}
    draw_id = data.get("draw_id")
    if not draw_id:
        return jsonify({"error": "draw_id required"}), 400
    ok, err = _verify_draw_owner(draw_id, user.id)
    if not ok:
        return jsonify({"error": err}), 403 if err != "Draw not found" else 404
    r = get_supabase().table("stripe_escrow").select("*").eq("draw_id", draw_id).execute()
    if not r.data:
        return jsonify({"error": "No escrow record"}), 404
    stripe.PaymentIntent.cancel(r.data[0]["stripe_payment_intent_id"])
    get_supabase().table("stripe_escrow").update({"status": "refunded"}).eq("draw_id", draw_id).execute()
    get_supabase().table("draws").update({"status": "disputed"}).eq("id", draw_id).execute()
    return jsonify({"success": True})


@app.route("/draws/<draw_id>", methods=["GET"])
@handle_errors
def get_draw(draw_id):
    d = get_supabase().table("draws").select("*").eq("id", draw_id).execute()
    e = get_supabase().table("stripe_escrow").select("*").eq("draw_id", draw_id).execute()
    p = get_supabase().table("draw_photos").select("*").eq("draw_id", draw_id).execute()
    return jsonify({
        "draw": d.data[0] if d.data else None,
        "escrow": e.data[0] if e.data else None,
        "photos": p.data,
    })


@app.route("/draws/<draw_id>/approve", methods=["POST"])
@require_auth
@handle_errors
def approve_draw(user, draw_id):
    ok, err = _verify_draw_owner(draw_id, user.id)
    if not ok:
        return jsonify({"error": err}), 403 if err != "Draw not found" else 404
    get_supabase().table("draws").update({
        "status": "owner_approved",
        "approved_at": datetime.utcnow().isoformat(),
    }).eq("id", draw_id).execute()
    tid, err = _release(draw_id)
    if err:
        return jsonify({"error": err}), 404
    return jsonify({"success": True, "transfer_id": tid})


@app.route("/draws/<draw_id>/photos/upload", methods=["POST"])
@require_auth
@handle_errors
def upload_photo(user, draw_id):
    data = request.get_json(silent=True) or {}
    image_b64 = data.get("image_base64")
    storage_path = data.get(
        "storage_path",
        "draws/" + draw_id + "/" + str(datetime.utcnow().timestamp()) + ".jpg",
    )
    if not image_b64:
        return jsonify({"error": "image_base64 required"}), 400

    image_bytes = base64.b64decode(image_b64)
    get_supabase().storage.from_(STORAGE_BUCKET).upload(
        storage_path,
        image_bytes,
        {"content-type": "image/jpeg", "upsert": "true"},
    )

    prompt = (
        'You are a construction quality inspector reviewing a milestone photo for payment release. '
        'Respond ONLY with valid JSON: {"score":<0-100>,"passed":<true|false>,"summary":"<one sentence>",'
        '"flags":[],"recommendations":[]} Score 80+ = passed. Be strict.'
    )
    msg = get_anthropic().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                {"type": "text", "text": prompt},
            ],
        }],
    )
    raw = msg.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        ai = json.loads(raw.strip())
    except json.JSONDecodeError:
        return jsonify({"error": "AI returned invalid JSON"}), 500
    score = ai.get("score", 0)
    passed = ai.get("passed", False)
    flags = ai.get("flags", [])
    pr = get_supabase().table("draw_photos").insert({
        "draw_id": draw_id,
        "uploaded_by": user.id,
        "storage_path": storage_path,
        "ai_analysis": ai,
        "ai_passed": passed,
        "ai_score": score,
        "ai_summary": ai.get("summary", ""),
        "ai_flags": flags,
    }).execute()
    get_supabase().table("draws").update({
        "status": "ai_approved" if passed else "ai_flagged",
        "submitted_at": datetime.utcnow().isoformat(),
    }).eq("id", draw_id).execute()
    return jsonify({
        "success": True,
        "photo_id": pr.data[0]["id"],
        "storage_path": storage_path,
        "ai_score": score,
        "ai_passed": passed,
        "ai_summary": ai.get("summary", ""),
        "ai_flags": flags,
        "ai_recommendations": ai.get("recommendations", []),
    })


@app.route("/draws/<draw_id>/photos", methods=["GET"])
@handle_errors
def get_photos(draw_id):
    p = get_supabase().table("draw_photos").select("*").eq("draw_id", draw_id).execute()
    return jsonify({"photos": p.data})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    try:
        event = stripe.Webhook.construct_event(
            request.data,
            request.headers.get("Stripe-Signature", ""),
            STRIPE_WEBHOOK_SECRET,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    if event["type"] == "payment_intent.amount_capturable_updated":
        did = event["data"]["object"]["metadata"].get("draw_id")
        if did:
            try:
                get_supabase().table("stripe_escrow").update({
                    "status": "held",
                    "held_at": datetime.utcnow().isoformat(),
                }).eq("draw_id", did).execute()
            except ConfigError:
                pass
    return jsonify({"received": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
