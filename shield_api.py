from flask import Blueprint, jsonify
import os, logging, hashlib, json
import stripe
import anthropic
import requests

log = logging.getLogger(__name__)
shield_bp = Blueprint("shield", __name__, url_prefix="/shield")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False
    log.warning("piexif not installed")

try:
    from PIL import Image as PilImage
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    log.warning("Pillow not installed")

from auth import require_auth, utc_now_iso

@shield_bp.route("/status")
def shield_status():
    return jsonify({"status": "ok", "piexif": PIEXIF_AVAILABLE, "pillow": PILLOW_AVAILABLE})
