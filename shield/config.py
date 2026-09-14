"""Environment configuration. Fails fast and loudly at import time.

Deliberately different from the parent app's config in one respect: there are
no in-code fallbacks for anything that protects data. The parent had
IP_HASH_SALT default to a literal committed in the repo, which made the
"hashed, not stored" claim about uploader IPs false — IPv4 is 2**32 values, so
a known salt means the hash *is* the address. Secrets are required or the
service refuses to boot.
"""
import os
import sys
import logging

log = logging.getLogger(__name__)

REQUIRED = (
    "SUPABASE_URL",
    "SUPABASE_SERVICE_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "ANTHROPIC_API_KEY",
    "IP_HASH_SALT",          # no fallback, by design
)

DEFAULTS = {
    "ALLOWED_ORIGINS":   "http://localhost:3000,http://127.0.0.1:5500",
    "SHIELD_BUCKET":     "shield-photos",
    "ANTHROPIC_MODEL":   "claude-sonnet-5",
    "MAX_UPLOAD_BYTES":  str(50 * 1024 * 1024),
    "SIGNED_URL_TTL":    "900",      # 15 min; only the server ever mints these
    "GPS_TOLERANCE_M":   "500",
    "MIN_CLEAN_JOBS":    "3",
    "SHIELD_FROM_EMAIL": "TradeDeck Shield <onboarding@resend.dev>",
}

OPTIONAL = ("RESEND_API_KEY", "STRIPE_SHIELD_PRICE_ID", "SHIELD_SUCCESS_URL",
            "SHIELD_CANCEL_URL", "BADGE_WEBHOOK_URL", "BADGE_WEBHOOK_SECRET")


def get(key, default=None):
    return os.environ.get(key, DEFAULTS.get(key, default))


def get_int(key):
    try:
        return int(get(key))
    except (TypeError, ValueError):
        return int(DEFAULTS[key])


def allowed_origins():
    return [o.strip() for o in get("ALLOWED_ORIGINS", "").split(",") if o.strip()]


def validate():
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if missing:
        print(f"FATAL: missing required environment variables: {', '.join(missing)}",
              file=sys.stderr)
        sys.exit(1)
    for k in OPTIONAL:
        if not os.environ.get(k):
            log.warning("%s not set — the feature that uses it is disabled", k)


def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("FLASK_DEBUG") == "1" else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
