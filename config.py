import os
import sys
import logging

REQUIRED_ENV = (
    "SUPABASE_URL",
    "SUPABASE_SERVICE_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "ANTHROPIC_API_KEY",
)

OPTIONAL_ENV_DEFAULTS = {
    "APP_URL": "https://tradedeckapp.com",
    "ALLOWED_ORIGINS": "https://tradedeckapp.com,http://localhost:3000,http://127.0.0.1:5500",
    "DRAW_PHOTOS_BUCKET": "draw-photos",
    "PLATFORM_FEE_BPS": "200",
    "MAX_IMAGE_BYTES": str(10 * 1024 * 1024),
    "ANTHROPIC_MODEL": "claude-sonnet-4-6",
    "JOBS_PAGE_SIZE": "50",
}


def _missing_required():
    return [key for key in REQUIRED_ENV if not os.environ.get(key)]


def validate_env():
    missing = _missing_required()
    if missing:
        print(f"FATAL: Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def configure_logging():
    level = logging.DEBUG if os.environ.get("FLASK_DEBUG") == "1" else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def get_env(key, default=None):
    if default is None and key in OPTIONAL_ENV_DEFAULTS:
        default = OPTIONAL_ENV_DEFAULTS[key]
    return os.environ.get(key, default)


def allowed_origins():
    raw = get_env("ALLOWED_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def platform_fee_bps():
    try:
        return max(0, min(int(get_env("PLATFORM_FEE_BPS", "200")), 1000))
    except ValueError:
        return 200


def max_image_bytes():
    try:
        return max(1024, int(get_env("MAX_IMAGE_BYTES", str(10 * 1024 * 1024))))
    except ValueError:
        return 10 * 1024 * 1024


def jobs_page_size():
    try:
        return max(1, min(int(get_env("JOBS_PAGE_SIZE", "50")), 100))
    except ValueError:
        return 50
