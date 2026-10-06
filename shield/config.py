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
    # A development attestation says nothing about a production device, so it
    # is off unless someone turns it on deliberately, per deployment.
    "APP_ATTEST_ALLOW_DEVELOPMENT": "0",
    # Google's revocation list for attestation certificates.
    "ANDROID_ATTESTATION_STATUS_URL":
        "https://android.googleapis.com/attestation/status",
    # Outside clock on the job ticket. Off means the field is absent and
    # genesis still completes. There is no Roughtime client in this service.
    "SHIELD_ROUGHTIME_ENABLED": "0",
}

OPTIONAL = ("RESEND_API_KEY", "STRIPE_SHIELD_PRICE_ID", "SHIELD_SUCCESS_URL",
            "SHIELD_CANCEL_URL", "BADGE_WEBHOOK_URL", "BADGE_WEBHOOK_SECRET",
            # Both of these, or App Attest cannot be checked and every iOS
            # capture is refused. That is the correct closed state, not an
            # outage -- but it is silent, so `validate()` warns for it like
            # any other disabled feature.
            #
            # APPLE_APP_ATTEST_ROOT_PEM is the anchor, and it is configuration
            # rather than a constant on purpose: a root certificate committed
            # to a repository is either wrong, in which case nothing verifies
            # and the failure looks like an app bug, or right-looking and not
            # Apple's, in which case the service validates chains an attacker
            # minted. Neither is visible by reading the code.
            "APPLE_APP_ATTEST_ROOT_PEM",
            "APP_ATTEST_APP_ID",          # "TEAMID.com.bundle.identifier"
            # Android Key Attestation, the same shape: Google's attestation
            # roots as a PEM bundle (configuration, never a constant), and the
            # app a key must have been made by -- its package name and the
            # SHA-256 of its signing certificate (hex, comma-separated to
            # allow a rotation). Any of the three missing, and every Android
            # capture is refused.
            "ANDROID_ATTESTATION_ROOTS_PEM",
            "ANDROID_PACKAGE_NAME",
            "ANDROID_SIGNING_CERT_SHA256",
            # ECDSA P-256 private key, PEM, that signs job tickets. The same
            # posture as the Apple root: configuration, never a constant in
            # this repository. Unset, and genesis is refused. The public
            # half is derived from this key when a package needs it.
            "SHIELD_TICKET_SIGNING_KEY_PEM")


def get(key, default=None):
    return os.environ.get(key, DEFAULTS.get(key, default))


def get_int(key):
    try:
        return int(get(key))
    except (TypeError, ValueError):
        return int(DEFAULTS[key])


def android_signing_digests():
    """ANDROID_SIGNING_CERT_SHA256 as a set of 32-byte digests.

    Accepts hex with or without colons (keytool prints them with). A malformed
    entry is dropped rather than raising, and an empty set refuses every
    Android capture, which is the closed state.
    """
    out = set()
    for part in (get("ANDROID_SIGNING_CERT_SHA256") or "").split(","):
        text = part.strip().replace(":", "")
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            continue
        if len(raw) == 32:
            out.add(raw)
    return out


def allowed_origins():
    return [o.strip() for o in get("ALLOWED_ORIGINS", "").split(",") if o.strip()]


def roughtime_enabled():
    """True only when the outside-clock flag is explicitly on.

    The default is off. A missing variable is off. Genesis does not wait
    on an outside clock either way.
    """
    return get("SHIELD_ROUGHTIME_ENABLED") == "1"


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
