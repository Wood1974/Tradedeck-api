"""Signed photographer note: the pure, network-free half of ID verification.

The phone signs a short statement with its device key after an ID check has passed. This module
checks that signature and computes the hash the rest of the system refers to. Nothing here talks
to Stripe or the database, so every rule can be tested on its own.

What a valid note shows: this device key signed exactly this statement, tied to one ID-check
session, at about this time. What it does not show: that the scene in any photo is honest.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

STATEMENT_VERSION = "1"
# Must match NOTE_STATEMENT in shield-app/src/identity/note.ts. Both test suites pin its SHA-256.
STATEMENT = (
    "I am the person who took the photographs in this record. I took each one myself, live, "
    "with this device's camera, and I have not edited, replaced or staged any of them. I "
    "understand this statement is signed with this device's key and tied to the ID check I completed."
)
NOTE_KIND = "tradedeck.shield.note"
MAX_CLOCK_SKEW_SECONDS = 600


def canonical(value) -> str:
    """Canonical JSON, byte-identical to stableStringify in shield-app/src/crypto/seal.ts."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal_id_for_key(raw_public_key: bytes) -> str:
    h = sha256_hex(raw_public_key)
    return f"{h[:8]}·{h[8:16]}".upper()


def statement_sha256() -> str:
    return sha256_hex(STATEMENT.encode("utf-8"))


def _load_key(raw_b64: str):
    raw = base64.b64decode(raw_b64, validate=True)
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("bad-public-key")
    return raw, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def verify_note(note: dict, session_id: str, now: datetime | None = None) -> tuple[bool, str, str | None]:
    """Returns (ok, reason, noteSha256). `note` is {payload, devicePublicKey, signature}."""
    now = now or datetime.now(timezone.utc)
    try:
        payload = note["payload"]
        if not isinstance(payload, dict):
            return False, "bad-payload", None
        if payload.get("kind") != NOTE_KIND or payload.get("v") != 1:
            return False, "bad-kind", None
        if payload.get("statementVersion") != STATEMENT_VERSION or payload.get("statement") != STATEMENT:
            return False, "statement-mismatch", None
        if payload.get("sessionId") != session_id:
            return False, "session-mismatch", None
        signed_at = datetime.fromisoformat(str(payload.get("signedAt", "")).replace("Z", "+00:00"))
        if signed_at.tzinfo is None:
            return False, "bad-time", None
        if abs((now - signed_at).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
            return False, "clock-skew", None
        raw, key = _load_key(note["devicePublicKey"])
        if payload.get("deviceSealId") != seal_id_for_key(raw):
            return False, "seal-id-key-mismatch", None
        sig = base64.b64decode(note["signature"], validate=True)
        if len(sig) != 64:  # WebCrypto emits raw r||s, not DER
            return False, "bad-signature-format", None
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        body = canonical(payload).encode("utf-8")
        try:
            key.verify(der, body, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, "signature-invalid", None
        return True, "ok", sha256_hex(body)
    except (KeyError, ValueError, TypeError):
        return False, "malformed", None


# ---------------------------------------------------------------- receipt --
# After Stripe reports `verified` and the note checks out, the service signs a small receipt. The phone stores it
# and the close-out packet embeds it, so anyone holding the service's public key can confirm offline that the
# service saw a passed ID check for this exact note. ECDSA P-256, raw r||s: the same form WebCrypto verifies.
RECEIPT_KIND = "tradedeck.shield.idreceipt"
ID_PROVIDER = "stripe-identity"


def load_receipt_key(pem: str | None):
    """Private key from the environment (PEM, with literal \\n tolerated). None when not configured."""
    if not pem:
        return None
    key = load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("receipt key must be an EC P-256 private key")
    return key


def receipt_public(private_key) -> tuple[str, str]:
    """(raw public key base64, key id). The key id is the first 16 hex chars of SHA-256 over the raw key."""
    raw = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return base64.b64encode(raw).decode(), sha256_hex(raw)[:16]


def make_receipt(private_key, *, attestation_id: str, note_sha256: str, device_seal_id: str,
                 session_id: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    _, kid = receipt_public(private_key)
    payload = {
        "kind": RECEIPT_KIND, "v": 1, "attestationId": attestation_id, "noteSha256": note_sha256,
        "deviceSealId": device_seal_id,
        # A hash, so the receipt can be audited against Stripe without publishing the session id.
        "sessionSha256": sha256_hex(session_id.encode()),
        "idCheck": {"provider": ID_PROVIDER, "status": "verified"},
        "issuedAt": now.isoformat().replace("+00:00", "Z"), "kid": kid,
    }
    der = private_key.sign(canonical(payload).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {"payload": payload, "signature": base64.b64encode(sig).decode()}


def verify_receipt(receipt: dict, public_raw_b64: str) -> tuple[bool, str]:
    """For tests and for third parties. Checks the signature and that the key id matches the key."""
    try:
        raw, key = _load_key(public_raw_b64)
        payload = receipt["payload"]
        if payload.get("kind") != RECEIPT_KIND or payload.get("v") != 1:
            return False, "bad-kind"
        if payload.get("kid") != sha256_hex(raw)[:16]:
            return False, "kid-mismatch"
        if payload.get("idCheck") != {"provider": ID_PROVIDER, "status": "verified"}:
            return False, "not-verified"
        sig = base64.b64decode(receipt["signature"], validate=True)
        if len(sig) != 64:
            return False, "bad-signature-format"
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        try:
            key.verify(der, canonical(payload).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, "signature-invalid"
        return True, "ok"
    except (KeyError, ValueError, TypeError):
        return False, "malformed"
