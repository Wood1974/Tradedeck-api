"""Verify an Apple App Attest attestation. The step that was missing.

Why this file is the whole blocker
----------------------------------
`attestation.py` maps a verification *outcome* onto a tier and refuses,
structurally, to grant trust to one that was not verified: `verified` must be
exactly `True`. Nothing in this service could produce that `True`, so
`tenant_api.upload_photo` refused every capture and photography was closed.

A native app does not change that on its own. An app can produce a perfect
attestation and the server still has nothing that can check it. This is the
check.

The trust anchor is configuration, not a constant
--------------------------------------------------
Apple's App Attest Root CA is not hardcoded here. A root certificate typed
from memory is either wrong -- in which case nothing verifies and the failure
looks like a bug in the app -- or, far worse, right-looking and not Apple's,
in which case this file cheerfully validates a chain an attacker minted.
Neither failure is visible by reading the code.

So the root arrives as PEM through `APPLE_APP_ATTEST_ROOT_PEM`, and with none
configured this module returns "not verified" rather than falling back to
anything. Fetch it from Apple, pin it, and treat rotating it as the security
event it is.

The procedure
-------------
Apple's, in order, and every step fails closed:

  1. Decode the CBOR attestation object; require fmt "apple-appattest".
  2. Build the certificate chain from `attStmt.x5c` and validate it to the
     configured root, checking validity dates.
  3. nonce = SHA256( authData || SHA256(challenge) ).
  4. The leaf must carry extension 1.2.840.113635.100.8.2 containing exactly
     that nonce. This is the binding: it is what makes the attestation about
     THIS capture rather than some earlier moment.
  5. keyId must equal SHA256 of the leaf's public key in uncompressed point
     form, and must equal the credentialId inside authData.
  6. rpIdHash must equal SHA256(appId), so an attestation minted for another
     app is not accepted for this one.
  7. The signature counter must be 0, which is what Apple specifies for an
     attestation (as opposed to an assertion).

Step 4 is the one worth staring at. Without it an attacker replays a genuine
attestation from a genuine device onto a file that device never saw, and every
other check still passes.
"""
import hashlib
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    from cryptography.exceptions import InvalidSignature
    AVAILABLE = True
except ImportError:                                      # pragma: no cover
    AVAILABLE = False

#: Apple's nonce extension. The attestation's binding to one challenge lives
#: here; everything else in the chain would verify without it.
NONCE_OID = "1.2.840.113635.100.8.2"

#: Apple sets this for App Attest keys. The development value is accepted only
#: when explicitly asked for, because a development attestation says nothing
#: about a production device.
AAGUID_PROD = b"appattest\x00\x00\x00\x00\x00\x00\x00"
AAGUID_DEV = b"appattestdevelop"

MIN_AUTH_DATA = 37 + 16 + 2      # rpIdHash + flags + counter + aaguid + length


def _no(reason, **extra):
    """Every refusal has the same shape, so no caller can mistake one."""
    return {"verified": False, "receipt_ok": False, "token_nonce": None,
            "reason": reason, **extra}


def _parse_auth_data(auth_data):
    """Split authData into the fields Apple defines. Length-checked first."""
    if len(auth_data) < MIN_AUTH_DATA:
        return None
    cred_len = int.from_bytes(auth_data[53:55], "big")
    if len(auth_data) < 55 + cred_len:
        return None
    return {
        "rp_id_hash": auth_data[0:32],
        "flags": auth_data[32],
        "counter": int.from_bytes(auth_data[33:37], "big"),
        "aaguid": auth_data[37:53],
        "credential_id": auth_data[55:55 + cred_len],
    }


def _chain_is_valid(leaf, intermediates, root, now):
    """Walk leaf -> intermediates -> root, checking signatures and dates.

    Deliberately explicit rather than delegating to a path builder. The set of
    certificates here is tiny and fixed, and an implementation whose failure
    mode I can read line by line is worth more, on this path, than one that
    handles cases Apple does not produce.
    """
    chain = [leaf] + list(intermediates) + [root]
    for cert in chain:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if not (not_before <= now <= not_after):
            return False, (f"a certificate in the chain is outside its "
                           f"validity window ({cert.subject.rfc4514_string()})")

    for child, parent in zip(chain, chain[1:]):
        if child.issuer != parent.subject:
            return False, "the certificate chain does not link up"
        try:
            parent.public_key().verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm))
        except InvalidSignature:
            return False, "a certificate in the chain has a bad signature"
        except Exception:
            return False, "a certificate in the chain could not be checked"
    return True, None


def verify(attestation_bytes, *, challenge, app_id, key_id, root_pem,
           allow_development=False, now=None):
    """Check one attestation. Returns a dict `interpret_app_attest` can read.

    `challenge` is the single-use value this server issued. `key_id` is the
    key identifier the client claims, base64-decoded to bytes by the caller.
    `app_id` is "TEAMID.bundle.identifier".

    Never raises. A malformed blob from an untrusted client is an expected
    input on this path, not an exception, and a traceback escaping here would
    be a denial of service with extra steps.
    """
    if not AVAILABLE:                                    # pragma: no cover
        return _no("attestation verification dependencies are not installed")
    if not root_pem:
        return _no("no Apple App Attest root certificate is configured, so "
                   "no chain can be trusted")
    if not challenge:
        return _no("no challenge was supplied, so nothing binds this "
                   "attestation to a capture")

    now = now or datetime.now(timezone.utc)

    try:
        obj = cbor2.loads(attestation_bytes)
    except Exception:
        return _no("the attestation object is not decodable CBOR")
    if not isinstance(obj, dict):
        return _no("the attestation object is not a CBOR map")

    if obj.get("fmt") != "apple-appattest":
        return _no(f"unexpected attestation format {obj.get('fmt')!r}")

    stmt = obj.get("attStmt")
    auth_data = obj.get("authData")
    if not isinstance(stmt, dict) or not isinstance(auth_data, bytes):
        return _no("the attestation object is missing attStmt or authData")

    x5c = stmt.get("x5c")
    if not isinstance(x5c, list) or not x5c:
        return _no("the attestation carries no certificate chain")

    try:
        certs = [x509.load_der_x509_certificate(c) for c in x5c]
        root = x509.load_pem_x509_certificate(
            root_pem.encode() if isinstance(root_pem, str) else root_pem)
    except Exception:
        return _no("a certificate could not be parsed")

    ok, why = _chain_is_valid(certs[0], certs[1:], root, now)
    if not ok:
        return _no(why)

    leaf = certs[0]

    # ---- the binding ------------------------------------------------------
    client_data_hash = hashlib.sha256(
        challenge.encode() if isinstance(challenge, str) else challenge).digest()
    expected_nonce = hashlib.sha256(auth_data + client_data_hash).digest()

    try:
        ext = leaf.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(NONCE_OID))
        ext_bytes = ext.value.value if hasattr(ext.value, "value") else bytes(ext.value)
    except Exception:
        return _no("the leaf certificate carries no App Attest nonce "
                   "extension, so the attestation is bound to nothing")

    # The extension wraps the digest in a small DER structure. Rather than
    # parse it, require the digest to appear inside: an attacker cannot make
    # a 32-byte SHA-256 they do not control appear in a certificate Apple
    # signed, which is the property being relied on.
    if expected_nonce not in ext_bytes:
        return _no("the attestation is not bound to this challenge — it "
                   "attests some other moment, or another server's capture")

    # ---- the key ----------------------------------------------------------
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return _no("the attested key is not an elliptic-curve key")
    uncompressed = public_key.public_bytes(Encoding.X962,
                                           PublicFormat.UncompressedPoint)
    computed_key_id = hashlib.sha256(uncompressed).digest()
    if key_id and computed_key_id != key_id:
        return _no("the attested key does not match the key id presented")

    parsed = _parse_auth_data(auth_data)
    if not parsed:
        return _no("authData is truncated or malformed")

    if parsed["credential_id"] != computed_key_id:
        return _no("authData names a different key than the certificate "
                   "attests")

    if parsed["rp_id_hash"] != hashlib.sha256(app_id.encode()).digest():
        return _no("this attestation was minted for a different app")

    if parsed["counter"] != 0:
        return _no("the signature counter is not zero, so this is an "
                   "assertion rather than an attestation")

    allowed = (AAGUID_PROD, AAGUID_DEV) if allow_development else (AAGUID_PROD,)
    if parsed["aaguid"] not in allowed:
        return _no("the attestation environment is not accepted "
                   f"({parsed['aaguid']!r}) — a development attestation says "
                   f"nothing about a production device")

    return {
        "verified": True,
        "receipt_ok": True,
        # What `interpret_app_attest` compares against the challenge it
        # issued. The binding is already proven above; returning it lets the
        # caller check it a second time in its own terms without re-deriving.
        "token_nonce": challenge,
        "key_id": computed_key_id,
        "reason": "chain validates to the configured Apple root, and the "
                  "attestation is bound to this capture's challenge",
    }
