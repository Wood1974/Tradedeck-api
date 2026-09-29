"""Verify Android Key Attestation. The Android half of `app_attest.py`.

Why Key Attestation and not Play Integrity
------------------------------------------
Both exist, and `attestation.interpret_play_integrity` already knows how to
read a Play Integrity verdict. But a Play Integrity token cannot be checked
here: it has to be sent to Google's `decodeIntegrityToken` API (or decrypted
with keys from the Play Console) on every capture, which puts a Google
round trip and a service-account credential in the path of every photograph.

Key Attestation is checked entirely on this server, the way App Attest is. The
device generates a key inside its secure hardware (the TEE, or a StrongBox
chip) and the hardware issues a certificate for it, chained to Google's
hardware attestation root, carrying a description of the key and the device:
which security level holds it, whether the bootloader is locked and the boot
verified, and which app -- by package name and signing certificate -- asked
for it. Everything is a signature check against a root this service pins.

What a pass means, precisely: a key generated in this device's secure
hardware, on a device whose bootloader is locked and whose boot was verified,
by an app with this package name signed by this signing certificate, bound to
one challenge and one photograph. Unlike App Attest, the boot state IS
reported, so a pass does say the OS was not booted from an unlocked
bootloader. It still says nothing about what was in front of the lens.

The trust anchor is configuration
---------------------------------
Google publishes its attestation roots and rotates them (an ECDSA root joined
the original RSA one). They arrive as a PEM bundle through
`ANDROID_ATTESTATION_ROOTS_PEM`, for the same reason Apple's root does: a root
typed into source is either wrong, and nothing verifies, or right-looking and
not Google's, and forged chains verify. With none configured, this refuses.

The procedure, every step failing closed
----------------------------------------
  1. The chain is the device's own, leaf first, ending at a certificate whose
     public key is one of the configured Google roots.
  2. Every certificate is inside its validity window, and each is signed by
     the next.
  3. No certificate's serial number is on Google's revocation list.
  4. ONLY the leaf carries the attestation extension. This is the check that
     is easy to miss: an app holding a genuine attested key can use it to sign
     a certificate for a key it made up, with any extension it likes, and that
     chain verifies to Google's root. The genuine attested certificate then
     sits one step up the chain -- and it is the only other place the
     extension can be. So an extension anywhere but the leaf is a refusal.
  5. Both security levels (attestation and KeyMint) are TEE or StrongBox. A
     Software level means no secure hardware stood behind the key.
  6. attestationChallenge == SHA256( challenge || SHA256(photo bytes) ), the
     same client data App Attest commits to.
  7. In the hardware-enforced list: the key was generated on the device, not
     imported; it is an EC key that can sign; the boot state is Verified and
     the device is locked.
  8. The attesting app's package name is the configured one, and one of its
     signing certificate digests is a configured one. A repackaged Shield --
     the realistic attacker, who controls what "the camera" returns -- is
     signed with a different certificate and fails here.

Later captures from the same key are a plain ECDSA-SHA256 signature over the
client data, checked against the key stored at attestation (`verify_signature`).
Android keys have no counter; replay is stopped by the single-use challenge
the signature covers.
"""
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    AVAILABLE = True
except ImportError:                                      # pragma: no cover
    AVAILABLE = False

#: The Android Key Attestation extension (KeyDescription).
KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

#: Google's published revocation list for attestation certificates.
DEFAULT_STATUS_URL = "https://android.googleapis.com/attestation/status"

SECURITY_SOFTWARE = 0
SECURITY_TEE = 1
SECURITY_STRONGBOX = 2
SECURITY_NAMES = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}

VERIFIED_BOOT_VERIFIED = 0

# AuthorizationList tags used here.
TAG_PURPOSE = 1
TAG_ALGORITHM = 2
TAG_EC_CURVE = 10
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_ATTESTATION_APPLICATION_ID = 709

PURPOSE_SIGN = 2
ALGORITHM_EC = 3
ORIGIN_GENERATED = 0


def _no(reason, **extra):
    """Same shape as app_attest._no, so the route reads both the same way."""
    return {"verified": False, "receipt_ok": False, "token_nonce": None,
            "reason": reason, **extra}


# ------------------------------------------------------------------ DER ----
# A minimal reader, not a general ASN.1 library. It reads exactly the
# structures Google defines for KeyDescription and nothing else, and it raises
# ValueError on anything malformed -- `verify` turns that into a refusal. The
# certificate is signed by the device's secure hardware, so a malformed
# extension is never an accident.

class _TLV:
    __slots__ = ("cls", "constructed", "tag", "value")

    def __init__(self, cls, constructed, tag, value):
        self.cls, self.constructed, self.tag, self.value = (
            cls, constructed, tag, value)


def _read(data, i=0):
    """One TLV at data[i:]. Returns (tlv, next_index)."""
    n = len(data)
    if i >= n:
        raise ValueError("truncated tag")
    first = data[i]
    i += 1
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    if tag == 0x1F:                              # high tag number form
        tag = 0
        for _ in range(4):
            if i >= n:
                raise ValueError("truncated tag number")
            b = data[i]
            i += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        else:
            raise ValueError("tag number too long")
    if i >= n:
        raise ValueError("truncated length")
    length = data[i]
    i += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or i + count > n:
            raise ValueError("unsupported length")
        length = int.from_bytes(data[i:i + count], "big")
        i += count
    if i + length > n:
        raise ValueError("value runs past the end")
    return _TLV(cls, constructed, tag, data[i:i + length]), i + length


def _children(tlv):
    if not tlv.constructed:
        raise ValueError("expected a constructed value")
    out, i = [], 0
    while i < len(tlv.value):
        child, i = _read(tlv.value, i)
        out.append(child)
    return out


def _whole(data):
    tlv, end = _read(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes")
    return tlv


def _int(tlv, tags=(2, 10)):                  # INTEGER or ENUMERATED
    if tlv.cls != 0 or tlv.tag not in tags or not tlv.value:
        raise ValueError("expected an integer")
    return int.from_bytes(tlv.value, "big", signed=True)


def _octets(tlv):
    if tlv.cls != 0 or tlv.tag != 4:
        raise ValueError("expected an octet string")
    return tlv.value


def _bool(tlv):
    if tlv.cls != 0 or tlv.tag != 1 or len(tlv.value) != 1:
        raise ValueError("expected a boolean")
    return tlv.value != b"\x00"


def _auth_list(tlv):
    """AuthorizationList -> {tag number: the explicitly tagged inner TLV}."""
    if tlv.cls != 0 or tlv.tag != 16:
        raise ValueError("expected an AuthorizationList sequence")
    out = {}
    for entry in _children(tlv):
        if entry.cls != 2:                      # context-specific
            raise ValueError("unexpected entry in an AuthorizationList")
        inner = _children(entry)
        if len(inner) != 1:
            raise ValueError("an AuthorizationList entry is not EXPLICIT")
        if entry.tag in out:
            raise ValueError("a tag appears twice in one AuthorizationList")
        out[entry.tag] = inner[0]
    return out


def parse_key_description(der):
    """The fields of KeyDescription this module relies on."""
    top = _whole(der)
    if top.cls != 0 or top.tag != 16:
        raise ValueError("KeyDescription is not a sequence")
    f = _children(top)
    if len(f) < 8:
        raise ValueError("KeyDescription is missing fields")
    return {
        "attestation_version": _int(f[0]),
        "attestation_security_level": _int(f[1]),
        "keymint_version": _int(f[2]),
        "keymint_security_level": _int(f[3]),
        "challenge": _octets(f[4]),
        "software": _auth_list(f[6]),
        "hardware": _auth_list(f[7]),
    }


def _root_of_trust(tlv):
    if tlv.cls != 0 or tlv.tag != 16:
        raise ValueError("RootOfTrust is not a sequence")
    f = _children(tlv)
    if len(f) < 3:
        raise ValueError("RootOfTrust is missing fields")
    return {"device_locked": _bool(f[1]), "verified_boot_state": _int(f[2])}


def _application_id(tlv):
    """AttestationApplicationId, which arrives wrapped in an OCTET STRING."""
    inner = _whole(_octets(tlv))
    if inner.cls != 0 or inner.tag != 16:
        raise ValueError("AttestationApplicationId is not a sequence")
    f = _children(inner)
    if len(f) != 2 or f[0].tag != 17 or f[1].tag != 17:
        raise ValueError("AttestationApplicationId has the wrong shape")
    packages = []
    for info in _children(f[0]):
        parts = _children(info)
        if len(parts) != 2:
            raise ValueError("AttestationPackageInfo has the wrong shape")
        packages.append(_octets(parts[0]).decode("utf-8", "strict"))
    digests = [_octets(d) for d in _children(f[1])]
    return packages, digests


def _int_set(tlv):
    if tlv.cls != 0 or tlv.tag != 17:
        raise ValueError("expected a SET OF INTEGER")
    return {_int(x, tags=(2,)) for x in _children(tlv)}


# ---------------------------------------------------------------- chain ----
def _public_key_bytes(cert):
    return cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _signed_by(child, parent):
    key = parent.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _has_key_description(cert):
    try:
        cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(KEY_DESCRIPTION_OID))
    except x509.ExtensionNotFound:
        return False
    return True


def _key_description_bytes(cert):
    ext = cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier(KEY_DESCRIPTION_OID))
    return ext.value.value


def _load_roots(roots_pem):
    data = roots_pem.encode() if isinstance(roots_pem, str) else roots_pem
    return x509.load_pem_x509_certificates(data)


# ----------------------------------------------------------- revocation ----
_status_lock = threading.Lock()
_status_cache = {"at": 0.0, "revoked": None}
STATUS_TTL_S = 3600
#: How long a previously fetched list is still used when Google cannot be
#: reached. Revocations are rare and slow-moving; refusing every Android
#: capture because one fetch timed out would be an outage for no security.
STATUS_STALE_OK_S = 24 * 3600


def revoked_serials(url=DEFAULT_STATUS_URL, fetch=None, now=None):
    """Google's revoked certificate serials, as lowercase hex, or None.

    None means the list could not be obtained and no recent copy is held, and
    `verify` refuses on None rather than skipping the check. Cached for an
    hour; a failed refresh falls back to a copy up to a day old.
    """
    now = time.time() if now is None else now
    with _status_lock:
        fresh = now - _status_cache["at"] < STATUS_TTL_S
        if fresh and _status_cache["revoked"] is not None:
            return _status_cache["revoked"]
    try:
        if fetch is None:
            import requests
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            body = resp.json()
        else:
            body = fetch(url)
        entries = body.get("entries") or {}
        revoked = frozenset(
            str(serial).lower().lstrip("0") or "0"
            for serial, info in entries.items()
            if isinstance(info, dict) and info.get("status") == "REVOKED")
    except Exception:
        log.warning("Could not fetch the Android attestation status list",
                    exc_info=True)
        with _status_lock:
            if (_status_cache["revoked"] is not None
                    and now - _status_cache["at"] < STATUS_STALE_OK_S):
                return _status_cache["revoked"]
        return None
    with _status_lock:
        _status_cache.update(at=now, revoked=revoked)
    return revoked


def _serial_hex(cert):
    return format(cert.serial_number, "x")


# --------------------------------------------------------------- verify ----
def verify(chain_der, *, challenge, payload_sha256, package_name,
           signing_digests, roots_pem, revoked, now=None):
    """Check one Key Attestation chain. Returns a dict the route can read.

    `chain_der` is the device's certificate chain, leaf first, as DER bytes.
    `challenge` is the single-use value this server issued, `payload_sha256`
    the digest of the bytes that arrived, computed by the server.
    `signing_digests` is the set of acceptable SHA-256 digests of the app's
    signing certificate, as bytes. `revoked` is `revoked_serials()`'s result:
    None refuses.

    Never raises.
    """
    if not AVAILABLE:                                    # pragma: no cover
        return _no("attestation verification dependencies are not installed")
    if not roots_pem:
        return _no("no Google attestation root is configured, so no chain "
                   "can be trusted")
    if not package_name or not signing_digests:
        return _no("the Android app's package name and signing certificate "
                   "are not configured, so no app can be recognised")
    if revoked is None:
        return _no("Google's attestation revocation list could not be "
                   "checked")
    if not challenge:
        return _no("no challenge was supplied, so nothing binds this "
                   "attestation to a capture")
    if not payload_sha256:
        return _no("no payload digest was supplied, so nothing binds this "
                   "attestation to the bytes that arrived")
    if not chain_der or len(chain_der) < 2:
        return _no("the attestation carries no certificate chain")

    now = now or datetime.now(timezone.utc)

    try:
        certs = [x509.load_der_x509_certificate(c) for c in chain_der]
        roots = _load_roots(roots_pem)
    except Exception:
        return _no("a certificate could not be parsed")

    # ---- 1-3. the chain ---------------------------------------------------
    anchors = {_public_key_bytes(r) for r in roots}
    if _public_key_bytes(certs[-1]) not in anchors:
        return _no("the chain does not end at a configured Google "
                   "attestation root")
    for cert in certs:
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return _no("a certificate in the chain is outside its validity "
                       "window")
        if _serial_hex(cert) in revoked:
            return _no("a certificate in the chain has been revoked by Google")
    for child, parent in zip(certs, certs[1:]):
        if child.issuer != parent.subject or not _signed_by(child, parent):
            return _no("the certificate chain does not verify")

    # ---- 4. the extension is the leaf's alone -----------------------------
    leaf = certs[0]
    if not _has_key_description(leaf):
        return _no("the leaf certificate carries no key attestation, so it "
                   "attests nothing")
    if any(_has_key_description(c) for c in certs[1:]):
        return _no("a certificate above the leaf carries a key attestation -- "
                   "an attested key was used to certify another key, which "
                   "is how an attestation is forged")

    try:
        desc = parse_key_description(_key_description_bytes(leaf))
        hw, sw = desc["hardware"], desc["software"]
    except Exception:
        return _no("the key attestation extension is malformed")

    # ---- 5. secure hardware -----------------------------------------------
    levels = (desc["attestation_security_level"],
              desc["keymint_security_level"])
    if any(level not in (SECURITY_TEE, SECURITY_STRONGBOX) for level in levels):
        return _no("the key is not held in secure hardware (security level "
                   f"{SECURITY_NAMES.get(levels[0], levels[0])})")

    # ---- 6. the binding ---------------------------------------------------
    client_data = (challenge.encode() if isinstance(challenge, str)
                   else challenge) + payload_sha256
    if desc["challenge"] != hashlib.sha256(client_data).digest():
        return _no("the attestation is not bound to this photograph -- it "
                   "attests some other moment, or some other file")

    # ---- 7. the key and the device ----------------------------------------
    try:
        if TAG_ORIGIN not in hw or _int(hw[TAG_ORIGIN], (2,)) != ORIGIN_GENERATED:
            return _no("the key was not generated in the device's secure "
                       "hardware")
        if TAG_ALGORITHM not in hw or _int(hw[TAG_ALGORITHM], (2,)) != ALGORITHM_EC:
            return _no("the attested key is not an elliptic-curve key")
        if TAG_PURPOSE not in hw or PURPOSE_SIGN not in _int_set(hw[TAG_PURPOSE]):
            return _no("the attested key cannot sign")
        if TAG_ROOT_OF_TRUST not in hw:
            return _no("the device did not report its boot state from "
                       "secure hardware")
        rot = _root_of_trust(hw[TAG_ROOT_OF_TRUST])
    except Exception:
        return _no("the key attestation extension is malformed")
    if rot["verified_boot_state"] != VERIFIED_BOOT_VERIFIED:
        return _no("the device's boot was not verified, so its operating "
                   "system cannot be trusted")
    if not rot["device_locked"]:
        return _no("the device's bootloader is unlocked")

    public_key = leaf.public_key()
    if (not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)):
        return _no("the attested key is not a P-256 key")

    # ---- 8. the app -------------------------------------------------------
    app_tlv = sw.get(TAG_ATTESTATION_APPLICATION_ID) or hw.get(
        TAG_ATTESTATION_APPLICATION_ID)
    if app_tlv is None:
        return _no("the attestation does not name the app that made the key")
    try:
        packages, digests = _application_id(app_tlv)
    except Exception:
        return _no("the key attestation extension is malformed")
    if packages != [package_name]:
        return _no("the key was made by a different app")
    if not set(digests) & set(signing_digests):
        return _no("the app that made the key is not signed with Shield's "
                   "signing certificate -- a repackaged build")

    uncompressed = public_key.public_bytes(Encoding.X962,
                                           PublicFormat.UncompressedPoint)
    level = desc["keymint_security_level"]
    return {
        "verified": True,
        "receipt_ok": True,
        "token_nonce": challenge,
        "key_id": hashlib.sha256(uncompressed).digest(),
        "public_key": uncompressed,
        "environment": "production",
        "receipt": None,
        "security_level": SECURITY_NAMES[level],
        "reason": "chain verifies to a configured Google root, the key is in "
                  f"{SECURITY_NAMES[level]} hardware on a locked, verified "
                  "device, made by Shield, and bound to this challenge and "
                  "these exact bytes",
    }


def verify_signature(signature, *, challenge, payload_sha256, public_key):
    """A later capture: an ECDSA-SHA256 signature over the client data.

    The client signs `challenge || SHA256(photo)` with `SHA256withECDSA`, so
    the message verified here is that client data, hashed once by ECDSA.
    There is no counter. Replay is stopped by the single-use challenge the
    signature covers, which the route spends before calling this.
    """
    if not AVAILABLE:                                    # pragma: no cover
        return _no("attestation verification dependencies are not installed")
    if not challenge:
        return _no("no challenge was supplied, so nothing binds this "
                   "signature to a capture")
    if not payload_sha256:
        return _no("no payload digest was supplied, so nothing binds this "
                   "signature to the bytes that arrived")
    if not public_key:
        return _no("no attested key is on file for this signature")
    if not signature:
        return _no("no signature was supplied")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes(public_key))
    except Exception:
        return _no("the key on file is not a valid P-256 public key")
    client_data = (challenge.encode() if isinstance(challenge, str)
                   else challenge) + payload_sha256
    try:
        key.verify(signature, client_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return _no("the signature does not verify -- it was not made by this "
                   "key over this challenge and these bytes")
    except Exception:
        return _no("the signature could not be checked")
    return {
        "verified": True,
        "receipt_ok": True,
        "token_nonce": challenge,
        "reason": "signed by a key this service attested, over this "
                  "challenge and these exact bytes",
    }
