"""A receipt for an accepted batch, and an RFC 3161 timestamp over its head.

The receipt is signed with the same ECDSA P-256 key that signs job tickets
(``SHIELD_TICKET_SIGNING_KEY_PEM``). The signed fields are the record id, the
custody-chain head after the batch was appended, and the server time the
batch was accepted. The phone chain is already inside that head: the custody
entry's signed ``event_data`` carries ``phone_chain_head``. This module does
not invent a second chain and it does not change ``chain_version``.

The timestamp is a separate step. After the receipt exists, this module asks
DigiCert for an RFC 3161 token over that head and, if DigiCert does not
answer, Sectigo. Both addresses are configuration. Nothing here is called
unless ``SHIELD_TSA_ENABLED`` is ``1``, and a test can hand in a transport
so the suite never opens a socket to either host.

If the timestamp authority does not answer, or answers with a token this
service cannot check, the receipt is unchanged. The package says the
timestamp is missing. Missing is not forged. This file does not mint a
token to fill that gap: ``mint_token`` exists so a test can run a local
authority with a certificate the test itself created. The route does not
call it.
"""
import base64
import hashlib
import logging
import secrets
import urllib.parse
import urllib.request

import capture_record
import config
import ticket

log = logging.getLogger(__name__)

RECEIPT_VERSION = 1

RECEIPT_FIELDS = (
    "version",
    "record_id",
    "head_hash",
    "accepted_at_ms",
)

# The imprint is the custody head itself. The head is already a SHA-256.
# A verifier compares these 32 bytes to the head. It does not hash them again.
IMPRINT_ALG = "sha256"

SHA256_OID = "2.16.840.1.101.3.4.2.1"
ECDSA_SHA256_OID = "1.2.840.10045.4.3.2"
RSA_SHA256_OID = "1.2.840.113549.1.1.11"
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE_OID = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"
# Private-looking documentation OID. A real authority sends its own policy.
# Verification records the policy. It does not require this one.
LOCAL_POLICY_OID = "1.3.6.1.4.1.99999.10.1"
TIME_STAMPING_EKU = "1.3.6.1.5.5.7.3.8"

STATUS_MISSING = "missing"
STATUS_PRESENT = "present"

# Tests assign this. Production leaves it None, and the default path then
# uses urllib only when the feature flag is on.
transport = None


class TsaUnavailable(Exception):
    """The timestamp authority did not return a token we could check."""


def _whole(value, key):
    if isinstance(value, float):
        raise ValueError(f"{key} is a float; the receipt only signs whole numbers")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be a whole number")
    if value < 0 or value > capture_record.JS_SAFE_INT:
        raise ValueError(
            f"{key} is outside the range a JSON number can carry exactly")
    return value


def _head(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("head_hash must be a 64-character lowercase hex SHA-256")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("head_hash must be lowercase hex") from exc
    if value != raw.hex():
        raise ValueError("head_hash must be lowercase hex")
    return value


def _text(value, key):
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{key} must be a non-empty string")
    if len(value) > 512:
        raise ValueError(f"{key} is longer than 512 characters")
    return value


def _signed_fields(*, record_id, head_hash, accepted_at_ms, version=RECEIPT_VERSION):
    if version != RECEIPT_VERSION:
        raise ValueError(f"unsupported receipt version {version!r}")
    return {
        "version": version,
        "record_id": _text(record_id, "record_id"),
        "head_hash": _head(head_hash),
        "accepted_at_ms": _whole(accepted_at_ms, "accepted_at_ms"),
    }


def build_receipt(*, record_id, head_hash, accepted_at_ms) -> dict:
    """The signed map. Nulls are not in it. A float is rejected."""
    receipt = _signed_fields(
        record_id=record_id, head_hash=head_hash, accepted_at_ms=accepted_at_ms)
    # Reject a float the field checks already caught, and pin the bytes.
    capture_record.canonical_whole(receipt)
    return receipt


def canonical(receipt) -> bytes:
    """UTF-8 JSON of the signed fields. Same whole-number rules as a ticket."""
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a JSON object")
    body = _signed_fields(
        record_id=receipt.get("record_id"),
        head_hash=receipt.get("head_hash"),
        accepted_at_ms=receipt.get("accepted_at_ms"),
        version=receipt.get("version", RECEIPT_VERSION))
    # canonical_whole drops nulls, rejects floats, and sorts keys. The
    # receipt has no nested values. Calling it keeps the byte rules in one
    # place with the capture record and the ticket.
    return capture_record.canonical_whole(body)


def head_imprint(head_hash) -> bytes:
    """The 32 bytes an RFC 3161 imprint carries for this head."""
    return bytes.fromhex(_head(head_hash))


def sign_receipt(receipt, *, pem=None) -> dict:
    """ECDSA P-256 over the canonical receipt. TicketKeyError if no key."""
    body = canonical(receipt)
    key = ticket.load_signing_key(pem)
    if key is None:
        raise ticket.TicketKeyError("no receipt signing key is configured")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    signature = key.sign(body, ec.ECDSA(hashes.SHA256()))
    signed = build_receipt(
        record_id=receipt["record_id"],
        head_hash=receipt["head_hash"],
        accepted_at_ms=receipt["accepted_at_ms"])
    return {
        "signed": signed,
        "signature": base64.b64encode(signature).decode("ascii"),
        "head_hash": signed["head_hash"],
    }


def verify_receipt(receipt, signature_b64, *, pem=None) -> dict:
    """Check the receipt signature. A missing key raises TicketKeyError."""
    body = canonical(receipt)
    key = ticket.load_signing_key(pem)
    if key is None:
        raise ticket.TicketKeyError("no receipt signing key is configured")
    raw = _b64(signature_b64)
    signed = build_receipt(
        record_id=receipt["record_id"],
        head_hash=receipt["head_hash"],
        accepted_at_ms=receipt["accepted_at_ms"])
    if raw is None:
        return {"ok": False, "reason": "receipt signature is not valid base64",
                "signed": signed}
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        key.public_key().verify(raw, body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return {"ok": False, "reason": "receipt signature does not verify",
                "signed": signed}
    except Exception:
        return {"ok": False, "reason": "receipt signature could not be checked",
                "signed": signed}
    return {"ok": True, "reason": "receipt signature verifies", "signed": signed}


def _b64(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        return None


def missing_timestamp(reason):
    """No token. This is not a forgery finding."""
    return {
        "status": STATUS_MISSING,
        "forged": False,
        "token_b64": None,
        "authority": None,
        "gen_time": None,
        "reason": reason,
        "note": ("The timestamp is missing. A missing timestamp is not a "
                 "forgery. The receipt still covers the custody head."),
    }


def enabled():
    return config.get("SHIELD_TSA_ENABLED") == "1"


def primary_url():
    return config.get("SHIELD_TSA_PRIMARY_URL")


def fallback_url():
    return config.get("SHIELD_TSA_FALLBACK_URL")


def authority_name(url):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if "digicert" in host:
        return "digicert"
    if "sectigo" in host or "comodoca" in host:
        return "sectigo"
    return host or "unknown"


def stamp(head_hash, *, fetch=None, urls=None, roots_pem=None, enabled_flag=None):
    """Ask for an RFC 3161 token over ``head_hash``.

    ``fetch`` is ``(url, body) -> bytes``. When it is omitted, the module
    transport is used, and when that is also omitted the real network is
    used only if the feature flag is on. Otherwise the result is missing,
    and missing is not forged.

    A token that does not verify is not kept. The next authority is tried.
    When none of them produce a token this service can check, the result is
    missing. This function does not call ``mint_token``.
    """
    try:
        imprint = head_imprint(head_hash)
    except ValueError as exc:
        return missing_timestamp(str(exc))

    if enabled_flag is None:
        enabled_flag = enabled()
    if fetch is None:
        fetch = transport
    if not enabled_flag and fetch is None:
        return missing_timestamp(
            "The timestamp authority is not enabled on this deployment.")
    if fetch is None:
        fetch = _urllib_post

    if urls is None:
        urls = [u for u in (primary_url(), fallback_url()) if u]
    if not urls:
        return missing_timestamp("No timestamp authority is configured.")

    if roots_pem is None:
        roots_pem = config.get("SHIELD_TSA_ROOTS_PEM")

    nonce = secrets.randbits(63)
    request = encode_timestamp_request(imprint, nonce)
    reasons = []
    for url in urls:
        try:
            raw = fetch(url, request)
        except Exception as exc:
            log.info("timestamp authority %s did not answer: %s", url, exc)
            reasons.append(f"{authority_name(url)} did not answer")
            continue
        if not raw:
            reasons.append(f"{authority_name(url)} returned nothing")
            continue
        checked = verify_token(
            raw, head_hash=head_hash, roots_pem=roots_pem, nonce=nonce)
        if not checked["ok"]:
            log.info("timestamp from %s was not kept: %s", url, checked["reason"])
            reasons.append(f"{authority_name(url)}: {checked['reason']}")
            continue
        return {
            "status": STATUS_PRESENT,
            "forged": False,
            "token_b64": base64.b64encode(raw).decode("ascii"),
            "authority": authority_name(url),
            "gen_time": checked.get("gen_time"),
            "reason": checked["reason"],
            "note": ("An RFC 3161 timestamp covers this custody head. "
                     "It does not say the photograph is real."),
        }
    detail = "; ".join(reasons) if reasons else "no timestamp authority answered"
    return missing_timestamp(
        "No timestamp could be obtained. " + detail)


def _urllib_post(url, body, timeout=10):
    """POST a TimeStampReq. Redirects are refused. Only used when enabled."""
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/timestamp-query"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as exc:
        raise TsaUnavailable(str(exc)) from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TsaUnavailable("the timestamp authority redirected the request")


# ----------------------------------------------------------------- DER -----
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _int(n):
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("DER integer must be a non-negative whole number")
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _octets(blob):
    return _tlv(0x04, blob)


def _oid_body(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(reversed(chunk))
    return out


def _oid(dotted):
    return _tlv(0x06, _oid_body(dotted))


def _alg_sha256():
    return _seq(_oid(SHA256_OID), _tlv(0x05, b""))


def _set_of(items):
    return _tlv(0x31, b"".join(sorted(items)))


def _read_len(data, i):
    if i >= len(data):
        raise ValueError("truncated DER")
    n = data[i]
    i += 1
    if n < 0x80:
        return n, i
    count = n & 0x7F
    if count == 0 or count > 4 or i + count > len(data):
        raise ValueError("bad DER length")
    length = int.from_bytes(data[i:i + count], "big")
    return length, i + count


def _walk(data):
    items = []
    i = 0
    while i < len(data):
        start = i
        if i >= len(data):
            break
        tag = data[i]
        i += 1
        length, i = _read_len(data, i)
        end = i + length
        if end > len(data):
            raise ValueError("truncated DER value")
        items.append((tag, data[i:end], data[start:end]))
        i = end
    return items


def _one_seq(data):
    items = _walk(data)
    if len(items) != 1 or items[0][0] != 0x30:
        raise ValueError("expected one SEQUENCE")
    return _walk(items[0][1])


def _parse_int(content):
    if not content:
        raise ValueError("empty integer")
    # Reject a non-minimal encoding, which is what DER forbids, so a second
    # encoding of the same number cannot be a second token.
    if len(content) > 1 and content[0] == 0x00 and not (content[1] & 0x80):
        raise ValueError("non-minimal integer")
    return int.from_bytes(content, "big")


def _oid_str(content):
    if not content:
        raise ValueError("empty oid")
    parts = [str(content[0] // 40), str(content[0] % 40)]
    i = 1
    while i < len(content):
        n = 0
        while True:
            if i >= len(content):
                raise ValueError("truncated oid")
            byte = content[i]
            i += 1
            n = (n << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        parts.append(str(n))
    return ".".join(parts)


def encode_timestamp_request(hashed_message, nonce):
    """A TimeStampReq. ``certReq`` is true so the answer carries a certificate."""
    if not isinstance(hashed_message, (bytes, bytearray)) or len(hashed_message) != 32:
        raise ValueError("the imprint must be 32 bytes")
    imprint = _seq(_alg_sha256(), _octets(bytes(hashed_message)))
    return _seq(_int(1), imprint, _int(nonce), _tlv(0x01, b"\xff"))


def parse_timestamp_request(data):
    """The imprint and the nonce a local authority has to echo."""
    fields = _one_seq(data)
    if len(fields) < 2 or fields[1][0] != 0x30:
        raise ValueError("timestamp request has no imprint")
    imprint = _walk(fields[1][1])
    hashed = None
    for tag, content, _raw in imprint:
        if tag == 0x04:
            hashed = content
    if hashed is None:
        raise ValueError("timestamp request imprint has no hash")
    nonce = None
    for tag, content, _raw in fields[2:]:
        if tag == 0x02:
            nonce = _parse_int(content)
    return {"hashed_message": hashed, "nonce": nonce}


def mint_token(*, hashed_message, nonce, key, cert, gen_time=None,
               policy_oid=LOCAL_POLICY_OID, serial=None):
    """A TimeStampResp from a key and certificate the caller generated.

    The route never calls this. A test's local authority does, with a
    certificate that test minted. A missing live authority is not filled
    in by calling this function.
    """
    from datetime import datetime, timezone
    if not isinstance(hashed_message, (bytes, bytearray)) or len(hashed_message) != 32:
        raise ValueError("the imprint must be 32 bytes")
    if gen_time is None:
        gen_time = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ")
    if isinstance(gen_time, str):
        gen_bytes = gen_time.encode("ascii")
    else:
        raise ValueError("gen_time must be a GeneralizedTime string")
    if serial is None:
        serial = secrets.randbits(63) or 1
    tst_info = _seq(
        _int(1),
        _oid(policy_oid),
        _seq(_alg_sha256(), _octets(bytes(hashed_message))),
        _int(serial),
        _tlv(0x18, gen_bytes),
        _int(nonce),
    )
    digest = hashlib.sha256(tst_info).digest()
    content_type = _seq(_oid(CONTENT_TYPE_OID), _set_of([_oid(TST_INFO_OID)]))
    message_digest = _seq(_oid(MESSAGE_DIGEST_OID), _set_of([_octets(digest)]))
    attr_body = b"".join(sorted((content_type, message_digest)))
    signed_set = _tlv(0x31, attr_body)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    signature = key.sign(signed_set, ec.ECDSA(hashes.SHA256()))
    issuer = cert.issuer.public_bytes()
    sid = _seq(issuer, _int(cert.serial_number))
    signer = _seq(
        _int(1),
        sid,
        _alg_sha256(),
        _tlv(0xA0, attr_body),
        _seq(_oid(ECDSA_SHA256_OID)),
        _octets(signature),
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    cert_der = cert.public_bytes(Encoding.DER)
    encap = _seq(_oid(TST_INFO_OID), _tlv(0xA0, _octets(tst_info)))
    signed_data = _seq(
        _int(3),
        _set_of([_alg_sha256()]),
        encap,
        _tlv(0xA0, cert_der),
        _set_of([signer]),
    )
    content_info = _seq(_oid(SIGNED_DATA_OID), _tlv(0xA0, signed_data))
    return _seq(_seq(_int(0)), _tlv(0xA0, content_info))


def verify_token(token, *, head_hash, roots_pem, nonce=None) -> dict:
    """Check a TimeStampResp against the custody head and a configured root.

    The root is configuration, the same posture as the Apple attestation
    root. No root, no pass. A token this function rejects is not stored as
    present, and the caller reports the timestamp missing rather than forged.
    """
    try:
        expected = head_imprint(head_hash)
    except ValueError as exc:
        return {"ok": False, "reason": str(exc)}
    try:
        parsed = _parse_response(token)
    except ValueError as exc:
        return {"ok": False, "reason": f"the timestamp token could not be read ({exc})"}
    if parsed["status"] not in (0, 1):
        return {"ok": False, "reason": f"the timestamp authority status is {parsed['status']}"}
    if parsed["hashed_message"] != expected:
        return {"ok": False, "reason": "the timestamp is not over this custody head"}
    if nonce is not None and parsed["nonce"] != nonce:
        return {"ok": False, "reason": "the timestamp nonce does not match this request"}
    if hashlib.sha256(parsed["tst_info"]).digest() != parsed["message_digest"]:
        return {"ok": False, "reason": "the timestamp's signed digest does not match the token"}
    if parsed["content_type"] != TST_INFO_OID:
        return {"ok": False, "reason": "the timestamp is not a TSTInfo"}
    cert = _signer_cert(parsed)
    if cert is None:
        return {"ok": False, "reason": "the timestamp token has no signer certificate"}
    if not _signature_ok(cert, parsed["signed_set"], parsed["signature"]):
        return {"ok": False, "reason": "the timestamp signature does not verify"}
    if not _has_time_stamping_eku(cert):
        return {"ok": False, "reason": "the timestamp certificate is not a time-stamping certificate"}
    if not _time_inside_cert(cert, parsed["gen_time"]):
        return {"ok": False, "reason": "the timestamp time is outside the certificate's validity"}
    if not _chains_to_roots(cert, roots_pem):
        return {"ok": False, "reason": "the timestamp certificate does not chain to a configured root"}
    return {
        "ok": True,
        "reason": "the timestamp verifies over this custody head",
        "gen_time": parsed["gen_time"],
        "policy": parsed["policy"],
        "serial": parsed["serial"],
    }


def _parse_response(token):
    fields = _one_seq(token)
    if not fields or fields[0][0] != 0x30:
        raise ValueError("no status")
    status_fields = _walk(fields[0][1])
    if not status_fields or status_fields[0][0] != 0x02:
        raise ValueError("status is not an integer")
    status = _parse_int(status_fields[0][1])
    if len(fields) < 2 or fields[1][0] != 0xA0:
        raise ValueError("no token")
    # [0] EXPLICIT ContentInfo, so the content is the ContentInfo TLV.
    content_info = fields[1][1]
    info_fields = _one_seq(content_info)
    if len(info_fields) < 2 or info_fields[0][0] != 0x06:
        raise ValueError("token content type is missing")
    if _oid_str(info_fields[0][1]) != SIGNED_DATA_OID:
        raise ValueError("token is not SignedData")
    if info_fields[1][0] != 0xA0:
        raise ValueError("SignedData is missing")
    # version INT, digestAlgorithms SET, encapContentInfo SEQ, certs [0], signers SET.
    signed_fields = _one_seq(info_fields[1][1])
    version_seen = False
    encap = None
    cert_bytes = b""
    signer_blob = None
    for tag, content, _raw in signed_fields:
        if tag == 0x02 and not version_seen:
            version_seen = True
            continue
        if tag == 0x31 and encap is None:
            continue
        if tag == 0x30 and encap is None:
            encap = content
            continue
        if tag == 0xA0 and encap is not None and not cert_bytes:
            cert_bytes = content
            continue
        if tag == 0x31 and encap is not None:
            signer_blob = content
    if encap is None or signer_blob is None:
        raise ValueError("SignedData is incomplete")
    encap_fields = _walk(encap)
    if len(encap_fields) < 2 or encap_fields[1][0] != 0xA0:
        raise ValueError("TSTInfo is missing")
    octet = _walk(encap_fields[1][1])
    if len(octet) != 1 or octet[0][0] != 0x04:
        raise ValueError("TSTInfo wrapper is not an octet string")
    tst_info = octet[0][1]
    tst_fields = _one_seq(tst_info)
    if len(tst_fields) < 5:
        raise ValueError("TSTInfo is short")
    if tst_fields[0][0] != 0x02 or tst_fields[1][0] != 0x06:
        raise ValueError("TSTInfo does not start with version and policy")
    policy = _oid_str(tst_fields[1][1])
    imprint = _walk(tst_fields[2][1]) if tst_fields[2][0] == 0x30 else []
    hashed = None
    for tag, content, _raw in imprint:
        if tag == 0x04:
            hashed = content
    if hashed is None:
        raise ValueError("TSTInfo has no imprint")
    if tst_fields[3][0] != 0x02 or tst_fields[4][0] != 0x18:
        raise ValueError("TSTInfo serial or time is missing")
    serial = _parse_int(tst_fields[3][1])
    gen_time = tst_fields[4][1].decode("ascii")
    nonce_val = None
    for tag, content, _raw in tst_fields[5:]:
        if tag == 0x02:
            nonce_val = _parse_int(content)
        elif tag in (0x30, 0x01, 0xA0, 0xA1):
            continue
        else:
            raise ValueError("TSTInfo has an unexpected field")
    signer_fields = _one_seq(_first_seq(signer_blob))
    signed_set, signature, content_type, message_digest = _signer_bits(signer_fields)
    return {
        "status": status,
        "hashed_message": hashed,
        "nonce": nonce_val,
        "policy": policy,
        "serial": serial,
        "gen_time": gen_time,
        "tst_info": tst_info,
        "certificates": cert_bytes,
        "signed_set": signed_set,
        "signature": signature,
        "content_type": content_type,
        "message_digest": message_digest,
    }


def _first_seq(set_content):
    """SignerInfos is a SET of SignerInfo. Take the first SEQUENCE."""
    for tag, content, raw in _walk(set_content):
        if tag == 0x30:
            return raw
    raise ValueError("no signer")


def _signer_bits(fields):
    signed_raw = None
    signature = None
    for tag, content, raw in fields:
        if tag == 0xA0 and signed_raw is None:
            signed_raw = raw
        elif tag == 0x04:
            signature = content
    if signed_raw is None or signature is None:
        raise ValueError("signer info has no signed attributes")
    # The signature covers the same bytes with the SET tag, not the implicit tag.
    if signed_raw[0] != 0xA0:
        raise ValueError("signed attributes are not implicit")
    signed_set = bytes([0x31]) + signed_raw[1:]
    attr_fields = _walk(_value_of(signed_raw))
    content_type = None
    message_digest = None
    for tag, content, _raw in attr_fields:
        if tag != 0x30:
            continue
        parts = _walk(content)
        if len(parts) < 2 or parts[0][0] != 0x06:
            continue
        oid = _oid_str(parts[0][1])
        inner = _walk(parts[1][1]) if parts[1][0] == 0x31 else []
        if oid == CONTENT_TYPE_OID and inner and inner[0][0] == 0x06:
            content_type = _oid_str(inner[0][1])
        elif oid == MESSAGE_DIGEST_OID and inner and inner[0][0] == 0x04:
            message_digest = inner[0][1]
    if content_type is None or message_digest is None:
        raise ValueError("signed attributes are missing content-type or message-digest")
    return signed_set, signature, content_type, message_digest


def _value_of(tlv):
    _tag, content, _raw = _walk(tlv)[0]
    return content


def _signer_cert(parsed):
    from cryptography import x509
    certs = []
    for tag, content, raw in _walk(parsed["certificates"]):
        if tag == 0x30:
            try:
                certs.append(x509.load_der_x509_certificate(raw))
            except Exception:
                continue
    for cert in certs:
        if _signature_ok(cert, parsed["signed_set"], parsed["signature"]):
            return cert
    return certs[0] if len(certs) == 1 else None


def _signature_ok(cert, signed_set, signature):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    pub = cert.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed_set, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, signed_set, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _has_time_stamping_eku(cert):
    from cryptography import x509
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except Exception:
        return False
    return TIME_STAMPING_EKU in {oid.dotted_string for oid in ext}


def _time_inside_cert(cert, gen_time):
    from datetime import datetime, timezone
    try:
        when = datetime.strptime(gen_time, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    start = getattr(cert, "not_valid_before_utc", None)
    end = getattr(cert, "not_valid_after_utc", None)
    if start is None:
        start = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if end is None:
        end = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return start <= when <= end


def _load_roots(roots_pem):
    from cryptography import x509
    marker = "BEGIN " + "CERTIFICATE"
    if not isinstance(roots_pem, str) or marker not in roots_pem:
        return []
    text = roots_pem.replace("\\n", "\n")
    out = []
    end = "-----END " + "CERTIFICATE-----"
    begin = "-----BEGIN " + "CERTIFICATE-----"
    chunks = text.split(end)
    for chunk in chunks:
        if begin not in chunk:
            continue
        pem = chunk.split(begin, 1)[1]
        pem = begin + pem + end + "\n"
        try:
            out.append(x509.load_pem_x509_certificate(pem.encode("ascii")))
        except Exception:
            continue
    return out


def _chains_to_roots(cert, roots_pem):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    roots = _load_roots(roots_pem)
    if not roots:
        return False
    for root in roots:
        if cert.issuer.public_bytes() != root.subject.public_bytes():
            continue
        pub = root.public_key()
        try:
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(cert.signature, cert.tbs_certificate_bytes,
                           ec.ECDSA(hashes.SHA256()))
            elif isinstance(pub, rsa.RSAPublicKey):
                pub.verify(cert.signature, cert.tbs_certificate_bytes,
                           padding.PKCS1v15(), hashes.SHA256())
            else:
                continue
        except InvalidSignature:
            continue
        except Exception:
            continue
        return True
    return False
