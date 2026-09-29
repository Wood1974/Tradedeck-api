"""Break an Apple App Attest attestation every way it can be broken.

This is the only file in the service that can turn `verified` into `True`, and
`verified is True` is the single condition between an unattested photograph and
full hardware trust. So a happy-path test proves nothing here: an
implementation that returns success unconditionally would pass it. What has to
be shown is that each individual check is load-bearing — that removing any one
of them, or corrupting the input it reads, is caught.

So every test below starts from an attestation that verifies, changes exactly
one thing, and asserts the refusal. If a check is ever deleted, the test for it
goes green in the wrong direction and fails.

The chain is synthetic, which is the point: a test that needed a real Apple
attestation could not be run, and an attestation nobody can regenerate is a
fixture that rots into a skipped test. The root here is a CA this file mints,
handed to `verify()` through the same `root_pem` parameter production uses —
which is exactly the substitution the module was designed for, and why the
Apple root is configuration rather than a constant.
"""
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

cbor2 = pytest.importorskip("cbor2", reason="cbor2 is not installed")
pytest.importorskip("cryptography", reason="cryptography is not installed")

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes                # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa    # noqa: E402
from cryptography.hazmat.primitives.serialization import (       # noqa: E402
    Encoding, PublicFormat)
from cryptography.x509.oid import NameOID                        # noqa: E402

import app_attest                                                # noqa: E402
import attestation                                               # noqa: E402

APP_ID = "ABCDE12345.com.tradedeck.shield"
CHALLENGE = "challenge-issued-for-this-one-capture"
PHOTO = b"\xff\xd8\xff\xe0 the bytes this attestation is supposed to be about"
PHOTO_SHA = hashlib.sha256(PHOTO).digest()
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------- the generator --
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, subject_key, issuer_cn, issuer_key, *, ca,
          not_before=None, not_after=None, extra=()):
    """One certificate. Everything the tests vary is a parameter."""
    not_before = not_before or (NOW - timedelta(days=30))
    not_after = not_after or (NOW + timedelta(days=30))
    builder = (x509.CertificateBuilder()
               .subject_name(_name(subject_cn))
               .issuer_name(_name(issuer_cn))
               .public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before.replace(tzinfo=None))
               .not_valid_after(not_after.replace(tzinfo=None))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                              critical=True))
    for ext, critical in extra:
        builder = builder.add_extension(ext, critical)
    return builder.sign(issuer_key, hashes.SHA256())


def _nonce_extension(nonce):
    """Apple's shape: SEQUENCE { [1] { OCTET STRING nonce } }.

    Hand-encoded rather than pulled from a DER library, so that the test knows
    what it built. `verify()` deliberately does not parse this structure — it
    requires the digest to appear inside — and this exercises that against the
    real wrapper rather than against a bare 32 bytes.
    """
    octets = b"\x04" + bytes([len(nonce)]) + nonce
    tagged = b"\xa1" + bytes([len(octets)]) + octets
    der = b"\x30" + bytes([len(tagged)]) + tagged
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier(app_attest.NONCE_OID), der)


def _auth_data(*, credential_id, app_id=APP_ID, counter=0,
               aaguid=app_attest.AAGUID_PROD, truncate=False):
    out = (hashlib.sha256(app_id.encode()).digest()          # rpIdHash
           + b"\x40"                                          # flags
           + counter.to_bytes(4, "big")
           + aaguid
           + len(credential_id).to_bytes(2, "big")
           + credential_id)
    return out[:40] if truncate else out


def build(*, challenge=CHALLENGE, payload_sha256=None, app_id=APP_ID, counter=0,
          aaguid=app_attest.AAGUID_PROD, fmt="apple-appattest",
          nonce_over=None, omit_nonce_ext=False, credential_id=None,
          leaf_expired=False, unlinked=False, drop_intermediate=False,
          rsa_leaf=False, root_override=None, truncate_auth_data=False):
    """Return (attestation_bytes, key_id, root_pem) for one scenario.

    Order matters and is Apple's: the nonce covers authData, and authData
    carries the key id, so the key must exist before authData, and authData
    before the certificate that attests it.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = (rsa.generate_private_key(65537, 2048) if rsa_leaf
                else ec.generate_private_key(ec.SECP256R1()))

    root = _cert("Test App Attest Root CA", root_key,
                 "Test App Attest Root CA", root_key, ca=True)
    inter = _cert("Test App Attest CA 1", inter_key,
                  "Test App Attest Root CA", root_key, ca=True)

    if rsa_leaf:
        key_id = hashlib.sha256(b"rsa-has-no-uncompressed-point").digest()
    else:
        key_id = hashlib.sha256(leaf_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)).digest()

    auth_data = _auth_data(credential_id=credential_id or key_id,
                           app_id=app_id, counter=counter, aaguid=aaguid,
                           truncate=truncate_auth_data)
    client_data = ((nonce_over or challenge).encode()
                   + (payload_sha256 or PHOTO_SHA))
    nonce = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()

    extra = () if omit_nonce_ext else ((_nonce_extension(nonce), False),)
    leaf_issuer_key = root_key if unlinked else inter_key
    leaf_issuer_cn = ("Test App Attest Root CA" if unlinked
                      else "Test App Attest CA 1")
    leaf = _cert("device leaf", leaf_key, leaf_issuer_cn, leaf_issuer_key,
                 ca=False, extra=extra,
                 not_before=(NOW - timedelta(days=400)) if leaf_expired else None,
                 not_after=(NOW - timedelta(days=370)) if leaf_expired else None)

    chain = [leaf.public_bytes(Encoding.DER)]
    if not drop_intermediate:
        chain.append(inter.public_bytes(Encoding.DER))

    blob = cbor2.dumps({"fmt": fmt,
                        "attStmt": {"x5c": chain, "receipt": b"receipt"},
                        "authData": auth_data})
    root_pem = (root_override or root).public_bytes(Encoding.PEM).decode()
    return blob, key_id, root_pem


def run(**kw):
    challenge = kw.pop("verify_challenge", CHALLENGE)
    app_id = kw.pop("verify_app_id", APP_ID)
    key_id_override = kw.pop("verify_key_id", None)
    payload = kw.pop("verify_payload_sha256", PHOTO_SHA)
    allow_dev = kw.pop("allow_development", False)
    blob, key_id, root_pem = build(**kw)
    return app_attest.verify(blob, challenge=challenge,
                             payload_sha256=payload, app_id=app_id,
                             key_id=key_id_override or key_id,
                             root_pem=root_pem,
                             allow_development=allow_dev, now=NOW)


# ------------------------------------------------------------- it does work --
def test_a_correct_attestation_verifies():
    """If this fails, every refusal below proves nothing."""
    out = run()
    assert out["verified"] is True, out["reason"]
    assert out["receipt_ok"] is True
    assert out["token_nonce"] == CHALLENGE


def test_a_verified_attestation_reaches_hardware_trust():
    """The whole point: this is what makes `verified=True` reachable.

    Asserted through `interpret_app_attest` rather than by reading the dict,
    because the dict's job is to satisfy that function, and a field renamed on
    one side of the boundary is exactly the defect that would leave captures
    silently refused forever.
    """
    out = run()
    verdict = attestation.interpret_app_attest(
        verified=out["verified"], receipt_ok=out["receipt_ok"],
        token_nonce=out["token_nonce"], expect_nonce=CHALLENGE)
    assert verdict["tier"] == attestation.TIER_HARDWARE
    assert verdict["trusted"] is True
    assert verdict["bound"] is True


def test_the_returned_nonce_is_checked_against_the_challenge_again():
    """A caller that expects a different challenge must not get trust."""
    out = run()
    verdict = attestation.interpret_app_attest(
        verified=out["verified"], receipt_ok=out["receipt_ok"],
        token_nonce=out["token_nonce"], expect_nonce="some-other-challenge")
    assert verdict["trusted"] is False


# ------------------------------------------------------------ the bindings --
def test_an_attestation_for_another_challenge_is_refused():
    """The replay. A genuine device, a genuine chain, a different moment."""
    out = run(nonce_over="a-challenge-from-an-hour-ago")
    assert out["verified"] is False
    assert "not bound" in out["reason"]


def test_verifying_against_another_challenge_is_refused():
    """Same attack from the other side: the server spent a fresh challenge."""
    out = run(verify_challenge="a-freshly-issued-challenge")
    assert out["verified"] is False
    assert "not bound" in out["reason"]


def test_an_attestation_does_not_transfer_to_other_bytes():
    """The attack the challenge alone does not stop.

    A genuine iPhone, a genuine app, an honest attestation against a live
    challenge — and a stock photograph of somebody else's finished roof in the
    same request. If `clientDataHash` covered only the challenge, every check
    would pass and the forged file would be sealed into the chain wearing
    hardware trust. That is AR-1 reappearing one layer up.
    """
    out = run(verify_payload_sha256=hashlib.sha256(b"a different file").digest())
    assert out["verified"] is False
    assert "not bound to this photograph" in out["reason"]


def test_an_attestation_minted_over_other_bytes_is_refused():
    """Same attack from the client's side."""
    out = run(payload_sha256=hashlib.sha256(b"what the device really saw").digest())
    assert out["verified"] is False
    assert "not bound to this photograph" in out["reason"]


def test_without_a_payload_digest_nothing_verifies():
    """No call shape can forget it, so no deployment can be bound to nothing."""
    blob, key_id, root = build()
    for empty in (None, b""):
        out = app_attest.verify(blob, challenge=CHALLENGE,
                                payload_sha256=empty, app_id=APP_ID,
                                key_id=key_id, root_pem=root, now=NOW)
        assert out["verified"] is False
        assert "payload digest" in out["reason"]


def test_a_leaf_without_the_nonce_extension_is_refused():
    out = run(omit_nonce_ext=True)
    assert out["verified"] is False
    assert "bound to nothing" in out["reason"]


def test_an_attestation_minted_for_another_app_is_refused():
    out = run(app_id="ZZZZZ99999.com.someone.else")
    assert out["verified"] is False
    assert "different app" in out["reason"]


# ----------------------------------------------------------------- the key --
def test_a_key_id_that_does_not_match_the_certificate_is_refused():
    out = run(verify_key_id=hashlib.sha256(b"some other key").digest())
    assert out["verified"] is False
    assert "key id" in out["reason"]


def test_auth_data_naming_a_different_key_is_refused():
    out = run(credential_id=hashlib.sha256(b"not this key").digest())
    assert out["verified"] is False
    assert "different key" in out["reason"]


def test_a_non_elliptic_curve_key_is_refused():
    out = run(rsa_leaf=True)
    assert out["verified"] is False
    assert "elliptic-curve" in out["reason"]


# --------------------------------------------------------------- the chain --
def test_a_chain_to_a_different_root_is_refused():
    """The forged-attestation case: the attacker runs their own CA."""
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root = _cert("Not Apple", other_root_key, "Not Apple",
                       other_root_key, ca=True)
    out = run(root_override=other_root)
    assert out["verified"] is False
    assert "chain" in out["reason"]


def test_a_chain_that_does_not_link_up_is_refused():
    out = run(unlinked=True)
    assert out["verified"] is False
    assert "does not link up" in out["reason"]


def test_a_missing_intermediate_is_refused():
    out = run(drop_intermediate=True)
    assert out["verified"] is False
    assert "does not link up" in out["reason"]


def test_an_expired_certificate_is_refused():
    out = run(leaf_expired=True)
    assert out["verified"] is False
    assert "validity window" in out["reason"]


def test_an_attestation_carrying_no_chain_is_refused():
    blob = cbor2.dumps({"fmt": "apple-appattest", "attStmt": {"x5c": []},
                        "authData": b"\x00" * 60})
    out = app_attest.verify(blob, challenge=CHALLENGE,
                            payload_sha256=PHOTO_SHA, app_id=APP_ID,
                            key_id=b"", root_pem=_a_root(), now=NOW)
    assert out["verified"] is False
    assert "no certificate chain" in out["reason"]


# --------------------------------------------------------------- the shape --
def test_a_non_zero_counter_is_refused():
    """An assertion replayed where an attestation belongs."""
    out = run(counter=1)
    assert out["verified"] is False
    assert "counter" in out["reason"]


def test_a_development_attestation_is_refused_by_default():
    out = run(aaguid=app_attest.AAGUID_DEV)
    assert out["verified"] is False
    assert "development" in out["reason"]


def test_a_development_attestation_passes_only_when_asked_for():
    out = run(aaguid=app_attest.AAGUID_DEV, allow_development=True)
    assert out["verified"] is True, out["reason"]


def test_an_unknown_attestation_environment_is_refused():
    out = run(aaguid=b"someothersandbox", allow_development=True)
    assert out["verified"] is False


def test_a_wrong_format_is_refused():
    out = run(fmt="android-key")
    assert out["verified"] is False
    assert "format" in out["reason"]


def test_truncated_auth_data_is_refused():
    """Reached directly: a short authData cannot carry a matching nonce."""
    assert app_attest._parse_auth_data(b"\x00" * 40) is None
    assert app_attest._parse_auth_data(b"") is None
    short = _auth_data(credential_id=b"\x01" * 32)[:50]
    assert app_attest._parse_auth_data(short) is None


def test_truncated_auth_data_is_refused_through_verify_too():
    """Not just the helper: the refusal has to survive the whole path.

    The nonce here is computed over the *truncated* bytes, so the binding
    check passes and the certificate attests exactly what arrived. Every
    earlier check is happy. If the length check were dropped, this would be
    a short buffer being sliced into fields.
    """
    out = run(truncate_auth_data=True)
    assert out["verified"] is False
    assert "truncated or malformed" in out["reason"]


def test_a_credential_length_longer_than_the_buffer_is_refused():
    """The classic: a length field that points past the end."""
    blown = (hashlib.sha256(APP_ID.encode()).digest() + b"\x40"
             + (0).to_bytes(4, "big") + app_attest.AAGUID_PROD
             + (9999).to_bytes(2, "big") + b"\x01" * 4)
    assert app_attest._parse_auth_data(blown) is None


# ------------------------------------------------------------ the anchor ----
def _a_root():
    key = ec.generate_private_key(ec.SECP256R1())
    return _cert("r", key, "r", key, ca=True).public_bytes(Encoding.PEM).decode()


def test_with_no_root_configured_nothing_verifies():
    """Absence of the anchor is a refusal, never a fallback.

    The failure this forbids is the quiet one: a service deployed without
    APPLE_APP_ATTEST_ROOT_PEM that verifies anything, because a missing root
    was treated as "skip the chain check".
    """
    blob, key_id, _root = build()
    for empty in (None, "", b""):
        out = app_attest.verify(blob, challenge=CHALLENGE,
                                payload_sha256=PHOTO_SHA, app_id=APP_ID,
                                key_id=key_id, root_pem=empty, now=NOW)
        assert out["verified"] is False
        assert "root certificate is configured" in out["reason"]


def test_with_no_challenge_nothing_verifies():
    blob, key_id, root = build()
    out = app_attest.verify(blob, challenge=None, payload_sha256=PHOTO_SHA,
                            app_id=APP_ID, key_id=key_id, root_pem=root,
                            now=NOW)
    assert out["verified"] is False
    assert "no challenge" in out["reason"]


def test_the_apple_root_is_not_hardcoded():
    """A certificate typed from memory is unreviewable either way.

    Wrong, and nothing verifies while the failure looks like an app bug.
    Right-looking and not Apple's, and this module validates chains an
    attacker minted. Neither is visible by reading the code, so the anchor
    has to arrive as configuration and this test says so out loud.
    """
    with open(os.path.join(os.path.dirname(__file__), "..",
                           "app_attest.py")) as fh:
        src = fh.read()
    assert "BEGIN CERTIFICATE" not in src


# ------------------------------------------------------------- it is input --
def test_garbage_never_raises():
    """Everything on this path arrives from an untrusted client.

    A traceback escaping `verify()` is a 500 an attacker can produce at will,
    which is a denial of service with extra steps.
    """
    import random
    rnd = random.Random(20260928)
    root = _a_root()
    cases = [b"", b"\x00", b"not cbor at all", b"\xff" * 64,
             cbor2.dumps([1, 2, 3]), cbor2.dumps("a string"),
             cbor2.dumps({"fmt": "apple-appattest"}),
             cbor2.dumps({"fmt": "apple-appattest", "attStmt": {},
                          "authData": b""}),
             cbor2.dumps({"fmt": "apple-appattest", "attStmt": {"x5c": "nope"},
                          "authData": b"x"}),
             cbor2.dumps({"fmt": "apple-appattest",
                          "attStmt": {"x5c": [b"not a certificate"]},
                          "authData": b"x" * 60})]
    cases += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 300)))
              for _ in range(300)]
    for blob in cases:
        out = app_attest.verify(blob, challenge=CHALLENGE,
                                payload_sha256=PHOTO_SHA, app_id=APP_ID,
                                key_id=b"\x00" * 32, root_pem=root, now=NOW)
        assert out["verified"] is False
        assert isinstance(out["reason"], str) and out["reason"]


def test_every_refusal_has_the_same_shape():
    """No caller should have to guess which keys a refusal carries."""
    for out in (app_attest.verify(b"", challenge=CHALLENGE,
                                  payload_sha256=PHOTO_SHA, app_id=APP_ID,
                                  key_id=b"", root_pem=_a_root(), now=NOW),
                run(counter=3), run(omit_nonce_ext=True)):
        assert out["verified"] is False
        assert out["receipt_ok"] is False
        assert out["token_nonce"] is None


# ------------------------------------------------------------- assertions --
# Same discipline as above: every test starts from an assertion that verifies,
# changes exactly one thing, and asserts the refusal.
DEVICE_KEY = ec.generate_private_key(ec.SECP256R1())
DEVICE_PUB = DEVICE_KEY.public_key().public_bytes(
    Encoding.X962, PublicFormat.UncompressedPoint)


def build_assertion(*, key=DEVICE_KEY, challenge=CHALLENGE,
                    payload_sha256=PHOTO_SHA, app_id=APP_ID, counter=1,
                    extensions=None, raw_extensions=None, sign_over=None,
                    omit_signature=False, truncate=False):
    flags = 0x80 if (extensions is not None or raw_extensions) else 0x00
    auth_data = (hashlib.sha256(app_id.encode()).digest()
                 + bytes([flags]) + counter.to_bytes(4, "big"))
    if extensions is not None:
        auth_data += cbor2.dumps(extensions)
    elif raw_extensions:
        auth_data += raw_extensions
    if truncate:
        auth_data = auth_data[:30]
    client_data = challenge.encode() + payload_sha256
    nonce = hashlib.sha256(
        auth_data + hashlib.sha256(client_data).digest()).digest()
    signature = key.sign(sign_over or nonce, ec.ECDSA(hashes.SHA256()))
    body = {"authenticatorData": auth_data}
    if not omit_signature:
        body["signature"] = signature
    return cbor2.dumps(body)


def run_assertion(blob=None, *, public_key=DEVICE_PUB, previous_counter=0,
                  challenge=CHALLENGE, payload_sha256=PHOTO_SHA, app_id=APP_ID,
                  environment="production", allow_development=False, **kw):
    blob = blob if blob is not None else build_assertion(**kw)
    return app_attest.verify_assertion(
        blob, challenge=challenge, payload_sha256=payload_sha256,
        app_id=app_id, public_key=public_key,
        previous_counter=previous_counter, environment=environment,
        allow_development=allow_development)


class TestAssertion:
    def test_a_correct_assertion_verifies(self):
        """If this fails, every refusal below proves nothing."""
        out = run_assertion()
        assert out["verified"] is True, out["reason"]
        assert out["counter"] == 1
        assert out["token_nonce"] == CHALLENGE

    def test_a_verified_assertion_reaches_hardware_trust(self):
        out = run_assertion()
        verdict = attestation.interpret_app_attest(
            verified=out["verified"], receipt_ok=out["receipt_ok"],
            token_nonce=out["token_nonce"], expect_nonce=CHALLENGE)
        assert verdict["tier"] == attestation.TIER_HARDWARE
        assert verdict["bound"] is True

    def test_an_attestation_returns_the_key_an_assertion_needs(self):
        """The two halves must meet: the key `verify` hands back is the one
        `verify_assertion` checks against."""
        blob, key_id, root_pem = build()
        out = app_attest.verify(blob, challenge=CHALLENGE,
                                payload_sha256=PHOTO_SHA, app_id=APP_ID,
                                key_id=key_id, root_pem=root_pem, now=NOW)
        assert out["verified"] is True, out["reason"]
        assert hashlib.sha256(out["public_key"]).digest() == key_id
        assert out["environment"] == "production"
        assert out["receipt"] == b"receipt"

    def test_a_different_photograph_is_refused(self):
        out = run_assertion(payload_sha256=hashlib.sha256(b"stock roof").digest())
        assert out["verified"] is False
        assert "signature" in out["reason"]

    def test_a_different_challenge_is_refused(self):
        assert run_assertion(challenge="some-other-challenge")["verified"] is False

    def test_a_signature_over_the_wrong_message_is_refused(self):
        assert run_assertion(sign_over=b"not the nonce")["verified"] is False

    def test_a_different_key_is_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        assert run_assertion(key=other)["verified"] is False

    def test_another_apps_assertion_is_refused(self):
        out = run_assertion(app_id="ZZZZZ99999.com.someone.else")
        assert out["verified"] is False
        assert "different app" in out["reason"]

    def test_a_counter_that_does_not_advance_is_refused(self):
        out = run_assertion(counter=5, previous_counter=5)
        assert out["verified"] is False
        assert "counter" in out["reason"]

    def test_a_counter_that_goes_backwards_is_refused(self):
        assert run_assertion(counter=3, previous_counter=7)["verified"] is False

    def test_zero_is_not_a_first_assertion(self):
        """Apple: greater than 0 on the first assertion."""
        assert run_assertion(counter=0, previous_counter=0)["verified"] is False

    def test_no_key_on_file_is_refused(self):
        assert run_assertion(public_key=None)["verified"] is False

    def test_a_garbage_key_on_file_is_refused(self):
        assert run_assertion(public_key=b"\x04" + b"\x00" * 64)["verified"] is False

    def test_a_development_key_is_refused_in_production(self):
        out = run_assertion(environment="development")
        assert out["verified"] is False
        assert "development" in out["reason"]

    def test_a_development_key_is_accepted_when_asked_for(self):
        out = run_assertion(environment="development", allow_development=True)
        assert out["verified"] is True, out["reason"]

    @pytest.mark.parametrize("blob", [b"", b"\xff\xff", cbor2.dumps([1, 2]),
                                      cbor2.dumps({"signature": "text"})])
    def test_malformed_input_is_refused_not_raised(self, blob):
        assert run_assertion(blob)["verified"] is False

    def test_a_missing_signature_is_refused(self):
        assert run_assertion(omit_signature=True)["verified"] is False

    def test_truncated_authenticator_data_is_refused(self):
        assert run_assertion(truncate=True)["verified"] is False

    def test_no_challenge_or_digest_is_refused(self):
        assert run_assertion(challenge="")["verified"] is False
        assert run_assertion(payload_sha256=b"")["verified"] is False

    @pytest.mark.parametrize("category", [2, 4])
    def test_distributed_builds_are_accepted(self, category):
        out = run_assertion(
            extensions={"apple_validation_category_01": category})
        assert out["verified"] is True, out["reason"]
        assert out["validation_category"] == category

    @pytest.mark.parametrize("category", [0, 1, 5, 6, 7, 8, 9, 10])
    def test_other_builds_are_refused(self, category):
        out = run_assertion(
            extensions={"apple_validation_category_01": category})
        assert out["verified"] is False
        assert "validation category" in out["reason"]

    def test_a_development_build_needs_development_allowed(self):
        ext = {"apple_validation_category_01": 3}
        assert run_assertion(extensions=ext)["verified"] is False
        assert run_assertion(extensions=ext,
                             allow_development=True)["verified"] is True

    def test_unreadable_extensions_are_refused(self):
        """Signed by the Secure Enclave, so never accidental."""
        out = run_assertion(raw_extensions=b"\xff\x00garbage")
        assert out["verified"] is False

    def test_absent_extensions_are_not_a_refusal(self):
        """Older OS versions do not send the dictionary at all."""
        out = run_assertion()
        assert out["verified"] is True
        assert out["validation_category"] is None
