"""Break an Android Key Attestation every way it can be broken.

Same discipline as `test_app_attest.py`: every test starts from a chain that
verifies, changes exactly one thing, and asserts the refusal. The chain is
synthetic -- a root this file mints, handed to `verify()` through the same
`roots_pem` parameter production fills from ANDROID_ATTESTATION_ROOTS_PEM --
and the KeyDescription extension is DER this file encodes by hand, so the test
knows exactly what it built.
"""
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("cryptography", reason="cryptography is not installed")

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes                # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa    # noqa: E402
from cryptography.hazmat.primitives.serialization import (       # noqa: E402
    Encoding, PublicFormat)
from cryptography.x509.oid import NameOID                        # noqa: E402

import android_attest                                            # noqa: E402
import attestation                                               # noqa: E402

PACKAGE = "com.tradedeck.shield"
SIGNING_DIGEST = hashlib.sha256(b"shield release signing certificate").digest()
CHALLENGE = "challenge-issued-for-this-one-capture"
PHOTO = b"\xff\xd8\xff\xe0 the bytes this attestation is supposed to be about"
PHOTO_SHA = hashlib.sha256(PHOTO).digest()
CLIENT_DATA_HASH = hashlib.sha256(CHALLENGE.encode() + PHOTO_SHA).digest()
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------ DER writer --
def tlv(first_byte_bits, tag, value):
    """Encode one TLV. `first_byte_bits` is class + constructed."""
    if tag < 31:
        head = bytes([first_byte_bits | tag])
    else:
        digits = []
        t = tag
        while True:
            digits.insert(0, t & 0x7F)
            t >>= 7
            if not t:
                break
        head = bytes([first_byte_bits | 0x1F]) + bytes(
            [d | 0x80 for d in digits[:-1]] + [digits[-1]])
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return head + length + value


def seq(*items):
    return tlv(0x20, 16, b"".join(items))


def set_of(*items):
    return tlv(0x20, 17, b"".join(sorted(items)))


def integer(v, tag=2):
    return tlv(0x00, tag, v.to_bytes(max(1, (v.bit_length() + 8) // 8),
                                     "big", signed=True))


def enum(v):
    return integer(v, tag=10)


def octets(b):
    return tlv(0x00, 4, b)


def boolean(v):
    return tlv(0x00, 1, b"\xff" if v else b"\x00")


def explicit(tag, inner):
    return tlv(0xA0, tag, inner)          # context-specific, constructed


def application_id(packages=(PACKAGE,), digests=(SIGNING_DIGEST,)):
    return seq(set_of(*[seq(octets(p.encode()), integer(1))
                        for p in packages]),
               set_of(*[octets(d) for d in digests]))


def key_description(*, challenge=CLIENT_DATA_HASH, att_level=1, km_level=1,
                    boot_state=0, locked=True, origin=0, algorithm=3,
                    purposes=(2, 3), app_id=None, app_in_hardware=False,
                    omit_root_of_trust=False, omit_origin=False):
    app_id = application_id() if app_id is None else app_id
    hw = [explicit(1, set_of(*[integer(p) for p in purposes])),
          explicit(2, integer(algorithm)),
          explicit(10, integer(1))]
    if not omit_origin:
        hw.append(explicit(702, integer(origin)))
    if not omit_root_of_trust:
        hw.append(explicit(704, seq(octets(b"\x00" * 32), boolean(locked),
                                    enum(boot_state), octets(b"\x11" * 32))))
    sw = [explicit(701, integer(1_700_000_000_000))]
    if app_in_hardware:
        hw.append(explicit(709, octets(app_id)))
    else:
        sw.append(explicit(709, octets(app_id)))
    return seq(integer(300), enum(att_level), integer(300), enum(km_level),
               octets(challenge), octets(b""), seq(*sw), seq(*hw))


# ---------------------------------------------------------- chain maker --
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, subject_key, issuer_cn, issuer_key, *, ca=True,
          ext=None, not_before=None, not_after=None, serial=None):
    builder = (x509.CertificateBuilder()
               .subject_name(_name(subject_cn))
               .issuer_name(_name(issuer_cn))
               .public_key(subject_key.public_key())
               .serial_number(serial or x509.random_serial_number())
               .not_valid_before((not_before or NOW - timedelta(days=30))
                                 .replace(tzinfo=None))
               .not_valid_after((not_after or NOW + timedelta(days=30))
                                .replace(tzinfo=None))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                              critical=True))
    if ext is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier(android_attest.KEY_DESCRIPTION_OID), ext),
            critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


DEVICE_KEY = ec.generate_private_key(ec.SECP256R1())
DEVICE_PUB = DEVICE_KEY.public_key().public_bytes(
    Encoding.X962, PublicFormat.UncompressedPoint)


def build(*, desc=None, rsa_root=False, leaf_key=None, leaf_expired=False,
          extension_on_intermediate=False, forged_by_attested_key=False,
          drop_root=False, root_override=None, leaf_serial=None,
          unlinked=False, **desc_kw):
    """Return (chain_der, roots_pem). Leaf first, root last, like Android."""
    root_key = (rsa.generate_private_key(65537, 2048) if rsa_root
                else ec.generate_private_key(ec.SECP256R1()))
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = leaf_key or DEVICE_KEY
    ext = desc if desc is not None else key_description(**desc_kw)

    root = _cert("Test Attestation Root", root_key,
                 "Test Attestation Root", root_key)
    inter = _cert("Test Attestation Intermediate", inter_key,
                  "Test Attestation Root", root_key,
                  ext=ext if extension_on_intermediate else None)
    leaf_issuer_key = root_key if unlinked else inter_key
    leaf = _cert("Android Keystore Key", leaf_key,
                 "Test Attestation Intermediate", leaf_issuer_key, ca=False,
                 ext=ext, serial=leaf_serial,
                 not_before=NOW - timedelta(days=400) if leaf_expired else None,
                 not_after=NOW - timedelta(days=370) if leaf_expired else None)
    chain = [leaf, inter, root]

    if forged_by_attested_key:
        # The attack step 4 exists for: the genuine attested key certifies a
        # key the attacker made, with an extension the attacker wrote.
        fake_key = ec.generate_private_key(ec.SECP256R1())
        fake = _cert("Forged Key", fake_key, "Android Keystore Key",
                     leaf_key, ca=False, ext=ext)
        chain = [fake] + chain
    if drop_root:
        chain = chain[:-1]

    roots_pem = (root_override or root).public_bytes(Encoding.PEM).decode()
    return [c.public_bytes(Encoding.DER) for c in chain], roots_pem


def run(*, verify_challenge=CHALLENGE, verify_payload=PHOTO_SHA,
        package=PACKAGE, digests=(SIGNING_DIGEST,), revoked=frozenset(),
        roots_pem=None, chain=None, **kw):
    built_chain, built_roots = build(**kw)
    return android_attest.verify(
        chain if chain is not None else built_chain,
        challenge=verify_challenge, payload_sha256=verify_payload,
        package_name=package, signing_digests=set(digests),
        roots_pem=roots_pem if roots_pem is not None else built_roots,
        revoked=revoked, now=NOW)


def refused(out, fragment=None):
    assert out["verified"] is False
    if fragment:
        assert fragment in out["reason"], out["reason"]
    return True


# ------------------------------------------------------------- it works --
def test_a_correct_attestation_verifies():
    """If this fails, every refusal below proves nothing."""
    out = run()
    assert out["verified"] is True, out["reason"]
    assert out["public_key"] == DEVICE_PUB
    assert out["key_id"] == hashlib.sha256(DEVICE_PUB).digest()
    assert out["security_level"] == "TrustedEnvironment"


def test_strongbox_verifies_and_says_so():
    out = run(att_level=2, km_level=2)
    assert out["verified"] is True, out["reason"]
    assert out["security_level"] == "StrongBox"


def test_an_rsa_root_verifies():
    """Google's original attestation root is RSA; the chain walk must cope."""
    out = run(rsa_root=True)
    assert out["verified"] is True, out["reason"]


def test_a_verified_attestation_reaches_a_trusted_tier():
    out = run()
    verdict = attestation.interpret_key_attestation(
        verified=out["verified"], receipt_ok=out["receipt_ok"],
        token_nonce=out["token_nonce"], expect_nonce=CHALLENGE,
        security_level=out["security_level"])
    assert verdict["trusted"] is True
    assert verdict["bound"] is True
    assert verdict["tier"] == attestation.TIER_DEVICE


def test_strongbox_reaches_the_hardware_tier():
    out = run(att_level=2, km_level=2)
    verdict = attestation.interpret_key_attestation(
        verified=True, receipt_ok=True, token_nonce=CHALLENGE,
        expect_nonce=CHALLENGE, security_level=out["security_level"])
    assert verdict["tier"] == attestation.TIER_HARDWARE


def test_an_unverified_result_never_reaches_trust():
    for impostor in (False, "true", 1, None):
        verdict = attestation.interpret_key_attestation(
            verified=impostor, receipt_ok=True, token_nonce=CHALLENGE,
            expect_nonce=CHALLENGE, security_level="StrongBox")
        assert verdict["trusted"] is False


# ----------------------------------------------------------- the anchor --
def test_no_roots_configured_is_refused():
    refused(run(roots_pem=""), "root")


def test_a_chain_to_someone_elses_root_is_refused():
    other = ec.generate_private_key(ec.SECP256R1())
    other_root = _cert("Other Root", other, "Other Root", other)
    refused(run(root_override=other_root), "root")


def test_a_chain_without_its_root_is_refused():
    refused(run(drop_root=True), "root")


def test_an_unlinked_chain_is_refused():
    refused(run(unlinked=True), "does not verify")


def test_an_expired_leaf_is_refused():
    refused(run(leaf_expired=True), "validity")


def test_a_revoked_certificate_is_refused():
    out = run(leaf_serial=0xABC123, revoked=frozenset({"abc123"}))
    refused(out, "revoked")


def test_an_unknown_revocation_state_is_refused():
    refused(run(revoked=None), "revocation")


def test_one_certificate_is_not_a_chain():
    chain, roots = build()
    out = android_attest.verify(
        chain[:1], challenge=CHALLENGE, payload_sha256=PHOTO_SHA,
        package_name=PACKAGE, signing_digests={SIGNING_DIGEST},
        roots_pem=roots, revoked=frozenset(), now=NOW)
    refused(out)


# ----------------------------------------------------- the forgery path --
def test_an_attested_key_certifying_another_key_is_refused():
    """The attack step 4 exists for. The chain verifies to the root."""
    refused(run(forged_by_attested_key=True), "forged")


def test_an_extension_on_an_intermediate_is_refused():
    refused(run(extension_on_intermediate=True), "above the leaf")


def test_a_leaf_without_the_extension_is_refused():
    chain, roots = build()
    no_ext = _cert("Android Keystore Key", DEVICE_KEY, "Test Attestation "
                   "Intermediate", ec.generate_private_key(ec.SECP256R1()),
                   ca=False)
    out = android_attest.verify(
        [no_ext.public_bytes(Encoding.DER)] + chain[1:], challenge=CHALLENGE,
        payload_sha256=PHOTO_SHA, package_name=PACKAGE,
        signing_digests={SIGNING_DIGEST}, roots_pem=roots,
        revoked=frozenset(), now=NOW)
    refused(out)


# ------------------------------------------------------ secure hardware --
@pytest.mark.parametrize("levels", [(0, 0), (0, 1), (1, 0)])
def test_a_software_key_is_refused(levels):
    refused(run(att_level=levels[0], km_level=levels[1]), "secure hardware")


# ---------------------------------------------------------- the binding --
def test_a_different_photograph_is_refused():
    refused(run(verify_payload=hashlib.sha256(b"stock roof").digest()),
            "not bound")


def test_a_different_challenge_is_refused():
    refused(run(verify_challenge="some-other-challenge"), "not bound")


def test_a_challenge_only_binding_is_refused():
    """The easy mistake: hashing the challenge without the photo digest."""
    refused(run(challenge=hashlib.sha256(CHALLENGE.encode()).digest()),
            "not bound")


def test_no_challenge_or_digest_is_refused():
    refused(run(verify_challenge=""))
    refused(run(verify_payload=b""))


# ---------------------------------------------------- the key and device --
def test_an_imported_key_is_refused():
    refused(run(origin=2), "not generated")


def test_a_missing_origin_is_refused():
    refused(run(omit_origin=True), "not generated")


def test_a_non_ec_key_description_is_refused():
    refused(run(algorithm=1), "elliptic")


def test_a_key_that_cannot_sign_is_refused():
    refused(run(purposes=(0, 1)), "cannot sign")


@pytest.mark.parametrize("state", [1, 2, 3])
def test_an_unverified_boot_is_refused(state):
    refused(run(boot_state=state), "boot")


def test_an_unlocked_bootloader_is_refused():
    refused(run(locked=False), "unlocked")


def test_a_missing_root_of_trust_is_refused():
    refused(run(omit_root_of_trust=True), "boot state")


def test_a_non_p256_key_is_refused():
    refused(run(leaf_key=ec.generate_private_key(ec.SECP384R1())), "P-256")


# -------------------------------------------------------------- the app --
def test_another_apps_key_is_refused():
    refused(run(app_id=application_id(packages=("com.someone.else",))),
            "different app")


def test_a_shared_uid_app_list_is_refused():
    """Several packages means a shared UID, and we cannot tell which asked."""
    refused(run(app_id=application_id(packages=(PACKAGE, "com.other"))),
            "different app")


def test_a_repackaged_build_is_refused():
    other = hashlib.sha256(b"an attacker's signing certificate").digest()
    refused(run(app_id=application_id(digests=(other,))), "repackaged")


def test_the_app_id_is_accepted_from_the_hardware_list_too():
    assert run(app_in_hardware=True)["verified"] is True


def test_no_app_configuration_is_refused():
    refused(run(package=""), "not configured")
    refused(run(digests=()), "not configured")


# ------------------------------------------------------------ malformed --
@pytest.mark.parametrize("ext", [b"", b"\x30", b"\x30\x03\x02\x01",
                                 b"\x04\x00", seq(integer(3))])
def test_a_malformed_extension_is_refused_not_raised(ext):
    refused(run(desc=ext))


def test_unparseable_certificates_are_refused_not_raised():
    refused(run(chain=[b"not a certificate", b"nor this"]))


# ------------------------------------------------------ later captures --
def sign(client_data, key=DEVICE_KEY):
    return key.sign(client_data, ec.ECDSA(hashes.SHA256()))


class TestSignature:
    def check(self, signature, **kw):
        args = dict(challenge=CHALLENGE, payload_sha256=PHOTO_SHA,
                    public_key=DEVICE_PUB)
        args.update(kw)
        return android_attest.verify_signature(signature, **args)

    def test_a_correct_signature_verifies(self):
        out = self.check(sign(CHALLENGE.encode() + PHOTO_SHA))
        assert out["verified"] is True, out["reason"]

    def test_a_different_photograph_is_refused(self):
        sig = sign(CHALLENGE.encode() + PHOTO_SHA)
        refused(self.check(sig, payload_sha256=hashlib.sha256(b"x").digest()))

    def test_a_different_challenge_is_refused(self):
        sig = sign(CHALLENGE.encode() + PHOTO_SHA)
        refused(self.check(sig, challenge="another"))

    def test_another_key_is_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        refused(self.check(sign(CHALLENGE.encode() + PHOTO_SHA, key=other)))

    def test_a_signature_over_the_hash_is_not_the_convention(self):
        """The client signs the client data itself, not its digest."""
        refused(self.check(sign(CLIENT_DATA_HASH)))

    @pytest.mark.parametrize("sig", [b"", b"\x30\x00", b"garbage"])
    def test_malformed_signatures_are_refused_not_raised(self, sig):
        refused(self.check(sig))

    def test_no_key_on_file_is_refused(self):
        refused(self.check(sign(CHALLENGE.encode() + PHOTO_SHA),
                           public_key=None))


# ----------------------------------------------------------- revocation --
class TestRevocationList:
    def setup_method(self):
        android_attest._status_cache.update(at=0.0, revoked=None)

    def test_revoked_entries_are_read_as_lowercase_hex(self):
        body = {"entries": {"0ABC": {"status": "REVOKED"},
                            "def1": {"status": "SUSPENDED"}}}
        out = android_attest.revoked_serials(fetch=lambda _u: body, now=1000)
        assert out == frozenset({"abc"})

    def test_a_failed_fetch_with_nothing_cached_is_none(self):
        def boom(_u):
            raise OSError("no network")
        assert android_attest.revoked_serials(fetch=boom, now=1000) is None

    def test_a_failed_refresh_falls_back_to_a_recent_copy(self):
        body = {"entries": {"abc": {"status": "REVOKED"}}}
        android_attest.revoked_serials(fetch=lambda _u: body, now=1000)

        def boom(_u):
            raise OSError("no network")
        later = 1000 + android_attest.STATUS_TTL_S + 1
        assert android_attest.revoked_serials(fetch=boom, now=later) == {"abc"}

    def test_a_copy_older_than_a_day_is_not_used(self):
        body = {"entries": {"abc": {"status": "REVOKED"}}}
        android_attest.revoked_serials(fetch=lambda _u: body, now=1000)

        def boom(_u):
            raise OSError("no network")
        much_later = 1000 + android_attest.STATUS_STALE_OK_S + 1
        assert android_attest.revoked_serials(fetch=boom,
                                              now=much_later) is None
