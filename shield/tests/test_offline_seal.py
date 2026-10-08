"""Python and the verify page must agree on an offline seal.

The page judges a package with wifi off. ``offline_seal.py`` is the
reference for that judgement. A disagreement is the page calling a record
SEALED that the reference does not, or the reverse, which is the page
accusing someone the reference does not.

These fixtures are built with the same functions the service uses to seal
a ticket, a capture, a receipt, and a timestamp. Nothing here is a
hand-written hash. The labels this file expects are the contract:

    SEALED
    TAMPERED
    FORGED
    UNVERIFIED TIME
    DEVICE CLOCK MISMATCH
    receipt present, timestamp absent

Flags are words beside the label. They do not change it. A missing
timestamp is not FORGED.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import capture_record  # noqa: E402
import ledger  # noqa: E402
import offline_seal  # noqa: E402
import queue_ingest  # noqa: E402
import ticket  # noqa: E402
import time_audit  # noqa: E402
import tsa  # noqa: E402

attest = pytest.importorskip("test_app_attest", reason="cbor2/cryptography are not installed")
android = pytest.importorskip("test_android_attest", reason="cryptography is not installed")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, NoEncryption, PrivateFormat, PublicFormat)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

HARNESS = os.path.join(os.path.dirname(__file__), "..", "webapp", "tests",
                       "harness.mjs")
JOB = "job-seal-1"
APP_ID = attest.APP_ID
WALL = 1_700_000_000_000
MONO = 5_000_000
BOOT = "boot-session-a"
PHOTO = "ab" * 32
LIST_HASH = "cd" * 32
ACTOR = "actor-1"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is not installed")


def js_seal(package, roots_pem, files=None):
    payload = {"op": "seal", "package": package, "roots_pem": roots_pem}
    if files:
        payload["files"] = [
            {"photo_id": photo_id, "hex": raw.hex()}
            for photo_id, raw in files.items()
        ]
    proc = subprocess.run(
        ["node", HARNESS],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(f"harness failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _signing_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    return pem


def _tsa_roots():
    """A local root, an intermediate, and a time-stamping leaf.

    The page's pinned DigiCert and Sectigo roots are what a real token
    chains to. This chain is the same shape, so the two judges can be
    compared without calling either public authority during the suite.
    """
    now = datetime.now(timezone.utc)

    def cert(subject, subject_key, issuer, issuer_key, *, ca, extra=()):
        name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        builder = (x509.CertificateBuilder()
                   .subject_name(name(subject))
                   .issuer_name(name(issuer))
                   .public_key(subject_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
                   .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                                  critical=True))
        for ext, critical in extra:
            builder = builder.add_extension(ext, critical)
        return builder.sign(issuer_key, hashes.SHA256())

    root_key = ec.generate_private_key(ec.SECP256R1())
    mid_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = cert("Seal Root", root_key, "Seal Root", root_key, ca=True)
    mid = cert("Seal Mid", mid_key, "Seal Root", root_key, ca=True)
    leaf = cert(
        "Seal TSA", leaf_key, "Seal Mid", mid_key, ca=False,
        extra=((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True),))
    pem = root.public_bytes(Encoding.PEM).decode()
    return leaf_key, leaf, (mid,), pem


def _point_b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _key_id(raw):
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def _assertion(platform, challenge, payload, counter, point_key):
    if platform == "ios":
        blob = attest.build_assertion(
            key=point_key, challenge=challenge, payload_sha256=payload,
            app_id=APP_ID, counter=counter)
        return base64.b64encode(blob).decode("ascii")
    signature = android.sign(challenge.encode() + payload, key=point_key)
    return base64.b64encode(signature).decode("ascii")


def build_package(*, platform="ios", boot_id=BOOT, wall_extra=0, flags=0,
                  photos=2, with_token=False):
    """One package whose seal is whatever the clocks and signatures say.

    ``wall_extra`` is added to each photo's wall clock and not to its
    monotonic clock, which is how a device-clock mismatch is made without
    breaking the bytes. ``boot_id`` on the photo, when it differs from the
    ticket, is unverified time. ``with_token`` stamps the custody head.
    """
    pem = _signing_pem()
    if platform == "ios":
        device_key = attest.DEVICE_KEY
        point = attest.DEVICE_PUB
    else:
        device_key = android.DEVICE_KEY
        point = android.DEVICE_PUB

    body = {
        "version": ticket.TICKET_VERSION,
        "record_id": JOB,
        "checkpoint_list_sha256": LIST_HASH,
        "actor_id": ACTOR,
        "expires_at_ms": WALL + 86_400_000,
        "server_time_ms": WALL,
    }
    signed_ticket = ticket.sign_ticket(body, pem=pem)
    ticket_hash = signed_ticket["ticket_hash"]
    clock = {"wall_time_ms": WALL, "monotonic_ms": MONO, "boot_id": BOOT}
    challenge, payload = ticket.hardware_binding(ticket_hash, clock)
    ticket_assertion = _assertion(platform, challenge, payload, 1, device_key)

    records = []
    prev = ticket_hash
    for index in range(photos):
        built = capture_record.build(
            checkpoint_id=f"cp-{index + 1}",
            photo_sha256=PHOTO,
            ticket_id=ticket_hash,
            wall_time_ms=WALL + (index + 1) * 10_000 + wall_extra,
            monotonic_ms=MONO + (index + 1) * 10_000,
            boot_id=boot_id,
            flags=flags,
        )
        sealed = capture_record.seal(built, prev)
        records.append(sealed)
        prev = sealed["record_hash"]

    accepted = []
    counter = 2
    for record in records:
        assertion = _assertion(
            platform, queue_ingest.CAPTURE_CHALLENGE,
            bytes.fromhex(record["record_hash"]), counter, device_key)
        audit = time_audit.assess(clock, record)
        accepted.append({
            "record": record,
            "assertion": assertion,
            "checkpoint_id": record["checkpoint_id"],
            "photo_sha256": record["photo_sha256"],
            "record_hash": record["record_hash"],
            "time": {
                "verdict": audit["verdict"],
                "labels": list(audit["labels"]),
                "flags": flags,
                "flag_names": capture_record.flag_names(flags),
            },
        })
        counter += 1

    prepared = {
        "accepted": accepted,
        "phone_chain_head": records[-1]["record_hash"],
        "ticket_clock": clock,
    }
    photo_ids = [f"ph-{index + 1}" for index in range(len(records))]
    event = queue_ingest.custody_event(
        prepared, ticket_hash=ticket_hash, photo_ids=photo_ids)
    event.update({
        "shield_job_id": JOB,
        "actor_id": ACTOR,
        "actor_type": "contractor",
        "recorded_at": "2026-09-14T10:31:00+00:00",
    })
    entry = ledger.seal(event, ledger.genesis_hash(JOB))
    head = entry["entry_hash"]
    receipt = tsa.sign_receipt(tsa.build_receipt(
        record_id=JOB, head_hash=head, accepted_at_ms=WALL + 60_000), pem=pem)
    receipt["phone_chain_head"] = records[-1]["record_hash"]

    roots = offline_seal.pinned_roots()
    timestamp = tsa.missing_timestamp("No timestamp token is stored for this receipt.")
    if with_token:
        leaf_key, leaf, extras, roots = _tsa_roots()
        token = tsa.mint_token(
            hashed_message=bytes.fromhex(head), nonce=7,
            key=leaf_key, cert=leaf, extra_certs=extras)
        timestamp = {
            "status": "present",
            "forged": False,
            "token_b64": base64.b64encode(token).decode("ascii"),
            "authority": "local",
            "gen_time": None,
        }

    offline = {
        "platform": platform,
        "app_id": APP_ID,
        "key_id": _key_id(point),
        "hardware_key_b64": _point_b64(point),
        "ticket": signed_ticket["ticket"],
        "ticket_signature": signed_ticket["server_signature"],
        "ticket_assertion": ticket_assertion,
        "ticket_clock": clock,
        "captures": [
            {"record": {k: v for k, v in item["record"].items()
                        if k != "hardware_signature"},
             "assertion": item["assertion"]}
            for item in accepted
        ],
    }
    package = {
        "schema": "tradedeck.shield.package.v2",
        "chain_version": 2,
        "job": {"shield_job_id": JOB},
        "record": {"id": JOB},
        "custody_entries": [entry],
        "custody": {"head_hash": head, "chain_intact": True, "chain_version": 2},
        "head_hash": head,
        "receipt": receipt,
        "timestamp": timestamp,
        "signing_key": ticket.export_public_key(pem),
        "offline": offline,
        "photos": [
            {
                "id": photo_ids[index],
                "checkpoint_id": record["checkpoint_id"],
                "original_hash": record["photo_sha256"],
            }
            for index, record in enumerate(records)
        ],
        "checkpoints": [
            {
                "checkpoint_number": index + 1,
                "checkpoint_id": record["checkpoint_id"],
                "photo_id": photo_ids[index],
                "sha256_original": record["photo_sha256"],
            }
            for index, record in enumerate(records)
        ],
    }
    return package, roots


def _agree(package, roots, label, files=None):
    py = offline_seal.judge(package, roots_pem=roots, files=files)
    js = js_seal(package, roots, files)
    assert py["label"] == label, py
    assert js["label"] == label, js
    assert js["flags"] == py["flags"]
    assert js["notes"] == py["notes"]
    return py


class TestTheTwoJudgesAgree:
    def test_a_token_that_checks_is_sealed(self):
        package, roots = build_package(with_token=True)
        got = _agree(package, roots, "SEALED")
        assert got["flags"] == []
        assert got["notes"] == []
        assert package["chain_version"] == 2

    def test_a_missing_timestamp_is_not_forged(self):
        package, roots = build_package(with_token=False)
        got = _agree(package, roots, "receipt present, timestamp absent")
        assert got["label"] != "FORGED"
        assert "forged" not in got["label"].lower()

    def test_android_agrees_on_the_same_missing_timestamp(self):
        package, roots = build_package(platform="android")
        _agree(package, roots, "receipt present, timestamp absent")

    def test_a_broken_capture_byte_is_tampered(self):
        package, roots = build_package()
        package["offline"]["captures"][0]["record"]["photo_sha256"] = "ef" * 32
        chain = package["custody_entries"][0]["event_data"]["phone_chain"]
        chain[0]["photo_sha256"] = "ef" * 32
        _agree(package, roots, "TAMPERED")

    def test_a_bad_hardware_signature_is_forged(self):
        package, roots = build_package()
        package["offline"]["captures"][0]["assertion"] = base64.b64encode(
            b"not-a-signature").decode()
        _agree(package, roots, "FORGED")

    def test_an_unknown_key_is_forged(self):
        package, roots = build_package()
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        package["offline"]["hardware_key_b64"] = base64.b64encode(other).decode()
        _agree(package, roots, "FORGED")

    def test_a_bad_ticket_signature_is_forged(self):
        package, roots = build_package()
        package["offline"]["ticket_signature"] = base64.b64encode(
            b"not-the-ticket").decode()
        _agree(package, roots, "FORGED")

    def test_a_reboot_is_unverified_time(self):
        package, roots = build_package(boot_id="boot-session-b")
        got = _agree(package, roots, "UNVERIFIED TIME")
        assert "receipt present, timestamp absent" in got["notes"]

    def test_a_three_minute_clock_jump_is_a_mismatch(self):
        package, roots = build_package(wall_extra=180_000)
        got = _agree(package, roots, "DEVICE CLOCK MISMATCH")
        assert "receipt present, timestamp absent" in got["notes"]

    def test_flags_are_words_and_do_not_change_the_label(self):
        package, roots = build_package(flags=(
            capture_record.FLAG_SCREEN_CAPTURED
            | capture_record.FLAG_DEBUGGER
            | capture_record.FLAG_MOCK_LOCATION
            | capture_record.FLAG_ROOT_TRACES))
        got = _agree(package, roots, "receipt present, timestamp absent")
        assert got["flags"] == [
            "screen captured", "debugger attached", "mock location", "root traces"]

    def test_flags_do_not_turn_a_sealed_package_into_something_else(self):
        package, roots = build_package(with_token=True, flags=capture_record.FLAG_DEBUGGER)
        got = _agree(package, roots, "SEALED")
        assert got["flags"] == ["debugger attached"]

    def test_a_token_over_a_different_head_is_forged(self):
        package, roots = build_package(with_token=True)
        leaf_key, leaf, extras, _roots = _tsa_roots()
        token = tsa.mint_token(
            hashed_message=b"\x11" * 32, nonce=3,
            key=leaf_key, cert=leaf, extra_certs=extras)
        package["timestamp"]["token_b64"] = base64.b64encode(token).decode()
        _agree(package, roots, "FORGED")

    def test_a_real_digicert_token_is_sealed_against_the_pinned_roots(self):
        """A token fetched from DigiCert, checked with the certificates in the page.

        The suite does not call DigiCert. This fixture was stamped once and
        checked in. The signature stays valid for as long as the certificate
        that signed it was valid at the time it was signed, which is the
        check both judges make.
        """
        path = os.path.join(os.path.dirname(__file__), "fixtures",
                            "sealed_digicert_package.json")
        package = json.loads(open(path).read())
        roots = offline_seal.pinned_roots()
        got = _agree(package, roots, "SEALED")
        assert got["notes"] == []

    def test_each_offline_photo_is_sealed_to_its_hash_and_checkpoint(self):
        package, roots = build_package(photos=2)
        bindings = package["custody_entries"][0]["event_data"]["sealed_photos"]
        assert bindings == [
            {
                "photo_id": "ph-1",
                "photo_sha256": PHOTO,
                "checkpoint_id": "cp-1",
            },
            {
                "photo_id": "ph-2",
                "photo_sha256": PHOTO,
                "checkpoint_id": "cp-2",
            },
        ]
        assert "photo_ids" not in package["custody_entries"][0]["event_data"]
        chain = ledger.verify_chain(package["custody_entries"], JOB)
        assert chain["intact"] is True
        _agree(package, roots, "receipt present, timestamp absent")

    def test_editing_an_offline_photo_hash_is_tampered_though_the_seal_verifies(self):
        package, roots = build_package(photos=1)
        package["photos"][0]["original_hash"] = "ef" * 32
        chain = ledger.verify_chain(package["custody_entries"], JOB)
        assert chain["intact"] is True
        _agree(package, roots, "TAMPERED")

    def test_editing_a_checkpoint_hash_is_tampered_though_the_seal_verifies(self):
        package, roots = build_package(photos=1)
        package["checkpoints"][0]["sha256_original"] = "ef" * 32
        assert ledger.verify_chain(package["custody_entries"], JOB)["intact"] is True
        _agree(package, roots, "TAMPERED")

    def test_bytes_that_match_the_manifest_but_not_the_phone_chain_are_tampered(self):
        package, roots = build_package(photos=1)
        new = b"not-the-photograph-the-phone-signed"
        digest = hashlib.sha256(new).hexdigest()
        package["photos"][0]["original_hash"] = digest
        package["checkpoints"][0]["sha256_original"] = digest
        assert ledger.verify_chain(package["custody_entries"], JOB)["intact"] is True
        _agree(package, roots, "TAMPERED", files={"ph-1": new})

    def test_a_package_with_no_phone_chain_has_no_seal(self):
        package, roots = build_package()
        package["offline"] = None
        py = offline_seal.judge(package, roots_pem=roots)
        js = js_seal(package, roots)
        assert py["label"] is None
        assert js["label"] is None
