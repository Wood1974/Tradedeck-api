"""An export receipt and a timestamp, checked against the computed head.

A full rewrite that keeps the receipt and the token from the original head
has to fail with no ``--expect-head``. A missing token says timestamp
missing. A missing receipt says receipt absent. Neither of those is a
failure. ``chain_version`` stays 2.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "verifier"))

import evidence  # noqa: E402
import ledger  # noqa: E402
import shield_verify  # noqa: E402
import ticket  # noqa: E402
import tsa  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, NoEncryption, PrivateFormat)
from cryptography.x509.oid import NameOID  # noqa: E402

JOB_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
JOB = {"id": JOB_ID, "external_ref": "WO-9001", "trade": "framing"}
HARNESS = os.path.join(os.path.dirname(__file__), "..", "webapp", "tests",
                       "harness.mjs")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "sealed_digicert_package.json")


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def _chain(note=None):
    out, prev = [], ledger.genesis_hash(JOB_ID)
    for i in range(3):
        raw = {
            "shield_job_id": JOB_ID,
            "event_type": "uploaded",
            "actor_type": "contractor",
            "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
        }
        if note:
            raw["integrity_note"] = note
        sealed = ledger.seal(raw, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


def _sign(pem, head, at_ms=1_700_000_000_000):
    return tsa.sign_receipt(tsa.build_receipt(
        record_id=JOB_ID, head_hash=head, accepted_at_ms=at_ms), pem=pem)


def _token(head):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-tsa")])
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=2)).replace(tzinfo=None))
            .sign(key, hashes.SHA256()))
    raw = tsa.mint_token(
        hashed_message=bytes.fromhex(head), nonce=7, key=key, cert=cert)
    return {
        "status": "present",
        "forged": False,
        "token_b64": base64.b64encode(raw).decode("ascii"),
        "authority": "local",
    }


def _manifest(entries, pem, signed, timestamp):
    built = evidence.build_manifest(
        job=JOB, points=[], photos=[], custody=entries,
        receipt=signed, timestamp=timestamp,
        signing_key=ticket.export_public_key(pem))
    assert built["custody"]["chain_version"] == 2
    return built


def _api(entries, pem, signed, timestamp):
    return {
        "schema": "tradedeck.shield.package.v2",
        "chain_version": 2,
        "record": {"id": JOB_ID},
        "custody": entries,
        "head_hash": ledger.head_of(entries, JOB_ID),
        "receipt": signed,
        "timestamp": timestamp,
        "signing_key": ticket.export_public_key(pem),
    }


def _js(manifest):
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    proc = subprocess.run(
        ["node", HARNESS],
        input=json.dumps({"op": "package", "manifest": manifest}),
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        pytest.fail(proc.stderr.strip())
    return json.loads(proc.stdout)


def _anchor_texts(report):
    return [item.get("text", "") for item in report.get("findings") or []
            if item.get("kind") == "anchor"]


class TestTheExportAnchor:
    def test_a_receipt_signed_over_the_wrong_head_fails(self):
        pem = _pem()
        entries = _chain()
        signed = _sign(pem, "ab" * 32)
        manifest = _manifest(entries, pem, signed, tsa.missing_timestamp("off"))
        report = shield_verify.verify_package(manifest)
        assert report["ok"] is False
        assert any("not over the custody head" in problem
                   for problem in report["problems"])
        js = _js(manifest)
        assert any("not over the custody head" in text for text in _anchor_texts(js))

    def test_a_full_rewrite_keeping_the_original_anchor_fails_without_expect_head(self):
        pem = _pem()
        original = _chain()
        original_head = ledger.head_of(original, JOB_ID)
        signed = _sign(pem, original_head)
        token = _token(original_head)
        honest = _manifest(original, pem, signed, token)
        assert shield_verify.verify_package(honest)["ok"] is True
        assert _anchor_texts(_js(honest)) == []

        forged = _chain("rewritten")
        assert ledger.head_of(forged, JOB_ID) != original_head
        for package in (
                _manifest(forged, pem, signed, token),
                _api(forged, pem, signed, token)):
            report = shield_verify.verify_package(package)
            assert report["ok"] is False, report
            assert any("not over the custody head" in problem
                       for problem in report["problems"])
            assert any("timestamp is not over" in problem
                       for problem in report["problems"])
            js = _js(package)
            texts = _anchor_texts(js)
            assert any("not over the custody head" in text for text in texts)
            assert any("timestamp is not over" in text for text in texts)

    def test_the_same_rewrite_with_no_receipt_still_verifies(self):
        """The limit that remains. No receipt is a note, not a failure."""
        forged = _chain("rewritten")
        bare = evidence.build_manifest(
            job=JOB, points=[], photos=[], custody=forged)
        report = shield_verify.verify_package(bare)
        assert report["ok"] is True, report["problems"]
        assert any(note == "receipt absent" for note in report["notes"])
        js = _js(bare)
        assert _anchor_texts(js) == []
        assert "receipt absent" in (js.get("notes") or [])

    def test_tsa_off_says_timestamp_missing_and_is_not_forged(self, monkeypatch):
        monkeypatch.setenv("SHIELD_TSA_ENABLED", "0")
        pem = _pem()
        entries = _chain()
        head = ledger.head_of(entries, JOB_ID)
        signed, timestamp = tsa.package_anchor(
            JOB_ID, head, at_ms=1_700_000_000_000, pem=pem)
        assert signed["signed"]["head_hash"] == head
        assert signed["signed"]["version"] == 1
        assert timestamp["status"] == "missing"
        assert timestamp["forged"] is False
        assert timestamp["token_b64"] is None
        assert "timestamp missing" in timestamp["note"]
        manifest = _manifest(entries, pem, signed, timestamp)
        report = shield_verify.verify_package(manifest)
        assert report["ok"] is True, report["problems"]
        assert any(note == "timestamp missing" for note in report["notes"])
        js = _js(manifest)
        assert _anchor_texts(js) == []
        assert "timestamp missing" in (js.get("notes") or [])

    def test_a_receipt_signed_by_a_different_key_fails(self):
        entries = _chain()
        head = ledger.head_of(entries, JOB_ID)
        signed = _sign(_pem(), head)
        manifest = _manifest(
            entries, _pem(), signed, tsa.missing_timestamp("off"))
        report = shield_verify.verify_package(manifest)
        assert report["ok"] is False
        assert any("signature does not verify" in problem
                   for problem in report["problems"])
        js = _js(manifest)
        assert any("signature does not verify" in text for text in _anchor_texts(js))

    def test_a_digicert_package_still_verifies_its_imprint(self):
        package = json.loads(open(FIXTURE).read())
        report = shield_verify.verify_package(package)
        assert report["ok"] is True, report["problems"]
        assert "timestamp missing" not in report["notes"]
        js = _js(package)
        assert _anchor_texts(js) == []
        assert package["chain_version"] == 2
