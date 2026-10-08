"""Offline batch ingest, the receipt, and an RFC 3161 timestamp.

These tests run on Linux. They mint the phone key and the timestamp
certificate locally, the same way the App Attest tests do. DigiCert and
Sectigo appear only as configuration. Nothing here opens a socket to either.
"""
import base64
import hashlib
import json
import os
import sys
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import capture_record  # noqa: E402
import evidence  # noqa: E402
import integrity  # noqa: E402
import ledger  # noqa: E402
import queue_ingest  # noqa: E402
import ticket  # noqa: E402
import time_audit  # noqa: E402
import tsa  # noqa: E402

attest_fixtures = pytest.importorskip(
    "test_app_attest", reason="cbor2/cryptography are not installed")
android_fixtures = pytest.importorskip(
    "test_android_attest", reason="cryptography is not installed")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, NoEncryption, PrivateFormat, load_pem_public_key)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

import test_tenant_api as api  # noqa: E402

SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
SIGNING_PEM = SIGNING_KEY.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

TICKET_HASH = "ab" * 32
WALL = 1_700_000_000_000
MONO = 5_000_000
BOOT = "boot-a"
STEP = 10_000
ALL_FLAGS = (capture_record.FLAG_SCREEN_CAPTURED
             | capture_record.FLAG_DEBUGGER
             | capture_record.FLAG_MOCK_LOCATION
             | capture_record.FLAG_ROOT_TRACES)
TICKET_CLOCK = {
    "wall_time_ms": WALL,
    "monotonic_ms": MONO,
    "boot_id": BOOT,
}
PHOTO_B64 = base64.b64encode(api.JPEG).decode()
PHOTO_HASH = integrity.sha256(api.JPEG)


def _actor(store):
    return next(k["id"] for k in store.rows["api_keys"]
                if k["tenant_id"] == api.TENANT_A)


def _key_b64(raw):
    return base64.b64encode(raw).decode()


@pytest.fixture
def app_and_db(monkeypatch):
    for key, value in api.CI_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", SIGNING_PEM)
    monkeypatch.setenv("APP_ATTEST_APP_ID", api.APP_ID)
    monkeypatch.delenv("SHIELD_TSA_ENABLED", raising=False)

    import db as db_mod
    import tenancy
    import auth
    import tenant_api

    store = api.FakeDB(api.base_rows())
    for number, label in ((2, "Flashing"), (3, "Drip edge"), (4, "Ridge")):
        store.rows["checkpoints"].append({
            "id": f"cp-{number}", "tenant_id": api.TENANT_A,
            "record_id": api.RECORD_A, "point_number": number,
            "label": label, "status": "pending",
        })
    monkeypatch.setattr(db_mod, "client", lambda: store)
    monkeypatch.setattr(auth, "db", lambda: store)
    monkeypatch.setattr(tenant_api, "db", lambda: store)

    keys = {}
    for tenant_id in (api.TENANT_A, api.TENANT_B):
        issued = tenancy.new_api_key()
        keys[tenant_id] = issued.token
        store.rows.setdefault("api_keys", []).append({
            "id": f"key-{tenant_id[:4]}",
            "tenant_id": tenant_id,
            "public_id": issued.public_id,
            "key_hash": issued.key_hash,
            "revoked_at": None,
            "tenants": {"status": "active"},
        })
    store.rows.setdefault("tenants", []).append(
        {"id": api.TENANT_B, "name": "Other Co", "slug": "other", "status": "active"})

    original = tsa._urllib_post

    def guarded(url, body, timeout=10):
        host = urllib.parse.urlparse(url).hostname
        if host not in ("127.0.0.1", "localhost"):
            raise AssertionError(f"CI must not contact {url}")
        return original(url, body, timeout=timeout)

    monkeypatch.setattr(tsa, "_urllib_post", guarded)
    monkeypatch.setattr(tsa, "transport", None)

    from flask import Flask
    flask_app = Flask(__name__)
    flask_app.register_blueprint(tenant_api.bp)
    flask_app.config["TESTING"] = True
    return flask_app, store, keys, tenant_api


def _seed_ios(store, sign_count=0):
    raw = hashlib.sha256(attest_fixtures.DEVICE_PUB).digest()
    store.rows.setdefault("attested_keys", []).append({
        "key_id": _key_b64(raw),
        "tenant_id": api.TENANT_A,
        "actor_id": _actor(store),
        "platform": "ios",
        "public_key": base64.b64encode(attest_fixtures.DEVICE_PUB).decode(),
        "environment": "production",
        "sign_count": sign_count,
        "revoked_at": None,
    })
    return raw


def _seed_android(store):
    raw = hashlib.sha256(android_fixtures.DEVICE_PUB).digest()
    store.rows.setdefault("attested_keys", []).append({
        "key_id": _key_b64(raw),
        "tenant_id": api.TENANT_A,
        "actor_id": _actor(store),
        "platform": "android",
        "security_level": "TrustedEnvironment",
        "public_key": base64.b64encode(android_fixtures.DEVICE_PUB).decode(),
        "environment": "production",
        "sign_count": 0,
        "revoked_at": None,
    })
    return raw


def _seed_ticket(store, key_raw, *, platform="ios", actor=None, clock=TICKET_CLOCK):
    row = {
        "id": "ticket-1",
        "tenant_id": api.TENANT_A,
        "record_id": api.RECORD_A,
        "ticket_hash": TICKET_HASH,
        "platform": platform,
        "actor_id": actor if actor is not None else _actor(store),
        "key_id": _key_b64(key_raw),
    }
    if clock is not None:
        row["ticket_clock"] = dict(clock)
    store.rows.setdefault("job_tickets", []).append(row)


def _record(checkpoint_id, prev, *, wall, mono, boot_id=BOOT, flags=0,
            photo_sha256=PHOTO_HASH):
    built = capture_record.build(
        checkpoint_id=checkpoint_id,
        photo_sha256=photo_sha256,
        ticket_id=TICKET_HASH,
        wall_time_ms=wall,
        monotonic_ms=mono,
        flags=flags,
        boot_id=boot_id,
    )
    return capture_record.seal(built, prev)


def _chain(specs, prev=TICKET_HASH):
    records = []
    for spec in specs:
        sealed = _record(prev=prev, **spec)
        records.append(sealed)
        prev = sealed["record_hash"]
    return records


def _ios_assertion(record_hash, counter):
    blob = attest_fixtures.build_assertion(
        challenge=queue_ingest.CAPTURE_CHALLENGE,
        payload_sha256=bytes.fromhex(record_hash),
        counter=counter)
    return base64.b64encode(blob).decode()


def _android_assertion(record_hash):
    signature = android_fixtures.sign(
        queue_ingest.CAPTURE_CHALLENGE.encode() + bytes.fromhex(record_hash))
    return base64.b64encode(signature).decode()


def _captures(records, assertions):
    return [{
        "photo_b64": PHOTO_B64,
        "record": record,
        "assertion": assertion,
    } for record, assertion in zip(records, assertions)]


def _post(client, captures, **extra):
    body = {"ticket_clock": TICKET_CLOCK, "captures": captures}
    body.update(extra)
    return client.post(f"/shield/v2/records/{api.RECORD_A}/queue", json=body)


def _receipts(store):
    return list(store.rows.get("receipts") or [])


def _tokens(store):
    return list(store.rows.get("tsa_tokens") or [])


def _batches(store):
    return [row for row in store.rows.get("custody_log") or []
            if row.get("event_type") == "offline_batch"]


def _assert_sealed_photo_pairing(entry, records, photos):
    """The pairing is three fields on one object, and the hash covers it."""
    bindings = entry["event_data"]["sealed_photos"]
    assert "photo_ids" not in entry["event_data"]
    assert len(bindings) == len(records) == len(photos)
    by_id = {photo["id"]: photo for photo in photos}
    for binding, record in zip(bindings, records):
        assert set(binding) == {"photo_id", "photo_sha256", "checkpoint_id"}
        assert binding["photo_sha256"] == record["photo_sha256"]
        assert binding["checkpoint_id"] == record["checkpoint_id"]
        stored = by_id[binding["photo_id"]]
        assert stored["original_hash"] == binding["photo_sha256"]
        assert stored["checkpoint_id"] == binding["checkpoint_id"]
    # Same objects, different list order, is a different signed entry.
    # The fields inside each object are what a verifier reads.
    reordered = json.loads(json.dumps(entry))
    reordered["event_data"]["sealed_photos"] = list(reversed(bindings))
    assert ledger.link(reordered, entry["prev_hash"]) != entry["entry_hash"]


def _consistent(checkpoint_id, flags=0):
    return {
        "checkpoint_id": checkpoint_id,
        "wall": WALL + STEP,
        "mono": MONO + STEP,
        "boot_id": BOOT,
        "flags": flags,
    }


class TestHardwareBinding:
    def test_a_capture_assertion_is_not_a_ticket_assertion(self):
        digest = bytes.fromhex("cd" * 32)
        challenge, payload = queue_ingest.hardware_binding(digest.hex())
        assert challenge == "shield-capture-v1"
        assert payload == digest
        good = attest_fixtures.build_assertion(
            challenge=challenge, payload_sha256=payload, counter=1)
        assert attest_fixtures.run_assertion(
            good, challenge=challenge, payload_sha256=payload)["verified"] is True
        genesis = attest_fixtures.build_assertion(
            challenge=ticket.GENESIS_CHALLENGE, payload_sha256=payload, counter=1)
        refused = attest_fixtures.run_assertion(
            genesis, challenge=challenge, payload_sha256=payload)
        assert refused["verified"] is False

    def test_the_default_cap_is_eight_and_the_authorities_are_config(self):
        assert queue_ingest.MAX_BATCH_PHOTOS == 8
        assert queue_ingest.batch_cap() == 8
        import config
        assert "timestamp.digicert.com" in config.DEFAULTS["SHIELD_TSA_PRIMARY_URL"]
        assert "timestamp.sectigo.com" in config.DEFAULTS["SHIELD_TSA_FALLBACK_URL"]
        assert config.DEFAULTS["SHIELD_TSA_ENABLED"] == "0"
        assert "mint_token" not in tsa.stamp.__code__.co_names


class TestAValidBatch:
    def test_two_photos_one_custody_entry_and_a_signed_receipt(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([_consistent("cp-1"), _consistent("cp-2")])
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        got = _post(client, _captures(records, assertions),
                    attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 201, got.get_json()
        body = got.get_json()

        assert body["stored"] is True
        assert body["accepted"] == 2
        assert body["refused"] == 0
        assert body["chain_version"] == 2
        assert body["phone_chain_head"] == records[-1]["record_hash"]
        assert body["custody_head_hash"] != body["phone_chain_head"]
        assert "PRIVATE" not in json.dumps(body)
        assert body["signing_key"]["pem"].startswith("-----BEGIN PUBLIC KEY-----")
        assert body["timestamp"]["status"] == "missing"
        assert body["timestamp"]["forged"] is False
        assert body["timestamp"]["token_b64"] is None

        batches = _batches(store)
        assert len(batches) == 1
        assert batches[0]["chain_version"] == 2
        assert batches[0]["file_hash"] == body["phone_chain_head"]
        assert batches[0]["event_data"]["phone_chain_head"] == body["phone_chain_head"]
        assert "chain_version" not in batches[0]["event_data"]
        nested = capture_record.verify_chain(
            batches[0]["event_data"]["phone_chain"], TICKET_HASH,
            expect_head=body["phone_chain_head"])
        assert nested["verdict"] == capture_record.VERDICT_INTACT
        ordered = tenant_api.chain_in_order(store.rows["custody_log"], api.RECORD_A)
        assert ledger.verify_chain(ordered, api.RECORD_A)["intact"] is True

        receipt = body["receipt"]
        checked = tsa.verify_receipt(
            receipt["signed"], receipt["signature"], pem=SIGNING_PEM)
        assert checked["ok"] is True, checked
        assert receipt["signed"]["head_hash"] == body["custody_head_hash"]
        assert receipt["signed"]["record_id"] == api.RECORD_A
        assert receipt["signed"]["version"] == 1
        tampered = dict(receipt["signed"])
        tampered["accepted_at_ms"] = receipt["signed"]["accepted_at_ms"] + 1
        assert tsa.verify_receipt(
            tampered, receipt["signature"], pem=SIGNING_PEM)["ok"] is False
        public = load_pem_public_key(body["signing_key"]["pem"].encode())
        public.verify(
            base64.b64decode(receipt["signature"]),
            tsa.canonical(receipt["signed"]),
            ec.ECDSA(hashes.SHA256()))

        assert len(_receipts(store)) == 1
        assert _tokens(store)[0]["status"] == "missing"
        assert _tokens(store)[0]["token_b64"] is None
        assert store.rows["attested_keys"][0]["sign_count"] == 2
        assert len(store.rows["photos"]) == 2
        assert {p["attestation_tier"] for p in store.rows["photos"]} == {
            "hardware_attested"}
        _assert_sealed_photo_pairing(batches[0], records, store.rows["photos"])
        assert body["photo_ids"] == [
            item["photo_id"] for item in batches[0]["event_data"]["sealed_photos"]]

        package = client.get(
            f"/shield/v2/records/{api.RECORD_A}/package").get_json()
        assert package["chain_version"] == 2
        assert package["schema"] == "tradedeck.shield.package.v2"
        assert package["head_hash"] == body["custody_head_hash"]
        assert package["timestamp"]["forged"] is False
        assert package["timestamp"]["status"] == "missing"
        assert package["receipt"]["time_labels"][0]["verdict"] == "CONSISTENT"
        assert "PRIVATE" not in json.dumps(package)


class TestRefusals:
    def _ready(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        return client, store, key_raw

    def test_a_tampered_record_stores_nothing(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        records = _chain([_consistent("cp-1"), _consistent("cp-2")])
        records[1]["wall_time_ms"] += 5
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        got = _post(client, _captures(records, assertions),
                    attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 422
        assert "Nothing was stored" in got.get_json()["error"]
        assert _receipts(store) == []
        assert _batches(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_a_broken_link_stores_nothing(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        records = _chain([
            _consistent("cp-1"), _consistent("cp-2"), _consistent("cp-3")])
        del records[1]
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        got = _post(client, _captures(records, assertions),
                    attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 422
        assert _receipts(store) == []
        assert store.rows["photos"] == []

    def test_a_short_chain_that_claims_a_longer_head_is_refused(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        records = _chain([_consistent("cp-1"), _consistent("cp-2")])
        assertion = _ios_assertion(records[0]["record_hash"], 1)
        got = _post(client, _captures(records[:1], [assertion]),
                    attestation_key_id=_key_b64(key_raw),
                    phone_chain_head=records[-1]["record_hash"])
        assert got.status_code == 422, got.get_json()
        assert "Nothing was stored" in got.get_json()["error"]
        assert _receipts(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_resubmitting_a_prefix_does_not_extend_the_chain(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        records = _chain([_consistent("cp-1"), _consistent("cp-2")])
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        first = _post(client, _captures(records, assertions),
                      attestation_key_id=_key_b64(key_raw))
        assert first.status_code == 201, first.get_json()
        again = _post(client, _captures(records[:1], [assertions[0]]),
                      attestation_key_id=_key_b64(key_raw))
        assert again.status_code == 422
        assert len(_receipts(store)) == 1
        assert len(_batches(store)) == 1
        assert store.rows["attested_keys"][0]["sign_count"] == 2

    def test_a_ticket_signature_is_not_a_capture_signature(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        records = _chain([_consistent("cp-1")])
        blob = attest_fixtures.build_assertion(
            challenge=ticket.GENESIS_CHALLENGE,
            payload_sha256=bytes.fromhex(records[0]["record_hash"]),
            counter=1)
        got = _post(
            client,
            _captures(records, [base64.b64encode(blob).decode()]),
            attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 422
        assert _receipts(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_bytes_that_are_not_the_photograph_are_refused(self, app_and_db):
        client, store, key_raw = self._ready(app_and_db)
        sealed = _record("cp-1", TICKET_HASH, wall=WALL + STEP, mono=MONO + STEP,
                         photo_sha256=integrity.sha256(api.JPEG + b"x"))
        assertion = _ios_assertion(sealed["record_hash"], 1)
        got = _post(client, _captures([sealed], [assertion]),
                    attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 422
        assert "photograph" in got.get_json()["error"].lower()
        assert _receipts(store) == []

    def test_no_ticket_stores_nothing(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        _seed_ios(store)
        got = _post(client, [])
        assert got.status_code == 409
        assert _receipts(store) == []

    def test_another_tenant_does_not_see_the_record(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_B, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        got = _post(client, [])
        assert got.status_code == 404
        assert _receipts(store) == []


class TestTimeLabels:
    def test_reboot_and_clock_jump_persist_and_flags_do_not_flip(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        jump = time_audit.CLOCK_MISMATCH_LIMIT_MS + 1
        specs = [
            _consistent("cp-1", flags=0),
            _consistent("cp-2", flags=ALL_FLAGS),
            {"checkpoint_id": "cp-3", "wall": WALL + STEP, "mono": MONO + STEP,
             "boot_id": "boot-b", "flags": 0},
            {"checkpoint_id": "cp-4", "wall": WALL + STEP + jump,
             "mono": MONO + STEP, "boot_id": BOOT, "flags": ALL_FLAGS},
        ]
        records = _chain(specs)
        plain = time_audit.assess(TICKET_CLOCK, records[0])
        flagged = time_audit.assess(TICKET_CLOCK, records[1])
        assert plain["verdict"] == flagged["verdict"] == "CONSISTENT"
        assert plain["labels"] == flagged["labels"]
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        got = _post(client, _captures(records, assertions),
                    attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 201, got.get_json()
        body = got.get_json()
        labels = body["time_labels"]
        assert [item["verdict"] for item in labels] == [
            "CONSISTENT", "CONSISTENT", "UNVERIFIED TIME",
            "DEVICE CLOCK MISMATCH"]
        assert labels[1]["verdict"] == labels[0]["verdict"]
        assert "screen_captured" in labels[1]["flag_names"]
        assert "UNVERIFIED TIME" in labels[2]["labels"]
        assert "DEVICE CLOCK MISMATCH" in labels[3]["labels"]
        assert body["timestamp"]["forged"] is False

        stored = _receipts(store)[0]["receipt_json"]["time_labels"]
        assert [item["verdict"] for item in stored] == [
            item["verdict"] for item in labels]
        nested = _batches(store)[0]["event_data"]["captures"]
        assert nested[2]["time_verdict"] == "UNVERIFIED TIME"
        assert nested[3]["time_verdict"] == "DEVICE CLOCK MISMATCH"
        assert nested[0]["time_verdict"] == nested[1]["time_verdict"]

        package = client.get(
            f"/shield/v2/records/{api.RECORD_A}/package").get_json()
        assert [item["verdict"] for item in package["receipt"]["time_labels"]] == [
            "CONSISTENT", "CONSISTENT", "UNVERIFIED TIME",
            "DEVICE CLOCK MISMATCH"]
        assert package["timestamp"]["forged"] is False
        assert package["chain_version"] == 2

        ordered = tenant_api.chain_in_order(
            store.rows["custody_log"], api.RECORD_A)
        # The package read appends an export entry. The receipt signs the
        # head from before that export, which is the batch entry.
        batch_only = [row for row in ordered if row.get("event_type") != "exported"]
        manifest = evidence.build_manifest(
            job={"id": api.RECORD_A}, points=[], photos=[], custody=batch_only,
            receipt=body["receipt"], timestamp=body["timestamp"],
            signing_key=body["signing_key"])
        assert manifest["custody"]["chain_version"] == 2
        assert manifest["timestamp"]["forged"] is False
        dumped = json.dumps(manifest)
        assert "UNVERIFIED TIME" in dumped
        assert "DEVICE CLOCK MISMATCH" in dumped
        assert "PRIVATE" not in dumped
        assert manifest["signing_key"]["pem"].startswith(
            "-----BEGIN PUBLIC KEY-----")


class TestAndroid:
    def test_one_capture_uses_the_android_verifier(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_android(store)
        _seed_ticket(store, key_raw, platform="android")
        records = _chain([_consistent("cp-1")])
        got = _post(
            client,
            _captures(records, [_android_assertion(records[0]["record_hash"])]),
            attestation_key_id=_key_b64(key_raw), platform="android")
        assert got.status_code == 201, got.get_json()
        assert store.rows["photos"][0]["attestation_tier"] == "device_attested"
        assert got.get_json()["chain_version"] == 2
        assert tsa.verify_receipt(
            got.get_json()["receipt"]["signed"],
            got.get_json()["receipt"]["signature"],
            pem=SIGNING_PEM)["ok"] is True


class TestTheStoredClock:
    def test_a_substituted_clock_does_not_relabel_the_batch(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([_consistent("cp-1")])
        # This observation would make the same photo UNVERIFIED TIME if the
        # request were allowed to replace the clock the ticket sealed.
        lie = {"wall_time_ms": WALL, "monotonic_ms": MONO, "boot_id": "other-boot"}
        got = _post(
            client,
            _captures(records, [_ios_assertion(records[0]["record_hash"], 1)]),
            attestation_key_id=_key_b64(key_raw),
            ticket_clock=lie)
        assert got.status_code == 201, got.get_json()
        body = got.get_json()
        assert body["time_labels"][0]["verdict"] == "CONSISTENT"
        assert _batches(store)[0]["event_data"]["ticket_clock"]["boot_id"] == BOOT
        assert body["receipt"]["signed"]["head_hash"] == body["custody_head_hash"]

    def test_a_ticket_with_no_stored_clock_stores_nothing(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw, clock=None)
        records = _chain([_consistent("cp-1")])
        got = _post(
            client,
            _captures(records, [_ios_assertion(records[0]["record_hash"], 1)]),
            attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 409, got.get_json()
        assert _receipts(store) == []
        assert _batches(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_sending_the_same_batch_again_returns_the_receipt(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([_consistent("cp-1")])
        captures = _captures(records, [_ios_assertion(records[0]["record_hash"], 1)])
        first = _post(client, captures, attestation_key_id=_key_b64(key_raw))
        assert first.status_code == 201, first.get_json()
        again = _post(client, captures, attestation_key_id=_key_b64(key_raw))
        assert again.status_code == 200, again.get_json()
        body = again.get_json()
        assert body["replayed"] is True
        assert body["phone_chain_head"] == first.get_json()["phone_chain_head"]
        assert body["custody_head_hash"] == first.get_json()["custody_head_hash"]
        assert len(_receipts(store)) == 1
        assert len(_batches(store)) == 1
        assert store.rows["attested_keys"][0]["sign_count"] == 1

    def test_a_receipt_that_does_not_store_does_not_burn_the_counter(
            self, app_and_db, monkeypatch):
        flask_app, store, keys, tenant_api = app_and_db

        def boom(_row):
            raise RuntimeError("disk")

        monkeypatch.setattr(tenant_api.shield_db, "insert_receipt", boom)
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([_consistent("cp-1")])
        got = _post(
            client,
            _captures(records, [_ios_assertion(records[0]["record_hash"], 1)]),
            attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 500, got.get_json()
        assert _receipts(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0


class TestBatchCap:
    def test_the_prefix_is_kept_and_the_rest_is_the_next_batch(
            self, app_and_db, monkeypatch):
        monkeypatch.setenv("SHIELD_QUEUE_BATCH_CAP", "2")
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([
            _consistent("cp-1"), _consistent("cp-2"), _consistent("cp-3")])
        assertions = [_ios_assertion(r["record_hash"], i)
                      for i, r in enumerate(records, start=1)]
        first = _post(client, _captures(records, assertions),
                      attestation_key_id=_key_b64(key_raw),
                      phone_chain_head=records[-1]["record_hash"])
        assert first.status_code == 201, first.get_json()
        body = first.get_json()
        assert body["accepted"] == 2
        assert body["refused"] == 1
        assert body["send_next_batch"] is True
        assert "Send the next batch." in body["message"]
        assert body["phone_chain_head"] == records[1]["record_hash"]
        assert body["chain_version"] == 2
        assert len(store.rows["photos"]) == 2
        assert len(_receipts(store)) == 1

        second = _post(client, _captures(records[2:], assertions[2:]),
                       attestation_key_id=_key_b64(key_raw))
        assert second.status_code == 201, second.get_json()
        assert second.get_json()["accepted"] == 1
        assert second.get_json()["send_next_batch"] is False
        assert second.get_json()["chain_version"] == 2
        assert len(_receipts(store)) == 2
        assert len(_batches(store)) == 2
        assert all(row["chain_version"] == 2 for row in _batches(store))
        ordered = tenant_api.chain_in_order(
            [row for row in store.rows["custody_log"]
             if row.get("event_type") == "offline_batch"],
            api.RECORD_A)
        assert ledger.verify_chain(ordered, api.RECORD_A)["intact"] is True
        assert len(store.rows["photos"]) == 3


def _tsa_material():
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

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

    root = cert("Test TSA Root", ca_key, "Test TSA Root", ca_key, ca=True)
    leaf = cert(
        "Test TSA", leaf_key, "Test TSA Root", ca_key, ca=False,
        extra=((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True),))
    pem = root.public_bytes(Encoding.PEM).decode()
    return leaf_key, leaf, pem


def _serve(leaf_key, leaf):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            parsed = tsa.parse_timestamp_request(raw)
            token = tsa.mint_token(
                hashed_message=parsed["hashed_message"],
                nonce=parsed["nonce"], key=leaf_key, cert=leaf)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(token)))
            self.end_headers()
            self.wfile.write(token)

        def log_message(self, fmt, *args):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


class TestTimestamp:
    def test_a_local_authority_timestamps_the_custody_head(
            self, app_and_db, monkeypatch):
        leaf_key, leaf, pem = _tsa_material()
        httpd = _serve(leaf_key, leaf)
        try:
            port = httpd.server_address[1]
            url = f"http://127.0.0.1:{port}"
            monkeypatch.setenv("SHIELD_TSA_ENABLED", "1")
            monkeypatch.setenv("SHIELD_TSA_PRIMARY_URL", url)
            monkeypatch.setenv("SHIELD_TSA_FALLBACK_URL", url)
            monkeypatch.setenv("SHIELD_TSA_ROOTS_PEM", pem)

            flask_app, store, keys, tenant_api = app_and_db
            client = api.client_for(
                flask_app, store, tenant_api, api.TENANT_A, keys)
            key_raw = _seed_ios(store)
            _seed_ticket(store, key_raw)
            records = _chain([_consistent("cp-1")])
            got = _post(
                client,
                _captures(records, [_ios_assertion(records[0]["record_hash"], 1)]),
                attestation_key_id=_key_b64(key_raw))
            assert got.status_code == 201, got.get_json()
            body = got.get_json()
            assert body["timestamp"]["status"] == "present"
            assert body["timestamp"]["forged"] is False
            assert body["timestamp"]["authority"] == "127.0.0.1"
            token = base64.b64decode(body["timestamp"]["token_b64"])
            checked = tsa.verify_token(
                token, head_hash=body["custody_head_hash"], roots_pem=pem)
            assert checked["ok"] is True, checked
            assert _tokens(store)[0]["status"] == "present"
            package = client.get(
                f"/shield/v2/records/{api.RECORD_A}/package").get_json()
            assert package["timestamp"]["status"] == "present"
            assert package["timestamp"]["forged"] is False
            assert package["chain_version"] == 2
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_both_authorities_down_still_keeps_the_receipt(
            self, app_and_db, monkeypatch):
        monkeypatch.setenv("SHIELD_TSA_ENABLED", "1")
        monkeypatch.setenv("SHIELD_TSA_PRIMARY_URL", "http://127.0.0.1:9")
        monkeypatch.setenv("SHIELD_TSA_FALLBACK_URL", "http://127.0.0.1:9")
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, tenant_api, api.TENANT_A, keys)
        key_raw = _seed_ios(store)
        _seed_ticket(store, key_raw)
        records = _chain([_consistent("cp-1")])
        got = _post(
            client,
            _captures(records, [_ios_assertion(records[0]["record_hash"], 1)]),
            attestation_key_id=_key_b64(key_raw))
        assert got.status_code == 201, got.get_json()
        body = got.get_json()
        assert len(_receipts(store)) == 1
        assert body["timestamp"]["status"] == "missing"
        assert body["timestamp"]["forged"] is False
        assert body["timestamp"]["token_b64"] is None
        assert _tokens(store)[0]["status"] == "missing"
        assert tsa.verify_receipt(
            body["receipt"]["signed"], body["receipt"]["signature"],
            pem=SIGNING_PEM)["ok"] is True
        package = client.get(
            f"/shield/v2/records/{api.RECORD_A}/package").get_json()
        assert package["timestamp"]["status"] == "missing"
        assert package["timestamp"]["forged"] is False
        assert "not a forgery" in package["timestamp"]["note"]

    def test_sectigo_is_the_fallback_and_neither_host_is_dialed(self, monkeypatch):
        _leaf_key, leaf, pem = _tsa_material()
        leaf_key = _leaf_key
        seen = []

        def fetch(url, body):
            seen.append(url)
            if "digicert" in url:
                raise tsa.TsaUnavailable("down")
            parsed = tsa.parse_timestamp_request(body)
            return tsa.mint_token(
                hashed_message=parsed["hashed_message"], nonce=parsed["nonce"],
                key=leaf_key, cert=leaf)

        out = tsa.stamp(
            "cd" * 32, fetch=fetch,
            urls=["http://timestamp.digicert.com", "http://timestamp.sectigo.com"],
            roots_pem=pem, enabled_flag=True)
        assert out["status"] == "present"
        assert out["forged"] is False
        assert out["authority"] == "sectigo"
        assert [urllib.parse.urlparse(url).hostname for url in seen] == [
            "timestamp.digicert.com", "timestamp.sectigo.com"]

        def refuse(url, body, timeout=10):
            raise AssertionError(url)

        monkeypatch.setattr(tsa, "_urllib_post", refuse)
        missing = tsa.stamp("ab" * 32, enabled_flag=False)
        assert missing["status"] == "missing"
        assert missing["forged"] is False

    def test_a_token_over_a_different_head_is_missing_not_forged(self):
        leaf_key, leaf, pem = _tsa_material()

        def fetch(url, body):
            return tsa.mint_token(
                hashed_message=b"\x11" * 32, nonce=1, key=leaf_key, cert=leaf)

        out = tsa.stamp(
            "ef" * 32, fetch=fetch, urls=["http://timestamp.digicert.com"],
            roots_pem=pem, enabled_flag=True)
        assert out["status"] == "missing"
        assert out["forged"] is False
        assert out["token_b64"] is None


def _cert(subject, subject_key, issuer, issuer_key, *, ca, hash_alg=None, extra=()):
    now = datetime.now(timezone.utc)
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
    return builder.sign(issuer_key, hash_alg or hashes.SHA256())


class TestARealTimestampShape:
    def test_sha384_and_an_intermediate_verify_and_a_gap_does_not(self):
        head = "ab" * 32
        root_key = ec.generate_private_key(ec.SECP256R1())
        mid_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = _cert("Root", root_key, "Root", root_key, ca=True)
        mid = _cert("Mid", mid_key, "Root", root_key, ca=True, hash_alg=hashes.SHA384())
        leaf = _cert(
            "TSA", leaf_key, "Mid", mid_key, ca=False, hash_alg=hashes.SHA384(),
            extra=((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True),))
        pem = root.public_bytes(Encoding.PEM).decode()
        token = tsa.mint_token(
            hashed_message=bytes.fromhex(head), nonce=7, key=leaf_key, cert=leaf,
            extra_certs=(mid,), hash_name="sha384",
            gen_time="20261006120000.5Z")
        checked = tsa.verify_token(token, head_hash=head, roots_pem=pem, nonce=7)
        assert checked["ok"] is True, checked
        assert checked["gen_time"] == "20261006120000.5Z"

        gap = tsa.mint_token(
            hashed_message=bytes.fromhex(head), nonce=7, key=leaf_key, cert=leaf,
            hash_name="sha384", gen_time="20261006120000.5Z")
        refused = tsa.verify_token(gap, head_hash=head, roots_pem=pem, nonce=7)
        assert refused["ok"] is False

        wrong_imprint = tsa.mint_token(
            hashed_message=bytes.fromhex(head), nonce=7, key=leaf_key, cert=leaf,
            extra_certs=(mid,), hash_name="sha384", imprint_oid=tsa.SHA384_OID)
        refused_oid = tsa.verify_token(
            wrong_imprint, head_hash=head, roots_pem=pem, nonce=7)
        assert refused_oid["ok"] is False

        local = tsa.mint_token(
            hashed_message=bytes.fromhex(head), nonce=7, key=leaf_key, cert=leaf,
            extra_certs=(mid,), hash_name="sha384", gen_time="20261006120000+0000")
        assert tsa.verify_token(
            local, head_hash=head, roots_pem=pem, nonce=7)["ok"] is False


class TestTheManifest:
    def test_a_package_with_no_receipt_still_says_missing_is_not_forged(self):
        job_id = "job-1"
        entry = ledger.seal({
            "record_id": job_id,
            "event_type": "created",
            "event_data": {"n": 1},
        }, ledger.genesis_hash(job_id))
        manifest = evidence.build_manifest(
            job={"id": job_id}, points=[], photos=[], custody=[entry])
        assert manifest["custody"]["chain_version"] == 2
        assert manifest["receipt"] is None
        assert manifest["timestamp"]["status"] == "missing"
        assert manifest["timestamp"]["forged"] is False
        assert manifest["signing_key"] is None
        assert evidence.public_signing_key(
            {"algorithm": "ECDSA-P-256-SHA256", "pem": SIGNING_PEM}) is None

    def test_custody_event_does_not_carry_a_chain_version(self):
        prepared = queue_ingest.prepare(
            [{"photo": api.JPEG, "record": _record(
                "cp-1", TICKET_HASH, wall=WALL + STEP, mono=MONO + STEP)}],
            ticket_hash=TICKET_HASH, expected_prev=TICKET_HASH,
            ticket_clock=TICKET_CLOCK, allowed_checkpoints={"cp-1"})
        assert prepared["ok"] is True
        event = queue_ingest.custody_event(
            prepared, ticket_hash=TICKET_HASH, photo_ids=["ph-1"])
        assert "chain_version" not in event
        assert event["event_type"] == "offline_batch"
        assert event["file_hash"] == prepared["phone_chain_head"]
        assert event["event_data"]["sealed_photos"] == [{
            "photo_id": "ph-1",
            "photo_sha256": PHOTO_HASH,
            "checkpoint_id": "cp-1",
        }]
        assert "photo_ids" not in event["event_data"]
        sealed = ledger.seal(
            {"record_id": api.RECORD_A, **event},
            ledger.genesis_hash(api.RECORD_A))
        assert sealed["chain_version"] == 2

    def test_a_sealed_photo_binding_is_part_of_the_custody_hash(self):
        prepared = queue_ingest.prepare(
            [{"photo": api.JPEG, "record": _record(
                "cp-1", TICKET_HASH, wall=WALL + STEP, mono=MONO + STEP)}],
            ticket_hash=TICKET_HASH, expected_prev=TICKET_HASH,
            ticket_clock=TICKET_CLOCK, allowed_checkpoints={"cp-1"})
        event = queue_ingest.custody_event(
            prepared, ticket_hash=TICKET_HASH, photo_ids=["ph-1"])
        event.update({
            "record_id": api.RECORD_A,
            "recorded_at": "2026-09-14T10:31:00+00:00",
        })
        sealed = ledger.seal(event, ledger.genesis_hash(api.RECORD_A))
        ordered = [sealed]
        assert ledger.verify_chain(ordered, api.RECORD_A)["intact"] is True
        edited = json.loads(json.dumps(sealed))
        edited["event_data"]["sealed_photos"][0]["photo_sha256"] = "ef" * 32
        broken = ledger.verify_chain([edited], api.RECORD_A)
        assert broken["intact"] is False
        assert broken["broken_at_index"] == 0
