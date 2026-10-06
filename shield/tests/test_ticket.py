"""Job ticket: server signature, phone countersignature, and a database row.

Genesis runs while the phone is online. The server signs a ticket with its
own P-256 key. The phone's attested install key signs the ticket hash,
checked by the same verifiers the capture path already uses. A missing or
invalid hardware signature stores nothing.

These tests run on Linux. They mint keys locally. They do not call Google,
Apple, or a phone.
"""
import base64
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import attestation  # noqa: E402
import capture_record  # noqa: E402
import ledger  # noqa: E402
import ticket  # noqa: E402

attest_fixtures = pytest.importorskip(
    "test_app_attest", reason="cbor2/cryptography are not installed")
android_fixtures = pytest.importorskip(
    "test_android_attest", reason="cryptography is not installed")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, NoEncryption, PrivateFormat, load_pem_public_key)
from cryptography.exceptions import InvalidSignature  # noqa: E402

import test_tenant_api as api  # noqa: E402

SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
SIGNING_PEM = SIGNING_KEY.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
OTHER_PEM = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

LIST_HASH = "ab" * 32
SERVER_MS = 1_700_000_000_000
# Frozen from the canonicalizer. A formatting change has to fail here on
# purpose, not ride through because the test rebuilt the bytes the same way.
CANONICAL = (
    '{"actor_id":"crew-1","checkpoint_list_sha256":"' + LIST_HASH + '",'
    '"expires_at_ms":1700604800000,"record_id":"rec-1",'
    '"server_time_ms":1700000000000,"version":1}'
)
CANONICAL_ROUGHTIME = (
    '{"actor_id":"crew-1","checkpoint_list_sha256":"' + LIST_HASH + '",'
    '"expires_at_ms":1700604800000,"record_id":"rec-1",'
    '"roughtime_ms":1700000000500,"server_time_ms":1700000000000,"version":1}'
)


def _sample(**overrides):
    base = dict(
        record_id="rec-1",
        checkpoint_list_sha256=LIST_HASH,
        actor_id="crew-1",
        server_time_ms=SERVER_MS,
    )
    base.update(overrides)
    return ticket.build_ticket(**base)


def _play(labels, *, nonce="job-1", app=None, package="com.tradedeck.shield",
          verified=True, expect_nonce="job-1", platform="android"):
    payload = {
        "deviceIntegrity": {"deviceRecognitionVerdict": list(labels)},
        "appIntegrity": {
            "appRecognitionVerdict": app or attestation.PLAY_RECOGNIZED,
            "packageName": package,
        },
        "requestDetails": {"requestHash": attestation.challenge_hash(nonce)},
    }
    return ticket.classify_play_integrity(
        payload, verified=verified, expect_nonce=expect_nonce,
        expect_package=package, platform=platform)


# --------------------------------------------------------------- canonical --
def test_chain_version_stays_2():
    assert ledger.CHAIN_VERSION == 2
    assert ticket.TICKET_VERSION == 1
    assert ticket.TICKET_VERSION != ledger.CHAIN_VERSION


def test_canonical_bytes_are_frozen():
    built = _sample()
    assert ticket.canonical(built).decode() == CANONICAL
    # Key order on the way in does not change the bytes.
    backwards = {k: built[k] for k in reversed(list(built))}
    assert ticket.canonical(backwards) == ticket.canonical(built)


def test_null_roughtime_matches_an_omitted_one_and_zero_does_not():
    plain = _sample()
    explicit = dict(plain)
    explicit["roughtime_ms"] = None
    assert ticket.canonical(explicit) == ticket.canonical(plain)
    with_zero = dict(plain)
    with_zero["roughtime_ms"] = 0
    assert b'"roughtime_ms":0' in ticket.canonical(with_zero)
    assert ticket.canonical(with_zero) != ticket.canonical(plain)


def test_a_present_roughtime_reading_is_in_the_bytes():
    built = _sample(roughtime_ms=SERVER_MS + 500)
    assert ticket.canonical(built).decode() == CANONICAL_ROUGHTIME


def test_a_float_is_rejected():
    with pytest.raises(ValueError, match="float"):
        _sample(server_time_ms=SERVER_MS + 0.5)
    with pytest.raises(ValueError, match="whole number"):
        ticket.canonical({**_sample(), "expires_at_ms": True})


CLOCK = {
    "wall_time_ms": 1_700_000_000_000,
    "monotonic_ms": 5_000_000,
    "boot_id": "boot-a",
    "boot_count": 4,
    "flags": 7,
}


def test_ticket_hash_is_sha256_of_those_bytes():
    built = _sample()
    digest = hashlib.sha256(CANONICAL.encode()).hexdigest()
    assert ticket.ticket_hash(built) == digest
    challenge, payload = ticket.hardware_binding(digest, CLOCK)
    assert challenge == ticket.GENESIS_CHALLENGE
    # The payload is not the ticket hash. A batch cannot swap the clock
    # the phone measured when it countersigned.
    assert payload != bytes.fromhex(digest)
    signed_clock = ticket.normalize_clock(CLOCK)
    assert "flags" not in signed_clock
    raw_clock = capture_record.canonical_whole(signed_clock)
    assert payload == hashlib.sha256(bytes.fromhex(digest) + raw_clock).digest()
    swapped = dict(CLOCK)
    swapped["wall_time_ms"] = CLOCK["wall_time_ms"] + 1
    assert ticket.hardware_binding(digest, swapped)[1] != payload


def test_checkpoint_list_hash_is_order_independent_and_ignores_status():
    first = {"id": "cp-1", "point_number": 1, "label": "Underlayment",
             "description": "lapped", "status": "pending"}
    second = {"id": "cp-2", "point_number": 2, "label": "Flashing",
              "status": "failed"}
    forward = ticket.checkpoint_list_hash([first, second])
    backward = ticket.checkpoint_list_hash([second, first])
    assert forward == backward
    graded = dict(first)
    graded["status"] = "approved"
    assert ticket.checkpoint_list_hash([graded, second]) == forward
    relabeled = dict(first)
    relabeled["label"] = "Something else"
    assert ticket.checkpoint_list_hash([relabeled, second]) != forward

    expected = json.dumps(
        {"checkpoints": [
            {"description": "lapped", "id": "cp-1", "label": "Underlayment",
             "point_number": 1},
            {"id": "cp-2", "label": "Flashing", "point_number": 2},
        ]},
        sort_keys=True, separators=(",", ":")).encode()
    assert forward == hashlib.sha256(expected).hexdigest()


# ---------------------------------------------------------------- signature --
def test_the_server_signature_verifies_and_a_tampered_ticket_does_not():
    built = _sample()
    signed = ticket.sign_ticket(built, pem=SIGNING_PEM)
    assert ticket.verify_server_signature(
        signed["ticket"], signed["server_signature"], pem=SIGNING_PEM)["ok"]

    tampered = dict(signed["ticket"])
    tampered["expires_at_ms"] = tampered["expires_at_ms"] + 1
    refused = ticket.verify_server_signature(
        tampered, signed["server_signature"], pem=SIGNING_PEM)
    assert refused["ok"] is False

    other = ticket.verify_server_signature(
        signed["ticket"], signed["server_signature"], pem=OTHER_PEM)
    assert other["ok"] is False


def test_the_exported_public_key_verifies_the_signature_without_the_private():
    built = _sample()
    signed = ticket.sign_ticket(built, pem=SIGNING_PEM)
    exported = ticket.export_public_key(SIGNING_PEM)
    assert exported["algorithm"] == "ECDSA-P-256-SHA256"
    assert "PRIVATE" not in exported["pem"]
    assert exported["pem"].startswith("-----BEGIN PUBLIC KEY-----")
    pub = load_pem_public_key(exported["pem"].encode())
    pub.verify(base64.b64decode(signed["server_signature"]),
               ticket.canonical(signed["ticket"]), ec.ECDSA(hashes.SHA256()))
    tampered = ticket.canonical(signed["ticket"]).replace(
        b"crew-1", b"crew-2")
    with pytest.raises(InvalidSignature):
        pub.verify(base64.b64decode(signed["server_signature"]),
                   tampered, ec.ECDSA(hashes.SHA256()))


def test_a_missing_signing_key_does_not_invent_one():
    assert ticket.load_signing_key("") is None
    assert ticket.load_signing_key("-----BEGIN PRIVATE KEY-----\nnope\n") is None
    with pytest.raises(ticket.TicketKeyError):
        ticket.sign_ticket(_sample(), pem="")


def test_expiry_wrong_actor_and_wrong_record_are_refused():
    built = _sample()
    assert ticket.seal_blocks(
        built, record_id="rec-1", actor_id="crew-1",
        checkpoint_list_sha256=LIST_HASH, now_ms=built["expires_at_ms"]) is None
    assert "expired" in ticket.seal_blocks(
        built, record_id="rec-1", actor_id="crew-1",
        checkpoint_list_sha256=LIST_HASH,
        now_ms=built["expires_at_ms"] + 1).lower()
    assert "actor" in ticket.seal_blocks(
        built, record_id="rec-1", actor_id="someone-else",
        checkpoint_list_sha256=LIST_HASH, now_ms=SERVER_MS).lower()
    assert "record" in ticket.seal_blocks(
        built, record_id="rec-2", actor_id="crew-1",
        checkpoint_list_sha256=LIST_HASH, now_ms=SERVER_MS).lower()


# ---------------------------------------------------------- play integrity --
def test_play_integrity_fixtures_pass_fail_and_absent():
    passed = _play([attestation.STRONG_INTEGRITY])
    assert passed["status"] == "pass"
    assert passed["trusted"] is True
    device = _play([attestation.DEVICE_INTEGRITY])
    assert device["status"] == "pass"

    failed = _play([])
    assert failed["status"] == "fail"
    assert failed["trusted"] is False
    unrecognized = _play([attestation.STRONG_INTEGRITY],
                         app=attestation.UNRECOGNIZED_VERSION)
    assert unrecognized["status"] == "fail"

    absent = ticket.classify_play_integrity(None, platform="android")
    assert absent["status"] == "absent"
    assert absent["trusted"] is False
    assert "not a failure" in absent["reason"]

    ios = ticket.classify_play_integrity(
        {"deviceIntegrity": {"deviceRecognitionVerdict": [
            attestation.STRONG_INTEGRITY]}},
        verified=True, platform="ios")
    assert ios["status"] == "absent"
    assert "Play Integrity" in ios["reason"]
    assert "jailbreak" in ios["reason"]

    # A token the server has not checked is not a pass, however good it looks.
    unverified = _play([attestation.STRONG_INTEGRITY], verified=False)
    assert unverified["status"] == "unverifiable"
    # A strong token bound to some other job is not a pass either.
    unbound = _play([attestation.STRONG_INTEGRITY], nonce="other-job")
    assert unbound["status"] == "unverifiable"

    columns = ticket.play_integrity_columns(passed)
    assert columns["play_integrity_status"] == "pass"
    assert attestation.STRONG_INTEGRITY in columns["play_integrity_labels"]


# -------------------------------------------------------------- roughtime --
def test_roughtime_off_or_absent_leaves_the_field_out():
    assert ticket.outside_clock_ms(enabled=False, fetch=lambda: 5) is None
    assert ticket.outside_clock_ms(enabled="0", fetch=lambda: 5) is None
    assert ticket.outside_clock_ms(enabled=True, fetch=None) is None
    assert ticket.outside_clock_ms(enabled=True, fetch=lambda: None) is None
    assert ticket.outside_clock_ms(enabled=True, fetch=lambda: 1.5) is None

    def boom():
        raise OSError("no network")

    assert ticket.outside_clock_ms(enabled="1", fetch=boom) is None
    assert ticket.outside_clock_ms(enabled="1", fetch=lambda: 1_700_000_000_500) == (
        1_700_000_000_500)


# ------------------------------------------------------- the existing keys --
def test_an_ios_assertion_over_the_ticket_hash_verifies():
    """The capture verifier, unchanged, over genesis client data."""
    digest_hex = ticket.ticket_hash(_sample())
    challenge, payload = ticket.hardware_binding(digest_hex, CLOCK)
    blob = attest_fixtures.build_assertion(
        challenge=challenge, payload_sha256=payload, counter=1)
    out = attest_fixtures.run_assertion(
        blob, challenge=challenge, payload_sha256=payload)
    assert out["verified"] is True, out["reason"]
    # A signature over the bare ticket hash is not this contract.
    bare = attest_fixtures.build_assertion(
        challenge=challenge, payload_sha256=bytes.fromhex(digest_hex), counter=1)
    assert attest_fixtures.run_assertion(
        bare, challenge=challenge, payload_sha256=payload)["verified"] is False
    # A capture assertion is not a ticket signature.
    photo = attest_fixtures.build_assertion(
        challenge="some-capture-nonce",
        payload_sha256=hashlib.sha256(b"photo").digest(), counter=1)
    refused = attest_fixtures.run_assertion(
        photo, challenge=challenge, payload_sha256=payload)
    assert refused["verified"] is False


def test_an_android_signature_over_the_ticket_hash_verifies():
    digest_hex = ticket.ticket_hash(_sample())
    challenge, payload = ticket.hardware_binding(digest_hex, CLOCK)
    signature = android_fixtures.sign(challenge.encode() + payload)
    out = android_fixtures.android_attest.verify_signature(
        signature, challenge=challenge, payload_sha256=payload,
        public_key=android_fixtures.DEVICE_PUB)
    assert out["verified"] is True, out["reason"]
    bare = android_fixtures.sign(challenge.encode() + bytes.fromhex(digest_hex))
    assert android_fixtures.android_attest.verify_signature(
        bare, challenge=challenge, payload_sha256=payload,
        public_key=android_fixtures.DEVICE_PUB)["verified"] is False
    capture = android_fixtures.sign(b"nonce" + hashlib.sha256(b"photo").digest())
    refused = android_fixtures.android_attest.verify_signature(
        capture, challenge=challenge, payload_sha256=payload,
        public_key=android_fixtures.DEVICE_PUB)
    assert refused["verified"] is False


# ------------------------------------------------------------------ route --
@pytest.fixture
def app_and_db(monkeypatch):
    for key, value in api.CI_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SHIELD_TICKET_SIGNING_KEY_PEM", SIGNING_PEM)
    monkeypatch.setenv("APP_ATTEST_APP_ID", api.APP_ID)

    import db as db_mod
    import tenancy
    import auth
    import tenant_api

    store = api.FakeDB(api.base_rows())
    store.rows["records"][0]["checkpoints_locked_at"] = "2026-10-06T00:00:00+00:00"
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

    from flask import Flask
    flask_app = Flask(__name__)
    flask_app.register_blueprint(tenant_api.bp)
    flask_app.config["TESTING"] = True
    return flask_app, store, keys, tenant_api


def _rows(store):
    return list(store.rows.get("job_tickets") or [])


def _actor(store):
    return next(k["id"] for k in store.rows["api_keys"]
                if k["tenant_id"] == api.TENANT_A)


def _seed_ios(store, actor=None, sign_count=0):
    key_id = hashlib.sha256(attest_fixtures.DEVICE_PUB).digest()
    store.rows.setdefault("attested_keys", []).append({
        "key_id": base64.b64encode(key_id).decode(),
        "tenant_id": api.TENANT_A,
        "actor_id": actor or _actor(store),
        "platform": "ios",
        "public_key": base64.b64encode(attest_fixtures.DEVICE_PUB).decode(),
        "environment": "production",
        "sign_count": sign_count,
        "revoked_at": None,
    })
    return key_id


def _seed_android(store, actor=None):
    key_id = hashlib.sha256(android_fixtures.DEVICE_PUB).digest()
    store.rows.setdefault("attested_keys", []).append({
        "key_id": base64.b64encode(key_id).decode(),
        "tenant_id": api.TENANT_A,
        "actor_id": actor or _actor(store),
        "platform": "android",
        "security_level": "TrustedEnvironment",
        "public_key": base64.b64encode(android_fixtures.DEVICE_PUB).decode(),
        "environment": "production",
        "sign_count": 0,
        "revoked_at": None,
    })
    return key_id


def _offer(client, platform="ios", **extra):
    body = {"platform": platform}
    body.update(extra)
    return client.post(f"/shield/v2/records/{api.RECORD_A}/genesis", json=body)


def _ios_assertion(ticket_hash_hex, counter=1, clock=None):
    challenge, payload = ticket.hardware_binding(
        ticket_hash_hex, CLOCK if clock is None else clock)
    blob = attest_fixtures.build_assertion(
        challenge=challenge, payload_sha256=payload, counter=counter)
    return base64.b64encode(blob).decode()


def _android_signature(ticket_hash_hex, clock=None):
    challenge, payload = ticket.hardware_binding(
        ticket_hash_hex, CLOCK if clock is None else clock)
    return android_fixtures.sign(challenge.encode() + payload)


def _seal_body(offer, assertion, key_id, platform="ios", **extra):
    body = {
        "platform": platform,
        "ticket": offer["ticket"],
        "server_signature": offer["server_signature"],
        "assertion": assertion,
        "attestation_key_id": base64.b64encode(key_id).decode(),
        "ticket_clock": CLOCK,
    }
    body.update(extra)
    return body


class TestGenesisRoute:
    def test_an_offer_is_signed_and_stores_nothing(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        got = _offer(client, actor_id="not-the-caller",
                     checkpoint_list_sha256="cd" * 32)
        assert got.status_code == 200, got.get_json()
        body = got.get_json()
        assert body["stored"] is False
        assert _rows(store) == []
        assert body["ticket"]["actor_id"] == _actor(store)
        assert body["ticket"]["record_id"] == api.RECORD_A
        assert body["ticket"]["checkpoint_list_sha256"] != "cd" * 32
        assert "roughtime_ms" not in body["ticket"]
        assert body["ticket_id"] == body["ticket_hash"]
        assert ledger.CHAIN_VERSION == 2
        assert "PRIVATE" not in json.dumps(body)
        assert body["server_public_key"]["pem"].startswith(
            "-----BEGIN PUBLIC KEY-----")
        checked = ticket.verify_server_signature(
            body["ticket"], body["server_signature"], pem=SIGNING_PEM)
        assert checked["ok"] is True
        assert checked["ticket_hash"] == body["ticket_hash"]

    def test_a_hardware_signature_stores_the_ticket(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        assertion = _ios_assertion(offer["ticket_hash"])
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, assertion, key_id))
        assert got.status_code == 201, got.get_json()
        body = got.get_json()
        assert body["stored"] is True
        assert body["chain_version"] == 2
        assert body["play_integrity"]["status"] == "absent"
        assert "jailbreak" in body["play_integrity"]["reason"]
        assert "Play Integrity" in body["play_integrity"]["reason"]
        rows = _rows(store)
        assert len(rows) == 1
        assert rows[0]["ticket_hash"] == offer["ticket_hash"]
        assert rows[0]["hardware_signature"] == assertion
        assert rows[0]["ticket_clock"] == ticket.normalize_clock(CLOCK)
        assert body["ticket_clock"] == rows[0]["ticket_clock"]
        assert ticket.ticket_hash(rows[0]["ticket_json"]) == rows[0]["ticket_hash"]
        assert store.rows["attested_keys"][0]["sign_count"] == 1
        # One ticket. A second seal does not write another row.
        again = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"], counter=2),
                            key_id))
        assert again.status_code == 409
        assert len(_rows(store)) == 1

    def test_a_missing_or_invalid_signature_stores_nothing(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()

        missing = dict(_seal_body(offer, "ignored", key_id))
        del missing["assertion"]
        got = client.post(f"/shield/v2/records/{api.RECORD_A}/genesis",
                          json=missing)
        assert got.status_code == 422
        assert _rows(store) == []

        bad = _seal_body(
            offer,
            base64.b64encode(b"not-an-assertion").decode(),
            key_id)
        got = client.post(f"/shield/v2/records/{api.RECORD_A}/genesis", json=bad)
        assert got.status_code == 422
        assert _rows(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_a_substituted_clock_stores_nothing(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        signed_for = dict(CLOCK)
        sent = dict(CLOCK)
        sent["wall_time_ms"] = CLOCK["wall_time_ms"] + 60_000
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(
                offer, _ios_assertion(offer["ticket_hash"], clock=signed_for),
                key_id, ticket_clock=sent))
        assert got.status_code == 422, got.get_json()
        assert _rows(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

        missing = _seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id)
        del missing["ticket_clock"]
        got = client.post(f"/shield/v2/records/{api.RECORD_A}/genesis", json=missing)
        assert got.status_code == 422
        assert _rows(store) == []
        assert store.rows["attested_keys"][0]["sign_count"] == 0

    def test_a_tampered_ticket_stores_nothing(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        offer["ticket"] = dict(offer["ticket"])
        offer["ticket"]["expires_at_ms"] = offer["ticket"]["expires_at_ms"] + 1
        # Sign the tampered bytes too, so only the server signature is wrong.
        digest = hashlib.sha256(ticket.canonical(offer["ticket"])).hexdigest()
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(digest), key_id))
        assert got.status_code == 422, got.get_json()
        assert _rows(store) == []

    def test_the_wrong_actor_is_refused(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        import tenancy
        owner = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(owner).get_json()

        issued = tenancy.new_api_key()
        store.rows["api_keys"].append({
            "id": "key-other-actor",
            "tenant_id": api.TENANT_A,
            "public_id": issued.public_id,
            "key_hash": issued.key_hash,
            "revoked_at": None,
            "tenants": {"status": "active"},
        })
        other = flask_app.test_client()
        other.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {issued.token}"
        got = other.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id))
        assert got.status_code == 422
        assert "actor" in got.get_json()["error"].lower()
        assert _rows(store) == []

    def test_a_key_attested_to_someone_else_stores_nothing(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store, actor="some-other-person")
        offer = _offer(client).get_json()
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id))
        assert got.status_code == 422
        assert _rows(store) == []

    def test_the_wrong_record_is_refused(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        other_id = "22222222-0000-0000-0000-000000000002"
        store.rows["records"].append({
            "id": other_id, "tenant_id": api.TENANT_A, "external_ref": "JOB-8",
            "status": "active",
            "checkpoints_locked_at": "2026-10-06T00:00:00+00:00",
        })
        store.rows["checkpoints"].append({
            "id": "cp-other", "tenant_id": api.TENANT_A, "record_id": other_id,
            "point_number": 1, "label": "Other", "status": "pending",
        })
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        got = client.post(
            f"/shield/v2/records/{other_id}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id))
        assert got.status_code == 422
        assert "record" in got.get_json()["error"].lower()
        assert _rows(store) == []

    def test_an_expired_ticket_stores_nothing(self, app_and_db, monkeypatch):
        flask_app, store, keys, _tenant_api = app_and_db
        clock = {"now": SERVER_MS}
        monkeypatch.setattr(ticket, "now_ms", lambda: clock["now"])
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        assert offer["ticket"]["expires_at_ms"] == SERVER_MS + ticket.TICKET_TTL_MS
        clock["now"] = offer["ticket"]["expires_at_ms"] + 1
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id))
        assert got.status_code == 422
        assert "expired" in got.get_json()["error"].lower()
        assert _rows(store) == []

    def test_android_signs_the_ticket_hash_and_stores_play_integrity(
            self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_android(store)
        offer = _offer(client, platform="android").get_json()
        signature = _android_signature(offer["ticket_hash"])
        # No token: the row records absence, which is not a fail.
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(
                offer, base64.b64encode(signature).decode(), key_id,
                platform="android"))
        assert got.status_code == 201, got.get_json()
        assert got.get_json()["play_integrity"]["status"] == "absent"
        assert "not a failure" in got.get_json()["play_integrity"]["reason"]
        assert _rows(store)[0]["play_integrity_status"] == "absent"
        assert _rows(store)[0]["platform"] == "android"

        # A presented token is stored unverifiable. This release does not
        # call Google, so the same fixture that classifies as a pass when
        # verified=True must not be stored as a pass from the route.
        other_id = "33333333-0000-0000-0000-000000000003"
        store.rows["records"].append({
            "id": other_id, "tenant_id": api.TENANT_A, "external_ref": "JOB-9",
            "status": "active",
            "checkpoints_locked_at": "2026-10-06T00:00:00+00:00",
        })
        store.rows["checkpoints"].append({
            "id": "cp-9", "tenant_id": api.TENANT_A, "record_id": other_id,
            "point_number": 1, "label": "Flashing", "status": "pending",
        })
        offered = client.post(
            f"/shield/v2/records/{other_id}/genesis",
            json={"platform": "android"}).get_json()
        signature = _android_signature(offered["ticket_hash"])
        strong = {
            "deviceIntegrity": {"deviceRecognitionVerdict": [
                attestation.STRONG_INTEGRITY]},
            "appIntegrity": {
                "appRecognitionVerdict": attestation.PLAY_RECOGNIZED,
                "packageName": "com.tradedeck.shield",
            },
            "requestDetails": {
                "requestHash": attestation.challenge_hash(offered["ticket_hash"])},
        }
        got = client.post(
            f"/shield/v2/records/{other_id}/genesis",
            json=_seal_body(
                offered, base64.b64encode(signature).decode(), key_id,
                platform="android", play_integrity=strong))
        assert got.status_code == 201, got.get_json()
        assert got.get_json()["play_integrity"]["status"] == "unverifiable"
        stored = next(r for r in _rows(store) if r["record_id"] == other_id)
        assert stored["play_integrity_status"] == "unverifiable"
        assert stored["play_integrity_status"] != "pass"

    def test_ios_ignores_a_play_integrity_body(self, app_and_db):
        flask_app, store, keys, _tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        offer = _offer(client).get_json()
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(
                offer, _ios_assertion(offer["ticket_hash"]), key_id,
                play_integrity={"deviceIntegrity": {
                    "deviceRecognitionVerdict": [attestation.STRONG_INTEGRITY]},
                    "play_integrity_status": "pass"}))
        assert got.status_code == 201, got.get_json()
        row = _rows(store)[0]
        assert row["play_integrity_status"] == "absent"
        assert "jailbreak" in row["play_integrity_reason"]

    def test_checkpoints_must_be_locked_and_the_key_must_be_configured(
            self, app_and_db, monkeypatch):
        flask_app, store, keys, _tenant_api = app_and_db
        store.rows["records"][0]["checkpoints_locked_at"] = None
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        got = _offer(client)
        assert got.status_code == 409
        assert _rows(store) == []

        store.rows["records"][0]["checkpoints_locked_at"] = "2026-10-06T00:00:00+00:00"
        monkeypatch.delenv("SHIELD_TICKET_SIGNING_KEY_PEM", raising=False)
        got = _offer(client)
        assert got.status_code == 503
        assert _rows(store) == []

    def test_another_tenant_and_a_viewer_store_nothing(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        other = api.client_for(flask_app, store, tenant_api, api.TENANT_B, keys)
        got = other.post(f"/shield/v2/records/{api.RECORD_A}/genesis",
                         json={"platform": "ios"})
        assert got.status_code == 404
        viewer = api.client_for(flask_app, store, tenant_api, api.TENANT_A,
                                keys, kind="member", role="viewer")
        got = viewer.post(f"/shield/v2/records/{api.RECORD_A}/genesis",
                          json={"platform": "ios"})
        assert got.status_code == 403
        assert _rows(store) == []

    def test_two_workers_share_the_row_and_not_the_challenge_jar(
            self, app_and_db, monkeypatch):
        flask_app, store, keys, tenant_api = app_and_db
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        key_id = _seed_ios(store)
        # Worker A's in-memory jar is not where the offer lives.
        tenant_api.CHALLENGES = attestation.ChallengeStore()
        offer = _offer(client).get_json()
        assert _rows(store) == []
        assert offer["ticket_hash"] not in tenant_api.CHALLENGES._live

        # Worker B has its own empty jar and its own client object. The
        # database is the shared rows. The seal carries the ticket itself;
        # there is nothing in memory to look up.
        other_jar = attestation.ChallengeStore()
        tenant_api.CHALLENGES = other_jar
        got = client.post(
            f"/shield/v2/records/{api.RECORD_A}/genesis",
            json=_seal_body(offer, _ios_assertion(offer["ticket_hash"]), key_id))
        assert got.status_code == 201, got.get_json()
        assert len(other_jar) == 0

        import db as db_mod
        other_worker = api.FakeDB(store.rows)
        assert other_worker is not store
        monkeypatch.setattr(db_mod, "client", lambda: other_worker)
        with flask_app.app_context():
            found = db_mod.find_job_ticket(api.TENANT_A, api.RECORD_A)
        assert found["ticket_hash"] == offer["ticket_hash"]
        assert found["hardware_signature"]
        # A worker that does not share the database cannot see it.
        isolated = api.FakeDB(api.base_rows())
        monkeypatch.setattr(db_mod, "client", lambda: isolated)
        with flask_app.app_context():
            assert db_mod.find_job_ticket(api.TENANT_A, api.RECORD_A) is None

    def test_roughtime_absent_still_completes(self, app_and_db, monkeypatch):
        flask_app, store, keys, _tenant_api = app_and_db
        monkeypatch.setenv("SHIELD_ROUGHTIME_ENABLED", "1")

        def boom():
            raise OSError("roughtime unreachable")

        monkeypatch.setattr(ticket, "roughtime_fetch", boom)
        client = api.client_for(flask_app, store, None, api.TENANT_A, keys)
        got = _offer(client)
        assert got.status_code == 200, got.get_json()
        assert "roughtime_ms" not in got.get_json()["ticket"]
        assert _rows(store) == []

        monkeypatch.setattr(ticket, "roughtime_fetch", lambda: SERVER_MS + 50)
        got = _offer(client)
        assert got.status_code == 200, got.get_json()
        assert got.get_json()["ticket"]["roughtime_ms"] == SERVER_MS + 50
