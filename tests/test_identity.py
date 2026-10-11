"""ID check + signed note: core rules and routes, with Stripe and the database faked."""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from flask import Flask, g

import identity_api
import identity_core as core


# ---------------------------------------------------------------- helpers --
class Device:
    """Signs like WebCrypto ECDSA P-256: raw 64-byte r||s over canonical JSON."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.raw = self.key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.pub_b64 = base64.b64encode(self.raw).decode()
        self.seal = core.seal_id_for_key(self.raw)

    def note(self, session_id, signed_at=None, **over):
        payload = {
            "kind": core.NOTE_KIND, "v": 1, "statement": core.STATEMENT, "statementVersion": core.STATEMENT_VERSION,
            "sessionId": session_id, "deviceSealId": self.seal,
            "signedAt": (signed_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
        }
        payload.update(over)
        r, s = utils.decode_dss_signature(self.key.sign(core.canonical(payload).encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"payload": payload, "devicePublicKey": self.pub_b64, "signature": base64.b64encode(sig).decode()}


class FakeQuery:
    def __init__(self, rows):
        self.rows, self.f, self.mode, self.arg, self.lim, self.order_key = rows, [], "select", None, None, None

    def select(self, *_a): self.mode = "select"; return self
    def eq(self, c, v): self.f.append((c, v)); return self
    def order(self, c, desc=False): self.order_key = (c, desc); return self
    def limit(self, n): self.lim = n; return self
    def insert(self, row): self.mode, self.arg = "insert", row; return self
    def update(self, patch): self.mode, self.arg = "update", patch; return self

    def execute(self):
        match = [r for r in self.rows if all(r.get(c) == v for c, v in self.f)]
        if self.mode == "insert":
            row = {"id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(), **self.arg}
            self.rows.append(row)
            return SimpleNamespace(data=[row])
        if self.mode == "update":
            for r in match:
                r.update(self.arg)
            return SimpleNamespace(data=match)
        if self.order_key:
            match.sort(key=lambda r: r.get(self.order_key[0], ""), reverse=self.order_key[1])
        return SimpleNamespace(data=match[: self.lim] if self.lim else match)


class FakeDb:
    def __init__(self, user_id="user-1"):
        self.tables, self.user_id = {}, user_id
        self.auth = SimpleNamespace(get_user=lambda token: SimpleNamespace(user=SimpleNamespace(id=self.user_id)))

    def table(self, name): return FakeQuery(self.tables.setdefault(name, []))


class FakeStripe:
    """Stands in for stripe.identity.VerificationSession."""

    def __init__(self):
        self.status, self.created = "requires_input", 0

    def create(self, **kw):
        self.created += 1
        assert kw["type"] == "document"
        assert kw["options"]["document"] == {"require_matching_selfie": True, "require_live_capture": True}
        return SimpleNamespace(id=f"vs_{self.created}", status="requires_input", url=f"https://verify.stripe.com/s/vs_{self.created}")

    def retrieve(self, sid): return SimpleNamespace(id=sid, status=self.status)


def _pem(key):
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


@pytest.fixture
def env(monkeypatch):
    receipt_key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv("IDENTITY_RECEIPT_KEY", _pem(receipt_key))
    db, st = FakeDb(), FakeStripe()
    monkeypatch.setattr(identity_api.stripe.identity, "VerificationSession", st)
    app = Flask(__name__)
    app.register_blueprint(identity_api.identity_bp)

    @app.before_request
    def _attach():
        g.supabase = db

    return SimpleNamespace(client=app.test_client(), db=db, stripe=st, receipt_key=receipt_key, monkeypatch=monkeypatch)


AUTH = {"Authorization": "Bearer t"}
CONSENT = {"consent": True, "consentVersion": identity_api.CONSENT_VERSION}


def start_and_verify(env):
    sid = env.client.post("/identity/start", json=CONSENT, headers=AUTH).get_json()["sessionId"]
    env.stripe.status = "verified"
    return sid


# ------------------------------------------------------------------- core --
def test_statement_is_pinned():
    # Same digest is pinned in shield-app/src/identity/note.test.ts. Change both together, with a new version.
    assert core.statement_sha256() == "8bde7dfaa7949d57d0179ecb7f6a8a6dfc0ecd11912604d22ca528589074945c"


def test_canonical_matches_the_phone():
    assert core.canonical({"b": 1, "a": [2, {"d": 1, "c": "é"}]}) == '{"a":[2,{"c":"é","d":1}],"b":1}'


def test_valid_note_verifies():
    d = Device()
    ok, why, sha = core.verify_note(d.note("vs_1"), "vs_1")
    assert (ok, why) == (True, "ok") and len(sha) == 64


@pytest.mark.parametrize("over,reason", [
    ({"statement": "I did not take these."}, "statement-mismatch"),
    ({"statementVersion": "2"}, "statement-mismatch"),
    ({"sessionId": "vs_other"}, "session-mismatch"),
    ({"deviceSealId": "00000000·00000000"}, "seal-id-key-mismatch"),
    ({"kind": "something.else"}, "bad-kind"),
])
def test_rejects_wrong_payload(over, reason):
    d = Device()
    assert core.verify_note(d.note("vs_1", **over), "vs_1")[1] == reason


def test_rejects_tampered_payload_and_foreign_key_and_clock():
    d = Device()
    n = d.note("vs_1")
    n["payload"]["signedAt"] = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    assert core.verify_note(n, "vs_1")[1] == "signature-invalid"
    other = Device()
    n2 = d.note("vs_1")
    n2["devicePublicKey"] = other.pub_b64
    assert core.verify_note(n2, "vs_1")[1] == "seal-id-key-mismatch"
    old = d.note("vs_1", signed_at=datetime.now(timezone.utc) - timedelta(hours=1))
    assert core.verify_note(old, "vs_1")[1] == "clock-skew"


def test_rejects_der_and_garbage():
    d = Device()
    n = d.note("vs_1")
    n["signature"] = base64.b64encode(b"\x30" + b"\x00" * 70).decode()
    assert core.verify_note(n, "vs_1")[1] == "bad-signature-format"
    assert core.verify_note({"payload": 5}, "vs_1")[0] is False
    assert core.verify_note({}, "vs_1")[1] == "malformed"


# ----------------------------------------------------------------- routes --
def test_statement_endpoint_is_public(env):
    j = env.client.get("/identity/statement").get_json()
    assert j["sha256"] == core.statement_sha256() and j["version"] == "1"


def test_requires_auth(env):
    assert env.client.post("/identity/start", json=CONSENT).status_code == 401
    assert env.client.get("/identity/status").status_code == 401
    assert env.client.post("/identity/note", json={}).status_code == 401


def test_start_needs_explicit_consent(env):
    assert env.client.post("/identity/start", json={}, headers=AUTH).status_code == 400
    assert env.client.post("/identity/start", json={"consent": "yes", "consentVersion": "1"}, headers=AUTH).status_code == 400
    assert env.stripe.created == 0


def test_start_creates_session_and_stores_no_personal_data(env):
    j = env.client.post("/identity/start", json=CONSENT, headers=AUTH).get_json()
    assert j["status"] == "requires_input" and j["url"].startswith("https://verify.stripe.com/")
    row = env.db.tables["shield_identity_sessions"][0]
    assert set(row) == {"id", "created_at", "user_id", "stripe_session_id", "status", "consent_at", "consent_version"}


def test_status_reads_stripe_not_the_client(env):
    env.client.post("/identity/start", json=CONSENT, headers=AUTH)
    assert env.client.get("/identity/status", headers=AUTH).get_json()["verified"] is False
    env.stripe.status = "verified"
    assert env.client.get("/identity/status", headers=AUTH).get_json()["verified"] is True
    assert env.db.tables["shield_identity_sessions"][0]["verified_at"]


def test_note_refused_until_verified(env):
    d = Device()
    sid = env.client.post("/identity/start", json=CONSENT, headers=AUTH).get_json()["sessionId"]
    r = env.client.post("/identity/note", json=d.note(sid), headers=AUTH)
    assert r.status_code == 409 and r.get_json()["error"] == "id-check-not-verified"
    assert env.client.post("/identity/note", json=d.note(sid), headers=AUTH).status_code == 409


def test_note_refused_without_any_id_check(env):
    assert env.client.post("/identity/note", json=Device().note("vs_1"), headers=AUTH).status_code == 409


def test_note_accepted_once_then_idempotent_and_publicly_checkable(env):
    d = Device()
    sid = start_and_verify(env)
    note = d.note(sid)
    r = env.client.post("/identity/note", json=note, headers=AUTH)
    assert r.status_code == 201
    att = r.get_json()
    again = env.client.post("/identity/note", json=note, headers=AUTH)
    assert again.status_code == 200 and again.get_json()["attestationId"] == att["attestationId"]
    assert again.get_json()["receipt"] == att["receipt"]  # the same receipt, not a fresh one
    assert len(env.db.tables["shield_note_attestations"]) == 1
    pub = env.client.get(f"/identity/attestations/{att['attestationId']}").get_json()
    assert pub["verified"] is True and pub["noteSha256"] == att["noteSha256"] and pub["deviceSealId"] == d.seal
    assert set(pub) == {"attestationId", "verified", "noteSha256", "deviceSealId", "signedAt", "statementVersion", "provider"}


def test_note_with_bad_signature_is_rejected(env):
    d = Device()
    sid = start_and_verify(env)
    n = d.note(sid)
    n["payload"]["deviceSealId"] = "00000000·00000000"
    assert env.client.post("/identity/note", json=n, headers=AUTH).status_code == 400
    assert "shield_note_attestations" not in env.db.tables or not env.db.tables["shield_note_attestations"]


def test_public_lookup_handles_unknown_and_malformed_ids(env):
    assert env.client.get("/identity/attestations/not-a-uuid").status_code == 404
    assert env.client.get(f"/identity/attestations/{uuid.uuid4()}").status_code == 404


# ---------------------------------------------------------------- receipt --
# Cross-language vector: the same receipt, key and signature are verified by the phone in
# shield-app/src/identity/receipt.test.ts. The key is a throwaway made for this test, not a real key.
VECTOR_PUB = "BK9KLQI7FrDwxKlg4FEpLz4MkVcEs8n9yqAslQzczPf9Aed0/GocEwPX1VNbDZQTQkMWag/j+n7UNTFt196/6pM="
VECTOR = {
    "payload": {
        "kind": "tradedeck.shield.idreceipt", "v": 1, "attestationId": "66666666-6666-4666-8666-666666666666",
        "noteSha256": "b" * 64, "deviceSealId": "AAAAAAAA\u00b7BBBBBBBB",
        "sessionSha256": "9d4c448fe82e0f2a7f32726170adde6932087bf87fa5f693b7b6dd5f99cff474",
        "idCheck": {"provider": "stripe-identity", "status": "verified"},
        "issuedAt": "2026-10-11T12:00:00Z", "kid": "1a473f66e378a662",
    },
    "signature": "uzbbuUQjxU6wvVHMGAXsviysDU+m1lGF8wRqGITK8Ltq17pl6z4YIzY+U6WFskTq9z5NWoWguuGas8Kt/zKxJw==",
}


def test_vector_verifies_and_rejects_edits():
    assert core.verify_receipt(VECTOR, VECTOR_PUB) == (True, "ok")
    edited = json.loads(json.dumps(VECTOR))
    edited["payload"]["noteSha256"] = "c" * 64
    assert core.verify_receipt(edited, VECTOR_PUB) == (False, "signature-invalid")
    edited = json.loads(json.dumps(VECTOR))
    edited["payload"]["idCheck"]["status"] = "requires_input"
    assert core.verify_receipt(edited, VECTOR_PUB)[0] is False
    assert core.verify_receipt(VECTOR, base64.b64encode(Device().raw).decode())[1] == "kid-mismatch"


def test_note_response_carries_a_receipt_that_verifies_with_the_published_key(env):
    d = Device()
    sid = start_and_verify(env)
    r = env.client.post("/identity/note", json=d.note(sid), headers=AUTH)
    att = r.get_json()
    key = env.client.get("/identity/receipt-key").get_json()
    assert core.verify_receipt(att["receipt"], key["publicKey"]) == (True, "ok")
    p = att["receipt"]["payload"]
    assert (p["attestationId"], p["noteSha256"], p["deviceSealId"]) == (att["attestationId"], att["noteSha256"], d.seal)
    assert p["kid"] == key["kid"] and p["sessionSha256"] == core.sha256_hex(sid.encode())
    assert sid not in json.dumps(att["receipt"])  # the Stripe session id itself is not published


def test_receipt_is_bound_to_this_note_and_not_reusable(env):
    sid = start_and_verify(env)
    a = env.client.post("/identity/note", json=Device().note(sid), headers=AUTH).get_json()
    b = env.client.post("/identity/note", json=Device().note(sid), headers=AUTH).get_json()
    assert a["receipt"]["payload"]["noteSha256"] != b["receipt"]["payload"]["noteSha256"]
    swapped = {"payload": {**a["receipt"]["payload"], "noteSha256": b["noteSha256"]}, "signature": a["receipt"]["signature"]}
    key = env.client.get("/identity/receipt-key").get_json()["publicKey"]
    assert core.verify_receipt(swapped, key)[0] is False


def test_no_note_is_accepted_without_a_receipt_key(env):
    d = Device()
    sid = start_and_verify(env)
    env.monkeypatch.delenv("IDENTITY_RECEIPT_KEY")
    r = env.client.post("/identity/note", json=d.note(sid), headers=AUTH)
    assert r.status_code == 503 and r.get_json()["error"] == "receipt-key-not-configured"
    assert not env.db.tables.get("shield_note_attestations")
    assert env.client.get("/identity/receipt-key").status_code == 503


def test_a_non_p256_receipt_key_is_refused_not_used(env):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    env.monkeypatch.setenv("IDENTITY_RECEIPT_KEY", _pem(_ec.generate_private_key(_ec.SECP384R1())))
    d = Device()
    sid = start_and_verify(env)
    assert env.client.post("/identity/note", json=d.note(sid), headers=AUTH).status_code == 503
