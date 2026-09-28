"""The sellable API: does it stay inside one tenant, and does it derive?

Two properties matter more than the rest and both are tested by trying to
break them.

**Isolation.** Every read is scoped on the caller's tenant before it runs. The
test for this is not "does scoping work" but "can tenant B reach tenant A's
record by asking for it by id", because that is the request an attacker
actually sends.

**Derivation.** The parent service's /shield/analyze-photo took the hash, the
EXIF flag, the coordinates and the image URL from the request body and never
re-read the row it was about to update. A contractor could upload a real photo
and point the analyser at a stock image of perfect work; the pass landed on the
real photo's row and the client-supplied hash went into the custody log as the
evidence. So the tests here send those fields and assert they are ignored.
"""
import base64
import hashlib
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import attestation  # noqa: E402

# The attestation generator lives with the tests that break it, and is reused
# here rather than copied: a second copy would drift, and the copy in the file
# that tests the accept path is exactly the one that must not.
attest_fixtures = pytest.importorskip(
    "test_app_attest", reason="cbor2/cryptography are not installed")

CI_ENV = {
    "SUPABASE_URL": "https://ci.invalid",
    "SUPABASE_SERVICE_KEY": "ci",
    "STRIPE_SECRET_KEY": "ci",
    "STRIPE_WEBHOOK_SECRET": "ci",
    "ANTHROPIC_API_KEY": "ci",
    "IP_HASH_SALT": "ci-salt-not-a-secret",
}

TENANT_A = "aaaaaaaa-0000-0000-0000-00000000000a"
TENANT_B = "bbbbbbbb-0000-0000-0000-00000000000b"
RECORD_A = "11111111-0000-0000-0000-000000000001"
APP_ID = "ABCDE12345.com.tradedeck.shield"

#: A real, minimal JPEG. The refusal tests can use four magic bytes because
#: nothing downstream of the gate ever runs on them; an accepted capture is
#: decoded, measured and EXIF-read, so it needs a file that actually is one.
JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
    "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR"
    "CAAIAAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA"
    "AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkK"
    "FhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWG"
    "h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl"
    "5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA"
    "AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYk"
    "NOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOE"
    "hYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk"
    "5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q==")


# ----------------------------------------------------------- a fake Supabase
class FakeQuery:
    """Records the filters applied, so a test can assert on the scoping."""

    def __init__(self, table, store):
        self.table, self.store = table, store
        self.filters = {}
        self._payload = None
        self._op = "select"
        self._order = None
        self._limit = None

    def select(self, *_a, **_kw):
        return self

    def insert(self, row):
        self._op, self._payload = "insert", row
        return self

    def update(self, row):
        self._op, self._payload = "update", row
        return self

    def eq(self, col, val):
        self.filters[col] = val
        return self

    def neq(self, *_a):
        return self

    def is_(self, *_a):
        return self

    def order(self, column, desc=False, **_kw):
        # Faithful on purpose. A no-op order() hides exactly the class of bug
        # it is meant to surface: the first version of the custody writer
        # picked its predecessor with order(recorded_at).limit(1), and a fake
        # that ignored both made the chain look fine here while breaking in a
        # browser.
        self._order = (column, desc)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        rows = self.store.rows.get(self.table, [])
        if self._op == "insert":
            payload = self._payload if isinstance(self._payload, list) else [self._payload]
            written = []
            for item in payload:
                item = {"id": item.get("id", f"generated-{len(rows)}"), **item}
                rows.append(item)
                written.append(item)
            self.store.rows[self.table] = rows
            self.store.writes.append((self.table, written))
            return type("Res", (), {"data": written})()
        if self._op == "update":
            self.store.writes.append((self.table, self._payload))
            return type("Res", (), {"data": []})()

        out = rows
        for col, val in self.filters.items():
            out = [r for r in out if r.get(col) == val]
        if self._order:
            column, desc = self._order
            out = sorted(out, key=lambda r: (r.get(column) is None,
                                             r.get(column) or ""), reverse=desc)
        if self._limit is not None:
            out = out[:self._limit]
        self.store.reads.append((self.table, dict(self.filters)))
        return type("Res", (), {"data": out})()


class FakeStorageBucket:
    def __init__(self, store):
        self.store = store

    def upload(self, path, raw, _opts=None):
        self.store.uploads.append((path, len(raw)))
        return {"path": path}


class FakeStorage:
    def __init__(self, store):
        self.store = store

    def from_(self, _bucket):
        return FakeStorageBucket(self.store)


class FakeSchema:
    def __init__(self, store):
        self.store = store

    def table(self, name):
        return FakeQuery(name, self.store)


class FakeAuth:
    """`db().auth.get_user(token)`, the shape auth.py calls.

    Present so the member credential path runs for real. A viewer being
    refused a write is only worth asserting if the role came back through the
    same lookup production uses.
    """

    def __init__(self, store):
        self.store = store

    def get_user(self, token):
        user_id = self.store.sessions.get(token)
        if not user_id:
            return type("Resp", (), {"user": None})()
        return type("Resp", (), {"user": type("U", (), {"id": user_id})()})()


class FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.reads, self.writes, self.uploads = [], [], []
        self.storage = FakeStorage(self)
        self.sessions = {}
        self.auth = FakeAuth(self)

    def schema(self, _name):
        return FakeSchema(self)

    def table(self, name):
        return FakeQuery(name, self)


def base_rows():
    return {
        "tenants": [{"id": TENANT_A, "name": "Acme Restoration",
                     "slug": "acme", "status": "active"}],
        "records": [{
            "id": RECORD_A, "tenant_id": TENANT_A, "external_ref": "JOB-7",
            "subject_ref": "crew-12", "buyer_ref": "owner-3",
            "site_lat": 40.76, "site_lng": -111.89, "status": "active",
            "checkpoints_locked_at": None,
        }],
        "checkpoints": [{"id": "cp-1", "tenant_id": TENANT_A,
                         "record_id": RECORD_A, "point_number": 1,
                         "label": "Underlayment", "status": "pending"}],
        "photos": [],
        "custody_log": [],
    }


@pytest.fixture
def app_and_db(monkeypatch):
    """A real app, a fake database, and real credentials.

    The auth path is NOT stubbed. `require_tenant` runs for every request here,
    parses the presented token and resolves it through `tenancy.usable_key`
    exactly as it would in production -- so these tests cover the credential
    check as well as the routes. Stubbing the decorator would have tested the
    handlers against an authorisation that cannot fail, which is the one
    condition worth being sure about.
    """
    for key, value in CI_ENV.items():
        monkeypatch.setenv(key, value)

    import db as db_mod
    import tenancy
    import auth
    import tenant_api

    store = FakeDB(base_rows())
    monkeypatch.setattr(db_mod, "client", lambda: store)
    monkeypatch.setattr(auth, "db", lambda: store)
    monkeypatch.setattr(tenant_api, "db", lambda: store)

    keys = {}
    for tenant_id in (TENANT_A, TENANT_B):
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
        {"id": TENANT_B, "name": "Other Co", "slug": "other", "status": "active"})

    from flask import Flask
    flask_app = Flask(__name__)
    flask_app.register_blueprint(tenant_api.bp)
    flask_app.config["TESTING"] = True

    return flask_app, store, keys, tenant_api


def client_for(flask_app, store, tenant_api, tenant_id, keys=None,
               kind="api_key", role=None):
    """A test client that presents a genuine credential for `tenant_id`."""
    client = flask_app.test_client()
    token = (keys or {}).get(tenant_id, "")
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    if kind == "member":
        # Not a shld_ token, so require_tenant falls through to the session
        # path and resolves this through shield.members, exactly as it would
        # for a human signed in to the console.
        session_token = f"session-{role or 'member'}"
        store.sessions[session_token] = f"user-{role or 'member'}"
        store.rows.setdefault("members", []).append({
            "id": f"member-{role or 'member'}",
            "tenant_id": tenant_id,
            "auth_user_id": f"user-{role or 'member'}",
            "role": role or "member",
            "disabled_at": None,
            "tenants": {"status": "active"},
        })
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {session_token}"
    return client


# --------------------------------------------------------------- isolation --
class TestTenantIsolation:
    def test_another_tenants_record_does_not_exist(self, app_and_db):
        """Not 403. Not found.

        A 403 confirms the id is real, which is a small leak and a free
        oracle: try ids until one stops 404ing. Scoping the lookup means the
        row is simply not there.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_B, keys)
        got = client.get(f"/shield/v2/records/{RECORD_A}")
        assert got.status_code == 404
        assert "not found" in got.get_json()["error"].lower()

    def test_listing_is_scoped_before_the_query_runs(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_B, keys)
        got = client.get("/shield/v2/records")
        assert got.status_code == 200
        assert got.get_json()["records"] == []
        reads = [f for table, f in store.reads if table == "records"]
        assert any(f.get("tenant_id") == TENANT_B for f in reads), (
            "the records query ran without a tenant_id filter")

    def test_the_owning_tenant_does_see_it(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.get("/shield/v2/records")
        assert [r["external_ref"] for r in got.get_json()["records"]] == ["JOB-7"]


# -------------------------------------------------------------- derivation --
class TestCaptureMustAttest:
    """A capture that cannot prove it came from a camera is not recorded.

    The owner's rule, 2026-09-28. It reverses attestation.py's own argument
    that a labelled capture beats no capture -- which holds for documenting
    work, and does not hold for a product whose claim is that the photograph
    is real. An `unattested` row is still hashed, chained and exported inside
    something marked "evidence", and the chain is what makes a reader believe
    it.

    What can pass it is one thing only: an App Attest attestation that
    `app_attest.verify` walked to the configured Apple root itself, bound to a
    challenge this service issued and has not spent. The class below proves
    that path end to end. Everything here proves the door stays shut for
    everything else -- and `verified` is never a value a caller supplies.
    """

    def test_an_upload_with_no_attestation_is_refused(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(
            f"/shield/v2/records/{RECORD_A}/photos",
            data={"checkpoint_id": "cp-1",
                  "file": (io.BytesIO(b"\xff\xd8\xff\xe0" + b"x" * 300), "x.jpg")},
            content_type="multipart/form-data")
        assert got.status_code == 422
        assert "camera" in got.get_json()["error"].lower()

    def test_a_refused_capture_writes_nothing(self, app_and_db):
        """Not the row, not the storage object, not the custody entry.

        A refusal that still leaves a photo row behind would put an
        unattested capture in the record by another door.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        client.post(f"/shield/v2/records/{RECORD_A}/photos",
                    data={"checkpoint_id": "cp-1",
                          "file": (io.BytesIO(b"\xff\xd8\xff\xe0" + b"x" * 300), "x.jpg")},
                    content_type="multipart/form-data")
        assert not [w for t, w in store.writes if t == "photos"]
        assert not store.uploads
        assert not [w for t, w in store.writes if t == "custody_log"]

    def test_claiming_an_attestation_does_not_make_one(self, app_and_db):
        """The caller may assert anything; assertion is not verification."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        for platform in ("ios", "android"):
            got = client.post(
                f"/shield/v2/records/{RECORD_A}/photos",
                data={"checkpoint_id": "cp-1",
                      "file": (io.BytesIO(b"\xff\xd8\xff\xe0" + b"x" * 300), "x.jpg"),
                      "attestation": "whatever-the-client-likes",
                      "attestation_platform": platform,
                      "attestation_tier": "hardware_attested"},
                content_type="multipart/form-data")
            assert got.status_code == 422, (
                f"a self-declared {platform} attestation was accepted")

    def test_an_unknown_platform_is_refused_not_guessed(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(
            f"/shield/v2/records/{RECORD_A}/photos",
            data={"checkpoint_id": "cp-1",
                  "file": (io.BytesIO(b"\xff\xd8\xff\xe0" + b"x" * 300), "x.jpg"),
                  "attestation": "t", "attestation_platform": "windows-phone"},
            content_type="multipart/form-data")
        assert got.status_code == 422
        assert "not one this service can check" in got.get_json()["error"]


class TestNothingTheCallerSendsIsEvidence:
    def test_every_custody_entry_carries_the_tenant(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        client.post("/shield/v2/records", json={"external_ref": "JOB-8"})
        entries = [w for t, w in store.writes if t == "custody_log"
                   for w in (w if isinstance(w, list) else [w])]
        assert entries
        assert all(e.get("tenant_id") == TENANT_A for e in entries)

    def test_the_chain_is_sealed_at_version_two(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        client.post("/shield/v2/records", json={"external_ref": "JOB-9"})
        entries = [w for t, w in store.writes if t == "custody_log"
                   for w in (w if isinstance(w, list) else [w])]
        assert entries[0]["chain_version"] == 2
        assert len(entries[0]["entry_hash"]) == 64


# ------------------------------------------------------------- the product --
class TestTheRecordLifecycle:
    def test_a_record_needs_an_external_ref(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post("/shield/v2/records", json={})
        assert got.status_code == 400
        assert "external_ref" in got.get_json()["error"]

    def test_one_party_cannot_be_both_sides(self, app_and_db):
        """The subject of the evidence may not also be the party buying it."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post("/shield/v2/records",
                          json={"external_ref": "JOB-X",
                                "subject_ref": "same", "buyer_ref": "same"})
        assert got.status_code == 400
        assert "differ" in got.get_json()["error"]

    def test_coordinates_must_come_as_a_pair(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post("/shield/v2/records",
                          json={"external_ref": "JOB-Y", "site_lat": 40.7})
        assert got.status_code == 400

    def test_checkpoints_lock_once_set(self, app_and_db):
        """A checkpoint list that can be edited later is not a commitment."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)

        first = client.post(f"/shield/v2/records/{RECORD_A}/checkpoints",
                            json={"checkpoints": [{"label": "Footing"},
                                                  {"label": "Rebar"}]})
        assert first.status_code == 201
        assert first.get_json()["locked"] is True

        store.rows["records"][0]["checkpoints_locked_at"] = "2026-09-28T00:00:00Z"
        second = client.post(f"/shield/v2/records/{RECORD_A}/checkpoints",
                             json={"checkpoints": [{"label": "Rewritten"}]})
        assert second.status_code == 409
        assert "locked" in second.get_json()["error"].lower()

    def test_a_viewer_cannot_open_a_record(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys,
                            kind="member", role="viewer")
        got = client.post("/shield/v2/records", json={"external_ref": "JOB-Z"})
        assert got.status_code == 403

    def test_a_photo_needs_a_checkpoint_on_this_record(self, app_and_db):
        """Checked before attestation, so the 404 is still reachable."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(f"/shield/v2/records/{RECORD_A}/photos",
                          data={"checkpoint_id": "cp-belonging-elsewhere",
                                "file": (io.BytesIO(b"\xff\xd8\xff\xe0abcd"), "x.jpg")},
                          content_type="multipart/form-data")
        assert got.status_code == 404

    def test_an_empty_file_is_refused(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(f"/shield/v2/records/{RECORD_A}/photos",
                          data={"checkpoint_id": "cp-1",
                                "file": (io.BytesIO(b""), "x.jpg")},
                          content_type="multipart/form-data")
        assert got.status_code == 400


class TestCaptureWithARealAttestation:
    """The other half: prove the door actually opens for a genuine capture.

    Every other test in this file proves a refusal, and a gate that refuses
    everything passes all of them. If the accept path were broken -- a field
    renamed between `app_attest.verify` and `interpret_app_attest`, a challenge
    never spent, a root read from the wrong key -- capture would be silently
    closed forever and the suite would stay green.

    The chain is minted by `test_app_attest`, and handed to the service the
    same way Apple's root would be: through APPLE_APP_ATTEST_ROOT_PEM. That
    substitution is the reason the anchor is configuration rather than a
    constant.
    """

    def attest(self, monkeypatch, client, record_id=RECORD_A, app_id=APP_ID,
               **kw):
        """Ask for a challenge, then answer it with a real attestation."""
        got = client.post(f"/shield/v2/records/{record_id}/capture-challenge")
        assert got.status_code == 201, got.get_json()
        challenge = got.get_json()["challenge"]

        blob, key_id, root_pem = attest_fixtures.build(
            challenge=challenge, app_id=app_id,
            payload_sha256=kw.pop("payload_sha256",
                                  hashlib.sha256(JPEG).digest()), **kw)
        monkeypatch.setenv("APPLE_APP_ATTEST_ROOT_PEM", root_pem)
        monkeypatch.setenv("APP_ATTEST_APP_ID", APP_ID)
        return {
            "attestation": base64.b64encode(blob).decode(),
            "attestation_key_id": base64.b64encode(key_id).decode(),
            "attestation_challenge": challenge,
            "attestation_platform": "ios",
        }, root_pem

    def post(self, client, fields, checkpoint="cp-1"):
        data = {"checkpoint_id": checkpoint,
                "file": (io.BytesIO(JPEG), "shot.jpg")}
        data.update(fields)
        return client.post(f"/shield/v2/records/{RECORD_A}/photos",
                           data=data, content_type="multipart/form-data")

    def test_a_genuine_attested_capture_is_recorded(self, app_and_db,
                                                    monkeypatch):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)

        got = self.post(client, fields)
        assert got.status_code == 201, got.get_json()

        written = [w for t, w in store.writes if t == "photos"]
        assert written, "a verified capture wrote no photo row"
        assert store.uploads, "a verified capture stored no object"
        assert [w for t, w in store.writes if t == "custody_log"]

    def test_the_recorded_tier_is_hardware_and_is_derived(self, app_and_db,
                                                          monkeypatch):
        """The row must say hardware_attested because the chain verified.

        Not because the client asked for it: the request below also claims a
        tier of its own, and the stored value has to be the derived one.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)
        fields["attestation_tier"] = "totally-made-up-tier"

        assert self.post(client, fields).status_code == 201
        row = [w for t, w in store.writes if t == "photos"][0]
        blob = json.dumps(row)
        assert attestation.TIER_HARDWARE in blob
        assert "totally-made-up-tier" not in blob

    def test_an_attestation_does_not_carry_over_to_another_file(
            self, app_and_db, monkeypatch):
        """A genuine device, an honest attestation, somebody else's photograph.

        This is the attack a challenge alone does not stop, and the reason the
        attestation is bound to `SHA256(challenge || SHA256(bytes))` rather
        than to the challenge by itself. The attestation below is real and
        live; only the file is swapped.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)

        got = client.post(
            f"/shield/v2/records/{RECORD_A}/photos",
            data=dict({"checkpoint_id": "cp-1",
                       "file": (io.BytesIO(JPEG + b"tampered"), "shot.jpg")},
                      **fields),
            content_type="multipart/form-data")
        assert got.status_code == 422, (
            "an attestation minted over one file was accepted for another")
        assert not [w for t, w in store.writes if t == "photos"]

    def test_a_payload_digest_from_the_caller_is_ignored(self, app_and_db,
                                                          monkeypatch):
        """The same rule as every other derived field, on the newest one.

        Written because a mutation survived: letting the request supply
        `payload_sha256` hands the attacker the other half of the binding —
        attest over a real photograph, send its digest, upload anything. The
        digest must come from the bytes that arrived and from nowhere else.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)
        fields["payload_sha256"] = base64.b64encode(
            hashlib.sha256(JPEG).digest()).decode()

        got = client.post(
            f"/shield/v2/records/{RECORD_A}/photos",
            data=dict({"checkpoint_id": "cp-1",
                       "file": (io.BytesIO(JPEG + b"not what was attested"),
                                "shot.jpg")},
                      **fields),
            content_type="multipart/form-data")
        assert got.status_code == 422, (
            "the caller's own payload digest was used instead of the bytes")

    def test_a_challenge_is_spent_once(self, app_and_db, monkeypatch):
        """The replay: same device, same attestation, a second photograph."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)

        assert self.post(client, fields).status_code == 201
        again = self.post(client, fields)
        assert again.status_code == 422, (
            "a spent challenge was accepted a second time -- one attestation "
            "would then cover every upload forever")

    def test_a_challenge_issued_to_another_actor_is_not_spendable(
            self, app_and_db, monkeypatch):
        """Otherwise one party's device answers another party's challenge."""
        flask_app, store, keys, tenant_api = app_and_db
        mine = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        theirs = client_for(flask_app, store, tenant_api, TENANT_A, keys,
                            kind="member", role="admin")
        fields, _root = self.attest(monkeypatch, theirs)
        assert self.post(mine, fields).status_code == 422

    def test_with_no_root_configured_even_a_genuine_capture_is_refused(
            self, app_and_db, monkeypatch):
        """A missing anchor closes the gate; it never skips the chain check.

        This is the fail-open shape that would matter most: a deployment that
        forgot the environment variable and recorded everything.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)
        monkeypatch.delenv("APPLE_APP_ATTEST_ROOT_PEM")

        assert self.post(client, fields).status_code == 422
        assert not [w for t, w in store.writes if t == "photos"]

    def test_a_chain_to_someone_elses_root_is_refused(self, app_and_db,
                                                      monkeypatch):
        """The forged attestation: the attacker runs their own CA."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)
        _blob, _key, other = attest_fixtures.build(challenge="x", app_id=APP_ID)
        monkeypatch.setenv("APPLE_APP_ATTEST_ROOT_PEM", other)

        assert self.post(client, fields).status_code == 422

    def test_an_attestation_for_another_bundle_is_refused(self, app_and_db,
                                                          monkeypatch):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client,
                                    app_id="ZZZZZ99999.com.someone.else")
        monkeypatch.setenv("APP_ATTEST_APP_ID", APP_ID)
        assert self.post(client, fields).status_code == 422

    def test_a_development_attestation_is_refused_unless_enabled(
            self, app_and_db, monkeypatch):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client,
                                    aaguid=attest_fixtures.app_attest.AAGUID_DEV)
        assert self.post(client, fields).status_code == 422

    def test_the_refusal_says_the_chain_did_not_verify(self, app_and_db,
                                                       monkeypatch):
        """The reason must come from the verifier, not from somewhere near it.

        Written because a mutation survived the rest of this class: hardcoding
        `verified=True` in the wiring still produced a refusal, because
        `receipt_ok` and `token_nonce` come from the same result and either one
        withholds trust on its own. Safe, and it made the reason wrong -- the
        operator reading the log would be told the key or app identity
        mismatched when in fact the chain did not verify. An inaccurate reason
        is how a real misconfiguration gets diagnosed as the wrong thing, so
        the text is pinned.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client)
        _b, _k, other = attest_fixtures.build(challenge="x", app_id=APP_ID)
        monkeypatch.setenv("APPLE_APP_ATTEST_ROOT_PEM", other)

        error = self.post(client, fields).get_json()["error"]
        assert "not cryptographically verified" in error, error
        assert "did not match" not in error, (
            "a chain failure is being reported as a key or app-identity "
            "mismatch")

    def test_android_is_closed_even_with_a_live_challenge(self, app_and_db,
                                                          monkeypatch):
        """Play Integrity is not built, so Android capture must stay shut.

        The other Android test presents no challenge, which means the binding
        check refuses it before the platform branch matters. This one spends a
        real one, so the only thing left holding the door is that an
        unverified Play Integrity verdict cannot reach a trusted tier.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(
            f"/shield/v2/records/{RECORD_A}/capture-challenge")
        challenge = got.get_json()["challenge"]

        refused = self.post(client, {
            "attestation": base64.b64encode(b"a play integrity token").decode(),
            "attestation_platform": "android",
            "attestation_challenge": challenge})
        assert refused.status_code == 422
        assert not [w for t, w in store.writes if t == "photos"]

    def test_a_challenge_from_another_record_is_still_the_actors_own(
            self, app_and_db, monkeypatch):
        """Scope, stated rather than assumed.

        The nonce binds an actor to a moment, not to a record. A capture is
        already scoped to its record by `require_record` and the checkpoint
        lookup, so this passing is correct -- it is written down so that a
        later reader does not mistake it for a hole, and so that narrowing the
        binding to a record becomes a deliberate change with a failing test.
        """
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        fields, _root = self.attest(monkeypatch, client, record_id=RECORD_A)
        assert self.post(client, fields).status_code == 201


class TestThePackage:
    def test_storage_paths_never_leave_the_building(self, app_and_db):
        """The recipient gets hashes, not our object paths."""
        flask_app, store, keys, tenant_api = app_and_db
        store.rows["photos"] = [{
            "id": "ph-1", "tenant_id": TENANT_A, "record_id": RECORD_A,
            "checkpoint_id": "cp-1", "storage_path": "secret/path/x.jpg",
            "original_hash": "a" * 64, "verdict": "pass",
        }]
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.get(f"/shield/v2/records/{RECORD_A}/package")
        assert got.status_code == 200
        body = got.get_data(as_text=True)
        assert "secret/path" not in body
        assert "a" * 64 in body

    def test_the_package_carries_a_head_hash(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        payload = client.get(f"/shield/v2/records/{RECORD_A}/package").get_json()
        assert len(payload["head_hash"]) == 64
        assert payload["chain_version"] == 2
        assert payload["schema"] == "tradedeck.shield.package.v2"

    def test_exporting_is_itself_recorded(self, app_and_db):
        """Who took a copy, and when, is part of the history."""
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        client.get(f"/shield/v2/records/{RECORD_A}/package")
        kinds = [w.get("event_type") for t, w in store.writes if t == "custody_log"
                 for w in ([w] if isinstance(w, dict) else w)]
        assert "exported" in kinds


class TestCloseOut:
    def test_the_grade_is_computed_not_submitted(self, app_and_db):
        """The parent built its report from the request body. This does not."""
        flask_app, store, keys, tenant_api = app_and_db
        store.rows["photos"] = [{
            "id": "ph-1", "tenant_id": TENANT_A, "record_id": RECORD_A,
            "checkpoint_id": "cp-1", "verdict": "fail",
            "superseded_by": None, "superseded_at": None,
        }]
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(f"/shield/v2/records/{RECORD_A}/complete",
                          json={"overall_verdict": "pass", "score": 100})
        assert got.status_code == 200
        grade = got.get_json()["grade"]
        assert grade["verdict"] != "pass", (
            "a caller declared their own outcome and the service believed it")

    def test_a_record_with_no_checkpoints_cannot_be_closed(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        store.rows["checkpoints"] = []
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        got = client.post(f"/shield/v2/records/{RECORD_A}/complete", json={})
        assert got.status_code == 409

    def test_closing_returns_the_head_to_keep(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        store.rows["photos"] = [{
            "id": "ph-1", "tenant_id": TENANT_A, "record_id": RECORD_A,
            "checkpoint_id": "cp-1", "verdict": "pass",
            "superseded_by": None, "superseded_at": None,
        }]
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        body = client.post(f"/shield/v2/records/{RECORD_A}/complete",
                           json={}).get_json()
        assert len(body["head_hash"]) == 64
        assert "outside Shield" in body["keep_this"]


class TestTheOutcomeReachesThePublishedReport:
    """Closing a record must land in completion_reports, not only the chain.

    /public/results counts that table. A close-out that seals its outcome into
    the custody log and writes no row there is an outcome the published failure
    rate structurally cannot include — and a rate that cannot include our
    failures is worse than no rate at all. This is the same defect as omitting
    a verdict category, arriving through the write path instead of the read.
    """

    def _closable(self, store, verdict="pass"):
        store.rows["photos"] = [{
            "id": "ph-1", "tenant_id": TENANT_A, "record_id": RECORD_A,
            "checkpoint_id": "cp-1", "verdict": verdict,
            "superseded_by": None, "superseded_at": None,
        }]

    def test_closing_writes_a_completion_report(self, app_and_db):
        flask_app, store, keys, tenant_api = app_and_db
        self._closable(store)
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        body = client.post(f"/shield/v2/records/{RECORD_A}/complete",
                           json={}).get_json()

        written = [w for t, w in store.writes if t == "completion_reports"
                   for w in (w if isinstance(w, list) else [w])]
        assert written, "the outcome never reached completion_reports"
        row = written[0]
        assert row["tenant_id"] == TENANT_A
        assert row["overall_verdict"] == body["grade"]["verdict"]
        assert row["custody_head_hash"] == body["head_hash"]
        assert len(row["report_sha256"]) == 64

    def test_an_incomplete_record_is_still_reported(self, app_and_db):
        """The outcome most worth publishing must not be the one that fails.

        A record whose checkpoints were not all documented grades
        'incomplete'. The schema's verdict constraint originally allowed only
        pass/flag/fail/fake, so this insert would have failed on exactly the
        jobs that went worst.
        """
        flask_app, store, keys, tenant_api = app_and_db
        store.rows["photos"] = []          # nothing documented at all
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        body = client.post(f"/shield/v2/records/{RECORD_A}/complete",
                           json={}).get_json()
        assert body["grade"]["verdict"] == "incomplete"

        written = [w for t, w in store.writes if t == "completion_reports"
                   for w in (w if isinstance(w, list) else [w])]
        assert written and written[0]["overall_verdict"] == "incomplete"

        import transparency
        assert "incomplete" in transparency.JOB_VERDICTS, (
            "an incomplete job would be bucketed as 'unrecognised', which "
            "reads like a data problem rather than a failure to document")

    def test_the_report_hash_is_reproducible_from_the_stored_json(self, app_and_db):
        """A recipient must be able to recompute it without guessing."""
        import hashlib
        import json
        flask_app, store, keys, tenant_api = app_and_db
        self._closable(store)
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        client.post(f"/shield/v2/records/{RECORD_A}/complete", json={})

        row = [w for t, w in store.writes if t == "completion_reports"
               for w in (w if isinstance(w, list) else [w])][0]
        canonical = json.dumps(row["report_json"], sort_keys=True,
                               separators=(",", ":"), default=str)
        assert hashlib.sha256(canonical.encode()).hexdigest() == row["report_sha256"]
