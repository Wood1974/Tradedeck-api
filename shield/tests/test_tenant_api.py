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
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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
class TestNothingTheCallerSendsIsEvidence:
    def test_a_client_supplied_hash_is_ignored(self, app_and_db):
        """The hash sealed into the chain is of the bytes that arrived."""
        import hashlib
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)

        raw = b"\xff\xd8\xff\xe0" + b"not really a jpeg but it has a header" * 4
        got = client.post(
            f"/shield/v2/records/{RECORD_A}/photos",
            data={
                "checkpoint_id": "cp-1",
                "file": (io.BytesIO(raw), "x.jpg"),
                # Everything below is a lie the caller would like believed.
                "original_hash": "0" * 64,
                "has_exif": "true",
                "verdict": "pass",
                "site_distance_m": "0",
            },
            content_type="multipart/form-data")
        assert got.status_code == 201, got.get_json()

        photo = got.get_json()["photo"]
        assert photo["original_hash"] == hashlib.sha256(raw).hexdigest()
        assert photo["original_hash"] != "0" * 64
        assert photo.get("verdict") is None, (
            "a caller set their own verdict and the service stored it")

    def test_the_custody_entry_seals_the_derived_hash(self, app_and_db):
        import hashlib
        flask_app, store, keys, tenant_api = app_and_db
        client = client_for(flask_app, store, tenant_api, TENANT_A, keys)
        raw = b"\xff\xd8\xff\xe0" + b"bytes" * 40
        client.post(f"/shield/v2/records/{RECORD_A}/photos",
                    data={"checkpoint_id": "cp-1",
                          "file": (io.BytesIO(raw), "x.jpg"),
                          "original_hash": "f" * 64},
                    content_type="multipart/form-data")

        uploaded = [w for t, w in store.writes if t == "custody_log"
                    for w in (w if isinstance(w, list) else [w])
                    if w.get("event_type") == "uploaded"]
        assert uploaded, "no custody entry was written for the upload"
        assert uploaded[0]["file_hash"] == hashlib.sha256(raw).hexdigest()

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
