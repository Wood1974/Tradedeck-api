"""Checkr start + webhook routes, with Checkr and the database faked."""
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from flask import Flask, g

import checkr_api
from tests.test_identity import FakeDb

AUTH = {"Authorization": "Bearer t"}
KEY = "checkr_test_key"


class FakeCheckr:
    def __init__(self):
        self.calls = []

    def __call__(self, path, payload):
        self.calls.append((path, payload))
        if path == "candidates":
            return {"id": "cand_1"}
        return {"id": "inv_1", "invitation_url": "https://apply.checkr.com/invite/inv_1"}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("CHECKR_ENABLED", "1")
    monkeypatch.setenv("CHECKR_API_KEY", KEY)
    monkeypatch.setenv("CHECKR_PACKAGE", "tasker_standard")
    db, ck = FakeDb(), FakeCheckr()
    db.tables["profiles"] = [{"id": "user-1", "email": "a@b.com", "full_name": "Josh Woodall",
                              "checkr_candidate_id": None, "checkr_status": None}]
    monkeypatch.setattr(checkr_api, "_checkr_post", ck)
    app = Flask(__name__)
    app.register_blueprint(checkr_api.checkr_bp)

    @app.before_request
    def _attach():
        g.supabase = db

    return SimpleNamespace(client=app.test_client(), db=db, checkr=ck, monkeypatch=monkeypatch)


def profile(env):
    return env.db.tables["profiles"][0]


def signed(event, key=KEY):
    raw = json.dumps(event).encode()
    return raw, {"X-Checkr-Signature": hmac.new(key.encode(), raw, hashlib.sha256).hexdigest(),
                 "Content-Type": "application/json"}


def test_start_requires_auth(env):
    assert env.client.post("/checkr/start").status_code == 401


def test_not_configured_is_503(env):
    env.monkeypatch.delenv("CHECKR_API_KEY")
    r = env.client.post("/checkr/start", headers=AUTH)
    assert r.status_code == 503 and r.get_json()["error"] == "not_configured"
    assert env.checkr.calls == []


def test_on_hold_without_enable_flag_even_with_keys(env):
    env.monkeypatch.delenv("CHECKR_ENABLED")
    r = env.client.post("/checkr/start", headers=AUTH)
    assert r.status_code == 503 and r.get_json()["error"] == "not_configured"
    assert env.checkr.calls == []


def test_start_creates_candidate_and_invitation(env):
    r = env.client.post("/checkr/start", headers=AUTH)
    assert r.status_code == 201
    assert r.get_json()["invitation_url"].startswith("https://apply.checkr.com/")
    (p1, cand), (p2, inv) = env.checkr.calls
    assert p1 == "candidates" and cand["first_name"] == "Josh" and cand["last_name"] == "Woodall"
    assert p2 == "invitations" and inv["package"] == "tasker_standard" and inv["candidate_id"] == "cand_1"
    assert profile(env)["checkr_status"] == "pending" and profile(env)["checkr_candidate_id"] == "cand_1"


def test_start_reuses_existing_candidate(env):
    profile(env)["checkr_candidate_id"] = "cand_9"
    env.client.post("/checkr/start", headers=AUTH)
    assert [c[0] for c in env.checkr.calls] == ["invitations"]


def test_start_refuses_when_already_cleared(env):
    profile(env)["checkr_status"] = "cleared"
    assert env.client.post("/checkr/start", headers=AUTH).status_code == 409


def test_checkr_failure_is_502_and_leaves_profile(env):
    def boom(path, payload):
        raise RuntimeError("down")
    env.monkeypatch.setattr(checkr_api, "_checkr_post", boom)
    assert env.client.post("/checkr/start", headers=AUTH).status_code == 502
    assert profile(env)["checkr_status"] is None


def test_webhook_rejects_bad_signature(env):
    raw, h = signed({"type": "report.completed"}, key="wrong")
    assert env.client.post("/checkr/webhook", data=raw, headers=h).status_code == 400


def test_webhook_clear_sets_cleared(env):
    profile(env).update(checkr_candidate_id="cand_1", checkr_status="pending")
    raw, h = signed({"type": "report.completed", "data": {"object": {"candidate_id": "cand_1", "result": "clear"}}})
    assert env.client.post("/checkr/webhook", data=raw, headers=h).status_code == 200
    assert profile(env)["checkr_status"] == "cleared" and profile(env)["checkr_cleared_at"]


def test_webhook_consider(env):
    profile(env).update(checkr_candidate_id="cand_1", checkr_status="pending")
    raw, h = signed({"type": "report.completed", "data": {"object": {"candidate_id": "cand_1", "result": "consider"}}})
    env.client.post("/checkr/webhook", data=raw, headers=h)
    assert profile(env)["checkr_status"] == "consider" and "checkr_cleared_at" not in profile(env)


def test_expired_invitation_resets_only_pending(env):
    profile(env).update(checkr_candidate_id="cand_1", checkr_status="pending")
    raw, h = signed({"type": "invitation.expired", "data": {"object": {"candidate_id": "cand_1"}}})
    env.client.post("/checkr/webhook", data=raw, headers=h)
    assert profile(env)["checkr_status"] is None
    profile(env)["checkr_status"] = "cleared"
    env.client.post("/checkr/webhook", data=raw, headers=h)
    assert profile(env)["checkr_status"] == "cleared"
