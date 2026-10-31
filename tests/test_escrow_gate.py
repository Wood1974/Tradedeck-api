"""Escrow / draw / Stripe Connect routes stay closed unless ESCROW_ENABLED is on."""

from unittest.mock import MagicMock, patch

import pytest

import escrow
from app import app

GATED = [
    ("post", "/stripe/connect/onboard"),
    ("post", "/stripe/escrow/create"),
    ("post", "/stripe/escrow/release"),
    ("post", "/stripe/escrow/refund"),
    ("get", "/draws/d1"),
    ("post", "/draws/d1/approve"),
    ("post", "/draws/d1/photos/upload"),
    ("get", "/draws/d1/photos"),
]


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.mark.parametrize("value", [None, "", "false", "0", "no"])
@pytest.mark.parametrize("method,path", GATED)
def test_routes_404_while_off(client, monkeypatch, method, path, value):
    if value is None:
        monkeypatch.delenv("ESCROW_ENABLED", raising=False)
    else:
        monkeypatch.setenv("ESCROW_ENABLED", value)
    with patch("app.supabase_admin") as sb, patch("app.stripe") as st:
        res = getattr(client, method)(path, json={"draw_id": "d1"},
                                      headers={"Authorization": "Bearer t"})
        assert res.status_code == 404
        sb.auth.get_user.assert_not_called()
        assert not st.mock_calls


@pytest.mark.parametrize("method,path", GATED)
def test_routes_reach_auth_when_on(client, monkeypatch, method, path):
    monkeypatch.setenv("ESCROW_ENABLED", "true")
    res = getattr(client, method)(path, json={"draw_id": "d1"})
    assert res.status_code == 401


def test_webhook_ignores_escrow_events_while_off(client, monkeypatch):
    monkeypatch.delenv("ESCROW_ENABLED", raising=False)
    event = {"id": "evt_1", "type": "payment_intent.amount_capturable_updated",
             "data": {"object": {"metadata": {"draw_id": "d1"}}}}
    with patch("app.stripe.Webhook.construct_event", return_value=event), \
         patch("app._webhook_already_processed", return_value=False), \
         patch("app._record_webhook_event") as record, \
         patch("app.mark_escrow_held") as held, \
         patch("app.supabase_admin") as sb:
        res = client.post("/stripe/webhook", data=b"{}", headers={"Stripe-Signature": "s"})
    assert res.status_code == 200
    held.assert_not_called()
    sb.table.assert_not_called()
    record.assert_called_once_with("evt_1", event["type"])


def test_escrow_create_uses_stored_amount_and_payee_not_request():
    draw = {"id": "d1", "job_id": "s1", "amount_cents": 50000, "payee_id": "worker"}
    schedule = {"id": "s1", "job_id": "j1", "payee_id": "worker"}
    job = {"id": "j1", "owner_id": "owner"}
    with patch.object(escrow, "get_draw", return_value=draw), \
         patch.object(escrow, "get_draw_schedule", return_value=schedule), \
         patch.object(escrow, "get_job", return_value=job), \
         patch.object(escrow, "get_escrow_for_draw", return_value=None):
        _, _, _, payee_id, amount = escrow.ensure_escrow_create_allowed(
            MagicMock(), {"draw_id": "d1", "amount_cents": 1, "payee_id": "attacker"}, "owner")
    assert payee_id == "worker"
    assert amount == 50000


def test_escrow_create_rejects_non_owner():
    draw = {"id": "d1", "job_id": "s1", "amount_cents": 50000, "payee_id": "worker"}
    with patch.object(escrow, "get_draw", return_value=draw), \
         patch.object(escrow, "get_draw_schedule", return_value={"id": "s1", "job_id": "j1"}), \
         patch.object(escrow, "get_job", return_value={"id": "j1", "owner_id": "owner"}):
        with pytest.raises(escrow.EscrowError) as e:
            escrow.ensure_escrow_create_allowed(MagicMock(), {"draw_id": "d1"}, "someone-else")
    assert e.value.status_code == 403
