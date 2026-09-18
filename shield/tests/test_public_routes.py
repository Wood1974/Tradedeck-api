"""The two routes that must work for someone who has never bought anything.

Every other route in this service requires a bearer token, and that is correct
— they read or write one customer's evidence. These two are the exception on
purpose: a price list only an insider can read is not a published price list,
and an outcome report only a customer can fetch is not a published outcome
report. Both claims in `INDEPENDENCE.md` depend on a stranger being able to
check them without asking us for anything.

So the first thing each test here asserts is the absence of a 401.
"""
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


class FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def select(self, *_a, **_kw):
        return self

    def execute(self):
        return type("Res", (), {"data": self._rows})()


class FakeDB:
    """Just enough Supabase surface for the two public reads."""

    def __init__(self, tables, fail=False):
        self._tables, self._fail = tables, fail
        self.selected = {}

    def table(self, name):
        if self._fail:
            raise RuntimeError("database unavailable")
        return FakeQuery(self._tables.get(name, []))


@pytest.fixture
def client(monkeypatch):
    for key, value in CI_ENV.items():
        monkeypatch.setenv(key, value)
    import app as app_module
    import routes
    routes._results_cache.update(at=0.0, payload=None)
    return app_module.create_app().test_client(), routes


class TestPricingIsReachableWithoutAToken:
    def test_no_token_required(self, client):
        c, _ = client
        assert c.get("/shield/public/pricing").status_code == 200

    def test_an_invalid_token_does_not_change_the_answer(self, client):
        """The price is the same for everyone, including strangers."""
        c, _ = client
        anon = c.get("/shield/public/pricing").get_json()
        noise = c.get("/shield/public/pricing",
                      headers={"Authorization": "Bearer nonsense"}).get_json()
        assert anon == noise

    def test_private_routes_still_require_a_token(self, client):
        """Guard against a blanket auth removal being mistaken for this change."""
        c, _ = client
        assert c.post("/shield/quote", json={"job_budget_cents": 1}).status_code == 401
        assert c.get("/shield/jobs/abc/checkpoints").status_code == 401

    def test_is_cacheable_rather_than_no_store(self, client):
        c, _ = client
        cache = c.get("/shield/public/pricing").headers["Cache-Control"]
        assert cache.startswith("public,")

    def test_publishes_every_price_the_service_can_charge(self, client):
        import pricing
        c, _ = client
        served = {t["price_cents"] for t in c.get("/shield/public/pricing").get_json()["tiers"]}
        assert served == pricing.VALID_PRICES


class TestResultsAreReachableWithoutAToken:
    TABLES = {
        "shield_completion_reports": [{"overall_verdict": "pass"},
                                      {"overall_verdict": "fail"}],
        "shield_photos": [{"ai_verdict": "pass", "has_exif": True,
                           "superseded_by": None, "superseded_at": None},
                          {"ai_verdict": "fail", "has_exif": False,
                           "superseded_by": "x", "superseded_at": "2026-09-01"}],
        "shield_custody_log": [{"event_type": "integrity_flag"},
                               {"event_type": "uploaded"}],
    }

    def test_no_token_required(self, client, monkeypatch):
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB(self.TABLES))
        assert c.get("/shield/public/results").status_code == 200

    def test_reports_the_failures_not_only_the_passes(self, client, monkeypatch):
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB(self.TABLES))
        body = c.get("/shield/public/results").get_json()
        assert body["job_verdicts"]["fail"] == 1
        assert body["photo_verdicts"]["fail"] == 1
        assert body["integrity_flags"] == 1

    def test_withholds_rates_on_a_tiny_sample(self, client, monkeypatch):
        """Two jobs must not be served to the world as a 50% pass rate."""
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB(self.TABLES))
        body = c.get("/shield/public/results").get_json()
        assert body["sufficient_sample"] is False
        assert body["job_verdict_rates_pct"] is None

    def test_a_database_failure_does_not_serve_a_zeroed_report(self, client, monkeypatch):
        """All-zero counts would be a false statement about our outcomes.

        An unreachable database means we do not know the numbers. Saying so
        with a 503 is honest; serving zeros because the query returned nothing
        is the kind of quiet falsehood this whole module exists to prevent.
        """
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB({}, fail=True))
        resp = c.get("/shield/public/results")
        assert resp.status_code == 503
        assert "job_verdicts" not in resp.get_json()

    def test_stale_numbers_beat_no_numbers_once_a_report_exists(self, client, monkeypatch):
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB(self.TABLES))
        first = c.get("/shield/public/results").get_json()
        monkeypatch.setattr(routes, "db", lambda: FakeDB({}, fail=True))
        routes._results_cache["at"] = 0.0          # force the query path
        again = c.get("/shield/public/results")
        assert again.status_code == 200
        assert again.get_json()["job_verdicts"] == first["job_verdicts"]

    def test_no_identifiers_reach_an_anonymous_caller(self, client, monkeypatch):
        c, routes = client
        monkeypatch.setattr(routes, "db", lambda: FakeDB(self.TABLES))
        blob = c.get("/shield/public/results").get_data(as_text=True)
        for key in ("shield_job_id", "contractor_id", "homeowner_id",
                    "site_address", "gps_lat", "report_json"):
            assert key not in blob
