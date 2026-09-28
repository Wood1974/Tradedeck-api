"""Drive the console in a real browser, against a real running service.

The API tests prove the routes behave. They say nothing about whether the page
a tenant actually opens can reach those routes and render what comes back —
and the failure that matters is not a wrong response, it is a console that
looks fine and quietly does nothing, which is what a Content-Security-Policy
mistake or a wrong element id produces.

So this starts the real Flask app on a port, with the database faked out at
the client boundary and nothing else stubbed, and clicks through the whole
product loop in Chromium: connect with a real API key, open a record, lock
checkpoints, upload a photograph, read the custody chain, close out.

Skipped when Playwright or the browser is absent.
"""
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

sync_api = pytest.importorskip("playwright.sync_api",
                               reason="playwright is not installed")

from test_tenant_api import (  # noqa: E402
    CI_ENV, RECORD_A, TENANT_A, FakeDB, base_rows)

CHROMIUM = "/opt/pw-browsers/chromium"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def service():
    """The real app, on a real port, with a fake database underneath."""
    for key, value in CI_ENV.items():
        os.environ.setdefault(key, value)

    import db as db_mod
    import tenancy

    store = FakeDB(base_rows())
    issued = tenancy.new_api_key()
    store.rows["api_keys"] = [{
        "id": "key-1", "tenant_id": TENANT_A, "public_id": issued.public_id,
        "key_hash": issued.key_hash, "revoked_at": None,
        "tenants": {"status": "active"},
    }]

    db_mod.client = lambda: store
    import auth
    import tenant_api
    auth.db = lambda: store
    tenant_api.db = lambda: store

    import app as app_mod
    flask_app = app_mod.create_app()

    port = free_port()
    thread = threading.Thread(
        target=lambda: flask_app.run(port=port, threaded=True,
                                     use_reloader=False),
        daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{port}"
    for _ in range(50):                      # wait for the socket to answer
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    return base, issued.token, store


@pytest.fixture(scope="module")
def page(service):
    base, token, store = service
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM)
        context = browser.new_context()
        # The upload path asks for a position; grant one so the branch runs.
        context.grant_permissions(["geolocation"])
        context.set_geolocation({"latitude": 40.7606, "longitude": -111.8908})
        pg = context.new_page()
        pg.problems = []
        pg.on("console", lambda m: pg.problems.append(m.text)
              if m.type == "error" else None)
        pg.on("pageerror", lambda e: pg.problems.append(str(e)))
        yield pg, base, token, store
        browser.close()


def connect(page_bundle):
    """Connect from a clean slate.

    The console resumes a session from sessionStorage, which is the right
    behaviour and makes these tests order-dependent: a later one would find
    itself already signed in and the connect form hidden. Clear it first so
    each test starts where a new visitor does.
    """
    pg, base, token, _store = page_bundle
    pg.goto(f"{base}/console/")
    pg.evaluate("() => sessionStorage.clear()")
    pg.reload()
    pg.wait_for_selector("#connectBtn", timeout=6000)
    pg.fill("#baseUrl", base)
    pg.fill("#token", token)
    pg.click("#connectBtn")
    pg.wait_for_selector("#records:not([hidden])", timeout=6000)


class TestTheConsole:
    def test_it_loads_without_a_policy_violation(self, page):
        """A CSP mistake shows up as a page that renders and does nothing."""
        pg, base, _token, _store = page
        pg.goto(f"{base}/console/")
        pg.evaluate("() => sessionStorage.clear()")
        pg.reload()
        pg.wait_for_selector("#connectBtn", timeout=6000)
        refusals = [p for p in pg.problems
                    if "Content Security Policy" in p or "Refused to" in p]
        assert not refusals, refusals[:3]
        assert pg.title() == "Shield Console"

    def test_a_bad_credential_is_reported_not_swallowed(self, page):
        pg, base, _token, _store = page
        pg.goto(f"{base}/console/")
        pg.evaluate("() => sessionStorage.clear()")
        pg.reload()
        pg.fill("#baseUrl", base)
        pg.fill("#token", "shld_deadbeef_notarealsecretatallbutwellformed")
        pg.click("#connectBtn")
        pg.wait_for_selector("#connectErr:not([hidden])", timeout=6000)
        assert "key" in pg.inner_text("#connectErr").lower()

    def test_connecting_shows_the_tenant_and_its_records(self, page):
        connect(page)
        pg, _base, _token, _store = page
        assert "Acme Restoration" in pg.inner_text("#whoTenant")
        assert "API key" in pg.inner_text("#whoCred")
        assert "JOB-7" in pg.inner_text("#recordList")

    def test_the_whole_loop(self, page):
        """Open, lock checkpoints, photograph one, read the chain, close."""
        connect(page)
        pg, _base, _token, store = page
        # The page is module-scoped, so problems accumulate -- including the
        # 401 the bad-credential test causes on purpose. Only new ones count.
        before = len(pg.problems)

        pg.click("#newRecordBtn")
        pg.fill('#newRecord input[name=external_ref]', "JOB-BROWSER-1")
        pg.fill('#newRecord input[name=trade]', "Roofing")
        pg.fill('#newRecord input[name=site_lat]', "40.76056")
        pg.fill('#newRecord input[name=site_lng]', "-111.89083")
        pg.click('#newRecord button[type=submit]')
        pg.wait_for_selector("#detail:not([hidden])", timeout=6000)
        assert "JOB-BROWSER-1" in pg.inner_text("#detailRef")

        # Checkpoints, and the lock confirmation.
        pg.fill('#pointRows input[name=label]', "Underlayment")
        pg.fill('#pointRows input[name=must_show]', "Full deck coverage")
        pg.once("dialog", lambda d: d.accept())
        pg.click('#setPoints button[type=submit]')
        pg.wait_for_selector("#pointList .point", timeout=6000)
        assert "Underlayment" in pg.inner_text("#pointList")

        # A photograph for that checkpoint. A real JPEG header so the server's
        # sniffing accepts it.
        pg.set_input_files(
            "#pointList input[type=file]",
            {"name": "roof.jpg", "mimeType": "image/jpeg",
             "buffer": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 300})
        pg.wait_for_selector("#pointList .evidence", timeout=8000)
        evidence = pg.inner_text("#pointList .evidence")
        assert "unattested" in evidence, (
            "a web upload must be labelled unattested — see AR-1")

        # The hash on screen is the one the SERVER derived.
        import hashlib
        expected = hashlib.sha256(
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 300).hexdigest()
        assert expected in evidence

        # The chain.
        pg.click('nav.tabs button[data-tab="chain"]')
        pg.wait_for_selector("#chainList .entry", timeout=6000)
        kinds = pg.inner_text("#chainList")
        assert "created" in kinds and "uploaded" in kinds
        assert "verifies" in pg.inner_text("#chainVerdict").lower()

        # Close out.
        pg.click('nav.tabs button[data-tab="close"]')
        pg.once("dialog", lambda d: d.accept())
        pg.click("#completeBtn")
        pg.wait_for_selector("#closeResult .verdict-box", timeout=6000)
        assert "head" in pg.inner_text("#closeResult").lower()

        assert not pg.problems[before:], pg.problems[before:][:3]

    def test_nothing_the_page_sends_is_computed_by_the_page(self, page):
        """The console must not hand the service evidence of its own.

        Reads the shipped source rather than trusting the walkthrough: a hash
        computed in the browser would be indistinguishable on screen from one
        the server derived, and that is exactly the confusion the parent
        service shipped.
        """
        console_js = os.path.join(
            os.path.dirname(__file__), "..", "console", "console.js")
        with open(console_js) as fh:
            src = fh.read()
        import re
        src = re.sub(r"/\*[\s\S]*?\*/", "", src)
        src = re.sub(r"//[^\n]*", "", src)

        for forbidden in ("crypto.subtle", "sha256", "original_hash",
                          "has_exif", "verdict:"):
            assert forbidden not in src, (
                f"console.js mentions {forbidden!r} in code — the browser must "
                f"send a file and a checkpoint, and derive nothing")
