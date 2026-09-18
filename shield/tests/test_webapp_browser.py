"""Drive the shipped single file in a real browser, against a real package.

The differential test proves `verify.js` computes the right answer. It says
nothing about whether the page a recipient actually opens reaches that answer
and renders it honestly — and the failure that matters is not a wrong hash, it
is a page that shows a reassuring tick while the chain underneath it is broken.

So this loads `index.html` in Chromium, drops in packages built by `ledger.py`,
and reads what the page says. Skipped when Playwright or the browser is absent.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ledger  # noqa: E402

sync_api = pytest.importorskip("playwright.sync_api",
                               reason="playwright is not installed")

WEBAPP = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "webapp"))


def entry(**over):
    base = {
        "shield_job_id": "job-abc", "photo_id": "photo-1",
        "event_type": "uploaded", "actor_id": "user-1",
        "actor_type": "contractor", "event_data": {"note": "footing form"},
        "gps_lat": 40.76056, "gps_lng": -111.89083, "file_hash": "a" * 64,
        "integrity_note": None, "exif_captured_at": "2026-09-14T10:30:00+00:00",
        "recorded_at": "2026-09-14T10:31:00+00:00",
    }
    base.update(over)
    return base


def package(job_id="job-abc", n=4, intact_claim=True):
    entries, prev = [], ledger.genesis_hash(job_id)
    for i in range(n):
        sealed = ledger.seal(
            entry(shield_job_id=job_id, photo_id=f"photo-{i}",
                  recorded_at=f"2026-09-14T10:{30 + i:02d}:00+00:00"), prev)
        entries.append(sealed)
        prev = sealed["entry_hash"]
    return {
        "job": {"shield_job_id": job_id},
        "custody_entries": entries,
        "custody": {"head_hash": prev, "chain_intact": intact_claim},
        "checkpoints": [],
    }, prev


def _chromium_path():
    """An already-installed Chromium, if the bundled one is not the right build.

    Playwright pins a browser revision per version, so a pip install that does
    not match what is on disk refuses to launch and tells you to download one.
    Where a host provides a browser (PLAYWRIGHT_BROWSERS_PATH), use it rather
    than pulling ~150 MB into a test run.
    """
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if not root or not os.path.isdir(root):
        return None
    candidates = sorted(
        (os.path.join(root, d, "chrome-linux", "chrome")
         for d in os.listdir(root) if d.startswith("chromium-")), reverse=True)
    return next((c for c in candidates if os.path.exists(c)), None)


@pytest.fixture(scope="module")
def browser():
    # --no-sandbox because this runs in a container that does not grant the
    # user namespaces Chromium's own sandbox needs. It is a test harness
    # loading a local file, not a browsing session.
    args = ["--no-sandbox", "--disable-background-networking",
            "--disable-component-update", "--no-first-run", "--disable-sync",
            "--disable-default-apps"]
    with sync_api.sync_playwright() as p:
        host = _chromium_path()
        try:
            b = (p.chromium.launch(executable_path=host, args=args) if host
                 else p.chromium.launch(args=args))
        except Exception as exc:                       # noqa: BLE001
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


@pytest.fixture
def page(browser, tmp_path):
    pg = browser.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.goto(f"file://{WEBAPP}/shield.html")
    yield pg
    assert not errors, f"the page logged errors: {errors}"
    pg.close()


def load(page, tmp_path, manifest, expect_head=None):
    path = tmp_path / "package.json"
    path.write_text(json.dumps(manifest))
    page.set_input_files("#packageFile", str(path))
    if expect_head:
        page.fill("#expectHead", expect_head)
        page.dispatch_event("#expectHead", "change")
    page.wait_for_selector("#verifyResult .card")
    return page.inner_text("#verifyResult")


class TestThePageTellsTheTruth:
    def test_an_intact_chain_reads_as_verified(self, page, tmp_path):
        manifest, _ = package()
        text = load(page, tmp_path, manifest)
        assert "Every link verifies" in text
        klass = page.get_attribute("#verifyResult .card", "class")
        assert "bad" not in klass

    def test_a_verified_chain_still_states_what_it_does_not_show(self, page, tmp_path):
        """A tick with no caveat is the overclaim this codebase exists to avoid.

        The reader is usually in a dispute, and what they do with an
        unqualified result is quote it.
        """
        manifest, _ = package()
        text = load(page, tmp_path, manifest)
        assert "does not show" in text.lower()
        assert "camera" in text.lower()
        # Without an expected head, truncation is undetectable — say so.
        assert "deleted from the end" in text

    def test_an_edited_entry_reads_as_broken_and_names_the_entry(self, page, tmp_path):
        manifest, _ = package()
        manifest["custody_entries"][2]["gps_lat"] = 41.5
        text = load(page, tmp_path, manifest)
        assert "does not verify" in text.lower()
        assert "entry 3 of 4" in text.lower()
        assert "bad" in page.get_attribute("#verifyResult .card", "class")

    def test_a_matching_expected_head_is_reported_as_confirmed(self, page, tmp_path):
        manifest, head = package()
        text = load(page, tmp_path, manifest, expect_head=head)
        assert "ends where you were told" in text.lower()
        assert "good" in page.get_attribute("#verifyResult .card", "class")

    def test_truncation_is_reported_when_a_head_is_supplied(self, page, tmp_path):
        manifest, head = package()
        manifest["custody_entries"] = manifest["custody_entries"][:-1]
        text = load(page, tmp_path, manifest, expect_head=head)
        assert "shortened" in text.lower()
        assert "bad" in page.get_attribute("#verifyResult .card", "class")

    def test_a_package_lying_about_itself_is_called_out(self, page, tmp_path):
        """SPEC.md §5 — a worse finding than a broken chain, shown separately."""
        manifest, _ = package()
        manifest["custody_entries"][1]["actor_type"] = "homeowner"
        text = load(page, tmp_path, manifest)          # still claims intact
        assert "misdescribes itself" in text.lower()

    def test_a_package_with_no_entries_is_not_reported_as_verified(self, page, tmp_path):
        manifest, _ = package()
        manifest["custody_entries"] = []
        text = load(page, tmp_path, manifest)
        assert "not verifiable" in text.lower()
        assert "producer's assertion" in text

    def test_junk_json_does_not_render_as_a_result(self, page, tmp_path):
        path = tmp_path / "junk.json"
        path.write_text("this is not json")
        page.set_input_files("#packageFile", str(path))
        page.wait_for_selector("#verifyResult .card")
        assert "not valid json" in page.inner_text("#verifyResult").lower()


class TestThePageMakesNoNetworkRequests:
    def test_verifying_is_entirely_local(self, page, tmp_path):
        """The claim on the tab is that nothing is uploaded. Check it.

        A recipient is often checking a package handed over by the party they
        are in dispute with. A request at this moment tells somebody they are
        checking, which is a reason on its own not to make one.
        """
        seen = []
        page.on("request", lambda r: seen.append(r.url))
        manifest, head = package()
        load(page, tmp_path, manifest, expect_head=head)
        external = [u for u in seen if not u.startswith("file://")]
        assert not external, f"the page made requests while verifying: {external}"
