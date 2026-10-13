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
    than pulling ~150 MB into a test run. A system Chrome is the same fallback.
    """
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if root and os.path.isdir(root):
        candidates = sorted(
            (os.path.join(root, d, "chrome-linux", "chrome")
             for d in os.listdir(root) if d.startswith("chromium-")), reverse=True)
        found = next((c for c in candidates if os.path.exists(c)), None)
        if found:
            return found
    for candidate in ("/opt/google/chrome/chrome", "/usr/bin/google-chrome",
                      "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if os.path.exists(candidate):
            return candidate
    return None


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


class TestTheOfflineSealCard:
    """The second card. Judged in the page, from the package, with no network.

    The packages are the same ones the differential test runs through
    ``offline_seal.py``. A local timestamp does not chain to the DigiCert and
    Sectigo certificates pinned in the page, so the SEALED case that uses a
    local authority is the differential test, not this one. This one checks
    that the page says the words, and that it says them with the network off.
    """

    def _package(self, **kw):
        from test_offline_seal import build_package
        package, _roots = build_package(**kw)
        return package

    def test_two_cards_and_a_missing_timestamp_is_named(self, page, tmp_path):
        text = load(page, tmp_path, self._package())
        assert page.locator("#custodyCard").count() == 1
        assert page.locator("#sealCard").count() == 1
        assert "Every link verifies" in text
        assert "receipt present, timestamp absent" in page.inner_text("#sealCard")
        assert "forged" not in page.inner_text("#sealCard").lower()

    def test_flags_are_words_beside_the_label(self, page, tmp_path):
        import capture_record
        package = self._package(flags=(
            capture_record.FLAG_SCREEN_CAPTURED | capture_record.FLAG_MOCK_LOCATION))
        text = page_text(page, tmp_path, package)
        seal = page.inner_text("#sealCard")
        assert "receipt present, timestamp absent" in seal
        assert "screen captured" in seal
        assert "mock location" in seal
        assert "Flags do not change this label" in seal
        assert "Every link verifies" in text

    def test_a_broken_byte_reads_tampered(self, page, tmp_path):
        package = self._package()
        package["offline"]["captures"][0]["record"]["photo_sha256"] = "ef" * 32
        seal = page_text(page, tmp_path, package, card="#sealCard")
        assert "TAMPERED" in seal

    def test_a_bad_signature_reads_forged(self, page, tmp_path):
        import base64
        package = self._package()
        package["offline"]["captures"][0]["assertion"] = base64.b64encode(
            b"not-a-signature").decode()
        seal = page_text(page, tmp_path, package, card="#sealCard")
        assert "FORGED" in seal

    def test_a_reboot_reads_unverified_time(self, page, tmp_path):
        package = self._package(boot_id="boot-session-after-reboot")
        seal = page_text(page, tmp_path, package, card="#sealCard")
        assert "UNVERIFIED TIME" in seal
        assert "receipt present, timestamp absent" in seal

    def test_a_three_minute_jump_reads_device_clock_mismatch(self, page, tmp_path):
        package = self._package(wall_extra=180_000)
        seal = page_text(page, tmp_path, package, card="#sealCard")
        assert "DEVICE CLOCK MISMATCH" in seal

    def test_a_digicert_token_reads_sealed_with_wifi_off(self, page, tmp_path):
        path = os.path.join(os.path.dirname(__file__), "fixtures",
                            "sealed_digicert_package.json")
        package = json.loads(open(path).read())
        seen = []
        page.context.set_offline(True)
        page.on("request", lambda r: seen.append(r.url))
        load(page, tmp_path, package)
        assert "Every link verifies" in page.inner_text("#custodyCard")
        seal = page.inner_text("#sealCard")
        assert "\nSEALED\n" in f"\n{seal}\n"
        external = [u for u in seen if not u.startswith("file://")]
        assert not external, f"the page made requests while verifying: {external}"

    def test_wifi_off_still_shows_both_cards(self, page, tmp_path):
        seen = []
        page.context.set_offline(True)
        page.on("request", lambda r: seen.append(r.url))
        text = load(page, tmp_path, self._package())
        assert "Every link verifies" in text
        assert "receipt present, timestamp absent" in page.inner_text("#sealCard")
        external = [u for u in seen if not u.startswith("file://")]
        assert not external, f"the page made requests while verifying: {external}"


def page_text(page, tmp_path, manifest, card="#verifyResult"):
    load(page, tmp_path, manifest)
    return page.inner_text(card)
