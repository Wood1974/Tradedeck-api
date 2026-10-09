"""Server-locked anchors.

A rewritten chain that keeps a fresh receipt still fails when the verifier
is given the anchors locked before the rewrite. The failure says
``no locked anchor for this head``. A tail that was locked and then removed
fails because that anchor names an entry the package no longer has. An old
package with no anchors says anchor absent, and that is not a failure.

The store in these tests is in-process. It refuses delete and overwrite
while retention is still running, which is the COMPLIANCE rule the bucket
has to enforce. Nothing here calls AWS, DigiCert, or Sectigo.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "verifier"))

import anchor_lock  # noqa: E402
import ledger  # noqa: E402
import offline_seal  # noqa: E402
import shield_verify  # noqa: E402
import tsa  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

JOB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
HARNESS = os.path.join(os.path.dirname(__file__), "..", "webapp", "tests",
                       "harness.mjs")
T0 = datetime(2026, 9, 1, 10, 5, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 1, 10, 7, tzinfo=timezone.utc)


def _chain(note=None, count=3):
    out, prev = [], ledger.genesis_hash(JOB)
    for i in range(count):
        raw = {
            "shield_job_id": JOB,
            "event_type": "uploaded",
            "actor_type": "contractor",
            "recorded_at": f"2026-09-0{i + 1}T10:00:00+00:00",
        }
        if note and i == count - 1:
            raw["integrity_note"] = note
        sealed = ledger.seal(raw, prev)
        out.append(sealed)
        prev = sealed["entry_hash"]
    return out


def _stamp_for(head, gen_time="20260901100500Z"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-tsa")])
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime(2026, 8, 1))
            .not_valid_after(datetime(2026, 12, 1))
            .sign(key, hashes.SHA256()))
    raw = tsa.mint_token(
        hashed_message=bytes.fromhex(head), nonce=11, key=key, cert=cert,
        gen_time=gen_time)
    token = base64.b64encode(raw).decode("ascii")
    return {
        "status": "present",
        "forged": False,
        "token_b64": token,
        "authority": "local",
        "gen_time": gen_time,
    }


def _lock(store, entries, *, now=T0):
    locked = []
    for seq, entry in enumerate(entries):
        recorded = datetime.fromisoformat(entry["recorded_at"])
        gen_time = (recorded + timedelta(minutes=5)).strftime("%Y%m%d%H%M%SZ")
        stamped = _stamp_for(entry["entry_hash"], gen_time)
        view = anchor_lock.anchor_after_seal(
            JOB, seq, entry["entry_hash"], entry["recorded_at"],
            timestamp=stamped, store=store, now=now)
        assert view["status"] == "locked", view
        locked.append(view["anchor"])
    return locked


def _package(entries, anchors=None):
    return {
        "schema": "tradedeck.shield.package.v2",
        "chain_version": 2,
        "record": {"id": JOB},
        "custody": entries,
        "head_hash": ledger.head_of(entries, JOB),
        "locked_anchors": list(anchors or []),
    }


def _js(manifest, anchors=None, op="package"):
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    payload = {"op": op, "manifest": manifest, "anchors": anchors}
    if op == "seal":
        payload = {"op": "seal", "package": manifest, "anchors": anchors}
    proc = subprocess.run(
        ["node", HARNESS], input=json.dumps(payload),
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        pytest.fail(proc.stderr.strip() or proc.stdout)
    return json.loads(proc.stdout)


def _texts(report):
    return [item.get("text", "") for item in report.get("findings") or []]


class _DownStore:
    """Fails puts until ``down`` is cleared. Then it is a compliance store."""

    def __init__(self):
        self.inner = anchor_lock.MemoryLockStore()
        self.down = True

    def put(self, key, body, retain_until):
        if self.down:
            raise OSError("s3 down")
        return self.inner.put(key, body, retain_until)

    def delete(self, key):
        return self.inner.delete(key)

    def get(self, key):
        return self.inner.get(key)

    def list(self, prefix):
        return self.inner.list(prefix)


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_ANCHOR_QUEUE_PATH", str(tmp_path / "anchors.db"))
    monkeypatch.delenv("SHIELD_ANCHOR_BUCKET", raising=False)


class TestTheLockStore:
    def test_compliance_refuses_overwrite_and_delete(self):
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        store = anchor_lock.MemoryLockStore(now=lambda: now)
        store.put("anchors/job/00000000-ab.json", b"{\"head_hash\":\"ab\"}",
                  now + timedelta(days=2555))
        with pytest.raises(anchor_lock.ComplianceError):
            store.put("anchors/job/00000000-ab.json", b"{\"head_hash\":\"ff\"}",
                      now + timedelta(days=1))
        with pytest.raises(anchor_lock.ComplianceError):
            store.delete("anchors/job/00000000-ab.json")
        assert store.get("anchors/job/00000000-ab.json") == b"{\"head_hash\":\"ab\"}"

    def test_a_disabled_deployment_does_not_stamp_or_write(self, queue, monkeypatch):
        def explode(*_args, **_kwargs):
            raise AssertionError("disabled mode asked for a timestamp")
        monkeypatch.setattr(tsa, "stamp", explode)
        view = anchor_lock.anchor_after_seal(
            JOB, 0, "ab" * 32, "2026-09-01T10:00:00+00:00")
        assert view["status"] == "disabled"
        assert anchor_lock.anchors_for(JOB) == []

    def test_chain_version_stays_2(self):
        assert ledger.CHAIN_VERSION == 2


class TestFailureThenRetry:
    def test_tsa_down_then_retry_records_the_delay(self, queue, monkeypatch):
        store = anchor_lock.MemoryLockStore()
        entries = _chain(count=1)
        head = entries[0]["entry_hash"]

        def down(_url, _body):
            raise OSError("timestamp authority down")

        view = anchor_lock.anchor_after_seal(
            JOB, 0, head, entries[0]["recorded_at"],
            store=store, fetch=down, now=T0)
        assert view["status"] == "timestamp_pending"
        assert store.list("anchors/") == []

        stamped = _stamp_for(head, "20260901100700Z")

        def later(head_hash, **_kwargs):
            assert head_hash == head
            return stamped

        monkeypatch.setattr(tsa, "stamp", later)
        drained = anchor_lock.drain(store=store, now=T1)
        assert drained[0]["status"] == "locked"
        assert drained[0]["anchor"]["delay_ms"] == 120_000
        assert store.list("anchors/")
        with pytest.raises(anchor_lock.ComplianceError):
            store.delete(drained[0]["object_key"])

    def test_s3_down_then_the_queue_drains(self, queue):
        store = _DownStore()
        entries = _chain(count=1)
        head = entries[0]["entry_hash"]
        stamped = _stamp_for(head)
        view = anchor_lock.anchor_after_seal(
            JOB, 0, head, entries[0]["recorded_at"],
            timestamp=stamped, store=store, now=T0)
        assert view["status"] == "anchor_pending"
        assert view["anchor"] is None
        assert store.list("anchors/") == []

        store.down = False
        drained = anchor_lock.drain(store=store, now=T1)
        assert drained[0]["status"] == "locked"
        assert drained[0]["anchor"]["delay_ms"] == 120_000
        assert drained[0]["anchor"]["head_hash"] == head
        with pytest.raises(anchor_lock.ComplianceError):
            store.delete(drained[0]["object_key"])


class TestTheVerifiers:
    def test_a_rewrite_has_no_locked_anchor_for_the_new_head(self, queue):
        store = anchor_lock.MemoryLockStore()
        original = _chain()
        locked = _lock(store, original)
        rewritten = _chain(note="replaced")
        assert ledger.head_of(rewritten, JOB) != ledger.head_of(original, JOB)
        package = _package(rewritten)
        report = shield_verify.verify_package(package, anchors=locked)
        assert report["ok"] is False
        assert any(problem == "no locked anchor for this head"
                   for problem in report["problems"])
        assert any("not in this chain" in problem for problem in report["problems"])
        js = _js(package, locked)
        texts = _texts(js)
        assert any(text == "no locked anchor for this head" for text in texts)
        assert any("not in this chain" in text for text in texts)
    def test_truncating_the_tail_leaves_an_anchor_behind(self, queue):
        store = anchor_lock.MemoryLockStore()
        original = _chain()
        locked = _lock(store, original)
        short = original[:-1]
        report = shield_verify.verify_package(_package(short), anchors=locked)
        assert report["ok"] is False
        assert any("not in this chain" in problem for problem in report["problems"])
        js = _js(_package(short), locked)
        assert any("not in this chain" in text for text in _texts(js))

    def test_an_old_record_with_no_anchors_is_not_a_failure(self, queue):
        entries = _chain()
        report = shield_verify.verify_package(_package(entries))
        assert report["ok"] is True
        assert "anchor absent" in report["notes"]
        assert "no locked anchor for this head" not in " ".join(report["problems"])
        js = _js(_package(entries))
        assert not any(item.get("kind") == "locked" for item in js["findings"])
        assert "anchor absent" in js["notes"]

    def test_python_and_javascript_agree_on_a_locked_chain(self, queue):
        store = anchor_lock.MemoryLockStore()
        entries = _chain()
        locked = _lock(store, entries)
        package = _package(entries, locked)
        report = shield_verify.verify_package(package)
        js = _js(package)
        assert report["ok"] is True
        assert not any(item.get("kind") == "locked" for item in js["findings"])
        problems, notes = anchor_lock.assess_anchors(entries, locked)
        assert problems == []
        assert "anchor absent" not in notes
        again, again_notes = shield_verify._check_locked(entries, locked)
        assert again == problems
        assert again_notes == notes

    def test_a_phone_copy_that_disagrees_does_not_outrank_the_lock(self, queue):
        store = anchor_lock.MemoryLockStore()
        entries = _chain(count=1)
        locked = _lock(store, entries)
        phone = dict(locked[0])
        phone["token_b64"] = base64.b64encode(b"not-the-token").decode("ascii")
        report = shield_verify.verify_package(
            _package(entries, locked), anchors=[phone])
        assert report["ok"] is False
        assert any("phone copy does not match" in problem
                   for problem in report["problems"])
        js = _js(_package(entries, locked), [phone])
        assert any("phone copy does not match" in text for text in _texts(js))

    def test_backfill_locks_only_the_current_head(self, queue):
        store = anchor_lock.MemoryLockStore()
        entries = _chain()
        tip = entries[-1]["entry_hash"]
        recorded = datetime.fromisoformat(entries[-1]["recorded_at"])
        gen = (recorded + timedelta(minutes=5)).strftime("%Y%m%d%H%M%SZ")
        view = anchor_lock.backfill_record(
            JOB, entries, store=store, now=recorded + timedelta(minutes=5),
            timestamp=_stamp_for(tip, gen))
        assert view["status"] == "locked"
        assert view["seq"] == len(entries) - 1
        assert len(store.list("anchors/")) == 1
        again = anchor_lock.backfill_record(
            JOB, entries, store=store, now=T1, timestamp=_stamp_for(tip, gen))
        assert again["status"] == "already_locked"
        bodies, source = anchor_lock.export_anchors(store=store)
        assert source == "s3"
        assert [item["head_hash"] for item in bodies] == [tip]
        report = shield_verify.verify_package(_package(entries), anchors=bodies)
        assert report["ok"] is True, report["problems"]
        assert "anchor absent" not in report["notes"]

    def test_the_backfill_command_reads_a_file(self, queue, tmp_path, capsys):
        entries = _chain(count=1)
        path = tmp_path / "records.json"
        path.write_text(json.dumps([{"record_id": JOB, "entries": entries}]))
        assert anchor_lock.main(["backfill", str(path)]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out[0]["status"] == "disabled"
        assert out[0]["head_hash"] == entries[-1]["entry_hash"]

    def test_the_seal_judges_agree_when_an_anchor_does_not_match(self):
        path = os.path.join(os.path.dirname(__file__), "fixtures",
                            "sealed_digicert_package.json")
        package = json.loads(open(path).read())
        entries = package.get("custody_entries") or package.get("custody")
        head = entries[-1]["entry_hash"]
        package["locked_anchors"] = [{
            "version": 1,
            "record_id": package["record"]["id"],
            "seq": 0,
            "head_hash": "ab" * 32,
            "recorded_at": entries[0].get("recorded_at") or "2026-10-06T12:00:00+00:00",
            "anchored_at": "2026-10-06T12:05:00+00:00",
            "gen_time": "20261006120500Z",
            "timestamp_status": "present",
            "token_b64": _stamp_for("ab" * 32, "20261006120500Z")["token_b64"],
            "object_key": anchor_lock.object_key(package["record"]["id"], 0, "ab" * 32),
            "receipt": None,
        }]
        py = offline_seal.judge(package)
        js = _js(package, op="seal")
        assert py["label"] == "TAMPERED"
        assert js["label"] == "TAMPERED"
        assert "no locked anchor for this head" in py["detail"]
        assert "no locked anchor for this head" in js["detail"]
        assert js["notes"] == py["notes"]
        assert head != "ab" * 32
