"""The browser verifier must agree with the chain writer, byte for byte.

Why this is differential rather than example-based
--------------------------------------------------
`webapp/verify.js` is a third implementation of `SPEC.md`, after `ledger.py`
(which writes chains) and `verifier/shield_verify.py` (which checks them). Two
of those already have a differential fuzz target, for a reason stated in the
fuzzer: a divergence would mean every package we ever issued verifies against
exactly one of our implementations.

The browser one raises the stakes, because JavaScript and Python genuinely
disagree about how to render the same value:

    Python repr(40.0)   -> '40.0'        JS String(40.0)   -> '40'
    Python repr(1e16)   -> '1e+16'       JS String(1e16)   -> '10000000000000000'
    Python repr(1e-05)  -> '1e-05'       JS String(1e-5)   -> '0.00001'
    Python json.dumps('é') -> '"\\u00e9"'  JS JSON.stringify -> '"é"'

None of those differences throw. They produce a different canonical form, so a
different hash, so a verdict of BROKEN on a package that is perfectly intact —
this product accusing an honest contractor of tampering because of a
floating-point formatting rule. That is the same failure `rebroadcast-never-accuses`
guards against on the optics side, arriving through the encoder instead.

Hand-picked examples would not have caught it. GPS coordinates like 40.76056
round-trip identically in both languages, so the realistic payload passes while
an integral latitude fails. These tests sweep the awkward values on purpose.

Skipped, not failed, when node is unavailable — CI has it; a contributor's
laptop might not, and a test that cannot run is worse than one that says why.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ledger  # noqa: E402

HARNESS = os.path.join(os.path.dirname(__file__), "..", "webapp", "tests",
                       "harness.mjs")

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is not installed")


def js(**request):
    """Run one request through verify.js and return the parsed response."""
    proc = subprocess.run(
        ["node", HARNESS], input=json.dumps(request), capture_output=True,
        text=True, timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(f"harness failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


# Values chosen because each one is a place the two languages part company,
# plus the coordinates that actually appear in this system.
AWKWARD_FLOATS = [
    40.76056, -111.89083,          # Salt Lake City, the realistic payload
    40.0, -111.0, 0.5, -0.5,       # integral and half values: '40' vs '40.0'
    1e15, 1e16, 1e17, 1e21,        # decimal/exponential switch differs
    1e-4, 1e-5, 1e-7, 1e-300,      # small-end switch and exponent padding
    0.1, 0.2, 0.3, 1 / 3,          # classic binary-representation values
    2.5e-10, 1.7976931348623157e308,
    123456789.123456789, 5e-324,   # smallest subnormal
    -0.0,
]


class TestFloatRendering:
    def test_matches_python_repr_exactly(self):
        got = js(op="repr", values=AWKWARD_FLOATS)
        for value, result in zip(AWKWARD_FLOATS, got):
            assert result["ok"], f"pyRepr threw on {value!r}"
            assert result["value"] == repr(value), (
                f"{value!r}: JavaScript rendered {result['value']!r}, "
                f"Python renders {repr(value)!r} — every chain carrying this "
                f"value would verify in one implementation and not the other"
            )

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_non_finite_refused_on_both_sides(self, bad):
        """ledger.py raises rather than sealing 'nan' as a coordinate.

        A verifier that quietly accepted one would disagree with every chain
        the service is capable of writing, in the direction that matters least
        obviously: it would pass something the writer would have refused.

        The value is sent as a marker string rather than a JSON literal — the
        harness speaks strict JSON, in which NaN and Infinity do not exist.
        That is itself worth knowing: a non-finite value cannot survive the
        transport a package travels over, so the only way one reaches a browser
        verifier is as the bare word NaN in a hand-edited file, which
        `JSON.parse` rejects before this code is reached.
        """
        value = float(bad)
        got = js(op="repr", values=[f"__nonfinite__{bad}"])[0]
        assert got["ok"] is False, f"pyRepr accepted {bad}"

        with pytest.raises(ValueError):
            ledger.canonical({"shield_job_id": "j", "gps_lat": value})


class TestJsonEncoding:
    CASES = [
        {"b": 1, "a": 2},                       # key order
        {"z": {"n": [1, 2, {"k": "v"}]}},       # nesting
        {"t": "café"},                          # ensure_ascii
        {"t": "日本語"},
        {"t": "emoji 🧱 here"},                  # astral plane, surrogate pair
        {"t": "quote\" back\\ slash"},
        {"t": "tab\there\nnewline"},
        {"t": ""},                  # control characters
        {"t": ""},
        {"list": [], "obj": {}},
        {"mixed": [1, "two", None, True, False]},
        {"é": "accented key"},                  # non-ASCII key, and sorting
        {"a": 1, "A": 2, "_": 3, "0": 4},       # code-point ordering
    ]

    @pytest.mark.parametrize("case", CASES)
    def test_matches_python_json_dumps(self, case):
        got = js(op="json", values=[case])[0]
        assert got["ok"], f"pyJson threw on {case!r}"
        expected = json.dumps(case, sort_keys=True, separators=(",", ":"))
        assert got["value"] == expected


def entry(**over):
    base = {
        "shield_job_id": "job-abc", "photo_id": "photo-1",
        "event_type": "uploaded", "actor_id": "user-1",
        "actor_type": "contractor",
        "event_data": {"note": "footing form", "n": 3},
        "gps_lat": 40.76056, "gps_lng": -111.89083,
        "file_hash": "a" * 64, "integrity_note": None,
        "exif_captured_at": "2026-09-14T10:30:00+00:00",
        "recorded_at": "2026-09-14T10:31:00+00:00",
    }
    base.update(over)
    return base


class TestCanonicalFormAgrees:
    ENTRIES = [
        entry(),
        entry(integrity_note="3,412 km outside the geofence"),
        entry(gps_lat=40.0, gps_lng=-111.0),          # integral coordinates
        entry(gps_lat=None, gps_lng=None),            # omitted, not nulled
        entry(event_data={}),
        entry(event_data={"z": "s", "a": {"nested": [1.5, 2.25]}}),
        entry(actor_type="homeowner", event_type="completed", photo_id=None),
        entry(event_data={"summary": "poured — 4\" slab, café site"}),
        entry(recorded_at="2026-09-14T10:31:00.123456+00:00"),
    ]

    def test_every_entry_canonicalises_identically(self):
        got = js(op="canonical", entries=self.ENTRIES)
        for row, result in zip(self.ENTRIES, got):
            assert result["ok"], f"canonical threw: {result}"
            expected = ledger.canonical(row).hex()
            assert result["value"] == expected, (
                f"canonical form diverged for {row.get('event_type')} / "
                f"{row.get('gps_lat')!r}"
            )

    def test_genesis_agrees(self):
        assert js(op="genesis", shield_job_id="job-abc") == \
            ledger.genesis_hash("job-abc")

    def test_link_agrees(self):
        prev = ledger.genesis_hash("job-abc")
        assert js(op="link", entry=entry(), prev_hash=prev) == \
            ledger.link(entry(), prev)


def build_chain(job_id="job-abc", n=6):
    """A real chain, sealed by the implementation that writes production ones."""
    entries, prev = [], ledger.genesis_hash(job_id)
    for i in range(n):
        row = entry(
            shield_job_id=job_id,
            photo_id=f"photo-{i}",
            event_type=["created", "uploaded", "analyzed"][i % 3],
            gps_lat=40.0 if i == 2 else 40.76056 + i / 1000,
            recorded_at=f"2026-09-14T10:{30 + i:02d}:00+00:00",
        )
        sealed = ledger.seal(row, prev)
        entries.append(sealed)
        prev = sealed["entry_hash"]
    return entries, prev


class TestChainVerification:
    def test_an_intact_chain_verifies_and_heads_agree(self):
        entries, head = build_chain()
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is True
        assert got["headHash"] == head

    def test_verifying_without_an_expected_head_says_so(self):
        """SPEC.md §6 — truncation is undetectable from inside the package."""
        entries, _ = build_chain()
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["truncationChecked"] is False
        assert "deleted from the end" in got["reason"]

    def test_expected_head_confirms_when_it_matches(self):
        entries, head = build_chain()
        got = js(op="verify", entries=entries, shield_job_id="job-abc",
                 expect_head=head)
        assert got["intact"] is True
        assert got["headMatchesExpected"] is True

    def test_truncation_is_caught_only_by_the_expected_head(self):
        """The attack the fuzzer found, checked from the browser side.

        Deleting from the end leaves a shorter chain in which every link still
        verifies, so `intact` is true and must be — the chain really is
        internally consistent. Only the head a recipient already held detects
        it, which is the whole argument for handing one over.
        """
        entries, head = build_chain()
        truncated = entries[:-2]

        blind = js(op="verify", entries=truncated, shield_job_id="job-abc")
        assert blind["intact"] is True

        with_head = js(op="verify", entries=truncated,
                       shield_job_id="job-abc", expect_head=head)
        assert with_head["headMatchesExpected"] is False

    def test_an_edited_field_is_caught_at_its_own_index(self):
        entries, _ = build_chain()
        entries[3]["gps_lat"] = 41.0
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 3
        assert "edited after" in got["reason"]

    def test_a_removed_entry_is_caught(self):
        entries, _ = build_chain()
        del entries[2]
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 2

    def test_a_reordered_chain_is_caught(self):
        entries, _ = build_chain()
        entries[1]["recorded_at"], entries[2]["recorded_at"] = \
            entries[2]["recorded_at"], entries[1]["recorded_at"]
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False

    def test_a_stripped_entry_hash_is_caught(self):
        entries, _ = build_chain()
        entries[4].pop("entry_hash")
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 4
        assert "never" in got["reason"] or "stripped" in got["reason"]

    def test_a_chain_from_another_job_does_not_verify(self):
        """Genesis is per-job, so a package cannot borrow another's chain."""
        entries, _ = build_chain(job_id="job-abc")
        got = js(op="verify", entries=entries, shield_job_id="job-xyz")
        assert got["intact"] is False
        assert got["brokeAt"] == 0

    def test_an_empty_chain_is_not_reported_as_verified(self):
        got = js(op="verify", entries=[], shield_job_id="job-abc")
        assert got["intact"] is False
        assert "nothing to verify" in got["reason"]


class TestTheJsonFloatAmbiguity:
    """The defect AR-12 named, and what chain_version 2 did about it.

    In v1, Python sealed `{"score": 100.0}` differently from `{"score": 100}`,
    and by the time a package reached a browser both read as the token `100`.
    That hit the close-out entry of every passing job — `complete_job` seals
    `score` and `coverage_pct`, both from `round()`, both very often integral —
    so the browser could not check the single most important entry in a clean
    record.

    v2 renders nested floats through repr() at seal time, so the stored row and
    the package both carry `"100.0"` and any language reproduces the hash. The
    first test below is that fix working.

    The old behaviour still matters for a v1 package, and the rule there is
    unchanged: do not call it tampering. That is an accusation against an
    honest contractor caused by a trailing zero, and to a reader it is
    indistinguishable from the real finding.
    """

    def test_a_clean_close_out_now_verifies_in_the_browser(self):
        """The whole point of chain_version 2.

        Same entry that was unverifiable in v1 — a close-out scoring 100 —
        now verifies in the browser with no caveat, because seal() stored the
        float as "100.0" and the package carries its own type.
        """
        entries, _ = build_chain(n=2)
        sealed = ledger.seal(
            entry(event_data={"verdict": "pass", "score": 100.0,
                              "coverage_pct": 100.0},
                  event_type="completed", photo_id=None,
                  recorded_at="2026-09-14T11:00:00+00:00"),
            entries[-1]["entry_hash"])
        assert sealed["event_data"]["score"] == "100.0"
        entries.append(sealed)

        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is True, got.get("reason")
        assert not got.get("ambiguous")

    def test_a_version_one_entry_is_still_ambiguous_not_tampered(self):
        """A v1 package must not be accused by a v2 verifier.

        No v1 chain was ever written — the live table had neither prev_hash
        nor entry_hash when the bump happened — so this guards a case that
        should never arrive. It is here because the alternative, if one ever
        did, is telling a contractor their record was altered when it was our
        format that could not be read.
        """
        entries, _ = build_chain(n=2)
        raw = entry(event_data={"verdict": "pass", "score": 100.0,
                                "coverage_pct": 100.0},
                    event_type="completed", photo_id=None,
                    recorded_at="2026-09-14T11:00:00+00:00")
        # Sealed the v1 way: event_data left as Python wrote it.
        v1 = {**raw, "chain_version": 1,
              "prev_hash": entries[-1]["entry_hash"],
              "entry_hash": ledger.link(raw, entries[-1]["entry_hash"])}
        entries.append(v1)

        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 2
        assert got["ambiguous"] is True, (
            "an integral float in a v1 entry was reported as tampering — the "
            "verifier is accusing someone because of a trailing zero"
        )
        assert "not evidence that anything was altered" in got["reason"]
        assert "Python verifier" in got["reason"]

    def test_a_version_two_mismatch_is_never_excused_as_ambiguity(self):
        """The escape hatch must not survive into the version that fixed it.

        A v2 entry carries its own types, so there is nothing left to be
        ambiguous about. If the hatch still applied, an attacker could edit a
        v2 entry containing any whole number and have the verifier print
        "not evidence that anything was altered" over the top of it.
        """
        entries, _ = build_chain(n=2)
        sealed = ledger.seal(
            entry(event_data={"verdict": "pass", "score": 100.0},
                  event_type="completed", photo_id=None,
                  recorded_at="2026-09-14T11:00:00+00:00"),
            entries[-1]["entry_hash"])
        entries.append(sealed)
        entries[2]["event_data"] = {"verdict": "pass", "score": "40.0"}

        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 2
        assert not got.get("ambiguous"), (
            "a v2 entry was edited and the verifier excused it as the JSON "
            "float ambiguity — v2 exists precisely so that cannot happen")

    def test_real_tampering_is_still_called_tampering(self):
        """The escape hatch must not swallow the finding it sits next to."""
        entries, _ = build_chain(n=3)
        entries[1]["actor_type"] = "homeowner"
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is False
        assert got["brokeAt"] == 1
        assert got["ambiguous"] is False
        assert "edited after" in got["reason"]

    def test_non_integral_floats_in_event_data_verify_normally(self):
        """The ambiguity is only about whole numbers; 1.5 is unambiguous."""
        entries, head = build_chain(n=2)
        sealed = ledger.seal(
            entry(event_data={"score": 87.5, "note": "partial"},
                  recorded_at="2026-09-14T11:00:00+00:00"),
            entries[-1]["entry_hash"])
        entries.append(sealed)
        got = js(op="verify", entries=entries, shield_job_id="job-abc")
        assert got["intact"] is True
