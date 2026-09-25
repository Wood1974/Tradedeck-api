#!/usr/bin/env python3
"""Independent verifier for a TradeDeck Shield evidence package.

Standard library only. No network. No Shield code. Copy this one file
anywhere and run it against a package you were given:

    python shield_verify.py manifest.json
    python shield_verify.py manifest.json --files ./photos

Why this file exists
--------------------
Shield's export claims a recipient can check it "without trusting us". That
claim is worth nothing if checking it requires running Shield's own code
against Shield's own database — you would only be asking the accused to
re-examine themselves.

So this is a *reimplementation from the published specification* (SPEC.md),
not an import of the production module. It shares no code with the service
that produced the package. When the two agree, that agreement means something:
two independent implementations of a written spec reached the same hash. If
Shield's `ledger.py` ever develops a bug, this file does not inherit it.

A test in Shield's own suite runs both against the same generated data and
asserts they agree, so the divergence gets caught by us before it gets found
by an opposing expert.

What it establishes
-------------------
  * Each custody entry hashes to the value it stores, given its predecessor.
  * The chain runs unbroken from a genesis value derived from the job id.
  * The head hash you were handed matches the head this chain computes.
  * Where photo files are supplied, their SHA-256 matches the manifest.

What it cannot establish
------------------------
  * That any photo came off a camera sensor rather than a file picker.
  * That the AI verdicts are correct.
  * That the work complies with any building code.
  * That no entry was *deleted before the chain was ever written* — the chain
    proves nothing was altered after the fact, not that everything that
    happened was recorded.
  * That the chain has not been TRUNCATED. Dropping entries from the end
    leaves a shorter chain in which every remaining link still verifies.
    Only a head hash you were given earlier detects it — pass --expect-head.

A package can verify perfectly and still describe work that was never done.
This tool checks integrity, not truth.
"""
import argparse
import hashlib
import json
import os
import sys

SPEC_VERSION = 2
GENESIS_PREFIX = "shield-custody-genesis-v1:"

# Fixed order. The hash covers these fields and nothing else — see SPEC.md.
SIGNED_FIELDS = (
    "shield_job_id",
    "photo_id",
    "event_type",
    "actor_id",
    "actor_type",
    "event_data",
    "gps_lat",
    "gps_lng",
    "file_hash",
    "integrity_note",
    "recorded_at",
)

# NOT signed since v2 (AR-11): exif_captured_at. The uploader writes EXIF
# DateTimeOriginal, so sealing it proved only that we had not changed it since
# recording -- which reads as though the capture time were established. It is
# still in the record; the chain simply does not vouch for it.


# --------------------------------------------------------------- hashing ---
def _finite(value, key):
    """repr() a float, refusing NaN and Infinity rather than sealing them."""
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite value for %r" % key)
    return repr(value)


def genesis_hash(shield_job_id):
    """The value the first entry's prev_hash must equal."""
    return hashlib.sha256((GENESIS_PREFIX + str(shield_job_id)).encode()).hexdigest()


def canonical(entry):
    """Deterministic bytes for one entry's signed fields.

    Per SPEC.md: signed fields only, absent and null are identical, floats via
    repr(), nested structures as compact sorted JSON, then the whole thing as
    compact sorted JSON. Non-finite numbers are refused rather than rendered.
    """
    out = {}
    for key in SIGNED_FIELDS:
        value = entry.get(key)
        if value is None:
            continue
        if isinstance(value, float):
            value = _finite(value, key)
        elif isinstance(value, (dict, list)):
            # Not normalised: normalisation is a write-time step in the
            # ledger, because only the writer knows whether 100 was an int or
            # a float. A verifier hashes the row exactly as the package
            # carries it.
            value = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               default=str, allow_nan=False)
        out[key] = value
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      default=str, allow_nan=False).encode()


def link(entry, prev_hash):
    """SHA-256 over canonical(entry) || "|" || prev_hash."""
    return hashlib.sha256(canonical(entry) + b"|" + prev_hash.encode()).hexdigest()


# ------------------------------------------------------------ the checks ---
def verify_chain(entries, shield_job_id):
    """Walk the chain oldest-first. Reports where it breaks, not just that."""
    expected_prev = genesis_hash(shield_job_id)
    for index, entry in enumerate(entries):
        stored_prev = entry.get("prev_hash")
        stored_hash = entry.get("entry_hash")
        if stored_hash is None:
            return _break(index, entries, expected_prev, "entry carries no hash")
        if stored_prev != expected_prev:
            return _break(index, entries, expected_prev,
                          "link mismatch — an entry was inserted, removed or "
                          "reordered here")
        if link(entry, stored_prev) != stored_hash:
            return _break(index, entries, expected_prev,
                          "content altered — a signed field was edited after "
                          "the entry was written")
        expected_prev = stored_hash
    return {"intact": True, "entries": len(entries), "verified": len(entries),
            "broken_at_index": None, "reason": None, "head_hash": expected_prev}


def _break(index, entries, head, reason):
    return {"intact": False, "entries": len(entries), "verified": index,
            "broken_at_index": index, "reason": reason, "head_hash": head}


def verify_files(manifest, file_bytes):
    """Match supplied bytes against the manifest's hashes.

    `file_bytes` maps photo_id -> bytes. Anything absent is reported as not
    supplied rather than as a failure — a recipient may hold only some files.
    """
    results = []
    for item in manifest.get("checkpoints", []):
        photo_id, expected = item.get("photo_id"), item.get("sha256_original")
        if not photo_id or not expected:
            results.append({"checkpoint": item.get("checkpoint_number"),
                            "photo_id": photo_id, "status": "no photo in package"})
            continue
        if photo_id not in file_bytes:
            results.append({"checkpoint": item.get("checkpoint_number"),
                            "photo_id": photo_id, "status": "file not supplied"})
            continue
        actual = hashlib.sha256(file_bytes[photo_id]).hexdigest()
        results.append({
            "checkpoint": item.get("checkpoint_number"),
            "photo_id": photo_id,
            "status": "match" if actual == expected else "MISMATCH",
            "expected": expected, "actual": actual,
        })
    return results


def verify_package(manifest, file_bytes=None, expect_head=None):
    """Everything checkable from a manifest, plus any files supplied.

    `expect_head` is a head hash you were given EARLIER, from your own records
    — not the one inside this package. That distinction is the whole point: an
    operator who truncates the chain also updates the package's own claim, so
    comparing the package against itself catches nothing. Comparing it against
    a head you already held catches truncation and rewrite both.
    """
    problems = []
    job_id = (manifest.get("job") or {}).get("shield_job_id")
    if not job_id:
        return {"ok": False, "problems": ["manifest has no job.shield_job_id"],
                "chain": None, "files": []}

    entries = manifest.get("custody_entries")
    if entries is None:
        problems.append(
            "package carries no custody_entries — the chain cannot be "
            "recomputed, so its integrity is this vendor's assertion rather "
            "than something you verified")
        chain = None
    else:
        chain = verify_chain(entries, job_id)
        if not chain["intact"]:
            problems.append("custody chain breaks at entry %d of %d: %s" % (
                chain["broken_at_index"] + 1, chain["entries"], chain["reason"]))

        claimed = manifest.get("custody") or {}
        if claimed.get("head_hash") and claimed["head_hash"] != chain["head_hash"]:
            problems.append(
                "head hash disagreement — the package states %s… but its own "
                "entries compute to %s…" % (str(claimed["head_hash"])[:16],
                                            chain["head_hash"][:16]))
        if claimed.get("chain_intact") is True and not chain["intact"]:
            problems.append(
                "the package asserts chain_intact: true and it is not")
        if claimed.get("entries") is not None and \
                claimed["entries"] != chain["entries"]:
            problems.append(
                "entry count disagreement — package states %s, carries %d"
                % (claimed["entries"], chain["entries"]))

    if expect_head and chain:
        if chain["head_hash"] != expect_head:
            problems.append(
                "head does not match the one you were given — you hold %s… and "
                "this package computes %s…. Entries have been removed from the "
                "end, or the history was rewritten. Both verify perfectly on "
                "their own; only your copy of the head detects this."
                % (str(expect_head)[:16], chain["head_hash"][:16]))
    notes = []
    if chain and not expect_head:
        notes.append(
            "No expected head supplied. A chain truncated at the end verifies "
            "perfectly — pass --expect-head with the head hash you were given "
            "when the record was closed out.")

    files = verify_files(manifest, file_bytes or {})
    for f in files:
        if f["status"] == "MISMATCH":
            problems.append("photo %s does not match its recorded hash"
                            % f["photo_id"])

    return {"ok": not problems, "problems": problems, "notes": notes,
            "chain": chain, "files": files}


# ------------------------------------------------------------------ cli ----
def _load_files(directory):
    """photo_id -> bytes, taking the photo id from the filename stem."""
    out = {}
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                out[os.path.splitext(name)[0]] = fh.read()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify a TradeDeck Shield evidence package. "
                    "Standard library only; nothing is sent anywhere.")
    ap.add_argument("manifest", help="path to the manifest JSON")
    ap.add_argument("--files", help="directory of photos named <photo_id>.<ext>")
    ap.add_argument("--expect-head", dest="expect_head",
                    help="the head hash you were given earlier, from your own "
                         "records — this is what detects truncation")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    with open(args.manifest) as fh:
        manifest = json.load(fh)
    report = verify_package(manifest,
                            _load_files(args.files) if args.files else None,
                            expect_head=args.expect_head)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    job = manifest.get("job") or {}
    print("Shield evidence package — independent verification")
    print("  job                %s" % job.get("shield_job_id"))
    print("  reference          %s" % (job.get("external_reference") or "—"))
    if report["chain"]:
        c = report["chain"]
        print("  custody chain      %s (%d/%d entries)"
              % ("INTACT" if c["intact"] else "BROKEN", c["verified"], c["entries"]))
        print("  head hash          %s" % c["head_hash"])
        if args.expect_head:
            print("  vs the head you hold %s"
                  % ("MATCHES" if c["head_hash"] == args.expect_head else "DIFFERS"))
        else:
            print("  (no --expect-head given: a chain truncated at the end")
            print("   verifies perfectly. Your own copy of the head detects that.)")
    else:
        print("  custody chain      NOT VERIFIABLE — no entries in package")
    supplied = [f for f in report["files"] if f["status"] in ("match", "MISMATCH")]
    if supplied:
        matched = sum(1 for f in supplied if f["status"] == "match")
        print("  photos checked     %d of %d match" % (matched, len(supplied)))
    else:
        print("  photos checked     none supplied (pass --files to check them)")

    print()
    if report["ok"]:
        print("PASS — everything checkable in this package checks out.")
    else:
        print("FAIL")
        for p in report["problems"]:
            print("  - %s" % p)
    print()
    print("This establishes integrity, not truth. It does not show that a photo")
    print("came off a camera, that the assessments are correct, or that the work")
    print("complies with any code. A package can verify perfectly and still")
    print("describe work that was never done.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
