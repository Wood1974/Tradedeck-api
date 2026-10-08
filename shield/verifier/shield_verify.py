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
  * For every photo, the sealed `uploaded` entry with that photo_id has a
    file_hash equal to the manifest hash and, where the file is supplied,
    equal to the SHA-256 of those bytes. The manifest hash is not sealed.
    Matching it alone is not a pass.
  * Where that sealed entry records a checkpoint number, the photo is filed
    under that checkpoint.

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
  * That the chain was not rewritten in full. A swap that also recomputes
    every link still verifies on its own. The same held head detects it.

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


def _job_id(manifest):
    """The id the genesis value was derived from.

    An evidence manifest names `job.shield_job_id`. The v2 API package names
    `record.id` and seals the chain under that id. Both are the same input.
    """
    job = manifest.get("job")
    if isinstance(job, dict) and job.get("shield_job_id"):
        return job.get("shield_job_id")
    record = manifest.get("record")
    if isinstance(record, dict) and record.get("id"):
        return record.get("id")
    return None


def _entries(manifest):
    """The custody rows, in chain order, from either package shape.

    Evidence exports put them in `custody_entries` and a summary object in
    `custody`. The API package puts the rows themselves in `custody`.
    """
    raw = manifest.get("custody_entries")
    if isinstance(raw, list):
        return raw
    custody = manifest.get("custody")
    if isinstance(custody, list):
        return custody
    return None


def _claimed(manifest):
    """The producer's own claims about the chain, from either package shape."""
    custody = manifest.get("custody")
    if isinstance(custody, dict):
        return custody
    claimed = {}
    if manifest.get("head_hash"):
        claimed["head_hash"] = manifest.get("head_hash")
    if "chain_intact" in manifest:
        claimed["chain_intact"] = manifest.get("chain_intact")
    return claimed


def _checkpoint_token(value):
    """A checkpoint number as a comparable string, or None when it is absent."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        if value == int(value):
            return str(int(value))
        return repr(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return text
        if number == int(number):
            return str(int(number))
        return text
    return str(value)


def _event_data(entry):
    data = entry.get("event_data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            return {}
    return data if isinstance(data, dict) else {}


def _sealed_point(entry):
    """Checkpoint number sealed on an upload, when the entry recorded one.

    v2 API uploads seal `event_data.point_number`. Legacy `/shield` uploads
    do not, and a missing number is not a disagreement — there is nothing
    to compare.
    """
    data = _event_data(entry)
    if "point_number" not in data:
        return None
    return _checkpoint_token(data.get("point_number"))


def _photo_claims(manifest):
    """Every photo the manifest asks a recipient to trust, in package order.

    Evidence exports list the live photo on `checkpoints[].sha256_original`
    and earlier attempts on `superseded_attempts`. API packages list the
    same bytes' hash as `photos[].original_hash` and name the checkpoint by
    id. The presence of `sha256_original` is what tells the two apart: an
    API checkpoint row does not have that key.
    """
    checkpoints = manifest.get("checkpoints") or []
    if not isinstance(checkpoints, list):
        checkpoints = []
    evidence_shape = any(isinstance(item, dict) and "sha256_original" in item
                         for item in checkpoints)
    claims = []
    if evidence_shape:
        for item in checkpoints:
            if not isinstance(item, dict):
                continue
            checkpoint = _checkpoint_token(item.get("checkpoint_number"))
            photo_id = item.get("photo_id")
            manifest_hash = item.get("sha256_original")
            if not photo_id and not manifest_hash:
                claims.append({"photo_id": None, "manifest_hash": None,
                               "checkpoint": checkpoint, "empty": True})
            else:
                claims.append({"photo_id": photo_id,
                               "manifest_hash": manifest_hash,
                               "checkpoint": checkpoint, "empty": False})
            for attempt in item.get("superseded_attempts") or []:
                if not isinstance(attempt, dict):
                    continue
                claims.append({
                    "photo_id": attempt.get("photo_id"),
                    "manifest_hash": attempt.get("sha256_original"),
                    "checkpoint": checkpoint,
                    "empty": False,
                })
        return claims

    by_id = {}
    for item in checkpoints:
        if isinstance(item, dict) and item.get("id") is not None:
            by_id[item.get("id")] = item
    photos = manifest.get("photos") or []
    if not isinstance(photos, list):
        return claims
    for photo in photos:
        if not isinstance(photo, dict):
            continue
        row = by_id.get(photo.get("checkpoint_id")) or {}
        claims.append({
            "photo_id": photo.get("id") if photo.get("id") is not None
            else photo.get("photo_id"),
            "manifest_hash": photo.get("original_hash"),
            "checkpoint": _checkpoint_token(row.get("point_number")),
            "empty": False,
        })
    return claims


def _verified_prefix(entries, chain):
    """Entries whose links actually verified.

    An uploaded entry at or after the break is not a seal. Its file_hash
    is exactly the field an editor would change, and the break is the
    evidence that the change did not recompute the chain.
    """
    if not entries or not chain:
        return []
    if chain.get("intact"):
        return list(entries)
    broke = chain.get("broken_at_index")
    if broke is None:
        return []
    return list(entries[:broke])


def _photo_label(photo_id):
    return photo_id if photo_id else "without an id"


def verify_files(manifest, file_bytes, entries=None, chain=None):
    """Bind every photo to the sealed upload record for that photo_id.

    `file_bytes` maps photo_id -> bytes. A file that was not supplied is
    reported as not supplied rather than as a failure — a recipient may
    hold only some files. The manifest hash is still checked against the
    sealed `file_hash` whether or not the bytes are here.

    A photo with no sealed `uploaded` entry is UNVERIFIED. That is weaker
    than a match and it is not an accusation: legacy rows predate the seal.
    A hash that disagrees with the seal, or a checkpoint the seal lets us
    check and that does not match, is a failure.

    Returns (results, problems, unverified, notes).
    """
    if entries is None:
        entries = _entries(manifest) or []
    prefix = _verified_prefix(entries, chain)
    supplied = file_bytes or {}
    results, problems, unverified, notes = [], [], [], []

    for claim in _photo_claims(manifest):
        photo_id = claim["photo_id"]
        checkpoint = claim["checkpoint"]
        if claim["empty"] or (not photo_id and not claim["manifest_hash"]):
            results.append({"checkpoint": checkpoint, "photo_id": photo_id,
                            "status": "no photo in package"})
            continue

        label = _photo_label(photo_id)
        wanted = str(photo_id) if photo_id is not None else None
        uploads = [e for e in prefix
                   if e.get("event_type") == "uploaded"
                   and e.get("photo_id") is not None
                   and str(e.get("photo_id")) == wanted]
        hashes = []
        for entry in uploads:
            digest = entry.get("file_hash")
            if digest not in hashes:
                hashes.append(digest)
        points = []
        for entry in uploads:
            point = _sealed_point(entry)
            if point is not None and point not in points:
                points.append(point)

        usable = [h for h in hashes if h]
        if not uploads or not usable:
            text = "photo %s has no sealed upload record" % label
            unverified.append(text)
            results.append({
                "checkpoint": checkpoint, "photo_id": photo_id,
                "status": "UNVERIFIED", "manifest_hash": claim["manifest_hash"],
                "sealed_hash": None, "sealed_checkpoint": None,
            })
            continue

        if len(hashes) != 1 or len(points) > 1:
            text = "photo %s has sealed upload records that disagree" % label
            problems.append(text)
            results.append({
                "checkpoint": checkpoint, "photo_id": photo_id,
                "status": "MISMATCH", "manifest_hash": claim["manifest_hash"],
                "sealed_hash": None, "sealed_checkpoint": None,
            })
            continue

        sealed = hashes[0]
        sealed_checkpoint = points[0] if points else None
        row_problems = []
        if claim["manifest_hash"] != sealed:
            row_problems.append(
                "photo %s manifest hash does not match the sealed upload record"
                % label)
        if (sealed_checkpoint is not None and checkpoint is not None
                and sealed_checkpoint != checkpoint):
            row_problems.append(
                "photo %s is filed under checkpoint %s but the sealed upload "
                "records checkpoint %s" % (label, checkpoint, sealed_checkpoint))
        elif sealed_checkpoint is None:
            notes.append(
                "photo %s has a sealed upload hash, but that entry does not "
                "seal a checkpoint number, so which checkpoint it belongs to "
                "was not checked" % label)

        actual = None
        has_file = photo_id in supplied or (
            wanted is not None and wanted in supplied)
        if has_file:
            blob = supplied[photo_id] if photo_id in supplied else supplied[wanted]
            actual = hashlib.sha256(blob).hexdigest()
            if actual != sealed:
                row_problems.append(
                    "photo %s does not match the sealed upload record" % label)

        problems.extend(row_problems)
        if row_problems:
            status = "MISMATCH"
        elif not has_file:
            status = "file not supplied"
        else:
            status = "match"
        results.append({
            "checkpoint": checkpoint, "photo_id": photo_id, "status": status,
            "expected": sealed, "actual": actual,
            "manifest_hash": claim["manifest_hash"], "sealed_hash": sealed,
            "sealed_checkpoint": sealed_checkpoint,
        })
    return results, problems, unverified, notes


def verify_package(manifest, file_bytes=None, expect_head=None):
    """Everything checkable from a manifest, plus any files supplied.

    `expect_head` is a head hash you were given EARLIER, from your own records
    — not the one inside this package. That distinction is the whole point: an
    operator who truncates the chain also updates the package's own claim, so
    comparing the package against itself catches nothing. Comparing it against
    a head you already held catches truncation and rewrite both.
    """
    problems = []
    notes = []
    job_id = _job_id(manifest)
    if not job_id:
        return {"ok": False, "verdict": "FAIL",
                "problems": ["manifest has no job.shield_job_id or record.id"],
                "unverified": [], "notes": [], "chain": None, "files": []}

    entries = _entries(manifest)
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

        claimed = _claimed(manifest)
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
    if chain and not expect_head:
        notes.append(
            "No expected head supplied. A chain truncated at the end verifies "
            "perfectly — pass --expect-head with the head hash you were given "
            "when the record was closed out.")

    files, photo_problems, unverified, photo_notes = verify_files(
        manifest, file_bytes or {}, entries, chain)
    problems.extend(photo_problems)
    notes.extend(photo_notes)

    if problems:
        verdict = "FAIL"
    elif unverified:
        verdict = "UNVERIFIED"
    else:
        verdict = "PASS"
    return {"ok": verdict == "PASS", "verdict": verdict, "problems": problems,
            "unverified": unverified, "notes": notes, "chain": chain,
            "files": files}


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

    job = manifest.get("job") if isinstance(manifest.get("job"), dict) else {}
    record = manifest.get("record") if isinstance(manifest.get("record"), dict) else {}
    print("Shield evidence package — independent verification")
    print("  job                %s" % (job.get("shield_job_id") or record.get("id")))
    print("  reference          %s" % (
        job.get("external_reference") or record.get("external_ref") or "—"))
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
    unverified_files = [f for f in report["files"] if f["status"] == "UNVERIFIED"]
    if supplied:
        matched = sum(1 for f in supplied if f["status"] == "match")
        print("  photos checked     %d of %d match the sealed upload record"
              % (matched, len(supplied)))
    elif unverified_files:
        print("  photos checked     %d unverified (no sealed upload record)"
              % len(unverified_files))
    else:
        print("  photos checked     none supplied (pass --files to check them)")

    print()
    if report["verdict"] == "PASS":
        print("PASS — everything checkable in this package checks out.")
    elif report["verdict"] == "UNVERIFIED":
        print("UNVERIFIED — the chain checks out, but one or more photos")
        print("cannot be tied to a sealed upload record. This is not a pass,")
        print("and it is not a finding that the photo was swapped.")
        for item in report["unverified"]:
            print("  - %s" % item)
    else:
        print("FAIL")
        for p in report["problems"]:
            print("  - %s" % p)
        for item in report.get("unverified") or []:
            print("  - unverified: %s" % item)
    for note in report.get("notes") or []:
        if note.startswith("photo "):
            print("  note: %s" % note)
    print()
    print("This establishes integrity, not truth. It does not show that a photo")
    print("came off a camera, that the assessments are correct, or that the work")
    print("complies with any code. A package can verify perfectly and still")
    print("describe work that was never done.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
