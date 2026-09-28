"""Hash-chained custody ledger.

The problem with the append-only trigger
----------------------------------------
The migration puts a BEFORE UPDATE OR DELETE trigger on shield_custody_log, so
the database refuses to rewrite history. That stops an application bug. It does
not stop anyone who can reach the database as an owner: `DROP TRIGGER`, edit,
recreate. It does not stop a leaked service-role key. And it leaves no trace —
afterwards the table looks exactly as it always did.

For an evidence product that is the wrong threat model. The question a lawyer,
an adjuster, or an opposing expert will ask is not "could the operator have
edited this?" — the operator always can. It is **"can you prove they didn't?"**

What this does
--------------
Each entry carries the hash of the entry before it:

    entry_hash = SHA-256( canonical(entry fields) || prev_hash )

Changing any historical field changes its hash, which breaks every hash after
it. To forge one entry convincingly you must recompute the entire tail of the
chain — and if any later head hash has left the building (returned to a
homeowner in a close-out packet, emailed to an adjuster, timestamped by a TSA,
written to a customer's own system), the forgery is detectable by anyone
holding that copy. The operator can still destroy the chain; they cannot
silently alter it.

That is a meaningfully different claim, and it is one that survives the
operator being the adversary — which is the claim an evidence product has to
be able to make about itself.

Design notes
------------
* One chain per Shield job, not one global chain. A job's packet is then
  independently verifiable by whoever received it, without exposing anything
  about other customers' jobs.
* `canonical()` must be byte-stable forever. Sorted keys, tight separators,
  no NaN, explicit None handling. A serialization change silently invalidates
  every chain ever written, so the format is versioned and pinned by tests.
* Verification reports *where* the chain broke, not just that it did. "Entry 7
  of 12 fails" is actionable; "invalid" is not.
"""
import hashlib
import json
from datetime import datetime, timezone

# Bump only with a migration that re-chains existing rows. Pinned by a test.
#
# 2 (2026-09-25) closed two defects that both needed the canonical form to
# change, so both had to wait for a bump. It was done while shield_custody_log
# was still empty -- no chain had ever been written, because the live table had
# neither prev_hash nor entry_hash -- so the re-chain SPEC.md section 8 requires
# had nothing to re-chain. The same change after the first real record would
# have invalidated it.
#
#   AR-12  nested floats now render through repr(), so a package carries its
#          own types and a verifier in any language can reproduce the hash.
#   AR-11  exif_captured_at left SIGNED_FIELDS; the subject writes it.
CHAIN_VERSION = 2

# Genesis link for a job's first entry. Distinct per job so two jobs can never
# share a prefix, and derived rather than constant so it is self-describing.
GENESIS_PREFIX = "shield-custody-genesis-v1:"

# The fields that are covered by the hash. Anything outside this set is
# metadata the chain does not vouch for — keep it explicit rather than hashing
# "whatever the row happens to contain", which would make the chain depend on
# schema drift.
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

# Deliberately NOT signed, since chain_version 2: `exif_captured_at`.
#
# It is read from EXIF DateTimeOriginal, which the uploader writes. Sealing it
# proved one thing -- that it had not changed since we recorded it -- and read,
# to anyone who had not read the spec, as though the capture time itself were
# established. That is the gap AR-11 named, and it is not theoretical:
# corroborate.py computes solar azimuth from (lat, lng, captured_at), so an
# attacker holding a photograph could declare the capture time whose sun
# position matches the shadows already in it. The astronomy would be exact and
# the input adversarial.
#
# It still travels in the record. The chain simply no longer vouches for it,
# which is the honest position for a value the subject supplies.
# `recorded_at` and the upload's `received_at` are server-side and stay signed;
# they prove "not after", never "not before", and the export says so.


def _finite(value, key):
    """repr() a float, refusing the two that are not numbers.

    repr() would turn NaN and Infinity into the strings 'nan' and 'inf' and
    seal them as if they were real values, sailing past allow_nan. A non-finite
    number in an evidence record is corrupt input, not something to
    canonicalise.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(
            f"non-finite value for {key!r} cannot be sealed into the "
            f"custody chain")
    return repr(value)


def normalize_event_data(value, _key="event_data"):
    """Render every nested float as its repr(), recursively. AR-12.

    Why this is not cosmetic
    ------------------------
    `json.dumps` renders the float 100.0 as `100.0` and the int 100 as `100`.
    Those hash differently. But a package travels as JSON, and after the round
    trip both are the token `100` -- so a verifier in any language but Python
    could not tell which one had been sealed, and the spec's central promise
    ("implement it in any language") did not hold.

    The entry it hit hardest was the one that matters most: close-out seals
    `score` and `coverage_pct`, both from round(), both whole whenever a job
    scores 100 or 0. The close-out of a clean record was exactly the entry a
    browser, Go or Rust verifier could not confirm.

    Unlike gps_lat, it could not be closed by declaring which fields are
    floats, because event_data is free-form and written at many call sites.
    So the value itself carries the answer: after this, a float is the string
    "100.0" in the stored row and in the package, and an int is the number 100.
    No reader has to guess, and no reader has to reimplement CPython's float
    repr to check a whole number.

    `seal()` applies this before hashing, so the row and the hash agree.
    Normalising only inside canonical() would have fixed nothing -- the
    recipient reads event_data out of the package, not out of our process.

    Idempotent: a string stays a string, so re-normalising a stored row is
    safe.
    """
    if isinstance(value, bool):
        return value          # bool is an int subclass; leave it alone
    if isinstance(value, float):
        return _finite(value, _key)
    if isinstance(value, dict):
        return {k: normalize_event_data(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_event_data(v, _key) for v in value]
    return value


def genesis_hash(shield_job_id: str) -> str:
    return hashlib.sha256((GENESIS_PREFIX + str(shield_job_id)).encode()).hexdigest()


def canonical(entry: dict) -> bytes:
    """Deterministic bytes for the signed subset of an entry.

    Stability rules, all load-bearing:
      * only SIGNED_FIELDS, always in a fixed order (not dict order)
      * sorted keys and tight separators inside nested structures
      * floats rendered via repr() so 40.1 never becomes 40.10000000000001
        on one machine and 40.1 on another
      * missing and null are the same thing, so an added-then-nulled column
        does not change a historical hash
    """
    out = {}
    for key in SIGNED_FIELDS:
        value = entry.get(key)
        if value is None:
            continue
        if isinstance(value, float):
            value = _finite(value, key)
        elif isinstance(value, datetime):
            value = value.astimezone(timezone.utc).isoformat()
        elif isinstance(value, (dict, list)):
            # Deliberately NOT normalised here. canonical() is a function of
            # the row as stored, and normalisation is a write-time step in
            # seal() -- because only the writer knows whether 100 was an int
            # or a float. JavaScript cannot tell, which is the defect AR-12
            # names. If this normalised, Python would hash raw and normalised
            # input alike while the browser could only hash what the package
            # gave it, and the two implementations would quietly disagree on
            # anything that had not been through seal(). The differential test
            # caught precisely that.
            value = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               default=str, allow_nan=False)
        out[key] = value
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      default=str, allow_nan=False).encode()


def link(entry: dict, prev_hash: str) -> str:
    """Hash of one entry given its predecessor."""
    return hashlib.sha256(canonical(entry) + b"|" + prev_hash.encode()).hexdigest()


def seal(entry: dict, prev_hash: str) -> dict:
    """Return the entry with its chain fields populated, ready to insert.

    `event_data` comes back normalised (AR-12), because the row that is stored
    has to be the row that was hashed. If we hashed "100.0" and stored 100.0,
    the recipient -- who only ever sees the stored value -- would be back to
    guessing which one we meant.
    """
    sealed = dict(entry)
    if isinstance(sealed.get("event_data"), (dict, list)):
        sealed["event_data"] = normalize_event_data(sealed["event_data"])
    return {**sealed,
            "chain_version": CHAIN_VERSION,
            "prev_hash": prev_hash,
            "entry_hash": link(sealed, prev_hash)}


def verify_chain(entries: list, shield_job_id: str) -> dict:
    """Walk a job's custody entries oldest-first and check every link.

    `entries` must be ordered by recorded_at ascending — the same order the
    ledger was written in. Returns a verdict naming the first break, so a
    reviewer can point at the row rather than at the whole table.
    """
    expected_prev = genesis_hash(shield_job_id)
    broken_at = None
    reason = None

    for index, entry in enumerate(entries):
        stored_prev = entry.get("prev_hash")
        stored_hash = entry.get("entry_hash")

        if stored_hash is None:
            broken_at, reason = index, "entry carries no hash (written before chaining, or stripped)"
            break
        if stored_prev != expected_prev:
            broken_at, reason = index, (
                f"link mismatch: entry names predecessor {str(stored_prev)[:12]}… "
                f"but the previous entry hashes to {expected_prev[:12]}… — an "
                f"entry was inserted, removed, or reordered here")
            break
        recomputed = link(entry, stored_prev)
        if recomputed != stored_hash:
            broken_at, reason = index, (
                f"content altered: entry hashes to {recomputed[:12]}… but stores "
                f"{str(stored_hash)[:12]}… — a signed field was edited after writing")
            break
        expected_prev = stored_hash

    intact = broken_at is None
    return {
        "intact": intact,
        "entries": len(entries),
        "verified": len(entries) if intact else broken_at,
        "broken_at_index": broken_at,
        "reason": reason,
        "head_hash": expected_prev,
        "chain_version": CHAIN_VERSION,
        "summary": (
            f"All {len(entries)} custody entries verify against the chain."
            if intact else
            f"Chain breaks at entry {broken_at + 1} of {len(entries)}: {reason}"),
    }


def head_of(entries: list, shield_job_id: str) -> str:
    """Current head hash — the single value that commits to the whole history.

    This is what belongs in a close-out packet, an emailed report, or an RFC
    3161 timestamp. Anyone holding an old head can later prove the history they
    were shown has not been rewritten.
    """
    if not entries:
        return genesis_hash(shield_job_id)
    return entries[-1].get("entry_hash") or genesis_hash(shield_job_id)
