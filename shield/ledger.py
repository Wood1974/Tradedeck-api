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
CHAIN_VERSION = 1

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
    "exif_captured_at",
    "recorded_at",
)


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
            # repr() would turn NaN/Infinity into the strings 'nan'/'inf' and
            # seal them as if they were real coordinates, sailing past
            # allow_nan. A non-finite value in an evidence record is corrupt
            # input, not something to canonicalise.
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueError(
                    f"non-finite value for {key!r} cannot be sealed into the "
                    f"custody chain")
            value = repr(value)
        elif isinstance(value, datetime):
            value = value.astimezone(timezone.utc).isoformat()
        elif isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               default=str, allow_nan=False)
        out[key] = value
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      default=str, allow_nan=False).encode()


def link(entry: dict, prev_hash: str) -> str:
    """Hash of one entry given its predecessor."""
    return hashlib.sha256(canonical(entry) + b"|" + prev_hash.encode()).hexdigest()


def seal(entry: dict, prev_hash: str) -> dict:
    """Return the entry with its chain fields populated, ready to insert."""
    return {**entry,
            "chain_version": CHAIN_VERSION,
            "prev_hash": prev_hash,
            "entry_hash": link(entry, prev_hash)}


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
