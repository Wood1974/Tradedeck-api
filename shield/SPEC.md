# Shield custody chain — specification v1

Everything needed to verify a Shield evidence package without running Shield's
code or contacting Shield. Implement it in any language; a working Python
reference is `verifier/shield_verify.py`, which is itself written from this
document rather than from the service.

This is published deliberately. The method is not the product — a seal nobody
can check is worth nothing, and a specification anyone can implement is what
makes checking possible.

---

## 1. Canonical form

Each custody entry is hashed over a **fixed set of fields, in a fixed order**.
Anything outside this set is metadata the chain does not vouch for.

```
shield_job_id, photo_id, event_type, actor_id, actor_type, event_data,
gps_lat, gps_lng, file_hash, integrity_note, exif_captured_at, recorded_at
```

Build a map from those fields, then serialise:

1. **Omit null.** A field that is absent and a field that is null are the same
   thing. This is load-bearing: adding a column and then nulling it must not
   change any historical hash.
2. **Floats via `repr()`.** So `40.1` is never `40.10000000000001` on one
   machine and `40.1` on another.
3. **Non-finite values are refused,** not rendered. `NaN` reaching a chain as
   the string `"nan"` would seal corrupt input as if it were a coordinate.
4. **Nested dicts and lists** become compact JSON with sorted keys:
   `json.dumps(v, sort_keys=True, separators=(",", ":"))`.
5. **The whole map** becomes compact JSON with sorted keys, the same way, then
   UTF-8 bytes.

## 2. Genesis

```
genesis = SHA256("shield-custody-genesis-v1:" + shield_job_id)
```

One chain per job, not one global chain — so a job's package is verifiable by
whoever received it without exposing anything about other customers.

## 3. The link

```
entry_hash = SHA256( canonical(entry) || "|" || prev_hash )
```

`prev_hash` is the previous entry's `entry_hash`, or `genesis` for the first.
The `"|"` is a literal single-byte separator.

## 4. Verification

Walk entries **oldest first**, ordered by `recorded_at` ascending — the order
they were written.

```
expected_prev = genesis(job_id)
for each entry:
    if entry.entry_hash is missing        -> BROKEN (never chained, or stripped)
    if entry.prev_hash != expected_prev   -> BROKEN (inserted, removed, reordered)
    if link(entry, prev_hash) != entry.entry_hash
                                          -> BROKEN (a signed field was edited)
    expected_prev = entry.entry_hash
head_hash = expected_prev
```

Report **where** it broke. "Entry 7 of 12 fails" is actionable; "invalid" is not.

## 5. The package

A manifest is JSON carrying at least:

| Key | What |
|---|---|
| `job.shield_job_id` | The id the genesis value derives from |
| `custody_entries` | Every entry's signed fields plus `prev_hash` and `entry_hash` |
| `custody.head_hash` | The head the producer claims |
| `custody.chain_intact` | What the producer claims about its own chain |
| `checkpoints[].sha256_original` | The hash of each photo as received |

**A package without `custody_entries` is not verifiable.** Its integrity is
then the producer's assertion, and any verifier should say so rather than pass
it. Shield's own export omitted these until this spec was written, which is
exactly the kind of thing publishing a spec surfaces.

Cross-check the producer's claims against your own computation. If
`custody.head_hash` disagrees with the head you compute, or the package asserts
`chain_intact: true` over a chain that breaks, the package is lying about
itself and that is a more serious finding than a broken chain.

## 6. What this establishes, and what it does not

**Establishes:** no entry was altered, inserted, removed or reordered after it
was written; the head you hold commits to the whole history; supplied photo
bytes match what was received.

**Does not establish:**

- That a photo came off a camera sensor rather than a file picker.
- That entries were never *omitted before the chain was written*. The chain
  proves nothing was changed afterwards, not that everything was recorded.
- That any assessment is correct, or that work complies with any code.

**The honest limit.** An attacker who recomputes the entire chain produces
something that verifies perfectly. What they cannot do is make it match a head
hash somebody already holds. That is why a head hash that has left the
building — in a close-out packet, an email to an adjuster, an RFC 3161
timestamp, a customer's own system — is worth more than the chain itself.
Keep the head you were given.

## 7. Versioning

`chain_version` is 1. It changes only with a migration that re-chains existing
rows, because a serialisation change silently invalidates every chain ever
written. The canonical form above is pinned by tests in both implementations.
