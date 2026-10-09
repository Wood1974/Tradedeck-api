# Shield custody chain — specification v2

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
gps_lat, gps_lng, file_hash, integrity_note, recorded_at
```

**`exif_captured_at` is deliberately not in that list**, and was removed in v2.
It is read from EXIF `DateTimeOriginal`, which the uploader writes. Sealing it
proved exactly one thing — that it had not changed since we recorded it — and
read, to anyone who had not read this document, as though the capture time
itself were established. It still travels in the record; the chain does not
vouch for it. `recorded_at` is server-side and stays signed. It proves *not
after*, never *not before*.

Build a map from those fields, then serialise:

1. **Omit null.** A field that is absent and a field that is null are the same
   thing. This is load-bearing: adding a column and then nulling it must not
   change any historical hash.
2. **Floats via `repr()`.** So `40.1` is never `40.10000000000001` on one
   machine and `40.1` on another.

   **Which fields are floats:** `gps_lat` and `gps_lng`, and only those. Every
   other signed field is a string, or a structure handled by rule 4. The
   service coerces both with `float()` before sealing.

   This has to be stated rather than inferred, and saying "floats via `repr()`"
   does not state it. A Python implementation can ask the value what type it
   is; an implementation in any other language is reading a package that has
   been through JSON, where `40.0` and `40` are the same token. Deciding by
   inspecting the value gets integral coordinates wrong — and *only* integral
   ones, so a latitude of 40.76056 verifies and a latitude of exactly 40.0 does
   not. Writing a third implementation is what surfaced this; §7 records the
   part of it that is still unfixed.
3. **Non-finite values are refused,** not rendered. `NaN` reaching a chain as
   the string `"nan"` would seal corrupt input as if it were a coordinate.
4. **Nested dicts and lists** become compact JSON with sorted keys:
   `json.dumps(v, sort_keys=True, separators=(",", ":"))`.

   **Nested floats are rendered through `repr()` before this happens, at the
   moment the entry is sealed — not at the moment it is hashed.** So a writer
   storing `{"score": 100.0}` stores `{"score": "100.0"}`, and that is what the
   package carries. A verifier hashes the row exactly as it arrives and does no
   normalisation of its own.

   The split matters and is easy to get backwards. Only the writer knows
   whether `100` was an integer or a float; a reader in JavaScript cannot tell,
   because JSON has one number type. If a verifier normalised, it would be
   guessing. So the writer commits to the answer and the package carries it.
   This is what v1 could not do, and §7 records what it cost.
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

**Truncation.** Dropping entries from the *end* of the chain leaves a shorter
chain in which every remaining link still verifies. Nothing inside the package
detects it — including the package's own `head_hash`, which a truncating
operator simply updates. This is a property of hash chains, not a defect, and
it is a cheaper attack than a full rewrite: no recomputation is needed, just
deletion. It is how an operator would remove the last few entries showing a
retake or an integrity flag.

The only defence is a head hash the recipient obtained **earlier, from their
own records**. Pass it to a verifier (`--expect-head`). A verification run
without one should say so rather than pass silently.

**The honest limit.** An attacker who recomputes the entire chain produces
something that verifies perfectly. What they cannot do is make it match a head
hash somebody already holds. That is why a head hash that has left the
building — in a close-out packet, an email to an adjuster, an RFC 3161
timestamp, a customer's own system — is worth more than the chain itself.
Keep the head you were given.

## 7. The defect that produced version 2

**Fixed in v2. Recorded here because a third party implements from this
document, and because how it was found is the useful part.**

In v1, rule 4 serialised `event_data` with the language's own JSON encoder,
which renders the float `100.0` as `100.0` and the integer `100` as `100`.
Those hash differently. After the package had been through JSON both were the
token `100`, and unlike `gps_lat` there was no fixed field list to declare,
because `event_data` is written at many call sites with whatever keys suit
them.

**So a non-Python verifier could not always reproduce the hash** — and the case
was not exotic. Close-out seals `score` and `coverage_pct`, both produced by
`round()`, both very often whole. The most important entry in a clean record
was the one most likely to be affected.

It was found by writing a third implementation of this document in JavaScript.
Neither Python implementation had noticed, because Python hands back a float
and can be asked. A specification is only as good as its least similar
implementation.

v2 closes it by moving the decision to the writer: nested floats are rendered
through `repr()` at seal time, so the stored row and the package both carry
`"100.0"`, and any language reproduces the hash by reading what it was given.

**A verifier meeting a v1 entry must still not report tampering.** Enumerate
the readings of the whole numbers in `event_data`; if one reproduces the
stored hash, the mismatch is explained by this defect and the honest report is
**cannot verify**, not **altered**. It must not report success on that
alternative reading either — a verifier that searches for an interpretation
under which a package passes has stopped verifying. `webapp/verify.js` does
this, gated on `chain_version` being 1, and says so on screen.

That gate is load-bearing. Applying the same leniency to a v2 entry would hand
an attacker a sentence to hide behind: edit any entry containing a whole
number, and the verifier prints *not evidence that anything was altered* over
the top of it.

## 8. Versioning

`chain_version` is **2**. It changes only with a migration that re-chains
existing rows, because a serialisation change silently invalidates every chain
ever written. The canonical form above is pinned by tests in all three
implementations.

**The 1 → 2 bump cost nothing, and that was the only reason to do it when it
was done.** `shield_custody_log` had neither `prev_hash` nor `entry_hash`, so
no chain had ever been written and the migration this section demands had
nothing to re-chain. The same change after the first real record would have
invalidated it. A format defect in an evidence product gets more expensive
every day it is left, and this one had a window where the price was zero.

## 9. Addendum — the on-phone capture record

Sections 1 through 8 are unchanged. `chain_version` is not part of this
record. It remains 2.

A phone that keeps taking photos with no signal needs its own record, signed
by the phone, linked to the previous record on that phone. That chain is not
the custody chain. Putting these bytes into `event_data` would make them look
like the custody chain vouched for a time the phone declared. It does not.
The reference implementation is `capture_record.py`. The time labels are
`time_audit.py`. Neither one is a route, a database migration, or a phone
app. Those come later, and they have to produce these bytes.

### 9.1 Version

`version` is `1`. It is inside the hashed bytes so this signing contract can
be told apart from the older one, which signs
`SHA256(challenge ‖ SHA256(photo))` and has no record of this shape. A later
change to these bytes increments `version`. It does not increment
`chain_version`.

### 9.2 Fields

Fixed membership. A field not in this list is metadata the record hash does
not cover.

| Field | JSON type | Required | What it is |
|---|---|---|---|
| `version` | number | yes | `1` |
| `checkpoint_id` | string | yes | Which checkpoint the photo is for |
| `photo_sha256` | string | yes | Lowercase hex SHA-256 of the original photo bytes |
| `ticket_id` | string | yes | The job ticket this capture was made under |
| `wall_time_ms` | number | yes | Phone wall clock, Unix epoch milliseconds |
| `monotonic_ms` | number | yes | Monotonic milliseconds since boot, sleep included |
| `boot_id` | string | no | Boot-session id (iOS `kern.bootsessionuuid`) |
| `boot_count` | number | no | Boot count (Android `BOOT_COUNT`) |
| `gnss_time_ms` | number | no | GNSS time, Unix epoch milliseconds. Omit when there is no fix |
| `location_simulated` | boolean | no | Platform mock-location flag. Omit when the platform did not report one |
| `sensor_hash` | string | no | Lowercase hex SHA-256 of the sensor snapshot. Omit when no snapshot was taken |
| `depth_hash` | string | no | Lowercase hex SHA-256 of the depth payload |
| `depth_present` | boolean | no | `true` only together with `depth_hash`. `false` means the phone reported that depth was not available |
| `flags` | number | yes | Bitfield below. `0` means no bits set, and it is not the same as omitting the field |

`prev_hash` and `record_hash` travel with the record and are **not** in the
table. They are the link, same as on a custody entry.

Whole numbers only. There is no float in this record.

| Quantity | Unit | Example |
|---|---|---|
| Coordinate | microdegrees | 40.760560° is `40760560` |
| Angle | hundredths of a degree | 184.50° is `18450` |
| Duration, wall time, GNSS time, monotonic time | milliseconds | 120.000 s is `120000`. 120.001 s is `120001` |
| Hash | lowercase hex, 64 characters | SHA-256 |

A number has to be an integer in the range a JSON number can carry exactly,
which is ±(2^53 − 1). Past that, a JavaScript verifier cannot reproduce the
hash. Booleans are JSON `true` and `false`. They are not `1` and `0`. Those
hash differently, and a reader in another language cannot guess which one was
signed.

`monotonic_ms` is already milliseconds when it is signed. iOS converts
`mach_continuous_time` through the timebase with integer arithmetic. Android
uses `elapsedRealtime()`. Raw ticks are not in the record: they are not
comparable across phones, and a floating timebase would put a float in the
signed bytes.

The sensor snapshot and the depth payload are not inside the record. Each is
canonicalised with the rules in §9.3, hashed, and the hex is what the record
holds. Angles inside a snapshot are hundredths of a degree. Coordinates are
microdegrees. The canonicalizer does not do that scaling. A float is a
rejected input, not a value to be converted.

`flags` bits, lowest first:

| Bit | Value | Name |
|---|---|---|
| 0 | 1 | screen captured |
| 1 | 2 | debugger attached |
| 2 | 4 | mock location |
| 3 | 8 | root traces |

A higher bit is kept in the integer and shown as unknown. It is not stripped,
and it does not change a time label or the byte verdict. The mock-location
**bit** and the `location_simulated` **field** are the same fact written
twice, once for the flag list and once next to the clock. This record does
not reconcile them. Neither one is a time label.

`depth_hash` without `depth_present: true` is not a record. `depth_present:
true` without `depth_hash` is not a record.

### 9.3 Canonical bytes

Build a map from the fields in §9.2, then serialise it with the rules in §1,
plus one rule §1 does not have:

1. Omit null. Absent and null are the same bytes. `0` and `false` are not
   null, and they are not omitted.
2. **Reject floats.** Do not render them with `repr()`. NaN and the
   infinities are floats and are rejected too. The custody chain still
   renders `gps_lat` and `gps_lng` with `repr()`, because that chain already
   has those fields. This record was defined so it would not.
3. Reject a boolean in a number field, and reject a number in a boolean
   field.
4. There are no nested objects in the record itself. A snapshot that is
   hashed *into* the record is a JSON object, keys sorted, nulls omitted,
   lists kept in order, same separators, floats rejected.
5. The map becomes compact JSON, keys sorted, separators `(",", ":")`,
   non-ASCII escaped as `\uXXXX`, then UTF-8. This is what `json.dumps` does
   with `sort_keys`, `separators=(",", ":")`, and `allow_nan=False`.

`version`, `checkpoint_id`, `photo_sha256`, `ticket_id`, `wall_time_ms`,
`monotonic_ms`, and `flags` are required. Omitting one of them is not a
record.

### 9.4 The phone-chain link

```
record_hash = SHA256( canonical(record) || "|" || prev_hash )
```

The `"|"` is one byte, as in §3. `prev_hash` is the previous record's
`record_hash`. For the first record it is the ticket hash defined in §10.

Walk the records in the order they were made. Do not sort them by time.

```
expected_prev = ticket hash
for each record:
    if record.record_hash is missing     -> TAMPERED
    if record.prev_hash != expected_prev -> TAMPERED (link broken)
    if link(record, prev_hash) != record.record_hash
                                         -> TAMPERED (bytes do not reproduce)
    expected_prev = record.record_hash
```

A record that fails to parse — a float, a missing required field, a hash
that is not lowercase hex — is TAMPERED. The bytes do not reproduce.

**INTACT** means every record in the list reproduces its hash and names the
hash before it. INTACT is not SEALED. SEALED also requires the hardware
signature, the ticket signature, and the timestamp, which are not checked
here.

Dropping records off the end leaves a shorter chain that still reports
INTACT. A head hash the holder already has is what catches that, same as §6.
A full rewrite that recomputes every link also reports INTACT and moves the
head. The head is the value worth keeping.

### 9.5 Time labels

`time_audit` reads two observations: the phone's clocks when the ticket was
issued, and the phone's clocks on the photo. Ticket time here is the phone's
wall clock at that moment, because monotonic time only means something
against the same clock. It does not read the custody chain, and it does not
read `flags`.

The limit is **120 seconds**, stored as `CLOCK_MISMATCH_LIMIT_MS = 120000`.
The comparison is integer milliseconds and it is strict: a difference of
`120000` agrees, a difference of `120001` does not, in either direction.

That limit is not the capture-challenge lifetime. The challenge lifetime is
how long a nonce may be spent. This limit is how far the device clock may
drift from its own monotonic clock, and from GNSS, before the record is
labeled. They are both 120 seconds today. They are different constants so
that changing one does not move the other.

| What happened | Label |
|---|---|
| Boot id or boot count differs between ticket and photo, or a boot identifier is present on only one of them, or neither observation has a boot identity | **UNVERIFIED TIME** |
| A wall or monotonic reading the comparison needs is missing, on the same boot | **UNVERIFIED TIME** |
| Same boot, and monotonic time on the photo is earlier than monotonic time on the ticket | **UNVERIFIED TIME**. The monotonic clock does not run backward on one boot, so there is no interval. A wall clock moved by the same amount does not make the interval reappear. This is not a device-clock mismatch and not a forgery finding |
| Same boot, monotonic elapsed is zero or positive, and \|wall − (ticket wall + monotonic elapsed)\| > 120 s | **DEVICE CLOCK MISMATCH** |
| GNSS time is present and \|GNSS − wall\| > 120 s | **DEVICE CLOCK MISMATCH** |
| GNSS time is absent | No extra label. The monotonic result stands, and the report says GNSS was absent |
| Same boot, difference ≤ 120 s, and GNSS absent or within 120 s of the wall | **CONSISTENT** |

Monotonic elapsed is `photo.monotonic_ms − ticket.monotonic_ms`. It is only
computed when the boot is the same and the elapsed time is not negative.
A reboot does not become a clock mismatch just because the wall clock also
moved: there is no interval to check. A monotonic clock that moved backward
on the same boot is the same kind of gap: the interval is not a duration,
even if the wall clock was set so the absolute formula would come out even.
UNVERIFIED TIME is not TAMPERED. The bytes can still be INTACT.

GNSS is compared to the photo's wall clock, not to the ticket. If the boot
changed **and** GNSS disagrees with the wall clock, both labels apply. The
single verdict is **DEVICE CLOCK MISMATCH**, because that disagreement was
measured, and **UNVERIFIED TIME** stays in the list. GNSS agreeing with the
wall clock does not clear a monotonic mismatch. GNSS being absent does not
create one and does not clear one. An indoor job has no sky.

`flags` and `location_simulated` never change these labels. A screen
capture, a debugger, a mock location, or a root trace is reported beside the
verdict. It does not turn CONSISTENT into DEVICE CLOCK MISMATCH, it does not
turn a mismatch back into CONSISTENT, and it does not make an intact chain
TAMPERED.

### 9.6 What this addendum does not establish

- That a hardware key signed the record. The hash is what that key will sign.
  The check that it did is later.
- That the ticket is genuine, or that the first `prev_hash` is the ticket
  hash the server issued. This addendum checks the link the caller supplies.
  §10 is the ticket. This addendum still does not check it.
- That the photo came off a camera sensor.
- That the wall clock is the true time when the label is CONSISTENT. A clock
  set wrong before the ticket, and left alone, agrees with itself.
- That a missing timestamp, a missing GNSS fix, or a reboot is forgery.
- Anything about the custody chain's `chain_version`, which remains 2.

## 10. Addendum — the job ticket (genesis)

Sections 1 through 8 are unchanged. `chain_version` is not part of this
ticket. It remains 2.

A phone that will keep taking photos with no signal needs a ticket first,
while it still has a signal. The server builds the ticket and signs it.
The phone's attested install key signs the hash. The row is written only
after that signature verifies. The reference implementation is `ticket.py`.
The route is `POST /shield/v2/records/<id>/genesis`. The phone apps do not
implement the call yet.

### 10.1 Version

`version` is `1`. It is inside the hashed bytes. It is not
`capture_record` version 1, and it is not `chain_version`. A later change
to these bytes increments `version`. It does not increment `chain_version`.

### 10.2 Fields

Fixed membership. A field not in this list is not signed and is not stored.

| Field | JSON type | Required | What it is |
|---|---|---|---|
| `version` | number | yes | `1` |
| `record_id` | string | yes | The record this ticket is for |
| `checkpoint_list_sha256` | string | yes | Lowercase hex SHA-256 of the locked checkpoint list, §10.5 |
| `actor_id` | string | yes | The authenticated actor. Taken from the credential, not the body |
| `expires_at_ms` | number | yes | Server clock plus 7 days, Unix milliseconds. `expires_at_ms` is after `server_time_ms` |
| `server_time_ms` | number | yes | Server clock when the ticket was offered, Unix milliseconds |
| `roughtime_ms` | number | no | Outside clock, Unix milliseconds. Omit when it is absent |

Whole numbers only. The same rule as §9.2. A float is rejected. `0` is not
absent. Null and absent are the same bytes.

`server_time_ms` is the server's clock. It is not the phone's wall clock.
§9.5 compares the phone's clocks with each other. The phone's own clocks
at the moment it countersigns are `ticket_clock`. They are not fields of
this signed ticket, because the server builds the ticket before the phone
measures them. They are covered by the hardware signature in §10.4 and
stored on the row. A later batch reads that row. It does not get to
supply a different baseline.

`ticket_id` on a capture record is the ticket hash from §10.3, not a
separate identifier. The database row also has its own id. That id is not
in the signed bytes.

### 10.3 Canonical bytes and the ticket hash

Same rules as §9.3: omit null, reject floats, reject a boolean in a number
field, compact JSON, keys sorted, separators `(",", ":")`, non-ASCII
escaped, UTF-8.

```
ticket_hash = SHA256( canonical(ticket) )
```

Lowercase hex, 64 characters. There is no `"|"` in this hash. The `"|"`
in §9.4 is how a capture record links to this hash, not how the hash is
made.

### 10.4 Who signs

**The server.** ECDSA on curve P-256, SHA-256, over the canonical bytes.
The signature is DER, then base64. The private key is the environment
variable `SHIELD_TICKET_SIGNING_KEY_PEM`. It is not in this repository.
Unset, genesis is refused and nothing is stored. The public half is
exported as PEM and as the uncompressed point (`0x04 || X || Y`, base64)
for an evidence package. The private key is not in that export.

**The phone.** The install key already in `shield.attested_keys`. The
signed message carries the ticket hash and the phone clock, in the same
slot the capture path already uses:

```
ticket_clock = canonical JSON of wall_time_ms, monotonic_ms, and boot_id and/or boot_count
clientData = UTF-8("shield-genesis-v1") || SHA256(ticket_hash_raw || ticket_clock)
```

`ticket_hash_raw` is the 32-byte digest, not the hex text. `ticket_clock`
is UTF-8 JSON with sorted keys and tight separators, the same whole-number
rules as §9.3. The SHA-256 is 32 bytes. iOS passes `SHA-256(clientData)` to
`generateAssertion`. Android signs `clientData` with `SHA256withECDSA` and
does not pre-hash it. Both are checked by the existing verifiers. Those
verifiers are not changed. A signature over the bare ticket hash does not
verify: the clock would otherwise be free to change at sync.

A capture assertion uses a server nonce as its challenge. A ticket
assertion uses the fixed challenge `shield-genesis-v1`. One does not
verify as the other.

The hardware signature has to be present and valid. If it is missing or
does not verify, the route refuses and writes no row. That is the same
rule as a photograph.

### 10.5 The checkpoint list

Genesis requires the record's checkpoints to be locked. The hash covers
each checkpoint's id, point number, label, and, when present, description,
code reference, and what the photo must show. Rows are sorted by point
number. Status is not in the hash: status changes as photos are graded,
and the commitment is the list that was locked.

The server computes the hash. A hash in the request body is ignored on
the offer, and on the seal it has to match the list now. A list that
moved does not get a stored ticket.

### 10.6 What is refused

The route refuses, and stores nothing, when:

- the hardware signature is missing or does not verify, including a
  signature that does not cover the `ticket_clock` sent with it
- `ticket_clock` is missing, or it has no wall time, no monotonic time,
  or no boot identity
- the server signature does not verify (the ticket was altered)
- `record_id` is not the record in the URL
- `actor_id` is not the authenticated actor
- the checkpoint hash is not the locked list
- `now` is past `expires_at_ms` (`expires_at_ms` itself is still current)
- the record already has a ticket
- the checkpoints are not locked
- no signing key is configured

iOS assertions advance the stored counter with the same compare-and-set
a photograph uses. A replayed assertion does not verify.

### 10.7 Play Integrity, once per job

Android only, and once, on this row, not on each photograph. The reading
is `attestation.interpret_play_integrity`.

| What was presented | Status stored |
|---|---|
| Nothing | **absent**. Not a pass and not a fail |
| A token this service has not cryptographically checked | **unverifiable**. Not a pass |
| A checked token with `MEETS_STRONG_INTEGRITY` or `MEETS_DEVICE_INTEGRITY`, bound to this ticket | **pass** |
| A checked token the platform rejected (no label, unrecognized app, emulator, basic only) | **fail** |

This release does not call Google. A token that arrives on the wire is
stored as unverifiable. Pass and fail are what the same function returns
for a fixture once `verified` is true. The route does not set that.

iOS has no Play Integrity API. A Play Integrity body on an iOS request is
ignored. The stored reason says so, and it says that App Attest does not
report whether the device is jailbroken. An iOS pass from App Attest is
a statement about the app and the Secure Enclave. It is not a statement
that the phone is not jailbroken.

### 10.8 Roughtime

`SHIELD_ROUGHTIME_ENABLED` defaults to off. There is no Roughtime client
in this release. When the flag is off, or the outside clock does not
answer, or the reading is not a whole number of milliseconds, `roughtime_ms`
is omitted. Genesis still completes. The ticket records the absence by
not having the field.

### 10.9 Two workers

The offer is not kept in the per-process challenge jar. Render runs two
gunicorn workers, and that jar is not shared. The phone sends the ticket
and the server signature back. Any worker can check the signature, because
the key is configuration, not memory. The stored ticket is a row in
`shield.job_tickets`, written by the service role. One row per record.

### 10.10 What this addendum does not establish

- That a real Apple device produced the assertion. The verifiers are the
  ones the capture tests already run, against keys those tests mint.
- That Google Play Integrity was called. It was not.
- That an iOS device is not jailbroken.
- That the phone's wall clock matches the server clock. The stored
  `ticket_clock` is the phone's own clocks at countersign. §9.5 compares
  later photos to that observation. A clock set wrong before the ticket,
  and left alone, still reads CONSISTENT.
- Anything about `chain_version`, which remains 2.

## 11. Addendum — the offline queue, the receipt, and the timestamp

Sections 1 through 8 are unchanged. `chain_version` is not part of the
receipt. It remains 2.

A phone that already holds a job ticket (§10) can keep taking photos with
no signal. Each photo has a capture record (§9) and a hardware signature
over that record. When the phone has a signal again it sends a batch. The
route is `POST /shield/v2/records/<id>/queue`. The reference
implementation is `queue_ingest.py` for the batch and `tsa.py` for the
receipt and the timestamp. The phone apps do not implement the call yet.

The same credential rules as the rest of `/shield/v2` apply. The record
has to belong to the tenant. The actor has to be the actor on the ticket.
The platform, when the body names one, has to be the platform on the
ticket. The signing key has to be the key that countersigned the ticket.

### 11.1 What one request carries

Each item is three parts:

- the photograph, base64
- the capture record from §9, including `prev_hash` and `record_hash`
- the hardware signature over that record

`ticket_clock` is not a field of this request. It is the observation
stored on the job ticket when the phone countersigned it (§10.4):
`wall_time_ms`, `monotonic_ms`, and `boot_id` and/or `boot_count`. The
route reads that row. A clock sent with the batch is not used. The
accepted batch nests the stored observation in the custody entry, so a
later edit moves the custody head.

The first batch on a record has to start at the ticket hash. The next
batch has to start at `phone_chain_head` from the receipt already stored
for this record. A batch that starts anywhere else is refused, and
nothing is stored.

### 11.2 How many photographs

`SHIELD_QUEUE_BATCH_CAP` defaults to 8. One request may carry that many.
Photographs past the cap are not accepted. The response says to send the
next batch, and it names how many were left behind. The prefix that was
accepted is a chain of its own. The next request starts at that prefix's
head.

A head the phone claims for the whole request is not applied to a prefix
the cap shortened. Applying it would refuse the split the cap exists to
make. When the request fits in the cap, a claimed head that is not the
head just computed is a truncated chain, and the batch is refused.

### 11.3 The hardware signature

The install key is the one already in `shield.attested_keys`, and it is
the key on the job ticket. A different key is refused.

The signed message uses the same slot the ticket uses, with a different
challenge, so a ticket signature does not verify as a capture and a
capture signature does not verify as a ticket:

```
clientData = UTF-8("shield-capture-v1") || record_hash_raw
```

`record_hash_raw` is the 32-byte record hash, not the hex text. The
record hash covers `photo_sha256`. The route recomputes SHA-256 of the
photograph that arrived and refuses the batch when it disagrees with the
record. iOS passes `SHA-256(clientData)` to `generateAssertion`. Android
signs `clientData` with `SHA256withECDSA`. Both are checked by
`app_attest.verify_assertion` and `android_attest.verify_signature`.
Those verifiers are not changed.

There is no server nonce on this path. The phone was offline. The
per-process challenge jar is not used. A replay of an earlier batch is
stopped by the chain: the next batch has to extend the phone-chain head
already stored. Sending the same batch again, after its receipt exists,
returns that receipt with HTTP 200 and `replayed` true, and stores
nothing else. iOS also has to advance
the assertion counter. The counter moves once, to the last counter in
the batch, and only after the receipt row for this batch is stored. A
failure before that row exists stores nothing and does not move the
counter, so the phone can send the batch again.

A signature that does not verify, or a key this service does not trust,
refuses the batch. Nothing is stored. Trust is the same two tiers a
photograph already requires.

### 11.4 The chain, and the clock labels

`capture_record.verify_chain` checks the batch. A signed field that was
edited, a missing link, a chain that does not start where the last
receipt ended, or a chain shorter than a head the phone claimed: the
verdict is TAMPERED, the route refuses, and nothing is stored.

`time_audit.assess` runs on every capture that linked. A reboot, or a
missing boot identity, is **UNVERIFIED TIME**. A wall clock that
disagrees with the ticket's wall clock plus the monotonic elapsed, or a
GNSS time that disagrees with the photo's wall clock, is **DEVICE CLOCK
MISMATCH**. The limit is the one in §9.5. These labels are stored on the
custody entry and on the receipt. They are not a reason to refuse the
photographs.

Flags do not enter the time verdict. Screen capture, a debugger, mock
location, and root traces are stored beside the label. They do not create
a mismatch, clear one, or turn a reboot into a consistent clock.

The labels describe the clocks the phone reported. A clock set wrong
before the ticket, and left alone, still reads CONSISTENT. That limit is
§9.5, and this addendum does not widen it.

The ticket's expiry is not re-checked here. A batch can arrive after the
seven days in §10.6. A wall clock that has been set back is a time label,
not a second expiry check.

### 11.5 One custody entry

The route appends one entry, `event_type` `offline_batch`. `file_hash`
is the phone-chain head. `event_data` carries that same head, the ticket
hash, the phone chain, the per-capture labels, `ticket_clock`, and
`sealed_photos`. `ledger.seal` stamps `chain_version` 2, as it does for
every other entry. The phone chain is nested under the custody chain. It
does not replace it, and it does not get its own `chain_version`.

`sealed_photos` is a list of objects, one per photograph stored for the
batch:

| Field | What it is |
|---|---|
| `photo_id` | The id assigned when the bytes were stored |
| `photo_sha256` | The hash of those bytes. The same hash is on the capture record, which the phone's key signed |
| `checkpoint_id` | The checkpoint named on that capture record |

A verifier pairs a photograph to its hash and its checkpoint by reading
those three fields on one object. It does not zip a `photo_ids` array
with `captures` or with `phone_chain` by position. There is no sealed
`photo_ids` array. The list sits in `event_data`, so editing one object,
or reordering the list, changes the custody head.

`photos[].original_hash` and `checkpoints[].sha256_original` are copies.
They are not sealed. The seal judge compares every offline photograph
those lists name, and any bytes supplied for that photograph, to
`phone_chain[].photo_sha256`. That hash sits in the capture record the
phone's key signed. When the two disagree the label is TAMPERED, even
if the phone chain, the hardware signatures, the receipt, and the
timestamp otherwise check. A photograph that is not in `sealed_photos`
is not an offline photograph, and this comparison does not apply to it.

The photographs are stored the way a single upload stores one: the hash
is recomputed, the file is sniffed, and a second live photo of the same
checkpoint supersedes the previous one. Those writes are not separate
custody events. The batch is one link. The id written on the photo row
is the `photo_id` in `sealed_photos`.

### 11.6 The receipt

After the custody entry is appended, the server signs a receipt with the
same ECDSA P-256 key that signs job tickets
(`SHIELD_TICKET_SIGNING_KEY_PEM`). Unset, the route refuses before it
writes. The signature is DER, then base64, over the canonical bytes of:

| Field | JSON type | What it is |
|---|---|---|
| `version` | number | `1`. Not `chain_version`. A later change to these bytes increments this, not `chain_version` |
| `record_id` | string | The record in the URL |
| `head_hash` | string | The custody-chain head after this batch's entry. Not the phone-chain head |
| `accepted_at_ms` | number | Server clock when the batch was accepted, Unix milliseconds |

Same canonical rules as §9.3 and §10.3. Whole numbers only. A float is
rejected.

`phone_chain_head` and the time labels are stored beside the signature.
They are not a second signature. The custody head already commits to
them, because they live in the signed `event_data` of the entry the head
covers.

The public half of the signing key is what a package carries. The private
key is not.

One receipt row per accepted batch, in `shield.receipts`, written by the
service role. The row is append-only. The next batch's index is one
higher, and its first record has to name this row's `phone_chain_head`.

### 11.7 The timestamp

After the receipt row exists, the server asks for an RFC 3161 token over
the custody head. The message imprint is the raw 32-byte head. The head
is already a SHA-256. A verifier compares those 32 bytes to the head. It
does not hash them again.

`SHIELD_TSA_PRIMARY_URL` defaults to DigiCert
(`http://timestamp.digicert.com`). `SHIELD_TSA_FALLBACK_URL` defaults to
Sectigo (`http://timestamp.sectigo.com`). `SHIELD_TSA_ENABLED` defaults
to off. Off means the server does not open a connection. The receipt
still exists. The package says the timestamp is missing.

When the flag is on, DigiCert is asked first. Sectigo is asked only if
DigiCert does not return a token this service can check. The check needs
a root in `SHIELD_TSA_ROOTS_PEM`. No root, no pass. The signer
certificate may sit under an intermediate that the token itself carries;
the chain has to end at one of those roots. The imprint algorithm has
to be SHA-256, which is what the request asked for. The signature over
the token may be SHA-256 or SHA-384, RSA or ECDSA. The token's time may
include a fraction of a second. A token that does not verify is not
stored as present. The result is missing.

Missing is not forged. There is no status that says it is. `forged` on
the package is false in both states: a timestamp anchors the custody
head, and a missing one is a missing anchor, not a finding about the
photograph. The service does not mint a token to fill the gap.

The outcome is one row in `shield.tsa_tokens`, append-only, either way.
`present` requires the token. `missing` requires its absence.

### 11.8 The package

`GET /shield/v2/records/<id>/package` and `evidence.build_manifest` both
carry a receipt, the timestamp block, and the public half of the signing
key. The receipt on an export is signed over the head that export's own
entries recompute to. See §11.10. `custody.chain_version` is the version
`ledger.verify_chain` already reports. It is still 2. A package with no
receipt says receipt absent. A package whose timestamp authority did not
answer says timestamp missing. Neither of those is a forgery.

### 11.9 What this addendum does not establish

- That the photograph came off a camera sensor.
- That the wall clock is the true time when the label is CONSISTENT.
- That a reboot, a missing GNSS fix, or a missing timestamp is forgery.
- That an iOS device is not jailbroken. App Attest does not say.
- That DigiCert or Sectigo were contacted. The flag defaults to off, and
  the addresses are configuration. A test runs a local authority with a
  certificate that test minted. It does not call either host.
- Anything that changes `chain_version`, which remains 2.
- That a chain was not truncated after the export and then re-signed.
  The receipt covers the head inside the package. A shorter chain with a
  new receipt over the shorter head still verifies. A head the recipient
  already holds is what catches that. See §6.

### 11.10 The export receipt

Every export signs a receipt over the head the exported entries recompute
to. The signed fields are the four in §11.6. `record_id` is the job or
the record. `head_hash` is that recomputed head, not a head stored beside
it. `accepted_at_ms` is the server time of the export, whole Unix
milliseconds. `version` stays `1`. `chain_version` stays 2.

The signature is the same ECDSA P-256 key that signs job tickets
(`SHIELD_TICKET_SIGNING_KEY_PEM`). `phone_chain_head` and the time labels
from the latest batch ride beside the signature. They are not signed
again. The custody head already commits to the entry that stored them.

Both package shapes carry it. `evidence.build_manifest` flattens the
signed fields onto `receipt` and puts the public key on `signing_key`.
`GET /shield/v2/records/<id>/package` nests the signed fields under
`receipt.signed` and puts the same public key on `signing_key`. The
custody list on that response is `custody`, not `custody_entries`. A
verifier accepts either shape.

The timestamp is an RFC 3161 token over that same head. The imprint is
the raw 32-byte head, as in §11.7. DigiCert is asked first, then Sectigo,
and only when `SHIELD_TSA_ENABLED` is `1`. A token already stored for the
batch is reused only when that token's head is this package's head. A
token over a different head is not shipped in its place. When the
authority is off or does not answer, the package still ships and the
timestamp block says timestamp missing. `forged` is false. The service
does not mint a token to fill the gap.

A verifier recomputes the head and checks three things against it:

- The receipt signature, with the public key in the package.
- The signed `head_hash` equals the head just computed. A full rewrite
  that leaves the original receipt in place fails here, with no
  `--expect-head`.
- The token's TSTInfo imprint, when a token is present, is that same
  head. A missing token is the note timestamp missing, not a failure.

No receipt is the note receipt absent, not a failure. A package from
before this receipt was added still verifies its chain.

`verifier/shield_verify.py` checks the signature and the imprint. It does
not check the token's certificate chain: that check needs the pinned
roots, and the independent verifier does not carry them. An attacker who
can sign a token can put the new head in the imprint. They cannot produce
the receipt signature. `offline_seal.py` and the verify page do check the
token against the pinned DigiCert and Sectigo roots.

A receipt inside the export does not stop a server that rewrites the
chain and then signs the new head itself. The deciding proof is the
server-locked anchor in §11.11. A copy kept on the phone is a backup.
It does not outrank the object in the bucket.

### 11.11 Server-locked anchors

After a v2 upload, a legacy `/shield` upload, or an offline batch is
sealed, the service asks DigiCert and then Sectigo for an RFC 3161
token over that entry's hash, the same way §11.7 does. The entry's own
hash is what is locked, not whatever the tip becomes after a later
event. On an upload that also seals `superseded` or `integrity_flag`,
each of those entries is locked too. `viewed`, `exported`, and
`completed` are not.

The anchor is one S3 object:

```
anchors/{record_id}/{seq:08d}-{head_hash}.json
```

`seq` is the entry's index in the chain at the moment it was sealed.
The body is `record_id`, `seq`, `head_hash`, the token, the token time,
`anchored_at`, `delay_ms`, and the receipt when the batch had one.
Object Lock is COMPLIANCE. Retention is `SHIELD_ANCHOR_RETENTION_DAYS`,
default 2555 (7×365). The bucket has to be created with Object Lock
already on. It cannot be turned on afterwards.

The application role is write-only: `s3:PutObject` and
`s3:PutObjectRetention` on `anchors/*`. It has no `s3:DeleteObject` and
no `s3:GetObject` or `s3:ListBucket`. A different principal, the read
role, has `s3:GetObject` on `anchors/*` and `s3:ListBucket` on the
bucket limited to that prefix. `python -m anchor_lock export` uses the
read role. That listing is the set a verifier should be given.

`SHIELD_ANCHOR_BUCKET` unset is the disabled mode. No S3 call is made.
Uploads still succeed. Verifiers say `anchor absent`, which is not a
failure. The other variables are `SHIELD_ANCHOR_REGION` (default
`us-east-1`), `SHIELD_ANCHOR_RETENTION_DAYS`,
`SHIELD_ANCHOR_ACCESS_KEY_ID`, `SHIELD_ANCHOR_SECRET_ACCESS_KEY`,
optional `SHIELD_ANCHOR_SESSION_TOKEN`, the matching
`SHIELD_ANCHOR_READ_*` keys, and `SHIELD_ANCHOR_QUEUE_PATH`.

The queue is SQLite. It has to be on the persistent disk
(`/var/data/shield-anchors.db` when the disk is mounted there). The
container disk does not survive a restart. The queue is not in S3: a
lock store that is down cannot be the place pending writes wait.

Failure. The timestamp authority being down leaves the upload in place
and the head `timestamp pending`. No object is written, because
COMPLIANCE would freeze it without a token. `python -m anchor_lock
retry` stamps it later. `delay_ms` on the object is the time from the
first attempt to the put that succeeded. S3 being down, after a token
is already in hand, queues the put as `anchor pending`. The upload is
not refused. The response says pending until the put succeeds. Both
down is timestamp pending first, then the put.

The upload response carries `locked_anchor` (and `locked_anchors` when
the request sealed more than one entry). The iOS app stores that JSON
in the app container. It does not store the photograph. Android app
source is not in this repository; the API field is what an Android
client would keep. A phone copy that disagrees with the locked body
fails the check. It never silently wins.

Honest exports include `locked_anchors` from the local index of puts
that succeeded. That index can be deleted by the same process that
writes it. It is not the deciding record.

A verifier unions `locked_anchors` in the package with `--anchors` (or
the anchors file on the verify page) by object key.

- No anchors: the note `anchor absent`. The chain can still pass.
- An anchor whose head is not an entry, or whose `seq` is not that
  entry's index: failure. This is the truncated tail, or a rewrite
  that left the old object in the set the verifier was given.
- The token's TSTInfo imprint has to be that head. The time on the
  anchor has to be no earlier than the entry's `recorded_at` minus
  five minutes. A stamp happens after the entry is sealed. A retry
  may be much later. Later is fine.
- The chain head has to have an anchor when that head is an upload,
  an offline batch, a supersede, or an integrity flag, or when no
  anchor in the set matches any entry. The failure says
  `no locked anchor for this head`. A backfill locks only the current
  head, so older entries are not required to have one. A `completed`
  or `viewed` tip is not required to have one either, as long as the
  anchors that do exist still match entries in the chain.

`python -m anchor_lock backfill records.json` anchors the current head
of every record in that file and leaves the earlier entries alone.
`chain_version` stays 2.

What this does not catch. Anchors bundled in a package the party under
dispute produced. That party can rewrite the chain, lock the new head,
and omit the old object. The verifier then sees one consistent anchor.
The bucket listing, taken with the read role, still contains the old
object, and that object names a head the new chain does not have.
Truncating a tail that was never locked (`viewed` after an upload) is
still the case §6 and the export receipt are for. The independent
verifier does not call S3 and does not check the token's certificate
chain. The page and `offline_seal.py` check the seal's token against
the pinned roots; the locked-anchor check reads the imprint.
