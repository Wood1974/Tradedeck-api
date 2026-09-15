# Accepted risks — do not re-report these

Known, understood, and deliberately not fixed. The daily audit must not list
any of these again. If you can show one is **worse than described here**, that
is a new finding — say exactly how it exceeds the entry.

Each carries a review date. Past it, the entry is stale and worth re-arguing.

---

### AR-1 · A photo cannot be proven to come from a camera sensor
**Reviewed 2026-09-14 · next review 2027-03-01**

Nothing in Shield establishes that bytes came off an image sensor rather than a
file picker. EXIF is forgeable in about twelve lines using the same library
Shield reads it with; this was demonstrated against the code, not assumed.

Mitigations in place: the geofence measures against a site location the *buyer*
fixed at purchase, and solar geometry constrains what the light must have looked
like — neither is a value an uploader can write into a file.

Closing it properly requires capture-time attestation (Apple App Attest binding
a photo hash to a Secure Enclave key, or Android Key Attestation with
`verifiedBootState`), which requires a native app with no library-import code
path. Not built. The README and the certification both say so rather than
letting a reader assume otherwise.

*A new finding here would be: a way to defeat the geofence or the solar check
specifically, or a place where the product claims more than the above.*

---

### AR-2 · No rate limiting
**Reviewed 2026-09-14 · next review 2026-12-01**

There is no limiter on any route. Upload and analyze both cost real money per
call. Intended to be added at the edge before public exposure.

*A new finding here needs a specific amplification with numbers — a route where
one request causes disproportionate work, or a limit that can be bypassed once
one exists. "Add rate limiting" is not a finding.*

---

### AR-3 · No integration tests against live services
**Reviewed 2026-09-14 · next review 2026-11-01**

Storage, database and model calls are unexercised. All 219 tests and 27
invariants are static or in-process. A behaviour that only appears against real
Supabase, Stripe or Anthropic would not be caught here.

*A new finding here would be a specific divergence between what the code assumes
and what the service actually does — e.g. a Supabase client method whose real
return shape differs from the one the code handles.*

---

### AR-4 · Migrations have never been applied
**Reviewed 2026-09-14 · next review on first apply**

The three migrations are parse-validated only; no Postgres was available. The
`shield_*` schema was reconstructed from column usage in the original
`shield_api.py`, so a live column this reconstruction missed is possible.

*A new finding here would be a concrete mismatch between a column the code
writes and one the migrations create.*

---

### AR-5 · The AI verdict is an opinion, not a finding
**Reviewed 2026-09-14 · next review 2027-03-01**

Field accuracy for construction vision models runs roughly 70–90%. Shield states
the model and confidence with every verdict, and the certification says
explicitly that an assessment is not a finding of code compliance.

*A new finding here would be a place where a model opinion is treated as fact —
gating money, minting a badge, or appearing in the export without its
confidence.*

---

### AR-6 · The operator can destroy the record
**Reviewed 2026-09-14 · next review 2027-03-01**

The hash chain makes tampering *detectable*, not impossible. Anyone with
database ownership can drop the triggers and rewrite the whole chain
consistently. What they cannot do is preserve a head hash that has already left
the building — which is why practice 7 in `PROTECTION.md` tells the buyer to
export and keep one.

Not closable without an external anchor (RFC 3161 timestamp on the chain head).
Cheap and worth doing; not built.

*A new finding here would be a way to alter history while preserving a
previously exported head, which would defeat the chain rather than merely
outrunning it.*

---

### AR-7 · `codes.py` covers 9 trades, not 5,500 jurisdictions
**Reviewed 2026-09-14 · next review 2026-12-01**

45 checkpoints against the 2021 IRC / 2020 NEC family, with no local amendments.
A competitor claims 5,500 jurisdictions. This is a licensing decision, not a
vulnerability.

*A new finding here would be a citation that is wrong or dangerously outdated —
which is a correctness issue worth reporting.*

---

### AR-8 · Tail truncation is undetectable without an externally held head
**Reviewed 2026-09-14 · next review 2027-03-01**

Deleting entries from the end of a custody chain leaves a shorter chain in
which every remaining link verifies. The package's own `head_hash` does not
help — an operator who truncates updates it too. Found by `audit/fuzz.py` in
under a minute of random chain mutation, which is the kind of thing a machine
finds and a reader does not.

This is a property of hash chains, not a fixable bug. The mitigation shipped
with it: `verifier/shield_verify.py --expect-head <hash>` compares against a
head the recipient obtained earlier from their own records, which detects
truncation and full rewrite alike. A verification run with no expected head
now says what it could not check rather than passing silently.

Operationally this makes one habit load-bearing: **the head hash must leave
the building** — in the close-out packet, in an email to the adjuster, in an
RFC 3161 timestamp, in the customer's own system. A head that only ever lived
on our servers protects nobody.

*A new finding here would be: a way to defeat an externally held head, or a
path where Shield fails to give the head to the party who needs it.*

---

### AR-9 · The capture-challenge store is per process
**Reviewed 2026-09-15 · next review 2026-12-01**

`attestation.ChallengeStore` keeps live capture nonces in process memory. Under
more than one gunicorn worker, a challenge issued by worker A is invisible to
worker B, so a legitimate capture can be rejected and the single-use guarantee
depends on which worker answers the second request.

Accepted for now because nothing issues challenges yet: App Attest and Play
Integrity require a native app, both Shield frontends are web pages, and every
real upload today is tier `unattested`. The store has no traffic to get wrong.

It stops being acceptable the moment the native app ships. The fix is a shared
store — the database or Redis — behind the same `issue`/`consume` interface;
only `_live` changes. This is written down here rather than left as a code
comment because the failure mode is silent under load and looks like a flaky
client.

*A new finding here would be: challenges being issued in production while this
is still in-memory, or a shared implementation that loses single-use under
concurrency.*

---

### AR-10 · `gps_corroborated` names a corroboration it does not perform
**Reviewed 2026-09-15 · next review 2026-12-01**

`integrity.assess()` returns `gps_corroborated`, and `routes.py` ships it in the
API response (lines 577 and 617). The field compares EXIF GPS against the
app-reported position — **both supplied by the same party, in the same request.**
It cannot fail for anyone willing to write EXIF, which takes about twelve lines
with `piexif`, the same library that reads it. This is the finding that produced
"EXIF is not evidence"; the field survived the reframe that the finding caused.

The geofence in `upload_photo` is the honest check and is unaffected: it measures
the reported position against a site the **buyer** fixed at purchase, which is
the one reference point the contractor does not supply.

Accepted by the project owner on 2026-09-15, with the exposure understood: a
third party integrating against this API reads `gps_corroborated: true` as a
statement that the location was corroborated. In a contested proceeding it is
one question — *who supplied both values you compared?*

The fix is a rename, not an algorithm: the field states that two self-reported
positions agree with each other, which is a real and mildly useful signal under
an honest name. Nothing else in the record depends on it.

*A new finding here would be: this field being cited as corroboration in an
export, a certification, or anything a customer reads — that crosses from an
accepted limit into an overclaim, which `SECURITY.md` treats as a defect.*

---

### AR-11 · `exif_captured_at` is a signed chain field the subject controls
**Reviewed 2026-09-15 · next review 2026-12-01**

`exif_captured_at` is one of `ledger.SIGNED_FIELDS`, so it is sealed into the
custody chain — and it is read from EXIF `DateTimeOriginal`, which the uploader
writes. The chain proves the value was not altered *after* it was recorded. It
says nothing about whether the value was true when it arrived.

The consequence is specific and currently dormant: `corroborate.py` computes
solar azimuth and elevation from `(lat, lng, captured_at)`. The astronomy is
exact and the sky is not editable — but if that check is ever wired to this
field, an attacker with a photograph simply declares the capture time whose sun
position matches the shadows already in it. The physics would be perfect and the
input adversarial. `corroborate.py` is imported by `routes.py` and never called,
so nothing ships from it today.

Accepted by the project owner on 2026-09-15. Removing the field from the signed
set is not a small change: the canonical form would change, which means
`chain_version` 1 → 2 and a re-chain of every row ever written.

The server-side times are the trustworthy ones and already exist: `received_at`
in `upload_photo` and `recorded_at` on every chain entry. They prove "not
after", never "not before" — and the export says so.

*A new finding here would be: solar corroboration wired to `exif_captured_at`
without anchoring the time to `received_at`, or any export presenting the EXIF
capture time as established rather than asserted.*
