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

Storage, database and model calls are unexercised. All 195 tests and 27
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
