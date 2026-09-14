# TradeDeck Shield — standalone evidence API

A contractor photographs building-code-anchored checkpoints on a job. Shield
seals each photo's bytes on arrival, corroborates the claim against facts the
contractor does not control, adjudicates the work against the cited code
section, and keeps a hash-chained custody record that can be verified by
someone who does not trust us.

Self-contained: imports nothing from the parent app.
`git subtree split --prefix=shield` lifts it into its own repo with history.

---

## Start here: what this does and does not prove

A product like this lives or dies on the precision of its claim, so here it is
without marketing.

**Proven, cryptographically, to a third party:**
- These bytes are identical to the bytes the service received. (SHA-256 taken
  before anything touches the file; original stored unmodified, never
  re-encoded.)
- This custody history has not been altered since any published chain head.
  (Each entry hashes its predecessor.)
- These requirements were fixed *before* this work was photographed. (The
  checkpoint schedule locks, and its hash is sealed into the chain.)

**Corroborated, not proven:**
- That the photo was taken at the job site. The geofence measures against a
  location the *buyer* set at purchase, before any photo existed — so it is not
  a value the audited party can move to fit a picture. It is still a claim
  about where a device said it was.
- That it was taken when claimed. Solar geometry for the claimed place and time
  determines shadow direction and length, and there is nothing in a file an
  attacker can edit to change what the sky was doing.

**Not proven, and we say so in the certification:**
- That any photo came off a camera sensor rather than a file picker. Nothing
  here establishes that, and neither does EXIF. Only capture-time attestation
  does — App Attest / Play Integrity / Android Key Attestation binding a photo
  hash to a key in secure hardware — and that needs a native app. Until then,
  the honest phrase is *"corroborated by independent signals"*, never
  *"GPS-verified"*.

Why the precision matters: **EXIF is not evidence.** Shield reads EXIF with
`piexif`; `piexif` also writes it. A stock photo stamped with the site's
coordinates and a plausible timestamp takes about a dozen lines. That attack
was run against an earlier version of this code and returned
`gps_corroborated: True`, `gps_distance_m: 0.1`, `integrity_note: None`. Every
mechanism worked exactly as designed and certified a downloaded image. Metadata
the adversary controls only ever catches lazy fraud.

---

## Layout

```
shield/
├── app.py           Flask factory, CORS, ProxyFix, size limits, health
├── routes.py        HTTP surface — the trust boundary
├── integrity.py     hashing, EXIF, haversine, compression
├── corroborate.py   solar geometry — a signal the uploader cannot edit
├── ledger.py        hash-chained custody, and its verifier
├── verdict.py       completion grading (coverage, severity, badge eligibility)
├── protection.py    live guidance: how strong this record is, what to do next
├── notes.py         contemporaneous field notes — contemporaneity grading, amendments
├── evidence.py      FRE 902(13)/(14) export: manifest, certification, how-to-verify
├── vision.py        Claude calls (structured outputs, prompt caching)
├── codes.py         IRC/IBC checkpoint map — 9 trades × 5 checkpoints
├── pricing.py       server-side price tiers
├── auth.py          Supabase JWT + shield-job authorization
├── config.py        env validation, fails fast
├── audit/           daily red-team: 32 invariants, protocol, accepted-risk ledger
└── tests/           175 tests
```

**`codes.py` is the domain asset** — 45 checkpoints with real citations
(`IRC R403.1.6` anchor bolts, `NEC 250.52(A)(3)` Ufer grounds), each with what
the photo must frame and what the frame must prove. Extracted programmatically
from the original so nothing drifted. *Citations track the 2021 IRC / 2020 NEC
family; jurisdictions adopt on their own schedule and amend locally — have
someone licensed in the target market confirm before selling there.*

**`notes.py` is what makes a photograph mean something.** A photo shows a
state. It does not show the weather, what the inspector said, which sub did the
work, or why the detail departs from the plan — and those are the facts
disputes turn on.

Notes are hearsay and need an exception to be admitted at all. Which one
applies turns almost entirely on **when the note was written**:

| Delay from the observation | Strongest exception available |
|---|---|
| Seconds to ~30 min | **FRE 803(1)** present sense impression — does not require the writer to testify |
| Up to ~2 hours | FRE 803(5) recorded recollection / 803(6) |
| Same day | FRE 803(6) business records |
| More than a day | None. It is recollection, and the export says so. |

So `written_at` is set by the server, never accepted from the client, and the
delay travels with every note into the export. Three consequences shaped the
module, and each is a refusal:

- **The model never writes or rewrites a note.** Not to tidy it, not to expand
  it. A note is the writer's own words or it is contaminated — and a note the
  author cannot swear to on the stand is worth less than no note. Guidance is
  deterministic text analysis; the author decides.
- **Notes are append-only.** The first question on cross is whether the note
  says what it said at the time. Corrections are amendments: both versions
  kept, both timestamped, both in the chain. A visible correction is credible;
  a silent one takes the record down with it.
- **Guidance never blocks a save.** A contractor on a roof in the wind must be
  able to write and move on. Guidance that refuses produces no note at all.

Because 803(1) reaches *descriptions and explanations* but not opinions, the
quality check steers away from conclusions: "looks good, all to code" is flagged
as an inference a reader cannot check, while `5'2" between anchor bolts, 14
bolts, tape in frame` scores as strong. Supported media are typed, dictated, and
**a photograph of a handwritten page** — handwritten field notes are a real
construction artefact and carry the same contemporaneity argument.

And the 803(6) phrase with product consequences is *regular practice*: a note
written on some jobs and not others is not one. Prompting at every checkpoint,
every time, and recording whether a note was written, is what establishes it.
The discipline is the evidence.

**`evidence.py` is the deliverable.** FRE 902(14) makes a digital record
self-authenticating when identified by "a process of digital identification" —
a hash comparison — "as shown by a certification of a qualified person." That
is a mechanical requirement, and it is why the upload path hashes before
touching anything. The export produces the manifest, an independent
verification of the custody chain, a pre-filled certification, and the commands
a recipient runs to check all of it themselves.

The certification is deliberately **left unsigned**. It is a sworn statement by
a human who can be cross-examined on it; auto-signing would be exactly the
hollow assurance this product exists to replace. It also states plainly what it
does *not* certify — that the AI is right, or that the work complies with any
code.

---

## The security posture

> **Nothing the client sends is trusted as evidence.**

`POST /shield/photos/<id>/analyze` takes an id and nothing else — no body at
all. Every value handed to the model is read back from the database, and the
signed URL is minted server-side from the stored path.

Defects found by adversarial review and closed here:

| Defect | Consequence | Fix |
|---|---|---|
| Grading dropped unphotographed checkpoints from the vote | 1 photo of 5 reported **"pass"**; repeated close-outs minted the verified badge | `verdict.py`: missing evidence outranks every verdict; badge counts distinct fully-clean jobs; one report per job |
| `point_id` never scoped to the job | Upload against another job's checkpoint → `approved` written onto a stranger's record | Checkpoint must belong to this job |
| Analyze was check-then-act | 20 concurrent calls = 20 billed samples, last writer wins | Conditional write; retakes supersede rather than overwrite |
| Checkpoints re-generatable by either party, forever | Photograph the work, read the verdicts, rewrite the requirements to match | Homeowner-only, locks once, schedule hash sealed into the chain |
| `actor_type` hardcoded `"homeowner"` | Contractor closing his own job was recorded as the buyer signing off | Derived from the job's parties |
| `external_ref` column did not exist | Every `POST /shield/jobs` failed | Added in the hardening migration |
| Activation checked no amount | Nothing bound a PaymentIntent to a job but its own metadata | Match the stored intent id; assert `amount_received` and currency; handle refunds and disputes |
| Storage RLS policy was permissive | It could not deny, and *granted* read on every other bucket | `as restrictive` |
| Custody rows had no links | `DROP TRIGGER` or `TRUNCATE` erased history silently | Hash chain + statement-level truncate trigger |
| X-Forwarded-For read leftmost | Stored IP was whatever the client sent | Rightmost hop + `ProxyFix` |
| Size checked after `read()` | Multi-GB POSTs spooled to disk, then OOM | `MAX_CONTENT_LENGTH` |

---

## Running it

```bash
cp shield/.env.example shield/.env      # six values are mandatory
pip install -r shield/requirements.txt
python -m pytest shield/tests -q        # 175 tests
gunicorn --chdir shield --bind 0.0.0.0:$PORT app:app
```

Migrations, in order, in the repo root `supabase/migrations/`:
`20260914000000_shield_schema_and_rls.sql` then
`20260914010000_shield_hardening.sql`, then
`20260914020000_shield_field_notes.sql`. Run the verification queries at the
bottom of each against the target project first — the schema was reconstructed
from code.

`IP_HASH_SALT` has no default and the service refuses to boot without it.
Generate once: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

---

## API

All `/shield/*` routes require `Authorization: Bearer <supabase-jwt>` except the
webhook, which authenticates by Stripe signature.

| Route | Purpose |
|---|---|
| `POST /shield/quote` | Price for a job budget (advisory; recomputed at purchase) |
| `POST /shield/jobs` | Create a job + PaymentIntent. **Sets the site location.** |
| `POST /shield/jobs/<id>/checkpoints` | Define the schedule. Homeowner only, once. |
| `GET  /shield/jobs/<id>/checkpoints` | List them |
| `POST /shield/jobs/<id>/photos` | The integrity anchor. multipart: `file`, `point_id`, `gps_lat`, `gps_lng` |
| `POST /shield/photos/<id>/analyze` | Adjudicate. No body. |
| `GET  /shield/jobs/<id>/custody` | Raw custody chain |
| `GET  /shield/jobs/<id>/protection` | How strong this record is and the next thing that would strengthen it |
| `GET  /shield/jobs/<id>/evidence` | **Manifest + certification + verification instructions** |
| `POST /shield/jobs/<id>/notes` | Write a field note. `written_at` is server-set. |
| `GET  /shield/jobs/<id>/notes` | Every note on the job, both parties', threaded with amendments |
| `POST /shield/jobs/<id>/notes/<nid>/amend` | Correct a note. Original preserved; reason required. |
| `GET  /shield/jobs/<id>/notes/prompts` | What to ask the author — a blank box gets "done" typed into it |
| `POST /shield/jobs/<id>/complete` | Close out. Requires every checkpoint documented. |
| `POST /shield/subscribe` | Contractor subscription checkout |
| `POST /shield/webhook` | Stripe events |

Only the assigned contractor uploads; either participant reads; a
non-participant gets `404`, not `403`, so ids cannot be probed.

Shield never writes another product's tables. A contractor reaching
`MIN_CLEAN_JOBS` fully-clean jobs fires `shield.contractor_verified` at
`BADGE_WEBHOOK_URL`; consumers decide what a badge means in their own system.

---

## Getting the strongest protection

See **[PROTECTION.md](PROTECTION.md)** — generated from `protection.py`, so the
guide and the live endpoint cannot drift apart. `GET /jobs/<id>/protection`
returns the same practices scored against the job as it actually stands, because
guidance in a README is guidance nobody follows: *"write the note now"* is useful
at minute two and worthless at hour six.

The practice almost nobody thinks of is exporting the package and keeping the
chain head hash somewhere outside this service. It is the only one that protects
the buyer against **us** — the chain makes tampering detectable, but only if
someone holds an earlier head to compare against.

---

## Daily adversarial audit

`shield/audit/` holds 22 **invariants** — one per exploit closed in this branch,
each named for the attack it prevents rather than the code it inspects. They run
in CI on every push touching `shield/` or the migrations, so a guard cannot be
removed by a refactor that leaves the behaviour tests passing.

```bash
python audit/invariants.py          # exit 1 if any closed exploit reopened
```

A scheduled agent runs `audit/PROTOCOL.md` daily against a rotating attack
surface. Its first rule is about noise: **silence is a valid and expected
outcome.** A report listing the same fifteen issues every morning is ignored by
Friday and cancelled the following Tuesday — worse than no audit, because it
manufactures the feeling of being watched without the fact of it. So the agent
reports new findings and regressions only, checks `accepted-risks.md` before
reporting anything, and opens nothing on a quiet day.

The audit never touches production. Code and schema only.

---

## Known gaps

Ranked by how much they would raise evidentiary strength.

1. **No capture attestation.** The single biggest gap. App Attest
   `generateAssertion(clientDataHash:)` binds a photo's SHA-256 to a
   Secure-Enclave key; Android Key Attestation's `attestationApplicationId` and
   `verifiedBootState` do the equivalent. Needs a native app with no
   library-import code path. Worth reading Guardian Project's `simple-c2pa`
   first — it is open source and already C2PA-conformant on both platforms.
2. **No RFC 3161 timestamp on the chain head.** Cheap and standard; makes the
   time of record something other than our own assertion. Free TSAs exist;
   check their terms for commercial use.
3. **No rate limiting.** Upload and analyze both cost real money per call. Add
   it at the edge before public exposure.
4. **No integration tests** against live Supabase, Stripe or Anthropic. Storage,
   database and model calls are unexercised here — walk one job end to end on
   staging before a paying customer.
5. **No WORM storage or retention policy.** Object-lock the originals; document
   retention and legal hold.
6. **Certification is text, not PDF.** A signed PDF is what actually gets
   emailed to an adjuster.

Deliberately *not* on this list: blockchain anchoring. In a construction
dispute nobody contests whether a hash was published before a date — they
contest what the photo depicts. It solves a problem this product does not have.
