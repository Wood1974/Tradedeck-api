# TradeDeck Shield — standalone API

Verified construction photo documentation. A contractor photographs code-anchored
checkpoints; the service seals each photo's bytes, corroborates where and when it
was taken, adjudicates it against the cited building-code section, and keeps an
append-only chain of custody the homeowner can export.

This directory is **self-contained**. It imports nothing from the parent Flask app
and can be lifted into its own repository with history intact:

```bash
git subtree split --prefix=shield -b shield-standalone
```

---

## The one rule

> **Nothing the client sends is trusted as evidence.**

The SHA-256 is computed over the bytes as received, before anything touches them.
The original is stored unmodified and never handed to the model — a stripped,
downscaled copy is. Every input to a verdict is read back from the database, never
from the request that asks for the verdict.

That rule is the product. The code is arranged around it, and the tests exist to
notice when it stops being true.

---

## What changed from the in-tree version

`shield_api.py` in the repo root is the predecessor. It is not a straight port —
six defects made the guarantee unenforceable, and each is closed here.

| Defect in `shield_api.py` | Consequence | Closed by |
|---|---|---|
| `analyze-photo` read `comp_url`, `has_exif`, `gps_*`, `original_hash` from the request body (`:598–607`) | A contractor could upload a real photo, then submit a stock image's URL for grading; the `pass` landed on the real row. The client-supplied hash became the audit record. Also an unvalidated server-side fetch (SSRF). | `POST /shield/photos/<id>/analyze` takes the id and **nothing else**. Every value is read from `shield_photos`; the signed URL is minted here from the stored path. |
| `amount_cents` came from the body, no price table, no ownership check (`:326`) | Shield purchasable on any job for one cent | `pricing.py` — server-side tiers, client figure ignored, `require_shield_job` checks participation |
| `piexif` reads JPEG/TIFF only, but HEIC/PNG/WebP were accepted (`:79–92`) | Every iPhone HEIC upload stamped *"possible screenshot"* | Pillow fallback + a third state: `unsupported` ≠ `absent`. Only `absent` is treated as a signal. |
| GPS compared in raw degrees against a fixed `0.005` (`:120`) | Tolerance drifted with latitude — 556 m at the equator, 278 m at 60°N | `integrity.haversine_m()` and an explicit metre threshold |
| `IP_HASH_SALT` fell back to a literal in the repo (`:197`) | IPv4 is 2³² values; a known salt makes the hash *be* the address | Required config. The service refuses to boot without it. |
| Custody check was `verdict in ('flagged','fake','fail')` but the model returns `'flag'` (`:729`) | Flagged photos never wrote their flag event | Corrected tuple, covered by a test |

Two smaller ones: checkpoint indexing silently mis-cited when the model returned
more points than a trade has (`codes.code_entry` now bounds it), and webhook
idempotency checked-then-acted-then-recorded, so concurrent deliveries could both
pass (the event is now claimed before any work).

---

## Layout

```
shield/
├── app.py          Flask factory, CORS, security headers, health
├── routes.py       HTTP surface — the trust boundary
├── integrity.py    hashing, EXIF, haversine, compression
├── vision.py       Claude calls (structured outputs, prompt caching)
├── codes.py        IRC/IBC checkpoint map — 9 trades × 5 checkpoints
├── pricing.py      server-side price tiers
├── auth.py         Supabase JWT + shield-job authorization
├── config.py       env validation, fails fast
├── db.py           Supabase client
└── tests/          33 tests, several regressions against the table above
```

`codes.py` is the asset. Nine trades, 45 checkpoints, each carrying a real code
citation (`IRC R403.1.6` anchor bolts, `NEC 250.52(A)(3)` Ufer grounds), what the
photo must frame, and what the frame has to prove. It was extracted
programmatically from the original so nothing drifted in the move. It is data, not
logic, so a licensed contractor can review it without reading Python.

**Code currency:** citations track the 2021 IRC / 2020 NEC family. Jurisdictions
adopt on their own schedule and amend locally — before selling into a new market,
have someone licensed there confirm the adopted edition.

---

## Running it

```bash
cp shield/.env.example shield/.env     # fill in; six values are mandatory
pip install -r shield/requirements.txt
python -m pytest shield/tests -q
gunicorn --chdir shield --bind 0.0.0.0:$PORT app:app
```

The database is `supabase/migrations/20260914000000_shield_schema_and_rls.sql`
in the repo root. Run its verification queries against the target project first —
the schema was reconstructed from code, and query 1 surfaces anything it missed.

`IP_HASH_SALT` has no default. Generate once:
`python -c "import secrets; print(secrets.token_urlsafe(32))"`. Changing it later
makes every previously stored uploader-IP hash uncorrelatable.

---

## API

All `/shield/*` routes need `Authorization: Bearer <supabase-jwt>` except the
webhook, which authenticates by Stripe signature.

| Route | Purpose |
|---|---|
| `POST /shield/quote` | Price for a job budget. Advisory — recomputed at purchase. |
| `POST /shield/jobs` | Create a pending job + PaymentIntent at the server price |
| `POST /shield/jobs/<id>/checkpoints` | Generate 5 checkpoints, attach code citations |
| `GET  /shield/jobs/<id>/checkpoints` | List them |
| `POST /shield/jobs/<id>/photos` | **The integrity anchor.** multipart: `file`, `point_id`, `gps_lat`, `gps_lng` |
| `POST /shield/photos/<id>/analyze` | Adjudicate. No body. |
| `GET  /shield/jobs/<id>/custody` | The audit trail — the deliverable |
| `POST /shield/jobs/<id>/complete` | Close-out packet, hashed server-side |
| `POST /shield/subscribe` | Contractor subscription checkout |
| `POST /shield/webhook` | Stripe events |

Roles: only the assigned contractor uploads; either participant reads; a
non-participant gets `404`, not `403`, so ids can't be probed.

### Integration

Shield never writes another product's tables. The parent set
`profiles.tradedeck_verified` directly, which is why it could not be separated.
Here, a contractor reaching `MIN_CLEAN_JOBS` clean completions fires
`shield.contractor_verified` at `BADGE_WEBHOOK_URL`, and consumers decide what a
badge means in their own system. `external_ref` on a Shield job carries the
caller's own job id, so TradeDeck is one API consumer among many.

---

## Testing

33 tests, all passing. They cover hashing stability, GPS corroboration and spoof
detection against real EXIF-bearing JPEGs, the `unsupported`/`absent` distinction,
that compression strips metadata and never mutates the original, price-tier
boundaries including hostile input, code-map completeness, and verdict derivation.

**Not yet covered:** no integration test runs against a live Supabase or Stripe —
the storage, database, and model calls are unexercised here. Stand the migration up
against a staging project and walk one job end to end before trusting this with a
paying customer.

---

## Known gaps

- **GPS is still device-reported.** EXIF corroboration raises the cost of faking a
  location but does not eliminate it — a determined uploader controls both the file
  and the reported position. The honest claim is *"corroborated by two independent
  sources"*, never *"GPS-verified"*. `gps_corroborated` is true only when EXIF
  independently agrees, and the model is told which case it is looking at.
- **No frontend.** Deliberate — this is API-only. The previous browser client is
  not portable: it never called the upload route, asserted its own hashes, wrote to
  the wrong bucket, and threw a `ReferenceError` on its main path.
- **No rate limiting.** Add it at the edge before public exposure; the upload and
  analyze routes both cost real money per call.
- **Custody export is JSON.** A signed PDF is what an adjuster or a court actually
  wants, and it is the obvious next increment.
