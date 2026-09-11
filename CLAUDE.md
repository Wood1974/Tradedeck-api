# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Guidance for Claude Code (or any agent) working in this repo. This is the
**Flask API backend** for TradeDeck, a marketplace app connecting
homeowners, general contractors, and workers around a full-transparency
trust system and milestone-based escrow. The frontend lives in the sibling
`tradedeck` repo (`Wood1974/Tradeneck`) — see that repo's CLAUDE.md for
product context.

This file was **rewritten Sep 2026 against the actual code and the live
Supabase database.** The previous version described a completely different
service (SQLite, its own weak auth, live-leads aggregator, "no escrow
code") — that service has since been **replaced**. None of it is in this
repo anymore. **Verify against the code, not against history.**

## What this service actually is now (verified from the code)

A **Supabase-native** Flask API. It uses the Supabase service-role key and
enforces authorization in Flask; it does **not** have its own user database.

- **Auth (`auth.py`)** — every protected route is gated by `require_auth`,
  which verifies a **Supabase user JWT** (`supabase.auth.get_user(token)`).
  The old SQLite auth with `sha256(password + SECRET_KEY)` is gone. **The
  dual-disconnected-auth problem from the old notes is resolved:** one user
  system (Supabase) across frontend and backend. `auth.py` also holds the
  draw/schedule authorization helpers and the ownership decorators
  (`require_draw_access`, `require_draw_owner`, `require_draw_payee`).
- **Config (`config.py`)** — `validate_env()` fails fast on missing
  required env vars; centralizes optional defaults.
- **Escrow (`escrow.py`)** — a real Stripe escrow **state machine**:
  manual-capture PaymentIntents, an explicit allowed-transition table
  (pending → held → released/refunded), idempotency keys on every Stripe
  call, Connect transfers to the payee minus a platform fee
  (`PLATFORM_FEE_BPS`, default 200 = 2%), and refund-vs-cancel logic.
- **Jobs (`app.py`)** — `GET /api/jobs` (filter by trade/location/status,
  paginated) and `POST /api/jobs` (auth'd). These read/write the Supabase
  `jobs` table.
- **Escrow + draw routes (`app.py`)** — `POST /stripe/connect/onboard`,
  `POST /stripe/escrow/{create,release,refund}`, `GET /draws/<id>`,
  `POST /draws/<id>/approve`, `POST /draws/<id>/photos/upload` (uploads to
  the `draw-photos` bucket and runs a Claude Vision quality score),
  `GET /draws/<id>/photos`, and `POST /stripe/webhook`.
- **TradeDeck Shield (`shield_api.py`, blueprint at `/shield`)** — a full
  new product module (~900 lines): per-trade AI checkpoints with real
  IRC/IBC/NEC code references, `POST /shield/upload-photo` (server-side
  EXIF extraction via piexif, SHA-256 of the untouched original, write-once
  storage to `shield-photos`, a compressed copy for Claude, chain-of-custody
  logging), `/shield/analyze-photo`, `/shield/generate-points`,
  `/shield/create-payment-intent`, `/shield/contractor-subscribe`,
  `/shield/complete-job`, `/shield/webhook`. Registered in `app.py`; if the
  import fails, a stub blueprint exposes the error at `/shield/status`.
- **AI photo review** is real (Claude Vision) — the old note that "there is
  no photo-quality AI check" is obsolete.

## Data layer

- **Supabase Postgres** (project `jlaajejpqjldpbinktln`), not SQLite. The
  old SQLite datastore and its inline `init_db()` schema are gone.
- The live DB has **25 tables, all RLS-enabled**, plus write-once /
  append-only triggers protecting the Shield custody tables. See the
  frontend CLAUDE.md for the full table list.
- SQL that must be applied to Supabase lives in `supabase_security.sql` and
  `supabase/migrations/`. As of Sep 2026 the `stripe_webhook_events` table
  (webhook idempotency, required by `app.py`) **has been applied** and the
  `draws.payee_id` column added. Search_path was pinned on the six flagged
  DB functions. `20260911140000_accept_application_rpc.sql` adds the hire
  RPC (see below). `20260911150000_tier_inputs.sql` adds the tier machinery:
  `jobs_completed` increments for the payee when a job's draws are all
  released, and `tier` is derived from `jobs_completed` + `rating` on every
  profile write (a documented starter formula; rating already recomputes
  from `reviews`).

## Structural issues — status

- **Dual auth: RESOLVED** (Supabase JWT everywhere).
- **Dual/overlapping lead aggregation: N/A now.** The old SQLite
  live-leads aggregator (Indeed/Craigslist/SAM.gov/ZipRecruiter) and
  GC-leads (PermitStack) routes are **no longer in this service.** The KSL
  scraper writing straight to Supabase (`jobs.source='ksl'`, 1,777 rows) is
  the live lead source. If lead aggregation returns, build it on Supabase.

## Known breaks / things to watch (Sep 2026)

- **Contractor draw side — now wired.** `draws.payee_id` is set by the
  `accept_application(p_application_id)` RPC
  (`supabase/migrations/20260911140000_accept_application_rpc.sql`): when a
  job owner hires an applicant in the frontend, it atomically marks the
  application accepted, rejects the siblings, and writes `payee_id` onto the
  job's `draw_schedules` and every `draw` under them — the value
  `auth.draw_payee_id()` / `require_draw_payee` reads. Verified end-to-end
  (happy path + non-owner denial) against the live DB. `escrow.py` needs no
  change; it already reads the payee. What remains is exercising a full
  escrow cycle in Stripe test mode (below).
- **Render may drift from git.** A `/internal/deploy` route used to let code
  be pushed straight into the running container; it has been **removed** now
  that everything is committed. If the deployed service behaves differently
  from this repo, redeploy from git to reconcile, then trust git.
- **Nothing below jobs has been exercised end-to-end** (live DB shows 1
  draw, 0 applications, 0 photos, 0 escrow rows). Run one full escrow cycle
  in Stripe test mode before real users.
- The Shield UI (`shield_merged.js`) and its old host shell
  (`tradedeck-newest.html`) have been **moved out** — `shield_merged.js` now
  lives in the frontend repo as `shield.js`, wired into `index.html` as a
  Shield tab. Only `tradedeck.html` (an older, unwired static build) remains
  in this repo root; it is served by no Flask route and can be deleted once
  you confirm nothing depends on it.

## Environment variables (set in Render; never commit real values)

- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` — Supabase (service role).
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_SHIELD_PRICE_ID`.
- `ANTHROPIC_API_KEY` — Claude Vision photo review + Shield analysis.
- `APP_URL`, `ALLOWED_ORIGINS`, `DRAW_PHOTOS_BUCKET`, `PLATFORM_FEE_BPS`,
  `MAX_IMAGE_BYTES`, `ANTHROPIC_MODEL`, `JOBS_PAGE_SIZE` — see `config.py`.
- `INTERNAL_ANALYZE_KEY` — optional; gates `POST /internal/analyze-photos`.
  Leave unset to keep that route disabled (returns 503). **Never hardcode
  it** — a hardcoded key was removed from `app.py` this session.

## Deployment

- Render: `tradedeck-api.onrender.com`, via `Procfile`
  (`gunicorn app:app`) and `render.yaml`.
- The KSL scraper and any Windows-hub automation write straight to
  Supabase, bypassing this API — a deliberate separation. Keep it.

## Conventions / working notes

- Solo-founder project (Joshua), iterating fast — expect drift between what
  notes claim and what's committed. Verify against `app.py` / `escrow.py` /
  `shield_api.py` / `auth.py` and the live DB directly.
