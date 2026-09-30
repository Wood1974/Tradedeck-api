# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Guidance for Claude Code (or any agent) working in this repo. This is the
**Flask API backend** for TradeDeck, a marketplace app connecting
homeowners, general contractors, and workers around a full-transparency
trust system and milestone-based escrow. The frontend lives in the sibling
`tradedeck` repo (`Wood1974/Tradeneck`) — see that repo's CLAUDE.md.

This file had gone **stale since its original writing** — real work kept
landing (escrow hardening, a KSL scraper, an entire second Shield service)
without anyone updating this doc alongside it. Rewritten Sep 2026 against
the actual code, after reconciling with a second branch that had also
drifted independently. **Verify against the code, not this file's git
history, before trusting a claim here** — it has been wrong before.

## What this service actually is now (verified from the code)

A **Supabase-native** Flask API (`app.py`, 14 routes). It uses the Supabase
service-role key and enforces authorization in Flask; it does **not** have
its own user database, and there is no SQLite anywhere in it despite what
older notes said.

- **Auth (`auth.py`)** — every protected route is gated by `require_auth`,
  which verifies a Supabase user JWT. Also holds the draw/schedule
  authorization helpers (`require_draw_access`, `require_draw_owner`,
  `require_draw_payee`) and `draw_payee_id(draw)`, which reads
  `draws.payee_id` (falling back to a legacy `contractor_id` if present) —
  the column the `accept_application` RPC (see below) sets on hire.
- **Config (`config.py`)** — `validate_env()` fails fast on missing
  required env vars.
- **Escrow (`escrow.py`)** — Stripe escrow **state machine**: manual-capture
  PaymentIntents, an explicit allowed-transition table (pending → held →
  released/refunded), idempotency keys on every Stripe call, Connect
  transfers to the payee minus a platform fee (`PLATFORM_FEE_BPS`), and
  refund-vs-cancel logic.
- **Jobs (`app.py`)** — `GET /api/jobs` (filter by trade/location/status,
  paginated) and `POST /api/jobs` (auth'd), reading/writing the Supabase
  `jobs` table.
- **Escrow + draw routes (`app.py`)** — `POST /stripe/connect/onboard`,
  `POST /stripe/escrow/{create,release,refund}`, `GET /draws/<id>`,
  `POST /draws/<id>/approve`, `POST /draws/<id>/photos/upload` (uploads to
  the `draw-photos` bucket, runs a Claude Vision quality score),
  `GET /draws/<id>/photos`, `POST /stripe/webhook`.
- **KSL scraper (`ksl_scraper.py`, wired into `app.py`)** — this resolves
  what older notes called "a separate standalone project, not part of
  either repo": it's built directly into this Flask app now. Filters to
  Wasatch-surrounding counties (`COUNTY_CITIES`), filters to actual
  construction listings (`CONSTRUCTION_KEYWORDS`), then classifies into 15
  trade categories (`TRADE_RULES`, first-match-wins) before upserting into
  `jobs` (`source='ksl'`, deduped on `external_url`). Exposed at
  `GET /api/ksl/scrape` (cron-friendly, no auth — write-only and
  idempotent). **Nothing in this repo's `render.yaml` schedules it** — the
  live DB clearly grows daily (confirmed by direct count), so something
  external is calling this route on a schedule; find and document that
  scheduler before assuming it's this repo's problem to add one.
- **TradeDeck Shield (`shield_api.py`, blueprint at `/shield`, registered
  in `app.py`)** — the original Shield module (~900 lines): per-trade AI
  checkpoints with IRC/IBC/NEC references, photo upload with EXIF
  extraction and chain-of-custody logging, analyze/generate-points,
  Stripe payment intents, contractor subscribe, complete-job, webhook. This
  is what's actually live in production — it's what the frontend's
  `shield.js` calls at `tradedeck-api.onrender.com/shield/*`.
- **A second, independent `shield/` subsystem now also lives in this
  repo — do not confuse it with `shield_api.py` above.** It is a
  self-contained evidence/attestation service (`shield/README.md`:
  *"imports nothing from the parent app"*), with its own `Procfile`,
  `render.yaml`, `requirements.txt`, auth, DB layer, a hash-chained custody
  ledger, solar-geometry photo corroboration, an FRE 902(13)/(14)
  evidentiary export, a documented independence/pricing policy
  (`INDEPENDENCE.md`, `PRICING.md`), and a 200+-test suite plus daily
  red-team fuzzing (`shield/audit/`, two new GitHub Actions workflows:
  `shield-audit.yml`, `shield-fuzz.yml`). Its own README says the intent is
  eventually to `git subtree split --prefix=shield` it into its own repo.
  **`app.py` does not import anything from `shield/`** — it's not wired
  into the deployed API at all yet. Treat it as a separate, more advanced,
  not-yet-deployed successor project sitting alongside the live one; don't
  "integrate" it into `app.py` without deliberately deciding to replace
  `shield_api.py`, and don't assume familiarity with `shield_api.py`
  transfers to `shield/` — they're unrelated implementations of the same
  idea at very different maturity levels.
- **Dead weight still sitting in the repo root, unwired to any Flask
  route** (the only route serving `/` returns a JSON status): `tradedeck.html`,
  `tradedeck-newest.html`, `tradedeck-final.html`, `tradedeck-merged.html`.
  These are static app-UI builds that don't belong in a Flask API repo —
  `tradedeck-newest.html` has at least been used as reference material for
  frontend work, so don't delete any of these without confirming nothing
  still depends on them being here.

## Data layer

- **Supabase Postgres** (project `jlaajejpqjldpbinktln`), not SQLite. The
  live DB has 25+ tables, all RLS-enabled, plus write-once/append-only
  triggers protecting the Shield custody tables.
- SQL that must be applied to Supabase lives in `supabase/migrations/`.
  Beyond the original security/webhook migration, this now includes:
  `20260911140000_accept_application_rpc.sql` (hire flow — see below),
  `20260911150000_tier_inputs.sql` (tier machinery — see below), and five
  Shield migrations from 14–20 Sep (`shield_schema_and_rls`,
  `shield_hardening`, `shield_field_notes`, `shield_retake_index`,
  `shield_standalone_schema`) backing the new `shield/` subsystem. All of
  the Sep 11 migrations were verified **live** against the project this
  session (not just committed) — `accept_application` and the tier
  triggers are real, callable objects in the current database.

## Accept-application → payee flow

`accept_application(p_application_id uuid)` — `SECURITY DEFINER`,
authorization-checked against `auth.uid()` (only the job owner can accept),
granted to `authenticated` only. Atomically: accepts that application,
rejects the other open applications on the same job (single-hire model),
and sets `payee_id` on the job's `draw_schedules` row **and** every `draw`
under it — the column `auth.draw_payee_id()` / `require_draw_payee` reads.
Called from the frontend's `hireApplicant()`. Verified end-to-end (happy
path + non-owner denial) against the live DB.

## Tier / trust machinery

`jobs_completed` increments for the payee when a job's draws are all
`released`; `tier` (Verified → Active → Proven → Trusted → TradeDeck Pro)
is derived from `jobs_completed` + `rating` on every profile write.
`rating` itself recomputes from `reviews` via an existing trigger.
Thresholds are a documented **starter** formula — timeline adherence, cost
variance, and cleanliness sign-offs aren't captured yet.

## Known breaks / things to watch (Sep 2026)

- **The `shield/` vs `shield_api.py` split above is the biggest
  orientation trap in this repo right now.** Read it before touching
  anything Shield-related.
- **Render may drift from git.** If the deployed service behaves
  differently from this repo, redeploy from git to reconcile, then trust
  git. There is no `/internal/deploy` route anymore — it wrote arbitrary
  files into the running container behind a single secret and has been
  removed entirely, along with `/internal/analyze-photos` (previously
  gated behind a hardcoded key, now deleted outright rather than gated —
  don't re-add it).
- **KSL scraper scheduling is undocumented.** `GET /api/ksl/scrape` exists
  and is unauthenticated by design (cron-friendly), but nothing in this
  repo declares who calls it. The live table grows daily regardless, so
  *something* external is hitting it — track that down rather than
  assuming a cron needs to be added here.
- Four dead static HTML files at repo root (see above) keep accumulating
  instead of shrinking — flag rather than silently delete.
- Nothing below `jobs` had real production rows as of last direct check
  (0 applications, 0 draw_schedules, 0 draws, 0 escrow rows) — the hire →
  escrow → release path has never run end-to-end for a real user.

## Environment variables (set in Render; never commit real values)

- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` — Supabase (service role).
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_SHIELD_PRICE_ID`.
- `ANTHROPIC_API_KEY` — Claude Vision photo review + Shield analysis.
- `APP_URL`, `ALLOWED_ORIGINS`, `DRAW_PHOTOS_BUCKET`, `PLATFORM_FEE_BPS`,
  `MAX_IMAGE_BYTES`, `ANTHROPIC_MODEL`, `JOBS_PAGE_SIZE` — see `config.py`.
- The standalone `shield/` subsystem has its **own** `render.yaml` and
  `.env.example` — its environment is not this app's; don't assume shared
  config.

## Deployment

- Render: `tradedeck-api.onrender.com`, via `Procfile` (`gunicorn app:app`)
  and `render.yaml` — this deploys `app.py` (and therefore `shield_api.py`
  via its blueprint registration), **not** the standalone `shield/`
  subsystem, which has never been deployed from this repo.
- The KSL scraper now lives *in* this service (see above) rather than
  bypassing it — update that assumption anywhere else it's written down.

## Conventions / working notes

- Solo-founder project (Joshua), iterating fast across many chat
  sessions/agents in parallel, sometimes on genuinely large independent
  efforts (the `shield/` subsystem is ~28k lines of net-new code from a
  single other session). Expect real architectural drift between branches,
  not just stale docs. **Before building on a feature, check the live code
  and the live DB — and check whether another open branch already touched
  the same area before redoing the work.**
