# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Guidance for Claude Code (or any agent) working in this repo. This is the
**Flask API backend** for TradeDeck, a marketplace app connecting
homeowners, general contractors, and workers around a full-transparency
trust system and (planned) milestone-based escrow. The frontend lives in
the sibling `tradedeck` repo (`Wood1974/Tradeneck`) — see that repo's
CLAUDE.md for product context.

This file reflects the **actual repo contents as of Sep 2026**, verified
by reading `app.py` directly — not carried over from planning notes, which
had drifted significantly from what's actually here.

**Sep 2026 update**: Draw/escrow functionality removed to align Shield as a 
standalone evidence verification system. Shield operates independently from 
job payment workflows.

## What this service actually does

- **Its own auth system**, entirely separate from the frontend's Supabase
  Auth: `/api/auth/register`, `/api/auth/login`, `/api/auth/me`. Passwords
  are hashed as `sha256(password + SECRET_KEY)` (a static, code-committed
  fallback secret if `SECRET_KEY` isn't set in the environment) and
  sessions are a base64-encoded JSON payload + HMAC-SHA256 signature — not
  a standard JWT library, and not bcrypt/scrypt/argon2 for password
  hashing. **This needs attention before real users register**: weak
  hashing, and it means a user account created via the frontend's Supabase
  sign-up does not exist here, and vice versa. Two disconnected user
  databases currently, not one system with two entry points.
- **Jobs**: `GET/POST /api/jobs`, `POST /api/jobs/<id>/apply` — native
  TradeDeck job postings and applications, backed by SQLite.
- **Live leads aggregator** (this was not documented anywhere in prior
  project notes — found by reading the code): `GET /api/live-leads`,
  `POST /api/live-leads/refresh`. Pulls and stores listings from Indeed
  (RSS), Craigslist Salt Lake (RSS), SAM.gov opportunities API, and
  ZipRecruiter API, filtered/tagged by a `TRADE_KEYWORDS` map (Framing,
  Concrete, Roofing, Electrical, Plumbing, HVAC, Excavation, Flooring,
  Siding, Painting, Finish Carpentry, General) and a `UTAH_CITIES` list.
  Writes to this service's own SQLite DB.
- **GC leads**: `GET /api/gc-leads`, `POST /api/gc-leads/refresh` — building
  permit data from a PermitStack API, similarly filtered by trade.
- **Chat**: `POST /api/chat` — a thin proxy to the Anthropic Messages API
  (`claude-haiku-4-5-20251001`) using `ANTHROPIC_API_KEY`. This is the only
  use of the Anthropic key in this codebase — there is **no photo-quality
  AI check** implemented here despite that being described in prior notes
  as built.
## Data layer

- **SQLite**, on Render's persistent disk (`DB_PATH`, default
  `/var/data/tradedeck.db` per `render.yaml`). This is the real, live
  datastore for everything this service does — not a legacy fallback.
- **No Supabase usage anywhere in this codebase.** The frontend's move to
  Supabase Auth (in `index.html`) has no counterpart here. If the plan is
  to consolidate on Supabase, this service's auth, jobs, and leads tables
  would all need to move — that's a real migration, not a config change.
- `tradedeck_schema.sql` (Supabase: profiles, jobs, applications, draws) was
  reconstructed fresh this session and verified against a local Postgres
  instance — it targets Supabase, and has **no relationship to this
  service's SQLite schema** (defined inline in `app.py`'s `init_db()`).
  Reconciling the two schemas is unresolved.

## Architecture (Sep 2026)

**Shield and TradeDeck are completely standalone applications** sharing the 
tradedeckapp.com domain but operating independently:

- **Shield**: Standalone evidence verification system with photo analysis, 
  integrity verification, and contractor scoring. No integration with jobs.
- **TradeDeck**: Simple job marketplace. Post fixed-price job → apply → hire → pay.
  No draws/milestones, no escrow, no multi-stage payments.

Draw/milestone/escrow functionality was **intentionally removed** to align 
with Shield's architecture. Draw/escrow concepts belong to job-workflow 
payment splits; Shield handles evidence collection independently. Stripe 
payment processing is retained for fixed-price job payments and Shield Pro 
subscription billing only.

Files deleted: `escrow.py` (complete payment state machine, no longer used).

## Environment variables (see `render.yaml` / set in Render dashboard — never commit real values)

- `DB_PATH` — SQLite file path (Render disk-backed).
- `PERMITSTACK_KEY`, `SAM_API_KEY`, `ZIPRECRUITER_KEY` — lead source APIs.
- `ANTHROPIC_API_KEY` — used only by `/api/chat`.
- `IDENTITY_RECEIPT_KEY`, `STRIPE_TEST_SECRET_KEY`, `IDENTITY_TEST_MODE_USER_IDS` — **legacy.** They configure the older ID-check
  code in `identity_api.py` / `identity_core.py` here. The Shield phone app no longer calls this service: it signs on with the standalone
  Shield server (`Wood1974/tradedeck-shield`, which uses `IDENTITY_TEST_MODE_EMAILS`), and the receipt key the app pins is that server's.
  The old key id stays pinned in the app so records signed by it still verify. Nothing is removed here; whether to retire this copy is a
  separate decision.
- `SECRET_KEY` — signs auth tokens and salts password hashes. **Must** be
  set explicitly in Render; the in-code fallback (`'tradedeck-secret-2026'`)
  is not safe for production and is visible to anyone reading this repo.

## Deployment

- Hosted on Render: `tradedeck-api.onrender.com`, via `Procfile`
  (`gunicorn app:app`) and `render.yaml`.

## Conventions / working notes

- **New tables start closed to clients.** Migration `20261020000000` changes the default so tables
  created in `public` give `anon`/`authenticated` nothing. Every migration that adds a table must
  grant what the app needs, explicitly (`grant select ... to authenticated`), and enable RLS.
  Tables created before that date still carry the old full-access default; they need a separate audit.

- Solo-founder project (Joshua), iterating fast across many sessions —
  expect drift between what's described as "done" elsewhere and what's
  actually committed here. Verify against `app.py` directly before
  building on top of a feature.
- Before adding new functionality, resolve (or at least flag to the
  project owner) the dual/disconnected auth systems.

## Working rules (set by the owner)

Standing instructions from the owner. They apply to every session in this repo, so don't wait to be told again.

- **Fix the root cause, once.** No workarounds or "for now" patches. If the real fix is bigger than asked, say so and propose it.
- **Say what was verified and what wasn't.** Never overstate. If something couldn't be run or checked (a device, a live server, a dashboard), say that plainly.
- **The owner merges.** Open PRs as drafts and leave them. Don't merge, and don't start TestFlight or store builds or change live settings (Render env vars, DNS, Stripe, Apple) without the owner's go.
- **Don't watch PRs.** Opening a PR subscribes the session automatically; unsubscribe right away. Check CI only when asked.
- **Decide before building** anything that changes who can see data, what leaves the phone, or what costs money: ask first, with a recommendation.
- **Never print or repeat a password, key or token.** If one has been exposed (in chat, a screenshot, a log), say so plainly so it gets rotated.
- **Say early which steps only the owner can do** (DNS at GoDaddy, the Render shell, the Apple portal, rolling the Stripe key, merging).
- **Render: read freely, change only with permission.** Reading is allowed without asking: services, deploy history, logs, metrics, and the *names* of environment variables (never print a value). Anything that changes Render (environment variables, deploys or restarts, creating, suspending or deleting a service, disk or database) needs the owner's go each time, and says first exactly what it will change.
- **Keep status updates short.** Long reports only when asked.
