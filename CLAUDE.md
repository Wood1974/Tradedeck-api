# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Guidance for Claude Code (or any agent) working in this repo. This is the
**Flask API backend** for TradeDeck, a marketplace app connecting
homeowners, general contractors, and workers around a full-transparency
trust system and (planned) milestone-based escrow. The frontend lives in
the sibling `tradedeck` repo (`Wood1974/Tradeneck`) — see that repo's
CLAUDE.md for product context.

This file reflects the **actual repo contents as of Aug 2026**, verified
by reading `app.py` directly — not carried over from planning notes, which
had drifted significantly from what's actually here.

## What this service actually does (verified from app.py, 631 lines)

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
  **This overlaps in purpose with the KSL Jobs scraper** built separately
  this session (see the tradedeck repo notes) — that scraper writes
  directly to Supabase, this aggregator writes to this service's own
  SQLite DB, and neither currently knows about the other. Worth deciding
  whether to consolidate before building more lead sources.
- **GC leads**: `GET /api/gc-leads`, `POST /api/gc-leads/refresh` — building
  permit data from a PermitStack API, similarly filtered by trade.
- **Chat**: `POST /api/chat` — a thin proxy to the Anthropic Messages API
  (`claude-haiku-4-5-20251001`) using `ANTHROPIC_API_KEY`. This is the only
  use of the Anthropic key in this codebase — there is **no photo-quality
  AI check** implemented here despite that being described in prior notes
  as built.
- Two static HTML files sit in this repo's root, **not wired to any Flask
  route** (the only route serving `/` returns a JSON status, not either of
  these): `tradedeck.html` and `tradedeck-newest.html`. These appear to be
  full app-UI builds that ended up in the wrong repo. `tradedeck-newest.html`
  was the more complete of the two (has a Site Photos/CompanyCam tab) and
  was used this session as the basis for the frontend's new `app.html` —
  see the tradedeck repo. Consider deleting these two files from this repo
  once you've confirmed nothing still depends on them being here.

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

## What's described elsewhere but NOT in this repo (verified absent)

- No Stripe Connect integration, no escrow logic, no draw/milestone
  endpoints, no photo upload or AI photo-quality-check code — despite
  earlier notes describing all of this as "built Aug 2026." Confirm with
  the project owner whether this exists uncommitted somewhere before
  re-building it from scratch.

## Environment variables (see `render.yaml` / set in Render dashboard — never commit real values)

- `DB_PATH` — SQLite file path (Render disk-backed).
- `PERMITSTACK_KEY`, `SAM_API_KEY`, `ZIPRECRUITER_KEY` — lead source APIs.
- `ANTHROPIC_API_KEY` — used only by `/api/chat`.
- `SECRET_KEY` — signs auth tokens and salts password hashes. **Must** be
  set explicitly in Render; the in-code fallback (`'tradedeck-secret-2026'`)
  is not safe for production and is visible to anyone reading this repo.

## Deployment

- Hosted on Render: `tradedeck-api.onrender.com`, via `Procfile`
  (`gunicorn app:app`) and `render.yaml`.
- Intentionally untouched by the KSL scraper and any Windows-hub
  automation — that writes straight to Supabase, bypassing this API. Keep
  that separation; it was a deliberate design choice.

## Conventions / working notes

- Solo-founder project (Joshua), iterating fast across many sessions —
  expect drift between what's described as "done" elsewhere and what's
  actually committed here. Verify against `app.py` directly before
  building on top of a feature.
- Before adding new functionality, resolve (or at least flag to the
  project owner) the two structural issues above: the dual/disconnected
  auth systems, and the dual/overlapping lead-aggregation systems
  (this service's live-leads vs. the standalone KSL scraper).
