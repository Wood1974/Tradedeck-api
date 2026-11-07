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

**Nov 2026 reconciliation.** This file was checked line by line against
`render.yaml`, `app.py` and the **live Render account**, because three separate
planning sessions were derailed by statements in here that were untrue. What was
wrong, now corrected below: the **Data layer** claimed the SQLite database sat
on a Render persistent disk (it sits on ephemeral disk and does not survive a
deploy); the Supabase note omitted that `render.yaml` provisions a
`SUPABASE_SERVICE_KEY` anyway; **Deployment** did not record that the standalone
Shield server is deployed **three times over**, twice with its own photo disk.
The infrastructure claims here are now sourced from the live account, not from
memory or from `render.yaml` alone — `render.yaml` and the dashboard disagree,
and **the dashboard is what runs.** Re-verify against both before trusting any
line in this file.

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

> **This section was wrong until Nov 2026 and the error was load-bearing.** It
> claimed the SQLite file sat on a Render persistent disk at
> `/var/data/tradedeck.db` "per `render.yaml`". None of that was true, and at
> least one planning session was built on top of it. Verified below against the
> live Render service and `render.yaml` itself.

- **SQLite, on ephemeral container disk — it does not survive a deploy.**
  `app.py:63` is `DB_PATH = get_env("DB_PATH", "/tmp/tradedeckapp_shield.db")`.
  `render.yaml` declares **no `DB_PATH`** and **no `disk:` block**, and the live
  service (`srv-d9hurcr7uimc73aovmu0`) has no disk attached. With no disk, the
  container filesystem is ephemeral, so this file is lost on **every deploy and
  every restart**. `autoDeploy` is on, triggered by each commit to `main`.
  Everything this service stores — its own auth accounts, native job postings,
  applications, `live-leads`, `gc-leads` — is therefore **not durable today.**
  Do not build anything on this datastore until that is resolved.
  (Unverified: whether `DB_PATH` is set in the Render dashboard. It would not
  help on its own — there is no disk for it to point at.)
- **Resolving it: prefer moving this data to Supabase over attaching a disk.**
  Supabase Postgres already exists, already has RLS, and the frontend already
  authenticates against it. Moving kills the dual-auth problem below in the same
  change. Attaching a disk is the cheap patch and leaves two user databases.
- **No Supabase *client* usage in this codebase** — the frontend's move to
  Supabase Auth has no counterpart here, so there are two disconnected user
  databases. **But note the contradiction:** `render.yaml` provisions
  `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` for this service anyway. The service
  role key bypasses every RLS policy in the project, so either this note is
  stale or that key is exposed for nothing. Settle which, and if it is unused,
  remove it from `render.yaml` and the dashboard.
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

**Escrow state across the two repos — read both before touching it.** Verified
Nov 2026: this service has **no** escrow or draw routes and no `escrow.py`
(`/stripe/connect/onboard` at `app.py:262` does survive). The *frontend* took
the opposite path — it **restored** its escrow/draw client code behind
`ESCROW_ENABLED = false` (Tradeneck `#55`). So the client code exists and is
switched off, while the server endpoints it would call do not exist. Turning
escrow on means restoring routes here **first**. Neither doc is wrong; reading
only one of them is.

**"Standalone" means nothing of Shield belongs in a web browser.** The Shield
phone app (`shield-app/` in the frontend repo) talks only to
`tradedeck-shield.onrender.com` — never to this service. But `shield_api.py`
here (**60.8 KB**, blueprint mounted at `/shield`, `app.py:30–47`) plus the
inline "SHIELD CAPTURE v1" routes (~line 305) and `/api/config/shields` (~824)
exist solely to serve the **older web Shield** (`shield.js`, 95.8 KB, in the
frontend). That web surface is slated for removal, after which nothing calls
any of this. Retiring it is its own decision and its own PR — same treatment as
the legacy `identity_api.py` note below.

## Environment variables (see `render.yaml` / set in Render dashboard — never commit real values)

- `DB_PATH` — SQLite file path. **Not disk-backed.** Not declared in
  `render.yaml`; the in-code default is `/tmp/tradedeckapp_shield.db` and no
  disk is mounted on the service. See **Data layer** above.
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
  **Not declared in `render.yaml`, and whether it is set in the dashboard is
  unverified** (the agent toolset here exposes no read-only env-var listing).
  Confirm it. If it is unset, treat the committed fallback as exposed and
  rotate — but note rotation invalidates live sessions and makes existing
  `sha256(password + SECRET_KEY)` hashes unverifiable, so it needs a password
  reset path. That is a migration, not a config change.
  Related: those password hashes are plain SHA-256 with a shared salt, not
  bcrypt/scrypt/argon2 and not salted per user. Replace before real users
  register — moot if this service's auth moves to Supabase.

## Deployment

- Hosted on Render: `tradedeck-api.onrender.com` (`srv-d9hurcr7uimc73aovmu0`),
  via `Procfile` (`gunicorn app:app`) and `render.yaml`. Python runtime, starter
  plan, Oregon, **no disk** (see **Data layer**). `autoDeploy` on every commit
  to `main`.
- **The standalone Shield server is deployed three times over.** All three
  Render services build `Wood1974/tradedeck-shield` from `main` with autoDeploy
  on, as of Nov 2026:
  | service | disk | health check |
  |---|---|---|
  | `tradedeck-shield` — the phone app's actual target | `shield-data` 10 GB @ `/data` | `/health` |
  | `tradedeck-shield-qtt8` | `shield-data` 10 GB @ `/data` | `/health` |
  | `tradedeck-shield-1` | none | none |
  Two live instances with **separate** photo disks means a sealed photo sits on
  whichever one answered — a custody problem for an evidence product, not just
  duplicated spend. Confirm which disk holds real photos before suspending
  anything. Owner-only.

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
- **Always fix the cause; don't append.** If a change would add to a shared list, file or section that other work also edits, give it its own file instead. When the same conflict or error comes back, fix what makes it repeat, not just this instance.
- **Say what was verified and what wasn't.** Never overstate. If something couldn't be run or checked (a device, a live server, a dashboard), say that plainly.
- **The owner merges.** Open PRs as drafts and leave them. Don't merge, and don't start TestFlight or store builds or change live settings (Render env vars, DNS, Stripe, Apple) without the owner's go.
- **Don't watch PRs.** Opening a PR subscribes the session automatically; unsubscribe right away. Check CI only when asked.
- **Decide before building** anything that changes who can see data, what leaves the phone, or what costs money: ask first, with a recommendation.
- **Never print or repeat a password, key or token.** If one has been exposed (in chat, a screenshot, a log), say so plainly so it gets rotated.
- **Say early which steps only the owner can do** (DNS at GoDaddy, the Render shell, the Apple portal, rolling the Stripe key, merging).
- **Render: read freely, change only with permission.** Reading is allowed without asking: services, deploy history, logs, metrics, and the *names* of environment variables (never print a value). Anything that changes Render (environment variables, deploys or restarts, creating, suspending or deleting a service, disk or database) needs the owner's go each time, and says first exactly what it will change.
- **Keep status updates short.** Long reports only when asked.
