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

**Nov 2026 reconciliation, done in three passes — the first two were each
wrong in a different way.** This matters more than any individual correction
below, so read it.

The first pass verified the *infrastructure* against the live Render account
and found real problems, but took this file's *application* description on
faith. That description was obsolete: it documented an owner-written auth
system with SHA-256 password hashing, SQLite-backed jobs, a live-leads
aggregator, a GC-permit feed and an Anthropic chat proxy. **None of those
routes exist in `app.py`.** The first pass then re-committed several of those
claims as "corrected", which was worse than leaving them alone.

The second pass rebuilt the description from `app.py`, `auth.py` and the
blueprints. What is actually true: auth is **Supabase JWT**, there is **one**
user system, `SECRET_KEY` is used by **no live code**, there is **no password
handling at all**, `/api/jobs` is **Supabase-backed**, Supabase **is** used
here, and the SQLite file holds **two tables** (`custom_packs`, `manifests`)
of Shield capture v1 data — not auth, jobs, applications or leads.

The second pass got one thing badly wrong, which the third pass fixes: it
recorded "no escrow or draw routes, `escrow.py` deleted — verified Nov 2026".
That was read from a **working tree five commits behind `origin/main`**. PR #35
(`140269c`, merged 2026-11-06) had already **restored `escrow.py` and every
escrow and draw route**. True of that branch, false of this repo. See
**Milestone escrow** for what the merged tree actually contains.

**The mechanism behind all three mistakes is the same: each pass verified
against the wrong reference.** Pass one trusted the previous version of this
file; pass two trusted the working tree; the fix each time was to go one level
closer to what actually runs. So: derive from the code, read it on
`origin/main`, and read infrastructure from the live Render account.

Infrastructure findings that did hold up: no `disk:` block and no `DB_PATH` in
`render.yaml`, so the SQLite file is on ephemeral disk; the standalone Shield
server is deployed **three times over**, twice with its own 10 GB photo disk;
and a full vendored copy of that server's source also lives in `shield/`.

**The lesson, which is the actual root cause of the rework:** this file was
rewritten from the previous version of itself, repeatedly, and so were the
plans built on it. Verify against the code and the live account every time.
`render.yaml` and the Render dashboard disagree, and **the dashboard is what
runs.**

**Sep 2026 update**: Draw/escrow functionality removed to align Shield as a 
standalone evidence verification system. Shield operates independently from 
job payment workflows.

## What this service actually does

> **Every bullet in the previous version of this section was false.** It
> described an owner-written auth system, SQLite-backed jobs, a live-leads
> aggregator, a GC-permit feed and an Anthropic chat proxy. **None of those
> routes exist in `app.py`.** The service was rewritten and this section was
> never re-derived from the code. Rebuilt below by reading `app.py`, `auth.py`
> and the blueprints directly, Nov 2026. If you change routes, regenerate this
> from `grep -rn '\.route(' --include=*.py .` rather than editing prose.

- **Auth is Supabase JWT, and there is exactly one user system.** `auth.py`'s
  `require_auth` decorator calls `supabase.auth.get_user(token)` on the bearer
  token. There are **no** `/api/auth/*` routes, **no password handling
  anywhere** in this codebase (no bcrypt/scrypt/argon2 — and no
  `sha256(password + …)` either), and **`SECRET_KEY` is referenced by no live
  code**: its only occurrence is a past-tense comment in `shield/tenancy.py`
  describing how the *old* app used to hash passwords. The "two disconnected
  user databases" problem this file used to describe **is resolved** — the
  frontend CLAUDE.md has said so for a while and was correct.
- **Supabase is used directly here.** `app.py:16` is
  `from supabase import create_client`; `auth.py` reads
  `supabase.table("jobs")`; `/api/jobs` GET and POST both go to
  `supabase_admin.table("jobs")`. That is why `render.yaml` provisions
  `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` — **they are needed, not stray.**
- **Jobs**: `GET/POST /api/jobs` — **backed by Supabase, not SQLite.** There is
  no `/api/jobs/<id>/apply` route; applications are handled frontend-side
  against Supabase.
- **Shield capture v1** — the bulk of `app.py`: `/api/packs`,
  `/api/packs/custom`, `/api/challenges/issue`, `/api/captures/<pack_id>/seal`,
  `/api/captures/<pack_id>/verify`, `/api/manifests/<pack_id>/submit`,
  `/api/manifests/<id>`, `/api/manifests/<id>/pdf`,
  `/api/manifests/<id>/verify-offline`, plus `/api/admin/manifests`,
  `/api/admin/challenges`, `/api/admin/verify/<id>`. **This is the only thing
  that uses the SQLite file** (see **Data layer**).
- **Blueprints** (`app.py:47-49`): `shield_bp` at `/shield` (serves the old
  **web** Shield only — see **Architecture**), `identity_bp` (legacy ID check),
  `checkr_bp` at `/checkr` with `/start` and `/webhook` — the frontend's
  `CHECKR_API` in `assets/app.js` points here. `render.yaml` notes Checkr is
  ON HOLD behind `CHECKR_ENABLED`.
- **Stripe and escrow** — see **Milestone escrow** below. `escrow.py` exists
  and all seven escrow/draw routes are present; the earlier claim here that
  they were deleted was read off a stale branch. `/stripe/webhook` is
  ungated; every other Stripe, escrow and draw route is gated.
- **Config/health**: `/`, `/health`, `/api/health`, `/api/config/shields`,
  `/api/config/location`.
- **Gone, despite prior notes**: `/api/auth/register|login|me`,
  `/api/live-leads`, `/api/live-leads/refresh`, `/api/gc-leads`,
  `/api/gc-leads/refresh`, `/api/chat`. The `TRADE_KEYWORDS` / `UTAH_CITIES`
  aggregator and the Anthropic proxy are not in this codebase. `anthropic` is
  still imported at `app.py:11` and `ANTHROPIC_API_KEY` is still provisioned —
  check whether either is still reachable before assuming the key is needed.

### A second, vendored copy of the standalone Shield server lives in `shield/`

`shield/` is a full application in its own right — its own `app.py`,
`Procfile`, `auth.py`, `config.py`, `console/`, Android/App attestation
modules, and its own `SPEC.md` / `SECURITY.md` / `INDEPENDENCE.md` /
`PRICING.md`. The three `tradedeck-shield` Render services deploy
`Wood1974/tradedeck-shield`, so **this source exists in two repositories.**
Which one is authoritative is unresolved and matters: divergence between them
is a silent correctness risk for an evidence product. Do not edit `shield/`
here assuming it is what runs at `tradedeck-shield.onrender.com`.
## Data layer

> **This section was wrong until Nov 2026 and the error was load-bearing.** It
> claimed the SQLite file sat on a Render persistent disk at
> `/var/data/tradedeck.db` "per `render.yaml`". None of that was true, and at
> least one planning session was built on top of it. Verified below against the
> live Render service and `render.yaml` itself.

- **Most data is in Supabase, not here.** Jobs, profiles, applications and
  everything the frontend reads live in Supabase Postgres under RLS. This
  service talks to it directly (see **What this service actually does**).
- **SQLite holds exactly two tables, and it is on ephemeral disk.**
  `init_db()` creates `custom_packs` and `manifests` — **Shield capture v1
  data, and nothing else.** No auth accounts, no jobs, no applications, no
  leads; earlier versions of this file claimed all four and were wrong.
  `app.py:63` is `DB_PATH = get_env("DB_PATH", "/tmp/tradedeckapp_shield.db")`,
  `render.yaml` declares **no `DB_PATH`** and **no `disk:` block**, and the live
  service (`srv-d9hurcr7uimc73aovmu0`) has no disk attached — so the file is
  lost on **every deploy and every restart**, and `autoDeploy` fires on each
  commit to `main`.
- **How much that matters depends on one question nobody has answered:** is
  Shield capture v1 still in use, or has `tradedeck-shield.onrender.com`
  superseded it? If superseded, `custom_packs`/`manifests` are dead data and
  the right fix is to **retire the SQLite store and the capture v1 routes
  entirely**, not to attach a disk. If still in use, sealed manifests are being
  destroyed on every deploy, which for an evidence product is severe.
  **Settle this before doing either.** Attaching a disk to keep dead data alive
  would be a patch on a vestigial subsystem.
  (Unverified: whether `DB_PATH` is set in the Render dashboard. It would not
  help on its own — there is no disk for it to point at.)
- `tradedeck_schema.sql` (Supabase: profiles, jobs, applications, draws) was
  reconstructed fresh this session and verified against a local Postgres
  instance — it targets Supabase, and has **no relationship to this
  service's SQLite schema** (defined inline in `app.py`'s `init_db()`).
  Reconciling the two schemas is unresolved.

## Milestone escrow (built, switched off)

- Routes in `app.py`: `/stripe/escrow/create|release|refund`,
  `/draws/<id>`, `/draws/<id>/approve`, `/draws/<id>/photos/upload`,
  `/draws/<id>/photos`, and `/stripe/connect/onboard`. Payment state
  machine in `escrow.py` (manual-capture PaymentIntent → held via webhook →
  capture + Transfer to the payee's Connect account on approval, minus
  `PLATFORM_FEE_BPS`). Draw access checks are in `auth.py`.
- **Off unless `ESCROW_ENABLED=true`** (`config.escrow_enabled()`). While
  off, `_require_escrow_enabled` makes every one of those routes return 404
  before auth or Stripe, and `/stripe/webhook` ignores escrow events (it
  still records them for idempotency). The variable is not set on Render, so
  it is off in production. Only the owner turns it on, together with
  `ESCROW_ENABLED` in the frontend's `assets/app.js`.
- Escrow amount and payee come only from the stored `draws` /
  `draw_schedules` rows (`payee_id` is set by the `accept_application`
  RPC), never from the request body.
- Shield is separate from escrow: no Shield code depends on it.
- `tests/test_escrow_gate.py` covers the gate. `escrow_enabled()` accepts `1`,
  `true` or `yes` (`config.py:56`); anything else, unset included, is off.
- **This closes a gap the frontend doc flags.** That doc warns its own
  `ESCROW_ENABLED` is client-side only and "the backend is what actually has to
  refuse payments". It now does. Because the server 404s regardless, a client
  flag left on surfaces as 404s rather than unguarded payments — and the
  frontend doc's line that these routes must be "restored here first" is
  **stale**: they are back, so turning escrow on is configuration, not a
  restore.
- ⚠️ **An earlier Nov 2026 pass of this file claimed `escrow.py` was deleted
  and no escrow or draw routes existed.** That was read off a working tree five
  commits behind `origin/main`, before PR #35 (`140269c`, merged 2026-11-06).
  Wrong about this repo. Kept here as the worked example of why the conventions
  below say to read `origin/main`.

## Architecture — Shield and TradeDeck are standalone (owner's decision)

This section was lost in the Nov 2026 merge of PR #35, because the version of
it written in Sep 2026 also asserted "no draws/milestones, no escrow", which
escrow's return made false. **The standalone decision itself still stands** and
is restored here without the stale escrow claims — the frontend CLAUDE.md
quotes it from this file, so it needs to exist here.

**Shield and TradeDeck are completely standalone applications**, sharing the
`tradedeckapp.com` domain and operating independently:

- **Shield** — standalone evidence verification: photo analysis, integrity
  verification, contractor scoring. **No integration with jobs.**
- **TradeDeck** — the job marketplace. Milestone escrow is part of *it*
  (built, switched off — see above), not of Shield. No Shield code depends on
  escrow and none should.

**"Standalone" also means nothing of Shield belongs in a web browser.** The
Shield phone app (`shield-app/` in the frontend repo) talks only to
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
- `ANTHROPIC_API_KEY` — **required for the service to boot at all.** `app.py:63`
  is `anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])` at module
  level, with a subscript rather than `.get()`, so an unset key raises
  `KeyError` on import and gunicorn never starts. Consumed by `_analyze_photo`
  (`app.py:231`) from `/draws/<id>/photos/upload` (`app.py:430`) — which is
  escrow-gated, so **the key is needed to boot even though the only caller is
  switched off**. There is no `/api/chat` route, despite older notes.
- `ESCROW_ENABLED` — not set (off). See "Milestone escrow". Owner-only to set.
- `IDENTITY_RECEIPT_KEY`, `STRIPE_TEST_SECRET_KEY`, `IDENTITY_TEST_MODE_USER_IDS` — **legacy.** They configure the older ID-check
  code in `identity_api.py` / `identity_core.py` here. The Shield phone app no longer calls this service: it signs on with the standalone
  Shield server (`Wood1974/tradedeck-shield`, which uses `IDENTITY_TEST_MODE_EMAILS`), and the receipt key the app pins is that server's.
  The old key id stays pinned in the app so records signed by it still verify. Nothing is removed here; whether to retire this copy is a
  separate decision.
- `SECRET_KEY` — **not used by any live code in this repo, and not needed.**
  Earlier versions of this file said it signed auth tokens and salted password
  hashes. It does not: auth is Supabase JWT (`auth.py`), there is no password
  handling here, and `SECRET_KEY`'s only occurrence is a past-tense comment in
  `shield/tenancy.py` about how the old app worked. There is nothing to confirm
  and nothing to rotate on this service's behalf. If it is still set in the
  Render dashboard it can be removed — but check `shield/` first, which is a
  separate vendored application and may use its own.
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` — **required, not stray.** Used by
  `app.py` and `auth.py`. The service role key bypasses every RLS policy in
  the project, so it belongs only in Render's env and GitHub's secrets, never
  in a workflow input (see `.github/workflows/apply-shield-migrations.yml`,
  which used to accept it as an unmasked `workflow_dispatch` string).

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
- **The dual-auth problem is resolved.** Earlier versions of this file told
  every new session to go resolve it first. Auth here is Supabase JWT via
  `auth.py`; there is one user system. Nothing to do.
- **Derive this file from the code, on `origin/main`, not from the previous
  version of this file and not from your working tree.** Three Nov 2026 passes
  each got this wrong in a different way and each produced a confidently wrong
  commit: pass one trusted the previous version of this file (hence the auth
  system, leads aggregator and chat proxy that do not exist); pass two trusted
  the working tree (hence "escrow.py deleted", while `origin/main` was five
  commits ahead with it restored). Concretely, before writing anything here:
  - `git fetch origin main` first, and read on `origin/main` — or note plainly
    that a claim is branch-local.
  - Routes: `git grep -nE '\.route\(' origin/main -- '*.py'`.
  - Tables: read `init_db()`.
  - Infrastructure: read the live Render account, because `render.yaml` and the
    dashboard disagree and **the dashboard is what runs**.
  - Check open and recently merged PRs in both repos before describing or
    rebuilding anything; the frontend CLAUDE.md's "check what the other open
    branch or PR already did" is the same rule and would have caught pass two.

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
