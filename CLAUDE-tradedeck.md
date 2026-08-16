# CLAUDE.md — tradedeck (frontend)

Guidance for Claude Code (or any agent) working in this repo. This is the
**frontend** of TradeDeck — a marketplace app connecting homeowners,
general contractors, and workers, built around full transparency, a
verified trust/tier system, and milestone-based escrow.

## Product context

TradeDeck lets subs and contractors hire and be hired directly — benchmarked
against heypros.com with the explicit goal of doing it better. Core
principles baked into every feature decision:

- **Full transparency**: homeowners see both contractor and worker tiers,
  contractors see worker tiers, workers see contractor tiers. Direct
  contact between parties, no platform gatekeeping of communication.
- **Trust is earned from objective on-platform data**, not popularity:
  jobs completed, timeline adherence, cost variance vs. bid, and site
  cleanliness sign-offs — not star ratings people can game.
- **Reviews are optional and never prompted.** After a job closes, users
  answer three binary yes/no questions (on time? clean? would hire again?)
  that silently feed the tier score. A written review is opt-in and, when
  given, carries elevated weight.

## Architecture

- Single production app at `index.html` — Supabase auth, all tabs, Draw
  Manager. Codebase was reconciled in Aug 2026 down to this one file after
  earlier iterations diverged (see "History" below).
- A parallel mobile-oriented rebuild also exists: `tradedeck-app.html`,
  5 tabs (Home, Find Work, Post a Job, Draw Manager, Profile). Confirm with
  the user which of `index.html` / `tradedeck-app.html` is the current
  source of truth before making structural changes — both existed as of
  the last reconciliation and may need merging or one may supersede the
  other.
- Marketing/waitlist landing page: `tradedeck-pitch.html` — spruce/brass/
  bone design system, Web3Forms for waitlist capture, Netlify-deployable,
  separate from the app itself.
- `draw_manager_frontend.html` — draw/escrow UI component (Stripe Connect
  escrow, photo upload + AI quality check, draw approval flow), built Aug
  2026. Confirm whether this has been merged into `index.html` or still
  stands alone.

## Backend & data

- Auth + data: **Supabase** project `jlaajejpqjldpbinktln` ("Tradedeck").
  Anon key is safe to use client-side (identifiable by suffix `_S4`); never
  use the service role key in frontend code.
- Separate Flask API backend lives in the sibling repo **tradedeck-api**
  (tradedeck-api.onrender.com) — used for Stripe Connect escrow logic and
  AI photo quality checks. See that repo's own CLAUDE.md.
- `tradedeck_schema.sql` (profiles, jobs, applications, draws tables) — as
  of the last update this had **not yet been run** against Supabase. Check
  current state before assuming these tables/columns exist.
- Jobs table has (or needs) additions for KSL-imported external listings:
  `source` (enum: `tradedeck`|`ksl`), `county`, `ksl_job_id`, `external_url`,
  and `posted_by` must be nullable (KSL jobs have no on-platform poster).
  A separate scraper project (not in this repo) writes those rows directly
  to Supabase.

## Key features implemented

- **Verification stack**: identity (all users) → background check (workers
  + contractors) → license cross-check vs. state DB → COI insurance upload
  + parse → ongoing quarterly monitoring.
- **Five-tier ranking**: Verified (1) → Active (2) → Proven (3) → Trusted
  (4) → TradeDeck Pro (5).
- **Draw/escrow system**: milestone-based draw schedule, per-draw
  verification (owner vs. third-party inspector), submit/approve/dispute
  flow, escrow balance tracker. Draw builder lives in the Post a Job flow —
  add/remove milestones, set % per draw, select verifier, validate percents
  sum to 100.
- **CompanyCam integration**: built against a placeholder API key; shows
  mock data until a real key is wired in.
- **Find Work tab**: currently shows Open Jobs + Lead Sources (or, in the
  newer tab layout, just Find Work). Pending frontend work: county filter
  tabs, a KSL-source badge, and sorting by posted date descending, to
  surface the KSL-scraped external jobs alongside native postings —
  KSL jobs display inline, no link-out to the original KSL listing.

## Deployment

- Hosted on Netlify: `calm-cupcake-a213bb.netlify.app`, custom domain
  `tradedeckapp.com`.
- DNS via GoDaddy: `A @ → 75.2.60.5` (Netlify), `CNAME www →
  calm-cupcake-a213bb.netlify.app`.
- Domain `tradedeckapp.com` registered through GoDaddy.

## Conventions / working notes

- This is a solo-founder project (Joshua) iterating fast — expect the repo
  to sometimes contain more than one candidate version of the same screen
  (e.g. `index.html` vs `tradedeck-app.html`). **Always confirm which file
  is canonical before editing**, rather than assuming.
- Hero copy (approved, don't rewrite without asking): *"Twenty years. Every
  nail. Every pour. Every roof. From foundation to ridge cap, I've built
  it, fixed it, and stood behind it — with hands that know the difference
  between a shortcut and a standard."*
- Keep secrets (Supabase service role key, Stripe secret key, Anthropic API
  key) out of this repo entirely — those belong in the backend repo's
  environment config, never committed here.
