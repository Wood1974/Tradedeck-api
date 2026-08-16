# CLAUDE.md — tradedeck-api (backend)

Guidance for Claude Code (or any agent) working in this repo. This is the
**Flask API backend** for TradeDeck, a marketplace app connecting
homeowners, general contractors, and workers around a full-transparency
trust system and milestone-based escrow. The frontend lives in the sibling
`tradedeck` repo — see that repo's CLAUDE.md for product context.

## What this service does

- **Stripe Connect escrow**: handles milestone-based draw payments —
  contractor submits a draw, an assigned verifier (homeowner or third-party
  inspector, per milestone) approves or disputes it, funds release from
  escrow on approval.
- **Photo upload + AI quality check**: draw submissions include site
  photos; this service runs them through an AI quality check (Anthropic
  API) as part of the draw approval flow, in `app.py`.
- Primary entry point: `app.py`.

## Data layer — two systems in play, check current state before assuming

- **Legacy**: SQLite database on Render's persistent disk. This was the
  original datastore.
- **Current direction**: Supabase project `jlaajejpqjldpbinktln`
  ("Tradedeck"), same project the frontend uses for auth. `tradedeck_schema.sql`
  defines `profiles`, `jobs`, `applications`, `draws` — as of the last
  known state, **this schema had not yet been executed** against Supabase.
- Given both exist, confirm with the user (or check `app.py`'s DB connection
  config directly) which one is actually live before making data-layer
  changes — don't assume SQLite is retired just because Supabase is the
  newer plan, and don't assume Supabase is wired up just because the schema
  file exists.
- Supabase Storage: a `draw-photos` bucket is defined in the schema SQL for
  the photo-upload flow above.

## Secrets / environment (never commit real values — this is a reference of what exists, not the values themselves)

- Stripe: sandbox account ("Jkw sandbox") with `sk_test_*` / `pk_test_*`
  keys — test mode only so far, no live keys yet.
- Anthropic API key (created at platform.claude.com) — used for the photo
  quality-check step in the draw approval flow.
- Supabase service role key — needed for any server-side write that must
  bypass RLS; keep scoped to this backend, never expose to the frontend.
- Store all of the above via Render's environment variable config, not in
  the repo.

## Related but out-of-repo

- A separate **KSL Jobs scraper** project runs on the founder's Windows PC
  (via Task Scheduler, using local Ollama for text normalization) and
  writes directly to the Supabase `jobs` table. It does **not** go through
  this API — if you're touching job-related endpoints, be aware rows can
  arrive from that path with `source = 'ksl'`, no `posted_by`, and fields
  like `county` / `ksl_job_id` / `external_url` that native TradeDeck job
  postings don't have.

## Deployment

- Hosted on Render: `tradedeck-api.onrender.com`.
- Render backend is intentionally untouched by the KSL scraper and by any
  Windows-hub automation — keep it that way; that separation was a
  deliberate architecture decision, not an oversight.

## Conventions / working notes

- Solo-founder project (Joshua), iterating fast. Confirm assumptions about
  which datastore is authoritative and which frontend file (`index.html` vs
  `tradedeck-app.html` in the sibling repo) a given API change needs to
  support, rather than guessing from the code alone.
