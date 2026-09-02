# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Flask API backend for TradeDeck. The frontend lives in the sibling `tradedeck` repo
(`Wood1974/Tradeneck`).

## What this service does (app.py v2.1)

Supabase-backed API for jobs, milestone draws, Stripe escrow, and AI photo checks.

| Area | Endpoints |
|------|-----------|
| Health | `GET /`, `GET /health` |
| Jobs | `GET/POST /api/jobs`, `POST /api/jobs/<id>/apply` |
| Stripe Connect | `POST /stripe/connect/onboard` (auth required) |
| Escrow | `POST /stripe/escrow/create`, `/release`, `/refund` (auth required) |
| Draws | `GET /draws/<id>`, `POST /draws/<id>/approve`, photo upload/list |
| Webhooks | `POST /stripe/webhook` |

Auth: Supabase JWT via `Authorization: Bearer <token>`. Required on sensitive routes
(escrow, draw approval, photo upload, Stripe Connect).

## Data layer

- **Supabase Postgres** — all tables defined in `tradedeck_schema.sql`
- **Supabase Storage** — bucket `draw-photos` for milestone photos
- No SQLite. The old SQLite-based API (auth, live-leads, gc-leads, chat) was removed.

## Environment variables (Render dashboard — never commit real values)

| Variable | Purpose |
|----------|---------|
| `SUPABASE_URL` | `https://<project-ref>.supabase.co` (NOT the dashboard URL) |
| `SUPABASE_SERVICE_KEY` | Service role key for server-side DB access |
| `SUPABASE_STORAGE_BUCKET` | Storage bucket name (default: `draw-photos`) |
| `STRIPE_SECRET_KEY` | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `ANTHROPIC_API_KEY` | Claude API for photo quality checks |
| `APP_URL` | Frontend URL for Stripe Connect redirects |

## Deployment checklist

1. Run `tradedeck_schema.sql` in Supabase SQL Editor
2. Create `draw-photos` storage bucket in Supabase
3. Set env vars in Render (especially `SUPABASE_URL` — must end in `.supabase.co`)
4. Enable Stripe Connect in the Stripe dashboard
5. Hit `GET /health` — should return `"status": "ok"`

## Known gaps / not in this repo

- Live leads aggregator (`/api/live-leads`) — removed with old SQLite API
- GC leads (`/api/gc-leads`) — removed
- Chat proxy (`/api/chat`) — removed
- `tradedeck.html` and `tradedeck-newest.html` are orphaned UI prototypes, not served by Flask

## Conventions

- Solo-founder project — verify against `app.py` before building on features
- Frontend uses Supabase Auth; this API validates those JWTs on protected routes
