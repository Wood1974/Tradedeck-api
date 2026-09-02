# CLAUDE.md — tradedeck-api (backend, repo: Wood1974/Tradedeck-api)

Flask API backend for TradeDeck. The frontend lives in the sibling `tradedeck` repo
(`Wood1974/Tradeneck`).

## What this service does (app.py v2.2)

| Area | Endpoints | Auth |
|------|-----------|------|
| Health | `GET /`, `GET /health` | No |
| Jobs | `GET/POST /api/jobs`, `POST /api/jobs/<id>/apply` | Apply: optional JWT |
| Live leads | `GET /api/live-leads`, `POST /api/live-leads/refresh` | No |
| GC leads | `GET /api/gc-leads`, `POST /api/gc-leads/refresh` | No |
| Chat | `POST /api/chat` | No |
| Stripe Connect | `POST /stripe/connect/onboard` | JWT required |
| Escrow | `POST /stripe/escrow/create`, `/release`, `/refund` | JWT required |
| Draws | `GET /draws/<id>`, `POST /draws/<id>/approve`, photo upload/list | Approve/upload: JWT |
| Webhooks | `POST /stripe/webhook` | Stripe signature |

Auth: Supabase JWT via `Authorization: Bearer <token>` on protected routes.

## Data layer

- **Supabase Postgres** — jobs, profiles, draws, escrow, photos (`tradedeck_schema.sql`)
- **Supabase Storage** — bucket `draw-photos` for milestone photos
- **SQLite** (leads cache only) — `live_leads`, `gc_leads`, `fetch_log` at `DB_PATH`

## Frontend integration

Copy `frontend-api-auth.js` into the Tradeneck repo. It auto-attaches the Supabase
session token to API calls:

```javascript
TradeDeckAPI.init({
  apiBase: 'https://tradedeck-api.onrender.com',
  supabaseUrl: 'https://<ref>.supabase.co',
  supabaseAnonKey: '<anon-key>'
});

// Protected route — throws if not signed in
TradeDeckAPI.post('/stripe/escrow/create', payload);

// Public route
TradeDeckAPI.get('/api/jobs').then(r => r.json());
```

## Environment variables (Render dashboard)

| Variable | Purpose |
|----------|---------|
| `SUPABASE_URL` | `https://<project-ref>.supabase.co` |
| `SUPABASE_SERVICE_KEY` | Service role key |
| `SUPABASE_STORAGE_BUCKET` | Storage bucket (default: `draw-photos`) |
| `STRIPE_SECRET_KEY` | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret |
| `ANTHROPIC_API_KEY` | Claude for chat + photo checks |
| `PERMITSTACK_KEY` | GC permit leads (optional) |
| `SAM_API_KEY` | SAM.gov leads (optional) |
| `ZIPRECRUITER_KEY` | ZipRecruiter leads (optional) |
| `DB_PATH` | SQLite path for leads cache (default: `/var/data/tradedeck-leads.db`) |
| `APP_URL` | Frontend URL for Stripe redirects |

## Deployment checklist

1. Run `tradedeck_schema.sql` in Supabase SQL Editor
2. Create `draw-photos` storage bucket
3. Set env vars in Render (`SUPABASE_URL` must end in `.supabase.co`)
4. Enable Stripe Connect in Stripe dashboard
5. `GET /health` → `"status": "ok"`

## Conventions

- Solo-founder project — verify against `app.py` before building on features
- Orphaned `tradedeck.html` prototypes were removed; UI lives in Tradeneck repo
