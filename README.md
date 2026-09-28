# Tradedeck-api

Flask API for TradeDeck (marketplace) and **TradeDeck Shield** (evidence).

## Two services, one repo

| Surface | Entry point | Deploy |
|---|---|---|
| **TradeDeck marketplace** | root `app.py` + `shield_api.py` | `Procfile` → `tradedeck-api.onrender.com` |
| **Shield standalone** | `shield/app.py` | `shield/Procfile` / `shield/render.yaml` → separate Render service |

TradeDeck keeps its existing embedded `/shield/*` blueprint (`shield_api.py`) so
the marketplace app behaves the same. The `shield/` package is the multi-tenant
evidence product: its own schema (`shield.*`), its own identity (API keys /
members), and zero imports from the parent app.

```bash
# Marketplace (unchanged)
gunicorn app:app

# Shield standalone
gunicorn --chdir shield --bind 0.0.0.0:$PORT app:app
```

See `shield/README.md` for the evidence API, and apply the Shield migrations in
`supabase/migrations/` (including `20260920000000_shield_standalone_schema.sql`
and `20260928000000_shield_standalone_runtime.sql`) before deploying the
standalone service.
