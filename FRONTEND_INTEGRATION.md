# Frontend integration (Tradeneck repo)

The Tradeneck frontend (`Wood1974/Tradeneck`) was updated locally to use
`frontend-api-auth.js`. Copy these files into that repo, or apply the patch.

## Quick apply

From the Tradeneck repo root:

```bash
# Option A: copy ready-made files
cp frontend-api-auth.js ./
# Then merge app.html and index.html changes manually, or copy from frontend-integration/

# Option B: apply patch (if on main)
git apply /path/to/0001-Wire-frontend-api-auth.js-for-protected-API-routes.patch
```

## What changed

### New file: `frontend-api-auth.js`

Copy from this repo root or `frontend-integration/frontend-api-auth.js`.

Attach in both HTML files after the Supabase script:

```html
<script src="frontend-api-auth.js"></script>
```

Initialize after creating the Supabase client:

```javascript
TradeDeckAPI.init({ supabase: db });  // app.html uses `db`
TradeDeckAPI.init({ supabase: sb });  // index.html uses `sb`
```

### Draw Manager (app.html + index.html)

| Action | Before | After |
|--------|--------|-------|
| Submit milestone | Supabase status update | Photo picker → `TradeDeckAPI.uploadDrawPhoto()` |
| Approve | Supabase status update | `TradeDeckAPI.approveDraw()` (triggers escrow release) |
| Dispute | Supabase status update | `TradeDeckAPI.refundDraw()` |

### Profile (index.html only)

Added **Connect Stripe Account** button calling `TradeDeckAPI.connectStripe()`.

## CSP

`_headers` and `app.html` CSP already allow `https://tradedeck-api.onrender.com`.
No CSP change needed for `index.html` (Netlify `_headers` covers it).

## Verify

1. Sign in on tradedeckapp.com
2. Open Draw Manager → Submit Photo on a pending milestone
3. Approve a submitted milestone (job owner only)
4. Profile → Connect Stripe Account

All protected calls should include `Authorization: Bearer <jwt>` in Network tab.
