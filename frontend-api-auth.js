/**
 * TradeDeck API client helper for the Tradeneck frontend (Supabase Auth).
 *
 * Usage:
 *   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
 *   <script src="frontend-api-auth.js"></script>
 *   <script>
 *     TradeDeckAPI.init({
 *       apiBase: 'https://tradedeck-api.onrender.com',
 *       supabaseUrl: 'https://YOUR_PROJECT.supabase.co',
 *       supabaseAnonKey: 'YOUR_ANON_KEY'
 *     });
 *
 *     // Public endpoint (no auth)
 *     TradeDeckAPI.get('/api/jobs').then(r => r.json());
 *
 *     // Protected endpoint (auto-attaches Bearer token)
 *     TradeDeckAPI.post('/stripe/escrow/create', { job_id, draw_id, amount_cents, payer_id });
 *   </script>
 */
(function (global) {
  var config = { apiBase: '', supabase: null };

  function init(opts) {
    config.apiBase = (opts.apiBase || '').replace(/\/$/, '');
    if (opts.supabase) {
      config.supabase = opts.supabase;
    } else if (opts.supabaseUrl && opts.supabaseAnonKey && global.supabase) {
      config.supabase = global.supabase.createClient(opts.supabaseUrl, opts.supabaseAnonKey);
    }
  }

  async function getToken() {
    if (!config.supabase) return null;
    var result = await config.supabase.auth.getSession();
    return result.data && result.data.session ? result.data.session.access_token : null;
  }

  async function request(method, path, body, requireAuth) {
    var headers = { 'Content-Type': 'application/json' };
    var token = await getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    if (requireAuth && !token) {
      throw new Error('Sign in required');
    }
    var opts = { method: method, headers: headers };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(config.apiBase + path, opts);
  }

  global.TradeDeckAPI = {
    init: init,
    get: function (path) { return request('GET', path, undefined, false); },
    post: function (path, body, requireAuth) {
      return request('POST', path, body, requireAuth !== false);
    },
    getToken: getToken,
  };
})(typeof window !== 'undefined' ? window : globalThis);
