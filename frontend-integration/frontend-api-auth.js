/**
 * TradeDeck API client for Tradeneck (Supabase Auth).
 * Auto-attaches Authorization: Bearer <jwt> on protected routes.
 */
(function (global) {
  var config = { apiBase: '', supabase: null };

  function init(opts) {
    config.apiBase = (opts.apiBase || 'https://tradedeck-api.onrender.com').replace(/\/$/, '');
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
    if (requireAuth && !token) throw new Error('Sign in required');
    var opts = { method: method, headers: headers };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(config.apiBase + path, opts);
  }

  async function apiJson(method, path, body, requireAuth) {
    var r = await request(method, path, body, requireAuth);
    var data = {};
    try { data = await r.json(); } catch (e) { /* empty */ }
    if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
    return data;
  }

  global.TradeDeckAPI = {
    init: init,
    get: function (path) { return request('GET', path, undefined, false); },
    post: function (path, body, requireAuth) {
      return request('POST', path, body, requireAuth !== false);
    },
    apiJson: apiJson,
    getToken: getToken,
    approveDraw: function (drawId) {
      return apiJson('POST', '/draws/' + drawId + '/approve', {});
    },
    refundDraw: function (drawId) {
      return apiJson('POST', '/stripe/escrow/refund', { draw_id: drawId });
    },
    uploadDrawPhoto: function (drawId, imageBase64) {
      return apiJson('POST', '/draws/' + drawId + '/photos/upload', { image_base64: imageBase64 });
    },
    connectStripe: function (userId, email) {
      return apiJson('POST', '/stripe/connect/onboard', { user_id: userId, email: email });
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
