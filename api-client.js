(function (global) {
  var API_URL = global.TRADEDECK_API_URL || 'https://tradedeck-api.onrender.com';
  var SUPABASE_URL = global.TRADEDECK_SUPABASE_URL || 'https://jlaajejpqjldpbinktln.supabase.co';
  var SUPABASE_ANON_KEY = global.TRADEDECK_SUPABASE_ANON_KEY || '';

  var supabaseClient = null;

  function getSupabase() {
    if (!global.supabase || !global.supabase.createClient) {
      throw new Error('Supabase JS SDK is not loaded');
    }
    if (!SUPABASE_ANON_KEY) {
      throw new Error('TRADEDECK_SUPABASE_ANON_KEY is not configured');
    }
    if (!supabaseClient) {
      supabaseClient = global.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    }
    return supabaseClient;
  }

  async function getAccessToken() {
    try {
      var result = await getSupabase().auth.getSession();
      return (result.data && result.data.session && result.data.session.access_token) || null;
    } catch (err) {
      return null;
    }
  }

  async function apiFetch(path, options) {
    options = options || {};
    var headers = Object.assign({}, options.headers || {});
    var token = await getAccessToken();

    if (token) {
      headers.Authorization = 'Bearer ' + token;
    } else if (options.requireAuth) {
      var authError = new Error('Sign in required');
      authError.code = 'AUTH_REQUIRED';
      throw authError;
    }

    var fetchOptions = {
      method: options.method || 'GET',
      headers: headers,
      credentials: 'omit',
    };

    if (options.body !== undefined && options.body !== null) {
      if (typeof options.body === 'object' && !(options.body instanceof FormData)) {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        fetchOptions.body = JSON.stringify(options.body);
      } else {
        fetchOptions.body = options.body;
      }
    }

    fetchOptions.headers = headers;
    var response = await fetch(API_URL + path, fetchOptions);
    var payload = null;
    var contentType = response.headers.get('content-type') || '';

    if (contentType.indexOf('application/json') !== -1) {
      payload = await response.json();
    } else if (!response.ok) {
      payload = { error: response.statusText || 'Request failed' };
    }

    if (!response.ok) {
      var error = new Error((payload && payload.error) || response.statusText || 'Request failed');
      error.status = response.status;
      error.payload = payload;
      throw error;
    }

    return payload;
  }

  global.TradeDeckAPI = {
    API_URL: API_URL,
    getSupabase: getSupabase,
    getAccessToken: getAccessToken,
    apiFetch: apiFetch,
  };
})(window);
