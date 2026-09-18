/**
 * Thin client for the Shield API.
 *
 * Standalone in the sense that matters: no TradeDeck, no Supabase SDK, no
 * hardcoded tenant. The base URL is configured by whoever runs the page and
 * the bearer token is supplied by the operator, because Shield is meant to be
 * a verification primitive several businesses can point at rather than one
 * company's feature.
 *
 * The rule this file exists to keep
 * --------------------------------
 * **Nothing this client sends is offered as evidence.** `routes.py` opens with
 * that sentence and it is the difference between this and the pre-hardening
 * client: the parent's `/shield/analyze-photo` accepted `comp_url`,
 * `has_exif`, `gps_lat` and `original_hash` from the request body and never
 * re-read them from the row it was about to update, so a contractor could
 * upload a genuine photo and then point the analyser at a stock image of
 * perfect work. The `pass` landed on the real photo's row and the
 * client-supplied hash went into the custody log as the evidence.
 *
 * So this client posts a photo id in the path and nothing else. It computes no
 * hash the server will trust, reads no EXIF the server will believe, and
 * reaches no verdict. Where it does hash a file — checking a photo you were
 * handed against a package — that number is shown to you and never uploaded.
 * `webapp-sends-no-evidence` fails the build if a forbidden field name appears
 * in a request body here.
 *
 * Route names are the hardened service's, which are not the old ones. Anything
 * still calling `/shield/analyze-photo` or `/shield/generate-points` is
 * talking to the API that had the fraud chain in it.
 */

export class ShieldClient {
  /**
   * @param {string} baseUrl  origin of the Shield service
   * @param {string|null} token  a bearer token for the authenticated routes;
   *   the two public routes never send one, even when it is set
   */
  constructor(baseUrl, token = null) {
    this.baseUrl = String(baseUrl || "").replace(/\/+$/, "");
    this.token = token;
  }

  async #request(path, { method = "GET", body, auth = true, raw } = {}) {
    const headers = {};
    if (auth && this.token) headers.Authorization = `Bearer ${this.token}`;
    if (body && !raw) headers["Content-Type"] = "application/json";

    let response;
    try {
      response = await fetch(`${this.baseUrl}/shield${path}`, {
        method, headers, body: raw ? body : (body && JSON.stringify(body)),
      });
    } catch (cause) {
      // A network failure is not a verdict about anything. Say so plainly
      // rather than letting a caller render it as an empty result.
      throw new ShieldError(
        `Could not reach ${this.baseUrl}. Check the service URL, and note that ` +
        `a browser will block a cross-origin call the service has not been ` +
        `configured to allow.`, { cause });
    }

    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }

    if (!response.ok) {
      throw new ShieldError(
        payload?.error || `${response.status} ${response.statusText}`,
        { status: response.status });
    }
    return payload;
  }

  /* --------------------------------------------------------- public routes -- */
  // No token is sent on either, deliberately. A price list or an outcome
  // report that behaves differently for a signed-in caller is not published.

  pricing() { return this.#request("/public/pricing", { auth: false }); }

  results() { return this.#request("/public/results", { auth: false }); }

  /* --------------------------------------------------- authenticated routes -- */

  createJob(fields) {
    return this.#request("/jobs", { method: "POST", body: fields });
  }

  /** Buyer-owned and one-shot: the schedule locks once generated. */
  generateCheckpoints(jobId, body = {}) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/checkpoints`,
                         { method: "POST", body });
  }

  listCheckpoints(jobId) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/checkpoints`);
  }

  /**
   * Upload a capture. Multipart, and the file itself is the payload.
   *
   * The coordinates travel with it because the service needs something to
   * measure against the buyer's geofence — not because they are believed.
   * AR-10 records that `gps_corroborated` names a corroboration it does not
   * perform, and the server re-derives everything it seals.
   */
  uploadPhoto(jobId, { file, pointId, gpsLat, gpsLng }) {
    const form = new FormData();
    form.append("file", file);
    form.append("point_id", pointId);
    form.append("gps_lat", String(gpsLat));
    form.append("gps_lng", String(gpsLng));
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/photos`,
                         { method: "POST", body: form, raw: true });
  }

  /** A photo id in the path and nothing else. No body, by design. */
  analyzePhoto(photoId) {
    return this.#request(`/photos/${encodeURIComponent(photoId)}/analyze`,
                         { method: "POST" });
  }

  custody(jobId) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/custody`);
  }

  evidence(jobId) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/evidence`);
  }

  completeJob(jobId) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/complete`,
                         { method: "POST" });
  }

  notes(jobId) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/notes`);
  }

  writeNote(jobId, body) {
    return this.#request(`/jobs/${encodeURIComponent(jobId)}/notes`,
                         { method: "POST", body });
  }
}

export class ShieldError extends Error {
  constructor(message, { status = null, cause = null } = {}) {
    super(message);
    this.name = "ShieldError";
    this.status = status;
    this.cause = cause;
  }
}
