/**
 * Shield console.
 *
 * The tenant-facing app: open a record, fix its checkpoints, photograph each
 * one, read the custody chain, close it out and export the package.
 *
 * What this file deliberately does not do
 * ---------------------------------------
 * It computes nothing the service will trust. No hash, no verdict, no EXIF
 * reading, no distance. It sends a file and a checkpoint id; everything sealed
 * into the chain is derived server-side from the bytes that arrived and from
 * the site coordinates on the record — the one reference point the party being
 * documented did not supply.
 *
 * That is not squeamishness. The parent service accepted `original_hash`,
 * `has_exif`, `gps_lat` and an image URL from the client and never re-read the
 * row it was about to update, so a contractor could upload a real photograph
 * and aim the analyser at a stock image of perfect work. A client that computes
 * evidence invites exactly that, whatever the current server does with it.
 * `tenant-api-derives-evidence` fails the build on the server side; this file
 * is the other half of the same rule.
 *
 * The credential lives in sessionStorage, not localStorage: closing the tab
 * ends it. A Shield API key can read every record a tenant holds, so it should
 * not outlive the session on a shared machine by default.
 */

const $ = (id) => document.getElementById(id);
const state = { base: "", token: "", record: null };

/* ------------------------------------------------------------------ http -- */
class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function api(path, { method = "GET", json, form } = {}) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (json) headers["Content-Type"] = "application/json";

  let response;
  try {
    response = await fetch(`${state.base}/shield/v2${path}`, {
      method, headers, body: form || (json && JSON.stringify(json)),
    });
  } catch (cause) {
    // A network failure is not an answer about anything. Say so rather than
    // letting a caller render it as an empty result.
    throw new ApiError(
      `Could not reach ${state.base || "the service"}. Check the address, and ` +
      `note that a browser blocks a cross-origin call the service has not ` +
      `been configured to allow.`, 0);
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(body.error || `Request failed (${response.status})`,
                                       response.status);
  return body;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3200);
}

function showError(id, err) {
  const el = $(id);
  el.textContent = err instanceof Error ? err.message : String(err);
  el.hidden = false;
}

function clearError(id) { $(id).hidden = true; }

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function when(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(+d) ? iso : d.toLocaleString();
}

/* --------------------------------------------------------------- connect -- */
async function connect() {
  clearError("connectErr");
  state.base = $("baseUrl").value.trim().replace(/\/+$/, "");
  state.token = $("token").value.trim();
  if (!state.token) return showError("connectErr", new Error("A credential is required."));

  try {
    const me = await api("/whoami");
    try {
      sessionStorage.setItem("shield-console", JSON.stringify(
        { base: state.base, token: state.token }));
    } catch { /* private window, or storage blocked. Not worth failing over. */ }

    $("whoTenant").textContent = me.tenant.name || me.tenant.id;
    $("whoCred").textContent = me.credential === "api_key" ? "API key" : `member · ${me.role || "member"}`;
    $("who").hidden = false;
    $("connect").hidden = true;
    await loadRecords();
  } catch (err) {
    showError("connectErr", err);
  }
}

function signOut() {
  try { sessionStorage.removeItem("shield-console"); } catch { /* ignore */ }
  state.token = ""; state.record = null;
  $("who").hidden = true;
  $("records").hidden = true;
  $("detail").hidden = true;
  $("connect").hidden = false;
  $("token").value = "";
}

/* --------------------------------------------------------------- records -- */
async function loadRecords() {
  $("records").hidden = false;
  $("detail").hidden = true;
  const list = $("recordList");
  list.textContent = "Loading…";
  try {
    const { records } = await api("/records");
    list.innerHTML = "";
    if (!records.length) {
      list.innerHTML = `<p class="empty">No records yet. Open one to begin.</p>`;
      return;
    }
    for (const r of records) {
      const button = document.createElement("button");
      button.className = "item";
      button.innerHTML =
        `<span><span class="ref">${esc(r.external_ref)}</span>` +
        `<span class="meta"><br>${esc(r.trade || "—")} · opened ${esc(when(r.created_at))}` +
        `${r.site_address ? " · " + esc(r.site_address) : ""}</span></span>` +
        `<span class="pill ${esc(r.status)}">${esc(r.status)}</span>`;
      button.addEventListener("click", () => openRecord(r.id));
      list.appendChild(button);
    }
  } catch (err) {
    list.innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
}

async function createRecord(event) {
  event.preventDefault();
  clearError("recordErr");
  const data = Object.fromEntries(new FormData(event.target).entries());
  for (const key of ["site_lat", "site_lng"]) {
    if (data[key] === "") delete data[key];
    else if (data[key] !== undefined) data[key] = Number(data[key]);
  }
  try {
    const { record } = await api("/records", { method: "POST", json: data });
    event.target.reset();
    $("newRecord").hidden = true;
    toast(`Record ${record.external_ref} opened`);
    await openRecord(record.id);
  } catch (err) {
    showError("recordErr", err);
  }
}

/* ------------------------------------------------------------ one record -- */
async function openRecord(id) {
  $("records").hidden = true;
  $("detail").hidden = false;
  showTab("work");
  try {
    const data = await api(`/records/${encodeURIComponent(id)}`);
    state.record = data;
    const r = data.record;
    $("detailRef").textContent = r.external_ref;
    $("detailSub").textContent = [
      r.trade, r.site_address,
      r.subject_ref && `subject ${r.subject_ref}`,
      r.buyer_ref && `for ${r.buyer_ref}`,
    ].filter(Boolean).join(" · ") || "—";
    $("detailStatus").textContent = r.status;
    $("detailStatus").className = `pill ${r.status}`;
    renderPoints(data);
  } catch (err) {
    $("pointList").innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
}

function renderPoints(data) {
  const locked = Boolean(data.record.checkpoints_locked_at);
  $("setPoints").hidden = locked;
  if (!locked && !$("pointRows").children.length) addPointRow();

  const list = $("pointList");
  list.innerHTML = "";
  if (!data.checkpoints.length) {
    if (locked) list.innerHTML = `<p class="empty">No checkpoints on this record.</p>`;
    return;
  }

  for (const point of data.checkpoints) {
    const photo = point.live_photo;
    const node = document.createElement("div");
    node.className = "point";
    node.innerHTML = `
      <header>
        <div>
          <span class="num">#${point.point_number}</span>
          <strong>${esc(point.label)}</strong>
          ${point.description ? `<div class="meta">${esc(point.description)}</div>` : ""}
          ${point.must_show ? `<div class="meta">Must show: ${esc(point.must_show)}</div>` : ""}
        </div>
        <span class="pill ${esc(photo?.verdict || point.status)}">${esc(photo?.verdict || point.status)}</span>
      </header>
      ${photo ? evidenceHtml(photo) : `
      <div class="drop">
        <input type="file" accept="image/*" capture="environment" id="f-${point.id}">
        <label for="f-${point.id}">Choose a photograph</label> for this checkpoint
      </div>`}
    `;
    list.appendChild(node);
    const input = node.querySelector("input[type=file]");
    if (input) input.addEventListener("change", () => uploadFor(point, input));
  }
}

function evidenceHtml(photo) {
  // Only what the SERVER derived is shown. Nothing here is computed in the
  // browser, so nothing on screen can disagree with what was sealed.
  return `<div class="evidence">
    ${photo.integrity_note ? `<div class="pill flag">${esc(photo.integrity_note)}</div>` : ""}
    <dl>
      <dt>Hash</dt><dd>${esc(photo.original_hash)}</dd>
      <dt>Recorded</dt><dd>${esc(when(photo.uploaded_at))}</dd>
      <dt>EXIF</dt><dd>${photo.has_exif ? "present" : "absent"}</dd>
      <dt>From site</dt><dd>${photo.site_distance_m == null ? "not measured"
        : Math.round(photo.site_distance_m) + " m"}</dd>
      <dt>Attestation</dt><dd>${esc(photo.attestation_tier || "unattested")}</dd>
    </dl>
  </div>`;
}

async function uploadFor(point, input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  form.append("checkpoint_id", point.id);

  // The device's own reading, sent as a claim and labelled as one. The server
  // measures it against the site on the record; it is never treated as
  // corroboration of itself.
  const position = await currentPosition();
  if (position) {
    form.append("gps_lat", String(position.lat));
    form.append("gps_lng", String(position.lng));
  }

  toast(`Uploading for “${point.label}”…`);
  try {
    await api(`/records/${encodeURIComponent(state.record.record.id)}/photos`,
              { method: "POST", form });
    toast("Recorded and sealed");
    await openRecord(state.record.record.id);
  } catch (err) {
    toast(err.message);
  }
}

function currentPosition() {
  return new Promise((resolve) => {
    if (!navigator.geolocation) return resolve(null);
    navigator.geolocation.getCurrentPosition(
      (p) => resolve({ lat: p.coords.latitude, lng: p.coords.longitude }),
      () => resolve(null),            // refused or unavailable: send nothing
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 0 });
  });
}

/* ----------------------------------------------------------- checkpoints -- */
function addPointRow() {
  const index = $("pointRows").children.length + 1;
  const row = document.createElement("div");
  row.className = "grid2";
  row.innerHTML = `
    <label class="field"><span>Checkpoint ${index}</span>
      <input name="label" placeholder="Underlayment before shingles"></label>
    <label class="field"><span>What it must show</span>
      <input name="must_show" placeholder="Full deck coverage, laps visible"></label>`;
  $("pointRows").appendChild(row);
}

async function savePoints(event) {
  event.preventDefault();
  clearError("pointsErr");
  const rows = [...$("pointRows").children];
  const checkpoints = rows.map((row) => ({
    label: row.querySelector("input[name=label]").value.trim(),
    must_show: row.querySelector("input[name=must_show]").value.trim(),
  })).filter((c) => c.label);

  if (!checkpoints.length) {
    return showError("pointsErr", new Error("Add at least one checkpoint."));
  }
  if (!confirm(`Lock ${checkpoints.length} checkpoint(s)?\n\nThey cannot be ` +
               `changed afterwards. That is the point: a list that can be ` +
               `edited later is not a commitment.`)) return;

  try {
    await api(`/records/${encodeURIComponent(state.record.record.id)}/checkpoints`,
              { method: "POST", json: { checkpoints } });
    $("pointRows").innerHTML = "";
    toast("Checkpoints locked");
    await openRecord(state.record.record.id);
  } catch (err) {
    showError("pointsErr", err);
  }
}

/* --------------------------------------------------------------- custody -- */
async function loadChain() {
  const list = $("chainList");
  const box = $("chainVerdict");
  list.textContent = "Loading…";
  try {
    const { custody, verification } = await api(
      `/records/${encodeURIComponent(state.record.record.id)}/custody`);

    box.className = `verdict-box ${verification.intact ? "ok" : "broken"}`;
    box.innerHTML =
      `<h3>${verification.intact ? "Chain verifies" : "Chain does not verify"}</h3>` +
      `<p>${esc(verification.summary)}</p>` +
      `<div class="head">head ${esc(verification.head_hash)}</div>` +
      `<p class="note">This service checking its own chain proves little. The
       package below is checkable by whoever receives it, with software we do
       not control.</p>`;

    list.innerHTML = "";
    for (const entry of custody) {
      const node = document.createElement("div");
      node.className = "entry";
      node.innerHTML =
        `<div class="kind">${esc(entry.event_type)}</div>` +
        `<div class="when">${esc(when(entry.recorded_at))} · ` +
        `${esc(entry.actor_kind || "system")}</div>` +
        (entry.integrity_note ? `<div class="pill flag">${esc(entry.integrity_note)}</div>` : "") +
        `<div class="hash">${esc(entry.entry_hash)}</div>`;
      list.appendChild(node);
    }
    if (!custody.length) list.innerHTML = `<p class="empty">No entries yet.</p>`;
  } catch (err) {
    list.innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
}

async function downloadPackage() {
  try {
    const payload = await api(
      `/records/${encodeURIComponent(state.record.record.id)}/package`);
    const blob = new Blob([JSON.stringify(payload, null, 2)],
                          { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `shield-${payload.record.external_ref || "record"}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    toast("Package downloaded. Keep the head hash somewhere else.");
  } catch (err) {
    toast(err.message);
  }
}

/* -------------------------------------------------------------- close out -- */
async function completeRecord() {
  clearError("closeErr");
  if (!confirm("Close this record?\n\nThe outcome is computed from the " +
               "checkpoints and their live photographs. It cannot be edited " +
               "afterwards.")) return;
  try {
    const result = await api(
      `/records/${encodeURIComponent(state.record.record.id)}/complete`,
      { method: "POST", json: {} });
    $("closeResult").innerHTML =
      `<div class="verdict-box ok">
         <h3>${esc(result.grade.verdict)}</h3>
         <p>${esc(result.grade.summary)}</p>
         <div class="head">head ${esc(result.head_hash)}</div>
       </div>
       <p class="note">${esc(result.keep_this)}</p>`;
    toast("Record closed and sealed");
    await openRecord(state.record.record.id);
    showTab("close");
  } catch (err) {
    showError("closeErr", err);
  }
}

/* ------------------------------------------------------------------ tabs -- */
function showTab(name) {
  for (const button of document.querySelectorAll("nav.tabs button")) {
    button.setAttribute("aria-selected", String(button.dataset.tab === name));
  }
  for (const panel of document.querySelectorAll(".tab")) {
    panel.classList.toggle("on", panel.id === name);
  }
  if (name === "chain") loadChain();
}

/* ------------------------------------------------------------------ wire -- */
$("connectBtn").addEventListener("click", connect);
$("token").addEventListener("keydown", (e) => { if (e.key === "Enter") connect(); });
$("signOut").addEventListener("click", signOut);
$("newRecordBtn").addEventListener("click", () => {
  $("newRecord").hidden = !$("newRecord").hidden;
});
$("cancelRecord").addEventListener("click", () => { $("newRecord").hidden = true; });
$("newRecord").addEventListener("submit", createRecord);
$("backToList").addEventListener("click", loadRecords);
$("addPoint").addEventListener("click", addPointRow);
$("setPoints").addEventListener("submit", savePoints);
$("downloadPackage").addEventListener("click", downloadPackage);
$("completeBtn").addEventListener("click", completeRecord);
for (const button of document.querySelectorAll("nav.tabs button")) {
  button.addEventListener("click", () => showTab(button.dataset.tab));
}

// Resume a session if this tab already had one.
try {
  const saved = JSON.parse(sessionStorage.getItem("shield-console") || "null");
  if (saved && saved.token) {
    $("baseUrl").value = saved.base || "";
    $("token").value = saved.token;
    connect();
  }
} catch { /* nothing saved, or storage unavailable */ }
