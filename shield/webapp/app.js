/**
 * UI wiring. All judgement lives in verify.js; this file only renders.
 *
 * One rule runs through the rendering: a verified chain is stated plainly, and
 * everything it does not establish is stated just as plainly next to it. A
 * green tick with no caveat would be the overclaim this whole codebase exists
 * to avoid — the recipient of a package is usually in a dispute, and what they
 * do with an overstated result is quote it.
 */
import { ShieldClient, ShieldError } from "./api.js";
import { verifyPackage, judgePhoto } from "./verify.js";

const $ = (id) => document.getElementById(id);
const client = () => new ShieldClient($("baseUrl").value, $("token").value || null);

/* ------------------------------------------------------------------- tabs -- */

for (const tab of document.querySelectorAll("[role=tab]")) {
  tab.addEventListener("click", () => {
    for (const other of document.querySelectorAll("[role=tab]")) {
      const on = other === tab;
      other.setAttribute("aria-selected", String(on));
      $(other.dataset.tab).hidden = !on;
    }
  });
}

/* ---------------------------------------------------------------- helpers -- */

const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function show(node, html) { node.innerHTML = html; }

function fail(node, err) {
  const message = err instanceof ShieldError ? err.message : String(err);
  show(node, `<div class="card bad"><h3>Could not complete that</h3>
    <p>${esc(message)}</p></div>`);
}

const money = (cents) => `$${(cents / 100).toLocaleString("en-US",
  { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

/* ----------------------------------------------------------------- verify -- */

let loadedPackage = null;

function renderVerification({ verifiable, chain, findings, photos }) {
  const node = $("verifyResult");

  if (!verifiable) {
    return show(node, `<div class="card bad"><h3>Not verifiable</h3>
      ${findings.map((f) => `<p>${esc(f.text)}</p>`).join("")}</div>`);
  }

  const lying = findings.filter((f) => f.severity === "lying");
  let head = "", cls = "", detail = "";

  if (chain.ambiguous) {
    cls = "unknown";
    head = "Cannot be checked in a browser";
    detail = `<p>${esc(chain.reason)}</p>`;
  } else if (!chain.intact) {
    cls = "bad";
    head = `Chain does not verify — entry ${chain.brokeAt + 1} of ${chain.entries}`;
    detail = `<p>${esc(chain.reason)}</p>`;
  } else if (chain.headMatchesExpected === false) {
    cls = "bad";
    head = "Every link verifies, but the chain has been shortened";
    detail = `<p>${esc(chain.reason)}</p>`;
  } else if (chain.headMatchesExpected === true) {
    cls = "good";
    head = "Verified, and it ends where you were told it would";
    detail = `<p>All ${chain.entries} entries link correctly, and the chain
      ends at the head hash you supplied. Nothing was altered, inserted,
      removed or reordered after it was written.</p>`;
  } else {
    cls = "partial";
    head = "Every link verifies";
    detail = `<p>All ${chain.entries} entries link correctly.</p>
      <p class="caveat">${esc(chain.reason)}</p>`;
  }

  const photoFatal = findings.filter((f) => f.photo && f.severity === "fatal");
  const photoUnverified = findings.filter((f) => f.photo && f.severity === "unverified");
  if (chain.intact && !chain.ambiguous && chain.headMatchesExpected !== false) {
    if (photoFatal.length) {
      cls = "bad";
      head = "Chain verifies, but a photo does not match its sealed upload record";
      detail = photoFatal.map((f) => `<p>${esc(f.text)}</p>`).join("");
    } else if (photoUnverified.length) {
      cls = "unknown";
      head = "Chain verifies, but a photo cannot be tied to a sealed upload record";
      detail = `<p>This is not a pass, and it is not a finding that the photo
        was swapped. There is no sealed upload entry to compare it to.</p>`
        + photoUnverified.map((f) => `<p>${esc(f.text)}</p>`).join("");
    }
  }
  const photoRows = photos || [];
  const photosBound = photoRows.some((p) =>
    p.status === "match" || p.status === "file not supplied");
  const photoNote = photosBound && !photoFatal.length && !photoUnverified.length
    ? `<p>Each photo hash in the manifest matches the sealed upload record.</p>`
    : "";

  const rows = [
    ["Entries", chain.entries],
    ["Genesis", chain.genesis],
    ["Computed head", chain.headHash ?? "—"],
  ];

  show(node, `
    <div class="card ${cls}">
      <h3>${esc(head)}</h3>
      ${detail}
      ${lying.length ? `<div class="lying"><h4>The package misdescribes itself</h4>
        ${lying.map((f) => `<p>${esc(f.text)}</p>`).join("")}</div>` : ""}
      <dl class="facts">${rows.map(([k, v]) =>
        `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join("")}</dl>
      ${photoNote}
      ${chain.intact ? `<p class="limits"><strong>What this does not show.</strong>
        That a photograph came off a camera rather than a file picker; that
        entries were never omitted <em>before</em> the chain was written; or
        that any assessment in the record is correct.</p>` : ""}
    </div>`);
}

async function loadPackage(file) {
  $("fileName").textContent = file.name;
  try {
    loadedPackage = JSON.parse(await file.text());
  } catch (err) {
    loadedPackage = null;
    return fail($("verifyResult"),
      "That file is not valid JSON, so it is not a package this can read.");
  }
  await runVerification();
}

async function runVerification() {
  if (!loadedPackage) return;
  try {
    const expectHead = $("expectHead").value.trim() || null;
    renderVerification(await verifyPackage(loadedPackage, { expectHead }));
  } catch (err) {
    fail($("verifyResult"), err);
  }
}

const drop = $("drop");
drop.addEventListener("click", () => $("packageFile").click());
drop.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("packageFile").click(); }
});
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files[0]) loadPackage(e.dataTransfer.files[0]);
});
$("packageFile").addEventListener("change", (e) => {
  if (e.target.files[0]) loadPackage(e.target.files[0]);
});
$("expectHead").addEventListener("change", runVerification);

$("photoFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file || !loadedPackage) {
    return show($("photoResult"),
      `<p class="muted">Load a package first.</p>`);
  }
  const judged = await judgePhoto(loadedPackage, file);
  const cls = judged.verdict === "match" ? "good"
    : judged.verdict === "UNVERIFIED" ? "unknown" : "bad";
  show($("photoResult"), `<div class="card ${cls}">
    <p>${esc(judged.text)}</p>
    <dl class="facts"><dt>SHA-256</dt><dd class="mono">${esc(judged.actual)}</dd></dl>
  </div>`);
});

/* ---------------------------------------------------------------- pricing -- */

$("loadPricing").addEventListener("click", async () => {
  const node = $("pricingResult");
  show(node, `<p class="muted">Loading…</p>`);
  try {
    const list = await client().pricing();
    show(node, `
      <div class="card">
        <table>
          <thead><tr><th>Tier</th><th>Job budget</th><th>Price</th></tr></thead>
          <tbody>${list.tiers.map((t) => `<tr>
            <td>${esc(t.tier)}</td><td>${esc(t.job_budget_band)}</td>
            <td class="num">${esc(t.price || money(t.price_cents))}</td></tr>`).join("")}
          </tbody>
        </table>
        <p class="commitment">${esc(list.commitment)}</p>
        <p class="muted small">Price depends on
          <code>${esc((list.price_depends_on || []).join(", "))}</code>
          and nothing else. Effective ${esc(list.effective)}.</p>
        <h4>Never charged, at any price</h4>
        <ul>${(list.never_charged || []).map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
        ${(list.notes || []).map((n) => `<p class="muted small">${esc(n)}</p>`).join("")}
      </div>`);
  } catch (err) { fail(node, err); }
});

/* ---------------------------------------------------------------- results -- */

$("loadResults").addEventListener("click", async () => {
  const node = $("resultsResult");
  show(node, `<p class="muted">Loading…</p>`);
  try {
    const r = await client().results();
    const counts = (title, obj, rates) => `
      <h4>${esc(title)}</h4>
      <table><thead><tr><th>Verdict</th><th>Count</th><th>Share</th></tr></thead>
      <tbody>${Object.entries(obj).map(([k, v]) => `<tr>
        <td>${esc(k)}</td><td class="num">${v}</td>
        <td class="num">${rates ? `${rates[k]}%` : "—"}</td></tr>`).join("")}
      </tbody></table>`;

    show(node, `
      <div class="card">
        <dl class="facts">
          <dt>Jobs closed</dt><dd class="num">${r.sample.jobs_closed}</dd>
          <dt>Photos recorded</dt><dd class="num">${r.sample.photos_recorded}</dd>
          <dt>of which superseded</dt><dd class="num">${r.sample.photos_superseded}</dd>
          <dt>Integrity flags</dt><dd class="num">${r.integrity_flags}</dd>
        </dl>
        ${r.sufficient_sample ? "" :
          `<p class="caveat">${esc(r.sample_note)}</p>`}
        ${counts("Job verdicts", r.job_verdicts, r.job_verdict_rates_pct)}
        ${counts("Photo verdicts", r.photo_verdicts, r.photo_verdict_rates_pct)}
        <h4>Attestation</h4>
        <p class="muted small">${esc(r.attestation.note)}</p>
        <h4>Stated limits</h4>
        <ul>${r.limits.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
        <p class="muted small">${esc(r.method)}</p>
        <p class="muted small">Generated ${esc(r.generated_at)}.</p>
      </div>`);
  } catch (err) { fail(node, err); }
});

/* ----------------------------------------------------------------- record -- */

function wire(buttonId, call) {
  $(buttonId).addEventListener("click", async () => {
    const node = $("recordResult");
    const jobId = $("jobId").value.trim();
    if (!jobId) return show(node, `<p class="muted">Enter a job id first.</p>`);
    show(node, `<p class="muted">Loading…</p>`);
    try {
      const data = await call(client(), jobId);
      show(node, `<pre class="mono dump">${esc(JSON.stringify(data, null, 2))}</pre>`);
    } catch (err) { fail(node, err); }
  });
}

wire("loadCheckpoints", (c, id) => c.listCheckpoints(id));
wire("loadCustody", (c, id) => c.custody(id));
wire("loadEvidence", (c, id) => c.evidence(id));
