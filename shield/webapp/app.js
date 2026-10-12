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
import { verifyPackage, checkPhoto } from "./verify.js";
import { judgeOfflineSeal } from "./seal.js";

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
let suppliedPhoto = null;
let suppliedAnchors = null;

function sealClass(label) {
  if (label === "SEALED") return "good";
  if (label === "UNVERIFIED TIME" || label === "receipt present, timestamp absent"
      || label === "receipt absent") {
    return "partial";
  }
  if (label === "TAMPERED" || label === "FORGED" || label === "DEVICE CLOCK MISMATCH") {
    return "bad";
  }
  return "unknown";
}

function renderSeal(seal) {
  const label = seal && seal.label;
  if (!label) {
    return `<div class="card unknown" id="sealCard">
      <p class="kicker">Offline seal</p>
      <h3>No offline seal</h3>
      <p>${esc((seal && seal.detail) || "This package has no offline seal.")}</p>
    </div>`;
  }
  const flags = seal.flags && seal.flags.length
    ? `Flags: ${seal.flags.join(", ")}.`
    : "No flags are set.";
  const notes = (seal.notes || []).map((note) =>
    `<p class="caveat">${esc(note)}</p>`).join("");
  return `<div class="card ${sealClass(label)}" id="sealCard">
    <p class="kicker">Offline seal</p>
    <h3>${esc(label)}</h3>
    <p>${esc(seal.detail || "")}</p>
    ${notes}
    <p>${esc(flags)} Flags do not change this label.</p>
    <p class="limits">Computed in this page from the package bytes. No request
      was made. A timestamp, when one is present, is checked against the
      DigiCert and Sectigo certificates pinned in this page.</p>
  </div>`;
}

function renderVerification({ verifiable, chain, findings, notes }, seal) {
  const node = $("verifyResult");
  const sealHtml = renderSeal(seal);

  if (!verifiable) {
    return show(node, `<div class="card bad" id="custodyCard"><h3>Not verifiable</h3>
      ${findings.map((f) => `<p>${esc(f.text)}</p>`).join("")}</div>${sealHtml}`);
  }

  const lying = findings.filter((f) => f.severity === "lying");
  const locked = findings.filter((f) => f.kind === "locked");
  const anchor = findings.filter((f) => f.kind === "anchor");
  const noteHtml = (notes || []).map((note) =>
    `<p class="caveat">${esc(note)}</p>`).join("");
  let head = "", cls = "", detail = "";

  if (chain.ambiguous) {
    cls = "unknown";
    head = "Cannot be checked in a browser";
    detail = `<p>${esc(chain.reason)}</p>`;
  } else if (!chain.intact) {
    cls = "bad";
    head = `Chain does not verify — entry ${chain.brokeAt + 1} of ${chain.entries}`;
    detail = `<p>${esc(chain.reason)}</p>`;
  } else if (locked.length) {
    cls = "bad";
    head = "The chain links, but there is no locked anchor for this head";
    detail = locked.map((f) => `<p>${esc(f.text)}</p>`).join("");
  } else if (anchor.length) {
    cls = "bad";
    head = "The chain links, but the receipt does not cover this head";
    detail = anchor.map((f) => `<p>${esc(f.text)}</p>`).join("");
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

  const rows = [
    ["Entries", chain.entries],
    ["Genesis", chain.genesis],
    ["Computed head", chain.headHash ?? "—"],
  ];

  show(node, `
    <div class="card ${cls}" id="custodyCard">
      <h3>${esc(head)}</h3>
      ${detail}
      ${noteHtml}
      ${lying.length ? `<div class="lying"><h4>The package misdescribes itself</h4>
        ${lying.map((f) => `<p>${esc(f.text)}</p>`).join("")}</div>` : ""}
      <dl class="facts">${rows.map(([k, v]) =>
        `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join("")}</dl>
      ${chain.intact ? `<p class="limits"><strong>What this does not show.</strong>
        That a photograph came off a camera rather than a file picker; that
        entries were never omitted <em>before</em> the chain was written; or
        that any assessment in the record is correct.</p>` : ""}
    </div>${sealHtml}`);
}

async function loadPackage(file) {
  $("fileName").textContent = file.name;
  suppliedPhoto = null;
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
    const custody = await verifyPackage(loadedPackage, {
      expectHead, anchors: suppliedAnchors,
    });
    const seal = await judgeOfflineSeal(loadedPackage, {
      files: suppliedPhoto ? [{ bytes: suppliedPhoto }] : undefined,
      anchors: suppliedAnchors,
    });
    renderVerification(custody, seal);
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
$("anchorsFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) {
    suppliedAnchors = null;
    $("anchorsName").textContent = "No anchor file loaded.";
    return;
  }
  try {
    const parsed = JSON.parse(await file.text());
    suppliedAnchors = Array.isArray(parsed) ? parsed : (parsed.anchors || []);
    $("anchorsName").textContent = file.name;
  } catch {
    suppliedAnchors = null;
    $("anchorsName").textContent = "That file is not anchor JSON.";
  }
  await runVerification();
});

$("photoFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file || !loadedPackage) {
    return show($("photoResult"),
      `<p class="muted">Load a package first.</p>`);
  }
  const hashes = (loadedPackage.checkpoints || [])
    .map((c) => c.sha256_original).filter(Boolean);
  suppliedPhoto = new Uint8Array(await file.arrayBuffer());
  const { actual } = await checkPhoto(file, null);
  const match = hashes.includes(actual);
  await runVerification();
  show($("photoResult"), `<div class="card ${match ? "good" : "bad"}">
    <p>${match
      ? "This file matches a photo hash recorded in the package."
      : "This file does not match any photo hash in the package."}</p>
    <dl class="facts"><dt>SHA-256</dt><dd class="mono">${esc(actual)}</dd></dl>
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
