/**
 * Node harness so pytest can drive verify.js and compare it against ledger.py.
 *
 * The browser verifier is only worth shipping if it agrees with the
 * implementation that writes the chains, byte for byte. Two encoders that
 * disagree do not report "we disagree" — the JavaScript one reports BROKEN on
 * an intact package, which is this product accusing an honest contractor of
 * tampering because of a formatting difference.
 *
 * So the test is differential rather than example-based: the same values go
 * through both implementations and the bytes are compared. Reads one JSON
 * request on stdin, writes one JSON response on stdout.
 */
import { canonical, pyJson, pyRepr, verifyChain, genesisHash, link }
  from "../verify.js";

const stdin = await new Promise((resolve) => {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (d) => { buf += d; });
  process.stdin.on("end", () => resolve(buf));
});

const req = JSON.parse(stdin);
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

function attempt(fn) {
  try { return { ok: true, value: fn() }; }
  catch (err) { return { ok: false, error: err.constructor.name }; }
}

let out;
switch (req.op) {
  case "repr":
    // Strict JSON has no NaN or Infinity, so non-finite cases arrive as a
    // marker and are revived here. That limitation is real rather than a test
    // convenience: a non-finite value cannot reach a browser verifier through
    // a package at all, because JSON.parse rejects the literal first.
    out = req.values.map((v) => attempt(() => pyRepr(
      typeof v === "string" && v.startsWith("__nonfinite__")
        ? { nan: NaN, inf: Infinity, "-inf": -Infinity }[v.slice(13)]
        : v)));
    break;

  case "json":
    out = req.values.map((v) => attempt(() => pyJson(v)));
    break;

  case "canonical":
    // Hex rather than the decoded string: a difference in how the two
    // languages encode a character must show up here, not be normalised away
    // by the comparison itself.
    out = req.entries.map((e) => attempt(() => hex(canonical(e))));
    break;

  case "genesis":
    out = await genesisHash(req.shield_job_id);
    break;

  case "link":
    out = await link(req.entry, req.prev_hash);
    break;

  case "verify":
    out = await verifyChain(req.entries, req.shield_job_id,
                            { expectHead: req.expect_head ?? null });
    break;

  default:
    out = { error: `unknown op ${req.op}` };
}

process.stdout.write(JSON.stringify(out));
