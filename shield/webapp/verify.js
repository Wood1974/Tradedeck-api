/**
 * Shield custody verification, in the browser, from the spec.
 *
 * This is a third independent implementation of `SPEC.md` — after `ledger.py`
 * (which writes chains) and `verifier/shield_verify.py` (which checks them).
 * It exists because the Python verifier is the right tool for an adjuster with
 * a terminal and the wrong one for everybody else, and "verifiable without
 * trusting us" means nothing if verifying requires installing Python.
 *
 * It imports nothing. No framework, no bundler, no network, no Shield code.
 * Open the page with the wifi off and it still works, which is the point: a
 * recipient checking our package by calling our API is asking the accused to
 * re-examine themselves.
 *
 * The part that is actually hard
 * ------------------------------
 * Byte-for-byte agreement with Python's canonical form. The chain hashes a
 * JSON serialisation, so any divergence in how the two languages render the
 * same value produces a different hash — and a verifier that computes a
 * different hash does not report "our encoders disagree". It reports BROKEN,
 * on a package that is perfectly intact.
 *
 * That failure mode is worse than useless. It is this product accusing an
 * honest contractor of tampering because of a floating-point formatting
 * difference, which is exactly the class of thing `rebroadcast-never-accuses`
 * exists to prevent on the optics side. Two divergences are real and both are
 * handled below:
 *
 *   1. **Float formatting.** `ledger.canonical()` renders floats with Python's
 *      `repr()`. `String(40.0)` is `"40"` in JavaScript and `"40.0"` in
 *      Python; `String(1e16)` is `"10000000000000000"` and `"1e+16"`. GPS
 *      coordinates are the realistic payload, so the common case would have
 *      passed a casual test and broken on a latitude that happened to be
 *      integral. `pyRepr` reimplements CPython's rule.
 *
 *   2. **Non-ASCII escaping.** Python's `json.dumps` defaults to
 *      `ensure_ascii=True` and emits `\uXXXX`; `JSON.stringify` emits the
 *      character. Any accented character in a site address or a field note
 *      would diverge. `pyJson` escapes like Python.
 *
 * Both are pinned by a differential test that fuzzes values through this file
 * and through `ledger.py` and compares bytes.
 */

const GENESIS_PREFIX = "shield-custody-genesis-v1:";

/** Hashed fields, in the fixed order of SPEC.md §1. */
export const SIGNED_FIELDS = [
  "shield_job_id", "photo_id", "event_type", "actor_id", "actor_type",
  "event_data", "gps_lat", "gps_lng", "file_hash", "integrity_note",
  // exif_captured_at is NOT here since chain_version 2 (AR-11): the uploader
  // writes EXIF DateTimeOriginal, so sealing it proved only that we had not
  // changed it, which reads as though the capture time were established.
  "recorded_at",
];

/**
 * Signed fields Python seals as floats — which JSON cannot tell us.
 *
 * `ledger.canonical()` branches on `isinstance(value, float)`, and a Python
 * float always renders through `repr()`: 40.0 becomes the string "40.0".
 * By the time that entry reaches a browser it has been through JSON, where
 * 40.0 and 40 are the same token. `JSON.parse` hands back the number 40 and
 * nothing distinguishes it from an integer, so a verifier that decides by
 * inspecting the value gets integral coordinates wrong — and only integral
 * ones, which is why the realistic payload (40.76056) passes while a latitude
 * that lands exactly on a degree fails.
 *
 * Writing this file is what surfaced it. SPEC.md §1 said "floats via repr()"
 * and left the reader to work out which fields are floats; that is answerable
 * from the Python source and not from the spec, which makes it a defect in the
 * spec rather than in either implementation. The list is now named in both.
 *
 * Guessing is not an option and neither is trying both renderings until one
 * verifies — a verifier that searches for an interpretation under which the
 * package passes is not verifying it. So the contract is declared: these two
 * fields are floats, every other signed field is a string or a structure, and
 * `routes.py` coerces with `float()` before sealing.
 */
export const FLOAT_FIELDS = new Set(["gps_lat", "gps_lng"]);

/**
 * The same ambiguity one level down, where it cannot be fixed by declaration.
 *
 * `event_data` is free-form and Python serialises it with `json.dumps`, which
 * renders the float 100.0 as `100.0` and the integer 100 as `100`. After JSON
 * transport both are the token `100`, and unlike `gps_lat` there is no fixed
 * field list to declare — the structure is written at many call sites with
 * whatever keys suit them.
 *
 * This is not hypothetical. Close-out seals
 * `{"verdict": …, "score": 100.0, "coverage_pct": 100.0, …}`, where `score`
 * and `coverage_pct` come from `round()` and are therefore floats that are
 * very often integral. A passing job produces exactly the entry this cannot
 * distinguish.
 *
 * Why it matters that this is handled precisely rather than defensively:
 * "a signed field was edited after it was written" is an accusation, and
 * making it against an honest contractor because two languages disagree about
 * a trailing zero would be indistinguishable, to the reader, from the real
 * finding. But the opposite error is just as bad — the first version of this
 * check simply asked "does event_data hold any whole number?", which is true
 * of nearly every entry, so it excused every mismatch and the verifier stopped
 * being able to report tampering at all. `ambiguityExplains` below decides the
 * question instead of dodging it; its own test caught the earlier version.
 *
 * The real fix is a chain format that cannot be read two ways — rendering
 * nested floats through `repr()` the way top-level ones already are, so a
 * package carries its own types. That changes every historical hash, making it
 * a `chain_version` bump and a migration, and it is not this file's call to
 * make. `shield_custody_log` is empty today, so the migration would cost
 * nothing; that window will not stay open.
 */
const FLOAT_MARK = Symbol("python-float");

/** Every position in a structure holding a whole number, as a path list. */
function integralPaths(value, path = [], out = [], depth = 0) {
  if (depth > 20) return out;
  if (typeof value === "number" && Number.isInteger(value)) out.push(path);
  else if (Array.isArray(value)) {
    value.forEach((v, i) => integralPaths(v, [...path, i], out, depth + 1));
  } else if (value && typeof value === "object") {
    for (const k of Object.keys(value)) {
      integralPaths(value[k], [...path, k], out, depth + 1);
    }
  }
  return out;
}

/** A copy with the numbers at `paths` marked to render as Python floats. */
function markFloats(value, paths) {
  const copy = structuredClone(value);
  for (const path of paths) {
    if (path.length === 0) return { [FLOAT_MARK]: value };
    let node = copy;
    for (const step of path.slice(0, -1)) node = node[step];
    const last = path[path.length - 1];
    node[last] = { [FLOAT_MARK]: node[last] };
  }
  return copy;
}

/**
 * Decide whether a hash mismatch is explained by the int/float ambiguity.
 *
 * The naive version of this check — "does event_data contain any whole
 * number?" — was written first and was much worse than useless. Nearly every
 * event_data holds some integer, so it excused every mismatch, and a verifier
 * that never reports tampering is not a verifier. Its own test caught it.
 *
 * This version decides rather than guesses. Each whole number in `event_data`
 * was sealed by Python as either an int or a float; that is a bounded set of
 * readings, so enumerate them and hash each. Then:
 *
 *   - the default reading matches   -> verified, normal path, never reaches here
 *   - some other reading matches    -> AMBIGUOUS. The mismatch is fully
 *                                      explained by the format defect, and we
 *                                      say we cannot check it rather than
 *                                      reporting either pass or tampering
 *   - no reading matches            -> TAMPERED, definitively. No
 *                                      interpretation of the ambiguity
 *                                      produces the stored hash, so the
 *                                      ambiguity is not what is wrong
 *
 * Note what this never does: report `intact: true` on a non-default reading. A
 * verifier that searches for an interpretation under which the package passes
 * has stopped verifying. Searching to find out whether a *known encoding
 * defect* could account for a failure is a different act, and its answer is
 * "cannot determine", never "fine".
 */
async function ambiguityExplains(entry, prevHash) {
  const paths = integralPaths(entry.event_data);
  if (paths.length === 0) return false;
  if (paths.length > 12) {
    // 2^12 is 4096 hashes, which is instant; beyond that stop enumerating and
    // fall back to the all-float reading, the one Python's round() produces.
    const probe = { ...entry, event_data: markFloats(entry.event_data, paths) };
    return (await link(probe, prevHash)) === entry.entry_hash;
  }
  for (let mask = 1; mask < (1 << paths.length); mask++) {
    const chosen = paths.filter((_, i) => mask & (1 << i));
    const probe = { ...entry, event_data: markFloats(entry.event_data, chosen) };
    if ((await link(probe, prevHash)) === entry.entry_hash) return true;
  }
  return false;
}

/* ------------------------------------------------------------------ bytes -- */

const encoder = new TextEncoder();

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 of a File/Blob/ArrayBuffer, for checking supplied photo bytes. */
export async function hashBytes(input) {
  const buf = input instanceof ArrayBuffer ? input : await input.arrayBuffer();
  return sha256Hex(new Uint8Array(buf));
}

/* ----------------------------------------------------------- python parity -- */

/**
 * CPython's `repr()` for a finite float.
 *
 * CPython picks the shortest digit string that round-trips — which is also
 * what `Number.prototype.toExponential()` with no argument gives — and then
 * formats it with two rules JavaScript does not share: decimal notation is
 * used when `-4 < decpt <= 16` (JavaScript switches at 21), and an integral
 * value keeps a trailing `.0`.
 *
 * `decpt` is the decimal exponent with the value written as 0.d1d2… × 10^decpt.
 */
export function pyRepr(value) {
  if (!Number.isFinite(value)) {
    // ledger.py raises here rather than sealing 'nan' as if it were a
    // coordinate. A verifier that quietly accepted one would disagree with
    // every chain the service is capable of writing.
    throw new RangeError("non-finite value cannot appear in a custody chain");
  }
  if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";

  const negative = value < 0;
  const [mantissa, exponent] = Math.abs(value).toExponential().split("e");
  const digits = mantissa.replace(".", "");
  const decpt = parseInt(exponent, 10) + 1;

  let out;
  if (decpt <= -4 || decpt > 16) {
    const lead = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const e = decpt - 1;
    out = `${lead}e${e < 0 ? "-" : "+"}${String(Math.abs(e)).padStart(2, "0")}`;
  } else if (decpt <= 0) {
    out = `0.${"0".repeat(-decpt)}${digits}`;
  } else if (decpt >= digits.length) {
    out = `${digits}${"0".repeat(decpt - digits.length)}.0`;
  } else {
    out = `${digits.slice(0, decpt)}.${digits.slice(decpt)}`;
  }
  return negative ? `-${out}` : out;
}

const ESCAPES = { "\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r",
                  "\t": "\\t", "\b": "\\b", "\f": "\\f" };

function pyString(text) {
  let out = '"';
  for (const ch of String(text)) {
    const code = ch.codePointAt(0);
    if (ESCAPES[ch]) out += ESCAPES[ch];
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else if (code < 0x7f) out += ch;
    else if (code > 0xffff) {
      // Python emits a surrogate pair, same as the UTF-16 representation.
      const v = code - 0x10000;
      const hi = 0xd800 + (v >> 10), lo = 0xdc00 + (v & 0x3ff);
      out += `\\u${hi.toString(16).padStart(4, "0")}`;
      out += `\\u${lo.toString(16).padStart(4, "0")}`;
    } else out += `\\u${code.toString(16).padStart(4, "0")}`;
  }
  return `${out}"`;
}

/**
 * `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
 *
 * Keys sort by code point. JavaScript's default sort compares UTF-16 code
 * units, which orders an astral character before some BMP ones — invisible
 * until a chain carries an emoji in a field note, and then permanently wrong.
 */
export function pyJson(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new RangeError("non-finite value in JSON");
    return Number.isInteger(value) && !Object.is(value, -0)
      ? String(value) : pyRepr(value);
  }
  if (typeof value === "string") return pyString(value);
  if (Array.isArray(value)) return `[${value.map(pyJson).join(",")}]`;
  // A number the ambiguity probe has marked as having been a Python float.
  // Unquoted: `json.dumps` renders a nested float as the bare token 100.0.
  // Only a *top-level* signed field is turned into a string, by
  // ledger.canonical() rather than by the JSON encoder.
  if (FLOAT_MARK in value) return pyRepr(value[FLOAT_MARK]);

  const keys = Object.keys(value).sort((a, b) => {
    const ax = [...a], bx = [...b];
    for (let i = 0; i < Math.min(ax.length, bx.length); i++) {
      const d = ax[i].codePointAt(0) - bx[i].codePointAt(0);
      if (d !== 0) return d;
    }
    return ax.length - bx.length;
  });
  return `{${keys.map((k) => `${pyString(k)}:${pyJson(value[k])}`).join(",")}}`;
}

/* --------------------------------------------------------------- the chain -- */

/** SPEC.md §1 — deterministic bytes for the signed subset of one entry. */
export function canonical(entry) {
  const out = {};
  for (const key of SIGNED_FIELDS) {
    const value = entry[key];
    if (value === null || value === undefined) continue;   // absent === null
    if (FLOAT_FIELDS.has(key)) {
      // Declared, not detected — see FLOAT_FIELDS. A number here is a float
      // whatever JSON made of it, and a string is one Python already rendered.
      out[key] = typeof value === "number" ? pyRepr(value) : String(value);
    } else if (typeof value === "object") {
      out[key] = pyJson(value);
    } else {
      out[key] = value;
    }
  }
  return encoder.encode(pyJson(out));
}

/** SPEC.md §2. */
export async function genesisHash(shieldJobId) {
  return sha256Hex(encoder.encode(GENESIS_PREFIX + String(shieldJobId)));
}

/** SPEC.md §3 — `SHA256( canonical(entry) || "|" || prev_hash )`. */
export async function link(entry, prevHash) {
  const body = canonical(entry);
  const tail = encoder.encode(`|${prevHash}`);
  const joined = new Uint8Array(body.length + tail.length);
  joined.set(body, 0);
  joined.set(tail, body.length);
  return sha256Hex(joined);
}

/**
 * SPEC.md §4 — walk the chain oldest first and report *where* it breaks.
 *
 * "Entry 7 of 12 fails, and here is why" is actionable. "Invalid" sends
 * somebody back to us to ask what happened, which defeats the purpose.
 */
export async function verifyChain(entries, shieldJobId, { expectHead = null } = {}) {
  const ordered = [...entries].sort((a, b) =>
    String(a.recorded_at ?? "").localeCompare(String(b.recorded_at ?? "")));

  const genesis = await genesisHash(shieldJobId);
  const result = {
    intact: false, entries: ordered.length, genesis,
    headHash: null, brokeAt: null, reason: null,
    headMatchesExpected: null, truncationChecked: expectHead != null,
    ambiguous: false,
  };

  if (ordered.length === 0) {
    result.reason = "The package carries no custody entries, so there is " +
      "nothing to verify. Its integrity is the producer's assertion.";
    return result;
  }

  let expectedPrev = genesis;
  for (let i = 0; i < ordered.length; i++) {
    const entry = ordered[i];
    const position = `entry ${i + 1} of ${ordered.length}`;

    if (!entry.entry_hash) {
      result.brokeAt = i;
      result.reason = `${position} carries no entry_hash — it was never ` +
        `chained, or the hash was stripped.`;
      return result;
    }
    if (entry.prev_hash !== expectedPrev) {
      result.brokeAt = i;
      result.reason = `${position} does not follow the one before it. An ` +
        `entry was inserted, removed or reordered here.`;
      return result;
    }
    let recomputed;
    try {
      recomputed = await link(entry, expectedPrev);
    } catch (err) {
      result.brokeAt = i;
      result.reason = `${position} cannot be canonicalised: ${err.message}`;
      return result;
    }
    if (recomputed !== entry.entry_hash) {
      result.brokeAt = i;
      // Only version 1 can be ambiguous. Version 2 renders nested floats
      // through repr(), so the package says which it sealed -- and excusing a
      // v2 mismatch as "a whole number might have been a float" would hand an
      // attacker the exact sentence they want a verifier to print.
      const mayBeV1 = Number(entry.chain_version ?? 1) === 1;
      if (mayBeV1 && await ambiguityExplains(entry, expectedPrev)) {
        // Do not accuse. See mayBeAmbiguous.
        result.ambiguous = true;
        result.reason = `${position} cannot be verified from JSON alone. Its ` +
          `event_data holds a whole number, and JSON cannot record whether ` +
          `that was written as 100 or 100.0 — the two seal differently. This ` +
          `is a known limitation of the published format, not evidence that ` +
          `anything was altered. Verify this package with the Python ` +
          `verifier, which reads the value's original type.`;
      } else {
        result.reason = `${position} has a signed field that was edited ` +
          `after it was written. Recomputing its hash does not reproduce the ` +
          `one stored with it.`;
      }
      return result;
    }
    expectedPrev = entry.entry_hash;
  }

  result.intact = true;
  result.headHash = expectedPrev;

  if (expectHead != null) {
    result.headMatchesExpected =
      expectHead.trim().toLowerCase() === expectedPrev;
    if (!result.headMatchesExpected) {
      result.reason = "Every link verifies, but the chain does not end at " +
        "the head hash you were given earlier. Entries have been removed " +
        "from the end, or the whole chain was rewritten.";
    }
  } else {
    // SPEC.md §6. Truncation leaves a shorter chain in which every remaining
    // link still verifies, and the producer simply updates head_hash. Saying
    // "verified" without flagging this would overstate what was checked.
    result.reason = "Every link verifies. This does not rule out entries " +
      "having been deleted from the end of the chain — only a head hash you " +
      "obtained earlier, from your own records, can do that.";
  }
  return result;
}

/**
 * SPEC.md §5 — verify a package and cross-check what it claims about itself.
 *
 * A package whose own `head_hash` disagrees with the computed head, or which
 * asserts `chain_intact: true` over a chain that breaks, is lying about
 * itself. The spec is explicit that this is a more serious finding than a
 * broken chain, so it is reported separately rather than folded in.
 */
export async function verifyPackage(manifest, { expectHead = null } = {}) {
  const jobId = manifest?.job?.shield_job_id;
  const entries = manifest?.custody_entries;
  const findings = [];

  if (!jobId) {
    return {
      verifiable: false, chain: null, findings: [{
        severity: "fatal",
        text: "No job.shield_job_id in the package. The genesis value derives " +
          "from it, so the chain cannot be checked at all.",
      }],
    };
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      verifiable: false, chain: null, findings: [{
        severity: "fatal",
        text: "No custody_entries in the package. SPEC.md §5: a package " +
          "without them is not verifiable, and its integrity is the " +
          "producer's assertion rather than something you can check.",
      }],
    };
  }

  const chain = await verifyChain(entries, jobId, { expectHead });

  const claimedHead = manifest?.custody?.head_hash;
  if (claimedHead && chain.headHash && claimedHead !== chain.headHash) {
    findings.push({
      severity: "lying",
      text: "The package states a head hash that is not the head of the " +
        "chain it contains. It is misdescribing itself.",
    });
  }
  if (manifest?.custody?.chain_intact === true && !chain.intact) {
    findings.push({
      severity: "lying",
      text: "The package asserts chain_intact: true over a chain that does " +
        "not verify. Per SPEC.md §5 this is a more serious finding than a " +
        "broken chain on its own.",
    });
  }
  if (chain.headMatchesExpected === false) {
    findings.push({
      severity: "fatal",
      text: "The chain does not end at the head hash you supplied.",
    });
  }
  if (!chain.intact) {
    findings.push({ severity: "fatal", text: chain.reason });
  }

  return { verifiable: true, chain, findings };
}

/**
 * Check supplied photo bytes against the hash the package recorded.
 *
 * Deliberately separate from chain verification: the chain establishes that
 * the recorded hash was not altered, and this establishes that a file you were
 * handed is the file that hash describes. Neither says the photograph is of
 * what anyone claims, and nothing here says it came off a camera.
 */
export async function checkPhoto(file, expectedSha256) {
  const actual = await hashBytes(file);
  return { matches: actual === expectedSha256, actual, expected: expectedSha256 };
}
