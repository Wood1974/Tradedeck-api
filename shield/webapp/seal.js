/**
 * The offline seal, judged from the package bytes alone.
 *
 * This is the second card on the verify page. The custody card is verify.js.
 * Nothing here contacts a server. Timestamp roots are the certificates in
 * tsa_roots.js, pinned in the page. A package cannot supply its own root.
 *
 * The labels are the same words offline_seal.py returns. A differential test
 * runs one package through both and compares them. A disagreement would be
 * this page calling a record SEALED that the reference calls something else,
 * or the reverse, which is the page accusing someone the reference does not.
 */
import { pyJson, verifyChain } from "./verify.js";
import { PINNED_TSA_ROOTS } from "./tsa_roots.js";

const RECORD_FIELDS = [
  "version", "checkpoint_id", "photo_sha256", "ticket_id", "wall_time_ms",
  "monotonic_ms", "boot_id", "boot_count", "gnss_time_ms", "location_simulated",
  "sensor_hash", "depth_hash", "depth_present", "flags",
];
const TICKET_FIELDS = [
  "version", "record_id", "checkpoint_list_sha256", "actor_id",
  "expires_at_ms", "server_time_ms", "roughtime_ms",
];
const RECEIPT_FIELDS = ["version", "record_id", "head_hash", "accepted_at_ms"];
const CLOCK_FIELDS = ["boot_count", "boot_id", "monotonic_ms", "wall_time_ms"];

const LIMIT_MS = 120000;
const SEALED = "SEALED";
const TAMPERED = "TAMPERED";
const FORGED = "FORGED";
const UNVERIFIED = "UNVERIFIED TIME";
const MISMATCH = "DEVICE CLOCK MISMATCH";
const ABSENT = "receipt present, timestamp absent";
const RANK = {
  [SEALED]: 0, [ABSENT]: 10, [UNVERIFIED]: 20, [MISMATCH]: 30, [FORGED]: 40,
  [TAMPERED]: 50,
};

const FLAG_WORDS = [
  [1, "screen captured"],
  [2, "debugger attached"],
  [4, "mock location"],
  [8, "root traces"],
];

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const SHA384_OID = "2.16.840.1.101.3.4.2.2";
const ECDSA_SHA256_OID = "1.2.840.10045.4.3.2";
const ECDSA_SHA384_OID = "1.2.840.10045.4.3.3";
const RSA_SHA256_OID = "1.2.840.113549.1.1.11";
const RSA_SHA384_OID = "1.2.840.113549.1.1.12";
const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
const RSA_PSS_OID = "1.2.840.113549.1.1.10";
const SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
const TST_INFO_OID = "1.2.840.113549.1.9.16.1.4";
const CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const TIME_STAMPING_EKU = "1.3.6.1.5.5.7.3.8";
const EKU_OID = "2.5.29.37";

const SIG_OIDS = {
  [SHA256_OID]: new Set([ECDSA_SHA256_OID, RSA_SHA256_OID, RSA_PSS_OID, RSA_ENCRYPTION_OID]),
  [SHA384_OID]: new Set([ECDSA_SHA384_OID, RSA_SHA384_OID, RSA_PSS_OID, RSA_ENCRYPTION_OID]),
};

const textEncoder = new TextEncoder();

function worsen(state, name, reason) {
  if (RANK[name] > RANK[state.label]) state.label = name;
  if (reason) state.reasons.push(reason);
}

export function flagWords(flags) {
  if (!Number.isSafeInteger(flags) || flags < 0) return [];
  const names = FLAG_WORDS.filter(([bit]) => flags & bit).map(([, word]) => word);
  let known = 0;
  for (const [bit] of FLAG_WORDS) known |= bit;
  let extra = flags & ~known;
  let index = 0;
  while (extra) {
    if (extra & 1) names.push(`bit ${index}`);
    extra >>>= 1;
    index += 1;
  }
  return names;
}

function whole(value) {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function canonicalFields(obj, fields) {
  const out = {};
  for (const key of fields) {
    if (!obj || obj[key] === null || obj[key] === undefined) continue;
    const value = obj[key];
    if (typeof value === "number" && !whole(value)) {
      throw new Error(`${key} is not a whole number`);
    }
    out[key] = value;
  }
  return textEncoder.encode(pyJson(out));
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

async function sha384(bytes) {
  const digest = await crypto.subtle.digest("SHA-384", bytes);
  return new Uint8Array(digest);
}

function hexToBytes(hex) {
  if (typeof hex !== "string" || !/^[0-9a-f]{64}$/.test(hex)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function recordLink(record, prev) {
  const body = canonicalFields(record, RECORD_FIELDS);
  const tail = textEncoder.encode(`|${prev}`);
  return toHex(await sha256(concat(body, tail)));
}

function b64ToBytes(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const text = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function derWalk(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const items = [];
  let i = 0;
  while (i < bytes.length) {
    const start = i;
    const tag = bytes[i];
    i += 1;
    if (i >= bytes.length) throw new Error("truncated DER");
    let length = bytes[i];
    i += 1;
    if (length >= 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 4 || i + count > bytes.length) throw new Error("bad DER length");
      length = 0;
      for (let k = 0; k < count; k++) length = (length * 256) + bytes[i++];
    }
    if (i + length > bytes.length) throw new Error("truncated DER value");
    items.push({
      tag,
      value: bytes.subarray(i, i + length),
      raw: bytes.subarray(start, i + length),
    });
    i += length;
  }
  return items;
}

function oidToStr(content) {
  if (!content.length) throw new Error("empty oid");
  const parts = [String(Math.floor(content[0] / 40)), String(content[0] % 40)];
  let i = 1;
  while (i < content.length) {
    let n = 0;
    while (true) {
      if (i >= content.length) throw new Error("truncated oid");
      const byte = content[i];
      i += 1;
      n = (n * 128) + (byte & 0x7f);
      if ((byte & 0x80) === 0) break;
    }
    parts.push(String(n));
  }
  return parts.join(".");
}

function derInt(content) {
  if (!content.length) throw new Error("empty integer");
  if (content.length > 1 && content[0] === 0x00 && (content[1] & 0x80) === 0) {
    throw new Error("non-minimal integer");
  }
  let n = 0;
  for (const byte of content) {
    n = (n * 256) + byte;
    if (!Number.isSafeInteger(n)) return null;
  }
  return n;
}

function unpadInt(bytes, size) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
  const rest = bytes.subarray(i);
  if (rest.length > size) return null;
  const out = new Uint8Array(size);
  out.set(rest, size - rest.length);
  return out;
}

function derToP1363(der, size = 32) {
  try {
    const items = derWalk(der);
    if (items.length !== 1 || items[0].tag !== 0x30) return null;
    const inner = derWalk(items[0].value);
    if (inner.length < 2 || inner[0].tag !== 0x02 || inner[1].tag !== 0x02) return null;
    const r = unpadInt(inner[0].value, size);
    const s = unpadInt(inner[1].value, size);
    if (!r || !s) return null;
    return concat(r, s);
  } catch {
    return null;
  }
}

async function importP256(point) {
  return crypto.subtle.importKey(
    "raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

async function ecdsaVerify(point, signature, data, hash = "SHA-256") {
  if (!point || point.length !== 65 || point[0] !== 4) return false;
  // P-256 coordinates are 32 bytes. The hash (SHA-256 or SHA-384) does not
  // change the signature width.
  const raw = derToP1363(signature, 32);
  if (!raw) return false;
  try {
    const key = await importP256(point);
    return await crypto.subtle.verify({ name: "ECDSA", hash }, key, raw, data);
  } catch {
    return false;
  }
}

async function rsaVerify(spki, signature, data, hash, pss = false) {
  try {
    const algorithm = pss
      ? { name: "RSA-PSS", hash }
      : { name: "RSASSA-PKCS1-v1_5", hash };
    const key = await crypto.subtle.importKey("spki", spki, algorithm, false, ["verify"]);
    const params = pss
      ? { name: "RSA-PSS", saltLength: hash === "SHA-384" ? 48 : 32 }
      : { name: "RSASSA-PKCS1-v1_5" };
    return await crypto.subtle.verify(params, key, signature, data);
  } catch {
    return false;
  }
}

function cborDecode(bytes, i = 0) {
  if (i >= bytes.length) return null;
  const initial = bytes[i];
  const major = initial >> 5;
  const info = initial & 0x1f;
  i += 1;
  let length;
  if (info < 24) length = info;
  else if (info === 24) { length = bytes[i]; i += 1; }
  else if (info === 25) { length = (bytes[i] << 8) | bytes[i + 1]; i += 2; }
  else if (info === 26) {
    length = 0;
    for (let k = 0; k < 4; k++) length = (length * 256) + bytes[i++];
  } else return null;
  if (major === 0) return { value: length, i };
  if (major === 2 || major === 3) {
    const raw = bytes.subarray(i, i + length);
    i += length;
    if (major === 2) return { value: raw, i };
    return { value: new TextDecoder().decode(raw), i };
  }
  if (major === 4) {
    const arr = [];
    for (let n = 0; n < length; n++) {
      const item = cborDecode(bytes, i);
      if (!item) return null;
      arr.push(item.value);
      i = item.i;
    }
    return { value: arr, i };
  }
  if (major === 5) {
    const map = new Map();
    for (let n = 0; n < length; n++) {
      const key = cborDecode(bytes, i);
      if (!key) return null;
      const val = cborDecode(bytes, key.i);
      if (!val) return null;
      map.set(key.value, val.value);
      i = val.i;
    }
    return { value: map, i };
  }
  return null;
}

async function iosAssertion(blob, challenge, payload, point, appId, previous) {
  const decoded = cborDecode(blob);
  if (!decoded || !(decoded.value instanceof Map)) return null;
  const signature = decoded.value.get("signature");
  const auth = decoded.value.get("authenticatorData");
  if (!(signature instanceof Uint8Array) || !(auth instanceof Uint8Array)) return null;
  if (auth.length < 37) return null;
  const client = concat(textEncoder.encode(challenge), payload);
  const clientHash = await sha256(client);
  const nonce = await sha256(concat(auth, clientHash));
  const ok = await ecdsaVerify(point, signature, nonce);
  if (!ok) return null;
  const appHash = await sha256(textEncoder.encode(appId || ""));
  if (!auth.subarray(0, 32).every((b, i) => b === appHash[i])) return null;
  const counter = (auth[33] * 2 ** 24) + (auth[34] << 16) + (auth[35] << 8) + auth[36];
  if (counter <= (previous || 0)) return null;
  return counter;
}

async function androidSignature(blob, challenge, payload, point) {
  const client = concat(textEncoder.encode(challenge), payload);
  return ecdsaVerify(point, blob, client);
}

function jobIdOf(manifest) {
  if (manifest?.job?.shield_job_id) return String(manifest.job.shield_job_id);
  if (manifest?.record?.id) return String(manifest.record.id);
  if (manifest?.record_id) return String(manifest.record_id);
  return null;
}

function entriesOf(manifest) {
  if (Array.isArray(manifest?.custody_entries)) return manifest.custody_entries;
  if (Array.isArray(manifest?.custody)) return manifest.custody;
  return null;
}

function phoneRecords(entries) {
  const found = [];
  for (const entry of entries || []) {
    let data = entry?.event_data;
    if (typeof data === "string") {
      try { data = JSON.parse(data); } catch { data = null; }
    }
    if (data && Array.isArray(data.phone_chain)) {
      for (const item of data.phone_chain) if (item && typeof item === "object") found.push(item);
    }
  }
  return found;
}

function signingKey(manifest) {
  return manifest?.signing_key
    || manifest?.receipt?.signing_key
    || manifest?.offline?.signing_key
    || null;
}

function pointOf(b64) {
  const raw = b64ToBytes(b64);
  if (!raw || raw.length !== 65 || raw[0] !== 4) return null;
  return raw;
}

async function keyIdMatches(keyId, point) {
  if (!keyId) return true;
  const digest = btoa(String.fromCharCode(...await sha256(point)));
  return keyId.trim() === digest;
}

function pemBodies(pem) {
  if (typeof pem !== "string" || !pem.includes("BEGIN CERTIFICATE")) return [];
  const out = [];
  for (const chunk of pem.split("-----END CERTIFICATE-----")) {
    const begin = chunk.indexOf("-----BEGIN CERTIFICATE-----");
    if (begin < 0) continue;
    const body = chunk.slice(begin + "-----BEGIN CERTIFICATE-----".length).replace(/\s+/g, "");
    const der = b64ToBytes(body);
    if (der) out.push(der);
  }
  return out;
}

function parseTime(text) {
  if (typeof text !== "string") return null;
  let body = text;
  if (body.endsWith("Z")) body = body.slice(0, -1);
  else return null;
  let frac = "";
  if (body.includes(".")) [body, frac] = body.split(".");
  if (!/^\d+$/.test(body) || (frac && !/^\d+$/.test(frac))) return null;
  let year, rest;
  if (body.length === 14) {
    year = Number(body.slice(0, 4));
    rest = body.slice(4);
  } else if (body.length === 12) {
    const yy = Number(body.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = body.slice(2);
  } else return null;
  if (rest.length < 10) return null;
  const month = Number(rest.slice(0, 2));
  const day = Number(rest.slice(2, 4));
  const hour = Number(rest.slice(4, 6));
  const minute = Number(rest.slice(6, 8));
  const second = Number(rest.slice(8, 10));
  const ms = frac ? Number((frac + "000").slice(0, 3)) : 0;
  return Date.UTC(year, month - 1, day, hour, minute, second, ms);
}

function timeText(tag, value) {
  if (tag !== 0x17 && tag !== 0x18) return null;
  return new TextDecoder().decode(value);
}

function parseCert(der) {
  const outer = derWalk(der);
  if (outer.length !== 1 || outer[0].tag !== 0x30) throw new Error("not a certificate");
  const top = derWalk(outer[0].value);
  if (top.length < 3 || top[0].tag !== 0x30 || top[2].tag !== 0x03) {
    throw new Error("certificate is short");
  }
  const tbsFields = derWalk(top[0].value);
  let index = 0;
  if (tbsFields[0].tag === 0xa0) index = 1;
  const sigAlgFields = derWalk(top[1].value);
  if (!sigAlgFields.length || sigAlgFields[0].tag !== 0x06) throw new Error("no signature algorithm");
  const signatureAlg = oidToStr(sigAlgFields[0].value);
  const unused = top[2].value[0];
  if (unused !== 0) throw new Error("certificate signature has unused bits");
  const signature = top[2].value.subarray(1);
  // serial, sig, issuer, validity, subject, spki
  const serial = tbsFields[index];
  const issuer = tbsFields[index + 2];
  const validity = derWalk(tbsFields[index + 3].value);
  const subject = tbsFields[index + 4];
  const spki = tbsFields[index + 5];
  let eku = false;
  const extensions = tbsFields.find((field) => field.tag === 0xa3);
  if (extensions) {
    const extSeq = derWalk(extensions.value);
    const list = extSeq[0]?.tag === 0x30 ? derWalk(extSeq[0].value) : extSeq;
    for (const ext of list) {
      if (ext.tag !== 0x30) continue;
      const parts = derWalk(ext.value);
      if (!parts.length || parts[0].tag !== 0x06) continue;
      if (oidToStr(parts[0].value) !== EKU_OID) continue;
      const octet = parts.find((part) => part.tag === 0x04);
      if (!octet) continue;
      const inner = derWalk(octet.value);
      const oids = inner[0]?.tag === 0x30 ? derWalk(inner[0].value) : inner;
      for (const item of oids) {
        if (item.tag === 0x06 && oidToStr(item.value) === TIME_STAMPING_EKU) eku = true;
      }
    }
  }
  return {
    tbs: top[0].raw,
    signatureAlg,
    signature,
    issuer: issuer.raw,
    subject: subject.raw,
    spki: spki.raw,
    notBefore: parseTime(timeText(validity[0].tag, validity[0].value)),
    notAfter: parseTime(timeText(validity[1].tag, validity[1].value)),
    eku,
    serial,
  };
}

function hashName(oid) {
  if (oid === SHA256_OID || oid === RSA_SHA256_OID || oid === ECDSA_SHA256_OID) return "SHA-256";
  if (oid === SHA384_OID || oid === RSA_SHA384_OID || oid === ECDSA_SHA384_OID) return "SHA-384";
  return null;
}

async function certSignatureOk(child, issuerSpki) {
  const hash = hashName(child.signatureAlg);
  if (!hash) return false;
  if (child.signatureAlg.startsWith("1.2.840.10045.4.3")) {
    // The issuer key is an EC point inside SPKI. Pull the bit string.
    const spkiFields = derWalk(derWalk(issuerSpki)[0].value);
    const bit = spkiFields[1];
    if (!bit || bit.tag !== 0x03) return false;
    const point = bit.value.subarray(1);
    return ecdsaVerify(point, child.signature, child.tbs, hash);
  }
  return rsaVerify(issuerSpki, child.signature, child.tbs, hash, false);
}

function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function chainsToRoots(cert, roots, extras) {
  let current = cert;
  const seen = new Set();
  for (let step = 0; step < 8; step++) {
    const ident = `${toHex(current.subject)}:${current.serial?.raw ? toHex(current.serial.raw) : step}`;
    if (seen.has(ident)) return false;
    seen.add(ident);
    for (const root of roots) {
      if (bytesEq(current.issuer, root.subject) && await certSignatureOk(current, root.spki)) {
        return true;
      }
    }
    let issuer = null;
    for (const candidate of extras) {
      if (candidate === current) continue;
      if (bytesEq(current.issuer, candidate.subject)
          && await certSignatureOk(current, candidate.spki)) {
        issuer = candidate;
        break;
      }
    }
    if (!issuer) return false;
    current = issuer;
  }
  return false;
}

function parseTimestamp(token) {
  const fields = derWalk(token);
  if (fields.length !== 1 || fields[0].tag !== 0x30) throw new Error("not a token");
  const top = derWalk(fields[0].value);
  if (!top.length || top[0].tag !== 0x30) throw new Error("no status");
  const statusFields = derWalk(top[0].value);
  if (!statusFields.length || statusFields[0].tag !== 0x02) throw new Error("status is not an integer");
  const status = derInt(statusFields[0].value);
  if (top.length < 2) throw new Error("no token");
  let contentInfo;
  if (top[1].tag === 0xa0) contentInfo = top[1].value;
  else if (top[1].tag === 0x30) contentInfo = top[1].raw;
  else throw new Error("no token");
  const infoItems = derWalk(contentInfo);
  const content = infoItems.length === 1 && infoItems[0].tag === 0x30
    ? derWalk(infoItems[0].value) : infoItems;
  if (content.length < 2 || content[0].tag !== 0x06) throw new Error("token content type is missing");
  if (oidToStr(content[0].value) !== SIGNED_DATA_OID) throw new Error("token is not SignedData");
  if (content[1].tag !== 0xa0) throw new Error("SignedData is missing");
  const signedItems = derWalk(derWalk(content[1].value)[0].value);
  let versionSeen = false;
  let encap = null;
  let certBytes = null;
  let signerBlob = null;
  for (const item of signedItems) {
    if (item.tag === 0x02 && !versionSeen) { versionSeen = true; continue; }
    if (item.tag === 0x31 && encap === null) continue;
    if (item.tag === 0x30 && encap === null) { encap = item.value; continue; }
    if (item.tag === 0xa0 && encap !== null && certBytes === null) { certBytes = item.value; continue; }
    if (item.tag === 0x31 && encap !== null) signerBlob = item.value;
  }
  if (encap === null || signerBlob === null) throw new Error("SignedData is incomplete");
  const encapFields = derWalk(encap);
  if (encapFields.length < 2 || encapFields[1].tag !== 0xa0) throw new Error("TSTInfo is missing");
  const octet = derWalk(encapFields[1].value);
  if (octet.length !== 1 || octet[0].tag !== 0x04) throw new Error("TSTInfo wrapper is not an octet string");
  const tstInfo = octet[0].value;
  const tstFields = derWalk(derWalk(tstInfo)[0].value);
  if (tstFields.length < 5) throw new Error("TSTInfo is short");
  const policy = oidToStr(tstFields[1].value);
  const imprint = derWalk(tstFields[2].value);
  let hashed = null;
  let imprintOid = null;
  for (const item of imprint) {
    if (item.tag === 0x30 && imprintOid === null) {
      const inner = derWalk(item.value);
      if (inner.length && inner[0].tag === 0x06) imprintOid = oidToStr(inner[0].value);
    } else if (item.tag === 0x04) hashed = item.value;
  }
  if (!hashed || !imprintOid) throw new Error("TSTInfo has no imprint");
  const genTime = new TextDecoder().decode(tstFields[4].value);
  const signerSeq = derWalk(signerBlob).find((item) => item.tag === 0x30);
  if (!signerSeq) throw new Error("no signer");
  const signer = derWalk(signerSeq.value);
  let seenSid = false;
  let digestOid = null;
  let signatureOid = null;
  let signedRaw = null;
  let signature = null;
  for (const item of signer) {
    if (!seenSid && (item.tag === 0x30 || item.tag === 0x80)) { seenSid = true; continue; }
    if (item.tag === 0x30 && signedRaw === null && digestOid === null) {
      const inner = derWalk(item.value);
      if (inner.length && inner[0].tag === 0x06) digestOid = oidToStr(inner[0].value);
      continue;
    }
    if (item.tag === 0xa0 && signedRaw === null) { signedRaw = item.raw; continue; }
    if (item.tag === 0x30 && signedRaw !== null && signatureOid === null) {
      const inner = derWalk(item.value);
      if (inner.length && inner[0].tag === 0x06) signatureOid = oidToStr(inner[0].value);
      continue;
    }
    if (item.tag === 0x04 && signature === null) signature = item.value;
  }
  if (!signedRaw || !signature || !digestOid || !signatureOid) {
    throw new Error("signer info is incomplete");
  }
  const signedSet = concat(new Uint8Array([0x31]), signedRaw.subarray(1));
  const attrFields = derWalk(derWalk(signedRaw)[0].value);
  let contentType = null;
  let messageDigest = null;
  for (const item of attrFields) {
    if (item.tag !== 0x30) continue;
    const parts = derWalk(item.value);
    if (parts.length < 2 || parts[0].tag !== 0x06) continue;
    const oid = oidToStr(parts[0].value);
    const inner = parts[1].tag === 0x31 ? derWalk(parts[1].value) : [];
    if (oid === CONTENT_TYPE_OID && inner.length && inner[0].tag === 0x06) {
      contentType = oidToStr(inner[0].value);
    } else if (oid === MESSAGE_DIGEST_OID && inner.length && inner[0].tag === 0x04) {
      messageDigest = inner[0].value;
    }
  }
  const certs = [];
  if (certBytes) {
    for (const item of derWalk(certBytes)) {
      if (item.tag === 0x30) {
        try { certs.push(parseCert(item.raw)); } catch { /* skip */ }
      }
    }
  }
  return {
    status, hashed, imprintOid, genTime, tstInfo, digestOid, signatureOid,
    signature, signedSet, contentType, messageDigest, certs,
  };
}

async function timestampOk(token, headHex, rootsPem) {
  let parsed;
  try { parsed = parseTimestamp(token); }
  catch (err) { return { ok: false, reason: `the timestamp token could not be read (${err.message})` }; }
  if (parsed.status !== 0 && parsed.status !== 1) {
    return { ok: false, reason: `the timestamp authority status is ${parsed.status}` };
  }
  const expected = hexToBytes(headHex);
  if (!expected || parsed.imprintOid !== SHA256_OID || !bytesEq(parsed.hashed, expected)) {
    return { ok: false, reason: "the timestamp is not over this custody head" };
  }
  if (!SIG_OIDS[parsed.digestOid] || !SIG_OIDS[parsed.digestOid].has(parsed.signatureOid)) {
    return { ok: false, reason: "the timestamp signature algorithm does not match its digest" };
  }
  const hash = hashName(parsed.digestOid);
  const hasher = hash === "SHA-384" ? sha384 : sha256;
  const digest = await hasher(parsed.tstInfo);
  if (!bytesEq(digest, parsed.messageDigest)) {
    return { ok: false, reason: "the timestamp's signed digest does not match the token" };
  }
  if (parsed.contentType !== TST_INFO_OID) {
    return { ok: false, reason: "the timestamp is not a TSTInfo" };
  }
  let signer = null;
  for (const cert of parsed.certs) {
    if (await cmsSignatureOk(cert, parsed)) { signer = cert; break; }
  }
  if (!signer && parsed.certs.length === 1) signer = parsed.certs[0];
  if (!signer) return { ok: false, reason: "the timestamp token has no signer certificate" };
  if (!signer.eku) return { ok: false, reason: "the timestamp certificate is not a time-stamping certificate" };
  const when = parseTime(parsed.genTime);
  if (when === null || signer.notBefore === null || signer.notAfter === null
      || when < signer.notBefore || when > signer.notAfter) {
    return { ok: false, reason: "the timestamp time is outside the certificate's validity" };
  }
  const roots = pemBodies(rootsPem).map((der) => {
    try { return parseCert(der); } catch { return null; }
  }).filter(Boolean);
  if (!roots.length) return { ok: false, reason: "no pinned timestamp root" };
  const extras = parsed.certs.filter((cert) => cert !== signer);
  if (!await chainsToRoots(signer, roots, extras)) {
    return { ok: false, reason: "the timestamp certificate does not chain to a configured root" };
  }
  return { ok: true, reason: "the timestamp verifies over this custody head" };
}

async function cmsSignatureOk(cert, parsed) {
  const hash = hashName(parsed.digestOid);
  if (!hash) return false;
  const ec = parsed.signatureOid === ECDSA_SHA256_OID || parsed.signatureOid === ECDSA_SHA384_OID;
  if (ec) {
    const spkiFields = derWalk(derWalk(cert.spki)[0].value);
    const bit = spkiFields[1];
    if (!bit || bit.tag !== 0x03) return false;
    return ecdsaVerify(bit.value.subarray(1), parsed.signature, parsed.signedSet, hash);
  }
  const pss = parsed.signatureOid === RSA_PSS_OID;
  return rsaVerify(cert.spki, parsed.signature, parsed.signedSet, hash, pss);
}

function bootChanged(ticketClock, capture) {
  const tid = ticketClock.boot_id || null;
  const cid = capture.boot_id || null;
  const tc = ticketClock.boot_count ?? null;
  const cc = capture.boot_count ?? null;
  let saw = false;
  if (tid !== null || cid !== null) {
    saw = true;
    if (!tid || !cid || tid !== cid) return true;
  }
  if (tc !== null || cc !== null) {
    saw = true;
    if (tc === null || cc === null || tc !== cc) return true;
  }
  return !saw;
}

function timeVerdict(ticketClock, capture) {
  const changed = bootChanged(ticketClock, capture);
  const gnss = capture.gnss_time_ms;
  const wall = capture.wall_time_ms;
  let gnssStatus = "absent";
  if (whole(gnss)) {
    if (!whole(wall)) gnssStatus = "uncompared";
    else gnssStatus = Math.abs(gnss - wall) > LIMIT_MS ? "mismatch" : "agrees";
  }
  let unverified = false;
  let mismatch = false;
  if (changed) unverified = true;
  else if (![ticketClock.wall_time_ms, capture.wall_time_ms, ticketClock.monotonic_ms, capture.monotonic_ms]
    .every(whole)) unverified = true;
  else {
    const elapsed = capture.monotonic_ms - ticketClock.monotonic_ms;
    if (elapsed < 0) unverified = true;
    else if (Math.abs(capture.wall_time_ms - (ticketClock.wall_time_ms + elapsed)) > LIMIT_MS) {
      mismatch = true;
    }
  }
  if (gnssStatus === "mismatch") mismatch = true;
  if (mismatch) return MISMATCH;
  if (unverified) return UNVERIFIED;
  return "CONSISTENT";
}

async function verifyPhoneChain(records, firstPrev) {
  let expected = firstPrev;
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (!record.record_hash) return { ok: false, summary: "A capture carries no hash." };
    if (record.prev_hash !== expected) {
      return { ok: false, summary: "A capture does not name the hash of the record before it." };
    }
    let recomputed;
    try { recomputed = await recordLink(record, record.prev_hash); }
    catch (err) {
      return { ok: false, summary: `A capture's bytes do not reproduce the hash (${err.message}).` };
    }
    if (recomputed !== record.record_hash) {
      return { ok: false, summary: "A capture's bytes do not reproduce the hash." };
    }
    expected = record.record_hash;
  }
  return { ok: true, head: expected };
}

function eventDataOf(entry) {
  if (!entry || typeof entry !== "object") return null;
  let data = entry.event_data;
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch { return null; }
  }
  return data && typeof data === "object" ? data : null;
}

function photoAnchors(entries) {
  const anchors = [];
  const problems = [];
  for (const entry of entries || []) {
    const data = eventDataOf(entry);
    if (!data || !Array.isArray(data.phone_chain)) continue;
    const records = data.phone_chain.filter((item) => item && typeof item === "object");
    const bindings = data.sealed_photos;
    if (bindings === undefined || bindings === null) {
      for (const record of records) {
        anchors.push({
          photo_id: null,
          photo_sha256: record.photo_sha256,
          checkpoint_id: record.checkpoint_id ? String(record.checkpoint_id) : "",
        });
      }
      continue;
    }
    if (!Array.isArray(bindings)) {
      problems.push("sealed_photos is not a list of photograph bindings.");
      continue;
    }
    const unused = [];
    for (const binding of bindings) {
      if (binding && typeof binding === "object") unused.push(binding);
      else problems.push("A sealed photograph binding is not an object.");
    }
    for (const record of records) {
      const digest = record.photo_sha256;
      const checkpoint = record.checkpoint_id ? String(record.checkpoint_id) : "";
      const index = unused.findIndex((binding) =>
        binding.photo_sha256 === digest && String(binding.checkpoint_id || "") === checkpoint);
      if (index < 0) {
        problems.push("A hardware-signed photograph has no sealed photo_id binding.");
        anchors.push({ photo_id: null, photo_sha256: digest, checkpoint_id: checkpoint });
        continue;
      }
      const match = unused.splice(index, 1)[0];
      let photoId = match.photo_id;
      if (typeof photoId !== "string" || !photoId.trim()) {
        problems.push("A sealed photograph has no photo_id.");
        photoId = null;
      }
      anchors.push({ photo_id: photoId, photo_sha256: digest, checkpoint_id: checkpoint });
    }
    if (unused.length) {
      problems.push("A sealed photograph is not in the hardware-signed phone chain.");
    }
  }
  return { anchors, problems };
}

function photoClaims(manifest) {
  const claims = [];
  if (Array.isArray(manifest?.photos)) {
    for (const photo of manifest.photos) {
      if (!photo || typeof photo !== "object") continue;
      const digest = typeof photo.original_hash === "string"
        ? photo.original_hash
        : (typeof photo.sha256_original === "string" ? photo.sha256_original : null);
      claims.push({
        photo_id: photo.id ? String(photo.id) : null,
        checkpoint_id: photo.checkpoint_id ? String(photo.checkpoint_id) : null,
        sha256: digest,
      });
    }
  }
  if (Array.isArray(manifest?.checkpoints)) {
    for (const item of manifest.checkpoints) {
      if (!item || typeof item !== "object") continue;
      if (!("sha256_original" in item) && !("photo_id" in item)) continue;
      claims.push({
        photo_id: item.photo_id ? String(item.photo_id) : null,
        checkpoint_id: item.checkpoint_id ? String(item.checkpoint_id) : null,
        sha256: typeof item.sha256_original === "string" ? item.sha256_original : null,
      });
      for (const old of item.superseded_attempts || []) {
        if (!old || typeof old !== "object") continue;
        claims.push({
          photo_id: old.photo_id ? String(old.photo_id) : null,
          checkpoint_id: null,
          sha256: typeof old.sha256_original === "string" ? old.sha256_original : null,
        });
      }
    }
  }
  return claims;
}

function anchorFor(claim, anchors) {
  if (claim.photo_id) {
    return anchors.find((anchor) => anchor.photo_id === claim.photo_id) || null;
  }
  if (!claim.checkpoint_id) return null;
  const byCheckpoint = anchors.filter((anchor) => anchor.checkpoint_id === claim.checkpoint_id);
  if (!byCheckpoint.length) return null;
  if (claim.sha256) {
    const exact = byCheckpoint.filter((anchor) => anchor.photo_sha256 === claim.sha256);
    return exact[0] || byCheckpoint[0];
  }
  return byCheckpoint.length === 1 ? byCheckpoint[0] : null;
}

function fileList(files) {
  if (!files) return [];
  const list = Array.isArray(files) ? files : Object.entries(files).map(([photo_id, bytes]) => ({ photo_id, bytes }));
  const out = [];
  for (const item of list) {
    if (item instanceof Uint8Array) {
      out.push({ photo_id: null, bytes: item });
      continue;
    }
    const bytes = item?.bytes;
    if (!(bytes instanceof Uint8Array) || !bytes.length) continue;
    out.push({ photo_id: item.photo_id ? String(item.photo_id) : null, bytes });
  }
  return out;
}

async function checkOfflinePhotos(manifest, entries, files, state) {
  const { anchors, problems } = photoAnchors(entries);
  for (const problem of problems) worsen(state, TAMPERED, problem);
  if (!anchors.length) return;
  const claims = photoClaims(manifest);
  for (const claim of claims) {
    const anchor = anchorFor(claim, anchors);
    if (!anchor) continue;
    if (claim.sha256 && claim.sha256 !== anchor.photo_sha256) {
      worsen(state, TAMPERED,
        "An offline photograph's hash does not match the hardware-signed phone chain.");
    }
    if (claim.checkpoint_id && anchor.checkpoint_id && claim.checkpoint_id !== anchor.checkpoint_id) {
      worsen(state, TAMPERED,
        "An offline photograph is not on the checkpoint the phone signed.");
    }
  }
  for (const file of fileList(files)) {
    const digest = toHex(await sha256(file.bytes));
    if (file.photo_id) {
      const found = anchors.find((anchor) => anchor.photo_id === file.photo_id);
      if (found && digest !== found.photo_sha256) {
        worsen(state, TAMPERED,
          "Supplied photograph bytes do not match the hardware-signed phone chain.");
      }
      continue;
    }
    for (const claim of claims) {
      if (claim.sha256 !== digest) continue;
      const anchor = anchorFor(claim, anchors);
      if (anchor && anchor.photo_sha256 !== digest) {
        worsen(state, TAMPERED,
          "Supplied photograph bytes match the manifest and do not match the hardware-signed phone chain.");
      }
    }
  }
}

/**
 * @param {object} manifest
 * @param {{ rootsPem?: string, files?: Array<{photo_id?: string, bytes: Uint8Array}> }} [options]
 */
export async function judgeOfflineSeal(manifest, options = {}) {
  const rootsPem = options.rootsPem || PINNED_TSA_ROOTS;
  if (!manifest || typeof manifest !== "object" || !manifest.offline?.captures?.length) {
    return {
      label: null, flags: [], notes: [],
      detail: "This package has no offline seal.",
    };
  }
  const state = { label: SEALED, reasons: [] };
  const captures = manifest.offline.captures;
  const flags = [];
  let bits = 0;
  for (const item of captures) {
    const value = item?.record?.flags;
    if (whole(value)) bits |= value;
  }
  flags.push(...flagWords(bits));

  const records = [];
  for (const item of captures) {
    if (!item || typeof item.record !== "object") {
      worsen(state, TAMPERED, "A capture in the package is not a record.");
      return finish(state, flags, false, false);
    }
    records.push(item.record);
  }

  const entries = entriesOf(manifest);
  const job = jobIdOf(manifest);
  let custodyHead = null;
  let custodyIntact = false;
  if (!entries || !job) {
    worsen(state, TAMPERED, "The package has no custody chain to anchor the receipt to.");
  } else {
    const chain = await verifyChain(entries, job);
    if (chain.ambiguous) {
      worsen(state, TAMPERED, "The custody head could not be recomputed from these bytes.");
    } else if (!chain.intact) {
      worsen(state, TAMPERED, "The custody chain does not reproduce, so the receipt is not anchored to these bytes.");
    } else {
      custodyIntact = true;
      custodyHead = chain.headHash;
    }
    const stored = phoneRecords(entries);
    if (!stored.length) {
      worsen(state, TAMPERED, "The phone chain is not inside a custody entry, so the receipt does not cover it.");
    } else if (stored.map((item) => item.record_hash).join() !== records.map((item) => item.record_hash).join()) {
      worsen(state, TAMPERED, "The phone chain in the package is not the phone chain in the custody entry.");
    }
  }

  let ticketHash = null;
  const ticketBody = manifest.offline.ticket;
  const clock = manifest.offline.ticket_clock;
  if (!ticketBody || typeof ticketBody !== "object") {
    worsen(state, FORGED, "The package has no job ticket.");
  } else {
    try {
      ticketHash = toHex(await sha256(canonicalFields(ticketBody, TICKET_FIELDS)));
    } catch (err) {
      worsen(state, FORGED, `The job ticket could not be read (${err.message}).`);
    }
    if (ticketHash) {
      const key = signingKey(manifest);
      const body = canonicalFields(ticketBody, TICKET_FIELDS);
      if (!await ecdsaOverKey(key, body, manifest.offline.ticket_signature)) {
        worsen(state, FORGED, "The job ticket signature does not verify.");
      }
      if (job && ticketBody.record_id && String(ticketBody.record_id) !== job) {
        worsen(state, FORGED, "The job ticket is not for this record.");
      }
    }
  }

  if (!ticketHash) {
    worsen(state, TAMPERED, "The phone chain has no ticket hash to start from.");
  } else {
    const chain = await verifyPhoneChain(records, ticketHash);
    if (!chain.ok) worsen(state, TAMPERED, chain.summary);
    if (records.some((record) => String(record.ticket_id || "") !== ticketHash)) {
      worsen(state, TAMPERED, "A capture was not made under this job ticket.");
    }
  }

  const point = pointOf(manifest.offline.hardware_key_b64);
  if (!point) {
    worsen(state, FORGED, "The package has no hardware key, or the key is not a P-256 point.");
  } else if (!await keyIdMatches(manifest.offline.key_id, point)) {
    worsen(state, FORGED, "The hardware key id is not the key in the package.");
  } else if (ticketHash && clock) {
    await checkSignatures(manifest.offline, records, point, ticketHash, clock, state);
  } else {
    worsen(state, FORGED, "The ticket signature cannot be checked without the ticket clock.");
  }

  if (clock && typeof clock === "object") {
    for (const record of records) {
      let verdict;
      try { verdict = timeVerdict(clock, record); }
      catch { worsen(state, TAMPERED, "A capture clock could not be read."); break; }
      if (verdict === MISMATCH) worsen(state, MISMATCH, "The device clock does not agree with the monotonic clock.");
      else if (verdict === UNVERIFIED) worsen(state, UNVERIFIED, "The monotonic interval cannot be checked.");
    }
  } else if (records.length) {
    worsen(state, UNVERIFIED, "The ticket clock is missing, so the time rules cannot run.");
  }

  await checkOfflinePhotos(manifest, entries, options.files, state);
  const receipt = await checkReceipt(manifest, custodyHead, custodyIntact, records, state);
  const timestampAbsent = await checkTimestamp(
    manifest, custodyIntact ? custodyHead : receipt.claimed, rootsPem, state);
  if (state.label === SEALED && timestampAbsent && receipt.present && receipt.ok) {
    state.label = ABSENT;
  }
  return finish(state, flags, timestampAbsent, receipt.present);
}

function finish(state, flags, timestampAbsent, receiptPresent) {
  const notes = [];
  if (timestampAbsent && receiptPresent && state.label !== ABSENT && state.label !== FORGED) {
    notes.push(ABSENT);
  }
  let detail = state.reasons.join(" ");
  if (!detail && state.label === SEALED) {
    detail = "The phone chain recomputes, the hardware signatures check, the ticket signature checks, the time rules pass, and the timestamp checks against the pinned certificates.";
  }
  if (!detail && state.label === ABSENT) {
    detail = "The receipt is present and its signature checks. The timestamp is absent. A missing timestamp is not a forgery.";
  }
  return { label: state.label, flags, notes, detail };
}

async function ecdsaOverKey(signing, body, signatureB64) {
  const signature = b64ToBytes(signatureB64);
  const point = pointOf(signing?.uncompressed_point_b64);
  if (!signature || !point) return false;
  return ecdsaVerify(point, signature, body);
}

async function checkSignatures(offline, records, point, ticketHash, clock, state) {
  if (offline.platform !== "ios" && offline.platform !== "android") {
    worsen(state, FORGED, "The package does not name ios or android.");
    return;
  }
  let payload;
  try {
    const clockBytes = canonicalFields(clock, CLOCK_FIELDS);
    payload = await sha256(concat(hexToBytes(ticketHash), clockBytes));
  } catch {
    worsen(state, FORGED, "The ticket clock could not be signed over.");
    return;
  }
  let previous = 0;
  const ticketOk = await oneSignature(
    offline.platform, offline.ticket_assertion, "shield-genesis-v1", payload,
    point, offline.app_id, previous);
  if (!ticketOk.ok) {
    worsen(state, FORGED, "The hardware signature on the job ticket does not verify.");
    return;
  }
  previous = ticketOk.counter;
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    const assertion = offline.captures[index].assertion || record.hardware_signature;
    const rawHash = hexToBytes(record.record_hash || "");
    if (!rawHash) {
      worsen(state, FORGED, "A capture has no record hash to sign.");
      return;
    }
    const checked = await oneSignature(
      offline.platform, assertion, "shield-capture-v1", rawHash,
      point, offline.app_id, previous);
    if (!checked.ok) {
      worsen(state, FORGED, `The hardware signature on capture ${index + 1} does not verify.`);
      return;
    }
    previous = checked.counter;
  }
}

async function oneSignature(platform, assertionB64, challenge, payload, point, appId, previous) {
  const raw = b64ToBytes(assertionB64);
  if (!raw) return { ok: false, counter: previous };
  if (platform === "ios") {
    const counter = await iosAssertion(raw, challenge, payload, point, appId, previous);
    if (counter === null) return { ok: false, counter: previous };
    return { ok: true, counter };
  }
  const ok = await androidSignature(raw, challenge, payload, point);
  return { ok, counter: previous };
}

async function checkReceipt(manifest, custodyHead, custodyIntact, records, state) {
  const receipt = manifest.receipt;
  if (!receipt || typeof receipt !== "object") {
    worsen(state, FORGED, "The package has no receipt.");
    return { ok: false, present: false, claimed: null };
  }
  const signed = receipt.signed && typeof receipt.signed === "object" ? receipt.signed : {
    version: receipt.version,
    record_id: receipt.record_id,
    head_hash: receipt.head_hash,
    accepted_at_ms: receipt.accepted_at_ms,
  };
  let body;
  try { body = canonicalFields(signed, RECEIPT_FIELDS); }
  catch (err) {
    worsen(state, FORGED, `The receipt could not be read (${err.message}).`);
    return { ok: false, present: true, claimed: null };
  }
  const signature = receipt.signature || receipt.server_signature;
  const ok = await ecdsaOverKey(signingKey(manifest), body, signature);
  if (!ok) {
    worsen(state, FORGED, "The receipt signature does not verify.");
    return { ok: false, present: true, claimed: signed.head_hash };
  }
  if (custodyIntact && signed.head_hash !== custodyHead) {
    worsen(state, TAMPERED, "The receipt is not over the custody head these bytes produce.");
  }
  const job = jobIdOf(manifest);
  if (job && signed.record_id && String(signed.record_id) !== job) {
    worsen(state, FORGED, "The receipt is not for this record.");
  }
  if (records.length) {
    const phoneHead = records[records.length - 1].record_hash;
    if (receipt.phone_chain_head && receipt.phone_chain_head !== phoneHead) {
      worsen(state, TAMPERED, "The receipt names a phone-chain head these records do not end at.");
    }
  }
  return { ok: true, present: true, claimed: signed.head_hash };
}

async function checkTimestamp(manifest, head, rootsPem, state) {
  const block = manifest.timestamp;
  if (!block || typeof block !== "object") return true;
  const token = block.token_b64;
  const present = block.status === "present" && typeof token === "string" && token.trim();
  if (!present) return true;
  const raw = b64ToBytes(token);
  if (!raw || !head) {
    worsen(state, FORGED, "The timestamp token could not be checked.");
    return false;
  }
  const checked = await timestampOk(raw, head, rootsPem);
  if (!checked.ok) {
    worsen(state, FORGED, `The timestamp does not check against the pinned certificates. ${checked.reason}`);
    return false;
  }
  return false;
}
