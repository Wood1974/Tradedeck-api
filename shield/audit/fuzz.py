#!/usr/bin/env python3
"""Continuous adversarial fuzzing. No tokens, no network, no dependencies.

Why this exists
---------------
The daily agent in PROTOCOL.md costs money every morning whether or not there
is anything to find, and it spends most of that money re-reading code it
already read. That is the wrong tier to do the grinding on.

Machines are better and cheaper than a model at the repetitive half of
attacking: throw millions of inputs at a parser, mutate a chain in every
possible way, check two implementations against each other forever. This file
does that for as long as you let it, for the price of the CPU. The model's
budget is then spent only on what a machine cannot do — inventing a new *class*
of attack — and on triaging what this finds.

Targets, in descending order of what a finding would cost us
------------------------------------------------------------
  1. differential   ledger.py vs verifier/shield_verify.py. A divergence means
                    every package we have ever issued verifies against exactly
                    one of our two implementations, and we do not know which is
                    right. Nothing else here is as expensive.
  2. chain          random tampering must always be caught, at the right index.
  3. canonical      absent == null, byte-stability, non-finite refused — the
                    three rules the whole chain rests on.
  4. parsers        untrusted bytes into sniff/probe/exif/compress. No crash,
                    no hang, no memory blowup. This is where the decompression
                    bomb lived.
  5. geometry       haversine and solar identities that must hold for all
                    inputs, not just the ones we wrote tests for.

Every finding is reproducible: the seed that produced it is printed and saved.
A finding is not a bug report — it is a failing case to turn into a named test
and, if it was ever exploitable, an invariant.

    python audit/fuzz.py                    # 60 seconds, random seed
    python audit/fuzz.py --seconds 1200     # what CI runs nightly
    python audit/fuzz.py --seed 12345       # reproduce a reported finding
    python audit/fuzz.py --target chain     # one surface
"""
import argparse
import io
import json
import os
import random
import resource
import string
import sys
import time
import traceback
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SHIELD = os.path.dirname(HERE)
sys.path.insert(0, SHIELD)
sys.path.insert(0, os.path.join(SHIELD, "verifier"))

import logging             # noqa: E402
# Malformed input makes the parsers log caught exceptions. That is their
# correct path; left on, it buries an actual finding in scrollback.
logging.disable(logging.CRITICAL)

import ledger              # noqa: E402
import shield_verify       # noqa: E402

try:
    import integrity
    from PIL import Image
    PARSERS = True
except Exception:                                    # pragma: no cover
    PARSERS = False

try:
    import corroborate
    GEOMETRY = True
except Exception:                                    # pragma: no cover
    GEOMETRY = False

# A single call that allocates more than this, or takes longer than this, is a
# denial-of-service finding whether or not it returns the right answer.
MAX_RSS_GROWTH_MB = 200
MAX_CALL_SECONDS = 5.0

EVENT_TYPES = ("uploaded", "ai_analyzed", "viewed", "superseded",
               "integrity_flag", "completed", "flagged")
ACTOR_TYPES = ("contractor", "homeowner", "system", "inspector")


# ------------------------------------------------------------- generators ---
def rand_text(rnd, n=12):
    """Deliberately hostile: unicode, quotes, braces, newlines, nulls."""
    pool = string.printable + "ü漢字🔨\"'\\{}[]|,:\x00\n\t"
    return "".join(rnd.choice(pool) for _ in range(rnd.randint(0, n)))


def rand_value(rnd, depth=0):
    pick = rnd.randint(0, 8 if depth < 2 else 5)
    if pick == 0:
        return None
    if pick == 1:
        return rnd.choice([True, False])
    if pick == 2:
        return rnd.randint(-10**9, 10**9)
    if pick == 3:
        return rnd.uniform(-180, 180)
    if pick == 4:
        return rand_text(rnd)
    if pick == 5:
        return rnd.choice([0.0, -0.0, 1e-300, 1e300, 40.76056])
    if pick == 6:
        return [rand_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))]
    if pick == 7:
        return {rand_text(rnd, 6): rand_value(rnd, depth + 1)
                for _ in range(rnd.randint(0, 4))}
    return rand_text(rnd, 40)


def rand_entry(rnd, job_id):
    entry = {"shield_job_id": job_id,
             "event_type": rnd.choice(EVENT_TYPES),
             "actor_type": rnd.choice(ACTOR_TYPES),
             "recorded_at": f"2026-09-{rnd.randint(1, 28):02d}T"
                            f"{rnd.randint(0, 23):02d}:00:00+00:00"}
    for field in ("photo_id", "actor_id", "file_hash", "integrity_note",
                  "exif_captured_at", "event_data", "gps_lat", "gps_lng"):
        if rnd.random() < 0.6:
            entry[field] = rand_value(rnd)
    # keep coordinates plausible often enough to exercise the float path
    if rnd.random() < 0.5:
        entry["gps_lat"] = rnd.uniform(-90, 90)
        entry["gps_lng"] = rnd.uniform(-180, 180)
    return entry


def rand_chain(rnd, job_id, n=None):
    chain, prev = [], ledger.genesis_hash(job_id)
    for _ in range(n or rnd.randint(1, 12)):
        try:
            sealed = ledger.seal(rand_entry(rnd, job_id), prev)
        except ValueError:
            continue                    # non-finite refused; that is correct
        chain.append(sealed)
        prev = sealed["entry_hash"]
    return chain


def rand_job_id(rnd):
    return "-".join("".join(rnd.choice("0123456789abcdef") for _ in range(k))
                    for k in (8, 4, 4, 4, 12))


# ---------------------------------------------------------------- targets ---
def t_differential(rnd, report):
    """The two implementations of SPEC.md must never disagree."""
    job = rand_job_id(rnd)
    if shield_verify.genesis_hash(job) != ledger.genesis_hash(job):
        return report("differential", "genesis values differ", {"job": job})

    entry = rand_entry(rnd, job)
    try:
        ours = ledger.canonical(entry)
    except ValueError:
        try:
            shield_verify.canonical(entry)
        except ValueError:
            return None                 # both refused; agreement
        return report("differential",
                      "the service refuses a value the verifier accepts",
                      {"entry": entry})
    try:
        theirs = shield_verify.canonical(entry)
    except ValueError:
        return report("differential",
                      "the verifier refuses a value the service accepts",
                      {"entry": entry})
    if ours != theirs:
        return report("differential", "canonical bytes differ", {
            "entry": entry, "service": ours.decode("utf-8", "replace"),
            "verifier": theirs.decode("utf-8", "replace")})

    prev = ledger.genesis_hash(job)
    if ledger.link(entry, prev) != shield_verify.link(entry, prev):
        return report("differential", "links differ", {"entry": entry})
    return None


def t_chain(rnd, report):
    """Any tampering must be detected, at the entry where it happened."""
    job = rand_job_id(rnd)
    chain = rand_chain(rnd, job)
    if not chain:
        return None

    clean = ledger.verify_chain(list(chain), job)
    if not clean["intact"]:
        return report("chain", "a freshly sealed chain does not verify",
                      {"job": job, "entries": len(chain)})
    if clean["head_hash"] != ledger.head_of(chain, job):
        return report("chain", "verify_chain and head_of disagree on the head",
                      {"job": job})

    i = rnd.randrange(len(chain))
    kind = rnd.choice(["edit", "delete", "reorder", "rehash", "relink"])
    tampered = [dict(e) for e in chain]
    if kind == "edit":
        field = rnd.choice(ledger.SIGNED_FIELDS)
        tampered[i][field] = rand_text(rnd) or "x"
        if tampered[i][field] == chain[i].get(field):
            return None                 # no-op mutation
    elif kind == "delete":
        del tampered[i]
        if not tampered:
            return None
        if i == len(chain) - 1:
            # Truncating the tail leaves a shorter chain in which every
            # remaining link verifies. That is a property of hash chains, not
            # a bug — so the rule to check is the mitigation: undetectable on
            # its own, detectable against a head the recipient already holds.
            short = ledger.verify_chain(tampered, job)
            if not short["intact"]:
                return report("chain", "tail truncation broke the chain — the "
                                       "documented behaviour is that it does not",
                              {"job": job, "index": i})
            held = ledger.head_of(chain, job)
            caught = shield_verify.verify_package(
                {"job": {"shield_job_id": job}, "custody_entries": tampered},
                expect_head=held)
            if caught["ok"]:
                return report("chain",
                              "tail truncation NOT caught even against a held "
                              "head — the only defence against it has failed",
                              {"job": job, "index": i, "held_head": held})
            return None
    elif kind == "reorder":
        if len(tampered) < 2:
            return None
        j = rnd.randrange(len(tampered))
        if i == j:
            return None
        tampered[i], tampered[j] = tampered[j], tampered[i]
    elif kind == "rehash":
        tampered[i]["entry_hash"] = "f" * 64
    else:
        tampered[i]["prev_hash"] = "e" * 64

    after = ledger.verify_chain(tampered, job)
    if after["intact"]:
        return report("chain", f"{kind} at index {i} was NOT detected",
                      {"job": job, "kind": kind, "index": i,
                       "entries": len(chain)})

    # the verifier must reach the same verdict as the service
    v = shield_verify.verify_chain(tampered, job)
    if v["intact"] != after["intact"] or \
            v["broken_at_index"] != after["broken_at_index"]:
        return report("chain", "service and verifier disagree about the break",
                      {"job": job, "kind": kind, "service": after["broken_at_index"],
                       "verifier": v["broken_at_index"]})
    return None


def t_canonical(rnd, report):
    """The three rules the chain rests on, over arbitrary field combinations."""
    job = rand_job_id(rnd)
    entry = rand_entry(rnd, job)
    try:
        once = ledger.canonical(entry)
    except ValueError:
        return None

    if ledger.canonical(dict(entry)) != once:
        return report("canonical", "not deterministic across calls",
                      {"entry": entry})

    # absent and null must be identical
    explicit = dict(entry)
    for field in ledger.SIGNED_FIELDS:
        if field not in explicit:
            explicit[field] = None
    if ledger.canonical(explicit) != once:
        return report("canonical", "explicit null differs from absent",
                      {"entry": entry})

    # unsigned fields must not move the hash
    noisy = dict(entry)
    noisy["some_new_column"] = rand_value(rnd)
    noisy["upload_ip_hash"] = rand_text(rnd)
    if ledger.canonical(noisy) != once:
        return report("canonical", "an unsigned field changed the hash",
                      {"entry": entry})

    # non-finite must be refused, never rendered
    for bad in (float("nan"), float("inf"), float("-inf")):
        probe = dict(entry)
        probe[rnd.choice(["gps_lat", "gps_lng"])] = bad
        try:
            ledger.canonical(probe)
            return report("canonical", f"accepted non-finite {bad!r}",
                          {"entry": entry})
        except ValueError:
            pass
    return None


def _seed_images():
    out = []
    for fmt, size in (("JPEG", (64, 48)), ("PNG", (40, 40)), ("WEBP", (32, 32))):
        buf = io.BytesIO()
        Image.new("RGB", size, (90, 90, 90)).save(buf, fmt)
        out.append(buf.getvalue())
    return out


def t_parsers(rnd, report, _cache=[]):
    """Untrusted bytes in. No crash, no hang, no memory blowup."""
    if not PARSERS:
        return None
    if not _cache:
        _cache.extend(_seed_images())

    raw = bytearray(rnd.choice(_cache))
    for _ in range(rnd.randint(1, 24)):          # corrupt it
        op = rnd.randint(0, 2)
        if op == 0 and raw:
            raw[rnd.randrange(len(raw))] = rnd.randint(0, 255)
        elif op == 1:
            at = rnd.randrange(len(raw) + 1)
            raw[at:at] = bytes(rnd.randint(0, 255) for _ in range(rnd.randint(1, 16)))
        elif raw:
            at = rnd.randrange(len(raw))
            del raw[at:at + rnd.randint(1, 32)]
    if rnd.random() < 0.1:
        raw = bytearray(os.urandom(rnd.randint(0, 2048)))
    raw = bytes(raw)

    for name, fn in (("sniff_mime", lambda b: integrity.sniff_mime(b)),
                     ("probe", lambda b: integrity.probe(b)),
                     ("extract_exif", lambda b: integrity.extract_exif(b, "image/jpeg")),
                     ("compress_for_model", lambda b: integrity.compress_for_model(b))):
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        start = time.monotonic()
        try:
            fn(raw)
        except Exception:
            return report("parsers", f"{name} raised on malformed input",
                          {"bytes_b64_len": len(raw),
                           "traceback": traceback.format_exc()[-600:]},
                          payload=raw)
        elapsed = time.monotonic() - start
        grew_mb = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) / 1024
        if elapsed > MAX_CALL_SECONDS:
            return report("parsers", f"{name} took {elapsed:.1f}s",
                          {"seconds": elapsed}, payload=raw)
        if grew_mb > MAX_RSS_GROWTH_MB:
            return report("parsers", f"{name} grew RSS by {grew_mb:.0f} MB",
                          {"mb": grew_mb}, payload=raw)
    return None


def t_geometry(rnd, report):
    """Identities that must hold everywhere, not only where we wrote tests."""
    if not PARSERS:
        return None
    lat1, lng1 = rnd.uniform(-90, 90), rnd.uniform(-180, 180)
    lat2, lng2 = rnd.uniform(-90, 90), rnd.uniform(-180, 180)

    d = integrity.haversine_m(lat1, lng1, lat2, lng2)
    if d is None or d < 0:
        return report("geometry", "haversine returned a negative or null distance",
                      {"a": [lat1, lng1], "b": [lat2, lng2], "d": d})
    if abs(d - integrity.haversine_m(lat2, lng2, lat1, lng1)) > 1e-6:
        return report("geometry", "haversine is not symmetric",
                      {"a": [lat1, lng1], "b": [lat2, lng2]})
    if integrity.haversine_m(lat1, lng1, lat1, lng1) > 1e-6:
        return report("geometry", "distance to self is not zero",
                      {"a": [lat1, lng1]})
    if d > 20_100_000:
        return report("geometry", "distance exceeds half the Earth's circumference",
                      {"d": d})

    if GEOMETRY and hasattr(corroborate, "solar_position"):
        when = datetime(2026, rnd.randint(1, 12), rnd.randint(1, 28),
                        rnd.randint(0, 23), tzinfo=timezone.utc)
        try:
            pos = corroborate.solar_position(lat1, lng1, when)
        except Exception:
            return report("geometry", "solar_position raised",
                          {"lat": lat1, "lng": lng1, "when": when.isoformat(),
                           "traceback": traceback.format_exc()[-400:]})
        az, el = pos.get("azimuth_deg"), pos.get("elevation_deg")
        if az is None or not (0 <= az < 360):
            return report("geometry", f"azimuth out of range: {az}",
                          {"lat": lat1, "lng": lng1, "when": when.isoformat()})
        if el is None or not (-90.5 <= el <= 90.5):
            return report("geometry", f"elevation out of range: {el}",
                          {"lat": lat1, "lng": lng1, "when": when.isoformat()})
    return None


def t_rebroadcast(rnd, report, _cache=[]):
    """Two arbitrary frames in. Never raise, never accuse."""
    if not PARSERS:
        return None
    try:
        import rebroadcast
    except Exception:
        return None
    if not _cache:
        _cache.extend(_seed_images())

    def frame():
        if rnd.random() < 0.25:
            return os.urandom(rnd.randint(0, 512))
        raw = bytearray(rnd.choice(_cache))
        for _ in range(rnd.randint(0, 8)):
            if raw:
                raw[rnd.randrange(len(raw))] = rnd.randint(0, 255)
        return bytes(raw)

    try:
        r = rebroadcast.analyze_flash_pair(frame(), frame())
    except Exception:
        return report("rebroadcast", "analyze_flash_pair raised",
                      {"traceback": traceback.format_exc()[-600:]})
    if r["verdict"] not in ("consistent_with_scene", "consistent_with_display",
                            "inconclusive"):
        return report("rebroadcast", f"unknown verdict {r['verdict']!r}", {"r": r})

    pts = [((rnd.uniform(0, 640), rnd.uniform(0, 480)),
            (rnd.uniform(0, 640), rnd.uniform(0, 480)))
           for _ in range(rnd.randint(0, 40))]
    try:
        p = rebroadcast.analyze_parallax(pts, (640, 480))
    except Exception:
        return report("rebroadcast", "analyze_parallax raised",
                      {"n": len(pts), "traceback": traceback.format_exc()[-600:]})
    if p["verdict"] not in ("planar", "non_planar", "inconclusive"):
        return report("rebroadcast", f"unknown verdict {p['verdict']!r}", {"p": p})

    out = rebroadcast.assess(flash=r, parallax=p)
    positive = r["verdict"] == "consistent_with_scene" or p["verdict"] == "non_planar"
    if out["upgrade"] is not positive:
        return report("rebroadcast", "assess() disagrees with its own signals",
                      {"flash": r["verdict"], "parallax": p["verdict"],
                       "upgrade": out["upgrade"]})
    for word in ("fraud", "fake", "forged", "faked"):
        if word in out["reason"].lower():
            return report("rebroadcast", f"assess() accused: {word!r} in reason",
                          {"reason": out["reason"]})
    return None


TARGETS = {"differential": t_differential, "chain": t_chain,
           "canonical": t_canonical, "parsers": t_parsers,
           "geometry": t_geometry, "rebroadcast": t_rebroadcast}


# ------------------------------------------------------------------ main ---
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--target", choices=sorted(TARGETS), action="append")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus"))
    ap.add_argument("--max-findings", type=int, default=10)
    args = ap.parse_args(argv)

    master_seed = args.seed if args.seed is not None else random.randrange(2**31)
    targets = {k: TARGETS[k] for k in (args.target or sorted(TARGETS))}
    findings, runs = [], {k: 0 for k in targets}

    def make_reporter(name, case_seed):
        def report(target, message, detail, payload=None):
            f = {"target": target, "message": message, "seed": case_seed,
                 "master_seed": master_seed, "detail": detail,
                 "found_utc": datetime.now(timezone.utc).isoformat()}
            os.makedirs(args.corpus, exist_ok=True)
            stem = f"{target}-{case_seed}"
            with open(os.path.join(args.corpus, stem + ".json"), "w") as fh:
                json.dump(f, fh, indent=2, default=str)
            if payload is not None:
                with open(os.path.join(args.corpus, stem + ".bin"), "wb") as fh:
                    fh.write(payload)
            findings.append(f)
            return f
        return report

    print(f"fuzzing {', '.join(targets)} for {args.seconds:.0f}s "
          f"(master seed {master_seed})")
    deadline = time.monotonic() + args.seconds
    names = list(targets)
    picker = random.Random(master_seed)

    while time.monotonic() < deadline and len(findings) < args.max_findings:
        name = picker.choice(names)
        case_seed = picker.randrange(2**31)
        rnd = random.Random(case_seed)
        runs[name] += 1
        try:
            targets[name](rnd, make_reporter(name, case_seed))
        except Exception:
            make_reporter(name, case_seed)(
                name, "the fuzzer itself raised — this is a finding too",
                {"traceback": traceback.format_exc()[-800:]})

    total = sum(runs.values())
    print(f"\n{total:,} cases: " + ", ".join(f"{k} {v:,}" for k, v in runs.items()))
    if not findings:
        print("\nNo findings. Nothing to fix.")
        return 0

    print(f"\n{len(findings)} FINDING(S) — reproduce with --seed <n> --target <t>\n")
    for f in findings:
        print(f"  [{f['target']}] {f['message']}")
        print(f"      python audit/fuzz.py --target {f['target']} --seed {f['seed']}")
    print(f"\nSaved to {args.corpus}/. Turn each into a named test, and into an "
          f"invariant if it was ever exploitable.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
