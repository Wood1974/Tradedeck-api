"""Security invariants — permanent tripwires for every exploit we have closed.

Why these are separate from tests/
----------------------------------
The unit tests check that code does what it is supposed to. These check that a
specific *attack* is still impossible. The distinction matters because the
failure mode is different: a unit test breaks when someone changes behaviour,
and an invariant breaks when someone quietly removes a guard while all the
behaviour tests still pass.

Every entry here was a working exploit at some point. Each is now a property
the daily audit re-checks, so a regression is caught the next morning rather
than in a dispute eighteen months later.

They are deliberately structural — they read the source and the schema rather
than exercising the route — because several of these guards cannot be triggered
without live Supabase and Stripe, and an invariant that only runs in a fully
provisioned environment is an invariant that stops running.

Adding one
----------
When a new exploit is found and fixed, add an INVARIANT here naming the attack
it prevents. The daily audit compares against this file; anything that was once
possible and is not covered here can silently come back.
"""
import inspect
import json
import re
import sys
from pathlib import Path

SHIELD = Path(__file__).resolve().parent.parent
REPO = SHIELD.parent
sys.path.insert(0, str(SHIELD))

MIGRATIONS = REPO / "supabase" / "migrations"


def _source(obj):
    return inspect.getsource(obj)


def _all_migrations():
    return "\n".join(p.read_text() for p in sorted(MIGRATIONS.glob("*.sql")))


def _calls(fn):
    """Dotted names actually called inside a function, read from its AST.

    Text matching is not good enough here. Commenting a guard out leaves its
    name in the source, so `"integrity.probe(" in src` keeps passing while the
    guard no longer runs — which is precisely the refactor these tripwires
    exist to catch. Verified by deliberately breaking each guard that way.
    """
    import ast
    import textwrap
    out = set()
    for node in ast.walk(ast.parse(textwrap.dedent(_source(fn)))):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            out.add(f"{f.value.id}.{f.attr}")
        elif isinstance(f, ast.Attribute):
            out.add(f.attr)
        elif isinstance(f, ast.Name):
            out.add(f.id)
    return out


# ---------------------------------------------------------------------------
# Each invariant: (id, the attack it stops, a callable returning (ok, detail))
# ---------------------------------------------------------------------------
def _check(fn):
    """Run a predicate and normalise its failure into a detail string."""
    try:
        return fn()
    except Exception as exc:  # a broken invariant is a failed invariant
        return False, f"invariant raised {type(exc).__name__}: {exc}"


def inv_analyze_trusts_nothing():
    import routes
    src = _source(routes.analyze_photo)
    reads = re.findall(r"request\.(get_json|form|args|data|files)", src)
    if reads:
        return False, f"analyze_photo reads request.{reads[0]} — the caller can " \
                      f"substitute the evidence being graded"
    if "_signed_url(" not in src:
        return False, "analyze_photo no longer mints its own signed URL"
    return True, "takes photo_id only; every input read from the database"


def inv_analyze_write_is_conditional():
    import routes
    if 'is_("ai_verdict", "null")' not in _source(routes.analyze_photo):
        return False, "verdict write is no longer conditional — concurrent calls " \
                      "can each bill a vision request and the last writer wins"
    return True, "verdict write is conditional on no existing verdict"


def inv_upload_scopes_the_checkpoint():
    import routes
    src = _source(routes.upload_photo)
    if '.eq("shield_job_id", shield_job_id)' not in src:
        return False, "point_id is not scoped to the job — a photo can be filed " \
                      "against a checkpoint belonging to someone else's job"
    return True, "point_id must belong to this shield job"


def inv_upload_hashes_before_touching():
    import routes
    src = _source(routes.upload_photo)
    try:
        i_read = src.index("raw = upload.read()")
        i_hash = src.index("integrity.sha256(raw)")
        i_store = src.index("db().storage")
        i_comp = src.index("compress_for_model")
    except ValueError as exc:
        return False, f"upload pipeline no longer recognisable: {exc}"
    if not i_read < i_hash < i_store and i_hash < i_comp:
        return False, "the SHA-256 anchor no longer precedes storage and " \
                      "compression — the hash may not cover the bytes received"
    return True, "read -> hash -> store original -> compress, in that order"


def inv_originals_are_never_overwritten():
    import routes
    if '"x-upsert": "false"' not in _source(routes.upload_photo):
        return False, "original storage write permits upsert — an original can " \
                      "be replaced after it was hashed"
    return True, "originals written with x-upsert false"


def inv_grading_counts_missing_evidence():
    import verdict
    g = verdict.grade([{"point_number": 1, "photo": {"ai_verdict": "pass"}}]
                      + [{"point_number": n} for n in range(2, 6)])
    if g["verdict"] == "pass":
        return False, "a job with 1 of 5 checkpoints documented reports 'pass'"
    if verdict.is_complete_enough([{"photo": {"ai_verdict": "pass"}}, {}]):
        return False, "close-out is permitted with an unphotographed checkpoint"
    if verdict.counts_toward_badge(g):
        return False, "a partial job counts toward the verified badge"
    return True, f"1-of-5 grades {g['verdict']!r}; close-out and badge both refused"


def inv_badge_counts_distinct_jobs():
    import routes
    src = _source(routes._maybe_award_badge)
    if "counts_toward_badge" not in src:
        return False, "badge no longer requires a fully clean job"
    if "{r[" not in src and "set(" not in src:
        return False, "badge may be counting completion rows rather than " \
                      "distinct jobs — repeat close-outs could mint it"
    return True, "badge requires distinct fully-clean jobs"


def inv_checkpoints_lock_and_are_buyer_owned():
    import routes
    src = _source(routes.generate_checkpoints)
    if 'role="homeowner"' not in src:
        return False, "the audited party can define the audit criteria"
    if "checkpoints_locked_at" not in src:
        return False, "the checkpoint schedule can be rewritten after the work " \
                      "has been photographed and graded"
    if "schedule_sha256" not in src:
        return False, "the locked schedule is no longer sealed into the chain"
    return True, "homeowner-only, locks once, schedule hash in the chain"


def inv_custody_is_chained():
    import routes
    if "ledger.seal" not in _source(routes.log_custody):
        return False, "custody entries are no longer hash-linked — tampering " \
                      "becomes undetectable rather than merely disallowed"
    return True, "each entry carries the hash of its predecessor"


def inv_custody_chain_detects_tampering():
    import ledger
    job = "invariant-job"
    chain, prev = [], ledger.genesis_hash(job)
    for i in range(4):
        e = ledger.seal({"shield_job_id": job, "event_type": "uploaded",
                         "recorded_at": f"2026-01-0{i+1}T00:00:00+00:00"}, prev)
        chain.append(e)
        prev = e["entry_hash"]
    if not ledger.verify_chain(chain, job)["intact"]:
        return False, "an untampered chain fails verification"
    chain[1]["event_type"] = "ai_analyzed"
    broken = ledger.verify_chain(chain, job)
    if broken["intact"] or broken["broken_at_index"] != 1:
        return False, "an edited entry is not detected at its index"
    return True, "edit detected at the correct entry"


def inv_actor_is_derived_not_asserted():
    import routes
    if routes.actor_role({"homeowner_id": "h", "contractor_id": "c"}, "c") != "contractor":
        return False, "actor role misattributes the contractor"
    if routes.actor_role({"homeowner_id": "h", "contractor_id": "c"}, "h") != "homeowner":
        return False, "actor role misattributes the homeowner"
    if "actor_role(g.shield_job" not in _source(routes.complete_job):
        return False, "close-out hardcodes the actor — a contractor closing his " \
                      "own job would be recorded as the buyer signing off"
    return True, "actor derived from the job's parties"


def inv_payment_is_verified():
    import routes
    src = _source(routes.webhook)
    for needle, why in (
        ("stripe_payment_intent_id", "activation does not match the stored intent"),
        ("amount_received", "activation does not check the amount received"),
        ("currency", "activation does not check the currency"),
    ):
        if needle not in src:
            return False, why
    return True, "matches stored intent, asserts amount and currency"


def inv_price_is_server_side():
    import pricing
    import routes
    for hostile in (None, 0, -1, "1", -99_999_999):
        _, price = pricing.quote(hostile)
        if price not in pricing.VALID_PRICES or price < 7_900:
            return False, f"pricing.quote({hostile!r}) returned {price}"
    before = _source(routes.create_job).split("pricing.quote")[0]
    if "amount_cents" in before:
        return False, "create_job reads amount_cents from the request body"
    return True, "price derived server-side; client figure ignored"


def inv_ip_salt_has_no_fallback():
    import config
    import integrity
    if "IP_HASH_SALT" not in config.REQUIRED:
        return False, "IP_HASH_SALT is no longer required — a committed default " \
                      "makes the stored hash reversible (IPv4 is 2**32 values)"
    try:
        integrity.hash_ip("203.0.113.9", "")
        return False, "hash_ip accepts an empty salt"
    except ValueError:
        return True, "salt required; empty salt refused"


def inv_forwarded_for_uses_the_trusted_hop():
    import routes
    if 'split(",")[-1]' not in _source(routes.client_ip):
        return False, "X-Forwarded-For is read from the left — the stored " \
                      "uploader IP is whatever the client sent"
    return True, "rightmost proxy hop"


def inv_upload_size_is_bounded_before_buffering():
    import app
    src = _source(app.create_app)
    if "MAX_CONTENT_LENGTH" not in src:
        return False, "MAX_CONTENT_LENGTH unset — the body is fully buffered " \
                      "before any size check"
    return True, "MAX_CONTENT_LENGTH set on the app"


def inv_notes_cannot_be_edited():
    sql = _all_migrations()
    if "shield_notes_no_mutate" not in sql:
        return False, "the append-only trigger on shield_notes is gone"
    if "before truncate on public.shield_notes" not in sql:
        return False, "TRUNCATE on shield_notes is not blocked"
    return True, "notes are append-only against UPDATE, DELETE and TRUNCATE"


def inv_note_time_is_server_set():
    import routes
    src = _source(routes.write_note)
    if "written_at = utc_now_iso()" not in src:
        return False, "note write time is not server-set — a client could claim " \
                      "contemporaneity it does not have"
    if re.search(r'data\.get\(["\']written_at', src):
        return False, "write_note reads written_at from the request body"
    return True, "written_at set server-side"


def inv_custody_survives_truncate():
    sql = _all_migrations()
    if "before truncate on public.shield_custody_log" not in sql:
        return False, "TRUNCATE bypasses the row-level trigger and erases the " \
                      "entire chain of custody without firing it"
    return True, "statement-level truncate trigger present"


def inv_evidence_bucket_policy_is_restrictive():
    sql = _all_migrations()
    if "as restrictive" not in sql:
        return False, "the storage policy is permissive — Postgres ORs permissive " \
                      "policies, so it cannot deny, and it grants read on every " \
                      "other bucket in the project"
    return True, "evidence bucket denied by a restrictive policy"


def inv_evidence_tables_resist_deletion():
    sql = _all_migrations()
    if "on delete restrict" not in sql:
        return False, "evidence rows cascade on parent delete — one DELETE can " \
                      "erase the photos and the trail of their erasure together"
    return True, "photos and custody rows restrict parent deletion"


def inv_certification_does_not_overclaim():
    import evidence
    m = evidence.build_manifest(
        job={"id": "inv-job"}, points=[], photos=[], custody=[], report=None)
    text = evidence.certification_text(m)
    for needle, why in (
        ("does not certify", "the certification no longer states its limits"),
        ("complies with any building code",
         "the certification no longer disclaims code compliance"),
        ("Signature: ______", "the certification is being auto-signed"),
    ):
        if needle not in text:
            return False, why
    return True, "limits stated; signature left to a human"


def inv_upload_types_by_content_not_header():
    import integrity
    import routes
    if "integrity.sniff_mime" not in _calls(routes.upload_photo):
        return False, ("upload_photo no longer sniffs the container — the "
                       "uploader's Content-Type decides what counts as a photo")
    if re.search(r"mime\s*=\s*integrity\.normalize_mime\(upload\.content_type\)",
                 _source(routes.upload_photo)):
        return False, "the declared Content-Type is authoritative again"
    for blob, label in ((b"%PDF-1.4" + b"\x00" * 64, "a PDF"),
                        (b"MZ\x90\x00" + b"\x00" * 64, "a PE binary"),
                        (b"\xff\xd8", "a truncated JPEG magic")):
        if integrity.sniff_mime(blob) is not None:
            return False, f"{label} is recognised as a photo"
    return True, "the container's own magic decides the type"


def inv_no_analysable_copy_falls_back_to_the_original():
    import integrity
    # Read the AST, not the text: the docstring names the old behaviour, and a
    # grep for it flags the explanation as the defect.
    import ast
    import textwrap
    tree = ast.parse(textwrap.dedent(_source(integrity.compress_for_model)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        returned = (node.value.elts if isinstance(node.value, ast.Tuple)
                    else [node.value])
        if any(isinstance(v, ast.Name) and v.id == "raw" for v in returned):
            return False, ("compress_for_model returns the original bytes on "
                           "failure — the model is handed the unstripped "
                           "original under a .jpg path")
    out, reason = integrity.compress_for_model(b"%PDF-1.4" + b"\x00" * 64)
    if out is not None:
        return False, "an unencodable file still produced an analysable copy"
    return True, f"unencodable input yields no copy ({reason}), never the original"


def inv_pixel_count_is_bounded_before_decoding():
    import io
    import integrity
    try:
        from PIL import Image
    except ImportError:
        return True, "Pillow absent; nothing decodes here"
    import routes
    if "integrity.probe" not in _calls(routes.upload_photo):
        return False, "upload_photo no longer probes dimensions before storing"
    buf = io.BytesIO()
    Image.new("L", (9000, 9000)).save(buf, "PNG", compress_level=9)
    bomb = buf.getvalue()
    probed = integrity.probe(bomb)
    if probed["ok"]:
        return False, (f"an {probed['pixels'] / 1e6:,.0f} Mpx image in "
                       f"{len(bomb) // 1024} KB passes the bound")
    out, _ = integrity.compress_for_model(bomb)
    if out is not None:
        return False, "the decoder still expands a decompression bomb"
    return True, (f"{len(bomb) // 1024} KB / {probed['pixels'] / 1e6:,.0f} Mpx "
                  f"refused from the header; limit {integrity.MAX_PIXELS // 1_000_000} Mpx")


def inv_one_selector_decides_the_evidence():
    import evidence
    import routes
    import verdict
    for fn in (routes.complete_job, evidence.build_manifest):
        if not {"live_photo_for", "grading.live_photo_for",
                "verdict.live_photo_for"} & _calls(fn):
            return False, (f"{fn.__name__} selects the live photo on its own "
                           f"again — close-out and the export can name "
                           f"different photos for one checkpoint")
    first = {"id": "old", "point_id": "p1", "uploaded_at": "2026-09-02T15:00:00+00:00",
             "superseded_by": "new", "superseded_at": "2026-09-03T09:00:00+00:00"}
    second = {"id": "new", "point_id": "p1", "uploaded_at": "2026-09-03T09:05:00+00:00"}
    for order in ([first, second], [second, first]):
        if verdict.live_photo_for("p1", order)["id"] != "new":
            return False, "selection depends on the order rows arrive in"
    if [p["id"] for p in verdict.superseded_for("p1", [first, second])] != ["old"]:
        return False, "the superseded attempt is not disclosed"
    return True, "close-out and the export share one deterministic selector"


def inv_retakes_supersede_rather_than_collide():
    import routes
    src = _source(routes.upload_photo)
    if "superseded_at" not in src:
        return False, ("upload_photo never marks the prior photo superseded — "
                       "the one-live-photo index rejects every retake")
    if src.index('"superseded_at": superseded_at') > src.index("insert(row)"):
        return False, ("the prior photo is superseded after the insert, which "
                       "is the order that collides with the index")
    # Migrations are cumulative, so it is the LAST definition of this index
    # that is in force — an earlier, correct one proves nothing.
    mig = _all_migrations()
    defs = re.findall(r"on public\.shield_photos\s*\(point_id\)\s*where\s+(\w+)\s+is null",
                      mig)
    if not defs:
        return False, "the one-live-photo index is gone"
    if defs[-1] != "superseded_at":
        return False, (f"the one-live-photo index is keyed on {defs[-1]}, which "
                       f"cannot be set before the replacement row exists — "
                       f"every retake collides with it")
    if "check (superseded_by is null or superseded_at is not null)" not in mig:
        return False, "a supersede pointer without a timestamp would stay live"
    return True, "prior photo leaves the live set before its replacement lands"


def inv_missing_exif_is_detectable_in_every_format():
    import io
    import integrity
    try:
        from PIL import Image
    except ImportError:
        return True, "Pillow absent"
    for fmt, mime in (("JPEG", "image/jpeg"), ("PNG", "image/png")):
        buf = io.BytesIO()
        Image.new("RGB", (256, 256)).save(buf, fmt)
        status = integrity.extract_exif(buf.getvalue(), mime)[1]
        if status != "absent":
            return False, (f"a {fmt} carrying no EXIF reports '{status}' — the "
                           f"screenshot / downloaded-image signal is unreachable "
                           f"for {mime}, and so is the integrity flag it raises")
    return True, "a stripped photo reads as 'absent' in both formats"


def inv_every_integrity_note_raises_a_flag():
    # Read the keys of the `flags` dict itself. Matching on the source text
    # passes as long as the condition's *variable* is mentioned anywhere in the
    # function, which it always is.
    import ast
    import textwrap
    import routes
    keys = None
    for node in ast.walk(ast.parse(textwrap.dedent(_source(routes.upload_photo)))):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                and any(getattr(t, "id", None) == "flags" for t in node.targets)):
            keys = {k.value for k in node.value.keys
                    if isinstance(k, ast.Constant)}
    if keys is None:
        return False, "upload_photo no longer builds a flags dict"
    required = {"gps_mismatch", "exif_absent", "off_site", "not_analysable"}
    missing = required - keys
    if missing:
        return False, (f"the integrity_flag event no longer covers "
                       f"{', '.join(sorted(missing))} — a note is written to the "
                       f"upload event and nothing scanning the chain for a flag "
                       f"will see it")
    return True, f"flag raised for all {len(keys)} note conditions"


# Anything a customer, a recipient, or an opposing party reads. The ledger
# itself and its source are excluded for the obvious reason.
PUBLISHED_DOCS = ("README.md", "PROTECTION.md", "audit/PROTOCOL.md",
                  "audit/README.md", "audit/accepted-risks.md")

# A claim named in order to deny it is the opposite of an overclaim — it is
# the behaviour this product depends on. "Nothing here proves a photo came off
# a camera sensor" must pass; "a photo came off a camera sensor" must not.
NEGATORS = ("not", "cannot", "can't", "never", "nothing", "no ", "without",
            "unearned", "yet", "fails to", "unable", "does nothing")


def _negation_window(text, index):
    """The text negation is judged in: the sentence, plus a list item's lead-in.

    A bullet inherits its negation from the line that introduces the list —
    "Not proven:" followed by "- That any photo came off a camera sensor" is an
    honest disclaimer, and a window that stops at the newline reads it as an
    assertion. Found by this check firing on our own README, which was right.
    """
    start = max(text.rfind(".", 0, index), text.rfind("\n", 0, index),
                text.rfind("!", 0, index), text.rfind("?", 0, index)) + 1
    ends = [e for e in (text.find(".", index), text.find("\n", index)) if e != -1]
    window = text[start:(min(ends) if ends else len(text))]

    line_start = text.rfind("\n", 0, index) + 1
    if re.match(r"\s*(?:[-*+]|\d+\.)\s", text[line_start:index + 1]):
        # walk back to the nearest non-blank line that is not itself an item
        for line in reversed(text[:line_start].split("\n")):
            if not line.strip():
                continue
            if re.match(r"\s*(?:[-*+]|\d+\.)\s", line):
                continue
            window = line + " " + window
            break
    return window.strip()


def inv_claims_ledger_is_current():
    import claims
    path = SHIELD / "audit" / "CLAIMS.md"
    if not path.exists():
        return False, "audit/CLAIMS.md is missing — run `python claims.py`"
    if path.read_text() != claims.render_markdown():
        return False, ("audit/CLAIMS.md no longer matches claims.py — the "
                       "ledger and the checks have drifted; regenerate it")
    return True, (f"{len(claims.unearned())} unearned, {len(claims.earned())} "
                  f"earned; ledger matches source")


def inv_unearned_claims_are_not_published():
    """The gate. An unearned claim may be denied, never asserted."""
    import claims
    offences = []
    for c in claims.unearned():
        phrase = c["phrase"].lower()
        for rel in PUBLISHED_DOCS:
            path = SHIELD / rel
            if not path.exists():
                continue
            text = path.read_text()
            low = text.lower()
            i = low.find(phrase)
            while i != -1:
                sentence = _negation_window(text, i)
                if not any(n in sentence.lower() for n in NEGATORS):
                    offences.append(f"{rel}: \"{sentence[:90]}\" asserts "
                                    f"unearned claim '{c['id']}'")
                i = low.find(phrase, i + 1)
    if offences:
        return False, ("an unearned claim is being asserted in published text "
                       "— " + "; ".join(offences[:3]))
    return True, (f"{len(claims.unearned())} unearned claims appear only where "
                  f"they are denied")


def inv_earned_claims_cite_a_passing_test():
    """A claim is earned by a test that exists, not by a decision to ship."""
    import claims
    for c in claims.earned():
        named = re.findall(r"(test_\w+\.py)", c["test"])
        if not named:
            return False, (f"earned claim '{c['id']}' names no test file — "
                           f"it was marked earned by assertion")
        for t in named:
            if not (SHIELD / "tests" / t).exists():
                return False, (f"earned claim '{c['id']}' cites {t}, which "
                               f"does not exist")
        if not c.get("earned"):
            return False, f"claim '{c['id']}' has no earned date"
    return True, f"all {len(claims.earned())} earned claims cite a real test"


def inv_verifier_shares_no_code_with_the_service():
    """A recipient checking our package must not be running our code.

    The verifier is a reimplementation from SPEC.md. The moment someone
    imports ledger into it "to avoid duplication", the independence that makes
    the export worth anything is gone — and nothing else would notice, because
    every test would still pass.
    """
    src = (SHIELD / "verifier" / "shield_verify.py")
    if not src.exists():
        return False, "verifier/shield_verify.py is missing"
    text = src.read_text()
    for forbidden in ("import ledger", "import evidence", "import integrity",
                      "import config", "from ledger", "from evidence"):
        if forbidden in text:
            return False, (f"the verifier contains '{forbidden}' — it is no "
                           f"longer an independent implementation")
    for stdlib_only in re.findall(r"^\s*import\s+(\w+)", text, re.M):
        if stdlib_only not in ("argparse", "hashlib", "json", "os", "sys"):
            return False, (f"the verifier imports '{stdlib_only}' — it must run "
                           f"from a bare interpreter with nothing installed")
    return True, "independent reimplementation, standard library only"


def inv_export_carries_recomputable_custody():
    """The package must contain what a recipient needs, not a summary of it."""
    import evidence
    src = _source(evidence.build_manifest)
    if "custody_entries" not in src:
        return False, ("the export no longer carries raw custody entries — a "
                       "recipient cannot recompute the chain, so its integrity "
                       "is our assertion rather than their check")
    return True, "raw entries exported; the chain is recomputable by the holder"


def inv_verifier_agrees_with_the_service():
    """Two implementations of one spec must reach the same hash."""
    import sys as _sys
    _sys.path.insert(0, str(SHIELD / "verifier"))
    import ledger
    import shield_verify
    job = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    if shield_verify.genesis_hash(job) != ledger.genesis_hash(job):
        return False, "the spec and the service disagree on the genesis value"
    entry = {"shield_job_id": job, "event_type": "uploaded",
             "actor_type": "contractor", "gps_lat": 40.76056,
             "event_data": {"b": 2, "a": [1, 2]},
             "recorded_at": "2026-09-01T10:00:00+00:00"}
    if shield_verify.canonical(entry) != ledger.canonical(entry):
        return False, ("the spec and the service disagree on canonical bytes — "
                       "every package we have issued verifies against only one "
                       "of them")
    prev = ledger.genesis_hash(job)
    if shield_verify.link(entry, prev) != ledger.link(entry, prev):
        return False, "the spec and the service compute different links"
    return True, "spec and service agree on genesis, canonical bytes and links"


def inv_rebroadcast_never_accuses():
    """A flat subject must never be turned into a finding against a contractor.

    Drywall, a slab, a foundation wall — construction is full of planar
    subjects, and both rebroadcast signals read planar as ambiguous. A build
    that let `assess()` upgrade a negative into an accusation would flag honest
    work far more often than fraud, which is worse than having no check.
    """
    import rebroadcast
    display_like = {"test": "flash_pair", "verdict": "consistent_with_display",
                    "reason": "flat gain"}
    planar = {"test": "parallax", "verdict": "planar", "reason": "one homography"}

    out = rebroadcast.assess(flash=display_like, parallax=planar)
    if out.get("upgrade") is not False:
        return False, "a negative result now upgrades the record"
    if out.get("verdict") != "not_corroborated":
        return False, (f"a negative result returns verdict "
                       f"{out.get('verdict')!r} rather than 'not_corroborated'")
    text = (out.get("reason") or "").lower()
    for word in ("fraud", "fake", "forged", "faked", "staged"):
        if word in text:
            return False, (f"the negative-result wording accuses: contains "
                           f"{word!r}")

    # and a positive must still be able to upgrade, or the check is inert
    good = rebroadcast.assess(
        flash={"test": "flash_pair", "verdict": "consistent_with_scene",
               "reason": "depth-varying gain"})
    if good.get("upgrade") is not True:
        return False, "a positive result no longer upgrades — the check is inert"
    return True, "positives upgrade; negatives never accuse"


def inv_attestation_fails_closed():
    """Unverified or unbound device claims must never reach a trusted tier.

    Two failure shapes, both of which this file previously missed:

    1. A truthy check instead of an identity one. `{"verified": "false"}`
       passes `if payload.get("verified")`, and the payload is attacker-
       supplied JSON, so a fail-open here hands hardware trust to anyone
       willing to type the word.
    2. A binding the CALLER asserts rather than the token carries. The first
       version took `challenge_ok` as a boolean, so spending a fresh nonce
       while presenting a token minted against an older one returned full
       hardware trust. This invariant passed anyway, because it built its own
       payload the same incomplete way the unit tests did.
    """
    import attestation

    def payload(*labels, app=None, nonce="inv-nonce"):
        out = {"deviceIntegrity": {"deviceRecognitionVerdict": list(labels)},
               "appIntegrity": {
                   "appRecognitionVerdict": app or attestation.PLAY_RECOGNIZED,
                   "packageName": "com.tradedeck.shield"}}
        if nonce is not None:
            out["requestDetails"] = {
                "requestHash": attestation.challenge_hash(nonce)}
        return out

    strong = payload(attestation.STRONG_INTEGRITY)
    for impostor in ("false", "unverified", 1, [1], {"ok": 1}, None):
        out = attestation.interpret_play_integrity(strong, verified=impostor,
                                                   expect_nonce="inv-nonce")
        if out["tier"] in attestation.TRUSTED_TIERS:
            return False, (f"a verdict flagged verified={impostor!r} reached "
                           f"trusted tier {out['tier']!r}")
        if attestation.interpret_app_attest(verified=impostor)["trusted"]:
            return False, f"App Attest trusted a verified={impostor!r} result"

    # a token about some OTHER capture
    replayed = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY, nonce="a-different-capture"),
        verified=True, expect_nonce="inv-nonce")
    if replayed["trusted"] or attestation.assess("android", replayed,
                                                 challenge_ok=True)["trusted"]:
        return False, ("a token bound to a different nonce was trusted — a "
                       "replay carries hardware trust onto a file the device "
                       "never saw")

    # a token carrying no binding at all, with the caller asserting otherwise
    unbound = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY, nonce=None), verified=True,
        expect_nonce="inv-nonce")
    if attestation.assess("android", unbound, challenge_ok=True)["trusted"]:
        return False, ("assess() can still be TOLD the binding happened; it "
                       "must read it off the token")

    # a repackaged app on genuine hardware
    repacked = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY,
                app=attestation.UNRECOGNIZED_VERSION),
        verified=True, expect_nonce="inv-nonce")
    if repacked["tier"] != attestation.TIER_FAILED:
        return False, ("a modified or repackaged app on a genuine handset is "
                       "not being caught — appIntegrity is unchecked")

    # malformed shapes must not raise; a crash in a route is a block
    for broken in ({"deviceIntegrity": "x"}, {"deviceIntegrity": [1]},
                   {"appIntegrity": 3, "deviceIntegrity": {}}):
        r = attestation.interpret_play_integrity(broken, verified=True,
                                                 expect_nonce="inv-nonce")
        if r["tier"] != attestation.TIER_UNVERIFIABLE:
            return False, f"malformed payload {broken!r} did not fail closed"

    # and the check must still be able to pass, or it is inert
    good = attestation.interpret_play_integrity(strong, verified=True,
                                                expect_nonce="inv-nonce")
    if not attestation.assess("android", good, challenge_ok=True)["trusted"]:
        return False, "a verified, challenge-bound attestation no longer passes"
    return True, ("unverified, unbound, replayed, repackaged and malformed all "
                  "fail closed; a correctly bound token still passes")


def inv_attestation_labels_rather_than_blocks():
    """Failing attestation must downgrade the record, never refuse the capture.

    A blocked capture produces no photograph, no hash and no custody entry —
    strictly less evidence than a recorded one carrying an honest note. Whether
    an unattested photo may close a milestone is the buyer's policy decision
    against their own money, not a refusal this library makes for them.

    Also guards the Play Integrity label the intuitive design gets backwards:
    an EMPTY deviceRecognitionVerdict is the attack signal, while
    MEETS_VIRTUAL_INTEGRITY is a recognised Play Games emulator. Blocking on
    VIRTUAL stops the honest PC gamer and admits the attacker.
    """
    import attestation

    def verdict(*labels):
        return attestation.interpret_play_integrity(
            {"deviceIntegrity": {"deviceRecognitionVerdict": list(labels)},
             "appIntegrity": {
                 "appRecognitionVerdict": attestation.PLAY_RECOGNIZED,
                 "packageName": "com.tradedeck.shield"},
             "requestDetails": {
                 "requestHash": attestation.challenge_hash("inv-nonce")}},
            verified=True, expect_nonce="inv-nonce")

    for case in (attestation.assess(),
                 attestation.assess("android", verdict(), challenge_ok=True),
                 attestation.assess("android", verdict(attestation.VIRTUAL_INTEGRITY)),
                 attestation.assess("ios", attestation.interpret_app_attest(
                     verified=True, receipt_ok=False), challenge_ok=True)):
        if case.get("capture_allowed") is not True:
            return False, (f"tier {case.get('tier')!r} now refuses the capture "
                           f"instead of labelling it")

    if verdict()["tier"] != attestation.TIER_FAILED:
        return False, ("an empty deviceRecognitionVerdict no longer reads as a "
                       "failure — Google documents it as root, hooking or an "
                       "unrecognised emulator, and it is the real attack signal")
    if verdict(attestation.VIRTUAL_INTEGRITY)["tier"] == attestation.TIER_FAILED:
        return False, ("a recognised Play Games emulator is being recorded as "
                       "an integrity failure, which it is not")

    unattested = attestation.assess()
    if unattested["tier"] != attestation.TIER_UNATTESTED:
        return False, "a capture with no attestation no longer reads as unattested"
    for word in ("fraud", "fake", "forged", "tamper", "compromise"):
        if word in unattested["reason"].lower():
            return False, (f"the wording for an ordinary web upload accuses: "
                           f"contains {word!r}")
    return True, "attestation labels the record and never blocks a capture"


INVARIANTS = (
    ("analyze-trusts-nothing", "Substitute the image being graded via the request body", inv_analyze_trusts_nothing),
    ("analyze-write-conditional", "Race concurrent analyses to re-roll a verdict", inv_analyze_write_is_conditional),
    ("upload-scopes-checkpoint", "File a photo against another job's checkpoint", inv_upload_scopes_the_checkpoint),
    ("upload-hash-ordering", "Have the hash cover processed rather than received bytes", inv_upload_hashes_before_touching),
    ("originals-immutable", "Replace an original after it was hashed", inv_originals_are_never_overwritten),
    ("grading-counts-missing", "Report 'pass' on a job that was barely documented", inv_grading_counts_missing_evidence),
    ("badge-distinct-jobs", "Mint the verified badge from repeat close-outs of one job", inv_badge_counts_distinct_jobs),
    ("checkpoints-locked", "Rewrite the requirements after seeing the verdicts", inv_checkpoints_lock_and_are_buyer_owned),
    ("custody-chained", "Rewrite history without leaving a trace", inv_custody_is_chained),
    ("custody-detects-edits", "Edit a custody entry undetected", inv_custody_chain_detects_tampering),
    ("actor-derived", "Have a contractor's sign-off recorded as the buyer's", inv_actor_is_derived_not_asserted),
    ("payment-verified", "Activate a job without paying its price", inv_payment_is_verified),
    ("price-server-side", "Buy Shield for a cent", inv_price_is_server_side),
    ("ip-salt-required", "Reverse a stored uploader IP from a known salt", inv_ip_salt_has_no_fallback),
    ("xff-trusted-hop", "Choose the IP recorded against your own upload", inv_forwarded_for_uses_the_trusted_hop),
    ("upload-size-bounded", "Exhaust the worker with an unbounded body", inv_upload_size_is_bounded_before_buffering),
    ("notes-append-only", "Silently edit a field note after the fact", inv_notes_cannot_be_edited),
    ("note-time-server-set", "Claim contemporaneity a note does not have", inv_note_time_is_server_set),
    ("custody-survives-truncate", "Erase the whole chain with one TRUNCATE", inv_custody_survives_truncate),
    ("bucket-policy-restrictive", "Read the evidence bucket, or any other, as a signed-in user", inv_evidence_bucket_policy_is_restrictive),
    ("evidence-delete-restricted", "Destroy evidence and its audit trail in one statement", inv_evidence_tables_resist_deletion),
    ("certification-honest", "Ship a certification that overclaims", inv_certification_does_not_overclaim),
    ("upload-types-by-content", "Pass arbitrary bytes off as a photograph with a Content-Type header", inv_upload_types_by_content_not_header),
    ("no-original-to-the-model", "Get the unstripped original handed to the model by malforming the file", inv_no_analysable_copy_falls_back_to_the_original),
    ("pixel-count-bounded", "Kill the worker with a 77 KB decompression bomb", inv_pixel_count_is_bounded_before_decoding),
    ("one-evidence-selector", "Have the sealed packet and the export cite different photos", inv_one_selector_decides_the_evidence),
    ("retakes-supersede", "Bury a failed checkpoint photo, or block retakes entirely", inv_retakes_supersede_rather_than_collide),
    ("exif-absent-reachable", "Submit a stripped or downloaded JPEG without tripping the screenshot signal", inv_missing_exif_is_detectable_in_every_format),
    ("note-implies-flag", "Land outside the buyer's geofence with no flag in the custody chain", inv_every_integrity_note_raises_a_flag),
    ("claims-ledger-current", "Let the claims ledger drift from what the checks actually enforce", inv_claims_ledger_is_current),
    ("unearned-claims-unpublished", "Ship a claim the product has not earned", inv_unearned_claims_are_not_published),
    ("earned-claims-cite-a-test", "Mark a claim earned by decision rather than by evidence", inv_earned_claims_cite_a_passing_test),
    ("verifier-is-independent", "Have a recipient 'verify' a package by running our own code", inv_verifier_shares_no_code_with_the_service),
    ("export-is-recomputable", "Hand over a package whose integrity is our assertion", inv_export_carries_recomputable_custody),
    ("spec-matches-service", "Ship a spec that does not produce the hashes we issue", inv_verifier_agrees_with_the_service),
    ("rebroadcast-never-accuses", "Turn a photograph of a flat wall into a fraud finding", inv_rebroadcast_never_accuses),
    ("attestation-fails-closed", "Claim hardware trust with an unverified or replayed attestation", inv_attestation_fails_closed),
    ("attestation-labels-not-blocks", "Turn a rooted phone into a subcontractor who cannot document his work", inv_attestation_labels_rather_than_blocks),
)


def run():
    """Run every invariant. Returns (results, failures)."""
    results = []
    for inv_id, attack, fn in INVARIANTS:
        ok, detail = _check(fn)
        results.append({"id": inv_id, "attack_prevented": attack,
                        "holding": ok, "detail": detail})
    return results, [r for r in results if not r["holding"]]


def main():
    results, failures = run()
    width = max(len(r["id"]) for r in results)
    for r in results:
        mark = "HOLDS " if r["holding"] else "BROKEN"
        print(f"  [{mark}] {r['id']:<{width}}  {r['detail']}")
    print()
    if failures:
        print(f"{len(failures)} INVARIANT(S) BROKEN — a closed exploit has reopened:")
        for f in failures:
            print(f"  - {f['id']}: prevents “{f['attack_prevented']}”")
            print(f"      {f['detail']}")
        return 1
    print(f"All {len(results)} invariants hold. No closed exploit has reopened.")
    return 0


if __name__ == "__main__":
    if "--json" in sys.argv:
        results, failures = run()
        print(json.dumps({"invariants": results, "broken": len(failures)}, indent=2))
        sys.exit(1 if failures else 0)
    sys.exit(main())
