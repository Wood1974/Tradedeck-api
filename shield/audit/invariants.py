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
