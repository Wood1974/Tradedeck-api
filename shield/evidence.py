"""Evidence export — the artefact a lawyer, adjuster or arbitrator actually wants.

Why this is the product
-----------------------
Nothing in a construction dispute turns on whether the AI was right. It turns
on whether the record can be relied on. Federal Rule of Evidence 902(14) makes
a digital record self-authenticating when it is identified "by a process of
digital identification" — in practice, a hash comparison — "as shown by a
certification of a qualified person." The Advisory Committee note is explicit
that the qualified person must at minimum check the hash value of the proffered
item and certify that it was identical to the original.

That is a mechanical requirement, and it is the whole reason the upload path
hashes bytes before touching them. This module turns the stored record into the
package that requirement expects: the manifest of hashes, the custody chain with
its verification result, and a pre-filled certification a named person signs.

What this module does NOT claim
-------------------------------
It does not make anything admissible. Only a judge does that, case by case, and
a vendor claiming otherwise is selling something. Authentication is also not
admissibility — hearsay, relevance and Rule 403 are separate fights. What this
produces is the foundation a competent lawyer needs in order to have the
argument at all, prepared in advance instead of reconstructed under deadline.

The certification is deliberately left unsigned. A certification is a sworn
statement by a human being who can be cross-examined on it. Auto-signing one
would be the exact kind of hollow assurance this product exists to replace.
"""
from datetime import datetime, timezone

import ledger

MANIFEST_SCHEMA = "tradedeck.shield.evidence-manifest.v1"


def _fmt(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")) \
            .astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return str(ts)


def build_manifest(*, job, points, photos, custody, report=None):
    """The hash manifest plus an independent verification of the custody chain.

    Every item a recipient needs in order to check the package themselves,
    without trusting us and without access to our database.
    """
    chain = ledger.verify_chain(custody, job["id"])

    items = []
    for pt in sorted(points, key=lambda p: p.get("point_number") or 0):
        live = next((ph for ph in photos
                     if ph.get("point_id") == pt["id"] and not ph.get("superseded_by")), None)
        retakes = [ph for ph in photos
                   if ph.get("point_id") == pt["id"] and ph.get("superseded_by")]
        items.append({
            "checkpoint_number": pt.get("point_number"),
            "checkpoint":        pt.get("label"),
            "requirement":       pt.get("description"),
            "code_section":      pt.get("irc_code") or pt.get("ibc_code"),
            "must_show":         pt.get("must_show"),
            "photo_id":          live.get("id") if live else None,
            "sha256_original":   live.get("original_hash") if live else None,
            "hash_algorithm":    live.get("original_hash_algo", "SHA-256") if live else None,
            "size_bytes":        live.get("original_size_bytes") if live else None,
            "received_utc":      live.get("server_received_at") if live else None,
            "exif_captured_utc": live.get("exif_captured_at") if live else None,
            "has_camera_metadata": live.get("has_exif") if live else None,
            "metres_from_site":  live.get("site_distance_m") if live else None,
            "verdict":           live.get("ai_verdict") if live else None,
            "confidence":        live.get("ai_confidence") if live else None,
            "model":             live.get("ai_model") if live else None,
            "assessment":        live.get("ai_notes") if live else None,
            # Retakes are disclosed, never hidden. A checkpoint photographed
            # four times before it passed is a fact about the job, and a
            # package that conceals it invites exactly the impeachment it was
            # built to survive.
            "superseded_attempts": [
                {"photo_id": r.get("id"), "sha256_original": r.get("original_hash"),
                 "verdict": r.get("ai_verdict"), "superseded_utc": r.get("superseded_at")}
                for r in retakes],
        })

    return {
        "schema": MANIFEST_SCHEMA,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "job": {
            "shield_job_id":          job["id"],
            "external_reference":     job.get("external_ref"),
            "site_address":           job.get("site_address"),
            "site_coordinates":       ([job.get("site_lat"), job.get("site_lng")]
                                       if job.get("site_lat") is not None else None),
            "geofence_radius_m":      job.get("site_radius_m"),
            "trade":                  job.get("trade"),
            "created_utc":            job.get("created_at"),
            "activated_utc":          job.get("activated_at"),
            "checkpoints_locked_utc": job.get("checkpoints_locked_at"),
            "completed_utc":          job.get("completed_at"),
        },
        "checkpoints": items,
        "custody": {
            "entries":       chain["entries"],
            "head_hash":     chain["head_hash"],
            "chain_intact":  chain["intact"],
            "chain_summary": chain["summary"],
            "chain_version": chain["chain_version"],
        },
        "outcome": {
            "verdict":       (report or {}).get("overall_verdict"),
            "score":         (report or {}).get("completion_score"),
            "packet_sha256": (report or {}).get("report_sha256"),
        },
    }


def certification_text(manifest, *, certifier_name="", certifier_title="",
                       certifier_qualifications=""):
    """A Rule 902(13)/(14) certification, pre-filled and left unsigned.

    Structured on what the rule and the practitioner literature actually ask
    for: who the certifier is and why they are competent, the substance of the
    testimony they would give live, and the process that produced the record.
    """
    job = manifest["job"]
    cust = manifest["custody"]
    items = manifest["checkpoints"]
    with_hash = [i for i in items if i["sha256_original"]]

    lines = [
        "CERTIFICATION OF RECORD GENERATED BY AN ELECTRONIC PROCESS",
        "Federal Rules of Evidence 902(13) and 902(14)",
        "",
        f"Shield job reference: {job['shield_job_id']}",
        f"Site: {job.get('site_address') or 'not recorded'}",
        f"Record generated: {_fmt(manifest['generated_utc'])}",
        "",
        "1. CERTIFIER",
        f"   Name:  {certifier_name or '_________________________________'}",
        f"   Title: {certifier_title or '_________________________________'}",
        "   Qualifications: "
        f"{certifier_qualifications or '_________________________________'}",
        "",
        "   I am familiar with the operation of the system described below and",
        "   competent to testify to the matters stated here. If called as a",
        "   witness I would testify to the following.",
        "",
        "2. THE SYSTEM AND ITS PROCESS",
        "   Photographs were submitted through the TradeDeck Shield service",
        "   against a checkpoint schedule fixed before the documented work",
        f"   began ({_fmt(job.get('checkpoints_locked_utc'))}). For each",
        "   photograph the system, in this order and before any processing:",
        "",
        "     (a) received the file and read its bytes;",
        "     (b) computed a SHA-256 digest over those bytes as received;",
        "     (c) extracted camera metadata from the unmodified original;",
        "     (d) wrote the original, unmodified, to write-once storage;",
        "     (e) recorded an entry in an append-only custody log, each entry",
        "         carrying the cryptographic hash of the entry preceding it.",
        "",
        "   The original file is never altered after step (d). A separate",
        "   reduced copy is generated for automated assessment; the original",
        "   is not used for that purpose and is not transmitted to any",
        "   third-party service.",
        "",
        "3. DIGITAL IDENTIFICATION — Rule 902(14)",
        f"   This record comprises {len(with_hash)} photograph(s) across",
        f"   {len(items)} checkpoint(s). Each is identified by the SHA-256",
        "   digest listed in the accompanying manifest. I have compared the",
        "   digest of each item produced against the digest recorded at the",
        "   time of receipt, and they are identical. Each item produced is",
        "   therefore an exact duplicate of the original as received.",
        "",
        "4. INTEGRITY OF THE CUSTODY RECORD",
        f"   The custody log contains {cust['entries']} entries. Each entry",
        "   incorporates the hash of its predecessor, so any alteration,",
        "   removal or reordering breaks every subsequent link.",
        f"   Verification result: {cust['chain_summary']}",
        f"   Chain head digest: {cust['head_hash']}",
        "",
        "5. SCOPE AND LIMITS OF THIS CERTIFICATION",
        "   This certification addresses the integrity and provenance of the",
        "   records only. It does not certify:",
        "",
        "     - that any automated assessment of a photograph is correct;",
        "     - that the work depicted complies with any building code;",
        "     - that a photograph depicts any particular place, beyond the",
        "       corroborating signals described in the manifest.",
        "",
        "   Automated assessments are stated with the model and confidence",
        "   used and are offered as opinion, not as a finding of compliance.",
        "",
        "6. DECLARATION",
        "   I declare under penalty of perjury under the laws of the United",
        "   States of America that the foregoing is true and correct.",
        "",
        "   Signature: ______________________________  Date: ______________",
        "",
        "NOTICE: Rule 902(11) requires that the proponent give an adverse party",
        "reasonable written notice of the intent to offer this record and make",
        "the record and this certification available for inspection sufficiently",
        "in advance to provide a fair opportunity to challenge them.",
    ]
    return "\n".join(lines)


def verification_instructions(manifest):
    """How a recipient checks this package without trusting us.

    A package that can only be verified by its author is not evidence. These
    are the commands an opposing expert would run, stated plainly so they can.
    """
    return "\n".join([
        "HOW TO VERIFY THIS PACKAGE INDEPENDENTLY",
        "",
        "1. Check each photograph against its recorded digest:",
        "",
        "     shasum -a 256 <photo file>",
        "",
        "   Compare the result to `sha256_original` for that checkpoint in the",
        "   manifest. They must match exactly. A mismatch means the file you",
        "   hold is not the file that was received.",
        "",
        "2. Check the custody chain. Each entry's `entry_hash` is:",
        "",
        "     SHA-256( canonical(signed fields) || \"|\" || prev_hash )",
        "",
        f"   The first entry's prev_hash is the job genesis: "
        f"{ledger.genesis_hash(manifest['job']['shield_job_id'])}",
        "   Recompute forward; every link must match. The published chain head",
        f"   is {manifest['custody']['head_hash']}.",
        "",
        "   The canonical form is documented in the service's ledger module:",
        f"   signed fields, in order: {', '.join(ledger.SIGNED_FIELDS)}.",
        "",
        "3. If you were given a chain head digest at an earlier date, compare it",
        "   to the head above. A head that has changed for entries you already",
        "   hold means the history was rewritten after you received it.",
    ])
