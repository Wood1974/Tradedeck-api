"""Claims we intend to be able to make, and what each one still costs.

The failure this prevents
-------------------------
`audit/accepted-risks.md` is a ledger of limits we have accepted. This is its
mirror: a ledger of claims we have *not yet earned*. Both exist for the same
reason, from opposite directions — the accepted-risks file stops the audit
re-reporting what we already know, and this file stops us saying something
before it is true.

A slogan written a month early is a roadmap item. The same slogan on a page a
week early is an overclaim, and an overclaim is the one kind of damage this
product does not recover from: the entire reason to prefer a record from us
over a competitor's is that our statements survive being tested. One that
doesn't spends an asset that took years to accumulate and cannot be rebought.

So every claim here carries the mechanism that would make it true, the test
that proves the mechanism works, and a date. The date is the gate. While it is
None the claim is UNEARNED, and `audit/invariants.py` fails the build if the
text of an unearned claim appears in anything a customer reads.

Why the phrase matters
----------------------
`phrase` is a short distinctive fragment of the claim — what an invariant
greps for. It is deliberately not the whole sentence: marketing rewords, and a
check that only catches the exact wording catches nothing. Pick the part that
carries the assertion and would survive an edit.

Adding one
----------
Write it the moment you *want* to say it, not when you can. That is the point:
capturing the ambition is free and it turns a temptation into a work item with
an acceptance test attached.
"""

CLAIMS = (
    {
        "id": "cheapest-to-do-the-work",
        "claim": "The cheapest way to pass is to do the work.",
        "phrase": "cheapest way to pass",
        "needs": (
            "DONE (synthetic only) — flash-pair analysis, rebroadcast.py.",
            "DONE (synthetic only) — two-pose parallax, rebroadcast.py.",
            "Field calibration of both against real phones, real displays and "
            "real jobsites. The thresholds have never seen a real photograph "
            "of a real screen.",
            "Server-issued capture nonce with a short TTL, bound into the "
            "attestation, so archived and pre-prepared images are excluded.",
            "Platform attestation (Apple App Attest / Android Key Attestation "
            "with verifiedBootState GREEN), which requires the native app.",
            "A capture flow that forces real translation between the two "
            "poses — pure rotation makes every scene look planar.",
        ),
        "test": "test_rebroadcast.py — discrimination proven on synthetic "
                "scenes; field calibration not yet designed",
        "earned": None,
        "note": "Two of the mechanisms now exist and separate the cases "
                "cleanly on synthetic data. That is the maths working, not the "
                "product working: no threshold here has met a real screen. "
                "Today a forgery still costs about twelve lines of Python; see "
                "AR-1.",
    },
    {
        "id": "tamper-evident-custody",
        "claim": "The custody history cannot be altered without detection, "
                 "including by the operator.",
        "phrase": "cannot be altered without detection",
        "needs": (
            "Hash-linked custody entries with a published chain head.",
            "Append-only enforcement at the database level against UPDATE, "
            "DELETE and TRUNCATE.",
            "A chain head that has left the building, so a full rewrite is "
            "detectable rather than merely internally inconsistent.",
        ),
        "test": "test_ledger.py — 21 tampering attacks, each caught at the "
                "correct entry index",
        "earned": "2026-09-14",
        "note": "Earned with one honest limit stated alongside it: a complete "
                "rewrite IS internally consistent. Detection depends on a "
                "holder comparing the head hash they were given.",
    },
    {
        "id": "verifiable-without-trusting-us",
        "claim": "The evidence export can be verified by a recipient without "
                 "trusting us.",
        "phrase": "without trusting us",
        "needs": (
            "A manifest carrying every hash and its algorithm.",
            "Independent chain verification the recipient runs themselves.",
            "Published commands that require no access to our systems.",
        ),
        "test": "test_evidence.py — manifest and verification instructions "
                "assert on what a recipient can check unaided",
        "earned": "2026-09-14",
        "note": "True for the chain and the hashes. It does NOT extend to the "
                "photograph's origin — see the unearned claim above.",
    },
    {
        "id": "requirements-predate-work",
        "claim": "The checkpoint requirements provably predate the work being "
                 "audited.",
        "phrase": "provably predate",
        "needs": (
            "Checkpoints generated by the buyer, not the audited party.",
            "A one-way lock with the schedule hash written into the chain.",
        ),
        "test": "test_shield.py — checkpoint locking; invariant "
                "checkpoints-locked",
        "earned": "2026-09-14",
        "note": "Predates the *upload*. It does not establish when the photo "
                "was taken, only that the criteria were fixed first.",
    },
    {
        "id": "independently-corroborated-location",
        "claim": "A photo's location is corroborated against a reference the "
                 "audited party does not control.",
        "phrase": "does not control",
        "needs": (
            "A geofence measured against a site the buyer fixed at purchase.",
            "Solar geometry constraining the light for the claimed place and "
            "time.",
        ),
        "test": "test_corroborate.py — solar position against geometric "
                "identities; test_shield.py — haversine geofence",
        "earned": "2026-09-14",
        "note": "Corroborates the *reported* position against the site. A "
                "contractor physically on site photographing a screen defeats "
                "it; that is what the flash-pair work is for.",
    },
    {
        "id": "note-time-is-real",
        "claim": "A field note's stated time is the time it was actually "
                 "written.",
        "phrase": "actually written",
        "needs": (
            "written_at set server-side and never accepted from the client.",
            "Append-only notes; corrections are amendments, not edits.",
            "The delay between observation and writing carried into the "
            "export rather than hidden.",
        ),
        "test": "test_notes.py — contemporaneity banding; invariants "
                "note-time-server-set and notes-append-only",
        "earned": "2026-09-14",
        "note": "The write time is ours. The *observation* time is the "
                "writer's assertion, and the export says so.",
    },
    {
        "id": "rebroadcast-detection",
        "claim": "A capture can be positively corroborated as a real "
                 "three-dimensional scene.",
        "phrase": "positively corroborated as a real",
        "needs": (
            "Flash-pair and parallax analysis — built.",
            "Thresholds calibrated against real devices and real displays, "
            "with a measured false-positive rate on ordinary flat subjects.",
            "The capture flow that produces the two frames and the two poses.",
        ),
        "test": "test_rebroadcast.py — 18 cases including the flat wall, the "
                "blown-out frame, and pure rotation",
        "earned": None,
        "note": "Deliberately framed as an UPGRADE, never a detector. Both "
                "signals are strong positives and weak negatives: non-planar "
                "proves depth, but planar means screen OR flat wall OR a "
                "rotated capture. Construction is full of flat subjects, so a "
                "system that read planar as fraud would accuse honest "
                "contractors far more often than it caught anyone. assess() "
                "enforces that asymmetry and a test asserts it.",
    },
    {
        "id": "photo-came-from-a-camera",
        "claim": "A photo came off a camera sensor rather than a file picker.",
        "phrase": "came off a camera sensor",
        "needs": (
            "Platform attestation binding the photo hash to hardware.",
            "Rebroadcast detection (flash pair, parallax) to defeat the "
            "screen-replay path that attestation alone leaves open.",
            "C2PA capture-side credentials where the device supports them.",
        ),
        "test": "not yet designed",
        "earned": None,
        "note": "This is AR-1. It may never be fully earnable — the honest "
                "endpoint is probably a stated cost of forgery, not a proof. "
                "If that is where it lands, change the claim rather than "
                "stretching the evidence to reach it.",
    },
    {
        "id": "listed-conforming-product",
        "claim": "Shield is a C2PA Conforming Product.",
        "phrase": "Conforming Product",
        "needs": (
            "Legal entity in good standing whose name matches registration "
            "exactly.",
            "C2PA conformance submission, legal onboarding, and product "
            "security architecture documentation.",
            "A Conformance Letter, then a Claim Signing Certificate from a CA "
            "on the C2PA Trust List.",
        ),
        "test": "listing verifiable on the public Conforming Products List",
        "earned": None,
        "note": "The one claim here whose proof is somebody else's register "
                "rather than our own test suite — which is precisely why it "
                "is worth more than the others.",
    },
)


def earned(claims=CLAIMS):
    """Claims that may appear in anything a customer reads."""
    return [c for c in claims if c["earned"]]


def unearned(claims=CLAIMS):
    """Claims that may not. The invariant enforces this against the docs."""
    return [c for c in claims if not c["earned"]]


def by_id(claim_id, claims=CLAIMS):
    return next((c for c in claims if c["id"] == claim_id), None)


def render_markdown(claims=CLAIMS) -> str:
    """The ledger as `audit/CLAIMS.md`.

    Generated rather than hand-written, and an invariant asserts the file on
    disk matches this output — so the ledger and the checks cannot drift the
    way a hand-maintained document always eventually does.
    """
    out = [
        "# Claims ledger — what we may say, and what it still costs",
        "",
        "**Generated from `shield/claims.py`. Do not edit by hand** — an",
        "invariant compares this file against the source and fails the build",
        "if they differ.",
        "",
        "The mirror of `accepted-risks.md`. That file records limits we have",
        "accepted; this one records claims we have not yet earned. A claim",
        "with no date is **unearned**, and `audit/invariants.py` fails if its",
        "text appears in anything a customer reads.",
        "",
        "Write a claim down the moment you want to make it. Capturing the",
        "ambition is free, and it converts a temptation into a work item with",
        "an acceptance test attached.",
        "",
        "---",
        "",
    ]
    for group, heading in ((unearned(claims), "Unearned — do not publish"),
                           (earned(claims), "Earned")):
        if not group:
            continue
        out += [f"## {heading}", ""]
        for c in group:
            status = f"earned {c['earned']}" if c["earned"] else "**UNEARNED**"
            out += [
                f"### {c['claim']}",
                f"`{c['id']}` · {status} · greps for *\"{c['phrase']}\"*",
                "",
                "**Needs:**",
            ]
            out += [f"- {n}" for n in c["needs"]]
            out += [
                "",
                f"**Test:** {c['test']}",
                "",
                c["note"],
                "",
            ]
        out += ["---", ""]
    return "\n".join(out).rstrip() + "\n"


if __name__ == "__main__":  # regenerate the ledger
    import pathlib
    target = pathlib.Path(__file__).parent / "audit" / "CLAIMS.md"
    target.write_text(render_markdown())
    print(f"wrote {target} ({len(unearned())} unearned, {len(earned())} earned)")
