# Claims ledger — what we may say, and what it still costs

**Generated from `shield/claims.py`. Do not edit by hand** — an
invariant compares this file against the source and fails the build
if they differ.

The mirror of `accepted-risks.md`. That file records limits we have
accepted; this one records claims we have not yet earned. A claim
with no date is **unearned**, and `audit/invariants.py` fails if its
text appears in anything a customer reads.

Write a claim down the moment you want to make it. Capturing the
ambition is free, and it converts a temptation into a work item with
an acceptance test attached.

---

## Unearned — do not publish

### The cheapest way to pass is to do the work.
`cheapest-to-do-the-work` · **UNEARNED** · greps for *"cheapest way to pass"*

**Needs:**
- DONE (synthetic only) — flash-pair analysis, rebroadcast.py.
- DONE (synthetic only) — two-pose parallax, rebroadcast.py.
- Field calibration of both against real phones, real displays and real jobsites. The thresholds have never seen a real photograph of a real screen.
- DONE (server side) — single-use capture nonce with a short TTL, ENFORCED against the token's own requestHash rather than asserted by the caller, so a replayed attestation cannot carry trust onto a file the device never saw. The first cut of this shipped the bookkeeping without the binding; see attack 21. Needs a shared store before it works under more than one worker (AR-9).
- Platform attestation, which requires the native app that does not exist. attestation.py holds the policy; nothing produces a verdict for it to read.
- A capture flow that forces real translation between the two poses — pure rotation makes every scene look planar.

**Test:** test_rebroadcast.py — discrimination proven on synthetic scenes; field calibration not yet designed

Two of the mechanisms now exist and separate the cases cleanly on synthetic data. That is the maths working, not the product working: no threshold here has met a real screen. Today a forgery still costs about twelve lines of Python; see AR-1.

### A capture can be positively corroborated as a real three-dimensional scene.
`rebroadcast-detection` · **UNEARNED** · greps for *"positively corroborated as a real"*

**Needs:**
- Flash-pair and parallax analysis — built.
- Thresholds calibrated against real devices and real displays, with a measured false-positive rate on ordinary flat subjects.
- The capture flow that produces the two frames and the two poses.

**Test:** test_rebroadcast.py — 18 cases including the flat wall, the blown-out frame, and pure rotation

Deliberately framed as an UPGRADE, never a detector. Both signals are strong positives and weak negatives: non-planar proves depth, but planar means screen OR flat wall OR a rotated capture. Construction is full of flat subjects, so a system that read planar as fraud would accuse honest contractors far more often than it caught anyone. assess() enforces that asymmetry and a test asserts it.

### A photo came off a camera sensor rather than a file picker.
`photo-came-from-a-camera` · **UNEARNED** · greps for *"came off a camera sensor"*

**Needs:**
- DONE — trust tiering and single-use capture challenges, attestation.py. Fails closed; an unverified or unbound attestation can never reach a trusted tier.
- The native app. App Attest and Play Integrity do not exist for a web page, and both Shield frontends are web pages, so every real upload today is tier 'unattested'.
- The cryptographic verification itself: CBOR plus an X.509 walk to Apple's App Attest root, and JWE decryption or a Google API call for Play Integrity. attestation.py takes an already-verified verdict and refuses to invent one.
- Rebroadcast detection (flash pair, parallax) to defeat the screen-replay path that attestation alone leaves open.
- C2PA capture-side credentials where the device supports them.

**Test:** test_attestation.py — 33 cases covering fail-closed verdicts, replayed and unbound tokens, repackaged apps, malformed payloads, and the empty-verdict attack signal

This is AR-1. The policy layer is built, hardened after an adversarial re-read found three holes in it (attacks 21-23), and the honest state of it is still that it has nothing to judge: with no native app, every capture is 'unattested', which the module treats as the expected case rather than a finding. Note also what a pass would NOT mean — Apple does not expose jailbreak state through App Attest, so 'attested' is a strong statement about the app and the silicon and a silent one about the OS. The claim may never be fully earnable; the honest endpoint is probably a stated cost of forgery, not a proof. If that is where it lands, change the claim rather than stretching the evidence to reach it.

### Shield is a C2PA Conforming Product.
`listed-conforming-product` · **UNEARNED** · greps for *"Conforming Product"*

**Needs:**
- Legal entity in good standing whose name matches registration exactly.
- C2PA conformance submission, legal onboarding, and product security architecture documentation.
- A Conformance Letter, then a Claim Signing Certificate from a CA on the C2PA Trust List.

**Test:** listing verifiable on the public Conforming Products List

The one claim here whose proof is somebody else's register rather than our own test suite — which is precisely why it is worth more than the others.

---

## Earned

### The custody history cannot be altered without detection, including by the operator.
`tamper-evident-custody` · earned 2026-09-14 · greps for *"cannot be altered without detection"*

**Needs:**
- Hash-linked custody entries with a published chain head.
- Append-only enforcement at the database level against UPDATE, DELETE and TRUNCATE.
- A chain head that has left the building, so a full rewrite is detectable rather than merely internally inconsistent.

**Test:** test_ledger.py — 21 tampering attacks, each caught at the correct entry index

Earned with one honest limit stated alongside it: a complete rewrite IS internally consistent. Detection depends on a holder comparing the head hash they were given.

### The evidence export can be verified by a recipient without trusting us.
`verifiable-without-trusting-us` · earned 2026-09-14 · greps for *"without trusting us"*

**Needs:**
- A manifest carrying every hash and its algorithm.
- Independent chain verification the recipient runs themselves.
- Published commands that require no access to our systems.

**Test:** test_evidence.py — manifest and verification instructions assert on what a recipient can check unaided

True for the chain and the hashes. It does NOT extend to the photograph's origin — see the unearned claim above.

### The checkpoint requirements provably predate the work being audited.
`requirements-predate-work` · earned 2026-09-14 · greps for *"provably predate"*

**Needs:**
- Checkpoints generated by the buyer, not the audited party.
- A one-way lock with the schedule hash written into the chain.

**Test:** test_shield.py — checkpoint locking; invariant checkpoints-locked

Predates the *upload*. It does not establish when the photo was taken, only that the criteria were fixed first.

### A photo's location is corroborated against a reference the audited party does not control.
`independently-corroborated-location` · earned 2026-09-14 · greps for *"does not control"*

**Needs:**
- A geofence measured against a site the buyer fixed at purchase.
- Solar geometry constraining the light for the claimed place and time.

**Test:** test_corroborate.py — solar position against geometric identities; test_shield.py — haversine geofence

Corroborates the *reported* position against the site. A contractor physically on site photographing a screen defeats it; that is what the flash-pair work is for.

### A field note's stated time is the time it was actually written.
`note-time-is-real` · earned 2026-09-14 · greps for *"actually written"*

**Needs:**
- written_at set server-side and never accepted from the client.
- Append-only notes; corrections are amendments, not edits.
- The delay between observation and writing carried into the export rather than hidden.

**Test:** test_notes.py — contemporaneity banding; invariants note-time-server-set and notes-append-only

The write time is ours. The *observation* time is the writer's assertion, and the export says so.

---
