# Attacks attempted against Shield

Every attack we know of, what happened, and what changed. Failures included —
an attack log that only lists wins is marketing.

Each closed attack has a named regression test **and** a permanent invariant in
`invariants.py`, so it cannot quietly reopen. The invariants are named for the
attack they prevent rather than the code they inspect.

**Read `accepted-risks.md` alongside this.** Some of these are not closed and
are not going to be, and that file says why.

| # | Attack | Outcome |
|---|---|---|
| 1 | Photograph 1 of 5 checkpoints and close out | **Worked, for $79.** Grading filtered unphotographed checkpoints out of the vote before deciding, so absent evidence could not produce a failure. Verdict "pass", score 20.0. Closed: missing evidence now outranks every verdict. |
| 2 | Close out the same job repeatedly to mint the verified badge | **Worked.** The badge counted rows, not distinct jobs. Closed: unique index plus distinct-job counting. |
| 3 | Stamp a stock photo with the site's coordinates using `piexif` | **Works today.** Returned `gps_corroborated: True`, distance 0.1 m, no integrity note. Twelve lines, using the same library Shield reads EXIF with. **Not closed** — see AR-1. Mitigated by a buyer-set geofence and solar geometry. Partly addressed by `rebroadcast.py`: a flash pair and two-pose parallax can now *positively* corroborate a real 3D scene, which a photographed screen cannot produce. Synthetic-calibrated only, and framed as an upgrade rather than a detector — see claim `rebroadcast-detection`. |
| 4 | Upload against a checkpoint belonging to another job | **Worked.** Landed `approved` on a stranger's record. Closed: `point_id` scoped to the job. |
| 5 | Race concurrent analyses to re-roll a verdict | **Worked.** 20 calls, 20 billed samples, last writer won. Closed: conditional write. |
| 6 | Regenerate checkpoints after seeing the verdicts | **Worked.** Closed: homeowner-only, one-way lock, schedule hash in the chain. |
| 7 | Activate a job without paying for it | **Worked.** Nothing bound a PaymentIntent to a job but its own metadata. Closed: stored intent, amount and currency asserted. |
| 8 | Read the evidence bucket as any signed-in user | **Worked.** The storage policy was permissive, so it could not deny and granted read on every other bucket too. Closed: `AS RESTRICTIVE`. |
| 9 | Erase custody history with `DROP TRIGGER` or `TRUNCATE` | **Worked silently.** Closed: hash-linked entries plus a statement-level truncate trigger. A rewrite is still possible and still detectable by anyone holding an old head hash. |
| 10 | Choose the IP recorded against your own upload | **Worked.** X-Forwarded-For was read leftmost. Closed: rightmost trusted hop. |
| 11 | Pass arbitrary bytes off as a photograph via Content-Type | **Worked.** A PDF labelled `image/jpeg` was hashed and stored; worse, the compressor's failure path handed the untouched original to the model. Closed: container magic decides the type, and no raw fallback. |
| 12 | Kill the worker with a 77 KB decompression bomb | **Worked.** 309 MB of RSS, no error raised; the byte limit never saw it. Closed: dimensions read from the header before decode. |
| 13 | Submit a downloaded or screenshotted JPEG | **Worked.** `exif_status` could never be `"absent"` for a JPEG, so the screenshot signal was dead in the format most cameras produce. Found by re-running attack 3 against rewritten code. Closed. |
| 14 | Land 3,400 km outside the buyer's geofence unflagged | **Worked.** A note was written; no `integrity_flag` was raised, so nothing scanning the chain would see it. Closed: every note condition raises the flag. |
| 15 | Bury a failed checkpoint photo behind a retake | **Blocked by accident, broken in both directions.** Retakes were impossible (the index rejected them, the API said "please retry"), and close-out and the export disagreed about which photo was evidence. Closed: one selector, retakes recorded and disclosed. |
| 16 | Ship a claim the product has not earned | **Possible until now.** Closed: `CLAIMS.md` plus an invariant that fails the build if an unearned claim appears in published text, unless it is being denied. |
| 17 | Hand a recipient a package whose integrity they cannot check | **Worked.** The export carried only a summary of the chain — count, head hash, and our own `chain_intact: true`. A recipient had to believe us. Found while writing `SPEC.md`. Closed: raw entries are exported and `verifier/shield_verify.py` recomputes them. |
| 18 | Truncate the custody chain to drop the last few entries | **Works, and always will.** A chain shortened at the end verifies perfectly; the package's own head claim is updated by whoever truncated it. Found by `audit/fuzz.py` in under a minute. **Not closed** — see AR-8. Mitigated by `--expect-head`: a head the recipient obtained earlier detects it. |

## On the tripwires themselves

Every invariant above was verified by deliberately breaking the guard it
protects and confirming it, and only it, fired.

**Four of them passed that test only after being rewritten to read the AST
instead of the source text.** Commenting a guard out leaves its name in the
file, so a text match kept passing while the guard no longer ran — which is
precisely the refactor these exist to catch. One flagged its own docstring,
because the docstring named the old behaviour it replaced.

The remaining text-matching invariants have not been audited that way yet.
