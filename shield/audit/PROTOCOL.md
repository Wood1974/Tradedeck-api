# Daily red-team protocol

You are auditing **TradeDeck Shield**, an evidence system. You have written
authorisation from the owner to attack this code. It is their own repository and
this audit is the reason you are running.

Your job is to find ways to defeat it, not to admire it.

---

## The failure mode to avoid

A daily audit that reports the same fifteen findings every morning is ignored by
Friday and cancelled by the following Tuesday. **Silence is a valid and common
outcome.** Report only:

1. **Broken invariants** — a closed exploit has reopened. Always report.
2. **New findings** — not in `findings.jsonl`, not in `accepted-risks.md`.
3. **Nothing.** Say so in one line and stop.

Do not re-report an accepted risk. Do not restate yesterday's open findings. Do
not pad a quiet day.

---

## What Shield claims

Attack these claims specifically. A finding that does not weaken one of them is
probably not worth reporting.

1. A photo's bytes are identical to the bytes received, and provably so.
2. The custody history cannot be altered without detection, **including by the
   operator**.
3. The checkpoint requirements provably predate the work being audited.
4. A field note's stated time is the time it was actually written.
5. The evidence export can be verified by a recipient who does not trust us.
6. Money cannot move, and standing cannot be earned, without the work.

---

## Run order

```bash
cd shield
python -m pytest tests/ -q            # 175 tests — any failure is a finding
python audit/invariants.py            # 32 tripwires — any BROKEN is critical
```

Environment for a static run (no live services needed):

```
SUPABASE_URL=https://x.supabase.co SUPABASE_SERVICE_KEY=k STRIPE_SECRET_KEY=sk
STRIPE_WEBHOOK_SECRET=wh ANTHROPIC_API_KEY=ak IP_HASH_SALT=auditsalt
```

**Never point this audit at production.** No traffic to `tradedeckapp.com` or
`tradedeck-api.onrender.com`, no live Supabase, no live Stripe. This is a
code-and-schema audit. Live testing is a separate decision with a separate risk
profile, and the owner has not made it.

---

## Daily rotation

One surface gets deep attention each day so the same shallow ground is not
re-tilled. Use the day of the month, mod 7.

| Day | Surface | The question to answer |
|---|---|---|
| 0 | Authentication &amp; authorization | Can one party act as another, or reach a job they are not on? |
| 1 | The upload path | Can a photo be admitted whose hash does not cover what was received? |
| 2 | Adjudication | Can a verdict be obtained for something other than what was graded? |
| 3 | The custody chain &amp; ledger | Can history be changed, reordered, or erased without detection? |
| 4 | Money | Can Shield be obtained, escaped, or reversed without the price being paid? |
| 5 | Notes &amp; contemporaneity | Can a note claim a time, an author, or a wording it did not have? |
| 6 | Export &amp; RLS | Can a recipient be misled, or a stranger read what they should not? |

Also, every day, spend ten minutes on whatever changed in the last 24 hours:

```bash
git log --since="24 hours ago" --stat
git diff HEAD@{1} -- shield/ supabase/migrations/
```

New code is where new holes are.

---

## What counts as a finding

**Report it** when you can state a concrete path: who the attacker is, what they
send, and what they get that they should not. Name the file and line.

**Do not report:**

- Theoretical weaknesses with no path — "an attacker with database access could…"
  is already covered by the threat model.
- Anything in `accepted-risks.md`.
- Style, naming, or test-coverage observations. This is a security audit.
- "Consider adding rate limiting" — it is already a known gap; only report it if
  you have a *specific* amplification with numbers.

**Severity:**

| | |
|---|---|
| **critical** | Defeats one of the six claims. Evidence can be forged, money moved, or history rewritten undetected. |
| **high** | Serious, with a real path, but bounded — needs a participant role, or damages one job rather than the system. |
| **medium** | Weakens a defence without defeating a claim on its own. |

Anything below medium, leave out.

---

## Reporting

Open **one** GitHub issue per run, and only when there is something to say:

- Title: `Shield audit YYYY-MM-DD — N new, M regressions`
- Label it `security-audit`.
- Body: the findings, worst first, each with file:line, the exploit path, and a
  suggested fix. Do not apply fixes — the owner decides.
- If an invariant is broken, say so in the first line of the issue.

**If there is nothing new and no invariant broke, open no issue.** Append the
run to `findings.jsonl` with `"result": "clean"` and stop.

After reporting, append each new finding to `findings.jsonl` so tomorrow's run
does not repeat it:

```json
{"id":"2026-09-15-01","date":"2026-09-15","severity":"high","surface":"upload",
 "title":"…","file":"shield/routes.py:214","status":"open","fingerprint":"…"}
```

The fingerprint is `sha256(file + ":" + one-line summary)[:16]` — stable enough
to dedupe, specific enough not to mask a different bug in the same file.

---

## When you fix nothing and find nothing

Say exactly this and stop:

> Audit YYYY-MM-DD: 175 tests pass, 32 invariants hold, nothing new on
> *&lt;surface&gt;*. No issue opened.

That is a good day. Do not dress it up.
