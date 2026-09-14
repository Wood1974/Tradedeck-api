# shield/audit

Daily adversarial audit of Shield. Three parts:

| File | What it is |
|---|---|
| `PROTOCOL.md` | The brief the daily agent follows — run order, rotation, what counts as a finding, and when to stay silent |
| `invariants.py` | 29 tripwires, one per exploit we have closed. Run it; any `BROKEN` means a closed hole reopened |
| `accepted-risks.md` | Known limits, deliberately unfixed. The audit must not re-report these |
| `findings.jsonl` | Append-only ledger, so a finding is reported once and not every morning |

## Run it yourself

```bash
cd shield
python -m pytest tests/ -q      # 161 tests
python audit/invariants.py      # 29 invariants
python audit/invariants.py --json
```

Exit code is non-zero if any invariant is broken, so it drops into CI unchanged.

## The design decision that matters

**Silence is the expected output.** A daily report listing the same fifteen
issues every morning gets ignored within a week, which is worse than no audit at
all — it manufactures the feeling of being watched without the fact of it.

So the audit reports new findings and regressions only, and says one line on a
quiet day. `accepted-risks.md` exists for the same reason: without it, every run
rediscovers that EXIF is forgeable and nobody reads run sixteen.

## Adding an invariant

When a new exploit is found and fixed, add it to `INVARIANTS` in
`invariants.py`, naming the attack it prevents rather than the code it checks.
Then break the fix deliberately and confirm the invariant trips — an invariant
that cannot fail is decoration.
