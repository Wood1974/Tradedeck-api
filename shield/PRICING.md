# Price list

**Effective 18 September 2026.** Served as JSON at `GET /shield/public/pricing`
— no account, no token, no sales call. This page and that endpoint are
generated from the same table in `pricing.py`; an invariant fails the build if
they disagree.

| Tier | Job budget | Price |
|---|---|---|
| standard | $0 – $5,000 | **$79** |
| extended | $5,000.01 – $20,000 | **$129** |
| major | over $20,000 | **$199** |

One price per record, charged once, at purchase.

## The only thing the price depends on

Job budget. That is not a policy statement, it is the function signature:

```python
def quote(job_budget_cents):
    ...
```

There is nowhere to pass a verdict, a score, a coverage figure or a customer
id, so there is no mechanism by which a fee could vary with what a record says.
`price-independent-of-verdict` fails the build if a second parameter appears,
and `price-list-is-complete` sweeps the budget axis to confirm no price exists
that this page does not show.

## Why a price list is a credibility document

We are paid by the party whose records we seal. That is **issuer-pays** — the
arrangement that cost the rating agencies their credibility in 2008. It is
survivable on one condition, and `INDEPENDENCE.md` states it as the hard line:

> **What we charge must be identical whether the record is favourable or
> damning.** Flat per-record or per-seat pricing only.

That sentence is worth nothing while the price list is private, because nobody
outside can check it. A promise only an insider can audit is a promise on the
honour system, which is the arrangement the whole document exists to reject. So
the list is public, and so is the list of things we do not charge.

## Never charged, at any price

- A share of funds released, disputes avoided, or claims denied.
- Success fees, bonuses, or any pricing contingent on an outcome.
- Equity, options, board seats or advisory roles in a party we seal for.
- Discounts, terms or roadmap commitments traded for a favourable record.
- Any arrangement in which one customer's displeasure costs us more than the
  flat value of their contract — because that is a stake in the outcome whether
  or not it is written down as one.

A flat number is perfectly consistent with a side letter granting one customer
a success fee, so the numbers alone prove nothing. The prohibitions are
published with them for that reason.

## What this does not fix

Flat pricing removes the channel the 2008 failure travelled down — a fee that
moved with the verdict. It does not remove the conflict itself. A customer
whose records keep coming back damning can still cancel, and enough of those
would be quiet pressure to make the system more forgiving: not on any one
record, but in thresholds, defaults and the wording of a verdict. Nobody would
ever decide to do it, which is what makes it the realistic failure mode rather
than bribery.

The defence against that is not on this page. It is `audit/invariants.py`,
`claims.py`, and `GET /shield/public/results` — the last of which publishes how
often this system actually says no, including the numbers that cost us money.

## Changes

Every change to this table is a change to `pricing.py`'s `EFFECTIVE` date and
shows up in git history. There is no negotiated pricing to omit from it.

| Date | Change |
|---|---|
| 2026-09-18 | First published. Table itself unchanged since 2026-09-14. |
