# Independence policy

**Adopted 14 September 2026.** This page is dated, public, and written before
anyone has offered money to break it — which is the only time a policy like
this is worth anything.

A record is worth what the neutrality of whoever sealed it is worth. Moody's
and S&P were credible for decades on investor-pays and lost it on issuer-pays;
Underwriters Laboratories was funded by the insurers carrying the risk, not by
the manufacturers it tested. That difference is the whole business, so it is
written down rather than assumed.

## The commitments

1. **Our fee never varies with what a record says.** *(Amended 15 September
   2026 — see Amendments. The original text forbade payment from a sealed
   party outright.)*

   The strongest arrangement is still the one we prefer and will take whenever
   we can get it: **paid only by the party who bears the risk of a record
   being wrong** — the lender, the insurer, the buyer. That is the
   Underwriters Laboratories position and it is the one worth defending.

   Where we are paid by a party whose own records we seal, that is
   **issuer-pays**, the arrangement that cost the rating agencies their
   credibility in 2008. It is survivable on exactly one condition, and this
   is the hard line:

   > **What we charge must be identical whether the record is favourable or
   > damning.** Flat per-record or per-seat pricing only.

   Specifically prohibited, at any price:

   - a share of funds released, disputes avoided, or claims denied
   - success fees, bonuses, or any pricing contingent on an outcome
   - equity, options, board seats or advisory roles in a party we seal for
   - discounts, terms or roadmap commitments traded for a favourable record
   - any arrangement in which one customer's displeasure costs us more than
     the flat value of their contract — because that is a stake in the
     outcome whether or not it is written down as one

   The test is not whether we would bend. It is whether a stranger
   reconstructing our incentives from our price list could see a reason we
   might. If they can, the record is worth less and so is the company.

   **That test requires a stranger to be able to read the price list**, so as
   of 18 September 2026 it is published: `PRICING.md`, and `GET
   /shield/public/pricing` for anyone who would rather not take a document's
   word for it. The guarantee is structural — `pricing.quote()` takes a job
   budget and nothing else, so there is no input through which a fee could
   vary with a verdict — and three invariants fail the build if that changes:
   a second parameter appears, a chargeable price goes missing from the
   published list, or either public route acquires a login.

   We do not change a sealed record at any party's request regardless of who
   pays — see commitment 2.

2. **We do not change a record's contents at any party's request.** Corrections
   are appended and disclosed. Nothing is removed. A retake supersedes; it does
   not erase.

3. **We publish our method, our known limits, and every attack we are aware
   of** — including attacks that succeeded. See `SPEC.md`,
   `audit/accepted-risks.md`, and `audit/ATTACKS.md`.

4. **We state plainly what our records do not establish.** We will not describe
   a record as proving something it does not prove, in any material, at any
   price. `audit/CLAIMS.md` lists what we have earned the right to say, and an
   invariant fails the build if an unearned claim reaches published text.

5. **We publish how often we say no.** `GET /shield/public/results` serves the
   outcome distribution — every verdict category, including the ones that cost
   us money, counting retaken photographs rather than quietly dropping them
   with the failures they contain. No account is needed to read it.

   Two things about that endpoint matter more than the numbers in it. It
   **withholds percentages below thirty closed jobs**, because a rate over a
   handful of jobs moves by tens of points on a single outcome and "100% pass
   rate" is the first thing a small sample is good for. And it **states in the
   payload that these are our own unaudited numbers about our own product** —
   a disclosure, not an attestation. Both are enforced by invariants, because
   both are the kind of restraint that erodes the week someone needs a figure
   for a deck.

6. **If we ever break one of these commitments, the fact and the date will
   appear on this page.**

## Why the last one matters most

A policy with no failure disclosure is marketing. A policy that promises to
publish its own violations is a commitment — and the day we publish a violation
honestly is worth more than the years we did not have one.

## Amendments

A policy that is silently rewritten when money appears is marketing. Every
change to the commitments above is recorded here, dated, with what it cost.

**15 September 2026 — commitment 1 weakened.** The original read: *"We are
paid only by parties who bear the risk of a record being wrong. We do not
accept payment, equity, revenue share, board seats, or any other
consideration from a party whose records we seal, or from anyone acting on
their behalf."*

That wording forbids selling API access to the party whose records we seal —
which is the business model under consideration. Rather than leave a policy
we were quietly planning to break, it is amended in the open.

**This is the weaker position, and the weakening is real.** Investor-pays
removes the conflict; issuer-pays only constrains it. What replaces it is a
narrower promise that can actually be kept and audited from the outside: the
fee is flat, so it cannot move with the verdict. Whether that is enough is
decided by whether we hold it under pressure, not by this paragraph.

No such contract exists yet. This is written before the first one, which is
the only time writing it is worth anything.

## Violations

None recorded.
