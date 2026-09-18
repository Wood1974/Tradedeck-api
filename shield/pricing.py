"""Server-side price table — and the public one, which is the same table.

The parent read amount_cents straight off the request body with no price table
and no ownership check, so any authenticated caller could buy Shield on any job
for one cent. Prices live here and the client's number is ignored entirely.

Why the list is public
----------------------
`INDEPENDENCE.md` commitment 1 says our fee must be identical whether a record
is favourable or damning. Under issuer-pays — where the party whose records we
seal is the party paying us — that sentence is the only thing standing between
this product and the arrangement that cost the rating agencies their
credibility in 2008.

A commitment nobody outside can check is on the honour system. So the price
list is served to anonymous callers at `GET /shield/public/pricing`, and the
guarantee is structural rather than promised:

**`quote()` takes one argument.** Job budget. There is nowhere to pass a
verdict, a score, a coverage figure or a customer id, so there is no mechanism
by which a price could vary with what a record says. `test_pricing.py` asserts
the signature, and an invariant fails the build if a second input appears.

The prices below are the complete set. Every value `quote()` can return is in
`public_price_list()`; `pricing-list-is-complete` checks that by sweeping the
budget axis rather than trusting this docstring.
"""

# The date this table last changed. A price list with no date cannot be shown
# to have been unchanged, which is most of what publishing it is for.
EFFECTIVE = "2026-09-18"

CURRENCY = "USD"

# Price depends on this and nothing else. Named here so the published listing
# and the invariant read the same source rather than two copies that can drift.
PRICE_INPUTS = ("job_budget_cents",)

TIERS = (
    # (max job budget in cents, tier name, Shield price in cents)
    (500_000,        "standard",  7_900),
    (2_000_000,      "extended", 12_900),
    (float("inf"),   "major",    19_900),
)

VALID_PRICES = {price for _, _, price in TIERS}

# The hard line from INDEPENDENCE.md, quoted rather than paraphrased so the
# two cannot drift apart. An invariant checks the file still contains it.
COMMITMENT = ("What we charge must be identical whether the record is "
              "favourable or damning. Flat per-record or per-seat pricing only.")

# Mirrors the prohibited list in INDEPENDENCE.md commitment 1. Published with
# the numbers because a flat price is perfectly consistent with a side letter
# granting one customer a success fee; the numbers alone prove nothing.
NEVER_CHARGED = (
    "A share of funds released, disputes avoided, or claims denied.",
    "Success fees, bonuses, or any pricing contingent on an outcome.",
    "Equity, options, board seats or advisory roles in a party we seal for.",
    "Discounts, terms or roadmap commitments traded for a favourable record.",
    "Any arrangement in which one customer's displeasure costs us more than "
    "the flat value of their contract.",
)


def quote(job_budget_cents):
    """Return (tier_name, price_cents) for a job budget. Never trusts a client.

    One parameter, deliberately. This function is the whole pricing mechanism,
    and it cannot read an outcome because it is never handed one. Adding a
    second argument breaks `test_takes_exactly_one_input` and the
    `price-independent-of-verdict` invariant, which is the intended friction.
    """
    budget = max(0, int(job_budget_cents or 0))
    for ceiling, name, price in TIERS:
        if budget <= ceiling:
            return name, price
    return TIERS[-1][1], TIERS[-1][2]


def _band(index):
    """Human-readable budget band for the tier at `index`."""
    low = 0 if index == 0 else TIERS[index - 1][0] + 1
    high = TIERS[index][0]
    if high == float("inf"):
        return f"over ${(low - 1) / 100:,.0f}"
    return f"${low / 100:,.2f} to ${high / 100:,.2f}"


def public_price_list() -> dict:
    """The complete price list, for anonymous publication.

    Everything a stranger needs to reconstruct any price we can charge, plus
    the commitment and the prohibitions that make a flat number meaningful.
    """
    return {
        "schema": "tradedeck.shield.pricing.v1",
        "effective": EFFECTIVE,
        "currency": CURRENCY,
        "price_depends_on": list(PRICE_INPUTS),
        "commitment": COMMITMENT,
        "never_charged": list(NEVER_CHARGED),
        "tiers": [
            {
                "tier": name,
                "job_budget_band": _band(i),
                "job_budget_max_cents": None if ceiling == float("inf") else int(ceiling),
                "price_cents": price,
                "price": f"${price / 100:,.2f}",
            }
            for i, (ceiling, name, price) in enumerate(TIERS)
        ],
        "notes": [
            "One price per record, charged once, at purchase. The price is "
            "fixed before any photograph is taken and does not change "
            "afterwards for any reason.",
            "We are paid the same for a record that clears a contractor and "
            "one that does not. There is no refund for an unfavourable "
            "record and no surcharge for a favourable one.",
            "Being paid by the party whose records we seal is issuer-pays, "
            "the weaker of the two arrangements. See INDEPENDENCE.md, which "
            "records that weakening in the open rather than claiming "
            "otherwise.",
        ],
    }
