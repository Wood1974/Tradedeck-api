"""Server-side price table.

The parent read amount_cents straight off the request body with no price table
and no ownership check, so any authenticated caller could buy Shield on any job
for one cent. Prices live here and the client's number is ignored entirely.
"""
TIERS = (
    # (max job budget in cents, tier name, Shield price in cents)
    (500_000,        "standard",  7_900),
    (2_000_000,      "extended", 12_900),
    (float("inf"),   "major",    19_900),
)

VALID_PRICES = {price for _, _, price in TIERS}


def quote(job_budget_cents):
    """Return (tier_name, price_cents) for a job budget. Never trusts a client."""
    budget = max(0, int(job_budget_cents or 0))
    for ceiling, name, price in TIERS:
        if budget <= ceiling:
            return name, price
    return TIERS[-1][1], TIERS[-1][2]
