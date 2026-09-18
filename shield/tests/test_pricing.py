"""The price list is public, and no price depends on what a record says.

Why this file exists
--------------------
`INDEPENDENCE.md` commitment 1 says our fee must be identical whether a record
is favourable or damning. That commitment is worth exactly nothing while the
price list is private, because nobody outside can check it. A promise only an
insider can audit is a promise on the honour system, which is the arrangement
the whole document exists to reject.

So these tests assert two things that together make the commitment checkable by
a stranger:

1. **Every price we can charge is published.** Not "the prices we advertise" —
   every value `quote()` is capable of returning. A price that exists and is
   not on the public list is a secret price, and a secret price is where an
   outcome-contingent fee would live.

2. **Price is a function of one input.** Job budget. Not verdict, not score,
   not coverage, not whether the contractor disputed the result. The proof is
   structural rather than behavioural: `quote()` cannot read a verdict because
   it is never given one.
"""
import pytest

import pricing


class TestQuote:
    def test_budget_selects_the_tier(self):
        assert pricing.quote(100_000) == ("standard", 7_900)
        assert pricing.quote(1_000_000) == ("extended", 12_900)
        assert pricing.quote(9_000_000) == ("major", 19_900)

    def test_boundaries_fall_to_the_cheaper_tier(self):
        assert pricing.quote(500_000)[0] == "standard"
        assert pricing.quote(500_001)[0] == "extended"
        assert pricing.quote(2_000_000)[0] == "extended"
        assert pricing.quote(2_000_001)[0] == "major"

    @pytest.mark.parametrize("junk", [None, 0, "", -1, -999_999])
    def test_absent_or_negative_budgets_fall_to_the_lowest_tier(self, junk):
        """A bad number must not become a discount below the published floor.

        The parent app read amount_cents straight off the request body. Here an
        unusable budget lands on the cheapest *published* tier — never below
        it, and never at zero.
        """
        _, price = pricing.quote(junk)
        assert price in pricing.VALID_PRICES
        assert price == min(pricing.VALID_PRICES)

    @pytest.mark.parametrize("junk", ["abc", "1e5", object()])
    def test_unparseable_budgets_raise_rather_than_guess(self, junk):
        """Refusing is safer than picking a tier from a value we cannot read."""
        with pytest.raises((ValueError, TypeError)):
            pricing.quote(junk)

    def test_takes_exactly_one_input(self):
        """The neutrality proof, stated as a signature.

        `quote` cannot price on a verdict because there is nowhere to pass one.
        If a second parameter is ever added, this fails and whoever added it has
        to say what it is for.
        """
        import inspect
        params = list(inspect.signature(pricing.quote).parameters)
        assert params == ["job_budget_cents"], (
            f"quote() now reads {params}. Price must depend on job budget and "
            f"nothing else — see INDEPENDENCE.md commitment 1."
        )


class TestPublicPriceList:
    def test_every_chargeable_price_is_published(self):
        """No secret prices.

        Sweep the budget axis across and past every tier boundary and assert
        each resulting price appears in the published list. A price reachable
        by some budget but absent from the list would be one nobody outside
        could audit.
        """
        published = {t["price_cents"] for t in pricing.public_price_list()["tiers"]}
        probes = [0, 1, 499_999, 500_000, 500_001, 1_999_999, 2_000_000,
                  2_000_001, 10_000_000, 10**12]
        reachable = {pricing.quote(b)[1] for b in probes}
        assert reachable == published == pricing.VALID_PRICES

    def test_declares_its_only_input(self):
        listing = pricing.public_price_list()
        assert listing["price_depends_on"] == ["job_budget_cents"]

    def test_names_what_is_prohibited(self):
        """The list carries the prohibitions, not just the numbers.

        A price list showing flat numbers is consistent with a side letter
        giving one customer a success fee. Publishing the prohibited
        arrangements alongside the numbers is what makes the flat number mean
        something.
        """
        text = " ".join(pricing.public_price_list()["never_charged"]).lower()
        for forbidden in ("success fee", "share of", "equity", "contingent"):
            assert forbidden in text

    def test_states_the_neutrality_commitment_verbatim(self):
        listing = pricing.public_price_list()
        assert ("identical whether the record is favourable or damning"
                in listing["commitment"])

    def test_is_json_serialisable(self):
        """It is served to anonymous callers; it must survive the encoder."""
        import json
        json.loads(json.dumps(pricing.public_price_list()))

    def test_carries_an_effective_date(self):
        """A price list with no date cannot be shown to have been unchanged."""
        assert pricing.public_price_list()["effective"]


class TestNeutralityIsStructural:
    def test_module_never_mentions_an_outcome(self):
        """Read the source: nothing in here knows what a verdict is.

        A text check is weak on its own, which is why the signature test above
        carries the real weight. This catches the other direction — a helper
        added later that looks up a score to adjust a price.
        """
        import inspect
        src = inspect.getsource(pricing).lower()
        # 'pass'/'fail' are too common in English to grep for; these are the
        # identifiers the grading system actually uses.
        for name in ("ai_verdict", "overall_verdict", "completion_score",
                     "coverage_pct", "counts_toward_badge", "grade("):
            assert name not in src, f"pricing.py reads {name}"

    def test_same_budget_always_yields_the_same_price(self):
        """No hidden state, no per-customer drift, no time-of-day pricing."""
        first = [pricing.quote(b) for b in (10_000, 700_000, 5_000_000)]
        for _ in range(50):
            assert [pricing.quote(b) for b in (10_000, 700_000, 5_000_000)] == first
