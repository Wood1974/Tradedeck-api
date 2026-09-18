"""The claims ledger, and the gate that makes it more than a diary.

A ledger nobody checks is a diary. The tests that matter here are not the ones
proving the data structure is well-formed — they are the ones proving the gate
catches an overclaim and lets an honest denial through, because that
distinction is the entire mechanism.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import claims  # noqa: E402

SHIELD = os.path.join(os.path.dirname(__file__), "..")


# ------------------------------------------------------------ the ledger ---
def test_every_claim_is_complete():
    for c in claims.CLAIMS:
        for field in ("id", "claim", "phrase", "needs", "test", "note"):
            assert c.get(field), f"{c.get('id')} is missing {field}"
        assert "earned" in c, f"{c['id']} has no earned field"
        assert c["phrase"].lower() in c["claim"].lower(), \
            f"{c['id']}: the grep phrase must actually occur in the claim"


def test_ids_are_unique():
    ids = [c["id"] for c in claims.CLAIMS]
    assert len(ids) == len(set(ids))


def test_earned_and_unearned_partition_the_ledger():
    assert len(claims.earned()) + len(claims.unearned()) == len(claims.CLAIMS)
    assert all(c["earned"] for c in claims.earned())
    assert not any(c["earned"] for c in claims.unearned())


def test_the_slogan_is_not_earned_yet():
    """The claim this whole file was built for.

    Forging a Shield record currently costs about twelve lines of Python. Until
    the rebroadcast work ships, this sentence is false, and the gate exists to
    stop it reaching a customer.
    """
    slogan = claims.by_id("cheapest-to-do-the-work")
    assert slogan is not None
    assert slogan["earned"] is None
    assert slogan in claims.unearned()


def test_every_earned_claim_names_a_test_that_exists():
    for c in claims.earned():
        named = re.findall(r"(test_\w+\.py)", c["test"])
        assert named, f"{c['id']} is earned but cites no test file"
        for t in named:
            assert os.path.exists(os.path.join(SHIELD, "tests", t)), \
                f"{c['id']} cites {t}, which does not exist"


# ------------------------------------------------------------- the gate ---
def _gate(text):
    """Run the published-text gate over one string. True = would fail."""
    sys.path.insert(0, os.path.join(SHIELD, "audit"))
    import invariants
    for c in claims.unearned():
        phrase = c["phrase"].lower()
        i = text.lower().find(phrase)
        while i != -1:
            window = invariants._negation_window(text, i)
            if not any(n in window.lower() for n in invariants.NEGATORS):
                return True
            i = text.lower().find(phrase, i + 1)
    return False


def test_gate_catches_a_bare_overclaim():
    assert _gate("The cheapest way to pass is to do the work."), \
        "an unearned slogan asserted outright must be caught"


def test_gate_catches_it_in_marketing_voice():
    assert _gate("With Shield, the cheapest way to pass is simply to do the "
                 "work — every time.")


def test_gate_allows_an_honest_denial():
    assert not _gate("Shield cannot prove a photo came off a camera sensor "
                     "rather than a file picker.")
    assert not _gate("Nothing here establishes that a photo came off a camera "
                     "sensor.")


def test_gate_allows_a_bullet_that_inherits_its_negation():
    """The case our own README hit, and the reason the window widened.

    Markdown list items inherit context from the line that introduces them. A
    window stopping at the newline reads an honest disclaimer as an assertion.
    """
    assert not _gate(
        "**Not proven, and we say so in the certification:**\n"
        "- That any photo came off a camera sensor rather than a file picker.\n")


def test_gate_still_fails_a_bullet_under_an_affirmative_heading():
    """Widening the window must not have made the gate toothless."""
    assert _gate(
        "**What Shield proves:**\n"
        "- That a photo came off a camera sensor rather than a file picker.\n")


def test_earned_claims_are_not_gated():
    """An earned claim may be stated plainly — that is the point of earning it."""
    assert not _gate("The custody history cannot be altered without detection.")
    assert not _gate("Verify this package without trusting us.")


# ------------------------------------------------------- the rendered md ---
def test_markdown_lists_unearned_first_and_marks_them():
    md = claims.render_markdown()
    assert "Unearned — do not publish" in md
    assert md.index("Unearned") < md.index("## Earned"), \
        "the unearned section must come first — it is the one that gates work"
    for c in claims.unearned():
        assert c["claim"] in md
        assert "**UNEARNED**" in md


def test_markdown_is_deterministic():
    assert claims.render_markdown() == claims.render_markdown()


def test_generated_file_matches_the_source():
    """Regenerate with `python claims.py` when this fails."""
    path = os.path.join(SHIELD, "audit", "CLAIMS.md")
    assert os.path.exists(path)
    with open(path) as fh:
        assert fh.read() == claims.render_markdown(), \
            "audit/CLAIMS.md has drifted from claims.py — regenerate it"
