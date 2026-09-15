"""Does the attestation layer hold the line where it matters?

Three properties are load-bearing, and each has a test that fails loudly if
somebody later "simplifies" it away:

  1. Unverified input can never reach a trusted tier. The realistic bug here is
     not a missing check, it is a truthy one — `{"verified": "false"}` passing
     an `if verdict["verified"]`.
  2. An empty Play Integrity verdict is the attack signal. The intuitive rule
     (block MEETS_VIRTUAL_INTEGRITY) blocks the wrong population entirely.
  3. The module labels and never blocks. A blocked capture is less evidence
     than a labelled one.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import attestation  # noqa: E402


def payload(*labels, app=None, nonce="capture-nonce", package=None):
    """A Play Integrity payload shaped like a real one.

    The first version of these tests built only the deviceIntegrity half and
    never carried a nonce. That is precisely why the appIntegrity hole and the
    unenforced challenge binding survived a full green suite: every test
    reached the code through the same incomplete happy path.
    """
    out = {"deviceIntegrity": {"deviceRecognitionVerdict": list(labels)},
           "appIntegrity": {
               "appRecognitionVerdict": app or attestation.PLAY_RECOGNIZED,
               "packageName": package or "com.tradedeck.shield"}}
    if nonce is not None:
        out["requestDetails"] = {"requestHash": attestation.challenge_hash(nonce)}
    return out


def read(*labels, **kw):
    nonce = kw.pop("nonce", "capture-nonce")
    return attestation.interpret_play_integrity(
        payload(*labels, nonce=nonce, **kw), verified=True,
        expect_nonce="capture-nonce")



# ------------------------------------------------------------- challenges ---
def test_a_challenge_is_single_use():
    """A replay inside the TTL must fail exactly like one after it."""
    store = attestation.ChallengeStore()
    nonce = store.issue("contractor-1")
    assert store.consume(nonce, "contractor-1") is True
    assert store.consume(nonce, "contractor-1") is False


def test_a_challenge_belongs_to_the_actor_it_was_issued_to():
    """Otherwise one party's challenge is answered by another party's device."""
    store = attestation.ChallengeStore()
    nonce = store.issue("contractor-1")
    assert store.consume(nonce, "contractor-2") is False


def test_a_challenge_expires():
    clock = {"t": 1000.0}
    store = attestation.ChallengeStore(ttl_s=120, clock=lambda: clock["t"])
    nonce = store.issue("contractor-1")
    clock["t"] += 121
    assert store.consume(nonce, "contractor-1") is False


def test_an_unknown_or_empty_nonce_is_refused():
    store = attestation.ChallengeStore()
    assert store.consume("never-issued", "contractor-1") is False
    assert store.consume("", "contractor-1") is False
    assert store.consume(None, "contractor-1") is False


def test_purge_drops_only_the_expired():
    clock = {"t": 1000.0}
    store = attestation.ChallengeStore(ttl_s=100, clock=lambda: clock["t"])
    old = store.issue("c1")
    clock["t"] += 101
    fresh = store.issue("c1")
    assert store.purge() == 1
    assert len(store) == 1
    assert store.consume(old, "c1") is False
    assert store.consume(fresh, "c1") is True


def test_the_nonce_is_hashed_before_it_enters_a_token():
    a = attestation.challenge_hash("abc")
    assert a == attestation.challenge_hash("abc")
    assert a != attestation.challenge_hash("abd")
    assert len(a) == 64


# ------------------------------------------------------------ fail closed ---
def test_unverified_play_integrity_cannot_reach_a_tier_it_claims():
    """The payload asserts the strongest label. It was never checked."""
    payload = {"deviceIntegrity": {"deviceRecognitionVerdict":
                                   [attestation.STRONG_INTEGRITY]}}
    out = attestation.interpret_play_integrity(payload, verified=False)
    assert out["tier"] == attestation.TIER_UNVERIFIABLE
    assert out["trusted"] is False


def test_a_truthy_verified_flag_is_not_a_verified_flag():
    """The fail-open bug this shape of check exists to prevent.

    "false" is a non-empty string and therefore truthy. So is "unverified", and
    so is 1. Only the boolean True may pass.
    """
    payload = {"deviceIntegrity": {"deviceRecognitionVerdict":
                                   [attestation.STRONG_INTEGRITY]}}
    for impostor in ("false", "unverified", 1, [1], {"ok": 1}):
        out = attestation.interpret_play_integrity(payload, verified=impostor)
        assert out["tier"] == attestation.TIER_UNVERIFIABLE, impostor
        assert out["trusted"] is False, impostor


def test_unverified_app_attest_cannot_reach_a_tier():
    out = attestation.interpret_app_attest(verified=False)
    assert out["tier"] == attestation.TIER_UNVERIFIABLE
    assert out["trusted"] is False


def test_a_malformed_payload_is_unverifiable_not_failed():
    """We could not read it. That is not the device failing a check."""
    for junk in (None, "MEETS_STRONG_INTEGRITY", 42, []):
        out = attestation.interpret_play_integrity(junk, verified=True)
        assert out["tier"] == attestation.TIER_UNVERIFIABLE, junk


# -------------------------------------------------- the label that matters ---
def test_an_empty_verdict_is_the_attack_signal():
    """Google documents empty as rooted / hooked / unrecognised emulator.

    This is the case the intuitive design misses entirely. Note it must be an
    otherwise READABLE payload: a token with no deviceIntegrity block at all is
    unverifiable, not a device that failed, and the module keeps those apart.
    """
    out = read()                                   # readable, zero labels
    assert out["tier"] == attestation.TIER_FAILED
    assert out["trusted"] is False

    for unreadable in ({"deviceIntegrity": {}}, {}):
        r = attestation.interpret_play_integrity(unreadable, verified=True,
                                                 expect_nonce="capture-nonce")
        assert r["tier"] == attestation.TIER_UNVERIFIABLE, unreadable


def test_a_recognised_emulator_is_not_an_attacker():
    """MEETS_VIRTUAL_INTEGRITY is Google Play Games for PC, not a spoofer.

    It still cannot be a capture device, so it is untrusted — but it must not
    be recorded as an integrity failure, because it is not one.
    """
    out = read(attestation.VIRTUAL_INTEGRITY)
    assert out["tier"] == attestation.TIER_EMULATOR
    assert out["tier"] != attestation.TIER_FAILED
    assert out["trusted"] is False


def test_the_strength_ladder():
    def tier(*labels):
        return read(*labels)["tier"]

    assert tier(attestation.STRONG_INTEGRITY,
                attestation.DEVICE_INTEGRITY) == attestation.TIER_HARDWARE
    assert tier(attestation.DEVICE_INTEGRITY) == attestation.TIER_DEVICE
    assert tier(attestation.BASIC_INTEGRITY) == attestation.TIER_BASIC_ONLY
    assert tier("SOMETHING_NEW") == attestation.TIER_BASIC_ONLY


def test_only_certified_device_labels_are_trusted():
    assert attestation.TRUSTED_TIERS == (attestation.TIER_HARDWARE,
                                         attestation.TIER_DEVICE)
    for tier in (attestation.TIER_BASIC_ONLY, attestation.TIER_EMULATOR,
                 attestation.TIER_UNATTESTED, attestation.TIER_UNVERIFIABLE,
                 attestation.TIER_FAILED):
        assert tier not in attestation.TRUSTED_TIERS


def test_app_attest_passes_but_does_not_claim_jailbreak_detection():
    """Apple does not expose jailbreak state. Saying otherwise is an overclaim."""
    out = attestation.interpret_app_attest(verified=True)
    assert out["tier"] == attestation.TIER_HARDWARE
    assert "jailbreak" in out["reason"].lower()
    assert "not jailbroken" not in out["reason"].lower()


def test_app_attest_rejection_is_a_failure_not_an_unknown():
    out = attestation.interpret_app_attest(verified=True, receipt_ok=False)
    assert out["tier"] == attestation.TIER_FAILED


# ---------------------------------------------------------------- assess ----
def _hardware():
    return read(attestation.STRONG_INTEGRITY)


def test_assess_never_blocks_a_capture():
    """The product-critical property. A blocked capture is no evidence at all."""
    cases = [
        attestation.assess(),
        attestation.assess("android", _hardware(), challenge_ok=True),
        attestation.assess("android", attestation.interpret_play_integrity(
            {"deviceIntegrity": {"deviceRecognitionVerdict": []}},
            verified=True), challenge_ok=True),
        attestation.assess("ios", attestation.interpret_app_attest(verified=False)),
    ]
    for out in cases:
        assert out["capture_allowed"] is True, out


def test_an_unbound_attestation_is_not_trusted():
    """Without a single-use challenge it proves a device, not this photograph."""
    for challenge in (None, False):
        out = attestation.assess("android", _hardware(), challenge_ok=challenge)
        assert out["trusted"] is False, challenge
        assert out["tier"] == attestation.TIER_UNVERIFIABLE
        assert out["challenge_bound"] is False


def test_a_bound_attestation_is_trusted():
    out = attestation.assess("android", _hardware(), challenge_ok=True)
    assert out["trusted"] is True
    assert out["tier"] == attestation.TIER_HARDWARE
    assert out["challenge_bound"] is True


def test_no_attestation_is_the_honest_default_not_a_finding():
    """Every web upload lands here. It must not read as an accusation."""
    out = attestation.assess()
    assert out["tier"] == attestation.TIER_UNATTESTED
    assert out["trusted"] is False
    assert out["capture_allowed"] is True
    for word in ("fraud", "fake", "forged", "tamper", "compromise"):
        assert word not in out["reason"].lower()


def test_a_failing_challenge_does_not_upgrade_an_untrusted_tier():
    """The challenge gate withholds trust; it never manufactures it."""
    failed = read()
    out = attestation.assess("android", failed, challenge_ok=True)
    assert out["tier"] == attestation.TIER_FAILED
    assert out["trusted"] is False


# ----------------------------------------------------------- record wording --
def test_the_trusted_tiers_add_no_note():
    """Notes record the unusual. A device behaving correctly is not that."""
    out = attestation.assess("android", _hardware(), challenge_ok=True)
    assert attestation.integrity_note(out) is None


def test_every_untrusted_tier_produces_a_note():
    for tier in (attestation.TIER_BASIC_ONLY, attestation.TIER_EMULATOR,
                 attestation.TIER_UNATTESTED, attestation.TIER_UNVERIFIABLE,
                 attestation.TIER_FAILED):
        note = attestation.integrity_note({"tier": tier})
        assert note and len(note) > 20, tier


def test_every_tier_is_described():
    """A tier that reaches an export with no description is a silent record."""
    tiers = [v for k, v in vars(attestation).items() if k.startswith("TIER_")]
    for tier in tiers:
        assert tier in attestation.DESCRIPTIONS, tier


# ===========================================================================
# Regression: the three defects an adversarial re-read found after the module
# had 24 passing tests and two passing invariants. Every one of them survived
# that suite because every test reached the code through the same happy path —
# they pinned the tier ladder and never touched the boundary.
# ===========================================================================
def test_a_malformed_device_integrity_does_not_raise():
    """DEFECT 3. An uncaught AttributeError in a route is a 500 on an upload —
    and by this module's own headline property, a crash IS a block."""
    for broken in ({"deviceIntegrity": "MEETS_STRONG_INTEGRITY"},
                   {"deviceIntegrity": ["MEETS_STRONG_INTEGRITY"]},
                   {"deviceIntegrity": 7}):
        out = attestation.interpret_play_integrity(broken, verified=True,
                                                   expect_nonce="n")
        assert out["tier"] == attestation.TIER_UNVERIFIABLE, broken
        assert out["trusted"] is False


def test_a_repackaged_app_on_a_genuine_phone_is_not_trusted():
    """DEFECT 2. The realistic attacker does not root the phone. He modifies
    the app that decides what the camera returns, and deviceIntegrity stays
    perfect because the hardware genuinely is."""
    out = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY,
                app=attestation.UNRECOGNIZED_VERSION,
                package="com.attacker.clone", nonce="n"),
        verified=True, expect_nonce="n")
    assert out["tier"] == attestation.TIER_FAILED
    assert out["trusted"] is False


def test_an_unreadable_app_integrity_is_unverifiable_not_failed():
    """Absent is not the same as refused — the distinction this module keeps."""
    stripped = payload(attestation.STRONG_INTEGRITY, nonce="n")
    del stripped["appIntegrity"]
    out = attestation.interpret_play_integrity(stripped, verified=True,
                                               expect_nonce="n")
    assert out["tier"] == attestation.TIER_UNVERIFIABLE


def test_a_token_bound_to_a_different_nonce_is_not_trusted():
    """DEFECT 1, the serious one.

    Spend a fresh nonce, present a token minted against an older one. Before
    the fix this returned hardware_attested / trusted / challenge_bound — the
    replay defence was written in the docstring and implemented nowhere.
    """
    out = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY, nonce="some-old-nonce"),
        verified=True, expect_nonce="the-nonce-for-this-capture")
    assert out["trusted"] is False
    assert out["tier"] == attestation.TIER_UNVERIFIABLE
    assert attestation.assess("android", out, challenge_ok=True)["trusted"] is False


def test_a_token_carrying_no_nonce_at_all_is_not_trusted():
    out = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY),
        verified=True, expect_nonce="the-nonce-for-this-capture")
    assert out["tier"] == attestation.TIER_UNVERIFIABLE


def test_binding_is_a_property_of_the_token_not_a_caller_assertion():
    """assess() must not be able to be told the binding happened.

    The original shape took `challenge_ok` as a boolean the caller asserted,
    so a correct nonce consumption alongside a replayed token passed. The
    verdict itself now has to carry the binding.
    """
    unbound = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY), verified=True)
    assert attestation.assess("android", unbound, challenge_ok=True)["trusted"] is False


def test_a_correctly_bound_token_is_still_trusted():
    """Proves the three fixes did not simply turn the module off."""
    out = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY, nonce="n"),
        verified=True, expect_nonce="n")
    assert out["tier"] == attestation.TIER_HARDWARE
    assert attestation.assess("android", out, challenge_ok=True)["trusted"] is True


def test_app_attest_also_requires_the_nonce_to_match():
    ok = attestation.interpret_app_attest(verified=True, receipt_ok=True,
                                          token_nonce="n", expect_nonce="n")
    assert ok["tier"] == attestation.TIER_HARDWARE
    bad = attestation.interpret_app_attest(verified=True, receipt_ok=True,
                                           token_nonce="other", expect_nonce="n")
    assert bad["tier"] == attestation.TIER_UNVERIFIABLE
    assert bad["trusted"] is False


def test_challenge_bound_never_claims_a_binding_the_token_lacks():
    """Found by re-running the original probes against the fixed code.

    `challenge_bound` was computed from the nonce consumption alone, so a
    replayed token reported challenge_bound: True beside tier
    attestation_unverifiable. The record would have carried a field asserting
    a binding that demonstrably did not exist — the exact shape of defect this
    whole module is supposed to avoid.
    """
    replayed = attestation.interpret_play_integrity(
        payload(attestation.STRONG_INTEGRITY, nonce="some-other-capture"),
        verified=True, expect_nonce="capture-nonce")
    out = attestation.assess("android", replayed, challenge_ok=True)
    assert out["trusted"] is False
    assert out["challenge_bound"] is False, (
        "the token was not bound to this capture, so the record must not say "
        "it was")
