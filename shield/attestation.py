"""What the capturing device can prove about itself — and what it cannot.

The gap this fills
------------------
`claims.py` carries `photo-came-from-a-camera` as UNEARNED, and AR-1 records
why: today a forged capture costs about twelve lines of Python. `rebroadcast.py`
attacks that from the optics side, by looking for depth in the scene. This
module attacks it from the device side, by asking the hardware to sign for
itself.

Neither one closes AR-1 alone. Attestation proves a genuine app on genuine
hardware; it says nothing about what was in front of the lens, which is exactly
the screen-replay path rebroadcast covers. Rebroadcast proves a 3D scene; it
says nothing about whether the file came from that camera. They are two
different halves and the claim needs both.

Three design decisions worth defending
--------------------------------------
**1. This module never blocks a capture. It labels one.**

The obvious design hard-blocks upload when attestation fails. It is wrong here,
for a reason specific to what Shield is. A blocked capture produces *no record*:
the subcontractor with a rooted Pixel simply cannot document his work, so the
pour goes unphotographed and the dispute six months later has nothing in it.
A labelled capture produces the photograph, the hash, the custody entry, and an
honest note that the device could not vouch for itself. The second outcome is
strictly more evidence than the first.

So Shield records and the buyer gates. Whether a `attestation_failed` photo may
close a structural milestone is the buyer's risk decision, made in their own
policy against their own money — not ours, made for them, in a library. This is
the same asymmetry `rebroadcast.assess()` enforces: a negative result is a weak
signal, and weak signals must not be given strong consequences.

**2. Unverified is never trusted, and absent is not the same as failed.**

Three states that a two-state design collapses and must not:

  * *unattested* — nothing was presented. Every web upload is this, because
    App Attest and Play Integrity require a native app and Shield's frontends
    are web pages. It is the honest default, not a finding against anyone.
  * *attestation_failed* — something was presented and the platform said no.
    That IS a finding.
  * *attestation_unverifiable* — something was presented and we could not
    check it (key fetch failed, malformed token, clock skew). Fail closed:
    never trusted, never reported as a failure by the device either.

**3. The cryptographic step is a boundary, and it fails closed.**

Verifying an App Attest blob means CBOR-decoding it and walking an X.509 chain
to Apple's App Attest root; verifying a Play Integrity token means decrypting
a JWE or calling Google's API. Neither dependency is in this service, and
neither can be exercised without the native app that does not exist yet. So
this module takes an already-verified verdict and refuses, structurally, to
grant trust to one that is not: `verified` must be exactly `True`, because the
string `"false"` is truthy and that is precisely how a fail-open bug gets
written.
"""
import hashlib
import hmac
import secrets
import time

# --------------------------------------------------------------- the tiers ---
# Ordered by what the hardware actually vouched for, strongest first.
TIER_HARDWARE     = "hardware_attested"
TIER_DEVICE       = "device_attested"
TIER_BASIC_ONLY   = "basic_integrity_only"
TIER_EMULATOR     = "recognized_emulator"
TIER_UNATTESTED   = "unattested"
TIER_UNVERIFIABLE = "attestation_unverifiable"
TIER_FAILED       = "attestation_failed"

#: The only tiers that may be treated as a device vouching for itself.
#: Everything else is absence, ambiguity, or a refusal — never trust.
TRUSTED_TIERS = (TIER_HARDWARE, TIER_DEVICE)

DESCRIPTIONS = {
    TIER_HARDWARE: (
        "The capture was made by a genuine app instance on genuine, certified "
        "hardware, attested by the platform vendor and bound to this specific "
        "capture by a single-use server challenge."),
    TIER_DEVICE: (
        "The capture was made by a genuine app instance on a certified device. "
        "The device did not report the stronger signal that also requires a "
        "recent security update."),
    TIER_BASIC_ONLY: (
        "The device passed basic checks but is not a certified device build. "
        "This is not treated as a device vouching for itself."),
    TIER_EMULATOR: (
        "The app was running on a recognised Android emulator. An emulator "
        "passes platform integrity checks but cannot hold a lens to a wall, so "
        "it is not treated as a capture device."),
    TIER_UNATTESTED: (
        "No device attestation was presented. Web uploads cannot present one; "
        "this is the expected state for them and is not a finding against the "
        "uploader."),
    TIER_UNVERIFIABLE: (
        "A device attestation was presented but could not be verified. It is "
        "treated as absent rather than as a failure by the device."),
    TIER_FAILED: (
        "A device attestation was presented and the platform did not recognise "
        "the device — signs of tampering, system compromise, or an "
        "unrecognised emulator."),
}

# ---------------------------------------------------- Play Integrity labels ---
# Verified against developer.android.com/google/play/integrity/verdicts.
#
# The label most people reach for is the wrong one. MEETS_VIRTUAL_INTEGRITY is
# issued to a *recognised* emulator — Google Play Games for PC — that passes
# system integrity checks. An attacker's emulator, the one feeding synthetic
# frames to a spoofed camera, does not earn that label: it earns an EMPTY
# deviceRecognitionVerdict, which Google documents as "signs of attack (such as
# API hooking) or system compromise (such as being rooted), or ... not running
# on a physical device". Blocking on VIRTUAL and passing everything else
# therefore blocks the honest PC gamer and admits the attacker.
#
# The rule that actually holds: require a positive label. Absence is the signal.
STRONG_INTEGRITY  = "MEETS_STRONG_INTEGRITY"
DEVICE_INTEGRITY  = "MEETS_DEVICE_INTEGRITY"
BASIC_INTEGRITY   = "MEETS_BASIC_INTEGRITY"
VIRTUAL_INTEGRITY = "MEETS_VIRTUAL_INTEGRITY"

# appIntegrity is the half the first version of this module ignored entirely,
# and it is the half that catches the realistic attacker. He does not root the
# phone — rooting costs him his deviceIntegrity label. He repackages the app
# that decides what "the camera" returns, and runs it on a genuine, certified,
# locked-bootloader handset whose deviceIntegrity is flawless.
PLAY_RECOGNIZED      = "PLAY_RECOGNIZED"
UNRECOGNIZED_VERSION = "UNRECOGNIZED_VERSION"

#: Default challenge lifetime. Long enough to frame a shot, short enough that a
#: token lifted off the wire is stale before it can be replayed.
CHALLENGE_TTL_S = 120


class ChallengeStore:
    """Single-use, time-bounded capture nonces.

    Why a challenge at all: without one, an attestation proves "this device was
    genuine at some point" and nothing more. The same token replays against
    every upload forever, including uploads of files the device never captured.
    Binding a server-issued, single-use nonce into the attestation is what makes
    it say *this capture*.

    Single-use is enforced by deleting on read, so a replay inside the TTL fails
    the same way a replay after it does.

    Production note, stated rather than buried: this backing store is per
    process. Under more than one gunicorn worker an issue on worker A is
    invisible to worker B, which turns a legitimate capture into a rejection and
    makes the single-use guarantee depend on which worker answers. A real
    deployment needs a shared store (the database, or Redis). The interface is
    the same; only `_live` changes.
    """

    def __init__(self, ttl_s=CHALLENGE_TTL_S, clock=time.time):
        self._live = {}
        self._ttl = ttl_s
        self._clock = clock

    def issue(self, subject):
        """A fresh nonce for one capture by one actor."""
        nonce = secrets.token_urlsafe(32)
        self._live[nonce] = (str(subject), self._clock() + self._ttl)
        return nonce

    def consume(self, nonce, subject):
        """Spend a nonce. True only for a live, unspent nonce of this subject.

        The subject check stops one actor spending a nonce issued to another —
        without it a contractor could request a challenge and have it answered
        by an attestation from someone else's device.
        """
        if not nonce:
            return False
        found = self._live.pop(nonce, None)
        if found is None:
            return False
        owner, expires_at = found
        if self._clock() > expires_at:
            return False
        return hmac.compare_digest(owner, str(subject))

    def purge(self, now=None):
        """Drop expired nonces. Returns how many went."""
        now = self._clock() if now is None else now
        dead = [n for n, (_, exp) in self._live.items() if now > exp]
        for n in dead:
            del self._live[n]
        return len(dead)

    def __len__(self):
        return len(self._live)


def challenge_hash(nonce):
    """What the client binds into the attestation.

    The raw nonce is not what goes into the token; its SHA-256 is. Both
    platforms expect an opaque fixed-length value, and hashing means a token
    captured off the wire never carries a nonce that is still spendable here.
    """
    return hashlib.sha256(str(nonce).encode()).hexdigest()


def _verified(verdict):
    """Exactly True, never merely truthy.

    `{"verified": "false"}` is truthy. So is `{"verified": "unverified"}`. A
    fail-open bug in this position grants full hardware trust to an attacker's
    own JSON, so the comparison is identity against True and the type is part
    of the contract.
    """
    return isinstance(verdict, dict) and verdict.get("verified") is True


def interpret_play_integrity(payload, verified=False, expect_nonce=None,
                             expect_package=None):
    """Map a decoded Play Integrity payload onto a tier.

    `payload` is the decoded token body; `verified` states whether its signature
    and provenance were actually checked upstream. Unverified input can only
    ever produce TIER_UNVERIFIABLE, whatever it claims about itself.

    `expect_nonce` is the single-use capture challenge this upload spent. The
    token must carry its hash, or the token is about some other capture and the
    result cannot be trusted however good the device looks. Omitting it does
    NOT skip the check — it makes the result unbound, and unbound is untrusted.
    """
    if verified is not True:
        return _result(TIER_UNVERIFIABLE, "platform", "the integrity token was "
                       "not cryptographically verified")
    if not isinstance(payload, dict):
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the integrity payload was not a readable object")

    # Every one of these was `payload.get(x) or {}` followed by `.get(...)`,
    # which raises AttributeError the moment the value is a str, a list or an
    # int. An uncaught raise in a route is a 500 on an upload — and by this
    # module's own headline property, a crash IS a block.
    device = payload.get("deviceIntegrity")
    if not isinstance(device, dict):
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the payload carried no readable deviceIntegrity block")

    app = payload.get("appIntegrity")
    if not isinstance(app, dict):
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the payload carried no readable appIntegrity block")
    app_verdict = str(app.get("appRecognitionVerdict") or "")
    if app_verdict != PLAY_RECOGNIZED:
        return _result(TIER_FAILED, "platform",
                       f"the running app is not the published one "
                       f"({app_verdict or 'no verdict'}) — a modified or "
                       f"repackaged build attests its hardware perfectly while "
                       f"controlling what the camera returns")
    if expect_package and str(app.get("packageName") or "") != expect_package:
        return _result(TIER_FAILED, "platform",
                       "the attestation is for a different application package")

    bound = _nonce_matches(payload, expect_nonce)
    if bound is False:
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the token is not bound to this capture's single-use "
                       "challenge, so it attests some other moment")

    labels = device.get("deviceRecognitionVerdict")
    if not isinstance(labels, (list, tuple)):
        labels = []
    labels = [str(x) for x in labels]

    # Absence is the attack signal, not VIRTUAL. See the note above.
    if not labels:
        return _result(TIER_FAILED, "platform",
                       "the device earned no integrity label at all, which "
                       "Google documents as signs of attack, system compromise, "
                       "or an unrecognised emulator", labels=labels, bound=bound)
    if STRONG_INTEGRITY in labels:
        return _result(TIER_HARDWARE, "platform",
                       "certified device with a recent security update",
                       labels=labels, bound=bound)
    if DEVICE_INTEGRITY in labels:
        return _result(TIER_DEVICE, "platform", "certified device",
                       labels=labels, bound=bound)
    if VIRTUAL_INTEGRITY in labels:
        return _result(TIER_EMULATOR, "platform",
                       "a recognised emulator, which cannot be a capture device",
                       labels=labels, bound=bound)
    if BASIC_INTEGRITY in labels:
        return _result(TIER_BASIC_ONLY, "platform",
                       "basic checks only; not a certified device build",
                       labels=labels, bound=bound)
    return _result(TIER_BASIC_ONLY, "platform",
                   "no recognised integrity label among those returned",
                   labels=labels, bound=bound)


def interpret_app_attest(verified=False, receipt_ok=True, token_nonce=None,
                         expect_nonce=None):
    """Map an App Attest verification outcome onto a tier.

    What this is allowed to mean, precisely: a genuine instance of this app,
    running on genuine Apple hardware, holding a key generated in the Secure
    Enclave.

    What it is NOT allowed to mean, however often it is written down that way:
    that the device is not jailbroken. Apple does not expose jailbreak status
    through App Attest, and treating a pass as a clean-device signal is an
    overclaim of exactly the kind `claims.py` exists to stop. It is a strong
    statement about the app and the silicon, and a silent one about the OS.
    """
    if verified is not True:
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the attestation was not cryptographically verified")
    if not receipt_ok:
        return _result(TIER_FAILED, "platform",
                       "the attestation was verified but rejected — the key or "
                       "the app identity did not match")
    if expect_nonce is not None and not hmac.compare_digest(
            str(token_nonce or ""), str(expect_nonce)):
        return _result(TIER_UNVERIFIABLE, "platform",
                       "the attestation is not bound to this capture's "
                       "single-use challenge, so it attests some other moment")
    return _result(TIER_HARDWARE, "platform",
                   "genuine app instance on genuine Apple hardware, key held "
                   "in the Secure Enclave (this says nothing about jailbreak "
                   "state, which Apple does not expose)",
                   bound=expect_nonce is not None)


def _nonce_matches(payload, expect_nonce):
    """Did this token commit to the challenge this capture spent?

    Returns True (bound), False (a nonce was required and did not match), or
    None (no binding was requested). None is NOT a pass — `assess` treats
    anything other than True as unbound, and unbound is never trusted.

    This is the check the first version of the module advertised in three
    docstrings, a commit message and a PR body, and implemented nowhere:
    `challenge_hash` was defined and called zero times, and the binding was a
    boolean the caller asserted. Consuming a fresh nonce while presenting a
    token minted against an older one returned full hardware trust.
    """
    if expect_nonce is None:
        return None
    details = payload.get("requestDetails")
    if not isinstance(details, dict):
        return False
    return hmac.compare_digest(str(details.get("requestHash") or ""),
                               challenge_hash(expect_nonce))


def _result(tier, source, reason, labels=None, bound=None):
    out = {"tier": tier, "source": source, "reason": reason,
           "trusted": tier in TRUSTED_TIERS, "bound": bound is True}
    if labels is not None:
        out["labels"] = list(labels)
    return out


def assess(platform=None, verdict=None, challenge_ok=None):
    """The whole picture for one capture. Never returns a refusal to record.

    `verdict` is the output of one of the interpret_* functions above.
    `challenge_ok` is the result of spending the capture nonce: True if a
    single-use server challenge was bound into this attestation, False if one
    was presented and did not check out, None if none was in play.
    """
    if verdict is None:
        return {
            "tier": TIER_UNATTESTED,
            "trusted": False,
            "capture_allowed": True,
            "challenge_bound": False,
            "platform": platform,
            "reason": DESCRIPTIONS[TIER_UNATTESTED],
            "note": "No device attestation was presented with this capture.",
        }

    tier = verdict.get("tier", TIER_UNVERIFIABLE)

    # An attestation that is not bound to a server-issued, single-use challenge
    # proves the device was genuine at some moment, not that it took THIS
    # photograph. A replayed token would otherwise carry full hardware trust
    # onto a file the device never saw, so trust is withheld rather than
    # downgraded quietly.
    if tier in TRUSTED_TIERS and (verdict.get("bound") is not True
                                  or challenge_ok is not True):
        missing = ("did not match the token"
                   if verdict.get("bound") is not True else
                   "failed" if challenge_ok is False else "was not presented")
        return {
            "tier": TIER_UNVERIFIABLE,
            "trusted": False,
            "capture_allowed": True,
            "challenge_bound": False,
            "platform": platform,
            "reason": (f"The device attested successfully, but the single-use "
                       f"capture challenge {missing}, so the attestation is "
                       f"not bound to this photograph."),
            "note": DESCRIPTIONS[TIER_UNVERIFIABLE],
        }

    return {
        "tier": tier,
        "trusted": tier in TRUSTED_TIERS,
        "capture_allowed": True,          # invariant: this module labels, never blocks
        # Both halves, or it is not bound: the server must have spent a live
        # single-use nonce AND the token must commit to that same nonce.
        # Reporting only the first put `challenge_bound: True` on a record
        # whose token was bound to a different capture entirely.
        "challenge_bound": verdict.get("bound") is True and challenge_ok is True,
        "platform": platform,
        "reason": verdict.get("reason", ""),
        "note": DESCRIPTIONS.get(tier, ""),
        **({"labels": verdict["labels"]} if "labels" in verdict else {}),
    }


def integrity_note(result):
    """One sentence for the custody record and the evidence export.

    Returns None for the trusted tiers: a record should carry notes about what
    is *unusual*, and a device that vouched for itself correctly is the
    intended case, not an exception worth annotating.
    """
    tier = result.get("tier")
    if tier in TRUSTED_TIERS:
        return None
    if tier == TIER_UNATTESTED:
        return ("No device attestation accompanied this capture, so the "
                "photograph's origin rests on the record around it rather than "
                "on the device.")
    return DESCRIPTIONS.get(tier, "Device attestation was inconclusive.")
