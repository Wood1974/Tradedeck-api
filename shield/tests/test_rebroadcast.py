"""Does the rebroadcast check actually discriminate?

The synthetic scenes below are the honest part of this file. There is no real
photograph of a real screen here — these are a rendered depth field and a
simulated display, built from the same physics the module claims to rely on.
That proves the *maths* separates the two cases. It does not prove the
thresholds survive a real phone, a real monitor, and a real jobsite, and
`audit/CLAIMS.md` still marks the claim these serve as unearned.

What the tests are really pinning down is the asymmetry: a positive result is
strong, a negative result is weak, and the combined assessment must never turn
a negative into an accusation. That last one is the product-critical property —
flat subjects are everywhere in construction, and a checker that called them
fraud would be worse than no checker.
"""
import io
import math
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import rebroadcast  # noqa: E402

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


# ------------------------------------------------------ synthetic scenes ---
def render(depth_fn, flash, size=256, albedo=0.55, ambient=70.0):
    """A greyscale frame of a scene whose depth varies by position.

    Ambient light is uniform. The torch is a point source, so its contribution
    falls off as 1/d^2 — the whole basis of the flash test.
    """
    img = Image.new("L", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            d = depth_fn(x / size, y / size)
            value = ambient * albedo
            if flash:
                # Tuned to a real phone torch: a strong but not blinding lift
                # at ~1 m, falling to almost nothing by ~5 m. The first draft
                # used a constant 47x larger, which clipped the near field to
                # 255 and made a real scene read as a flat display — the
                # failure the module now refuses rather than judges.
                value += albedo * 190.0 / (d * d)
            px[x, y] = max(0, min(255, int(value)))
    return _png(img)


def render_display(flash, size=256, glare=14.0):
    """A photograph of a screen.

    The panel emits its own light, so the displayed image is unchanged by the
    torch. What the torch adds is a near-uniform specular wash off the glass —
    the same everywhere because the glass is flat and at one distance.
    """
    img = Image.new("L", (size, size))
    px = img.load()
    rnd = random.Random(7)
    for y in range(size):
        for x in range(size):
            # arbitrary displayed content, identical in both frames
            value = 60 + 50 * math.sin(x / 14.0) * math.cos(y / 19.0) + rnd.uniform(-2, 2)
            if flash:
                value += glare
            px[x, y] = max(0, min(255, int(value)))
    return _png(img)


def _png(img):
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


# depth in metres: a real scene runs from near to far across the frame
def depth_3d(u, v):
    return 0.9 + 4.5 * v


def depth_flat_wall(u, v):
    return 2.4


# ------------------------------------------------------------ flash pair ---
def test_a_real_scene_with_depth_is_recognised():
    r = rebroadcast.analyze_flash_pair(render(depth_3d, False),
                                       render(depth_3d, True))
    assert r["verdict"] == "consistent_with_scene", r
    assert r["gain_spread"] >= rebroadcast.SCENE_GAIN_SPREAD


def test_a_photographed_display_is_recognised():
    r = rebroadcast.analyze_flash_pair(render_display(False),
                                       render_display(True))
    assert r["verdict"] == "consistent_with_display", r
    assert r["gain_spread"] <= rebroadcast.DISPLAY_GAIN_SPREAD


def test_a_flat_wall_looks_like_a_display_and_that_is_the_known_limit():
    """The false positive that would wreck the product if acted on.

    A flat wall at uniform depth gains uniformly, exactly as a screen does.
    This test exists to hold that behaviour in place so nobody later 'fixes'
    it into an accusation.
    """
    r = rebroadcast.analyze_flash_pair(render(depth_flat_wall, False),
                                       render(depth_flat_wall, True))
    assert r["verdict"] in ("consistent_with_display", "inconclusive")
    combined = rebroadcast.assess(flash=r)
    assert combined["upgrade"] is False
    assert "verdict" in combined and "fraud" not in combined["reason"].lower()


def test_daylight_is_inconclusive_not_suspicious():
    """A flash that changes nothing says nothing. It must not say 'screen'."""
    bright = render(depth_3d, False, ambient=250.0)
    r = rebroadcast.analyze_flash_pair(bright, bright)
    assert r["verdict"] == "inconclusive"
    assert "not suspicious" in r["reason"]


def test_an_overexposed_flash_frame_is_refused_not_judged():
    """A real scene shot too close clips, and clipping looks flat.

    The error would fall against an honest capture, so the pair is refused.
    This is the first draft of these very tests, preserved as a case.
    """
    def hot(u, v):
        return 0.35 + 0.1 * v          # very close: the torch blows it out

    r = rebroadcast.analyze_flash_pair(render(hot, False), render(hot, True))
    assert r["verdict"] == "inconclusive"
    assert "blown out" in r["reason"]
    assert r["saturated_fraction"] > rebroadcast.MAX_SATURATED_BLOCKS


def test_identical_frames_are_inconclusive():
    frame = render(depth_3d, False)
    assert rebroadcast.analyze_flash_pair(frame, frame)["verdict"] == "inconclusive"


def test_unreadable_input_does_not_raise():
    r = rebroadcast.analyze_flash_pair(b"not an image", b"also not")
    assert r["verdict"] == "inconclusive"


# -------------------------------------------------------------- parallax ---
def project(points3d, camera_x, f=600.0, cx=320.0, cy=240.0):
    """Pinhole projection from a camera translated along x."""
    out = []
    for X, Y, Z in points3d:
        out.append((f * (X - camera_x) / Z + cx, f * Y / Z + cy))
    return out


def scene_points(rnd, planar, n=60):
    pts = []
    for _ in range(n):
        X = rnd.uniform(-1.6, 1.6)
        Y = rnd.uniform(-1.2, 1.2)
        Z = 3.0 if planar else rnd.uniform(1.2, 7.0)
        pts.append((X, Y, Z))
    return pts


def correspondences(planar, baseline=0.5, seed=3, n=60):
    rnd = random.Random(seed)
    pts = scene_points(rnd, planar, n)
    a, b = project(pts, 0.0), project(pts, baseline)
    return list(zip(a, b))


def test_a_scene_with_depth_defeats_every_homography():
    r = rebroadcast.analyze_parallax(correspondences(planar=False), (640, 480))
    assert r["verdict"] == "non_planar", r
    assert r["homography_inlier_ratio"] < rebroadcast.PLANAR_INLIER_RATIO


def test_a_flat_subject_is_explained_by_one_homography():
    r = rebroadcast.analyze_parallax(correspondences(planar=True), (640, 480))
    assert r["verdict"] == "planar", r
    assert r["homography_inlier_ratio"] >= rebroadcast.PLANAR_INLIER_RATIO


def test_a_planar_verdict_names_its_own_ambiguity():
    """It must not read as an accusation, because it cannot support one."""
    r = rebroadcast.analyze_parallax(correspondences(planar=True), (640, 480))
    reason = r["reason"].lower()
    assert "flat wall" in reason and "rotated" in reason


def test_too_few_matches_is_inconclusive():
    r = rebroadcast.analyze_parallax(correspondences(planar=False, n=6)[:6],
                                     (640, 480))
    assert r["verdict"] == "inconclusive"
    assert "correspondences" in r["reason"]


def test_pure_rotation_of_a_3d_scene_reads_as_planar():
    """A fundamental ambiguity, pinned so nobody mistakes it for a bug.

    With zero baseline every scene is a homography. This is why the capture
    flow has to force real translation, and why a planar result can never be
    a finding on its own.
    """
    r = rebroadcast.analyze_parallax(correspondences(planar=False, baseline=0.0),
                                     (640, 480))
    assert r["verdict"] == "planar"


def test_more_depth_gives_a_lower_inlier_ratio():
    """The signal should scale with how much depth is actually present."""
    shallow = rebroadcast.analyze_parallax(
        list(zip(project(scene_points(random.Random(1), False, 60), 0.0),
                 project(scene_points(random.Random(1), False, 60), 0.05))),
        (640, 480))
    deep = rebroadcast.analyze_parallax(correspondences(planar=False, baseline=0.8),
                                        (640, 480))
    assert deep["homography_inlier_ratio"] <= shallow["homography_inlier_ratio"]


def test_parallax_is_deterministic_for_a_given_seed():
    a = rebroadcast.analyze_parallax(correspondences(planar=False), (640, 480))
    b = rebroadcast.analyze_parallax(correspondences(planar=False), (640, 480))
    assert a == b


# -------------------------------------------------------------- combined ---
def test_either_positive_signal_alone_upgrades():
    flash = rebroadcast.analyze_flash_pair(render(depth_3d, False),
                                           render(depth_3d, True))
    par = rebroadcast.analyze_parallax(correspondences(planar=False), (640, 480))
    for combo in ({"flash": flash}, {"parallax": par},
                  {"flash": flash, "parallax": par}):
        assert rebroadcast.assess(**combo)["upgrade"] is True


def test_a_negative_never_becomes_an_accusation():
    """The product-critical property of this whole module."""
    flash = rebroadcast.analyze_flash_pair(render_display(False),
                                           render_display(True))
    par = rebroadcast.analyze_parallax(correspondences(planar=True), (640, 480))
    out = rebroadcast.assess(flash=flash, parallax=par)
    assert out["upgrade"] is False
    assert out["verdict"] == "not_corroborated"
    for word in ("fraud", "fake", "forged", "faked"):
        assert word not in out["reason"].lower()
    assert out["review_suggested"] is True


def test_no_signals_at_all_infers_nothing():
    out = rebroadcast.assess()
    assert out["upgrade"] is False
    assert out["review_suggested"] is False
    assert "No inference either way" in out["reason"]


def test_a_real_scene_passes_both_tests_together():
    """The case the capture flow is designed to produce."""
    out = rebroadcast.assess(
        flash=rebroadcast.analyze_flash_pair(render(depth_3d, False),
                                             render(depth_3d, True)),
        parallax=rebroadcast.analyze_parallax(correspondences(planar=False),
                                              (640, 480)))
    assert out["verdict"] == "capture_corroborated"
    assert len(out["signals"]) == 2
