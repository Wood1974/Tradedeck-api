"""Is this a photograph of a scene, or a photograph of a screen?

Standard library plus Pillow. No numpy, no OpenCV — the same reason the
verifier and the fuzzer have no dependencies: a check that must run on every
upload should not be able to fail because an install broke.

The asymmetry that decides how this is used
-------------------------------------------
Both tests below are **strong positives and weak negatives**, and that is not a
shortcoming to be engineered away — it is what the physics and the geometry
actually support.

  Flash pair.    If the flash brightens near things much more than far things,
                 you photographed a REFLECTOR at varying depth. A screen is an
                 EMITTER: the displayed image does not respond to your torch,
                 so the gain is flat plus one specular blob. Depth-varying gain
                 therefore proves a real scene.
                 But flat gain proves nothing — you may have been in bright
                 daylight where the flash changes little, or photographing
                 something genuinely flat and evenly lit.

  Parallax.      If two views cannot be explained by any single homography,
                 the scene is NOT planar, so it cannot have been a screen.
                 But a planar result is ambiguous three ways: a screen, a
                 genuinely flat subject, or a capture where the camera rotated
                 instead of translating. Pure rotation about the optical centre
                 produces a homography for ANY scene — that is a fundamental
                 ambiguity, not a bug.

The consequence is the important part. **In construction, flat subjects are
everywhere** — drywall, a slab, a foundation wall, a sill plate against flat
concrete. A system that treated "planar" as fraud would accuse honest
contractors constantly, and a fraud detector that cries wolf on ordinary work
is worse than no detector.

So these are **evidence upgrades, not fraud detectors**. A capture that passes
earns a stronger claim. A capture that does not earns no penalty — it simply
does not get the upgrade. `assess()` enforces that: it never returns a verdict
that accuses, only one that certifies or abstains.

Calibration status
------------------
The thresholds below were chosen against SYNTHETIC scenes — a rendered depth
field versus a simulated display. They have never been run against a real
photograph of a real screen. Treat them as a starting point that needs field
calibration before any claim rests on them, and see `audit/CLAIMS.md`, where
the claim these serve is still marked unearned.
"""
import io
import math
import random

try:
    from PIL import Image
    PILLOW = True
except ImportError:                                  # pragma: no cover
    PILLOW = False

# Analysis resolution. Small on purpose: block means over a downscaled frame
# are what carry the signal, and sensor noise is not.
ANALYSIS_PX = 256
GRID = 8

# Below this mean gain the torch did not meaningfully change the frame, so the
# test has nothing to say. Daylight, or a flash that did not fire.
MIN_MEAN_GAIN = 4.0
# A blown-out flash frame is the dangerous case: once near blocks clip at 255
# the depth-dependent variation is destroyed and a REAL scene starts to look
# like a flat emitter. That is the false-accusation direction, so an
# overexposed pair is refused rather than judged. Surfaced by a synthetic
# scene whose flash was unrealistically bright.
SATURATED_LEVEL = 245.0
MAX_SATURATED_BLOCKS = 0.30
# Normalised spread of per-block gain. Synthetic-calibrated; see module docs.
SCENE_GAIN_SPREAD = 0.35
DISPLAY_GAIN_SPREAD = 0.15

# Parallax. A homography that explains this proportion of correspondences
# within tolerance means the scene is consistent with a plane.
PLANAR_INLIER_RATIO = 0.90
RANSAC_ITERS = 300
INLIER_PX = 2.0
MIN_CORRESPONDENCES = 12


# ------------------------------------------------------------ flash pair ---
def _blocks(raw, grid=GRID):
    """Mean luminance of each cell of a grid over a downscaled greyscale frame."""
    img = Image.open(io.BytesIO(raw))
    if img.mode != "L":
        img = img.convert("L")
    img.thumbnail((ANALYSIS_PX, ANALYSIS_PX))
    w, h = img.size
    if w < grid or h < grid:
        return None
    px = img.load()
    out = []
    for gy in range(grid):
        for gx in range(grid):
            x0, x1 = gx * w // grid, (gx + 1) * w // grid
            y0, y1 = gy * h // grid, (gy + 1) * h // grid
            total = count = 0
            for y in range(y0, y1):
                for x in range(x0, x1):
                    total += px[x, y]
                    count += 1
            out.append(total / count if count else 0.0)
    return out


def _saturated_fraction(blocks):
    return sum(1 for b in blocks if b >= SATURATED_LEVEL) / len(blocks)


def _stdev(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))


def analyze_flash_pair(no_flash, flash, grid=GRID):
    """Two frames milliseconds apart, torch off then on.

    Returns a three-valued verdict. `consistent_with_scene` is the only one
    that upgrades anything; `consistent_with_display` is a flag for a human,
    never an automatic accusation; `inconclusive` is common and expected.
    """
    if not PILLOW:
        return _flash_result("inconclusive", "Pillow unavailable")
    try:
        a, b = _blocks(no_flash, grid), _blocks(flash, grid)
    except Exception as exc:
        return _flash_result("inconclusive", f"could not read a frame: {exc}")
    if a is None or b is None:
        return _flash_result("inconclusive", "frames too small to analyse")
    if len(a) != len(b):
        return _flash_result("inconclusive", "frames differ in shape")

    gains = [f - n for n, f in zip(a, b)]
    mean_gain = sum(gains) / len(gains)
    darkened = sum(1 for g in gains if g < -2.0) / len(gains)

    saturated = _saturated_fraction(b)
    if saturated > MAX_SATURATED_BLOCKS:
        return _flash_result(
            "inconclusive",
            f"{saturated:.0%} of the flash frame is blown out. Clipping "
            f"destroys the depth-dependent variation this test measures, and a "
            f"real scene photographed too close reads as flat. Refused rather "
            f"than judged, because the error would fall against an honest "
            f"capture.",
            mean_gain=mean_gain, spread=None, darkened=darkened,
            saturated=saturated)

    if mean_gain < MIN_MEAN_GAIN:
        return _flash_result(
            "inconclusive",
            f"the torch changed the frame by only {mean_gain:.1f} levels — too "
            f"little to distinguish a reflector from an emitter. Common in "
            f"daylight, and not suspicious.",
            mean_gain=mean_gain, spread=None, darkened=darkened)

    spread = _stdev(gains) / mean_gain

    if spread >= SCENE_GAIN_SPREAD:
        return _flash_result(
            "consistent_with_scene",
            f"the torch brightened some regions {spread:.2f}x more unevenly "
            f"than others — illumination falling off with distance across a "
            f"reflecting surface at varying depth. A display cannot do this; "
            f"it emits its own light and does not respond to a torch.",
            mean_gain=mean_gain, spread=spread, darkened=darkened)
    if spread <= DISPLAY_GAIN_SPREAD:
        return _flash_result(
            "consistent_with_display",
            f"the torch raised the whole frame almost uniformly "
            f"(spread {spread:.2f}) — what a flat emitting surface does. Also "
            f"what a flat, evenly lit real surface does, so this is a reason "
            f"to look, not a finding.",
            mean_gain=mean_gain, spread=spread, darkened=darkened)
    return _flash_result(
        "inconclusive",
        f"gain spread {spread:.2f} falls between the thresholds.",
        mean_gain=mean_gain, spread=spread, darkened=darkened)


def _flash_result(verdict, reason, mean_gain=None, spread=None, darkened=None,
                  saturated=None):
    return {"test": "flash_pair", "verdict": verdict, "reason": reason,
            "mean_gain": round(mean_gain, 2) if mean_gain is not None else None,
            "gain_spread": round(spread, 3) if spread is not None else None,
            "darkened_fraction": round(darkened, 3) if darkened is not None else None,
            "saturated_fraction": round(saturated, 3) if saturated is not None else None}


# -------------------------------------------------------------- parallax ---
def _solve8(rows):
    """Gaussian elimination with partial pivoting. rows is 8 x 9 (augmented).

    Deliberately not SVD: a minimal four-point solve needs only this, and it
    keeps the module dependency-free.
    """
    n = 8
    m = [list(r) for r in rows]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[pivot][col]) < 1e-12:
            return None                        # degenerate sample
        m[col], m[pivot] = m[pivot], m[col]
        pv = m[col][col]
        for j in range(col, n + 1):
            m[col][j] /= pv
        for r in range(n):
            if r == col:
                continue
            factor = m[r][col]
            if factor:
                for j in range(col, n + 1):
                    m[r][j] -= factor * m[col][j]
    return [m[r][n] for r in range(n)]


def _homography(quad):
    """H from four correspondences ((x, y), (x2, y2)), with h33 fixed at 1."""
    rows = []
    for (x, y), (u, v) in quad:
        rows.append([x, y, 1, 0, 0, 0, -x * u, -y * u, u])
        rows.append([0, 0, 0, x, y, 1, -x * v, -y * v, v])
    h = _solve8(rows)
    return None if h is None else h + [1.0]


def _apply(h, x, y):
    d = h[6] * x + h[7] * y + h[8]
    if abs(d) < 1e-12:
        return None
    return ((h[0] * x + h[1] * y + h[2]) / d,
            (h[3] * x + h[4] * y + h[5]) / d)


def analyze_parallax(correspondences, image_size, seed=0):
    """Can one homography explain every matched point?

    `correspondences` is [((x1, y1), (x2, y2)), ...] in pixels, from two views
    of the same subject. `image_size` is (w, h) of the first view.

    A plane — a screen, a photograph, a flat wall — maps between two views by
    exactly one homography. A scene with depth does not: near and far points
    shift by different amounts, and no single 8-parameter transform fits both.
    """
    n = len(correspondences)
    if n < MIN_CORRESPONDENCES:
        return _par_result("inconclusive",
                           f"only {n} correspondences; need at least "
                           f"{MIN_CORRESPONDENCES} to fit and test a homography",
                           n=n)

    # Normalise to roughly [-1, 1] so the 8x8 solve stays well conditioned.
    w, h = image_size
    scale = max(w, h) / 2.0
    cx, cy = w / 2.0, h / 2.0
    norm = [(((a[0] - cx) / scale, (a[1] - cy) / scale),
             ((b[0] - cx) / scale, (b[1] - cy) / scale))
            for a, b in correspondences]
    tol = INLIER_PX / scale

    rnd = random.Random(seed)
    best_inliers, best_h = 0, None
    for _ in range(RANSAC_ITERS):
        quad = rnd.sample(norm, 4)
        H = _homography(quad)
        if H is None:
            continue
        inliers = 0
        for (x, y), (u, v) in norm:
            p = _apply(H, x, y)
            if p and math.hypot(p[0] - u, p[1] - v) <= tol:
                inliers += 1
        if inliers > best_inliers:
            best_inliers, best_h = inliers, H

    if best_h is None:
        return _par_result("inconclusive", "no homography could be fitted", n=n)

    ratio = best_inliers / n
    residuals = []
    for (x, y), (u, v) in norm:
        p = _apply(best_h, x, y)
        residuals.append(math.hypot(p[0] - u, p[1] - v) * scale if p else float("inf"))
    residuals.sort()
    median_px = residuals[len(residuals) // 2]

    if ratio >= PLANAR_INLIER_RATIO:
        return _par_result(
            "planar",
            f"one homography explains {ratio:.0%} of matched points to within "
            f"{INLIER_PX:.0f}px. Consistent with a screen — and equally with a "
            f"flat wall, or with a capture where the camera rotated instead of "
            f"moving. Ambiguous by construction; not a finding on its own.",
            n=n, ratio=ratio, median_px=median_px)
    return _par_result(
        "non_planar",
        f"no single homography fits: best explains only {ratio:.0%} of points, "
        f"median residual {median_px:.1f}px. The subject has real depth, so it "
        f"was not a flat display.",
        n=n, ratio=ratio, median_px=median_px)


def _par_result(verdict, reason, n=0, ratio=None, median_px=None):
    return {"test": "parallax", "verdict": verdict, "reason": reason,
            "correspondences": n,
            "homography_inlier_ratio": round(ratio, 3) if ratio is not None else None,
            "median_residual_px": round(median_px, 2) if median_px is not None else None}


# -------------------------------------------------------------- combined ---
def assess(flash=None, parallax=None):
    """Combine into an evidence upgrade. Never into an accusation.

    `capture_corroborated` is the only outcome that strengthens a record.
    Everything else leaves the record exactly as it was — because a flat
    subject, a bright day, and a rotated capture are all ordinary, and a system
    that penalised them would penalise honest work far more often than fraud.
    """
    signals = [r for r in (flash, parallax) if r]
    positives = [r for r in signals
                 if r["verdict"] in ("consistent_with_scene", "non_planar")]
    display_like = [r for r in signals
                    if r["verdict"] in ("consistent_with_display", "planar")]

    if positives:
        return {
            "verdict": "capture_corroborated",
            "upgrade": True,
            "reason": "Independent physical evidence that a real three-"
                      "dimensional scene was in front of the lens: "
                      + "; ".join(r["reason"] for r in positives),
            "signals": signals,
            "review_suggested": False,
        }
    if display_like:
        return {
            "verdict": "not_corroborated",
            "upgrade": False,
            "reason": "No positive evidence of a real scene, and the capture "
                      "looks flat. That is ordinary for a wall, a slab, or a "
                      "bright day — it is a reason for a human to look if "
                      "something else about this job is already in question, "
                      "and nothing more.",
            "signals": signals,
            "review_suggested": True,
        }
    return {
        "verdict": "not_corroborated",
        "upgrade": False,
        "reason": "The capture did not support these checks. No inference "
                  "either way.",
        "signals": signals,
        "review_suggested": False,
    }
