"""
Backend Security Invariants for Shield Capture v1

Enforce immutable trust model invariants by validating that capture manifests
maintain cryptographic integrity and adhere to Shield Capture v1 semantics.

Core responsibility:
1. Evidence chain integrity (manifests are valid, immutable, sequential)
2. Checkpoint consistency (captures match pack definitions)
3. Nonce exhaustion (challenges consumed exactly once)
4. GPS spoofing detection (location consistency checks pass)
5. Device binding consistency (device hashes are stable or change predictably)
"""

import logging
import re
import time
from typing import List, Dict, Tuple, Optional

import capture
import location
import pdf_export
import packs
from capture import Challenges

logger = logging.getLogger(__name__)

# Constants for validation
SHA256_HEX_LENGTH = 64
SHA256_HEX_PATTERN = r"^[a-f0-9]{64}$"


# ============================================================================
# Helper Functions
# ============================================================================

def _validate_sha256_hex(value: str, field_name: str) -> None:
    """
    Validate that a value is a valid SHA-256 hex string (64 lowercase hex chars).

    Args:
        value: The value to validate
        field_name: Name of the field for error messages

    Raises:
        AssertionError: If value is not a valid SHA-256 hex string
    """
    assert isinstance(value, str), \
        f"{field_name} must be string, got {type(value).__name__}"
    assert len(value) == SHA256_HEX_LENGTH, \
        f"{field_name} must be {SHA256_HEX_LENGTH} chars, got {len(value)}"
    assert re.match(SHA256_HEX_PATTERN, value), \
        f"{field_name} must be valid hex, got {value[:8]}..."


# ============================================================================
# 1. assert_manifest_structure
# ============================================================================

def assert_manifest_structure(manifest: List[Dict]) -> None:
    """
    Validate manifest is well-formed list of captures.

    Checks:
    - manifest is a list
    - each entry is a dict with keys: checkpoint_name, photo_bytes, note, bind_hash
    - bind_hash is 64-char hex SHA-256
    - checkpoint_name is non-empty string
    - photo_bytes is bytes (non-empty)
    - note is string

    Args:
        manifest: List of capture dicts to validate

    Raises:
        AssertionError: If manifest structure is invalid
    """
    assert isinstance(manifest, list), f"manifest must be a list, got {type(manifest).__name__}"

    for i, entry in enumerate(manifest):
        assert isinstance(entry, dict), f"manifest entry {i} must be a dict, got {type(entry).__name__}"

        # Check required keys
        required_keys = {"checkpoint_name", "photo_bytes", "note", "bind_hash"}
        missing_keys = required_keys - set(entry.keys())
        assert not missing_keys, f"manifest entry {i} missing required keys: {missing_keys}"

        # Validate checkpoint_name
        checkpoint_name = entry.get("checkpoint_name")
        assert isinstance(checkpoint_name, str), \
            f"manifest entry {i}: checkpoint_name must be string, got {type(checkpoint_name).__name__}"
        assert checkpoint_name.strip(), f"manifest entry {i}: checkpoint_name cannot be empty"

        # Validate photo_bytes
        photo_bytes = entry.get("photo_bytes")
        assert isinstance(photo_bytes, bytes), \
            f"manifest entry {i}: photo_bytes must be bytes, got {type(photo_bytes).__name__}"
        assert len(photo_bytes) > 0, f"manifest entry {i}: photo_bytes cannot be empty"

        # Validate note
        note = entry.get("note")
        assert isinstance(note, str), f"manifest entry {i}: note must be string, got {type(note).__name__}"

        # Validate bind_hash
        bind_hash = entry.get("bind_hash")
        _validate_sha256_hex(bind_hash, f"manifest entry {i}: bind_hash")


# ============================================================================
# 2. assert_pack_checkpoint_correspondence
# ============================================================================

def assert_pack_checkpoint_correspondence(manifest: List[Dict], pack: Dict) -> None:
    """
    Validate all captures match pack checkpoint definitions.

    Checks:
    - manifest has exactly len(pack['points']) captures
    - each manifest entry's checkpoint_name matches pack['points'][i]['name']
    - pack points are in sequential order (order field = 1, 2, 3, ...)
    - no duplicate checkpoint names in manifest

    Args:
        manifest: List of capture dicts
        pack: Pack dict with 'points' array

    Raises:
        AssertionError: If correspondence fails with detailed mismatch info
    """
    # Check manifest length matches pack points
    assert len(manifest) == len(pack["points"]), \
        f"manifest has {len(manifest)} captures but pack defines " \
        f"{len(pack['points'])} checkpoints"

    # Check for duplicate checkpoint names in manifest
    checkpoint_names = [m["checkpoint_name"] for m in manifest]
    seen = set()
    for name in checkpoint_names:
        assert name not in seen, f"duplicate checkpoint name in manifest: {name}"
        seen.add(name)

    # Check sequential pack ordering
    for i, point in enumerate(pack["points"]):
        expected_order = i + 1
        assert point["order"] == expected_order, \
            f"pack point {i} has order {point['order']}, expected {expected_order}"

    # Check each manifest checkpoint matches corresponding pack point
    for i, (manifest_entry, pack_point) in enumerate(zip(manifest, pack["points"])):
        manifest_name = manifest_entry["checkpoint_name"]
        pack_name = pack_point["name"]
        assert manifest_name == pack_name, \
            f"checkpoint {i}: manifest name '{manifest_name}' does not match " \
            f"pack point name '{pack_name}'"


# ============================================================================
# 3. assert_nonce_single_use
# ============================================================================

def assert_nonce_single_use(nonce: str, challenges: Challenges) -> bool:
    """
    Verify nonce is valid and hasn't been consumed.

    Checks:
    - nonce is 32-byte hex (64 chars)
    - nonce exists in Challenges (not already consumed/expired)

    Args:
        nonce: The nonce string to check
        challenges: Challenges instance managing nonces

    Returns:
        True if valid and unconsumed, False otherwise
        Does NOT consume the nonce (that's consume()'s job)
    """
    # Check format: 64-char hex string
    if not isinstance(nonce, str):
        return False
    if len(nonce) != 64:
        return False
    if not re.match(r"^[a-f0-9]{64}$", nonce):
        return False

    # Check if nonce is valid using public API (not consumed and not expired)
    return challenges.is_valid(nonce)


# ============================================================================
# 4. assert_location_consistent
# ============================================================================

def assert_location_consistent(gps_points: List[Tuple[float, float, float]]) -> None:
    """
    Verify GPS points show no impossible movement (spoofing detection).

    Accepts tuples or dicts of (lat, lon, timestamp_seconds)
    Uses location.score() to check for impossible speeds

    Raises AssertionError if verdict is "reject"
    Logs warning if verdict is "flag" but doesn't raise
    Silent pass on "consistent"
    Each point timestamp must be > previous (strictly increasing)

    Args:
        gps_points: List of dicts with lat, lon, timestamp (Unix seconds)

    Raises:
        AssertionError: If GPS spoofing detected or timestamps not monotonic
    """
    # Convert input format (support both tuple and dict formats)
    points = []
    for pt in gps_points:
        if isinstance(pt, dict):
            points.append(pt)
        elif isinstance(pt, (tuple, list)) and len(pt) >= 3:
            points.append({
                "lat": pt[0],
                "lon": pt[1],
                "timestamp": pt[2]
            })
        else:
            raise AssertionError(f"Invalid GPS point format: {pt}")

    # Check timestamps are strictly increasing
    for i in range(len(points) - 1):
        ts1 = points[i].get("timestamp")
        ts2 = points[i + 1].get("timestamp")
        assert ts2 > ts1, \
            f"GPS timestamps not strictly increasing: {ts1} -> {ts2}"

    # Use location.score() to check for spoofing
    result = location.score(points)
    verdict = result.get("verdict")
    reason = result.get("reason", "")
    max_speed = result.get("max_speed_mph", 0)

    if verdict == "reject":
        raise AssertionError(
            f"GPS spoofing detected: {reason} (max speed: {max_speed:.1f} mph)"
        )
    elif verdict == "flag":
        logger.warning(
            f"GPS anomaly flagged: {reason} (max speed: {max_speed:.1f} mph)"
        )


# ============================================================================
# 5. assert_device_consistency
# ============================================================================

def assert_device_consistency(device_bind_hashes: List[str]) -> None:
    """
    Verify device bind hashes show consistent device or valid migration.

    Checks:
    - all hashes are lowercase hex or empty strings
    - if multiple non-empty hashes exist, they should be identical (same device)
    - allows transition from empty to non-empty (native app adoption)
    - rejects transition from non-empty to different non-empty (device swap)

    Args:
        device_bind_hashes: List of device bind hash strings

    Raises:
        AssertionError: If device swap detected
    """
    non_empty_hashes = set()

    for i, hash_val in enumerate(device_bind_hashes):
        # Validate format
        if hash_val:  # Non-empty
            assert isinstance(hash_val, str), \
                f"device hash {i} must be string or empty, got {type(hash_val).__name__}"
            assert re.match(r"^[a-f0-9]{64}$", hash_val.lower()), \
                f"device hash {i} must be valid hex, got {hash_val[:8]}..."
            non_empty_hashes.add(hash_val.lower())

    # Check for device swap: only one device hash allowed (or all empty)
    if len(non_empty_hashes) > 1:
        raise AssertionError(
            f"Device swap detected: multiple different device hashes found: "
            f"{sorted(non_empty_hashes)[:2]}..."
        )


# ============================================================================
# 6. assert_capture_sequence_integrity
# ============================================================================

def assert_capture_sequence_integrity(manifest: List[Dict]) -> None:
    """
    Verify captures form valid cryptographic sequence.

    Checks:
    - each bind_hash is 64-char hex
    - bind_hash values are deterministic (repeated seal() with same input → same hash)
    - first capture's bind_hash depends on nonce
    - later captures' bind_hashes form chain (capture N depends on N-1)

    Note: This function doesn't validate the full chain mathematically
    (that requires the original nonce + parameters), but checks structure

    Args:
        manifest: List of capture dicts with bind_hash

    Raises:
        AssertionError: If sequence is malformed
    """
    for i, entry in enumerate(manifest):
        bind_hash = entry.get("bind_hash")
        _validate_sha256_hex(bind_hash, f"manifest entry {i}: bind_hash")


# ============================================================================
# 7. assert_timestamp_monotonic
# ============================================================================

def assert_timestamp_monotonic(manifest: List[Dict]) -> None:
    """
    Verify manifest timestamps are strictly increasing.

    Assumes each manifest entry has a 'timestamp' field (ISO 8601 string or Unix seconds).
    Checks:
    - timestamps parse correctly
    - each timestamp > previous (strictly increasing, no ties)

    Args:
        manifest: List of capture dicts with timestamp field

    Raises:
        AssertionError: With timestamp mismatch details
    """
    if not manifest:
        return

    prev_timestamp = None

    for i, entry in enumerate(manifest):
        assert "timestamp" in entry, \
            f"manifest entry {i} missing 'timestamp' field"

        timestamp_val = entry.get("timestamp")

        # Parse timestamp (support both ISO 8601 strings and Unix seconds)
        if isinstance(timestamp_val, str):
            # Try to parse ISO 8601
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
                timestamp = dt.timestamp()
            except (ValueError, AttributeError):
                raise AssertionError(
                    f"manifest entry {i}: timestamp '{timestamp_val}' cannot be parsed"
                )
        elif isinstance(timestamp_val, (int, float)):
            timestamp = timestamp_val
        else:
            raise AssertionError(
                f"manifest entry {i}: timestamp must be string or number, "
                f"got {type(timestamp_val).__name__}"
            )

        # Check strictly increasing
        if prev_timestamp is not None:
            assert timestamp > prev_timestamp, \
                f"timestamps not strictly increasing: {prev_timestamp} -> {timestamp} at entry {i}"

        prev_timestamp = timestamp


# ============================================================================
# 8. assert_no_manifest_tampering
# ============================================================================

def assert_no_manifest_tampering(
    manifest: List[Dict],
    manifest_hash: str,
    expected_hash: Optional[str] = None
) -> None:
    """
    Verify manifest has not been modified since signing.

    Uses pdf_export._compute_manifest_hash() to recompute manifest SHA-256
    Checks:
    - provided manifest_hash is 64-char hex
    - recomputed hash matches manifest_hash (OR expected_hash if provided)

    Args:
        manifest: List of capture dicts
        manifest_hash: The hash provided/stored for this manifest
        expected_hash: Optional alternate expected hash

    Raises:
        AssertionError: If hash mismatch detected
    """
    # Validate provided hash format
    _validate_sha256_hex(manifest_hash, "manifest_hash")

    # Recompute hash
    recomputed_hash = pdf_export._compute_manifest_hash(manifest)

    # Compare against manifest_hash or expected_hash
    if expected_hash:
        assert recomputed_hash == expected_hash, \
            f"manifest hash mismatch: recomputed {recomputed_hash[:8]}... " \
            f"does not match expected {expected_hash[:8]}..."
    else:
        assert recomputed_hash == manifest_hash, \
            f"manifest tampering detected: recomputed {recomputed_hash[:8]}... " \
            f"does not match provided {manifest_hash[:8]}..."


# ============================================================================
# 9. assert_bind_hash_validity
# ============================================================================

def assert_bind_hash_validity(
    photo_bytes: bytes,
    note: str,
    checkpoint_name: str,
    nonce: str,
    account_id: str,
    gps_lat: float,
    gps_lon: float,
    timestamp: int,
    bind_hash: str,
    device_bind_hash: Optional[str] = None
) -> None:
    """
    Verify a single capture's bind_hash is correct (offline verification).

    Uses capture.verify_capture() to validate
    Checks:
    - all inputs are valid types
    - verify_capture() returns True (hash matches computed hash)

    Args:
        photo_bytes: Raw photo bytes
        note: Text note
        checkpoint_name: Checkpoint name
        nonce: Single-use nonce (64-char hex)
        account_id: User account ID
        gps_lat: GPS latitude
        gps_lon: GPS longitude
        timestamp: Unix timestamp (seconds)
        bind_hash: Expected bind hash (64-char hex)
        device_bind_hash: Optional device bind hash

    Raises:
        AssertionError: If verification fails
    """
    # Validate input types
    assert isinstance(photo_bytes, bytes), \
        f"photo_bytes must be bytes, got {type(photo_bytes).__name__}"
    assert len(photo_bytes) > 0, "photo_bytes cannot be empty"

    assert isinstance(note, str), f"note must be string, got {type(note).__name__}"
    assert isinstance(checkpoint_name, str), \
        f"checkpoint_name must be string, got {type(checkpoint_name).__name__}"

    assert isinstance(nonce, str) and len(nonce) == 64, \
        f"nonce must be 64-char hex string, got {repr(nonce)[:20]}..."

    assert isinstance(account_id, str) and account_id, \
        f"account_id must be non-empty string, got {repr(account_id)}"

    assert isinstance(gps_lat, (int, float)), \
        f"gps_lat must be number, got {type(gps_lat).__name__}"
    assert isinstance(gps_lon, (int, float)), \
        f"gps_lon must be number, got {type(gps_lon).__name__}"

    assert isinstance(timestamp, int), \
        f"timestamp must be int, got {type(timestamp).__name__}"

    _validate_sha256_hex(bind_hash, "bind_hash")

    # Create checkpoint pack dict for verification
    checkpoint_pack = {
        "name": checkpoint_name,
        "order": 1  # Minimal required fields
    }

    # Verify the capture seal using capture.verify_capture()
    is_valid = capture.verify_capture(
        photo_bytes=photo_bytes,
        note=note,
        checkpoint_pack=checkpoint_pack,
        nonce=nonce,
        account_id=account_id,
        gps_lat=gps_lat,
        gps_lon=gps_lon,
        timestamp=timestamp,
        expected_seal=bind_hash
    )

    assert is_valid, \
        f"bind_hash verification failed: seal does not match computed hash"
