"""
Shield Capture Core Layer
Single-use nonce management, seal binding, and offline verification.

This module provides the foundation for immutable chain links:
- Challenges: Single-use nonce manager with 120s TTL
- seal(): Bind photo+note+checkpoint+nonce+account+GPS into SHA256 chain link
- verify_capture(): Offline verification of seals (constant-time compare)
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Optional

# Constants
NONCE_BYTES = 32  # 32 bytes = 64-character hex string


class Challenges:
    """
    Single-use nonce manager with 120-second TTL.

    Each nonce is a random 32-byte hex string that can be consumed exactly once
    within 120 seconds of issuance. After consumption or expiry, the nonce is invalid.
    """

    TTL_SECONDS = 120

    def __init__(self):
        """Initialize challenge manager with empty nonce store."""
        self._challenges: Dict[str, float] = {}

    def issue(self, account_id: str) -> str:
        """
        Generate a random 32-byte hex nonce with 120-second TTL.

        Args:
            account_id: User account ID (for tracking purposes, not used in nonce generation)

        Returns:
            Random 64-character hex string (32 bytes)
        """
        # Generate random bytes and convert to hex
        nonce = secrets.token_hex(NONCE_BYTES)

        # Store nonce with current timestamp for TTL tracking
        self._challenges[nonce] = time.time()

        return nonce

    def consume(self, nonce: str) -> bool:
        """
        Check if nonce exists and hasn't expired, then delete it (single-use).

        Args:
            nonce: The nonce string to consume

        Returns:
            True if nonce was valid and consumed, False if already consumed or expired
        """
        # Check if nonce exists
        if nonce not in self._challenges:
            return False

        # Get issue time
        issue_time = self._challenges[nonce]
        current_time = time.time()

        # Check if expired (120 second TTL)
        if current_time - issue_time >= self.TTL_SECONDS:
            # Clean up expired nonce
            del self._challenges[nonce]
            return False

        # Nonce is valid, delete it (single-use)
        del self._challenges[nonce]
        return True


def _compute_seal_hash(
    photo_bytes: bytes,
    note: str,
    checkpoint_pack: dict,
    nonce: str,
    account_id: str,
    gps_lat: float,
    gps_lon: float,
    timestamp: int
) -> str:
    """
    Internal helper to compute the SHA256 hash of capture data.

    Returns:
        64-character hex SHA256 hash
    """
    # Construct the data to be sealed
    # Order matters for reproducibility
    data_to_seal = b""

    # 1. Photo bytes (raw binary)
    data_to_seal += photo_bytes

    # 2. Note (as UTF-8)
    data_to_seal += note.encode('utf-8')

    # 3. Checkpoint pack (as JSON, sorted keys for reproducibility)
    checkpoint_json = json.dumps(checkpoint_pack, sort_keys=True, separators=(',', ':'))
    data_to_seal += checkpoint_json.encode('utf-8')

    # 4. Nonce (as UTF-8)
    data_to_seal += nonce.encode('utf-8')

    # 5. Account ID (as UTF-8)
    data_to_seal += account_id.encode('utf-8')

    # 6. GPS coordinates (as formatted string for reproducibility)
    # GPS: fixed 10 decimal places (~1.1mm precision) for reproducible serialization
    gps_str = f"{gps_lat:.10f},{gps_lon:.10f}"
    data_to_seal += gps_str.encode('utf-8')

    # 7. Timestamp (as string for reproducibility)
    data_to_seal += str(timestamp).encode('utf-8')

    # Compute SHA256
    seal_hash = hashlib.sha256(data_to_seal).hexdigest()

    return seal_hash


def seal(
    photo_bytes: bytes,
    note: str,
    checkpoint_pack: dict,
    nonce: str,
    account_id: str,
    gps_lat: float,
    gps_lon: float,
    timestamp: int,
    device_bind_hash: Optional[str] = None
) -> dict:
    """
    Bind photo+note+checkpoint+nonce+account+GPS into immutable SHA256 chain link.

    Creates a SHA256 hash of all capture data, binding the photo, note,
    checkpoint configuration, nonce, account ID, GPS coordinates, and timestamp
    into a single immutable hash that can later be verified offline.

    If device_bind_hash is provided (native app), verifies device consistency.

    Args:
        photo_bytes: Raw photo data (bytes)
        note: Text note accompanying the photo
        checkpoint_pack: Checkpoint configuration dict
        nonce: Single-use nonce (64-char hex string)
        account_id: User account ID
        gps_lat: GPS latitude
        gps_lon: GPS longitude
        timestamp: Unix timestamp (seconds)
        device_bind_hash: Optional device digest hash from native app (case-insensitive)

    Returns:
        dict with:
            bind_hash: 64-character hex SHA256 hash
            bind_ok: None (no device hash, web capture), True (match), False (mismatch)

    Raises:
        ValueError: If photo_bytes is empty or account_id is missing
    """
    # Input validation
    if not photo_bytes:
        raise ValueError("photo_bytes cannot be empty")
    if not account_id:
        raise ValueError("account_id is required")

    # Compute the seal hash
    bind_hash = _compute_seal_hash(
        photo_bytes=photo_bytes,
        note=note,
        checkpoint_pack=checkpoint_pack,
        nonce=nonce,
        account_id=account_id,
        gps_lat=gps_lat,
        gps_lon=gps_lon,
        timestamp=timestamp
    )

    # Compare device digest if provided (case-insensitive, whitespace-trimmed)
    posted = (device_bind_hash or "").strip().lower() or None
    bind_ok = None if posted is None else posted == bind_hash

    return {
        "bind_hash": bind_hash,
        "bind_ok": bind_ok
    }


def verify_capture(
    photo_bytes: bytes,
    note: str,
    checkpoint_pack: dict,
    nonce: str,
    account_id: str,
    gps_lat: float,
    gps_lon: float,
    timestamp: int,
    expected_seal: str
) -> bool:
    """
    Offline verification of capture seal using constant-time comparison.

    Recomputes the seal hash from provided data and compares it to the expected
    seal using constant-time comparison to prevent timing attacks.

    Works entirely offline - requires no external services or network access.

    Args:
        photo_bytes: Raw photo data (bytes)
        note: Text note accompanying the photo
        checkpoint_pack: Checkpoint configuration dict
        nonce: Single-use nonce (64-char hex string)
        account_id: User account ID
        gps_lat: GPS latitude
        gps_lon: GPS longitude
        timestamp: Unix timestamp (seconds)
        expected_seal: The seal hash to verify against (64-char hex string)

    Returns:
        True if seal matches, False otherwise

    Raises:
        ValueError: If photo_bytes is empty or account_id is missing
    """
    # Input validation
    if not photo_bytes:
        raise ValueError("photo_bytes cannot be empty")
    if not account_id:
        raise ValueError("account_id is required")

    # Compute the seal hash directly (without device_bind_hash)
    computed_seal = _compute_seal_hash(
        photo_bytes=photo_bytes,
        note=note,
        checkpoint_pack=checkpoint_pack,
        nonce=nonce,
        account_id=account_id,
        gps_lat=gps_lat,
        gps_lon=gps_lon,
        timestamp=timestamp
    )

    # Constant-time comparison to prevent timing attacks
    # hmac.compare_digest uses a constant-time algorithm
    return hmac.compare_digest(computed_seal, expected_seal)
