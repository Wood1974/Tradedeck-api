"""
Test fixtures and mock data for Shield Capture v1 E2E integration tests.

Provides:
- Realistic capture sequences (remodel, insurance_loss, rental_unit)
- GPS traces with various movement patterns
- Device binding scenarios
- Timestamp sequences
"""

import json
import time
import hashlib
from typing import Dict, List, Tuple, Optional
import pytest

import capture
import location
import packs
import pdf_export


# ============================================================================
# Photo Fixtures
# ============================================================================

def get_valid_jpeg_bytes() -> bytes:
    """Return minimal valid JPEG bytes for testing."""
    # Minimal JPEG: SOI marker, EOI marker
    return b'\xff\xd8\xff\xd9'


def get_corrupted_jpeg_bytes() -> bytes:
    """Return invalid JPEG bytes."""
    return b'not a real jpeg'


def get_oversized_photo_bytes() -> bytes:
    """Return 10MB of photo data."""
    return b'x' * (10 * 1024 * 1024)


# ============================================================================
# GPS Fixtures
# ============================================================================

def get_stationary_gps() -> List[Dict]:
    """GPS points with no movement (stationary site)."""
    base_time = int(time.time())
    lat, lon = 40.7128, -74.0060  # NYC
    return [
        {"lat": lat, "lon": lon, "timestamp": base_time + i * 60}
        for i in range(5)
    ]


def get_valid_trip_gps() -> List[Dict]:
    """GPS points showing realistic trip (5 points over 25 minutes)."""
    base_time = int(time.time())
    # NYC to 5 miles away (reasonable trip)
    points = [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": base_time},        # Start
        {"lat": 40.7150, "lon": -74.0100, "timestamp": base_time + 300},  # 5 min
        {"lat": 40.7180, "lon": -74.0150, "timestamp": base_time + 600},  # 10 min
        {"lat": 40.7200, "lon": -74.0180, "timestamp": base_time + 900},  # 15 min
        {"lat": 40.7228, "lon": -74.0220, "timestamp": base_time + 1200}, # 20 min
        {"lat": 40.7250, "lon": -74.0260, "timestamp": base_time + 1500}, # 25 min
    ]
    return points


def get_spoofed_gps() -> List[Dict]:
    """GPS points showing impossible speeds (spoofing)."""
    base_time = int(time.time())
    # Jump 500 miles in 1 second (impossible)
    return [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": base_time},
        {"lat": 41.8781, "lon": -87.6298, "timestamp": base_time + 1},  # Chicago
    ]


def get_unrealistic_gps() -> List[Dict]:
    """GPS points showing unrealistic speeds (~150 mph)."""
    base_time = int(time.time())
    return [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": base_time},
        {"lat": 41.0000, "lon": -74.0000, "timestamp": base_time + 60},  # ~20 miles in 60 sec
    ]


# ============================================================================
# Device Binding Fixtures
# ============================================================================

def get_consistent_device_hashes() -> List[str]:
    """Same device hash for all captures."""
    device_hash = 'a' * 64  # Valid SHA256 hex
    return [device_hash] * 5


def get_device_adoption_sequence() -> List[str]:
    """Sequence showing adoption of device binding (empty → hash)."""
    return [
        '',                    # No device binding
        '',                    # Still no device
        'b' * 64,             # Device binding adopted
        'b' * 64,             # Same device
        'b' * 64,             # Same device
    ]


def get_device_swap_hashes() -> List[str]:
    """Multiple different device hashes (device swap)."""
    return [
        'a' * 64,
        'a' * 64,
        'b' * 64,  # Different device hash (invalid)
        'b' * 64,
    ]


# ============================================================================
# Timestamp Fixtures
# ============================================================================

def get_valid_monotonic_timestamps() -> List[int]:
    """Strictly increasing Unix timestamps."""
    base_time = int(time.time())
    return [base_time + (i * 300) for i in range(5)]  # 5 min apart


def get_skewed_timestamps() -> List[int]:
    """Timestamps with clock skew (out of order)."""
    base_time = int(time.time())
    return [
        base_time,
        base_time + 300,
        base_time + 200,  # Goes backward
        base_time + 500,
    ]


def get_duplicate_timestamps() -> List[int]:
    """Same timestamp for multiple entries (not strictly increasing)."""
    base_time = int(time.time())
    return [base_time, base_time, base_time + 300, base_time + 600]


# ============================================================================
# Pack Fixtures
# ============================================================================

@pytest.fixture
def remodel_pack() -> Dict:
    """Remodel pack definition."""
    return packs.get_pack("remodel")


@pytest.fixture
def insurance_loss_pack() -> Dict:
    """Insurance loss pack definition."""
    return packs.get_pack("insurance_loss")


@pytest.fixture
def rental_unit_pack() -> Dict:
    """Rental unit pack definition."""
    return packs.get_pack("rental_unit")


@pytest.fixture
def lender_draw_pack() -> Dict:
    """Lender draw pack definition."""
    return packs.get_pack("lender_draw")


# ============================================================================
# Manifest/Capture Sequence Fixtures
# ============================================================================

@pytest.fixture
def challenges() -> capture.Challenges:
    """Fresh Challenges instance for testing."""
    return capture.Challenges()


def create_capture_dict(
    checkpoint_name: str,
    photo_bytes: bytes,
    note: str,
    bind_hash: str,
    timestamp: int = None
) -> Dict:
    """Create a capture dict for manifest."""
    if timestamp is None:
        timestamp = int(time.time())

    return {
        "checkpoint_name": checkpoint_name,
        "photo_bytes": photo_bytes,
        "note": note,
        "bind_hash": bind_hash,
        "timestamp": timestamp,
    }


@pytest.fixture
def valid_remodel_manifest(remodel_pack, challenges) -> Dict:
    """
    Complete, valid 5-checkpoint remodel manifest.

    Returns dict with:
    - manifest: list of 5 captures
    - nonce: consumed nonce
    - gps_points: stationary GPS trace
    - account_id: test user
    - pack: remodel pack definition
    """
    pack = packs.get_pack("remodel")
    nonce = challenges.issue("test_user")
    gps = get_stationary_gps()
    account_id = "test_user"

    photo = get_valid_jpeg_bytes()
    base_time = int(time.time())

    manifest = []
    for i, point in enumerate(pack["points"]):
        cp_pack = {"name": point["name"], "order": point["order"]}
        bind_result = capture.seal(
            photo_bytes=photo,
            note=f"Note for {point['name']}",
            checkpoint_pack=cp_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps[i]["lat"],
            gps_lon=gps[i]["lon"],
            timestamp=base_time + (i * 300),
        )

        manifest.append({
            "checkpoint_name": point["name"],
            "photo_bytes": photo,
            "note": f"Note for {point['name']}",
            "bind_hash": bind_result["bind_hash"],
            "timestamp": base_time + (i * 300),
        })

    return {
        "manifest": manifest,
        "nonce": nonce,
        "gps_points": gps,
        "account_id": account_id,
        "pack": pack,
    }


@pytest.fixture
def valid_insurance_manifest(challenges) -> Dict:
    """Complete, valid 5-checkpoint insurance loss manifest."""
    pack = packs.get_pack("insurance_loss")
    nonce = challenges.issue("test_user")
    gps = get_stationary_gps()
    account_id = "test_user"

    photo = get_valid_jpeg_bytes()
    base_time = int(time.time())

    manifest = []
    for i, point in enumerate(pack["points"]):
        cp_pack = {"name": point["name"], "order": point["order"]}
        bind_result = capture.seal(
            photo_bytes=photo,
            note=f"Insurance documentation: {point['name']}",
            checkpoint_pack=cp_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps[i]["lat"],
            gps_lon=gps[i]["lon"],
            timestamp=base_time + (i * 300),
        )

        manifest.append({
            "checkpoint_name": point["name"],
            "photo_bytes": photo,
            "note": f"Insurance documentation: {point['name']}",
            "bind_hash": bind_result["bind_hash"],
            "timestamp": base_time + (i * 300),
        })

    return {
        "manifest": manifest,
        "nonce": nonce,
        "gps_points": gps,
        "account_id": account_id,
        "pack": pack,
    }


@pytest.fixture
def valid_rental_manifest(challenges) -> Dict:
    """Complete, valid 5-checkpoint rental unit manifest."""
    pack = packs.get_pack("rental_unit")
    nonce = challenges.issue("test_user")
    gps = get_stationary_gps()
    account_id = "test_user"

    photo = get_valid_jpeg_bytes()
    base_time = int(time.time())

    manifest = []
    for i, point in enumerate(pack["points"]):
        cp_pack = {"name": point["name"], "order": point["order"]}
        bind_result = capture.seal(
            photo_bytes=photo,
            note=f"Rental assessment: {point['name']}",
            checkpoint_pack=cp_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps[i]["lat"],
            gps_lon=gps[i]["lon"],
            timestamp=base_time + (i * 300),
        )

        manifest.append({
            "checkpoint_name": point["name"],
            "photo_bytes": photo,
            "note": f"Rental assessment: {point['name']}",
            "bind_hash": bind_result["bind_hash"],
            "timestamp": base_time + (i * 300),
        })

    return {
        "manifest": manifest,
        "nonce": nonce,
        "gps_points": gps,
        "account_id": account_id,
        "pack": pack,
    }


# ============================================================================
# GPS Trace Fixtures
# ============================================================================

@pytest.fixture
def stationary_gps():
    """GPS trace with no movement."""
    return get_stationary_gps()


@pytest.fixture
def valid_trip_gps():
    """GPS trace showing realistic movement."""
    return get_valid_trip_gps()


@pytest.fixture
def spoofed_gps():
    """GPS trace showing impossible speeds."""
    return get_spoofed_gps()


@pytest.fixture
def unrealistic_gps():
    """GPS trace showing unrealistic speeds."""
    return get_unrealistic_gps()


# ============================================================================
# Device Binding Fixtures
# ============================================================================

@pytest.fixture
def consistent_device_hashes():
    """Same device hash throughout."""
    return get_consistent_device_hashes()


@pytest.fixture
def device_adoption_sequence():
    """Device binding adoption sequence."""
    return get_device_adoption_sequence()


@pytest.fixture
def device_swap_hashes():
    """Multiple different device hashes."""
    return get_device_swap_hashes()


# ============================================================================
# Photo Fixtures
# ============================================================================

@pytest.fixture
def valid_photo():
    """Valid JPEG photo bytes."""
    return get_valid_jpeg_bytes()


@pytest.fixture
def corrupted_photo():
    """Corrupted/invalid photo bytes."""
    return get_corrupted_jpeg_bytes()


@pytest.fixture
def oversized_photo():
    """10MB photo bytes."""
    return get_oversized_photo_bytes()
