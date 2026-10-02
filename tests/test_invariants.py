"""
Test suite for Shield Capture v1 security invariants.

Tests validation of:
- Evidence chain integrity (manifests are valid, immutable, sequential)
- Checkpoint consistency (captures match pack definitions)
- Nonce exhaustion (challenges consumed exactly once)
- GPS spoofing detection (location consistency checks pass)
- Device binding consistency (device hashes are stable or change predictably)
"""

import pytest
import time
from datetime import datetime, timedelta
from audit.invariants import (
    assert_manifest_structure,
    assert_pack_checkpoint_correspondence,
    assert_nonce_single_use,
    assert_location_consistent,
    assert_device_consistency,
    assert_capture_sequence_integrity,
    assert_timestamp_monotonic,
    assert_no_manifest_tampering,
    assert_bind_hash_validity,
)
from capture import Challenges, seal, verify_capture
import packs
import pdf_export


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def valid_manifest():
    """Valid manifest with all required fields."""
    return [
        {
            "checkpoint_name": "Foundation Inspection",
            "photo_bytes": b"fake photo data 1",
            "note": "Foundation looks good",
            "bind_hash": "a" * 64,  # Valid 64-char hex
        },
        {
            "checkpoint_name": "Framing Check",
            "photo_bytes": b"fake photo data 2",
            "note": "Framing is level",
            "bind_hash": "b" * 64,
        },
    ]


@pytest.fixture
def valid_pack():
    """Valid pack from packs module."""
    return packs.get_pack("remodel")


@pytest.fixture
def challenges():
    """Fresh Challenges instance for nonce testing."""
    return Challenges()


@pytest.fixture
def valid_gps_points():
    """Valid GPS points showing stationary location."""
    now = int(time.time())
    return [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now},
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now + 5},
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now + 10},
    ]


# ============================================================================
# 1. Manifest Structure Validation (6 tests)
# ============================================================================

def test_assert_manifest_structure_valid(valid_manifest):
    """Valid manifest should pass validation."""
    assert_manifest_structure(valid_manifest)  # Should not raise


def test_assert_manifest_structure_empty_valid():
    """Empty manifest should be valid (valid list, just no entries)."""
    # An empty list is structurally valid, just with no captures
    assert_manifest_structure([])  # Should not raise


def test_assert_manifest_structure_not_a_list():
    """Non-list manifest should fail."""
    with pytest.raises(AssertionError, match="list"):
        assert_manifest_structure({"checkpoint_name": "test"})


def test_assert_manifest_structure_missing_checkpoint_name():
    """Entry missing checkpoint_name should fail."""
    manifest = [
        {
            "photo_bytes": b"fake",
            "note": "test",
            "bind_hash": "a" * 64,
        }
    ]
    with pytest.raises(AssertionError, match="checkpoint_name"):
        assert_manifest_structure(manifest)


def test_assert_manifest_structure_invalid_bind_hash():
    """Invalid bind_hash (not 64-char hex) should fail."""
    manifest = [
        {
            "checkpoint_name": "Test",
            "photo_bytes": b"fake",
            "note": "test",
            "bind_hash": "not_hex_or_too_short",  # Invalid
        }
    ]
    with pytest.raises(AssertionError, match="bind_hash"):
        assert_manifest_structure(manifest)


def test_assert_manifest_structure_non_bytes_photo():
    """Non-bytes photo_bytes should fail."""
    manifest = [
        {
            "checkpoint_name": "Test",
            "photo_bytes": "not bytes",  # Invalid
            "note": "test",
            "bind_hash": "a" * 64,
        }
    ]
    with pytest.raises(AssertionError, match="photo_bytes"):
        assert_manifest_structure(manifest)


def test_assert_manifest_structure_empty_photo_bytes():
    """Empty photo_bytes should fail."""
    manifest = [
        {
            "checkpoint_name": "Test",
            "photo_bytes": b"",  # Empty
            "note": "test",
            "bind_hash": "a" * 64,
        }
    ]
    with pytest.raises(AssertionError, match="photo_bytes"):
        assert_manifest_structure(manifest)


# ============================================================================
# 2. Pack Checkpoint Correspondence (6 tests)
# ============================================================================

def test_assert_pack_checkpoint_correspondence_perfect_match(valid_manifest, valid_pack):
    """Manifest checkpoints perfectly matching pack should pass."""
    # Create manifest matching the remodel pack's 5 checkpoints
    remodel_pack = packs.get_pack("remodel")
    manifest = [
        {
            "checkpoint_name": remodel_pack["points"][i]["name"],
            "photo_bytes": b"test",
            "note": f"Checkpoint {i}",
            "bind_hash": chr(ord('a') + i) * 64,
        }
        for i in range(len(remodel_pack["points"]))
    ]
    assert_pack_checkpoint_correspondence(manifest, remodel_pack)  # Should not raise


def test_assert_pack_checkpoint_correspondence_manifest_too_short():
    """Manifest with fewer captures than pack should fail."""
    pack = packs.get_pack("remodel")  # 5 checkpoints
    manifest = [
        {
            "checkpoint_name": pack["points"][0]["name"],
            "photo_bytes": b"test",
            "note": "Only one",
            "bind_hash": "a" * 64,
        }
    ]
    with pytest.raises(AssertionError, match="manifest has|captures but pack"):
        assert_pack_checkpoint_correspondence(manifest, pack)


def test_assert_pack_checkpoint_correspondence_manifest_too_long():
    """Manifest with more captures than pack should fail."""
    pack = packs.get_pack("remodel")  # 5 checkpoints
    manifest = [
        {
            "checkpoint_name": pack["points"][i]["name"],
            "photo_bytes": b"test",
            "note": f"Checkpoint {i}",
            "bind_hash": chr(ord('a') + i) * 64,
        }
        for i in range(len(pack["points"]))
    ] + [
        {
            "checkpoint_name": "Extra checkpoint",
            "photo_bytes": b"test",
            "note": "Extra",
            "bind_hash": "z" * 64,
        }
    ]
    with pytest.raises(AssertionError, match="manifest has|captures but pack"):
        assert_pack_checkpoint_correspondence(manifest, pack)


def test_assert_pack_checkpoint_correspondence_names_mismatch():
    """Checkpoint names not matching pack should fail."""
    pack = packs.get_pack("remodel")
    manifest = [
        {
            "checkpoint_name": "WRONG NAME",  # Mismatch
            "photo_bytes": b"test",
            "note": "Test",
            "bind_hash": "a" * 64,
        },
        {
            "checkpoint_name": pack["points"][1]["name"],
            "photo_bytes": b"test",
            "note": "Test",
            "bind_hash": "b" * 64,
        },
        {
            "checkpoint_name": pack["points"][2]["name"],
            "photo_bytes": b"test",
            "note": "Test",
            "bind_hash": "c" * 64,
        },
        {
            "checkpoint_name": pack["points"][3]["name"],
            "photo_bytes": b"test",
            "note": "Test",
            "bind_hash": "d" * 64,
        },
        {
            "checkpoint_name": pack["points"][4]["name"],
            "photo_bytes": b"test",
            "note": "Test",
            "bind_hash": "e" * 64,
        },
    ]
    with pytest.raises(AssertionError, match="mismatch|name"):
        assert_pack_checkpoint_correspondence(manifest, pack)


def test_assert_pack_checkpoint_correspondence_duplicate_names():
    """Duplicate checkpoint names should fail."""
    pack = packs.get_pack("remodel")
    manifest = [
        {
            "checkpoint_name": "Duplicate",
            "photo_bytes": b"test",
            "note": "First",
            "bind_hash": "a" * 64,
        },
        {
            "checkpoint_name": "Duplicate",  # Duplicate
            "photo_bytes": b"test",
            "note": "Second",
            "bind_hash": "b" * 64,
        },
        {
            "checkpoint_name": pack["points"][2]["name"],
            "photo_bytes": b"test",
            "note": "Third",
            "bind_hash": "c" * 64,
        },
        {
            "checkpoint_name": pack["points"][3]["name"],
            "photo_bytes": b"test",
            "note": "Fourth",
            "bind_hash": "d" * 64,
        },
        {
            "checkpoint_name": pack["points"][4]["name"],
            "photo_bytes": b"test",
            "note": "Fifth",
            "bind_hash": "e" * 64,
        },
    ]
    with pytest.raises(AssertionError, match="duplicate"):
        assert_pack_checkpoint_correspondence(manifest, pack)


# ============================================================================
# 3. Nonce Validation (4 tests)
# ============================================================================

def test_assert_nonce_single_use_valid_unconsumed(challenges):
    """Valid unconsumed nonce should return True."""
    nonce = challenges.issue("test_account")
    result = assert_nonce_single_use(nonce, challenges)
    assert result is True


def test_assert_nonce_single_use_invalid_format():
    """Invalid nonce format should return False."""
    challenges = Challenges()
    invalid_nonces = [
        "too_short",
        "not_hex_chars_!@#$%^&*()",
        "",
        "a" * 63,  # One char short
    ]
    for nonce in invalid_nonces:
        result = assert_nonce_single_use(nonce, challenges)
        assert result is False


def test_assert_nonce_single_use_already_consumed(challenges):
    """Consumed nonce should return False."""
    nonce = challenges.issue("test_account")
    challenges.consume(nonce)  # Consume it
    result = assert_nonce_single_use(nonce, challenges)
    assert result is False


def test_assert_nonce_single_use_expired(challenges):
    """Expired nonce should return False."""
    nonce = challenges.issue("test_account")
    # Manually set expiration time in the past
    challenges._challenges[nonce] = time.time() - 121  # 121 seconds ago
    result = assert_nonce_single_use(nonce, challenges)
    assert result is False


# ============================================================================
# 4. Location Consistency (4 tests)
# ============================================================================

def test_assert_location_consistent_stationary(valid_gps_points):
    """Stationary GPS points should pass."""
    assert_location_consistent(valid_gps_points)  # Should not raise


def test_assert_location_consistent_impossible_speed():
    """Impossible speed (>250 mph) should raise AssertionError."""
    now = int(time.time())
    # Two points 1000 km apart, 10 seconds apart = 250,000+ mph
    points = [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now},
        {"lat": 50.0, "lon": 10.0, "timestamp": now + 10},  # Huge distance
    ]
    with pytest.raises(AssertionError):
        assert_location_consistent(points)


def test_assert_location_consistent_unrealistic_speed(caplog):
    """Unrealistic speed (>120 mph) should log warning but not raise."""
    now = int(time.time())
    # Create distance that results in ~150 mph (unrealistic but not impossible)
    # ~5 km in 120 seconds = ~2.5 km/min = 150 km/h ≈ 93 mph (too slow)
    # Let's use ~25 km in 60 seconds = 1500 km/h ≈ 930 mph (impossible)
    # Actually, let me use ~7 km in 30 seconds = 840 km/h ≈ 520 mph (impossible)
    # Let me use ~2 km in 60 seconds = 120 km/h ≈ 75 mph (ok)
    # Let me use ~4 km in 60 seconds = 240 km/h ≈ 150 mph (unrealistic)
    points = [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now},
        {"lat": 40.75, "lon": -74.0, "timestamp": now + 60},  # ~4 km at 60 seconds ≈ 240 km/h ≈ 150 mph
    ]
    with caplog.at_level("WARNING"):
        assert_location_consistent(points)
    # Warning should be logged but no exception raised
    assert "flag" in caplog.text.lower() or "warning" in caplog.text.lower() or len(caplog.records) > 0


def test_assert_location_consistent_non_monotonic_timestamps():
    """Non-monotonic timestamps should raise AssertionError."""
    now = int(time.time())
    points = [
        {"lat": 40.7128, "lon": -74.0060, "timestamp": now},
        {"lat": 40.7129, "lon": -74.0059, "timestamp": now - 5},  # Time goes backwards
    ]
    with pytest.raises(AssertionError):
        assert_location_consistent(points)


# ============================================================================
# 5. Device Consistency (3 tests)
# ============================================================================

def test_assert_device_consistency_all_identical():
    """All identical device hashes should pass."""
    hashes = ["a" * 64, "a" * 64, "a" * 64]
    assert_device_consistency(hashes)  # Should not raise


def test_assert_device_consistency_empty_to_nonempty():
    """Transition from empty to non-empty hash (native app adoption) should pass."""
    hashes = ["", "", "b" * 64]
    assert_device_consistency(hashes)  # Should not raise


def test_assert_device_consistency_device_swap():
    """Transition from one non-empty hash to different non-empty hash should fail."""
    hashes = ["a" * 64, "b" * 64]  # Device swap
    with pytest.raises(AssertionError, match="device|swap"):
        assert_device_consistency(hashes)


# ============================================================================
# 6. Capture Sequence Integrity (2 tests)
# ============================================================================

def test_assert_capture_sequence_integrity_valid():
    """Valid bind_hash sequence should pass."""
    manifest = [
        {
            "checkpoint_name": "Test1",
            "photo_bytes": b"data1",
            "note": "Note1",
            "bind_hash": "a" * 64,  # Valid hex
        },
        {
            "checkpoint_name": "Test2",
            "photo_bytes": b"data2",
            "note": "Note2",
            "bind_hash": "b" * 64,  # Valid hex
        },
    ]
    assert_capture_sequence_integrity(manifest)  # Should not raise


def test_assert_capture_sequence_integrity_malformed_hash():
    """Malformed bind_hash should fail."""
    manifest = [
        {
            "checkpoint_name": "Test1",
            "photo_bytes": b"data1",
            "note": "Note1",
            "bind_hash": "not_valid_hex",  # Invalid
        },
    ]
    with pytest.raises(AssertionError, match="bind_hash|format|hex"):
        assert_capture_sequence_integrity(manifest)


# ============================================================================
# 7. Timestamp Monotonicity (2 tests)
# ============================================================================

def test_assert_timestamp_monotonic_strictly_increasing():
    """Strictly increasing timestamps should pass."""
    manifest = [
        {
            "checkpoint_name": "Test1",
            "photo_bytes": b"data1",
            "note": "Note1",
            "bind_hash": "a" * 64,
            "timestamp": 1000,
        },
        {
            "checkpoint_name": "Test2",
            "photo_bytes": b"data2",
            "note": "Note2",
            "bind_hash": "b" * 64,
            "timestamp": 1001,
        },
        {
            "checkpoint_name": "Test3",
            "photo_bytes": b"data3",
            "note": "Note3",
            "bind_hash": "c" * 64,
            "timestamp": 2000,
        },
    ]
    assert_timestamp_monotonic(manifest)  # Should not raise


def test_assert_timestamp_monotonic_not_increasing():
    """Non-increasing timestamps should fail."""
    manifest = [
        {
            "checkpoint_name": "Test1",
            "photo_bytes": b"data1",
            "note": "Note1",
            "bind_hash": "a" * 64,
            "timestamp": 1000,
        },
        {
            "checkpoint_name": "Test2",
            "photo_bytes": b"data2",
            "note": "Note2",
            "bind_hash": "b" * 64,
            "timestamp": 999,  # Goes backwards
        },
    ]
    with pytest.raises(AssertionError, match="monotonic|increasing"):
        assert_timestamp_monotonic(manifest)


# ============================================================================
# 8. Manifest Tampering Detection (2 tests)
# ============================================================================

def test_assert_no_manifest_tampering_unmodified(valid_manifest):
    """Unmodified manifest should pass."""
    manifest_hash = pdf_export._compute_manifest_hash(valid_manifest)
    assert_no_manifest_tampering(valid_manifest, manifest_hash)  # Should not raise


def test_assert_no_manifest_tampering_modified(valid_manifest):
    """Modified manifest should fail."""
    original_hash = pdf_export._compute_manifest_hash(valid_manifest)
    # Modify the manifest
    valid_manifest[0]["note"] = "MODIFIED NOTE"
    with pytest.raises(AssertionError, match="tampering|mismatch|hash"):
        assert_no_manifest_tampering(valid_manifest, original_hash)


# ============================================================================
# 9. Bind Hash Offline Verification (3 tests)
# ============================================================================

def test_assert_bind_hash_validity_correct_hash():
    """Valid capture with correct hash should pass."""
    photo_bytes = b"test photo data"
    note = "Test note"
    checkpoint_pack = {"order": 1, "name": "Test checkpoint"}
    checkpoint_name = "Test checkpoint"
    nonce = "a" * 64
    account_id = "test_account"
    gps_lat = 40.7128
    gps_lon = -74.0060
    timestamp = 1000000000

    # Compute the correct bind_hash
    result = seal(photo_bytes, note, checkpoint_pack, nonce, account_id, gps_lat, gps_lon, timestamp)
    bind_hash = result["bind_hash"]

    # Verify should pass (pass checkpoint_name string, not pack dict)
    assert_bind_hash_validity(
        photo_bytes, note, checkpoint_name, nonce, account_id, gps_lat, gps_lon, timestamp, bind_hash
    )  # Should not raise


def test_assert_bind_hash_validity_incorrect_hash():
    """Capture with incorrect hash should fail."""
    photo_bytes = b"test photo data"
    note = "Test note"
    checkpoint_pack = {"order": 1, "name": "Test checkpoint"}
    checkpoint_name = "Test checkpoint"
    nonce = "a" * 64
    account_id = "test_account"
    gps_lat = 40.7128
    gps_lon = -74.0060
    timestamp = 1000000000
    wrong_hash = "b" * 64  # Wrong hash

    with pytest.raises(AssertionError, match="hash|verify|invalid"):
        assert_bind_hash_validity(
            photo_bytes, note, checkpoint_name, nonce, account_id, gps_lat, gps_lon, timestamp, wrong_hash
        )


def test_assert_bind_hash_validity_invalid_input_types():
    """Invalid input types should fail."""
    with pytest.raises((AssertionError, ValueError, TypeError)):
        assert_bind_hash_validity(
            "not bytes",  # Invalid: should be bytes
            "Test note",
            {"order": 1, "name": "Test"},
            "a" * 64,
            "test_account",
            40.7128,
            -74.0060,
            1000000000,
            "b" * 64
        )


# ============================================================================
# Integration Tests
# ============================================================================

def test_full_capture_workflow():
    """End-to-end test: create nonce, seal capture, verify manifest."""
    # 1. Create a nonce
    challenges = Challenges()
    nonce = challenges.issue("test_account")

    # 2. Create a minimal checkpoint pack (matches what assert_bind_hash_validity creates)
    checkpoint_pack = {"name": "Foundation Inspection", "order": 1}
    checkpoint_name = "Foundation Inspection"

    # 3. Use consistent timestamp throughout
    timestamp = int(time.time())

    # 4. Seal a capture
    photo_bytes = b"real photo data"
    note = "Foundation inspection complete"
    result = seal(
        photo_bytes=photo_bytes,
        note=note,
        checkpoint_pack=checkpoint_pack,
        nonce=nonce,
        account_id="test_account",
        gps_lat=40.7128,
        gps_lon=-74.0060,
        timestamp=timestamp,
    )
    bind_hash = result["bind_hash"]

    # 5. Create manifest
    manifest = [
        {
            "checkpoint_name": checkpoint_name,
            "photo_bytes": photo_bytes,
            "note": note,
            "bind_hash": bind_hash,
            "timestamp": timestamp,
        }
    ]

    # 6. Verify manifest structure
    assert_manifest_structure(manifest)

    # 7. Verify timestamp is monotonic
    assert_timestamp_monotonic(manifest)

    # 8. Verify bind hash (now should pass with matching checkpoint pack structure)
    assert_bind_hash_validity(
        photo_bytes=photo_bytes,
        note=note,
        checkpoint_name=checkpoint_name,
        nonce=nonce,
        account_id="test_account",
        gps_lat=40.7128,
        gps_lon=-74.0060,
        timestamp=timestamp,
        bind_hash=bind_hash
    )
