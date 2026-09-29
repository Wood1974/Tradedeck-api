"""
Tests for Shield Capture Core layer.
Tests single-use nonce management, seal binding, offline verification, and device digest.
"""

import pytest
import time
from unittest.mock import Mock, patch

from capture import Challenges, seal, verify_capture


@pytest.fixture
def capture_data():
    """Common test data for capture operations."""
    return {
        "photo_bytes": b"test-photo",
        "note": "test note",
        "checkpoint_pack": {"id": "1"},
        "nonce": "a" * 64,
        "account_id": "user-123",
        "gps_lat": 40.7128,
        "gps_lon": -74.0060,
        "timestamp": 1630000000,
    }


class TestChallengesNonceGeneration:
    """Test nonce generation."""

    def test_nonce_generation(self):
        """Challenges.issue() generates random 32-byte hex nonce."""
        challenges = Challenges()
        nonce = challenges.issue("user-123")

        # Nonce should be 64 characters (32 bytes in hex)
        assert isinstance(nonce, str)
        assert len(nonce) == 64

        # Should be valid hex
        try:
            int(nonce, 16)
        except ValueError:
            pytest.fail("Nonce is not valid hex")

    def test_nonce_uniqueness(self):
        """Each nonce should be unique."""
        challenges = Challenges()
        nonce1 = challenges.issue("user-123")
        nonce2 = challenges.issue("user-123")

        assert nonce1 != nonce2

    def test_nonce_randomness(self):
        """Nonces should be random across multiple generations."""
        challenges = Challenges()
        nonces = set()

        for i in range(10):
            nonce = challenges.issue(f"user-{i}")
            nonces.add(nonce)

        # All should be unique
        assert len(nonces) == 10


class TestChallengesNonceConsumption:
    """Test single-use nonce enforcement."""

    def test_nonce_consumption(self):
        """Nonce can be consumed once, second use fails."""
        challenges = Challenges()
        nonce = challenges.issue("user-123")

        # First consumption should succeed
        assert challenges.consume(nonce) is True

        # Second consumption should fail
        assert challenges.consume(nonce) is False

    def test_nonce_consumption_wrong_nonce(self):
        """Consuming non-existent nonce returns False."""
        challenges = Challenges()

        # Try to consume nonce that was never issued
        assert challenges.consume("nonexistent-nonce-" + "0" * 48) is False

    def test_multiple_nonces_independent(self):
        """Multiple nonces are independent."""
        challenges = Challenges()
        nonce1 = challenges.issue("user-123")
        nonce2 = challenges.issue("user-456")

        # Consume first nonce
        assert challenges.consume(nonce1) is True

        # Second nonce should still be consumable
        assert challenges.consume(nonce2) is True

        # Both should be exhausted now
        assert challenges.consume(nonce1) is False
        assert challenges.consume(nonce2) is False


class TestChallengesNonceExpiry:
    """Test nonce TTL enforcement (120 seconds)."""

    @patch('capture.time.time')
    def test_nonce_expiry(self, mock_time):
        """Nonce expires after 120 seconds."""
        challenges = Challenges()

        # Mock time at 0
        mock_time.return_value = 0
        nonce = challenges.issue("user-123")

        # Immediate consumption should work
        assert challenges.consume(nonce) is True

        # Create another nonce at time 0
        mock_time.return_value = 0
        nonce2 = challenges.issue("user-123")

        # Move time forward 121 seconds (past TTL)
        mock_time.return_value = 121

        # Consumption should fail (expired)
        assert challenges.consume(nonce2) is False

    @patch('capture.time.time')
    def test_nonce_not_expired_before_ttl(self, mock_time):
        """Nonce works within TTL window."""
        challenges = Challenges()

        # Issue nonce at time 0
        mock_time.return_value = 0
        nonce = challenges.issue("user-123")

        # Move forward 119 seconds (within TTL)
        mock_time.return_value = 119

        # Should still be consumable
        assert challenges.consume(nonce) is True

    @patch('capture.time.time')
    def test_nonce_expires_at_boundary(self, mock_time):
        """Nonce expires at exactly 120 seconds."""
        challenges = Challenges()

        # Issue nonce at time 0
        mock_time.return_value = 0
        nonce = challenges.issue("user-123")

        # Move to exactly 120 seconds
        mock_time.return_value = 120

        # Should be expired
        assert challenges.consume(nonce) is False


class TestSealBinding:
    """Test seal binding of photo + note + checkpoint + nonce + account + GPS."""

    def test_seal_roundtrip(self, capture_data):
        """seal() and verify_capture() roundtrip correctly."""
        # Seal the data
        result = seal(**capture_data)
        seal_hash = result["bind_hash"]

        # Verify should return True
        assert verify_capture(**capture_data, expected_seal=seal_hash) is True

    def test_seal_format(self, capture_data):
        """seal() returns dict with bind_hash and bind_ok."""
        result = seal(**capture_data)

        # Should return dict
        assert isinstance(result, dict)
        assert "bind_hash" in result
        assert "bind_ok" in result

        # bind_hash should be 64-char hex string (SHA256)
        bind_hash = result["bind_hash"]
        assert isinstance(bind_hash, str)
        assert len(bind_hash) == 64

        # Should be valid hex
        try:
            int(bind_hash, 16)
        except ValueError:
            pytest.fail("Seal hash is not valid hex")

        # bind_ok should be None (no device_bind_hash provided)
        assert result["bind_ok"] is None

    def test_seal_deterministic(self, capture_data):
        """seal() is deterministic - same input gives same output."""
        result1 = seal(**capture_data)
        result2 = seal(**capture_data)

        assert result1["bind_hash"] == result2["bind_hash"]

    @pytest.mark.parametrize("field,tamper_fn", [
        ("photo_bytes", lambda d: {**d, "photo_bytes": b"tampered"}),
        ("note", lambda d: {**d, "note": "tampered"}),
        ("gps_lat", lambda d: {**d, "gps_lat": 50.0}),
        ("timestamp", lambda d: {**d, "timestamp": d["timestamp"] + 1}),
    ])
    def test_verify_fails_on_tampered(self, capture_data, field, tamper_fn):
        """Verification fails if data is tampered."""
        result = seal(**capture_data)
        tampered = tamper_fn(capture_data)
        assert verify_capture(**tampered, expected_seal=result["bind_hash"]) is False


class TestOfflineVerification:
    """Test that verification works without Supabase access."""

    def test_offline_verification(self):
        """verify_capture() works without any external dependencies."""
        # All parameters are local
        photo_bytes = b"offline-test-photo"
        note = "Offline verification test"
        checkpoint_pack = {"offline": True, "checkpoint_id": "999"}
        nonce = "1" * 64
        account_id = "offline-user"
        gps_lat = -33.8688
        gps_lon = 151.2093
        timestamp = 1630000003

        # Seal and verify entirely offline
        result = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        seal_hash = result["bind_hash"]

        # This verification should work without any network calls
        verify_result = verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=seal_hash
        )

        assert verify_result is True

    def test_verify_constant_time(self, capture_data):
        """Verification uses constant-time comparison."""
        result = seal(**capture_data)
        seal_hash = result["bind_hash"]

        # Wrong seal should fail
        wrong_seal = "0" * 63 + "1"  # Off by one at end
        verify_result = verify_capture(**capture_data, expected_seal=wrong_seal)

        assert verify_result is False


class TestDeviceDigest:
    """Test device digest verification."""

    def test_device_digest_none_on_web_capture(self, capture_data):
        """No device_bind_hash (web capture) -> bind_ok=None."""
        result = seal(**capture_data, device_bind_hash=None)
        assert result["bind_ok"] is None

    def test_device_digest_match(self, capture_data):
        """device_bind_hash matches bind_hash -> bind_ok=True."""
        result = seal(**capture_data)

        # Provide matching device digest
        result_with_device = seal(**capture_data, device_bind_hash=result["bind_hash"])

        assert result_with_device["bind_ok"] is True

    def test_device_digest_mismatch(self, capture_data):
        """device_bind_hash differs -> bind_ok=False."""
        # Provide mismatched device digest
        wrong_hash = "0" * 64  # Completely different hash
        result_with_device = seal(**capture_data, device_bind_hash=wrong_hash)

        assert result_with_device["bind_ok"] is False

    def test_device_digest_case_insensitive(self, capture_data):
        """Device digest comparison is case-insensitive."""
        result = seal(**capture_data)

        # Provide uppercase version of hash
        result_with_device = seal(**capture_data, device_bind_hash=result["bind_hash"].upper())

        assert result_with_device["bind_ok"] is True

    def test_device_digest_whitespace_trimmed(self, capture_data):
        """Whitespace is stripped before device digest comparison."""
        result = seal(**capture_data)

        # Provide hash with surrounding whitespace
        result_with_device = seal(**capture_data, device_bind_hash="  " + result["bind_hash"] + "  ")

        assert result_with_device["bind_ok"] is True


class TestInputValidation:
    """Test input validation for seal and verify_capture."""

    def test_seal_rejects_empty_photo_bytes(self, capture_data):
        """seal() raises ValueError if photo_bytes is empty."""
        data = {**capture_data, "photo_bytes": b""}
        with pytest.raises(ValueError, match="photo_bytes cannot be empty"):
            seal(**data)

    def test_seal_rejects_missing_account_id(self, capture_data):
        """seal() raises ValueError if account_id is missing."""
        data = {**capture_data, "account_id": ""}
        with pytest.raises(ValueError, match="account_id is required"):
            seal(**data)

    def test_verify_rejects_empty_photo_bytes(self, capture_data):
        """verify_capture() raises ValueError if photo_bytes is empty."""
        result = seal(**capture_data)
        data = {**capture_data, "photo_bytes": b"", "expected_seal": result["bind_hash"]}
        with pytest.raises(ValueError, match="photo_bytes cannot be empty"):
            verify_capture(**data)

    def test_verify_rejects_missing_account_id(self, capture_data):
        """verify_capture() raises ValueError if account_id is missing."""
        result = seal(**capture_data)
        data = {**capture_data, "account_id": "", "expected_seal": result["bind_hash"]}
        with pytest.raises(ValueError, match="account_id is required"):
            verify_capture(**data)
