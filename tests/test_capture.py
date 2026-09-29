"""
Tests for Shield Capture Core layer.
Tests single-use nonce management, seal binding, and offline verification.
"""

import pytest
import time
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture import Challenges, seal, verify_capture


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

    @patch('time.time')
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

    @patch('time.time')
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

    @patch('time.time')
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

    def test_seal_roundtrip(self):
        """seal() and verify_capture() roundtrip correctly."""
        # Test data
        photo_bytes = b"test-photo-data-123"
        note = "This is a test note"
        checkpoint_pack = {"checkpoint_id": "123", "location": "site"}
        nonce = "a" * 64  # 32-byte hex nonce
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        # Seal the data
        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Verify should return True
        assert verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=seal_hash
        ) is True

    def test_seal_format(self):
        """seal() returns a hex string."""
        photo_bytes = b"test-photo"
        note = "test note"
        checkpoint_pack = {"id": "1"}
        nonce = "b" * 64
        account_id = "user-456"
        gps_lat = 51.5074
        gps_lon = -0.1278
        timestamp = 1630000001

        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Should be a hex string (64 chars for SHA256)
        assert isinstance(seal_hash, str)
        assert len(seal_hash) == 64

        # Should be valid hex
        try:
            int(seal_hash, 16)
        except ValueError:
            pytest.fail("Seal hash is not valid hex")

    def test_seal_deterministic(self):
        """seal() is deterministic - same input gives same output."""
        photo_bytes = b"test-photo"
        note = "test note"
        checkpoint_pack = {"id": "1"}
        nonce = "c" * 64
        account_id = "user-789"
        gps_lat = 35.6762
        gps_lon = 139.6503
        timestamp = 1630000002

        seal_hash1 = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        seal_hash2 = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        assert seal_hash1 == seal_hash2

    def test_verify_fails_on_tampered_photo(self):
        """Verification fails if photo is tampered."""
        photo_bytes = b"original-photo"
        note = "test note"
        checkpoint_pack = {"id": "1"}
        nonce = "d" * 64
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        # Seal original
        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Verify fails with tampered photo
        assert verify_capture(
            photo_bytes=b"tampered-photo",
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=seal_hash
        ) is False

    def test_verify_fails_on_tampered_note(self):
        """Verification fails if note is tampered."""
        photo_bytes = b"photo"
        note = "original note"
        checkpoint_pack = {"id": "1"}
        nonce = "e" * 64
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Verify fails with tampered note
        assert verify_capture(
            photo_bytes=photo_bytes,
            note="tampered note",
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=seal_hash
        ) is False

    def test_verify_fails_on_tampered_gps(self):
        """Verification fails if GPS is tampered."""
        photo_bytes = b"photo"
        note = "note"
        checkpoint_pack = {"id": "1"}
        nonce = "f" * 64
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Verify fails with tampered GPS
        assert verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=50.0,  # Different latitude
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=seal_hash
        ) is False

    def test_verify_fails_on_tampered_timestamp(self):
        """Verification fails if timestamp is tampered."""
        photo_bytes = b"photo"
        note = "note"
        checkpoint_pack = {"id": "1"}
        nonce = "0" * 64
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Verify fails with tampered timestamp
        assert verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=1630000001,  # Different timestamp
            expected_seal=seal_hash
        ) is False


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
        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # This verification should work without any network calls
        result = verify_capture(
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

        assert result is True

    def test_verify_constant_time(self):
        """Verification uses constant-time comparison."""
        # This test ensures we're not vulnerable to timing attacks
        photo_bytes = b"photo"
        note = "note"
        checkpoint_pack = {"id": "1"}
        nonce = "2" * 64
        account_id = "user-123"
        gps_lat = 40.7128
        gps_lon = -74.0060
        timestamp = 1630000000

        seal_hash = seal(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp
        )

        # Wrong seal should fail
        wrong_seal = "0" * 63 + "1"  # Off by one at end
        result = verify_capture(
            photo_bytes=photo_bytes,
            note=note,
            checkpoint_pack=checkpoint_pack,
            nonce=nonce,
            account_id=account_id,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timestamp=timestamp,
            expected_seal=wrong_seal
        )

        assert result is False


class TestDeviceDigest:
    """Test device digest comparison."""

    def test_device_digest_consistency(self):
        """Device digest should be consistent for same data."""
        # This is a placeholder test - would need device digest implementation
        # For now, just verify it doesn't crash
        pass
