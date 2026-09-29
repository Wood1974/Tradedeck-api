"""
Tests for Shield location scoring.
Tests GPS spoofing detection through speed and clock-skew analysis.
"""

import pytest
from location import score


class TestLocationScoreing:
    """Test GPS spoofing detection."""

    def test_single_point_consistent(self):
        """Single GPS point should return consistent verdict."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000}
        ]
        result = score(points)

        assert result["verdict"] == "consistent"
        assert "reason" in result
        assert result["max_speed_mph"] == 0.0
        assert "single point" in result["reason"].lower()

    def test_zero_movement_consistent(self):
        """Same GPS point twice should return consistent verdict."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000010}
        ]
        result = score(points)

        assert result["verdict"] == "consistent"
        assert result["max_speed_mph"] == 0.0

    def test_normal_speed_consistent(self):
        """Normal GPS movement (10 mph) should return consistent verdict."""
        # New York to nearby location: ~0.15 km (0.093 miles), 10 seconds
        # Expected speed: ~0.093 miles / (10/3600) hours = ~33 mph
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7138, "lon": -74.0050, "timestamp": 1630000010}
        ]
        result = score(points)

        assert result["verdict"] == "consistent"
        assert result["max_speed_mph"] < 120  # Well below flag threshold

    def test_impossible_speed_reject(self):
        """Impossible speed (500 mph) should return reject verdict."""
        # New York to San Francisco is ~2,569 miles
        # In 10 seconds would be ~500 mph
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 37.7749, "lon": -122.4194, "timestamp": 1630000010}
        ]
        result = score(points)

        assert result["verdict"] == "reject"
        assert result["max_speed_mph"] > 250
        assert "impossible" in result["reason"].lower() or "physical" in result["reason"].lower()

    def test_unrealistic_speed_flag(self):
        """Unrealistic but possible speed (150 mph) should return flag verdict."""
        # To get 150 mph: need 1.5 miles in 36 seconds
        # 1.5 miles = 2.414 km
        # At latitude 40.7128, 1 degree lon ~ 84 km, so 0.0287 degrees = 2.414 km
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7128, "lon": -73.9773, "timestamp": 1630000036}  # 0.0287 degrees east
        ]
        result = score(points)

        assert result["verdict"] == "flag"
        assert result["max_speed_mph"] > 120
        assert result["max_speed_mph"] < 250
        assert "unrealistic" in result["reason"].lower() or "high speed" in result["reason"].lower()

    def test_clock_skew_flag(self):
        """Future timestamp should return flag verdict (clock skew)."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000100},
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000}  # Earlier timestamp
        ]
        result = score(points)

        assert result["verdict"] == "flag"
        assert "clock" in result["reason"].lower() or "time" in result["reason"].lower()

    def test_negative_time_delta_flag(self):
        """Negative time delta (out of order timestamps) should flag."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000100},
            {"lat": 40.7200, "lon": -74.0000, "timestamp": 1630000050}
        ]
        result = score(points)

        assert result["verdict"] == "flag"

    def test_three_points_max_speed(self):
        """With three points, max_speed should be the highest between segments."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000010},  # Zero movement
            {"lat": 37.7749, "lon": -122.4194, "timestamp": 1630000020}   # Impossible
        ]
        result = score(points)

        assert result["verdict"] == "reject"
        assert result["max_speed_mph"] > 250

    def test_empty_list(self):
        """Empty points list should return consistent (no data to verify)."""
        points = []
        result = score(points)

        assert result["verdict"] == "consistent"
        assert result["max_speed_mph"] == 0.0

    def test_result_structure(self):
        """Result should always contain verdict, reason, and max_speed_mph."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000}
        ]
        result = score(points)

        assert isinstance(result, dict)
        assert "verdict" in result
        assert "reason" in result
        assert "max_speed_mph" in result

        assert result["verdict"] in ["reject", "flag", "consistent"]
        assert isinstance(result["reason"], str)
        assert isinstance(result["max_speed_mph"], (int, float))

    def test_realistic_trip(self):
        """Realistic trip: NYC to nearby location at realistic speeds."""
        # Simulate 2-minute trip traveling at realistic speeds
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7150, "lon": -74.0040, "timestamp": 1630000030},  # 30 seconds
            {"lat": 40.7200, "lon": -74.0000, "timestamp": 1630000060},  # Another 30 seconds
        ]
        result = score(points)

        # Should be consistent for a realistic trip
        assert result["verdict"] == "consistent"
        assert result["max_speed_mph"] < 120

    def test_verdict_priority_reject_over_flag(self):
        """If any segment shows impossible speed, reject even if others flag."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7150, "lon": -74.0040, "timestamp": 1630000100},  # ~30 mph
            {"lat": 37.7749, "lon": -122.4194, "timestamp": 1630000110}   # ~500 mph
        ]
        result = score(points)

        assert result["verdict"] == "reject"
        assert result["max_speed_mph"] > 250

    def test_zero_time_delta(self):
        """Zero time delta (same timestamp) should handle gracefully."""
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 40.7200, "lon": -74.0000, "timestamp": 1630000000}  # Same time, different location
        ]
        result = score(points)

        # Zero time delta with movement = infinite speed = reject
        assert result["verdict"] == "reject"

    def test_haversine_accuracy(self):
        """Test Haversine calculation accuracy (known distance)."""
        # NYC to LA is approximately 2,451 miles
        # Moving there in 10 hours = ~245 mph (flagged but not rejected)
        hours_10 = 10 * 3600
        points = [
            {"lat": 40.7128, "lon": -74.0060, "timestamp": 1630000000},
            {"lat": 34.0522, "lon": -118.2437, "timestamp": 1630000000 + hours_10}
        ]
        result = score(points)

        # Speed should be around 245 mph
        assert 200 < result["max_speed_mph"] < 300
        assert result["verdict"] == "flag"
