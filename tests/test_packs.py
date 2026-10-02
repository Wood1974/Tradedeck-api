"""
Tests for Shield Capture Pack Templates.
Tests pack retrieval, validation, and structure for fixed, code, and custom packs.
"""

import pytest
from packs import (
    get_pack,
    validate_pack,
    validate_fixed_pack,
    validate_code_pack,
    validate_custom_pack_id,
    list_fixed_packs,
    PackNotFoundError,
    PackValidationError,
)


class TestFixedPackRetrieval:
    """Test retrieval of fixed packs."""

    @pytest.mark.parametrize(
        "pack_id,expected_name",
        [
            ("remodel", "Kitchen/Bath Remodel"),
            ("lender_draw", "Construction Draw Schedule"),
            ("insurance_loss", "Insurance Loss Documentation"),
            ("rental_unit", "Rental Unit Assessment"),
            ("auto_shop", "Vehicle Repair Documentation"),
        ],
    )
    def test_get_fixed_pack(self, pack_id, expected_name):
        """Retrieve fixed pack by ID with correct name."""
        pack = get_pack(pack_id)
        assert pack["id"] == pack_id
        assert pack["name"] == expected_name
        assert len(pack["points"]) == 5
        assert all(isinstance(p, dict) for p in pack["points"])

    def test_all_fixed_packs_have_structure(self):
        """All fixed packs have required structure."""
        for pack_id in list_fixed_packs():
            pack = get_pack(pack_id)
            assert "id" in pack
            assert "name" in pack
            assert "points" in pack
            assert isinstance(pack["points"], list)
            assert len(pack["points"]) == 5


class TestPackStructure:
    """Test pack structure and validation."""

    def test_pack_point_structure(self):
        """Pack points have required fields."""
        pack = get_pack("remodel")
        for point in pack["points"]:
            assert "order" in point
            assert "name" in point
            assert "description" in point
            assert isinstance(point["order"], int)
            assert isinstance(point["name"], str)
            assert isinstance(point["description"], str)

    def test_pack_point_ordering(self):
        """Pack points ordered sequentially starting from 1."""
        pack = get_pack("remodel")
        for i, point in enumerate(pack["points"], start=1):
            assert point["order"] == i

    def test_pack_point_names_not_empty(self):
        """All point names are non-empty strings."""
        pack = get_pack("remodel")
        for point in pack["points"]:
            assert len(point["name"].strip()) > 0

    def test_pack_point_descriptions_not_empty(self):
        """All point descriptions are non-empty strings."""
        pack = get_pack("remodel")
        for point in pack["points"]:
            assert len(point["description"].strip()) > 0


class TestCodePack:
    """Test code pack existence and structure."""

    def test_code_pack_exists(self):
        """Code pack can be retrieved."""
        pack = get_pack("code")
        assert pack["id"] == "code"
        assert pack["name"] == "IRC/IBC Violations"
        assert isinstance(pack["points"], list)

    def test_code_pack_structure(self):
        """Code pack has valid structure."""
        pack = get_pack("code")
        assert "id" in pack
        assert "name" in pack
        assert "points" in pack
        # Code pack can have dynamic number of points (0-20 range typically)
        assert len(pack["points"]) <= 20


class TestCustomPackValidation:
    """Test custom pack validation."""

    def create_custom_pack(self, pack_id, num_points):
        """Helper to create a custom pack with specified number of points."""
        return {
            "id": pack_id,
            "name": "Test Pack",
            "points": [
                {"order": i, "name": f"Point {i}", "description": f"Test point {i}"}
                for i in range(1, num_points + 1)
            ],
        }

    def test_custom_pack_5_points_minimum(self):
        """Custom pack must have at least 5 points."""
        custom_pack = self.create_custom_pack("custom_abc123", 4)
        with pytest.raises(PackValidationError) as exc_info:
            validate_pack(custom_pack)
        assert "at least 5 points" in str(exc_info.value)

    def test_custom_pack_20_points_maximum(self):
        """Custom pack can have maximum 20 points."""
        custom_pack = self.create_custom_pack("custom_abc123", 21)
        with pytest.raises(PackValidationError) as exc_info:
            validate_pack(custom_pack)
        assert "maximum 20 points" in str(exc_info.value)

    def test_custom_pack_5_points_valid(self):
        """Custom pack with exactly 5 points is valid."""
        custom_pack = self.create_custom_pack("custom_abc123", 5)
        # Should not raise
        validate_pack(custom_pack)

    def test_custom_pack_20_points_valid(self):
        """Custom pack with exactly 20 points is valid."""
        custom_pack = self.create_custom_pack("custom_abc123", 20)
        # Should not raise
        validate_pack(custom_pack)

    def test_pack_point_order_validation(self):
        """Pack points must be ordered sequentially from 1."""
        custom_pack = {
            "id": "custom_abc123",
            "name": "My Custom Pack",
            "points": [
                {"order": 1, "name": "Point 1", "description": "Test point 1"},
                {"order": 2, "name": "Point 2", "description": "Test point 2"},
                {"order": 4, "name": "Point 3", "description": "Test point 3"},  # Gap
                {"order": 5, "name": "Point 4", "description": "Test point 4"},
                {"order": 6, "name": "Point 5", "description": "Test point 5"},
            ],
        }
        with pytest.raises(PackValidationError) as exc_info:
            validate_pack(custom_pack)
        assert "sequential" in str(exc_info.value).lower()

    def test_pack_missing_name_field(self):
        """Pack point with missing name fails validation."""
        custom_pack = {
            "id": "custom_abc123",
            "name": "My Custom Pack",
            "points": [
                {"order": 1, "name": "Point 1", "description": "Test point 1"},
                {"order": 2, "description": "Test point 2"},  # Missing name
                {"order": 3, "name": "Point 3", "description": "Test point 3"},
                {"order": 4, "name": "Point 4", "description": "Test point 4"},
                {"order": 5, "name": "Point 5", "description": "Test point 5"},
            ],
        }
        with pytest.raises(PackValidationError) as exc_info:
            validate_pack(custom_pack)
        assert "name" in str(exc_info.value).lower()

    def test_pack_empty_name(self):
        """Pack point with empty name fails validation."""
        custom_pack = {
            "id": "custom_abc123",
            "name": "My Custom Pack",
            "points": [
                {"order": 1, "name": "Point 1", "description": "Test point 1"},
                {"order": 2, "name": "", "description": "Test point 2"},  # Empty
                {"order": 3, "name": "Point 3", "description": "Test point 3"},
                {"order": 4, "name": "Point 4", "description": "Test point 4"},
                {"order": 5, "name": "Point 5", "description": "Test point 5"},
            ],
        }
        with pytest.raises(PackValidationError) as exc_info:
            validate_pack(custom_pack)
        assert "name" in str(exc_info.value).lower()


class TestPackErrorHandling:
    """Test error handling for pack operations."""

    def test_pack_not_found_raises_error(self):
        """Requesting non-existent pack raises PackNotFoundError."""
        with pytest.raises(PackNotFoundError) as exc_info:
            get_pack("nonexistent_pack")
        assert "nonexistent_pack" in str(exc_info.value)

    def test_invalid_pack_id_format(self):
        """Invalid pack ID format raises error."""
        with pytest.raises(PackNotFoundError):
            get_pack("")

    def test_pack_not_found_error_message(self):
        """PackNotFoundError provides helpful message."""
        pack_id = "unknown_pack_123"
        with pytest.raises(PackNotFoundError) as exc_info:
            get_pack(pack_id)
        error_msg = str(exc_info.value)
        assert pack_id in error_msg


class TestPackIDs:
    """Test pack ID handling and validation."""

    def test_remodel_pack_id(self):
        """Pack ID 'remodel' is correct."""
        pack = get_pack("remodel")
        assert pack["id"] == "remodel"

    def test_code_pack_id(self):
        """Pack ID 'code' is correct."""
        pack = get_pack("code")
        assert pack["id"] == "code"

    def test_custom_pack_id_format(self):
        """Custom pack IDs follow 'custom_' prefix pattern."""
        custom_id = "custom_test123"
        custom_pack = {
            "id": custom_id,
            "name": "Test Pack",
            "points": [
                {"order": i, "name": f"Point {i}", "description": f"Test {i}"}
                for i in range(1, 6)
            ],
        }
        validate_pack(custom_pack)
        assert custom_pack["id"].startswith("custom_")


class TestPackUtilities:
    """Test pack utility functions."""

    def test_list_fixed_packs_returns_all_ids(self):
        """list_fixed_packs() returns all fixed pack IDs."""
        packs = list_fixed_packs()
        assert "remodel" in packs
        assert "lender_draw" in packs
        assert "insurance_loss" in packs
        assert "rental_unit" in packs
        assert "auto_shop" in packs
        assert len(packs) == 5

    def test_validate_fixed_pack_true_for_valid(self):
        """validate_fixed_pack() returns True for valid fixed pack IDs."""
        assert validate_fixed_pack("remodel") is True
        assert validate_fixed_pack("lender_draw") is True
        assert validate_fixed_pack("insurance_loss") is True

    def test_validate_fixed_pack_false_for_invalid(self):
        """validate_fixed_pack() returns False for invalid pack IDs."""
        assert validate_fixed_pack("nonexistent") is False
        assert validate_fixed_pack("code") is False
        assert validate_fixed_pack("custom_123") is False

    def test_validate_code_pack_true(self):
        """validate_code_pack() returns True."""
        assert validate_code_pack() is True

    def test_validate_custom_pack_id_true_for_valid(self):
        """validate_custom_pack_id() returns True for custom pack IDs."""
        assert validate_custom_pack_id("custom_123") is True
        assert validate_custom_pack_id("custom_abc_def") is True

    def test_validate_custom_pack_id_false_for_invalid(self):
        """validate_custom_pack_id() returns False for non-custom pack IDs."""
        assert validate_custom_pack_id("remodel") is False
        assert validate_custom_pack_id("code") is False
        assert validate_custom_pack_id("invalid") is False

    def test_get_pack_returns_copy_not_reference(self):
        """get_pack() returns a deep copy, not a reference to template."""
        pack1 = get_pack("remodel")
        pack2 = get_pack("remodel")
        assert pack1 is not pack2
        pack1["name"] = "Modified Name"
        assert pack2["name"] == "Kitchen/Bath Remodel"
        # Verify original template is unchanged
        pack3 = get_pack("remodel")
        assert pack3["name"] == "Kitchen/Bath Remodel"
