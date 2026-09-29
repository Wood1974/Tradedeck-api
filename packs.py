"""
Shield Capture Pack Templates

Checkpoint packs define structured templates for evidence collection in Shield.
- Fixed packs: predefined templates for common scenarios (remodels, insurance claims)
- Code packs: AI-generated checkpoints based on IRC/IBC violations
- Custom packs: buyer-defined checkpoints for unique scenarios

Pack structure:
{
    "id": "pack_id",
    "name": "Human-readable pack name",
    "points": [
        {"order": 1, "name": "Checkpoint name", "description": "What to capture"}
    ]
}

Validation rules:
- Custom packs must have 5-20 points
- All packs must have points ordered sequentially from 1
- All point names must be non-empty strings
"""

from typing import Dict, List, Optional


class PackNotFoundError(Exception):
    """Raised when a requested pack template is not found."""

    pass


class PackValidationError(Exception):
    """Raised when a pack fails validation."""

    pass


# Fixed pack templates
FIXED_PACKS: Dict[str, Dict] = {
    "remodel": {
        "id": "remodel",
        "name": "Kitchen/Bath Remodel",
        "description": "Comprehensive checkpoint pack for kitchen and bathroom remodels",
        "points": [
            {
                "order": 1,
                "name": "Before Photos",
                "description": "Overall before photos of the space from multiple angles",
            },
            {
                "order": 2,
                "name": "Framing",
                "description": "Structural framing installation and blocking",
            },
            {
                "order": 3,
                "name": "Drywall & Tape",
                "description": "Drywall installation, taping, and mudding",
            },
            {
                "order": 4,
                "name": "Finishes",
                "description": "Paint, tile, fixtures, and final finishes",
            },
            {
                "order": 5,
                "name": "Cleanup & Handover",
                "description": "Site cleanup and final walkthrough",
            },
        ],
    },
    "lender_draw": {
        "id": "lender_draw",
        "name": "Construction Draw Schedule",
        "description": "Lender-required checkpoints for construction draws",
        "points": [
            {
                "order": 1,
                "name": "Foundation & Framing",
                "description": "Foundation poured and framing complete",
            },
            {
                "order": 2,
                "name": "Roof & Weather-tight",
                "description": "Roof installed and building weather-tight",
            },
            {
                "order": 3,
                "name": "Rough Inspections",
                "description": "Passed electrical, plumbing, and HVAC inspections",
            },
            {
                "order": 4,
                "name": "Drywall Complete",
                "description": "Drywall installed and ready for finish trades",
            },
            {
                "order": 5,
                "name": "Substantial Completion",
                "description": "All trades substantially complete",
            },
        ],
    },
    "insurance_loss": {
        "id": "insurance_loss",
        "name": "Insurance Loss Documentation",
        "description": "Documentation for insurance claim assessment",
        "points": [
            {
                "order": 1,
                "name": "Damage Overview",
                "description": "Wide shots showing extent of damage",
            },
            {
                "order": 2,
                "name": "Close-up Details",
                "description": "Detailed photos of specific damage areas",
            },
            {
                "order": 3,
                "name": "Water/Moisture Indicators",
                "description": "Evidence of water damage and moisture",
            },
            {
                "order": 4,
                "name": "Affected Materials",
                "description": "Photos of drywall, insulation, flooring damage",
            },
            {
                "order": 5,
                "name": "Timestamp & Reference",
                "description": "Photos with date/location references",
            },
        ],
    },
    "rental_unit": {
        "id": "rental_unit",
        "name": "Rental Unit Assessment",
        "description": "Damage assessment and maintenance documentation for rental properties",
        "points": [
            {
                "order": 1,
                "name": "Unit Entry & Overall",
                "description": "Entry point and overall condition of unit",
            },
            {
                "order": 2,
                "name": "Flooring & Walls",
                "description": "Condition of flooring, walls, and paint",
            },
            {
                "order": 3,
                "name": "Appliances & Fixtures",
                "description": "Condition of appliances, fixtures, and hardware",
            },
            {
                "order": 4,
                "name": "Damage Documentation",
                "description": "Any damage requiring repair or remediation",
            },
            {
                "order": 5,
                "name": "Cleanliness & Move-out",
                "description": "Final cleanliness and move-out condition",
            },
        ],
    },
    "auto_shop": {
        "id": "auto_shop",
        "name": "Vehicle Repair Documentation",
        "description": "Documentation for vehicle repair work",
        "points": [
            {
                "order": 1,
                "name": "Vehicle Overview",
                "description": "Full vehicle photos and damage assessment",
            },
            {
                "order": 2,
                "name": "Disassembly",
                "description": "Photos during disassembly showing damage extent",
            },
            {
                "order": 3,
                "name": "Repairs in Progress",
                "description": "Progress photos during repair work",
            },
            {
                "order": 4,
                "name": "Parts Installation",
                "description": "Photos of new parts being installed",
            },
            {
                "order": 5,
                "name": "Final Inspection",
                "description": "Final vehicle condition after repair completion",
            },
        ],
    },
}

# Code pack for AI-generated checkpoints
CODE_PACK: Dict = {
    "id": "code",
    "name": "IRC/IBC Violations",
    "description": "AI-generated checkpoints based on IRC and IBC code violations",
    "points": [],  # Generated dynamically based on violations found
}

# Custom packs are stored separately and retrieved by custom_<id> pattern


def get_pack(pack_id: str) -> Dict:
    """
    Retrieve a checkpoint pack template by ID.

    Supports three pack types:
    1. Fixed packs: remodel, lender_draw, insurance_loss, rental_unit, auto_shop
    2. Code pack: code (AI-generated IRC/IBC violations)
    3. Custom packs: custom_<id> (buyer-defined, retrieved from storage)

    Args:
        pack_id: Pack identifier (string)

    Returns:
        Pack dictionary with id, name, and points array

    Raises:
        PackNotFoundError: If pack_id is not found or invalid
    """
    if not pack_id or not isinstance(pack_id, str):
        raise PackNotFoundError(f"Invalid pack ID: {pack_id}")

    # Check fixed packs first
    if pack_id in FIXED_PACKS:
        return FIXED_PACKS[pack_id].copy()

    # Check code pack
    if pack_id == "code":
        return CODE_PACK.copy()

    # Custom packs follow pattern custom_<id>
    if pack_id.startswith("custom_"):
        # In a real implementation, this would query a database or storage
        # For now, we raise not found as custom packs must be explicitly stored
        raise PackNotFoundError(f"Custom pack not found: {pack_id}")

    # Pack not found
    raise PackNotFoundError(f"Pack not found: {pack_id}")


def validate_pack(pack: Dict) -> None:
    """
    Validate pack structure and content.

    Rules:
    - Pack must have 'id', 'name', 'points' keys
    - Must have 5-20 points (for custom packs; fixed packs exempt)
    - Points must be ordered sequentially starting from 1
    - All point names must be non-empty strings
    - All point descriptions must be non-empty strings

    Args:
        pack: Pack dictionary to validate

    Raises:
        PackValidationError: If pack fails validation
    """
    # Check required top-level keys
    if not isinstance(pack, dict):
        raise PackValidationError("Pack must be a dictionary")

    required_keys = ["id", "name", "points"]
    for key in required_keys:
        if key not in pack:
            raise PackValidationError(f"Pack missing required key: {key}")

    # Check points is a list
    if not isinstance(pack["points"], list):
        raise PackValidationError("Pack 'points' must be a list")

    # Point count validation (5-20 for custom packs)
    point_count = len(pack["points"])
    if pack["id"].startswith("custom_"):
        if point_count < 5:
            raise PackValidationError(
                f"Custom pack must have at least 5 points, got {point_count}"
            )
        if point_count > 20:
            raise PackValidationError(
                f"Custom pack can have maximum 20 points, got {point_count}"
            )

    # Validate point structure and ordering
    for i, point in enumerate(pack["points"], start=1):
        if not isinstance(point, dict):
            raise PackValidationError(f"Point {i} must be a dictionary")

        # Check required point fields
        if "order" not in point:
            raise PackValidationError(f"Point {i} missing 'order' field")
        if "name" not in point:
            raise PackValidationError(f"Point {i} missing 'name' field")
        if "description" not in point:
            raise PackValidationError(f"Point {i} missing 'description' field")

        # Validate order is sequential starting from 1
        if point["order"] != i:
            raise PackValidationError(
                f"Point orders must be sequential starting from 1. "
                f"Expected order {i}, got {point['order']}"
            )

        # Validate name is non-empty string
        if not isinstance(point["name"], str) or not point["name"].strip():
            raise PackValidationError(f"Point {i} name must be non-empty string")

        # Validate description is non-empty string
        if not isinstance(point["description"], str) or not point[
            "description"
        ].strip():
            raise PackValidationError(
                f"Point {i} description must be non-empty string"
            )


def validate_fixed_pack(pack_id: str) -> bool:
    """
    Check if a pack ID is a valid fixed pack.

    Args:
        pack_id: Pack identifier to check

    Returns:
        True if pack_id is a valid fixed pack ID, False otherwise
    """
    return pack_id in FIXED_PACKS


def validate_code_pack(pack_id: str) -> bool:
    """
    Check if a pack ID is the code pack.

    Args:
        pack_id: Pack identifier to check

    Returns:
        True if pack_id is "code", False otherwise
    """
    return pack_id == "code"


def validate_custom_pack_id(pack_id: str) -> bool:
    """
    Check if a pack ID follows custom pack naming pattern.

    Args:
        pack_id: Pack identifier to check

    Returns:
        True if pack_id starts with "custom_", False otherwise
    """
    return isinstance(pack_id, str) and pack_id.startswith("custom_")


def list_fixed_packs() -> List[str]:
    """
    List all available fixed pack IDs.

    Returns:
        List of fixed pack IDs
    """
    return list(FIXED_PACKS.keys())


def list_all_pack_ids() -> List[str]:
    """
    List all fixed pack IDs and the code pack ID.

    Returns:
        List of all available pack IDs (fixed + code)
    """
    return list_fixed_packs() + ["code"]
