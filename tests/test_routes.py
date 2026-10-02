"""
Test Shield Capture v1 API Route Handlers

Comprehensive tests for 20+ backend endpoints covering:
- Pack management (3 endpoints)
- Challenge & capture (4 endpoints)
- Export & verification (4 endpoints)
- Configuration & metadata (3 endpoints)
- Admin/monitoring (3 endpoints)
- Legacy/utility endpoints (2 endpoints)
"""

import json
import time
from io import BytesIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from flask import Flask

from app import app
from capture import Challenges
import packs


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_jwt_header():
    """Return mock JWT authorization header."""
    return {"Authorization": "Bearer mock_jwt_token"}


@pytest.fixture
def mock_supabase():
    """Mock Supabase client with JWT verification (non-admin user)."""
    with patch("app.supabase_admin") as mock_sb:
        # Mock user response (non-admin)
        mock_user_obj = MagicMock()
        mock_user_obj.id = "test_user_id"
        mock_user_obj.role = "user"
        mock_user_obj.admin = False
        mock_user_obj.user_metadata = {}

        mock_response = MagicMock()
        mock_response.user = mock_user_obj
        mock_sb.auth.get_user.return_value = mock_response

        yield mock_sb


# ============================================================================
# Pack Management Tests (4 tests)
# ============================================================================

def test_get_packs_list(client):
    """GET /api/packs - List all available packs."""
    response = client.get("/api/packs")
    assert response.status_code == 200

    data = response.get_json()
    assert "packs" in data
    assert isinstance(data["packs"], list)
    assert len(data["packs"]) > 0

    # Verify pack structure
    for pack in data["packs"]:
        assert "id" in pack
        assert "name" in pack
        assert "description" in pack
        assert "checkpoint_count" in pack


def test_get_packs_list_with_filter(client):
    """GET /api/packs?pack_type=fixed - List packs with type filter."""
    response = client.get("/api/packs?pack_type=fixed")
    assert response.status_code == 200

    data = response.get_json()
    assert "packs" in data
    # Should have fixed packs (remodel, lender_draw, etc.)
    assert len(data["packs"]) >= 5


def test_get_single_pack(client):
    """GET /api/packs/:pack_id - Get single pack with checkpoint definitions."""
    response = client.get("/api/packs/remodel")
    assert response.status_code == 200

    data = response.get_json()
    assert data["id"] == "remodel"
    assert "name" in data
    assert "description" in data
    assert "points" in data
    assert isinstance(data["points"], list)
    assert len(data["points"]) > 0

    # Verify point structure
    for point in data["points"]:
        assert "order" in point
        assert "name" in point
        assert "description" in point


def test_get_single_pack_not_found(client):
    """GET /api/packs/:pack_id - 404 if pack not found."""
    response = client.get("/api/packs/nonexistent_pack_id")
    assert response.status_code == 404
    assert "error" in response.get_json()


def test_create_custom_pack(client, mock_jwt_header, mock_supabase):
    """POST /api/packs/custom - Create custom pack with buyer-written checkpoints."""
    request_body = {
        "name": "Custom Inspection",
        "description": "Custom checkpoint pack",
        "points": [
            {"name": "Point 1", "description": "First checkpoint"},
            {"name": "Point 2", "description": "Second checkpoint"},
            {"name": "Point 3", "description": "Third checkpoint"},
            {"name": "Point 4", "description": "Fourth checkpoint"},
            {"name": "Point 5", "description": "Fifth checkpoint"},
        ]
    }

    response = client.post(
        "/api/packs/custom",
        json=request_body,
        headers=mock_jwt_header
    )

    assert response.status_code == 201
    data = response.get_json()
    assert "id" in data
    assert data["name"] == "Custom Inspection"
    assert data["points_count"] == 5


def test_create_custom_pack_too_few_points(client, mock_jwt_header, mock_supabase):
    """POST /api/packs/custom - 400 if fewer than 5 points."""
    request_body = {
        "name": "Invalid Pack",
        "description": "Too few points",
        "points": [
            {"name": "Point 1", "description": "Only"},
        ]
    }

    response = client.post(
        "/api/packs/custom",
        json=request_body,
        headers=mock_jwt_header
    )
    assert response.status_code == 400


def test_create_custom_pack_too_many_points(client, mock_jwt_header, mock_supabase):
    """POST /api/packs/custom - 400 if more than 20 points."""
    request_body = {
        "name": "Invalid Pack",
        "description": "Too many points",
        "points": [
            {"name": f"Point {i}", "description": f"Checkpoint {i}"}
            for i in range(1, 22)
        ]
    }

    response = client.post(
        "/api/packs/custom",
        json=request_body,
        headers=mock_jwt_header
    )
    assert response.status_code == 400


# ============================================================================
# Challenge & Capture Tests (4 tests)
# ============================================================================

def test_issue_challenge_nonce(client, mock_jwt_header, mock_supabase):
    """POST /api/challenges/issue - Issue single-use nonce for capture session."""
    response = client.post(
        "/api/challenges/issue",
        json={"account_id": "test_account_id"},
        headers=mock_jwt_header
    )

    assert response.status_code == 200
    data = response.get_json()
    assert "nonce" in data
    assert "ttl_seconds" in data
    assert len(data["nonce"]) == 64  # 32 bytes = 64-char hex
    assert data["ttl_seconds"] == 120


def test_seal_capture(client, mock_jwt_header, mock_supabase):
    """POST /api/captures/:pack_id/seal - Seal single photo+note capture."""
    # First get a valid nonce
    from app import challenges
    nonce = challenges.issue("test_user_id")

    photo_data = BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    data = {
        "photo": (photo_data, "test.png"),
        "note": "Test note",
        "checkpoint_name": "Before Photos",
        "nonce": nonce,
        "gps_lat": "40.7128",
        "gps_lon": "-74.0060",
        "device_bind_hash": None
    }

    response = client.post(
        "/api/captures/remodel/seal",
        data=data,
        content_type="multipart/form-data",
        headers=mock_jwt_header
    )

    assert response.status_code == 200
    result = response.get_json()
    assert "bind_hash" in result
    assert "bind_ok" in result
    assert len(result["bind_hash"]) == 64  # SHA256 hex


def test_seal_capture_invalid_nonce(client, mock_jwt_header, mock_supabase):
    """POST /api/captures/:pack_id/seal - 400 if nonce invalid/expired."""
    photo_data = BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    data = {
        "photo": (photo_data, "test.png"),
        "note": "Test note",
        "checkpoint_name": "Before Photos",
        "nonce": "a" * 64,  # Invalid nonce
        "gps_lat": "40.7128",
        "gps_lon": "-74.0060",
    }

    response = client.post(
        "/api/captures/remodel/seal",
        data=data,
        content_type="multipart/form-data",
        headers=mock_jwt_header
    )

    assert response.status_code == 400


def test_seal_capture_invalid_pack(client, mock_jwt_header, mock_supabase):
    """POST /api/captures/:pack_id/seal - 404 if pack not found."""
    from app import challenges
    nonce = challenges.issue("test_user_id")

    photo_data = BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    data = {
        "photo": (photo_data, "test.png"),
        "note": "Test note",
        "checkpoint_name": "Before Photos",
        "nonce": nonce,
        "gps_lat": "40.7128",
        "gps_lon": "-74.0060",
    }

    response = client.post(
        "/api/captures/nonexistent_pack/seal",
        data=data,
        content_type="multipart/form-data",
        headers=mock_jwt_header
    )

    assert response.status_code == 404


def test_verify_capture(client):
    """POST /api/captures/:pack_id/verify - Offline verify a sealed capture."""
    # Create a valid capture
    nonce = "a" * 64

    request_body = {
        "photo_bytes": "fake_photo_data",
        "note": "Test note",
        "checkpoint_name": "Before Photos",
        "nonce": nonce,
        "gps_lat": 40.7128,
        "gps_lon": -74.0060,
        "timestamp": int(time.time()),
        "device_bind_hash": None,
        "bind_hash": "b" * 64,
        "account_id": "test_user"
    }

    response = client.post(
        "/api/captures/remodel/verify",
        json=request_body
    )

    # Will fail verification (fake hash), but endpoint should return valid response
    assert response.status_code == 200
    result = response.get_json()
    assert "valid" in result
    assert "reason" in result


# ============================================================================
# Manifest Submission Tests (2 tests)
# ============================================================================

def test_submit_manifest_incomplete_pack(client, mock_jwt_header, mock_supabase):
    """POST /api/manifests/:pack_id/submit - 400 if checkpoints missing."""
    # Remodel pack has 5 checkpoints, submit only 1
    # Use base64 for photo_bytes to make it JSON serializable
    import base64
    manifest = [
        {
            "checkpoint_name": "Before Photos",
            "photo_bytes": base64.b64encode(b"fake_photo_1").decode("utf-8"),
            "note": "Note 1",
            "bind_hash": "c" * 64,
            "nonce": "a" * 64,
            "gps_lat": 40.7128,
            "gps_lon": -74.0060,
            "timestamp": int(time.time())
        }
    ]

    response = client.post(
        "/api/manifests/remodel/submit",
        json=manifest,
        headers=mock_jwt_header
    )

    # Should return 400 for incomplete pack
    assert response.status_code == 400


# ============================================================================
# Export & Verification Tests (2 tests)
# ============================================================================

def test_get_manifest(client, mock_jwt_header, mock_supabase):
    """GET /api/manifests/:manifest_id - Retrieve manifest metadata."""
    response = client.get(
        "/api/manifests/test_manifest_id",
        headers=mock_jwt_header
    )

    # 404 if manifest doesn't exist (which it shouldn't in test)
    assert response.status_code == 404


def test_get_manifest_pdf(client, mock_jwt_header, mock_supabase):
    """GET /api/manifests/:manifest_id/pdf - Download manifest as PDF."""
    response = client.get(
        "/api/manifests/test_manifest_id/pdf",
        headers=mock_jwt_header
    )

    # 404 if manifest doesn't exist
    assert response.status_code == 404


def test_verify_manifest_offline(client):
    """POST /api/manifests/:manifest_id/verify-offline - Offline verification."""
    request_body = {
        "manifest": [],
        "manifest_hash": "a" * 64,
        "chain_head_hash": "b" * 64
    }

    response = client.post(
        "/api/manifests/test_manifest_id/verify-offline",
        json=request_body
    )

    assert response.status_code in [200, 400]


# ============================================================================
# Configuration & Metadata Tests (3 tests)
# ============================================================================

def test_get_shield_config(client):
    """GET /api/config/shields - Return Shield configuration."""
    response = client.get("/api/config/shields")
    assert response.status_code == 200

    data = response.get_json()
    assert "version" in data
    assert "features" in data
    assert isinstance(data["features"], list)


def test_get_location_config(client):
    """GET /api/config/location - Return location verification settings."""
    response = client.get("/api/config/location")
    assert response.status_code == 200

    data = response.get_json()
    assert "impossible_speed_mph" in data
    assert "unrealistic_speed_mph" in data


def test_api_health_check(client, mock_supabase):
    """GET /api/health - Health check endpoint."""
    # Mock the database call to succeed
    mock_supabase.table.return_value.select.return_value.limit.return_value.execute.return_value = MagicMock(
        data=[{"id": "test"}]
    )

    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.get_json()
    assert "status" in data


# ============================================================================
# Admin/Monitoring Tests (2 tests)
# ============================================================================

def test_admin_list_manifests_forbidden(client, mock_jwt_header, mock_supabase):
    """GET /api/admin/manifests - Returns 403 for non-admin."""
    response = client.get(
        "/api/admin/manifests",
        headers=mock_jwt_header
    )

    # Non-admin should get 403
    assert response.status_code == 403


def test_admin_verify_manifest_forbidden(client, mock_jwt_header, mock_supabase):
    """POST /api/admin/verify/:manifest_id - Returns 403 for non-admin."""
    response = client.post(
        "/api/admin/verify/test_manifest_id",
        headers=mock_jwt_header
    )

    # Non-admin should get 403
    assert response.status_code == 403


# ============================================================================
# Legacy/Utility Tests (2 tests)
# ============================================================================

def test_get_jobs_legacy(client, mock_supabase):
    """GET /api/jobs - Verify existing endpoint still works."""
    mock_supabase.table.return_value.select.return_value.eq.return_value.order.return_value.range.return_value.execute.return_value = MagicMock(
        data=[],
        count=0
    )

    response = client.get("/api/jobs")
    assert response.status_code == 200


def test_post_jobs_legacy(client, mock_jwt_header, mock_supabase):
    """POST /api/jobs - Verify existing endpoint still works."""
    request_body = {
        "title": "Test Job",
        "trade": "Framing",
        "location": "Salt Lake City",
        "description": "Test description"
    }

    mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock(
        data=[request_body]
    )

    response = client.post(
        "/api/jobs",
        json=request_body,
        headers=mock_jwt_header
    )

    assert response.status_code in [200, 201]


# ============================================================================
# Error Handling Tests (2 tests)
# ============================================================================

def test_missing_jwt_token(client):
    """Missing JWT should return 401."""
    response = client.post("/api/packs/custom", json={})
    # Endpoints requiring auth should return 401 without JWT
    assert response.status_code == 401


def test_missing_required_fields(client, mock_jwt_header, mock_supabase):
    """Missing required fields should return 400."""
    response = client.post(
        "/api/packs/custom",
        json={},  # Missing required fields
        headers=mock_jwt_header
    )

    assert response.status_code == 400
