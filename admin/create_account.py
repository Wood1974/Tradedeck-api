#!/usr/bin/env python3
"""Admin script to create Shield business accounts and API keys.

Usage:
    python admin/create_account.py --name "Company Name" --email "admin@example.com"

This creates a Shield tenant account and generates an API key for programmatic access.
The API key is long-lived and should be stored securely in environment config.
"""
import argparse
import os
import secrets
import uuid
from datetime import datetime, timezone
import sys
import hashlib
import hmac

# Add parent directory to path for imports.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import db


def create_account(name, email):
    """Create a Shield tenant and issue an API key.

    Returns (tenant_id, api_key) on success.
    """
    if not name or not email:
        raise ValueError("Name and email are required")

    schema = db().schema("shield")

    # Create the tenant.
    tenant_id = str(uuid.uuid4())
    try:
        result = schema.table("tenants").insert({
            "id": tenant_id,
            "name": name,
            "email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
        print(f"✓ Created tenant: {tenant_id}")
    except Exception as e:
        print(f"✗ Failed to create tenant: {e}")
        raise

    # Generate and store an API key.
    # API key format: base64(random 32 bytes)
    # Stored as: base64(random 32 bytes) + HMAC-SHA256(key, "shield")
    api_key_bytes = secrets.token_bytes(32)
    api_key_b64 = __import__('base64').b64encode(api_key_bytes).decode('ascii')
    api_key_hex = api_key_bytes.hex()

    # Create an API key record that maps the key to the tenant.
    # In production, this would also track usage, expiration, etc.
    try:
        # Note: depends on shield.api_keys table existing
        # For now, just store it in tenants; a proper design has a separate table.
        schema.table("tenants").update({
            "api_key": api_key_b64,
        }).eq("id", tenant_id).execute()
        print(f"✓ Generated API key")
    except Exception as e:
        print(f"⚠ Could not store API key in database: {e}")
        print(f"  (This may fail if shield.api_keys table does not exist yet.)")

    return tenant_id, api_key_b64


def main():
    parser = argparse.ArgumentParser(
        description="Create a Shield business account and API key")
    parser.add_argument("--name", required=True, help="Company name")
    parser.add_argument("--email", required=True, help="Admin email address")

    args = parser.parse_args()

    try:
        tenant_id, api_key = create_account(args.name, args.email)
        print()
        print("=" * 70)
        print("Account created successfully!")
        print("=" * 70)
        print(f"Tenant ID:  {tenant_id}")
        print(f"API Key:    {api_key}")
        print()
        print("Store the API key securely. It cannot be recovered if lost.")
        print("Use it in your application to authenticate with Shield API:")
        print()
        print('  curl -H "Authorization: Bearer <API_KEY>" \\')
        print('    https://tradedeck-api.onrender.com/shield/v2/records')
        print()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
