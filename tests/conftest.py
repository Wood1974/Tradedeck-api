"""
Pytest configuration and shared fixtures for Shield Capture tests.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set required environment variables for testing
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test_service_key")
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_123456")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "test_webhook_secret")
os.environ.setdefault("ANTHROPIC_API_KEY", "test_anthropic_key")
