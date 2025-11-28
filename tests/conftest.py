"""Pytest configuration and fixtures."""
import os
import sys
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_path))

# Set default environment variables for tests
os.environ.setdefault("OPENAI_API_KEY", "test-key-for-testing")

