"""Pytest configuration and fixtures."""
import os
import sys
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_path))

# Set default environment variables for tests
os.environ.setdefault("OPENAI_API_KEY", "test-key-for-testing")

# Ensure tests don't mutate the tracked dev DB (backend/acpg.db).
_test_db_path = (Path(__file__).parent.parent / ".pytest_acpg.db").resolve()
try:
    _test_db_path.unlink()
except FileNotFoundError:
    pass
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_test_db_path}")
