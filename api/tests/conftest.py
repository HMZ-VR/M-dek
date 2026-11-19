"""pytest configuration — make `api/` importable as a package root."""
import os
import sys
from pathlib import Path

# Ensure SECRET_KEY is set before any api modules are imported (database.py fails fast).
os.environ.setdefault(
    "SECRET_KEY",
    "test-secret-key-for-pytest-only-not-production-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
)
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/test_does_not_exist")

API_ROOT = Path(__file__).resolve().parent.parent
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))
