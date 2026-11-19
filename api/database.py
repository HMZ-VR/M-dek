# database.py
import os
import sys

DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres@localhost:5432/mudek_db")

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()

_WEAK_SECRETS = {"", "super-secret-key", "changeme", "secret", "dev"}
if SECRET_KEY in _WEAK_SECRETS or len(SECRET_KEY) < 32:
    sys.stderr.write(
        "FATAL: SECRET_KEY environment variable is missing or too weak. "
        "Generate a strong key with: python3 -c \"import secrets; print(secrets.token_urlsafe(64))\" "
        "and set it in the .env file. The application will refuse to start with the default key.\n"
    )
    sys.exit(1)
