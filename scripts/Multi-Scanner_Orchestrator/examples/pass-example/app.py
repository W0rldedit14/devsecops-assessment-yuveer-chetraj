"""
Clean example application - no security issues.
This example should PASS all three scan categories:
- Secrets: No hardcoded secrets
- Dependencies: No vulnerable packages
- SAST: No code vulnerabilities
"""

import os
import hashlib
import logging

logger = logging.getLogger(__name__)


def get_database_url():
    """Securely retrieve database URL from environment variables."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL environment variable is not set")
    return db_url


def hash_password(password: str, salt: str) -> str:
    """Hash a password using a secure algorithm."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()


def get_user_by_id(db_connection, user_id: int):
    """Safely query user by ID using parameterized query."""
    query = "SELECT * FROM users WHERE id = %s"
    cursor = db_connection.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


def read_config(config_path: str) -> dict:
    """Read configuration from a file safely."""
    import json
    with open(config_path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Application starting...")
    db_url = get_database_url()
    logger.info("Connected to database successfully")
