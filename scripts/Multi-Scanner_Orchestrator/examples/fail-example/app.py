"""
Vulnerable example application - security issues in all categories.
This example should FAIL all three scan categories:
- Secrets: Hardcoded credentials and API keys
- Dependencies: Vulnerable packages in requirements.txt
- SAST: SQL injection, command injection, insecure crypto
"""

import os
import hashlib
import subprocess
import sqlite3

# SECRETS: Hardcoded credentials (will be flagged by Checkov secrets)
DATABASE_PASSWORD = "SuperSecretPassword123!"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU7jzKFDPTnFEBKGMJR4EXAMPLEKEY0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----"""


def get_user(username):
    """SAST: SQL Injection vulnerability."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def run_system_command(user_input):
    """SAST: Command injection vulnerability."""
    # Vulnerable: unsanitized user input in shell command
    result = subprocess.call("echo " + user_input, shell=True)
    return result


def weak_hash(password):
    """SAST: Use of weak cryptographic hash."""
    # Vulnerable: MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def read_file(filename):
    """SAST: Path traversal vulnerability."""
    # Vulnerable: no sanitization of filename
    with open("/app/data/" + filename, "r") as f:
        return f.read()


def insecure_deserialization(data):
    """SAST: Insecure deserialization."""
    import pickle
    # Vulnerable: deserializing untrusted data
    return pickle.loads(data)


def send_request(url):
    """SAST: SSRF vulnerability - no URL validation."""
    import requests
    # Vulnerable: no validation of URL, could be internal service
    response = requests.get(url, verify=False)
    return response.text


def log_sensitive_data(user):
    """SAST: Logging sensitive information."""
    print(f"User login: {user['username']}, password: {user['password']}")


if __name__ == "__main__":
    # Hardcoded connection string
    db_url = f"postgresql://admin:{DATABASE_PASSWORD}@localhost:5432/myapp"
    print(f"Connecting to: {db_url}")

    user = get_user("admin' OR '1'='1")
    run_system_command("hello; rm -rf /")
    weak_hash("password123")
