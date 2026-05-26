import ipaddress
import logging
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, List, Optional
from urllib.parse import urlparse

import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger(__name__)

# =============================================================================
# Security Constants
# =============================================================================

DATABASE_PATH = "test.db"

SAFE_FILE_BASE = Path("./data").resolve()

ALLOWED_COMMANDS = {
    "date": ["date"],
    "uptime": ["uptime"],
}

ALLOWED_API_HOSTS = {
    "api.secure-domain.com",
}

REQUEST_TIMEOUT = 5

# =============================================================================
# Password Hashing
# =============================================================================

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash password using Argon2."""
    return password_hasher.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password securely."""
    try:
        return password_hasher.verify(hashed_password, password)
    except VerifyMismatchError:
        return False


# =============================================================================
# Database
# =============================================================================

def get_user_password_hash(username: str) -> Optional[str]:
    """Fetch password hash from database."""

    if not isinstance(username, str):
        return None

    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )

        result = cursor.fetchone()

    if result is None:
        return None

    return result[0]


def login(username: str, password: str) -> bool:
    """Secure login flow."""

    if not username or not password:
        return False

    stored_hash = get_user_password_hash(username)

    if stored_hash is None:
        return False

    return verify_password(password, stored_hash)


# =============================================================================
# Token Generation
# =============================================================================

def generate_secure_token() -> str:
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(32)


# =============================================================================
# Safe Command Execution
# =============================================================================

def run_allowed_command(command_name: str) -> str:
    """Run only allowlisted commands."""

    if command_name not in ALLOWED_COMMANDS:
        raise ValueError("Command not allowed")

    cmd = ALLOWED_COMMANDS[command_name]

    result = subprocess.run(
        cmd,
        shell=False,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )

    return result.stdout


# =============================================================================
# IP Validation
# =============================================================================

def validate_ip(ip: str) -> bool:
    """Validate IPv4 / IPv6 address."""

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ping_host(ip: str) -> bool:
    """Safely ping validated IP."""

    if not validate_ip(ip):
        raise ValueError("Invalid IP address")

    try:
        subprocess.run(
            ["ping", "-c", "1", ip],
            shell=False,
            check=True,
            timeout=3,
            capture_output=True,
        )

        return True

    except subprocess.SubprocessError as e:
        logger.error("Ping failed: %s", e)
        return False


# =============================================================================
# Safe File Access
# =============================================================================

def safe_read_file(file_name: str) -> str:
    """Prevent path traversal."""

    target_path = (SAFE_FILE_BASE / file_name).resolve()

    if not str(target_path).startswith(str(SAFE_FILE_BASE)):
        raise ValueError("Invalid file path")

    with open(target_path, "r", encoding="utf-8") as file:
        return file.read()


# =============================================================================
# SSRF Protection
# =============================================================================

def validate_api_url(url: str) -> bool:
    """Allow only trusted domains."""

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return False

    if parsed.hostname not in ALLOWED_API_HOSTS:
        return False

    return True


def call_api() -> str:
    """Safely call external API."""

    url = os.getenv(
        "API_ENDPOINT",
        "https://api.secure-domain.com/data"
    )

    if not validate_api_url(url):
        raise ValueError("Untrusted API endpoint")

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        return response.text

    except requests.RequestException as e:
        logger.error("API request failed: %s", e)
        return ""


# =============================================================================
# Safe JSON Parsing
# =============================================================================

def load_json_safe(data: str) -> Any:
    """Safely parse JSON with size limit."""

    import json

    MAX_SIZE = 10000

    if len(data) > MAX_SIZE:
        raise ValueError("JSON payload too large")

    return json.loads(data)


# =============================================================================
# Utility Functions
# =============================================================================

def divide(a: float, b: float) -> Optional[float]:
    """Safe division."""

    if b == 0:
        logger.warning("Division by zero attempted")
        return None

    return a / b


def append_item(
    item: Any,
    items: Optional[List[Any]] = None
) -> List[Any]:
    """Avoid mutable default arguments."""

    if items is None:
        items = []

    items.append(item)

    return items


# =============================================================================
# Safe Recursive Function
# =============================================================================

def recursive(depth: int = 0, max_depth: int = 10) -> None:
    """
    Recursive function with a safe exit condition.

    Args:
        depth (int): Current recursion depth.
        max_depth (int): Maximum allowed recursion depth.
    """

    logger.info("Current recursion depth: %s", depth)

    # Base case to stop recursion
    if depth >= max_depth:
        logger.info("Maximum recursion depth reached")
        return

    # Recursive call
    recursive(depth + 1, max_depth)


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":

    logger.info("Application started")

    token = generate_secure_token()

    logger.info("Generated token successfully")

    print(token)

    try:
        output = run_allowed_command("date")
        print(output)

    except Exception as e:
        logger.error("Command execution error: %s", e)

    # Test recursive function
    recursive()
