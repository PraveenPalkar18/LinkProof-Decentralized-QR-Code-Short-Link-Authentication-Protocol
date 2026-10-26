"""LinkProof Configuration Module."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Automatically load local .env if present without requiring extra third-party dependencies
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    try:
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip()
                    _v = _v.strip().strip('"').strip("'")
                    if _k not in os.environ:
                        os.environ[_k] = _v
    except Exception:
        pass


class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "linkproof-cns-security-secret-key-2026-fallback")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "data" / "linkproof.db"))
    PUBLISHER_KEY_DIR = os.environ.get("PUBLISHER_KEY_DIR", str(BASE_DIR / "data" / "publisher_keys"))

    # Cryptographic protocol specifications
    PROTOCOL_NAME = "linkproof"
    PROTOCOL_VERSION = "1.0"
    SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"

    # Multi-hop redirect & network safety
    MAX_REDIRECT_HOPS = int(os.environ.get("MAX_REDIRECT_HOPS", 10))
    HTTP_TIMEOUT_SECONDS = float(os.environ.get("HTTP_TIMEOUT_SECONDS", 5.0))
    MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", 524288))  # 512 KB
    ALLOWED_SCHEMES = ("http", "https")
    BLOCK_PRIVATE_NETWORKS = os.environ.get("BLOCK_PRIVATE_IPS", "True").lower() in ("true", "1", "yes")

    # File Upload Limits
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp"}

    # Threat Intelligence Integration (Google Safe Browsing v4)
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    SAFE_BROWSING_TIMEOUT_SECONDS = float(os.environ.get("SAFE_BROWSING_TIMEOUT_SECONDS", 4.0))

class TestConfig(Config):
    """Configuration for automated test suite."""
    TESTING = True
    DATABASE_PATH = ":memory:"
    SECRET_KEY = "test-secret-key-only-for-automated-tests"
    BLOCK_PRIVATE_NETWORKS = True
    GOOGLE_SAFE_BROWSING_API_KEY = ""
