"""Backend configuration and settings for ScamShield-AI."""

from __future__ import annotations

import os
from pathlib import Path

# Mitigate Windows OpenBLAS memory pool allocation limits in Python 3.12
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

# Resolve project root (c:\Users\hp\OneDrive\Desktop\ShieldAI)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# ML model path
MODEL_PATH = PROJECT_ROOT / "ml" / "models" / "model.joblib"

# API Settings
API_TITLE = "ScamShield-AI API"
API_VERSION = "1.0.0"
API_PREFIX = "/api/v1"

# Host and Port configuration (configurable via environment variables)
API_HOST = os.environ.get("SCAMSHIELD_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("SCAMSHIELD_PORT", "8000"))

# Explicit local frontend development origins for CORS (Vite, React, Next.js, Vue)
DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def get_cors_origins() -> list[str]:
    """Parse allowed CORS origins from environment variable or return safe local defaults.

    Origins can be specified as a comma-separated list via CORS_ALLOWED_ORIGINS.
    Wildcard '*' is disallowed when credentials are enabled.
    """
    raw_env = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if raw_env.strip():
        parsed = [
            origin.strip()
            for origin in raw_env.split(",")
            if origin.strip() and origin.strip() != "*"
        ]
        if parsed:
            return parsed
    return list(DEFAULT_CORS_ORIGINS)


CORS_ORIGINS = get_cors_origins()

# Validation limits
MAX_TEXT_LENGTH = 5000
MIN_TEXT_LENGTH = 1

# Threat Intelligence / Reputation settings
REPUTATION_FEED_PATH = PROJECT_ROOT / "backend" / "data" / "reputation" / "threat_feed.json"
REPUTATION_FEED_MAX_AGE_DAYS = 7

# Image Scanning & OCR settings
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_IMAGE_WIDTH = 10000
MAX_IMAGE_HEIGHT = 10000
MAX_IMAGE_PIXELS = 25_000_000  # 25 MP pixel limit to prevent decompression bombs
MAX_EXTRACTED_URLS = 20
TESSERACT_CMD = os.environ.get("TESSERACT_CMD", None)
OCR_ENGINE = os.environ.get("OCR_ENGINE", "auto").lower()


