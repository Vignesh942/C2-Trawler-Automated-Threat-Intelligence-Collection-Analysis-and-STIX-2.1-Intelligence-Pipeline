"""Application configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency fallback
    load_dotenv = None


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    threatfox_api_key: str | None = None
    request_timeout: int = 120
    log_level: str = "INFO"


def load_settings(env_file: str = ".env") -> Settings:
    """Load optional configuration from a .env file."""
    if load_dotenv is not None:
        load_dotenv(env_file)

    timeout = os.getenv("REQUEST_TIMEOUT", "120")
    try:
        request_timeout = int(timeout)
    except ValueError:
        request_timeout = 120

    return Settings(
        threatfox_api_key=os.getenv("THREATFOX_API_KEY") or None,
        request_timeout=request_timeout,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )

