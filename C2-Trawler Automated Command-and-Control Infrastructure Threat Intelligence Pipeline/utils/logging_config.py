"""Logging setup for CLI and modules."""

from __future__ import annotations

import logging
from pathlib import Path


def setup_logging(level: str = "INFO") -> None:
    """Configure console and file logging."""
    Path("logs").mkdir(parents=True, exist_ok=True)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/c2_trawler.log", encoding="utf-8"),
        ],
        force=True,
    )

