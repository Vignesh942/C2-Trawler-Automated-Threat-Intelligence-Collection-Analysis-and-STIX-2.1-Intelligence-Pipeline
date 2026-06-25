"""Filesystem helpers for project paths."""

from __future__ import annotations

from pathlib import Path


REQUIRED_DIRECTORIES = [
    "data/raw",
    "data/processed",
    "exports",
    "logs",
    "reports",
]


def ensure_directories() -> None:
    """Create the standard project output directories."""
    for directory in REQUIRED_DIRECTORIES:
        Path(directory).mkdir(parents=True, exist_ok=True)

