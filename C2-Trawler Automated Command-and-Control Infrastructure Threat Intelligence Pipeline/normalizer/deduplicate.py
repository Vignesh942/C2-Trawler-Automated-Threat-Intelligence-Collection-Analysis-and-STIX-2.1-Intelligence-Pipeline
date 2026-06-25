"""Deduplicate normalized IOC records."""

from __future__ import annotations

import logging
from typing import Any

from utils.json_store import merge_unique_indicators, read_json, write_json


class DeduplicationEngine:
    """Remove duplicate indicators and merge repeated JSON memory safely."""

    def __init__(
        self,
        normalized_path: str = "data/normalized_iocs.json",
        output_path: str = "data/unique_iocs.json",
    ) -> None:
        self.normalized_path = normalized_path
        self.output_path = output_path
        self.logger = logging.getLogger(self.__class__.__name__)

    def deduplicate(self, include_existing: bool = False) -> list[dict[str, Any]]:
        """Deduplicate normalized IOCs and optionally merge with existing unique output."""
        normalized = read_json(self.normalized_path, [])
        existing = read_json(self.output_path, []) if include_existing else []
        unique = merge_unique_indicators(existing, normalized)
        write_json(self.output_path, unique)
        self.logger.info("Deduplicated %d normalized records into %d unique IOCs", len(normalized), len(unique))
        return unique
