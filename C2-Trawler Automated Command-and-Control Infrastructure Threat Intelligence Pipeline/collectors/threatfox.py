"""ThreatFox collector for recent malware infrastructure indicators."""

from __future__ import annotations

import logging
import os
from typing import Any

from utils.http_client import post_json
from utils.json_store import write_json
from utils.sample_data import sample_threatfox


class ThreatFoxCollector:
    """Collect indicators from the free ThreatFox API."""

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(
        self,
        raw_path: str = "data/raw/threatfox_raw.json",
        timeout: int = 120,
        api_key: str | None = None,
    ) -> None:
        self.raw_path = raw_path
        self.timeout = timeout
        self.api_key = api_key or os.getenv("THREATFOX_API_KEY")
        self.logger = logging.getLogger(self.__class__.__name__)

    def collect(self, days: int = 3, sample: bool = False) -> dict[str, Any]:
        """Collect recent ThreatFox IOCs and save the raw API response."""
        if sample:
            payload = sample_threatfox()
            write_json(self.raw_path, payload)
            return payload

        request_body = {"query": "get_iocs", "days": days}
        headers = {"Auth-Key": self.api_key} if self.api_key else None
        try:
            payload = post_json(self.API_URL, request_body, timeout=self.timeout, headers=headers)
        except Exception as exc:
            if "401" in str(exc):
                self.logger.warning(
                    "ThreatFox collection failed with 401 Unauthorized. Add THREATFOX_API_KEY to .env if your "
                    "ThreatFox access requires authentication."
                )
            else:
                self.logger.warning("ThreatFox collection failed: %s", exc)
            payload = {"query_status": "error", "data": [], "error": str(exc)}

        write_json(self.raw_path, payload)
        return payload
