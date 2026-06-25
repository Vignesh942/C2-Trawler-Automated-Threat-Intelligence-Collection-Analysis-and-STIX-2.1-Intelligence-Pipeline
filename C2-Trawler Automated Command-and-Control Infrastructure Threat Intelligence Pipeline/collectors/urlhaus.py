"""URLHaus collector for recent malicious URLs."""

from __future__ import annotations

import logging
from typing import Any

from utils.http_client import get_json
from utils.json_store import write_json
from utils.sample_data import sample_urlhaus


class URLHausCollector:
    """Collect malicious URL indicators from the free URLHaus recent JSON feed."""

    FEED_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"

    def __init__(self, raw_path: str = "data/raw/urlhaus_raw.json", timeout: int = 120) -> None:
        self.raw_path = raw_path
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)

    def collect(self, sample: bool = False) -> dict[str, Any]:
        """Collect URLHaus records and save the raw feed response."""
        if sample:
            payload = sample_urlhaus()
            write_json(self.raw_path, payload)
            return payload

        try:
            payload = get_json(self.FEED_URL, timeout=self.timeout)
        except Exception as exc:
            self.logger.warning("URLHaus collection failed: %s", exc)
            payload = {"error": str(exc), "urls": {}}

        write_json(self.raw_path, payload)
        return payload
