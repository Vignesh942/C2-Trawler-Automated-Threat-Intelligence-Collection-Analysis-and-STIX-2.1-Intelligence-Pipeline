"""OpenPhish collector for public phishing URLs."""

from __future__ import annotations

import logging
from typing import Any

from utils.http_client import get_text
from utils.json_store import write_json
from utils.sample_data import sample_openphish


class OpenPhishCollector:
    """Collect phishing URL indicators from the free OpenPhish feed."""

    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, raw_path: str = "data/raw/openphish_raw.json", timeout: int = 120) -> None:
        self.raw_path = raw_path
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)

    def collect(self, sample: bool = False) -> dict[str, Any]:
        """Collect OpenPhish URLs and save them as JSON-wrapped raw feed data."""
        if sample:
            payload = sample_openphish()
            write_json(self.raw_path, payload)
            return payload

        try:
            text = get_text(self.FEED_URL, timeout=self.timeout)
            urls = [line.strip() for line in text.splitlines() if line.strip()]
            payload: dict[str, Any] = {"feed": "OpenPhish", "urls": urls}
        except Exception as exc:
            self.logger.warning("OpenPhish collection failed: %s", exc)
            payload = {"feed": "OpenPhish", "urls": [], "error": str(exc)}

        write_json(self.raw_path, payload)
        return payload
