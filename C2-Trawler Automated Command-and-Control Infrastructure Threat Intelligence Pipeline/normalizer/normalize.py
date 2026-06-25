"""Normalize raw feed responses into the C2-Trawler IOC schema."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from utils.indicators import detect_indicator_type, normalize_indicator_value, today_utc
from utils.json_store import read_json, write_json
from utils.malware_families import GENERIC_LABELS, canonicalize_malware_family


class IOCNormalizer:
    """Transform raw feed data into a common IOC schema."""

    def __init__(self, raw_dir: str = "data/raw", output_path: str = "data/normalized_iocs.json") -> None:
        self.raw_dir = Path(raw_dir)
        self.output_path = output_path
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def _extract_tags(tags: list[str] | None) -> dict[str, list[str]]:
        """Extract and categorize tags into infrastructure attributes and threat tags."""
        result = {
            "infrastructure_attributes": [],
            "threat_tags": [],
            "other_tags": [],
        }

        if not tags or not isinstance(tags, list):
            return result

        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag_lower = tag.strip().lower()
            if tag_lower in GENERIC_LABELS:
                result["threat_tags"].append(tag)
            elif canonicalize_malware_family(tag):
                result["other_tags"].append(tag)
            else:
                result["infrastructure_attributes"].append(tag)

        return result

    def normalize(self) -> list[dict[str, Any]]:
        """Normalize all supported raw feed files."""
        records: list[dict[str, Any]] = []
        records.extend(self._normalize_threatfox(read_json(self.raw_dir / "threatfox_raw.json", {})))
        records.extend(self._normalize_urlhaus(read_json(self.raw_dir / "urlhaus_raw.json", {})))
        records.extend(self._normalize_openphish(read_json(self.raw_dir / "openphish_raw.json", {})))
        write_json(self.output_path, records)
        self.logger.info("Normalized %d IOC records", len(records))
        return records

    def _build_record(
        self,
        value: str,
        indicator_type: str | None,
        malware_family: str | None,
        source: str,
        threat_category: str | None,
        first_seen: str | None,
        tags: list[str] | None = None,
    ) -> dict[str, Any] | None:
        if not value or not value.strip():
            return None

        detected_type = detect_indicator_type(value, indicator_type)
        if detected_type not in {"ipv4", "domain", "url"}:
            return None

        normalized_value = normalize_indicator_value(value, detected_type)
        if not normalized_value:
            return None

        valid_family = canonicalize_malware_family(malware_family)
        categorized_tags = self._extract_tags(tags)

        return {
            "indicator_type": detected_type,
            "value": normalized_value,
            "malware_family": valid_family or "Unknown",
            "source": source,
            "threat_category": threat_category or "unknown",
            "first_seen": first_seen or today_utc(),
            "tags": categorized_tags,
            "raw_tags": tags or [],
        }

    def _normalize_threatfox(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for item in payload.get("data") or []:
            record = self._build_record(
                value=str(item.get("ioc", "")),
                indicator_type=str(item.get("ioc_type", "")),
                malware_family=item.get("malware_printable") or item.get("malware"),
                source="ThreatFox",
                threat_category=item.get("threat_type"),
                first_seen=item.get("first_seen"),
                tags=item.get("tags"),
            )
            if record:
                records.append(record)
        return records

    def _normalize_urlhaus(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for entry in payload.values():
            items = entry if isinstance(entry, list) else [entry]
            for item in items:
                if not isinstance(item, dict):
                    continue
                record = self._normalize_urlhaus_item(item)
                if record:
                    records.append(record)
        return records

    def _normalize_urlhaus_item(self, item: dict[str, Any]) -> dict[str, Any] | None:
        tags = item.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)]

        malware_family = None
        for tag in tags:
            if isinstance(tag, str):
                family = canonicalize_malware_family(tag)
                if family:
                    malware_family = family
                    break

        return self._build_record(
            value=str(item.get("url", "")),
            indicator_type="url",
            malware_family=malware_family,
            source="URLHaus",
            threat_category=item.get("threat"),
            first_seen=item.get("dateadded"),
            tags=tags,
        )

    def _normalize_openphish(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for url in payload.get("urls") or []:
            record = self._build_record(
                value=str(url),
                indicator_type="url",
                malware_family="Phishing",
                source="OpenPhish",
                threat_category="phishing",
                first_seen=today_utc(),
                tags=["phishing"],
            )
            if record:
                records.append(record)
        return records
