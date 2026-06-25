"""Export intelligence artifacts for downstream tools."""

from __future__ import annotations

import csv
from typing import Any

from utils.json_store import read_json, write_json


class IntelligenceExporter:
    """Export IOC data in JSON and CSV formats."""

    def __init__(
        self,
        input_path: str = "data/enriched_iocs.json",
        fallback_path: str = "data/unique_iocs.json",
        json_path: str = "exports/iocs.json",
        csv_path: str = "exports/iocs.csv",
    ) -> None:
        self.input_path = input_path
        self.fallback_path = fallback_path
        self.json_path = json_path
        self.csv_path = csv_path

    def export(self) -> list[dict[str, Any]]:
        """Export IOC records to JSON and CSV."""
        records = read_json(self.input_path, None)
        if records is None:
            records = read_json(self.fallback_path, [])
        write_json(self.json_path, records)
        self._write_csv(records)
        return records

    def _write_csv(self, records: list[dict[str, Any]]) -> None:
        fieldnames = [
            "indicator_type",
            "value",
            "malware_family",
            "source",
            "threat_category",
            "first_seen",
            "reverse_dns",
            "asn",
            "country",
            "network_name",
            "hostname",
            "resolved_ip",
            "registrar",
        ]
        with open(self.csv_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                enrichment = record.get("enrichment") or {}
                row = {field: record.get(field) for field in fieldnames}
                row.update({field: enrichment.get(field) for field in fieldnames if field in enrichment})
                writer.writerow(row)

