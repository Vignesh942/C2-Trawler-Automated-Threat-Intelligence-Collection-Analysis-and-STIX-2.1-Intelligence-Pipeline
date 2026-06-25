"""Map observed malware families to local MITRE ATT&CK techniques."""

from __future__ import annotations

from collections import Counter
from typing import Any

from utils.json_store import read_json, write_json
from utils.malware_families import canonicalize_malware_family, resolve_mapping_key


class MitreMapper:
    """Apply local ATT&CK technique mappings to observed malware families."""

    def __init__(
        self,
        mappings_path: str = "mitre/mappings.json",
        iocs_path: str = "data/unique_iocs.json",
        output_path: str = "reports/mitre_mapping.json",
    ) -> None:
        self.mappings_path = mappings_path
        self.iocs_path = iocs_path
        self.output_path = output_path

    def map_observed_families(self) -> dict[str, Any]:
        """Create an observed-family mapping report."""
        mappings = read_json(self.mappings_path, {})
        records = read_json(self.iocs_path, [])
        family_counts: Counter[str] = Counter()

        for record in records:
            family = canonicalize_malware_family(record.get("malware_family")) or "Unknown"
            family_counts[family] += 1

        observed: dict[str, Any] = {}
        technique_counts: Counter[str] = Counter()

        for family, count in family_counts.most_common():
            if family == "Unknown":
                continue
            mapping_key = resolve_mapping_key(family, mappings)
            techniques = mappings.get(mapping_key or "", mappings.get("Unknown", []))
            observed[family] = {"indicator_count": count, "techniques": techniques}
            for technique in techniques:
                technique_counts[technique["id"]] += count

        result = {
            "observed_malware_families": observed,
            "most_observed_attack_techniques": [
                {
                    "id": technique_id,
                    "count": count,
                    "name": self._technique_name(technique_id, mappings),
                }
                for technique_id, count in technique_counts.most_common()
            ],
        }
        write_json(self.output_path, result)
        return result

    @staticmethod
    def _technique_name(technique_id: str, mappings: dict[str, Any]) -> str:
        for techniques in mappings.values():
            for technique in techniques:
                if technique.get("id") == technique_id:
                    return str(technique.get("name"))
        return "Unknown"
