"""STIX 2.1 bundle generation."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from utils.indicators import today_utc
from utils.json_store import read_json, write_json
from utils.malware_families import canonicalize_malware_family

try:
    from stix2 import AttackPattern, Bundle, Identity, Indicator, Malware, Relationship, Report
except ImportError:  # pragma: no cover - dependency fallback
    AttackPattern = Bundle = Identity = Indicator = Malware = Relationship = Report = None

UNKNOWN_FAMILY = "Unattributed Infrastructure"
PIPELINE_IDENTITY = "C2-Trawler Threat Intelligence Pipeline"


class StixBuilder:
    """Build STIX 2.1 objects for indicators, malware families, and ATT&CK patterns."""

    def __init__(
        self,
        iocs_path: str = "data/unique_iocs.json",
        mitre_path: str = "reports/mitre_mapping.json",
        output_path: str = "exports/stix_bundle.json",
        report_copy_path: str = "reports/stix_bundle.json",
        max_indicators: int = 1000,
    ) -> None:
        self.iocs_path = iocs_path
        self.mitre_path = mitre_path
        self.output_path = output_path
        self.report_copy_path = report_copy_path
        self.max_indicators = max_indicators
        self.logger = logging.getLogger(self.__class__.__name__)

    def build(self) -> dict[str, Any]:
        """Generate and save a STIX 2.1 bundle."""
        records = read_json(self.iocs_path, [])
        mitre_mapping = read_json(self.mitre_path, {})
        if all([Bundle, Indicator, Malware, AttackPattern, Relationship, Identity, Report]):
            bundle = self._build_with_stix2(records, mitre_mapping)
        else:
            self.logger.warning("stix2 is unavailable; using standards-shaped fallback JSON")
            bundle = self._build_fallback(records, mitre_mapping)

        bundle = self._finalize_bundle(bundle, len(records))
        write_json(self.output_path, bundle)
        write_json(self.report_copy_path, bundle)
        self.logger.info(
            "Generated STIX 2.1 bundle with %d objects (%d indicators)",
            len(bundle.get("objects", [])),
            sum(1 for obj in bundle.get("objects", []) if obj.get("type") == "indicator"),
        )
        return bundle

    def _select_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.max_indicators <= 0 or len(records) <= self.max_indicators:
            return records
        self.logger.info("STIX generation limited to first %d of %d IOCs", self.max_indicators, len(records))
        return records[: self.max_indicators]

    def _family_name(self, record: dict[str, Any]) -> str:
        return canonicalize_malware_family(record.get("malware_family")) or UNKNOWN_FAMILY

    def _build_with_stix2(self, records: list[dict[str, Any]], mitre_mapping: dict[str, Any]) -> dict[str, Any]:
        objects: list[Any] = []
        malware_objects: dict[str, Any] = {}
        attack_objects: dict[str, Any] = {}
        indicator_ids: list[str] = []

        identity = Identity(name=PIPELINE_IDENTITY, identity_class="system")
        objects.append(identity)

        for record in self._select_records(records):
            family = self._family_name(record)
            malware = malware_objects.get(family)
            if malware is None:
                malware = Malware(
                    name=family,
                    is_family=True,
                    labels=["malware-family"] if family != UNKNOWN_FAMILY else ["threat-infrastructure"],
                )
                malware_objects[family] = malware
                objects.append(malware)

            indicator = Indicator(
                name=f"{record.get('indicator_type')} indicator: {record.get('value')}",
                description=f"Collected from {record.get('source', 'unknown source')}",
                pattern=self._stix_pattern(record),
                pattern_type="stix",
                valid_from=self._valid_from(record.get("first_seen")),
                indicator_types=["malicious-activity"],
                labels=[str(record.get("threat_category") or "unknown")],
            )
            objects.append(indicator)
            indicator_ids.append(indicator.id)
            objects.append(
                Relationship(
                    source_ref=indicator.id,
                    relationship_type="indicates",
                    target_ref=malware.id,
                )
            )

        for family, item in (mitre_mapping.get("observed_malware_families") or {}).items():
            if family == "Unknown":
                continue

            malware = malware_objects.get(family)
            if malware is None:
                malware = Malware(name=family, is_family=True, labels=["malware-family"])
                malware_objects[family] = malware
                objects.append(malware)

            for technique in item.get("techniques") or []:
                technique_id = technique.get("id")
                attack = attack_objects.get(technique_id)
                if attack is None:
                    attack = AttackPattern(
                        name=technique.get("name") or technique_id,
                        external_references=[
                            {
                                "source_name": "mitre-attack",
                                "external_id": technique_id,
                                "url": f"https://attack.mitre.org/techniques/{str(technique_id).replace('.', '/')}/",
                            }
                        ],
                    )
                    attack_objects[technique_id] = attack
                    objects.append(attack)
                objects.append(
                    Relationship(
                        source_ref=malware.id,
                        relationship_type="uses",
                        target_ref=attack.id,
                    )
                )

        report = Report(
            name=f"C2-Trawler Daily Threat Report ({today_utc()})",
            description="Automated C2 infrastructure collection with MITRE ATT&CK enrichment.",
            published=self._valid_from(today_utc()),
            report_types=["threat-actor", "indicator"],
            object_refs=indicator_ids[:100],
            created_by_ref=identity.id,
            labels=["c2-trawler", "automated-collection"],
        )
        objects.append(report)

        return json.loads(Bundle(objects=objects, allow_custom=False).serialize())

    def _build_fallback(self, records: list[dict[str, Any]], mitre_mapping: dict[str, Any]) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        malware_ids: dict[str, str] = {}
        attack_ids: dict[str, str] = {}
        indicator_ids: list[str] = []
        created = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        identity_id = f"identity--{uuid4()}"

        objects.append(
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created,
                "modified": created,
                "name": PIPELINE_IDENTITY,
                "identity_class": "system",
            }
        )

        for record in self._select_records(records):
            family = self._family_name(record)
            malware_id = malware_ids.setdefault(family, f"malware--{uuid4()}")
            if not any(obj.get("id") == malware_id for obj in objects):
                objects.append(
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": created,
                        "modified": created,
                        "name": family,
                        "is_family": True,
                        "labels": ["malware-family"] if family != UNKNOWN_FAMILY else ["threat-infrastructure"],
                    }
                )

            indicator_id = f"indicator--{uuid4()}"
            indicator_ids.append(indicator_id)
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": created,
                    "modified": created,
                    "name": f"{record.get('indicator_type')} indicator: {record.get('value')}",
                    "description": f"Collected from {record.get('source', 'unknown source')}",
                    "pattern": self._stix_pattern(record),
                    "pattern_type": "stix",
                    "valid_from": self._valid_from(record.get("first_seen")).isoformat().replace("+00:00", "Z"),
                    "indicator_types": ["malicious-activity"],
                    "labels": [str(record.get("threat_category") or "unknown")],
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid4()}",
                    "created": created,
                    "modified": created,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_id,
                }
            )

        for family, item in (mitre_mapping.get("observed_malware_families") or {}).items():
            if family == "Unknown":
                continue

            malware_id = malware_ids.setdefault(family, f"malware--{uuid4()}")
            if not any(obj.get("id") == malware_id for obj in objects):
                objects.append(
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": created,
                        "modified": created,
                        "name": family,
                        "is_family": True,
                        "labels": ["malware-family"],
                    }
                )

            for technique in item.get("techniques") or []:
                technique_id = technique.get("id")
                attack_id = attack_ids.setdefault(str(technique_id), f"attack-pattern--{uuid4()}")
                if not any(obj.get("id") == attack_id for obj in objects):
                    objects.append(
                        {
                            "type": "attack-pattern",
                            "spec_version": "2.1",
                            "id": attack_id,
                            "created": created,
                            "modified": created,
                            "name": technique.get("name") or technique_id,
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "external_id": technique_id,
                                    "url": f"https://attack.mitre.org/techniques/{str(technique_id).replace('.', '/')}/",
                                }
                            ],
                        }
                    )
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{uuid4()}",
                        "created": created,
                        "modified": created,
                        "relationship_type": "uses",
                        "source_ref": malware_id,
                        "target_ref": attack_id,
                    }
                )

        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": f"report--{uuid4()}",
                "created": created,
                "modified": created,
                "created_by_ref": identity_id,
                "name": f"C2-Trawler Daily Threat Report ({today_utc()})",
                "description": "Automated C2 infrastructure collection with MITRE ATT&CK enrichment.",
                "published": created,
                "report_types": ["threat-actor", "indicator"],
                "object_refs": indicator_ids[:100],
                "labels": ["c2-trawler", "automated-collection"],
            }
        )

        return {"type": "bundle", "id": f"bundle--{uuid4()}", "spec_version": "2.1", "objects": objects}

    @staticmethod
    def _finalize_bundle(bundle: dict[str, Any], total_records: int) -> dict[str, Any]:
        bundle["type"] = "bundle"
        bundle["spec_version"] = "2.1"
        bundle["x_c2_trawler_metadata"] = {
            "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source_ioc_count": total_records,
            "bundle_object_count": len(bundle.get("objects", [])),
        }
        return bundle

    @staticmethod
    def _stix_pattern(record: dict[str, Any]) -> str:
        value = str(record.get("value", "")).replace("\\", "\\\\").replace("'", "\\'")
        indicator_type = record.get("indicator_type")
        if indicator_type == "ipv4":
            return f"[ipv4-addr:value = '{value}']"
        if indicator_type == "domain":
            return f"[domain-name:value = '{value}']"
        return f"[url:value = '{value}']"

    @staticmethod
    def _valid_from(first_seen: Any) -> datetime:
        if isinstance(first_seen, str):
            cleaned = first_seen.replace(" UTC", "+00:00").replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(cleaned)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=UTC)
                return parsed
            except ValueError:
                try:
                    return datetime.strptime(first_seen[:10], "%Y-%m-%d").replace(tzinfo=UTC)
                except ValueError:
                    pass
        return datetime.now(UTC).replace(microsecond=0)
