"""Threat intelligence report generation."""

from __future__ import annotations

from collections import Counter
from typing import Any

from utils.indicators import today_utc
from utils.json_store import read_json, write_json


class ThreatReportGenerator:
    """Generate JSON and text reports for analysts."""

    def __init__(
        self,
        stats_path: str = "reports/malware_statistics.json",
        mitre_path: str = "reports/mitre_mapping.json",
        json_path: str = "reports/threat_report.json",
        text_path: str = "reports/threat_report.txt",
    ) -> None:
        self.stats_path = stats_path
        self.mitre_path = mitre_path
        self.json_path = json_path
        self.text_path = text_path

    def generate(self) -> dict[str, Any]:
        """Generate analyst-friendly JSON and text reports."""
        stats = read_json(self.stats_path, {})
        mitre = read_json(self.mitre_path, {})
        top_families = stats.get("top_malware_families") or []
        techniques = mitre.get("most_observed_attack_techniques") or []
        report = {
            "report_title": "C2-Trawler Threat Intelligence Report",
            "collection_date": today_utc(),
            "total_indicators_collected": stats.get("total_indicators", 0),
            "source_distribution": stats.get("source_distribution", {}),
            "malware_family_statistics": stats.get("indicator_count_per_malware_family", {}),
            "threat_type_distribution": stats.get("threat_type_distribution", {}),
            "ioc_type_distribution": stats.get("ioc_type_distribution", {}),
            "top_observed_threats": top_families[:10],
            "mitre_attack_mappings": mitre.get("observed_malware_families", {}),
            "most_observed_attack_techniques": techniques[:15],
            "summary_findings": self._summary(stats, techniques),
            "outputs": {
                "human_readable_report": self.text_path,
                "structured_report": self.json_path,
                "stix_bundle": "exports/stix_bundle.json",
                "ioc_exports": ["exports/iocs.json", "exports/iocs.csv"],
            },
        }
        write_json(self.json_path, report)
        self._write_text_report(report)
        return report

    def _summary(self, stats: dict[str, Any], techniques: list[dict[str, Any]]) -> list[str]:
        family_counts = stats.get("indicator_count_per_malware_family") or {}
        threat_types = stats.get("threat_type_distribution") or {}
        findings: list[str] = []

        total = stats.get("total_indicators", 0)
        if total == 0:
            findings.append("No indicators were available for assessment.")
            return findings

        if family_counts:
            top_families = [family for family, _ in sorted(family_counts.items(), key=lambda x: x[1], reverse=True)[:3]]
            findings.append(
                f"Observed C2 and malware infrastructure was dominated by {', '.join(top_families)} indicators."
            )

        if threat_types:
            top_threat, top_count = max(threat_types.items(), key=lambda x: x[1])
            threat_total = sum(threat_types.values())
            percentage = (top_count / threat_total * 100) if threat_total > 0 else 0
            findings.append(
                f"{self._format_label(top_threat)} activity represented {percentage:.1f}% of collected indicators."
            )

        if stats.get("ioc_type_distribution"):
            ioc_types = stats["ioc_type_distribution"]
            top_ioc = max(ioc_types.items(), key=lambda x: x[1])[0]
            findings.append(f"The most common indicator type was {top_ioc.upper()}.")

        if techniques:
            top_ids = ", ".join(technique["id"] for technique in techniques[:3])
            findings.append(f"Primary ATT&CK techniques mapped include {top_ids}.")

        return findings

    def _write_text_report(self, report: dict[str, Any]) -> None:
        family_stats = Counter(report.get("malware_family_statistics") or {})
        techniques = report.get("most_observed_attack_techniques") or []
        threat_types = report.get("threat_type_distribution") or {}
        ioc_types = report.get("ioc_type_distribution") or {}
        sources = report.get("source_distribution") or {}
        total = report.get("total_indicators_collected", 0)

        lines = [
            "=" * 80,
            "C2-TRAWLER THREAT INTELLIGENCE REPORT",
            "=" * 80,
            "",
            f"Report Date   : {report['collection_date']}",
            f"Total IOCs    : {total:,}",
            "",
            "-" * 80,
            "EXECUTIVE SUMMARY",
            "-" * 80,
            "",
        ]

        for finding in report.get("summary_findings") or []:
            lines.append(f"  * {finding}")

        lines.extend(
            [
                "",
                "-" * 80,
                "COLLECTION OVERVIEW",
                "-" * 80,
                "",
            ]
        )

        if sources:
            lines.append("Feed Sources:")
            source_total = sum(sources.values())
            for source, count in sorted(sources.items(), key=lambda item: item[1], reverse=True):
                percentage = (count / source_total * 100) if source_total > 0 else 0
                lines.append(f"  * {source}: {count:,} ({percentage:.1f}%)")
        else:
            lines.append("  No source metadata available.")

        if ioc_types:
            ioc_total = sum(ioc_types.values())
            lines.extend(["", "IOC Type Distribution:"])
            for ioc_type, count in sorted(ioc_types.items(), key=lambda item: item[1], reverse=True):
                percentage = (count / ioc_total * 100) if ioc_total > 0 else 0
                lines.append(f"  * {ioc_type.upper()}: {count:,} ({percentage:.1f}%)")

        if threat_types:
            threat_total = sum(threat_types.values())
            lines.extend(["", "Threat Category Distribution:"])
            for threat_type, count in sorted(threat_types.items(), key=lambda item: item[1], reverse=True):
                percentage = (count / threat_total * 100) if threat_total > 0 else 0
                lines.append(f"  * {self._format_label(threat_type)}: {count:,} ({percentage:.1f}%)")

        lines.extend(
            [
                "",
                "-" * 80,
                "TOP MALWARE FAMILIES",
                "-" * 80,
                "",
            ]
        )

        if family_stats:
            for index, (family, count) in enumerate(family_stats.most_common(15), start=1):
                lines.append(f"  {index:>2}. {family:<24} {count:>6,} indicators")
        else:
            lines.append("  No attributed malware families were identified.")

        lines.extend(
            [
                "",
                "-" * 80,
                "MITRE ATT&CK TECHNIQUES",
                "-" * 80,
                "",
            ]
        )

        if techniques:
            for technique in techniques[:15]:
                lines.append(
                    f"  {technique['id']:<8} {technique['name']:<42} {technique.get('count', 0):>6,} mapped IOCs"
                )
        else:
            lines.append("  No ATT&CK techniques were mapped.")

        lines.extend(
            [
                "",
                "-" * 80,
                "THREAT ASSESSMENT",
                "-" * 80,
                "",
            ]
        )

        if family_stats:
            top_family, top_count = family_stats.most_common(1)[0]
            lines.append(f"  Primary malware family : {top_family} ({top_count:,} indicators)")

        if threat_types:
            top_threat, top_count = max(threat_types.items(), key=lambda item: item[1])
            lines.append(f"  Primary threat category: {self._format_label(top_threat)} ({top_count:,} indicators)")

        if ioc_types:
            top_ioc, top_count = max(ioc_types.items(), key=lambda item: item[1])
            lines.append(f"  Primary indicator type : {top_ioc.upper()} ({top_count:,} indicators)")

        lines.extend(
            [
                "",
                "-" * 80,
                "RECOMMENDED ACTIONS",
                "-" * 80,
                "",
                "  * Block or alert on exported IOCs at perimeter and DNS security controls.",
                "  * Ingest exports/stix_bundle.json into your SIEM or threat intel platform.",
                "  * Hunt for mapped ATT&CK techniques associated with dominant malware families.",
                "  * Review phishing and payload-delivery URLs for credential-theft campaigns.",
                "  * Refresh detections after each scheduled collection run.",
                "",
                "-" * 80,
                "OUTPUT ARTIFACTS",
                "-" * 80,
                "",
                f"  Human-readable report : {self.text_path}",
                f"  Structured JSON report: {self.json_path}",
                "  STIX 2.1 bundle       : exports/stix_bundle.json",
                "  IOC exports           : exports/iocs.json, exports/iocs.csv",
                "",
                "=" * 80,
                "END OF REPORT",
                "=" * 80,
            ]
        )

        with open(self.text_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")

    @staticmethod
    def _format_label(value: str) -> str:
        return value.replace("_", " ").strip().title()
