"""C2-Trawler command line interface."""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

from analysis.malware import MalwareProfiler
from collectors.openphish import OpenPhishCollector
from collectors.threatfox import ThreatFoxCollector
from collectors.urlhaus import URLHausCollector
from enrichment.enrich import IOCEnricher
from exports.exporter import IntelligenceExporter
from mitre.mapper import MitreMapper
from normalizer.deduplicate import DeduplicationEngine
from normalizer.normalize import IOCNormalizer
from reporting.report_generator import ThreatReportGenerator
from stix_generator.stix_builder import StixBuilder
from utils.config import load_settings
from utils.filesystem import ensure_directories
from utils.json_store import read_json, write_json
from utils.logging_config import setup_logging
from utils.malware_families import canonicalize_malware_family


logger = logging.getLogger("c2-trawler")


def collect(days: int, sample: bool, timeout: int = 30, threatfox_api_key: str | None = None) -> None:
    """Run all collectors."""
    ThreatFoxCollector(timeout=timeout, api_key=threatfox_api_key).collect(days=days, sample=sample)
    URLHausCollector(timeout=timeout).collect(sample=sample)
    OpenPhishCollector(timeout=timeout).collect(sample=sample)


def run_pipeline(
    days: int,
    sample: bool,
    skip_enrichment: bool = False,
    enable_whois: bool = False,
    enrichment_limit: int = 500,
    timeout: int = 30,
    threatfox_api_key: str | None = None,
    skip_stix: bool = False,
) -> None:
    """Run the complete CTI workflow."""
    logger.info("Starting C2-Trawler pipeline")
    collect(days=days, sample=sample, timeout=timeout, threatfox_api_key=threatfox_api_key)
    normalized = IOCNormalizer().normalize()
    unique = DeduplicationEngine().deduplicate()
    if not normalized:
        logger.warning("No indicators were normalized. Check internet access to the configured public feeds.")
    if not skip_enrichment:
        IOCEnricher(enable_whois=enable_whois, max_records=enrichment_limit).enrich()
    else:
        write_json("data/enriched_iocs.json", unique)
    MalwareProfiler().profile()
    MitreMapper().map_observed_families()
    if not skip_stix:
        StixBuilder().build()
    else:
        logger.info("STIX generation skipped")
    ThreatReportGenerator().generate()
    IntelligenceExporter().export()
    _print_pipeline_summary()
    logger.info("Pipeline complete")


def _print_pipeline_summary() -> None:
    """Print a concise summary of generated artifacts."""
    stats = read_json("reports/malware_statistics.json", {})
    total = stats.get("total_indicators", 0)
    print("")
    print("C2-Trawler pipeline finished successfully.")
    print(f"  Indicators processed : {total:,}")
    print("  Human-readable report: reports/threat_report.txt")
    print("  Structured JSON report: reports/threat_report.json")
    print("  STIX 2.1 bundle      : exports/stix_bundle.json")
    print("  IOC exports          : exports/iocs.json, exports/iocs.csv")
    print("")


def search(indicator_type: str | None = None, value: str | None = None, malware: str | None = None) -> list[dict[str, Any]]:
    """Search collected intelligence by IOC value or malware family."""
    records = read_json("data/enriched_iocs.json", None)
    if records is None:
        records = read_json("data/unique_iocs.json", [])
    mitre = read_json("reports/mitre_mapping.json", {})
    results: list[dict[str, Any]] = []

    for record in records:
        if malware:
            record_family = canonicalize_malware_family(record.get("malware_family")) or str(record.get("malware_family") or "Unknown")
            query_family = canonicalize_malware_family(malware) or malware
            if record_family.lower() != query_family.lower():
                continue
        if indicator_type and str(record.get("indicator_type")) != indicator_type:
            continue
        if value and str(record.get("value", "")).lower() != value.lower():
            continue
        enriched_record = dict(record)
        family = canonicalize_malware_family(record.get("malware_family")) or str(record.get("malware_family") or "Unknown")
        enriched_record["attack_techniques"] = (
            mitre.get("observed_malware_families", {}).get(family, {}).get("techniques", [])
        )
        results.append(enriched_record)

    return results


def print_json(data: Any) -> None:
    """Pretty-print data for CLI users."""
    print(json.dumps(data, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Build the command parser."""
    parser = argparse.ArgumentParser(
        description="C2-Trawler: automated C2 infrastructure threat intelligence pipeline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the full CTI workflow")
    run_parser.add_argument("--days", type=int, default=3, help="ThreatFox lookback window in days")
    run_parser.add_argument("--sample", action="store_true", help="Use deterministic offline sample feed data")
    run_parser.add_argument("--skip-enrichment", action="store_true", help="Skip DNS, RDAP, and WHOIS enrichment")
    run_parser.add_argument("--enable-whois", action="store_true", help="Enable slower WHOIS lookups during enrichment")
    run_parser.add_argument(
        "--enrichment-limit",
        type=int,
        default=500,
        help="Maximum IOCs to actively enrich; use 0 for no limit",
    )
    run_parser.add_argument("--skip-stix", action="store_true", help="Skip STIX bundle generation (faster for large datasets)")

    collect_parser = subparsers.add_parser("collect", help="Collect raw feed data")
    collect_parser.add_argument("--days", type=int, default=3, help="ThreatFox lookback window in days")
    collect_parser.add_argument("--sample", action="store_true", help="Use deterministic offline sample feed data")

    subparsers.add_parser("normalize", help="Normalize raw feed data")
    subparsers.add_parser("dedupe", help="Deduplicate normalized IOCs")
    subparsers.add_parser("enrich", help="Enrich unique IOCs")
    subparsers.add_parser("profile", help="Generate malware family statistics")
    subparsers.add_parser("mitre", help="Map observed malware to MITRE ATT&CK")
    subparsers.add_parser("stix", help="Generate STIX 2.1 bundle")
    subparsers.add_parser("report", help="Generate analyst reports")
    subparsers.add_parser("export", help="Export IOC JSON and CSV files")

    search_ip = subparsers.add_parser("search-ip", help="Search by IPv4 address")
    search_ip.add_argument("value")

    search_domain = subparsers.add_parser("search-domain", help="Search by domain")
    search_domain.add_argument("value")

    search_malware = subparsers.add_parser("search-malware", help="Search by malware family")
    search_malware.add_argument("value")

    return parser


def main() -> None:
    """CLI entry point."""
    ensure_directories()
    settings = load_settings()
    setup_logging(settings.log_level)
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        run_pipeline(
            args.days,
            args.sample,
            args.skip_enrichment,
            args.enable_whois,
            args.enrichment_limit,
            settings.request_timeout,
            settings.threatfox_api_key,
            args.skip_stix,
        )
    elif args.command == "collect":
        collect(args.days, args.sample, settings.request_timeout, settings.threatfox_api_key)
    elif args.command == "normalize":
        IOCNormalizer().normalize()
    elif args.command == "dedupe":
        DeduplicationEngine().deduplicate()
    elif args.command == "enrich":
        IOCEnricher().enrich()
    elif args.command == "profile":
        print_json(MalwareProfiler().profile())
    elif args.command == "mitre":
        print_json(MitreMapper().map_observed_families())
    elif args.command == "stix":
        print_json(StixBuilder().build())
    elif args.command == "report":
        print_json(ThreatReportGenerator().generate())
    elif args.command == "export":
        print_json(IntelligenceExporter().export())
    elif args.command == "search-ip":
        print_json(search(indicator_type="ipv4", value=args.value))
    elif args.command == "search-domain":
        print_json(search(indicator_type="domain", value=args.value))
    elif args.command == "search-malware":
        print_json(search(malware=args.value))


if __name__ == "__main__":
    main()
