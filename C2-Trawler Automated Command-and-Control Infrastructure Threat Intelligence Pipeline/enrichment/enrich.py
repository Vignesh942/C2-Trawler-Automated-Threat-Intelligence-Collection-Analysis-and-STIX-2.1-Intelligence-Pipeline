"""Free IOC enrichment routines."""

from __future__ import annotations

import logging
import socket
from typing import Any

from utils.indicators import hostname_from_value
from utils.json_store import read_json, write_json

try:
    from ipwhois import IPWhois
except ImportError:  # pragma: no cover - optional dependency fallback
    IPWhois = None

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency fallback
    whois = None


class IOCEnricher:
    """Enrich IP, domain, and URL indicators using free local/network lookups."""

    def __init__(
        self,
        input_path: str = "data/unique_iocs.json",
        output_path: str = "data/enriched_iocs.json",
        socket_timeout: float = 0.3,
        enable_whois: bool = False,
        max_records: int | None = 500,
    ) -> None:
        self.input_path = input_path
        self.output_path = output_path
        self.socket_timeout = socket_timeout
        self.enable_whois = enable_whois
        self.max_records = max_records
        self.logger = logging.getLogger(self.__class__.__name__)

    def enrich(self) -> list[dict[str, Any]]:
        """Enrich IOCs and save the result."""
        socket.setdefaulttimeout(self.socket_timeout)
        logging.getLogger("whois").setLevel(logging.CRITICAL)
        logging.getLogger("whois.whois").setLevel(logging.CRITICAL)
        records = read_json(self.input_path, [])
        limit = len(records) if self.max_records is None or self.max_records <= 0 else self.max_records
        enriched = [self._enrich_record(record) for record in records[:limit]]
        if limit < len(records):
            enriched.extend(self._mark_enrichment_skipped(record) for record in records[limit:])
            self.logger.warning(
                "Enrichment limited to %d of %d IOCs. Use --enrichment-limit 0 to enrich all records.",
                limit,
                len(records),
            )
        write_json(self.output_path, enriched)
        self.logger.info("Enriched %d IOC records", len(enriched))
        return enriched

    def _enrich_record(self, record: dict[str, Any]) -> dict[str, Any]:
        indicator_type = str(record.get("indicator_type", ""))
        value = str(record.get("value", ""))
        result = dict(record)
        enrichment: dict[str, Any] = {"errors": []}

        if indicator_type == "ipv4":
            enrichment.update(self._enrich_ip(value))
        elif indicator_type in {"domain", "url"}:
            hostname = hostname_from_value(value, indicator_type)
            enrichment["hostname"] = hostname
            if hostname:
                enrichment.update(self._enrich_domain(hostname))

        if not enrichment["errors"]:
            enrichment.pop("errors")
        result["enrichment"] = enrichment
        return result

    @staticmethod
    def _mark_enrichment_skipped(record: dict[str, Any]) -> dict[str, Any]:
        result = dict(record)
        result["enrichment"] = {"skipped": "enrichment limit reached"}
        return result

    def _enrich_ip(self, ip_address: str) -> dict[str, Any]:
        details: dict[str, Any] = {}
        errors: list[str] = []

        try:
            details["reverse_dns"] = socket.gethostbyaddr(ip_address)[0]
        except Exception as exc:
            errors.append(f"reverse_dns: {exc}")

        if IPWhois is not None:
            try:
                rdap = IPWhois(ip_address).lookup_rdap(depth=0)
                details["asn"] = rdap.get("asn")
                network = rdap.get("network") or {}
                details["country"] = network.get("country")
                details["network_name"] = network.get("name")
            except Exception as exc:
                errors.append(f"rdap: {exc}")
        else:
            errors.append("rdap: ipwhois package unavailable")

        details["errors"] = errors
        return details

    def _enrich_domain(self, hostname: str) -> dict[str, Any]:
        details: dict[str, Any] = {}
        errors: list[str] = []

        try:
            details["resolved_ip"] = socket.gethostbyname(hostname)
        except Exception as exc:
            errors.append(f"dns: {exc}")

        if not self.enable_whois:
            pass
        elif whois is not None:
            try:
                whois_data = whois.whois(hostname)
                details["registrar"] = self._stringify_whois_value(getattr(whois_data, "registrar", None))
                details["creation_date"] = self._stringify_whois_value(getattr(whois_data, "creation_date", None))
                details["country"] = self._stringify_whois_value(getattr(whois_data, "country", None))
            except Exception as exc:
                errors.append(f"whois: {exc}")
        else:
            errors.append("whois: python-whois package unavailable")

        details["errors"] = errors
        return details

    @staticmethod
    def _stringify_whois_value(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, list):
            return ", ".join(str(item) for item in value if item)
        return str(value)
