"""Indicator parsing and normalization helpers."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def today_utc() -> str:
    """Return the current UTC date."""
    return datetime.now(UTC).date().isoformat()


def clean_value(value: str) -> str:
    """Trim harmless wrapping characters from an indicator value."""
    return value.strip().strip('"').strip("'")


def strip_ipv4_port(value: str) -> str:
    """Return an IPv4 address without a trailing port when present."""
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def detect_indicator_type(value: str, explicit_type: str | None = None) -> str | None:
    """Detect whether a value is an IPv4 address, domain, or URL."""
    value = clean_value(value)
    explicit = (explicit_type or "").lower()

    if explicit in {"url", "uri"} or value.startswith(("http://", "https://")):
        return "url"

    candidate = strip_ipv4_port(value)
    try:
        ip = ipaddress.ip_address(candidate)
        if ip.version == 4:
            return "ipv4"
    except ValueError:
        pass

    if explicit in {"domain", "hostname", "fqdn"}:
        return "domain"

    parsed = urlparse(value)
    if parsed.hostname:
        return "url"

    if DOMAIN_RE.match(value.rstrip(".")):
        return "domain"

    return None


def normalize_indicator_value(value: str, indicator_type: str) -> str:
    """Canonicalize an indicator value for downstream processing."""
    cleaned = clean_value(value)
    if indicator_type == "ipv4":
        return strip_ipv4_port(cleaned)
    if indicator_type == "domain":
        return cleaned.rstrip(".").lower()
    if indicator_type == "url":
        return cleaned
    return cleaned


def indicator_key(indicator: dict[str, Any]) -> tuple[str, str]:
    """Return a stable deduplication key for an indicator record."""
    return (
        str(indicator.get("indicator_type", "")).lower(),
        str(indicator.get("value", "")).lower(),
    )


def hostname_from_value(value: str, indicator_type: str) -> str | None:
    """Extract a hostname from a domain or URL indicator."""
    if indicator_type == "domain":
        return value
    if indicator_type == "url":
        parsed = urlparse(value)
        return parsed.hostname
    return None

