"""Deterministic sample feed data for offline demos and tests."""

from __future__ import annotations

from typing import Any


def sample_threatfox() -> dict[str, Any]:
    """Return representative ThreatFox-style data."""
    return {
        "query_status": "ok",
        "data": [
            {
                "ioc": "185.220.101.5:443",
                "ioc_type": "ip:port",
                "malware": "AsyncRAT",
                "malware_printable": "AsyncRAT",
                "threat_type": "botnet_cc",
                "first_seen": "2026-06-24 08:15:00 UTC",
            },
            {
                "ioc": "c2-remcos.example.net",
                "ioc_type": "domain",
                "malware": "Remcos",
                "malware_printable": "Remcos",
                "threat_type": "malware_download",
                "first_seen": "2026-06-24 06:44:00 UTC",
            },
            {
                "ioc": "https://sliver-cdn.example.org/update.bin",
                "ioc_type": "url",
                "malware": "Sliver",
                "malware_printable": "Sliver",
                "threat_type": "payload_delivery",
                "first_seen": "2026-06-23 21:05:00 UTC",
            },
            {
                "ioc": "185.220.101.5:443",
                "ioc_type": "ip:port",
                "malware": "AsyncRAT",
                "malware_printable": "AsyncRAT",
                "threat_type": "botnet_cc",
                "first_seen": "2026-06-24 08:15:00 UTC",
            },
        ],
    }


def sample_urlhaus() -> dict[str, Any]:
    """Return representative URLHaus-style data."""
    return {
        "100001": {
            "id": "100001",
            "dateadded": "2026-06-24 05:10:00 UTC",
            "url": "http://payloads.example.com/agenttesla.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["AgentTesla", "exe"],
        },
        "100002": {
            "id": "100002",
            "dateadded": "2026-06-23 18:24:00 UTC",
            "url": "http://lumma-loader.example.org/gate",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Lumma"],
        },
    }


def sample_openphish() -> dict[str, Any]:
    """Return representative OpenPhish-style data."""
    return {
        "feed": "OpenPhish",
        "urls": [
            "https://login-secure.example.com/session",
            "https://mfa-check.example.net/verify",
        ],
    }

