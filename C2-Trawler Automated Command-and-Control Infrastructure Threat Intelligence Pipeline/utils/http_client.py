"""Small HTTP helpers with requests support and urllib fallback."""

from __future__ import annotations

import json
from typing import Any
from urllib import request

try:
    import requests
except ImportError:  # pragma: no cover - dependency fallback
    requests = None


def get_json(url: str, timeout: int = 30, headers: dict[str, str] | None = None) -> Any:
    """GET a JSON endpoint using requests when available."""
    request_headers = {"User-Agent": "C2-Trawler/1.0", **(headers or {})}
    if requests is not None:
        response = requests.get(url, timeout=timeout, headers=request_headers)
        response.raise_for_status()
        return response.json()

    http_request = request.Request(url, headers=request_headers, method="GET")
    with request.urlopen(http_request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def get_text(url: str, timeout: int = 30, headers: dict[str, str] | None = None) -> str:
    """GET a text endpoint using requests when available."""
    request_headers = {"User-Agent": "C2-Trawler/1.0", **(headers or {})}
    if requests is not None:
        response = requests.get(url, timeout=timeout, headers=request_headers)
        response.raise_for_status()
        return response.text

    http_request = request.Request(url, headers=request_headers, method="GET")
    with request.urlopen(http_request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def post_json(
    url: str,
    body: dict[str, Any],
    timeout: int = 30,
    headers: dict[str, str] | None = None,
) -> Any:
    """POST JSON and parse the JSON response."""
    request_headers = {"User-Agent": "C2-Trawler/1.0", **(headers or {})}
    if requests is not None:
        response = requests.post(url, json=body, timeout=timeout, headers=request_headers)
        response.raise_for_status()
        return response.json()

    encoded = json.dumps(body).encode("utf-8")
    http_request = request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json", **request_headers},
        method="POST",
    )
    with request.urlopen(http_request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))
