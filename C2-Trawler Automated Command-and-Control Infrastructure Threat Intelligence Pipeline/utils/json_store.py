"""JSON read/write helpers with duplicate-safe merging."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from utils.indicators import indicator_key

logger = logging.getLogger(__name__)


def read_json(path: str | Path, default: Any = None) -> Any:
    """Read a JSON file, returning a default value when it is absent or invalid."""
    file_path = Path(path)
    if not file_path.exists():
        return default
    try:
        with file_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in %s: %s", file_path, exc)
        return default


def write_json(path: str | Path, data: Any) -> None:
    """Write JSON atomically with readable indentation."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")
    temp_path.replace(file_path)


def _prefer_malware_family(old_value: str, new_value: str) -> str:
    """Prefer a concrete malware family over Unknown or generic merged labels."""
    candidates = [value.strip() for value in (old_value, new_value) if value and value.strip() != "Unknown"]
    if not candidates:
        return "Unknown"
    if len(candidates) == 1:
        return candidates[0]
    return sorted(set(candidates))[0]


def merge_unique_indicators(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge indicator records while keeping one record per type/value pair."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in [*existing, *incoming]:
        key = indicator_key(item)
        if not all(key):
            continue
        if key not in merged:
            merged[key] = dict(item)
            continue

        current = merged[key]
        for field in ("source", "threat_category", "malware_family"):
            old_value = current.get(field)
            new_value = item.get(field)
            if not old_value and new_value:
                current[field] = new_value
            elif new_value and old_value != new_value:
                if field == "malware_family":
                    current[field] = _prefer_malware_family(str(old_value), str(new_value))
                else:
                    values = sorted(set(str(old_value).split(", ")) | {str(new_value)})
                    current[field] = ", ".join(value for value in values if value and value != "Unknown")

        if item.get("first_seen") and (
            not current.get("first_seen") or str(item["first_seen"]) < str(current["first_seen"])
        ):
            current["first_seen"] = item["first_seen"]

    return sorted(merged.values(), key=lambda record: (record["indicator_type"], record["value"]))

