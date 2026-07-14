"""JSON export for scan results."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ..models.finding import ScanResult


def to_dict(result: ScanResult) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    def serialize(obj):
        if hasattr(obj, '__dataclass_fields__'):
            d = {}
            for field_name in obj.__dataclass_fields__:
                value = getattr(obj, field_name)
                if hasattr(value, 'value'):
                    value = value.value
                d[field_name] = serialize(value)
            return d
        elif isinstance(obj, list):
            return [serialize(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: serialize(v) for k, v in obj.items()}
        elif isinstance(obj, set):
            return [serialize(item) for item in obj]
        else:
            return obj

    return serialize(result)


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Convert scan result to pretty-printed JSON."""
    return json.dumps(to_dict(result), indent=indent, default=str)


def save_json(result: ScanResult, path: str) -> None:
    """Save scan results to a JSON file."""
    with open(path, 'w') as f:
        f.write(to_json(result))


def export(result: ScanResult, output: Optional[str] = None) -> str:
    """Export scan results. If output is a path, saves to file.
    If output is '-', returns JSON string.
    """
    json_str = to_json(result)

    if output == "-" or output == "stdout":
        return json_str

    if output:
        save_json(result, output)
        return f"Results saved to {output}"

    return json_str
