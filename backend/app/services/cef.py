"""Minimal parser for ArcSight CEF lines.

CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|key=value key=value
"""

import re
from datetime import UTC, datetime
from typing import Any

_EXT_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.]*)=")

# CEF extension keys mapped to the field names the rest of the app uses.
_KEY_MAP = {
    "src": "src_ip",
    "dst": "dst_ip",
    "dpt": "dst_port",
    "spt": "src_port",
    "suser": "user",
    "duser": "user",
    "dhost": "host",
    "shost": "src_host",
    "msg": "message",
}


def parse_cef(line: str) -> dict[str, Any]:
    """Turn one CEF line into the dict accepted by EventCreate. Raises ValueError if malformed."""
    start = line.find("CEF:")
    if start < 0:
        raise ValueError("not a CEF line")
    parts = re.split(r"(?<!\\)\|", line[start:], maxsplit=7)
    if len(parts) < 7:
        raise ValueError("CEF header needs 7 pipe-separated fields")
    _, vendor, product, _, signature_id, name, cef_severity = parts[:7]
    extension = parts[7] if len(parts) > 7 else ""

    raw: dict[str, Any] = {"cef_name": name, "signature_id": signature_id, "vendor": vendor}
    matches = list(_EXT_KEY.finditer(extension))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        key = match.group(1)
        raw[_KEY_MAP.get(key, key)] = extension[match.end() : end].strip()

    timestamp = datetime.now(UTC)
    if "rt" in raw:
        try:
            timestamp = datetime.fromtimestamp(int(raw["rt"]) / 1000, tz=UTC)
        except (TypeError, ValueError):
            pass
    if "dst_port" in raw:
        try:
            raw["dst_port"] = int(raw["dst_port"])
        except ValueError:
            pass

    try:
        level = int(cef_severity)
        severity = 1 if level <= 3 else 2 if level <= 6 else 3 if level <= 8 else 4
    except ValueError:
        severity = None

    return {
        "source": product.strip().lower().replace(" ", "_") or "cef",
        "event_type": name.strip().lower().replace(" ", "_") or "unknown",
        "raw_data": raw,
        "timestamp": timestamp,
        "severity": severity,
    }
