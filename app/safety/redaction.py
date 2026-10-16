"""Secret redaction.

Tool output, HTTP headers and error strings may contain credentials or tokens.
Anything that crosses a display/export boundary is passed through here first.
"""

from __future__ import annotations

import re
from typing import Any

_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s&,;]+"),
    re.compile(r"(?i)(password\s*[=:]\s*)[^\s&,;]+"),
    re.compile(r"(?i)(passwd\s*[=:]\s*)[^\s&,;]+"),
    re.compile(r"(?i)(secret\s*[=:]\s*)[^\s&,;]+"),
    re.compile(r"(?i)(token\s*[=:]\s*)[^\s&,;]+"),
    re.compile(r"(?i)(set-cookie:\s*)[^\n]+"),
    re.compile(r"(?i)(x-api-key:\s*)[^\s]+"),
]

_REDACTED = "[REDACTED]"


def redact(value: str) -> str:
    """Return ``value`` with credential-like substrings masked."""
    if not value:
        return value
    result = value
    for pattern in _PATTERNS:
        result = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}", result)
    return result


def redact_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact a mapping/list structure in place-safe fashion."""
    cleaned: dict[str, Any] = {}
    for key, value in mapping.items():
        lowered = str(key).lower()
        if lowered in {"set-cookie", "cookie", "authorization"}:
            cleaned[key] = _REDACTED
        elif isinstance(value, dict):
            cleaned[key] = redact_mapping(value)
        elif isinstance(value, list):
            cleaned[key] = [
                redact_mapping(v) if isinstance(v, dict)
                else redact(v) if isinstance(v, str)
                else v
                for v in value
            ]
        elif isinstance(value, str):
            cleaned[key] = redact(value)
        else:
            cleaned[key] = value
    return cleaned
