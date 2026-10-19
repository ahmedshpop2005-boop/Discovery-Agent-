"""External SMB enumeration (enum4linux-ng).

A read-only wrapper around enum4linux-ng for authorised SMB enumeration: shares,
users, groups, OS info and password policy. Degrades to ``unavailable`` when the
binary is missing; ``smb_probe`` (pure Python) remains the fallback with the same
``smb_info`` capability.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from app.config import settings
from app.tools.base import (
    EffectClass,
    ToolContext,
    ToolResult,
    evidence,
    failure,
    run_command,
    unavailable,
    which,
)
from app.tools.registry import tool


def _temp_json() -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    handle.close()
    return Path(handle.name)


def _parse_enum4linux(text: str) -> dict:
    """Summarise an enum4linux-ng JSON report."""
    try:
        raw = json.loads(text or "{}")
    except (ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    result: dict = {
        "hostname": raw.get("target", {}).get("hostname") if isinstance(raw.get("target"), dict) else None,
        "os": raw.get("os_info", {}).get("OS") if isinstance(raw.get("os_info"), dict) else None,
    }
    for key in ("users", "shares", "groups"):
        value = raw.get(key)
        if isinstance(value, dict):
            result[key] = list(value.keys())
        elif isinstance(value, list):
            result[key] = value
    return {k: v for k, v in result.items() if v}


@tool(
    name="enum4linux_ng",
    description="SMB/Samba enumeration (shares, users, groups, OS) via enum4linux-ng.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="smb_info",
    priority=40,
    requires=("host", "services"),
    profiles=("network", "full"),
    order=50,
)
def enum4linux_ng(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    safe_command = f"enum4linux-ng -A {host}"
    if which("enum4linux-ng") is None:
        return unavailable("enum4linux_ng", "enum4linux-ng is not installed.", command=safe_command)

    report = _temp_json()
    command = ["enum4linux-ng", "-A", host, "-oJ", str(report)]
    started = time.perf_counter()
    try:
        run_command(command, timeout=settings.nmap_timeout)
    except Exception as exc:
        report.unlink(missing_ok=True)
        return failure("enum4linux_ng", f"enum4linux-ng did not complete: {type(exc).__name__}", command=safe_command)

    try:
        parsed = _parse_enum4linux(report.read_text(encoding="utf-8", errors="replace"))
    finally:
        report.unlink(missing_ok=True)

    duration = int((time.perf_counter() - started) * 1000)
    summary = (
        f"{len(parsed.get('shares', []))} share(s), {len(parsed.get('users', []))} user(s) enumerated."
        if parsed
        else "No SMB details enumerated."
    )
    return ToolResult(
        tool="enum4linux",
        status="ok" if parsed else "partial",
        summary=summary,
        data=parsed,
        evidence=[evidence("enum4linux", f"{key}: {value}") for key, value in list(parsed.items())[:10]],
        command=safe_command,
        note="Read-only enumeration; no credential attacks.",
        duration_ms=duration,
    )
