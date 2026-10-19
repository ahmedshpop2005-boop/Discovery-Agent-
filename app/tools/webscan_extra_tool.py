"""External web fingerprinting / content discovery tools.

* ``whatweb``      - technology fingerprinting (http_fingerprint capability).
* ``gobuster_scan``- directory/content discovery against a bounded wordlist.
* ``wafw00f``      - WAF fingerprinting (http_waf_detect capability).

Each degrades to ``unavailable`` when its binary is missing, so the pure-Python
posture tools (``http_posture``, ``web_content``, ``http_waf_detect``) remain the
always-available baseline.
"""

from __future__ import annotations

import json
import re
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

_GOBUSTER_LINE = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)(?:\s*\[Size:\s*(?P<size>\d+)\])?")
_WAFW00F_BEHIND = re.compile(r"is behind\s+(?P<name>.+?)(?:\s*\(|$)", re.IGNORECASE)

_FALLBACK_WORDS = ["admin", "login", "api", "backup", "config", "uploads", "robots.txt", "sitemap.xml"]


def _load_wordlist() -> list[str]:
    path = settings.wordlist_dir / "common.txt"
    if not path.exists():
        return _FALLBACK_WORDS
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _temp_file(suffix: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    handle.close()
    return Path(handle.name)


def _parse_whatweb_json(text: str) -> dict:
    """Parse WhatWeb JSON-lines output into ``{plugins, summary}``."""
    plugins: dict[str, dict] = {}
    targets: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get("target"):
            targets.append(item["target"])
        for name, detail in (item.get("plugins") or {}).items():
            info: dict = {}
            if isinstance(detail, dict):
                for key in ("version", "string"):
                    value = detail.get(key)
                    if isinstance(value, list) and value:
                        info[key] = value[0]
                    elif isinstance(value, str):
                        info[key] = value
            plugins[name] = info
    return {"plugins": plugins, "targets": targets, "technologies": sorted(plugins)}


def _parse_gobuster(stdout: str) -> list[dict]:
    found: list[dict] = []
    for line in stdout.splitlines():
        match = _GOBUSTER_LINE.match(line.strip())
        if match:
            found.append(
                {
                    "path": match.group("path"),
                    "status": int(match.group("status")),
                    "size": int(match.group("size")) if match.group("size") else None,
                }
            )
    return found


def _parse_wafw00f(stdout: str) -> dict:
    cleaned = stdout.strip()
    try:
        raw = json.loads(cleaned)
        if isinstance(raw, list) and raw:
            item = raw[0]
            return {
                "detected": bool(item.get("detected")),
                "firewall": item.get("firewall") or "None",
                "manufacturer": item.get("manufacturer") or "",
            }
    except (ValueError, TypeError):
        pass
    match = _WAFW00F_BEHIND.search(stdout)
    if match:
        return {"detected": True, "firewall": match.group("name").strip(), "manufacturer": ""}
    return {"detected": False, "firewall": "None", "manufacturer": ""}


@tool(
    name="whatweb",
    description="Web technology fingerprinting with WhatWeb.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_fingerprint",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=45,
)
def whatweb(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    safe_command = f"whatweb --color=never {url}"
    if which("whatweb") is None:
        return unavailable("whatweb", "WhatWeb is not installed.", command=safe_command)

    report = _temp_file(".json")
    command = ["whatweb", "--color=never", "--log-json", str(report), url]
    started = time.perf_counter()
    try:
        run_command(command, timeout=settings.http_timeout * 4)
    except Exception as exc:
        report.unlink(missing_ok=True)
        return failure("whatweb", f"WhatWeb did not complete: {type(exc).__name__}", command=safe_command)

    try:
        parsed = _parse_whatweb_json(report.read_text(encoding="utf-8", errors="replace"))
    finally:
        report.unlink(missing_ok=True)

    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="whatweb",
        status="ok" if parsed["technologies"] else "partial",
        summary=f"{len(parsed['technologies'])} technolog(ies) fingerprinted.",
        data=parsed,
        evidence=[evidence("whatweb", name) for name in parsed["technologies"][:12]],
        command=safe_command,
        note="Fingerprinting only; no exploitation.",
        duration_ms=duration,
    )


@tool(
    name="gobuster_scan",
    description="Directory/content discovery with Gobuster (bounded wordlist).",
    category="CONTENT",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="web_content",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=62,
)
def gobuster_scan(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    words = ctx.option("content_words") or _load_wordlist()
    wordlist = _temp_file(".txt")
    wordlist.write_text("\n".join(words), encoding="utf-8")
    safe_command = f"gobuster dir -u {url} -w common.txt ({len(words)} words)"

    try:
        if which("gobuster") is None:
            return unavailable("gobuster", "Gobuster is not installed.", command=safe_command)
        command = [
            "gobuster", "dir", "-u", url, "-w", str(wordlist),
            "-q", "-t", "20", "--timeout", "5s",
        ]
        started = time.perf_counter()
        completed = run_command(command, timeout=settings.nmap_timeout)
    except Exception as exc:
        return failure("gobuster", f"Gobuster did not complete: {type(exc).__name__}", command=safe_command)
    finally:
        wordlist.unlink(missing_ok=True)

    found = _parse_gobuster(completed.stdout)
    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="gobuster",
        status="ok" if found else "partial",
        summary=f"{len(found)} path(s) discovered across {len(words)} candidate(s).",
        data={"paths": found, "tested": len(words)},
        evidence=[evidence("gobuster", f"{p['path']} -> {p['status']}") for p in found[:12]],
        command=safe_command,
        note="Directory discovery only; no exhaustive brute force.",
        duration_ms=duration,
    )


@tool(
    name="wafw00f",
    description="Web application firewall detection with wafw00f.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_waf_detect",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=66,
)
def wafw00f(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    safe_command = f"wafw00f {url}"
    if which("wafw00f") is None:
        return unavailable("wafw00f", "wafw00f is not installed.", command=safe_command)

    command = ["wafw00f", url, "-f", "json"]
    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.http_timeout * 4)
    except Exception as exc:
        return failure("wafw00f", f"wafw00f did not complete: {type(exc).__name__}", command=safe_command)

    parsed = _parse_wafw00f(completed.stdout)
    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="wafw00f",
        status="ok",
        summary=(f"WAF: {parsed['firewall']}" if parsed["detected"] else "No WAF detected."),
        data=parsed,
        evidence=[evidence("wafw00f", f"detected={parsed['detected']} firewall={parsed['firewall']}")],
        command=safe_command,
        note="Detection only; no bypass attempts.",
        duration_ms=duration,
    )
