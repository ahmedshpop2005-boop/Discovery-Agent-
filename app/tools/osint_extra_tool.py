"""External OSINT / DNS enumeration tools.

Thin, non-destructive wrappers around established recon binaries:

* ``amass_enum``    - OWASP Amass passive subdomain enumeration (OSINT only).
* ``theharvester``  - emails / hosts / subdomains from public sources.
* ``dnsrecon``      - standard DNS enumeration and zone data.
* ``netdiscover``   - ARP host discovery on the local segment.

None of these binaries is required: when one is absent the tool reports
``unavailable`` and the workflow continues (the executor also falls back to a
pure-Python tool with the same capability).
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

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _temp_json() -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    handle.close()
    return Path(handle.name)


def _parse_amass(stdout: str, domain: str) -> list[str]:
    """Return unique subdomains from Amass stdout (one host per line)."""
    found: list[str] = []
    for line in stdout.splitlines():
        candidate = line.strip().strip(",").lower()
        if candidate and candidate.endswith(domain) and " " not in candidate:
            if candidate not in found:
                found.append(candidate)
    return found


def _parse_harvester(stdout: str, domain: str) -> dict:
    """Extract emails, hosts and subdomains from theHarvester stdout."""
    emails = sorted(set(_EMAIL_RE.findall(stdout)))
    hosts = sorted({h.lower() for h in re.findall(r"\b([A-Za-z0-9._\-]+\." + re.escape(domain) + r")\b", stdout)})
    ips = sorted(set(_IP_RE.findall(stdout)))
    return {"emails": emails, "hosts": hosts, "ips": ips}


def _parse_dnsrecon_json(text: str) -> list[dict]:
    """Normalise dnsrecon's JSON report into simple records."""
    try:
        raw = json.loads(text or "[]")
    except (ValueError, TypeError):
        return []
    records: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        rtype = item.get("type") or item.get("record_type") or "unknown"
        if rtype in {"ScanInfo", "Unsupported"}:
            continue
        records.append(
            {
                "type": rtype,
                "name": item.get("name") or item.get("target") or "",
                "address": item.get("address") or item.get("value") or "",
                "raw": item.get("exchange") or item.get("strings") or "",
            }
        )
    return records


def _parse_netdiscover(stdout: str) -> list[dict]:
    """Parse netdiscover rows into ``{ip, mac, vendor}`` records."""
    hosts: list[dict] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and _IP_RE.fullmatch(parts[0]):
            hosts.append({"ip": parts[0], "mac": parts[1], "vendor": " ".join(parts[2:])})
    return hosts


@tool(
    name="amass_enum",
    description="OWASP Amass passive subdomain enumeration (OSINT sources only).",
    category="DNS",
    effect_class=EffectClass.PASSIVE,
    capability="subdomain",
    priority=40,
    requires=("hostname",),
    profiles=("network", "full"),
    order=78,
)
def amass_enum(ctx: ToolContext) -> ToolResult:
    domain = ctx.target.host
    timeout_min = max(1, int(ctx.option("amass_timeout", 1)))
    command = ["amass", "enum", "-passive", "-silent", "-d", domain, "-timeout", str(timeout_min)]
    safe_command = f"amass enum -passive -d {domain}"
    if which("amass") is None:
        return unavailable("amass", "Amass is not installed; using the built-in DNS enumerator.", command=safe_command)

    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=min(timeout_min * 60 + 120, 300))
    except Exception as exc:  # timeout / OSError
        return failure("amass", f"Amass did not complete: {type(exc).__name__}", command=safe_command)

    subdomains = _parse_amass(completed.stdout, domain)
    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="amass",
        status="ok" if subdomains else "partial",
        summary=f"{len(subdomains)} subdomain(s) via Amass passive.",
        data={"subdomains": subdomains},
        evidence=[evidence("amass", f"{name}") for name in subdomains[:10]],
        command=safe_command,
        note="Passive OSINT only; no active DNS brute force.",
        duration_ms=duration,
    )


@tool(
    name="theharvester",
    description="Emails, hosts and subdomains from public sources (theHarvester).",
    category="OSINT",
    effect_class=EffectClass.PASSIVE,
    capability="osint",
    priority=50,
    requires=("hostname",),
    profiles=("web", "full"),
    order=85,
)
def theharvester(ctx: ToolContext) -> ToolResult:
    domain = ctx.target.host
    limit = str(ctx.option("harvester_limit", 50))
    command = ["theHarvester", "-d", domain, "-b", "duckduckgo,bing", "-l", limit]
    safe_command = f"theHarvester -d {domain} -b duckduckgo,bing -l {limit}"
    if which("theHarvester") is None:
        return unavailable("theharvester", "theHarvester is not installed.", command=safe_command)

    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.nmap_timeout)
    except Exception as exc:
        return failure("theharvester", f"theHarvester did not complete: {type(exc).__name__}", command=safe_command)

    parsed = _parse_harvester(completed.stdout + "\n" + completed.stderr, domain)
    duration = int((time.perf_counter() - started) * 1000)
    total = len(parsed["emails"]) + len(parsed["hosts"])
    return ToolResult(
        tool="theharvester",
        status="ok" if total else "partial",
        summary=f"{len(parsed['emails'])} email(s), {len(parsed['hosts'])} host(s) via theHarvester.",
        data=parsed,
        evidence=[evidence("theharvester", f"{e}") for e in parsed["emails"][:10]],
        command=safe_command,
        note="Public-source OSINT; absence of results is not proof of absence.",
        duration_ms=duration,
    )


@tool(
    name="dnsrecon",
    description="Standard DNS enumeration (records, NS, MX, zone data) via dnsrecon.",
    category="DNS",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="dns_enum",
    priority=40,
    requires=("hostname",),
    profiles=("web", "network", "full"),
    order=30,
)
def dnsrecon_tool(ctx: ToolContext) -> ToolResult:
    domain = ctx.target.host
    safe_command = f"dnsrecon -d {domain} -t std"
    if which("dnsrecon") is None:
        return unavailable("dnsrecon", "dnsrecon is not installed.", command=safe_command)

    report = _temp_json()
    command = ["dnsrecon", "-d", domain, "-t", "std", "-j", str(report)]
    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.nmap_timeout)
    except Exception as exc:
        return failure("dnsrecon", f"dnsrecon did not complete: {type(exc).__name__}", command=safe_command)
    finally:
        pass

    records: list[dict] = []
    try:
        if report.exists() and report.stat().st_size:
            records = _parse_dnsrecon_json(report.read_text(encoding="utf-8", errors="replace"))
    finally:
        report.unlink(missing_ok=True)

    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="dnsrecon",
        status="ok" if records else "partial",
        summary=f"{len(records)} DNS record(s) via dnsrecon.",
        data={"records": records},
        evidence=[evidence("dnsrecon", f"{r['type']} {r['name']} {r['address']}".strip()) for r in records[:10]],
        command=safe_command,
        note="Standard enumeration only; no zone-transfer brute force.",
        duration_ms=duration,
    )


@tool(
    name="netdiscover",
    description="ARP host discovery on the local segment (netdiscover).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="host_discovery",
    priority=60,
    requires=("host",),
    profiles=("network", "full"),
    order=6,
)
def netdiscover_tool(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    safe_command = f"netdiscover -r {host}/32"
    if which("netdiscover") is None:
        return unavailable("netdiscover", "netdiscover is not installed (Linux/ARP only).", command=safe_command)

    command = ["netdiscover", "-r", f"{host}/32", "-N"]
    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.socket_timeout * 3)
    except Exception as exc:
        return failure("netdiscover", f"netdiscover did not complete: {type(exc).__name__}", command=safe_command)

    hosts = _parse_netdiscover(completed.stdout)
    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="netdiscover",
        status="ok" if hosts else "partial",
        summary=f"{len(hosts)} host(s) via ARP discovery.",
        data={"hosts": hosts},
        evidence=[evidence("netdiscover", f"{h['ip']} {h['mac']}") for h in hosts[:10]],
        command=safe_command,
        note="Layer-2 ARP; only meaningful on the local segment.",
        duration_ms=duration,
    )
