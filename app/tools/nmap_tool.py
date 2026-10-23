"""Nmap tool: safe service discovery.

Uses ``-sV --version-light`` with a bounded port set and a polite timing
template. Nmap is *not* required: when the binary is absent the tool reports
``unavailable`` and the workflow continues with the pure-Python scanners.
"""

from __future__ import annotations

import time
from xml.etree import ElementTree

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

NMAP_COMMAND = "nmap -sV --version-light --top-ports {ports} -T3"


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    ports: list[dict] = []
    try:
        root = ElementTree.fromstring(xml_text or "<nmaprun/>")
    except ElementTree.ParseError:
        return ports
    for host in root.findall(".//host"):
        addresses = [a.get("addr") for a in host.findall("address")]
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service = port.find("service")
            ports.append(
                {
                    "host": addresses[0] if addresses else None,
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "product": (service.get("product") or "") if service is not None else "",
                    "version": (service.get("version") or "") if service is not None else "",
                    "cpe": [c.text for c in service.findall("cpe")] if service is not None else [],
                }
            )
    return ports


@tool(
    name="nmap_discovery",
    description="Nmap top-ports TCP service + version discovery (safe profile).",
    category="NETWORK",
    effect_class=EffectClass.PASSIVE,
    capability="port_discovery",
    priority=10,
    requires=("host",),
    profiles=("safe", "network", "full"),
    order=10,
)
def nmap_discovery(ctx: ToolContext) -> ToolResult:
    top_ports = int(ctx.option("top_ports", settings.aggressive_ports if ctx.option("aggressive") else 100))
    safe_command = NMAP_COMMAND.format(ports=top_ports)
    if which("nmap") is None:
        return unavailable(
            "nmap",
            "Nmap is not installed; falling back to built-in scanners.",
            command=safe_command,
        )

    command = ["nmap", "-sV", "--version-light", "--top-ports", str(top_ports), "-T3", "-oX", "-", ctx.target.host]
    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.nmap_timeout)
    except Exception as exc:  # timeout, OSError
        return failure("nmap", f"Discovery did not complete: {type(exc).__name__}", command=safe_command)

    ports = _parse_nmap_xml(completed.stdout)
    duration = int((time.perf_counter() - started) * 1000)
    status = "ok" if completed.returncode == 0 else "partial"
    if status == "partial" and not ports:
        return failure("nmap", "Nmap returned no parseable results.", command=safe_command)

    return ToolResult(
        tool="nmap",
        status=status,
        summary=f"{len(ports)} open TCP service(s) across the top {top_ports} ports.",
        data={"ports": ports, "top_ports": top_ports},
        evidence=[evidence("nmap", f"open ports: {[p['port'] for p in ports]}")],
        command=safe_command,
        note="Service discovery only; no exploitation.",
        duration_ms=duration,
    )
