"""Additional network tools (redundancy and coverage).

* ``host_alive``   - is the host up (ICMP + common-TCP fallback)?
* ``masscan_scan`` - very fast port scan when masscan is installed.
* ``udp_scan``     - bounded UDP top-ports scan (requires nmap).
* ``traceroute``   - network path to the target.

They complement ``nmap_discovery`` / ``tcp_scan``; any of them can stand in for
another in the ``port_discovery`` / ``host_discovery`` capabilities.
"""

from __future__ import annotations

import socket
import time
from xml.etree import ElementTree

from app.config import settings
from app.tools.base import (
    EffectClass,
    ToolContext,
    ToolResult,
    evidence,
    run_command,
    unavailable,
    which,
)
from app.tools.registry import tool


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@tool(
    name="host_alive",
    description="Check host liveness via ICMP and common-TCP fallback.",
    category="NETWORK",
    effect_class=EffectClass.PASSIVE,
    capability="host_discovery",
    requires=("host",),
    profiles=("safe", "web", "network", "full"),
    order=5,
)
def host_alive(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    icmp = None
    ping = which("ping")
    if ping is not None:
        try:
            proc = run_command([ping, "-n", "1", "-w", "1500", host] if ping.lower().endswith("ping.exe") or ping.lower().endswith("ping") else [ping, "-c", "1", "-W", "2", host], timeout=8)
            icmp = proc.returncode == 0
        except Exception:
            icmp = None

    tcp_hits = [p for p in (80, 443, 22, 3389) if _tcp_open(host, p, settings.socket_timeout)]
    alive = bool(icmp) or bool(tcp_hits)
    status = "ok"
    return ToolResult(
        tool="host_alive",
        status=status,
        summary=f"host {'responded' if alive else 'did not respond'} (icmp={icmp}, tcp={tcp_hits})",
        data={"alive": alive, "icmp": icmp, "tcp_open": tcp_hits},
        evidence=[evidence("host_alive", f"alive={alive} icmp={icmp} tcp_open={tcp_hits}")],
        command=f"ICMP + TCP liveness {host}",
        note="No response is not proof of absence (host firewall may drop probes).",
    )


@tool(
    name="masscan_scan",
    description="Very fast TCP port scan using masscan (when installed).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="port_discovery",
    priority=15,
    requires=("host",),
    profiles=("network", "full"),
    order=22,
)
def masscan_scan(ctx: ToolContext) -> ToolResult:
    binary = which("masscan")
    if binary is None:
        return unavailable("masscan", "masscan is not installed.", command="masscan -p1-1024 --rate 1000")

    ports = str(ctx.option("masscan_ports", "1-1024"))
    rate = int(ctx.option("masscan_rate", 1000))
    command = [binary, "-p", ports, "--rate", str(rate), "--wait", "2", "-oX", "-", ctx.target.host]
    read_text = "masscan -p {} --rate {} {}".format(ports, rate, ctx.target.host)
    started = time.perf_counter()
    try:
        proc = run_command(command, timeout=120)
    except Exception as exc:
        return ToolResult(tool="masscan", status="failed", summary="masscan did not complete.", error=type(exc).__name__, command=read_text)

    open_ports: list[dict] = []
    try:
        root = ElementTree.fromstring(proc.stdout or "<nmaprun/>")
        for port in root.findall(".//port"):
            if port.find("state") is not None and port.find("state").get("state") == "open":
                open_ports.append({"port": int(port.get("portid", 0)), "protocol": port.get("protocol", "tcp"), "service": "unknown", "product": "", "version": ""})
    except ElementTree.ParseError:
        pass

    return ToolResult(
        tool="masscan",
        status="ok" if open_ports else "partial",
        summary=f"masscan reported {len(open_ports)} open port(s).",
        data={"ports": open_ports},
        evidence=[evidence("masscan", f"open ports: {[p['port'] for p in open_ports]}")],
        command=read_text,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


@tool(
    name="udp_scan",
    description="Bounded UDP top-ports scan (requires nmap).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="udp_scan",
    requires=("host",),
    profiles=("network", "full"),
    order=24,
)
def udp_scan(ctx: ToolContext) -> ToolResult:
    binary = which("nmap")
    if binary is None:
        return unavailable("udp_scan", "nmap is required for UDP scanning.", command="nmap -sU --top-ports 50")
    top = int(ctx.option("udp_top_ports", 50))
    command = [binary, "-sU", "--top-ports", str(top), "-T3", "-oX", "-", ctx.target.host]
    read_text = f"nmap -sU --top-ports {top} {ctx.target.host}"
    try:
        proc = run_command(command, timeout=180)
    except Exception as exc:
        return ToolResult(tool="udp_scan", status="failed", summary="UDP scan did not complete.", error=type(exc).__name__, command=read_text)

    ports: list[dict] = []
    try:
        root = ElementTree.fromstring(proc.stdout or "<nmaprun/>")
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") in {"open", "open|filtered"}:
                svc = port.find("service")
                ports.append({"port": int(port.get("portid", 0)), "protocol": "udp", "service": svc.get("name", "unknown") if svc is not None else "unknown", "product": (svc.get("product") or "") if svc is not None else "", "version": (svc.get("version") or "") if svc is not None else ""})
    except ElementTree.ParseError:
        pass

    return ToolResult(
        tool="udp_scan",
        status="ok" if ports else "partial",
        summary=f"{len(ports)} UDP service(s) visible.",
        data={"ports": ports},
        evidence=[evidence("udp_scan", f"udp ports: {[(p['port'], p['service']) for p in ports]}")],
        command=read_text,
        note="UDP results are often filtered; treat as leads.",
    )


@tool(
    name="traceroute",
    description="Trace the network path to the target.",
    category="NETWORK",
    effect_class=EffectClass.PASSIVE,
    capability="network_path",
    requires=("host",),
    profiles=("network", "full"),
    order=90,
)
def traceroute(ctx: ToolContext) -> ToolResult:
    tracer = which("tracert") or which("traceroute")
    if tracer is None:
        return unavailable("traceroute", "No traceroute binary found.", command="traceroute")
    windows = tracer.lower().endswith(".exe") or "tracert" in tracer.lower()
    command = [tracer, "-h", "15", "-w", "1000", ctx.target.host] if windows else [tracer, "-m", "15", "-w", "2", ctx.target.host]
    read_text = f"traceroute {ctx.target.host}"
    try:
        proc = run_command(command, timeout=90)
    except Exception as exc:
        return ToolResult(tool="traceroute", status="failed", summary="traceroute did not complete.", error=type(exc).__name__, command=read_text)
    hops = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()][:20]
    return ToolResult(
        tool="traceroute",
        status="ok" if hops else "partial",
        summary=f"{len(hops)} hop line(s) collected.",
        data={"hops": hops},
        evidence=[evidence("traceroute", "; ".join(hops[:5]))],
        command=read_text,
    )
