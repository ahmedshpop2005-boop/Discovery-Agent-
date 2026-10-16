"""Service banner grabber.

Reads the greeting banner of discovered services over TCP. For protocol
identification it sends at most a single read-only request (an HTTP ``HEAD``
or a Redis ``INFO``); everything else is a passive read. No authentication is
attempted and no state is changed.
"""

from __future__ import annotations

import socket

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

# port -> (probe bytes or None, needs probe?)  ; None probe = passive read
_PROBES: dict[int, bytes | None] = {
    21: None,
    22: None,
    25: None,
    110: None,
    143: None,
    3306: None,
    5432: None,
    80: b"HEAD / HTTP/1.0\r\nHost: sentinel.invalid\r\nUser-Agent: AutoPentestSentinel\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: sentinel.invalid\r\nUser-Agent: AutoPentestSentinel\r\n\r\n",
    443: None,
    6379: b"INFO\r\n",
}


def _grab(host: str, port: int, timeout: float) -> str | None:
    probe = _PROBES.get(port, None)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe is not None:
                sock.sendall(probe)
            chunks = []
            total = 0
            while total < 2048:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            if not chunks:
                return None
            return b"".join(chunks).decode("utf-8", errors="replace").strip()
    except OSError:
        return None


@tool(
    name="service_banner",
    description="Grab service banners for discovered open ports.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="service_banner",
    requires=("host", "services"),
    profiles=("network", "full", "safe"),
    order=50,
)
def service_banner(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    services = ctx.option("services") or []
    ports = []
    for service in services:
        try:
            ports.append(int(service.get("port")))
        except (TypeError, ValueError):
            continue
    ports = sorted(set(ports))[:20]

    if not ports:
        return ToolResult(
            tool="service_banner",
            status="skipped",
            summary="No services were available to banner-grab.",
        )

    banners: dict[str, str] = {}
    for port in ports:
        banner = _grab(host, port, settings.socket_timeout)
        if banner:
            banners[str(port)] = banner[:400]

    status = "ok" if banners else "partial"
    return ToolResult(
        tool="service_banner",
        status=status,
        summary=f"{len(banners)} of {len(ports)} service(s) returned a banner.",
        data={"banners": banners, "probed_ports": ports},
        evidence=[evidence("service_banner", f"port {p}: {b.splitlines()[0][:80]}") for p, b in banners.items()],
        command=f"banner grab on {ports}",
        note="Banners are advertised strings, not authenticated versions.",
    )
