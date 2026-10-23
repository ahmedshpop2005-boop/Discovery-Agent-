"""Pure-Python asynchronous TCP connect scanner.

This tool needs no external binary, so the platform can still discover
services when Nmap is unavailable. It performs a full TCP handshake against a
bounded port set with concurrency limits - non-destructive and read-only.
"""

from __future__ import annotations

import asyncio
import socket
import time

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

# Compact common-service port map used for annotation.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    512: "exec", 513: "login", 514: "shell", 587: "submission", 636: "ldaps",
    873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "ms-sql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "node/grafana", 3128: "squid", 3306: "mysql", 3389: "rdp",
    4443: "https-alt", 5000: "upnp/flask", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis", 7001: "weblogic",
    7443: "https-alt", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9042: "cassandra", 9090: "http-alt", 9200: "elasticsearch", 9300: "es-transport",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 50000: "db2",
}

WEB_PORTS = [80, 443, 8000, 8080, 8081, 8443, 8888, 9443, 3000, 5000]

_TOP_100 = sorted(COMMON_PORTS.keys())[:100]


def _preset(name: str) -> list[int]:
    if name == "web":
        return WEB_PORTS
    if name == "top100":
        return _TOP_100
    return sorted(COMMON_PORTS.keys())  # "common"


async def _probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def _scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[int]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe(host, port, timeout, sem) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted(p for p in results if p is not None)


@tool(
    name="tcp_scan",
    description="Built-in async TCP connect scan over a bounded port set (no nmap needed).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="port_discovery",
    priority=20,
    requires=("host",),
    profiles=("safe", "network", "full"),
    order=20,
)
def tcp_scan(ctx: ToolContext) -> ToolResult:
    preset = str(ctx.option("tcp_preset", "common"))
    ports = ctx.option("tcp_ports") or _preset(preset)
    ports = [int(p) for p in ports][: settings.tcp_scan_max_ports]
    timeout = float(ctx.option("tcp_timeout", settings.socket_timeout))
    concurrency = int(ctx.option("tcp_concurrency", settings.tcp_scan_concurrency))

    started = time.perf_counter()
    try:
        open_ports = asyncio.run(_scan(ctx.target.host, ports, timeout, concurrency))
    except OSError as exc:
        return ToolResult(
            tool="tcp_scan",
            status="failed",
            summary="TCP connect scan could not resolve or reach the host.",
            error=str(exc),
        )

    duration = int((time.perf_counter() - started) * 1000)
    services = [
        {"port": p, "protocol": "tcp", "service": COMMON_PORTS.get(p, "unknown"), "product": "", "version": ""}
        for p in open_ports
    ]
    return ToolResult(
        tool="tcp_scan",
        status="ok",
        summary=f"{len(open_ports)} open TCP port(s) from a {len(ports)}-port set.",
        data={"ports": services, "scanned": len(ports), "preset": preset},
        evidence=[evidence("tcp_scan", f"open ports: {open_ports}", preset=preset, scanned=len(ports))],
        command=f"async tcp connect scan ({preset}, {len(ports)} ports)",
        note="Connect scan only; no payloads are sent.",
        duration_ms=duration,
    )
