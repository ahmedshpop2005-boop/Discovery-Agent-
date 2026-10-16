"""Extra DNS tools: nslookup fallback, reverse DNS and zone-transfer attempt."""

from __future__ import annotations

import socket

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

try:
    import dns.query  # type: ignore
    import dns.resolver  # type: ignore
    import dns.zone  # type: ignore

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DNS_AVAILABLE = False


@tool(
    name="dns_nslookup",
    description="DNS records via the nslookup binary (fallback for dns_recon).",
    category="DNS",
    effect_class=EffectClass.READ_ONLY,
    capability="dns_resolve",
    priority=20,
    requires=("hostname",),
    profiles=("safe", "web", "network", "full"),
    order=26,
)
def dns_nslookup(ctx: ToolContext) -> ToolResult:
    binary = which("nslookup")
    if binary is None:
        return unavailable("nslookup", "nslookup is not installed.", command="nslookup -type=A")
    host = ctx.target.host
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            proc = run_command([binary, "-type=" + rtype, host], timeout=8)
        except Exception:
            continue
        values = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if rtype in {"A", "AAAA"} and line.lower().startswith("address") and "#53" not in line:
                values.append(line.split(":", 1)[-1].strip())
            elif rtype in {"MX", "NS", "TXT"} and ("exchanger" in line.lower() or "nameserver" in line.lower() or "text" in line.lower()):
                values.append(line)
        if values:
            records[rtype] = sorted(set(values))
    return ToolResult(
        tool="dns_nslookup",
        status="ok" if records else "partial",
        summary=f"{sum(len(v) for v in records.values())} record(s) via nslookup.",
        data={"records": records},
        evidence=[evidence("dns_nslookup", f"{k}: {v}") for k, v in records.items()],
        command=f"nslookup {host}",
    )


@tool(
    name="reverse_dns",
    description="Reverse-DNS (PTR) lookup for the target address.",
    category="DNS",
    effect_class=EffectClass.READ_ONLY,
    capability="reverse_dns",
    requires=("host",),
    profiles=("web", "network", "full"),
    order=27,
)
def reverse_dns(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    names: list[str] = []
    if _DNS_AVAILABLE:
        address = ctx.target.host
        if not ctx.target.is_ip:
            try:
                address = str(dns.resolver.resolve(host, "A", lifetime=4)[0])  # type: ignore[attr-defined]
            except Exception:
                address = host
        try:
            from dns import reversename  # type: ignore

            answers = dns.resolver.resolve(reversename.from_address(address), "PTR", lifetime=4)  # type: ignore[attr-defined]
            names = [str(a).rstrip(".") for a in answers]
        except Exception:
            names = []
    if not names:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ctx.target.host)
            names = [hostname] + list(aliases)
        except (socket.herror, socket.gaierror, OSError):
            names = []
    return ToolResult(
        tool="reverse_dns",
        status="ok" if names else "partial",
        summary=", ".join(names) if names else "no PTR record for the address.",
        data={"names": names},
        evidence=[evidence("reverse_dns", f"PTR: {names}")],
        command=f"PTR lookup {ctx.target.host}",
    )


@tool(
    name="dns_zone_transfer",
    description="Attempt an AXFR zone transfer against the domain's name servers.",
    category="DNS",
    effect_class=EffectClass.READ_ONLY,
    capability="zone_transfer",
    requires=("hostname",),
    profiles=("network", "full"),
    order=28,
)
def dns_zone_transfer(ctx: ToolContext) -> ToolResult:
    if not _DNS_AVAILABLE:
        return unavailable("dns_zone_transfer", "dnspython is required for AXFR.", command="AXFR")
    domain = ctx.target.host
    try:
        ns_records = [str(r).rstrip(".") for r in dns.resolver.resolve(domain, "NS", lifetime=5)]  # type: ignore[attr-defined]
    except Exception:
        return ToolResult(tool="dns_zone_transfer", status="partial", summary="could not resolve name servers.", command=f"AXFR {domain}")

    transferred: dict[str, list[str]] = {}
    for ns in ns_records[:3]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=6))  # type: ignore[attr-defined]
            transferred[ns] = sorted(name.to_text() for name in zone.nodes.keys())
        except Exception:
            continue
    return ToolResult(
        tool="dns_zone_transfer",
        status="ok" if transferred else "partial",
        summary=("zone transfer SUCCEEDED (misconfiguration)" if transferred else "all name servers refused AXFR (expected)"),
        data={"transferred": transferred, "nameservers": ns_records},
        evidence=[evidence("dns_zone_transfer", f"AXFR result: {transferred or 'refused'}")],
        command=f"AXFR {domain}",
        note="A successful AXFR exposes all DNS records and is a finding; refusal is normal.",
    )
