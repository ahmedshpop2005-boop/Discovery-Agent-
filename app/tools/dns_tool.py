"""DNS reconnaissance tool.

Enumerates public DNS records (A/AAAA/NS/MX/TXT/CNAME/SOA/CAA) for an
authorized hostname. Uses ``dnspython`` when available and falls back to the
system resolver / ``nslookup`` otherwise. Read-only; no zone transfer is
attempted.
"""

from __future__ import annotations

from app.tools.base import EffectClass, ToolContext, ToolResult, evidence, run_command, which
from app.tools.registry import tool

try:
    import dns.resolver  # type: ignore

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    _DNS_AVAILABLE = False

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")


def _resolve_dnspython(host: str, rtype: str) -> list[str]:
    import dns.resolver  # type: ignore

    answers: list[str] = []
    try:
        for record in dns.resolver.resolve(host, rtype, lifetime=6):
            answers.append(record.to_text())
    except Exception:
        return []
    return answers


def _resolve_fallback(host: str, rtype: str) -> list[str]:
    binary = which("nslookup")
    if binary is None:
        return []
    proc = run_command([binary, "-type=" + rtype, host], timeout=8)
    values: list[str] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if rtype == "A" and line.startswith("Address"):
            values.append(line.split(":", 1)[-1].strip())
        elif rtype in {"MX", "NS", "TXT", "CNAME", "SOA", "CAA"}:
            if f"{rtype} " in line or line.lower().startswith(("mail exchanger", "text =")):
                values.append(line)
    return values


@tool(
    name="dns_recon",
    description="Enumerate public DNS records for a hostname.",
    category="DNS",
    effect_class=EffectClass.READ_ONLY,
    capability="dns_resolve",
    priority=10,
    requires=("hostname",),
    profiles=("safe", "web", "network", "full"),
    order=25,
)
def dns_recon(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        values = _resolve_dnspython(host, rtype) if _DNS_AVAILABLE else _resolve_fallback(host, rtype)
        if values:
            records[rtype] = values

    if not records:
        return ToolResult(
            tool="dns_recon",
            status="partial",
            summary="No DNS records could be resolved for the target.",
            data={"records": {}, "resolver": "dnspython" if _DNS_AVAILABLE else "nslookup"},
            note="Empty result means nothing was collected, not that no records exist.",
            command=f"DNS query {host}",
        )

    return ToolResult(
        tool="dns_recon",
        status="ok",
        summary=f"{sum(len(v) for v in records.values())} DNS record(s) across {len(records)} type(s).",
        data={"records": records, "resolver": "dnspython" if _DNS_AVAILABLE else "nslookup"},
        evidence=[evidence("dns_recon", f"{rtype}: {values}") for rtype, values in records.items()],
        command=f"DNS query {host}",
    )
