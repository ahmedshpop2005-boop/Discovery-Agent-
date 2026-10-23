"""WHOIS registration lookup.

Queries registration data for an authorized domain over TCP/43, following a
single referral. Read-only OSINT; used to record registrar, creation/expiry
dates and name servers.
"""

from __future__ import annotations

import socket

from app.tools.base import EffectClass, ToolContext, ToolResult, evidence, run_command, which
from app.tools.registry import tool

_IANA = "whois.iana.org"

_FIELDS = {
    "registrar",
    "registrant organization",
    "org",
    "creation date",
    "created",
    "registry expiry date",
    "expiry date",
    "expiration date",
    "updated date",
    "name server",
    "nserver",
    "domain status",
    "status",
}


def _whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse(text: str) -> dict:
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line or line.startswith("%") or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in _FIELDS and value.strip():
            result.setdefault(key, []).append(value.strip())
    return result


@tool(
    name="whois_lookup",
    description="Registration (WHOIS) lookup for a domain.",
    category="OSINT",
    effect_class=EffectClass.READ_ONLY,
    capability="whois",
    requires=("hostname",),
    profiles=("web", "network", "full"),
    order=70,
)
def whois_lookup(ctx: ToolContext) -> ToolResult:
    domain = ctx.target.host
    try:
        referral_text = _whois_query(_IANA, domain)
        refer = None
        for line in referral_text.splitlines():
            if line.lower().startswith("refer:"):
                refer = line.split(":", 1)[1].strip()
                break
        body = _whois_query(refer, domain) if refer else referral_text
    except OSError:
        binary = which("whois")
        if binary is None:
            return ToolResult(
                tool="whois_lookup",
                status="unavailable",
                summary="WHOIS is not reachable and no whois client is installed.",
                command=f"whois {domain}",
            )
        proc = run_command([binary, domain], timeout=12)
        if proc.returncode != 0:
            return ToolResult(
                tool="whois_lookup",
                status="failed",
                summary="WHOIS lookup failed.",
                error=(proc.stderr or "")[-200:],
                command=f"whois {domain}",
            )
        body = proc.stdout

    parsed = _parse(body)
    if not parsed:
        return ToolResult(
            tool="whois_lookup",
            status="partial",
            summary="WHOIS returned no parseable registration fields.",
            data={"fields": {}},
            command=f"whois {domain}",
        )
    return ToolResult(
        tool="whois_lookup",
        status="ok",
        summary=f"WHOIS returned {len(parsed)} field group(s).",
        data={"fields": parsed},
        evidence=[evidence("whois_lookup", f"{k}: {v}") for k, v in list(parsed.items())[:6]],
        command=f"whois {domain}",
    )
