"""Subdomain enumeration (DNS-only).

Resolves a small, bounded wordlist of common subdomain labels against the
authorized domain using DNS only - no HTTP requests and no brute force of
hosts. Opt-in: enabled only in the ``full`` profile.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

try:
    import dns.resolver  # type: ignore

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DNS_AVAILABLE = False


def _load_wordlist() -> list[str]:
    path = settings.wordlist_dir / "subdomains.txt"
    if not path.exists():
        return ["www", "mail", "api", "dev", "staging", "test", "vpn", "portal", "admin", "app"]
    words = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words


def _resolves(fqdn: str) -> list[str]:
    if _DNS_AVAILABLE:
        try:
            import dns.resolver  # type: ignore

            return [r.to_text() for r in dns.resolver.resolve(fqdn, "A", lifetime=4)]
        except Exception:
            return []
    try:
        infos = socket.getaddrinfo(fqdn, None)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


@tool(
    name="subdomain_enum",
    description="DNS-only subdomain enumeration from a small wordlist.",
    category="DNS",
    effect_class=EffectClass.READ_ONLY,
    capability="subdomain",
    requires=("hostname",),
    profiles=("network", "full"),
    order=80,
)
def subdomain_enum(ctx: ToolContext) -> ToolResult:
    domain = ctx.target.host
    words = ctx.option("subdomain_words") or _load_wordlist()
    words = words[: settings.subdomain_limit]

    found: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_resolves, f"{word}.{domain}"): word for word in words}
        for future in as_completed(futures):
            word = futures[future]
            addresses = future.result()
            if addresses:
                found[f"{word}.{domain}"] = addresses

    return ToolResult(
        tool="subdomain_enum",
        status="ok" if found else "partial",
        summary=f"{len(found)} subdomain(s) resolved from {len(words)} candidates.",
        data={"subdomains": found, "tested": len(words)},
        evidence=[evidence("subdomain_enum", f"{name}: {addrs}") for name, addrs in list(found.items())[:10]],
        command=f"DNS resolve *.{domain} ({len(words)} candidates)",
        note="DNS-only; empty result is not proof that no subdomains exist.",
    )
