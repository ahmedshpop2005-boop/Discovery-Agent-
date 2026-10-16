"""HTTP posture tool.

A handful of rate-conscious requests against an authorized base URL:

* base request  - status, redacted headers, redirect, tech fingerprints;
* ``OPTIONS``   - advertised methods;
* one ``Origin`` probe - CORS reflection check.

Only observations are recorded. A missing header or an ``Allow`` list is a
posture observation, not a proven vulnerability.
"""

from __future__ import annotations

import re
import time

import httpx

from app.config import settings
from app.safety.redaction import redact
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _parse_set_cookie(header: str) -> dict:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    lowered = {p.lower(): p for p in parts[1:]}
    samesite = None
    for part in parts[1:]:
        if part.lower().startswith("samesite="):
            samesite = part.split("=", 1)[1]
    return {
        "name": name,
        "secure": "secure" in lowered,
        "httponly": "httponly" in lowered,
        "samesite": samesite,
        "has_domain": any(p.lower().startswith("domain=") for p in parts[1:]),
    }


def _tech_fingerprint(headers: dict[str, str], body: bytes) -> list[str]:
    hints: list[str] = []
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server:
        hints.append(f"Server: {server}")
    if powered:
        hints.append(f"X-Powered-By: {powered}")
    for header in ("x-aspnet-version", "x-generator", "x-drupal-cache", "x-shopify-stage"):
        if header in headers:
            hints.append(f"{header}: {headers[header]}")
    match = re.search(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if match:
        hints.append(f"meta generator: {match.group(1).decode('utf-8', 'replace')}")
    return hints


@tool(
    name="http_posture",
    description="HTTP status, security headers, cookies, CORS, methods (safe profile).",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_headers",
    priority=10,
    requires=("base_url",),
    profiles=("safe", "web", "network", "full"),
    order=30,
)
def http_posture(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    started = time.perf_counter()
    try:
        response = httpx.get(
            url,
            follow_redirects=False,
            timeout=settings.http_timeout,
            headers={"User-Agent": settings.user_agent},
        )
    except httpx.HTTPError as exc:
        return ToolResult(
            tool="http_posture",
            status="failed",
            summary="The HTTP request did not complete.",
            error=redact(str(exc)),
            command=f"GET {url}",
        )

    headers = {k.lower(): redact(v) for k, v in response.headers.items()}
    body = response.content[:40000]
    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).decode("utf-8", "replace").strip()[:120] if title_match else None

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    present = [h for h in SECURITY_HEADERS if h in headers]
    cookies = [_parse_set_cookie(c) for c in response.headers.get_list("set-cookie")]
    tech = _tech_fingerprint(headers, body)

    methods = None
    try:
        options = httpx.options(
            url, timeout=settings.http_timeout, headers={"User-Agent": settings.user_agent}
        )
        methods = options.headers.get("allow") or options.headers.get("access-control-allow-methods")
    except httpx.HTTPError:
        methods = None

    cors = None
    try:
        probe = httpx.get(
            url,
            headers={"User-Agent": settings.user_agent, "Origin": "https://sentinel.invalid"},
            timeout=settings.http_timeout,
        )
        acao = probe.headers.get("access-control-allow-origin")
        if acao:
            cors = {"allow_origin": acao, "credentials": probe.headers.get("access-control-allow-credentials")}
    except httpx.HTTPError:
        cors = None

    duration = int((time.perf_counter() - started) * 1000)
    data = {
        "url": str(response.url),
        "final_url": str(response.url),
        "http_status": response.status_code,
        "headers": headers,
        "missing_headers": missing,
        "present_headers": present,
        "cookies": cookies,
        "methods": methods,
        "cors": cors,
        "technology": tech,
        "title": title,
        "redirect": headers.get("location"),
    }
    return ToolResult(
        tool="http_posture",
        status="ok",
        summary=(
            f"HTTP {response.status_code}; {len(missing)} security header(s) missing; "
            f"{len(cookies)} cookie(s) observed."
        ),
        data=data,
        evidence=[
            evidence("http_posture", f"HTTP {response.status_code} from {url}"),
            evidence("http_posture", f"missing security headers: {missing}"),
        ],
        command=f"GET {url} (+OPTIONS, +Origin probe)",
        note="Non-destructive; a limited/blocked response is recorded, not graded as secure.",
        duration_ms=duration,
    )
