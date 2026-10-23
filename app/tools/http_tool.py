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
from datetime import datetime, timezone

from app.net.http import request_with_retries
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


_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
_HREF_RE = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
_API_RE = re.compile(r'["\'](/[A-Za-z0-9_\-./{}:$]*(?:api|v[0-9]+)[A-Za-z0-9_\-./{}:$]*)["\']', re.IGNORECASE)


def _attr(attrs: str, name: str) -> str | None:
    match = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
    return match.group(1) if match else None


def _extract_forms(html: str, limit: int = 20) -> list[dict]:
    """Bounded extraction of HTML forms (action, method, input names)."""
    forms: list[dict] = []
    for match in _FORM_RE.finditer(html):
        attrs, inner = match.group(1), match.group(2)
        forms.append(
            {
                "action": _attr(attrs, "action") or "",
                "method": (_attr(attrs, "method") or "GET").upper(),
                "parameters": sorted(set(_INPUT_NAME_RE.findall(inner)))[:20],
            }
        )
        if len(forms) >= limit:
            break
    return forms


def _extract_links(html: str, origin: str) -> tuple[list[str], int]:
    """Same-origin links (bounded) plus the count of external links."""
    from urllib.parse import urlparse

    origin_host = urlparse(origin).netloc.lower()
    links: list[str] = []
    external = 0
    for value in _HREF_RE.findall(html):
        if value.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        parsed = urlparse(value)
        if parsed.netloc and parsed.netloc.lower() != origin_host:
            external += 1
            continue
        candidate = parsed.path or "/"
        if candidate.lower().endswith(
            (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2")
        ):
            continue
        if candidate not in links:
            links.append(candidate)
        if len(links) >= 50:
            break
    return links, external


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
    profiles=("safe", "web", "full"),
    order=30,
)
def http_posture(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    started = time.perf_counter()
    observed_at = datetime.now(timezone.utc)
    result = request_with_retries(url, method="GET", follow_redirects=False)

    if result.status_code is None:
        return ToolResult(
            tool="http_posture",
            status="failed",
            summary=f"The HTTP request did not complete ({result.response_class.value}).",
            error=result.error or result.response_class.value,
            data={
                "url": url,
                "response_class": result.response_class.value,
                "attempts": result.attempts,
                "retries": result.retries,
                "retry_reasons": result.retry_reasons,
                "observed_at": observed_at.isoformat(),
            },
            command=f"GET {url}",
        )

    headers = dict(result.headers)
    body = result.body[:40000]
    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).decode("utf-8", "replace").strip()[:120] if title_match else None

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    present = [h for h in SECURITY_HEADERS if h in headers]
    cookies = [_parse_set_cookie(c) for c in result.set_cookie if c.strip()]
    tech = _tech_fingerprint(headers, body)

    html = body.decode("utf-8", "replace")
    forms = _extract_forms(html)
    links, external_links = _extract_links(html, result.final_url or url)
    scripts = sorted(set(_SCRIPT_SRC_RE.findall(html)))[:30]
    api_hints = sorted(set(_API_RE.findall(html)))[:30]

    methods = None
    options = request_with_retries(url, method="OPTIONS", retries=0)
    if options.status_code is not None:
        methods = options.headers.get("allow") or options.headers.get("access-control-allow-methods")

    cors = None
    probe = request_with_retries(
        url,
        method="GET",
        headers={"Origin": "https://sentinel.invalid"},
        retries=0,
    )
    if probe.status_code is not None:
        acao = probe.headers.get("access-control-allow-origin")
        if acao:
            cors = {"allow_origin": acao, "credentials": probe.headers.get("access-control-allow-credentials")}

    duration = int((time.perf_counter() - started) * 1000)
    limited = result.response_class.value not in {"success", "redirect"}
    data = {
        "url": url,
        "final_url": result.final_url or url,
        "http_status": result.status_code,
        "response_class": result.response_class.value,
        "content_type": result.content_type,
        "edge_indicators": result.edge_indicators,
        "edge_likely": result.edge_likely,
        "limited": limited,
        "attempts": result.attempts,
        "retries": result.retries,
        "retry_reasons": result.retry_reasons,
        "request_error": result.error,
        "body_snippet": result.snippet(),
        "observed_at": observed_at.isoformat(),
        "headers": headers,
        "missing_headers": missing,
        "present_headers": present,
        "cookies": cookies,
        "methods": methods,
        "cors": cors,
        "technology": tech,
        "title": title,
        "redirect": headers.get("location"),
        "forms": forms,
        "links": links,
        "scripts": scripts,
        "api_hints": api_hints,
        "external_links": external_links,
        "www_authenticate": headers.get("www-authenticate"),
    }
    return ToolResult(
        tool="http_posture",
        status="ok",
        summary=(
            f"HTTP {result.status_code} ({result.response_class.value}); "
            f"{len(missing)} security header(s) missing; {len(cookies)} cookie(s) observed."
        ),
        data=data,
        evidence=[
            evidence(
                "http_posture",
                f"HTTP {result.status_code} ({result.response_class.value}) from {url}",
                url=url,
                status=result.status_code,
                response_class=result.response_class.value,
                edge_indicators=result.edge_indicators,
                attempts=result.attempts,
            ),
            evidence("http_posture", f"missing security headers: {missing}"),
        ],
        command=f"GET {url} (+OPTIONS, +Origin probe)",
        note=(
            "Non-destructive. A 401/403/429 or CDN response is classified as limited; "
            "its origin application is unconfirmed and never graded as secure."
        ),
        duration_ms=duration,
    )
