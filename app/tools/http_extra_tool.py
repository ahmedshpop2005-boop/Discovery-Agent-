"""Extra HTTP tools: curl fallback, favicon hash and WAF/CDN fingerprinting."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import httpx

from app.config import settings
from app.safety.redaction import redact
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

_WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "akamai-grn": "Akamai",
    "x-iinfo": "Imperva/Incapsula",
    "x-cdn": "Generic CDN",
    "x-cache": "CDN cache",
    "server": "Server header",
    "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure Front Door",
    "x-vercel-id": "Vercel",
}


@tool(
    name="http_curl",
    description="HTTP headers/methods via the curl binary (fallback for http_posture).",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_headers",
    priority=20,
    requires=("base_url",),
    profiles=("safe", "web", "network", "full"),
    order=31,
)
def http_curl(ctx: ToolContext) -> ToolResult:
    binary = which("curl")
    if binary is None:
        return unavailable("curl", "curl is not installed.", command="curl -sS -D - <url>")
    url = ctx.target.base_url
    with tempfile.NamedTemporaryFile("w", suffix=".body", delete=False) as handle:
        body_path = Path(handle.name)
    try:
        command = [binary, "-sS", "-D", "-", "-o", str(body_path), "--max-time", str(int(settings.http_timeout)), "-A", settings.user_agent, url]
        proc = run_command(command, timeout=settings.http_timeout + 5)
    except Exception as exc:
        return ToolResult(tool="curl", status="failed", summary="curl request did not complete.", error=type(exc).__name__, command=f"curl -sS -D - {url}")
    finally:
        body_path.unlink(missing_ok=True)

    headers: dict[str, str] = {}
    status_line = ""
    for line in (proc.stdout or "").splitlines():
        if line.lower().startswith("http/") and not status_line:
            status_line = line.strip()
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = redact(value.strip())

    present = [h for h in ("content-security-policy", "strict-transport-security", "x-frame-options") if h in headers]
    status = "ok" if status_line else "partial"
    return ToolResult(
        tool="curl",
        status=status,
        summary=status_line or "curl returned no status line.",
        data={"status_line": status_line, "headers": headers, "security_headers_present": present},
        evidence=[evidence("curl", f"{status_line}; headers={list(headers)[:8]}")],
        command=f"curl -sS -D - {url}",
    )


@tool(
    name="http_favicon",
    description="Fetch and fingerprint the site favicon.",
    category="WEB",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="http_favicon",
    requires=("base_url",),
    profiles=("web", "full"),
    order=62,
)
def http_favicon(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url.rstrip("/") + "/favicon.ico"
    try:
        response = httpx.get(url, timeout=settings.http_timeout, headers={"User-Agent": settings.user_agent})
    except httpx.HTTPError as exc:
        return ToolResult(tool="http_favicon", status="partial", summary="favicon could not be retrieved.", error=redact(str(exc)), command=f"GET {url}")
    if response.status_code != 200 or not response.content:
        return ToolResult(tool="http_favicon", status="partial", summary="no favicon served.", data={"status": response.status_code}, command=f"GET {url}")
    digest = hashlib.md5(response.content).hexdigest()  # noqa: S324 - identification, not security
    return ToolResult(
        tool="http_favicon",
        status="ok",
        summary=f"favicon md5 {digest} ({len(response.content)} bytes).",
        data={"md5": digest, "sha256": hashlib.sha256(response.content).hexdigest(), "size": len(response.content), "content_type": response.headers.get("content-type")},
        evidence=[evidence("http_favicon", f"md5={digest} size={len(response.content)}")],
        command=f"GET {url}",
    )


@tool(
    name="http_waf_detect",
    description="Detect WAF/CDN/edge in front of the application from headers.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_fingerprint",
    requires=("base_url",),
    profiles=("web", "full"),
    order=63,
)
def http_waf_detect(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    try:
        response = httpx.get(url, timeout=settings.http_timeout, headers={"User-Agent": settings.user_agent})
    except httpx.HTTPError as exc:
        return ToolResult(tool="http_waf_detect", status="failed", summary="request did not complete.", error=redact(str(exc)), command=f"GET {url}")
    headers = {k.lower(): v for k, v in response.headers.items()}
    detected = sorted({name for key, name in _WAF_SIGNATURES.items() if key in headers})
    return ToolResult(
        tool="http_waf_detect",
        status="ok",
        summary=("edge/WAF indicators: " + ", ".join(detected)) if detected else "no WAF/CDN header indicators found.",
        data={"indicators": detected, "server": headers.get("server")},
        evidence=[evidence("http_waf_detect", f"indicators={detected}")],
        command=f"GET {url}",
    )
