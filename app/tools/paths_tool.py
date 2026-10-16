"""Web content discovery (well-known files only).

Retrieves ``/robots.txt``, ``/sitemap.xml`` and ``/.well-known/security.txt``.
These are published, low-impact resources. Paths listed in robots.txt are
reported as *observations* that name areas of interest - they are not probed
or brute-forced.
"""

from __future__ import annotations

import re

import httpx

from app.config import settings
from app.safety.redaction import redact
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

WELL_KNOWN = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]

_LOC_RE = re.compile(r"(?im)^\s*Sitemap:\s*(\S+)")
_SITEMAP_LOC_RE = re.compile(r"(?is)<loc>\s*(.*?)\s*</loc>")
_DISALLOW_RE = re.compile(r"(?im)^\s*Disallow:\s*(\S+)")


@tool(
    name="web_content",
    description="Fetch robots.txt / sitemap.xml / security.txt and parse hints.",
    category="CONTENT",
    effect_class=EffectClass.PASSIVE,
    capability="web_content",
    requires=("base_url",),
    profiles=("web", "full"),
    order=60,
)
def web_content(ctx: ToolContext) -> ToolResult:
    base = ctx.target.base_url
    found: dict[str, dict] = {}
    errors: list[str] = []

    for path in WELL_KNOWN:
        url = base.rstrip("/") + path
        try:
            response = httpx.get(
                url,
                timeout=settings.http_timeout,
                follow_redirects=True,
                headers={"User-Agent": settings.user_agent},
            )
        except httpx.HTTPError as exc:
            errors.append(f"{path}: {redact(str(exc))}")
            continue
        if response.status_code != 200:
            continue
        body = response.text[:20000]
        entry: dict = {"status": response.status_code, "size": len(body), "content_type": response.headers.get("content-type")}
        if path == "/robots.txt":
            entry["disallow"] = sorted(set(_DISALLOW_RE.findall(body)))[:60]
            entry["sitemaps"] = sorted(set(_LOC_RE.findall(body)))[:20]
        elif path == "/sitemap.xml":
            entry["urls"] = sorted(set(_SITEMAP_LOC_RE.findall(body)))[:80]
        else:  # security.txt
            entry["fields"] = [
                line.strip() for line in body.splitlines() if line.strip() and not line.startswith("#")
            ][:20]
        found[path] = entry

    if not found:
        return ToolResult(
            tool="web_content",
            status="partial",
            summary="None of the well-known files were retrievable.",
            data={"found": {}, "errors": errors},
            note="Absence of these files is not evidence of security.",
            command=f"GET {base}{{robots.txt,sitemap.xml,security.txt}}",
        )

    return ToolResult(
        tool="web_content",
        status="ok",
        summary=f"{len(found)} well-known resource(s) retrieved.",
        data={"found": found, "errors": errors},
        evidence=[evidence("web_content", f"{path}: HTTP 200 ({entry['size']} bytes)") for path, entry in found.items()],
        command=f"GET {base}{{robots.txt,sitemap.xml,security.txt}}",
    )
