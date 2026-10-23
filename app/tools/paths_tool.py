"""Web content discovery (well-known files only).

Retrieves ``/robots.txt``, ``/sitemap.xml`` and ``/.well-known/security.txt``.
These are published, low-impact resources. Paths listed in robots.txt are
reported as *observations* that name areas of interest - they are not probed
or brute-forced.

Each resource has an independent outcome (retrieved / missing / inaccessible /
parse failure / network error) so a missing file is never confused with a
blocked request or a broken parser.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from app.net.http import request_with_retries
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

_INACCESSIBLE = {401, 403, 429}


def _error_category(status: int | None, response_class: str) -> str:
    if status is None:
        return response_class
    if status == 401:
        return "auth_required"
    if status == 403:
        return "access_denied"
    if status == 429:
        return "rate_limited"
    if status == 404:
        return "not_found"
    if status >= 500:
        return "server_error"
    if 400 <= status < 500:
        return "client_error"
    return response_class


def _parse_robots(text: str) -> dict:
    return {
        "disallow": sorted(set(_DISALLOW_RE.findall(text)))[:60],
        "sitemaps": sorted(set(_LOC_RE.findall(text)))[:20],
    }


def _parse_sitemap(text: str) -> dict:
    return {"urls": sorted(set(_SITEMAP_LOC_RE.findall(text)))[:80]}


def _parse_security_txt(text: str) -> dict:
    return {
        "fields": [
            line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
        ][:20]
    }


def _parse(path: str, text: str) -> dict:
    if path == "/robots.txt":
        return _parse_robots(text)
    if path == "/sitemap.xml":
        return _parse_sitemap(text)
    return _parse_security_txt(text)


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
    base = ctx.target.base_url.rstrip("/")
    observed_at = datetime.now(timezone.utc)
    requested = ctx.option("well_known_paths") or WELL_KNOWN
    paths: list[str] = []
    for candidate in requested:
        path = str(candidate).strip()
        if path.startswith("/") and "://" not in path and path not in paths:
            paths.append(path)
    resources: dict[str, dict] = {}
    found: dict[str, dict] = {}
    missing: list[str] = []
    inaccessible: list[str] = []
    parse_errors: list[str] = []
    errors: list[str] = []
    network_failures = 0

    for path in paths:
        url = base + path
        result = request_with_retries(url, method="GET", follow_redirects=True)
        entry: dict = {
            "url": url,
            "final_url": result.final_url,
            "status": result.status_code,
            "response_class": result.response_class.value,
            "content_type": result.content_type,
            "size": result.body_length,
            "edge_indicators": result.edge_indicators,
            "diagnostic": result.snippet(160),
            "retrieved": False,
            "redirected": bool(result.redirect_chain),
            "attempts": result.attempts,
            "retries": result.retries,
            "retry_reasons": result.retry_reasons,
            "observed_at": observed_at.isoformat(),
        }
        if result.status_code is None:
            entry["outcome"] = "network_error"
            entry["error_category"] = _error_category(None, result.response_class.value)
            entry["error"] = result.error or result.response_class.value
            errors.append(f"{path}: {entry['error']}")
            network_failures += 1
        elif result.ok:
            entry["outcome"] = "retrieved"
            entry["retrieved"] = True
            try:
                entry.update(_parse(path, result.text[:20000]))
                entry["parse_status"] = "ok"
            except Exception as exc:  # malformed content must not abort the tool
                entry["parse_status"] = "failed"
                entry["error_category"] = "parse_error"
                entry["parse_error"] = f"{type(exc).__name__}: {exc}"
                parse_errors.append(f"{path}: {entry['parse_error']}")
            found[path] = entry
        elif result.status_code in _INACCESSIBLE:
            entry["outcome"] = "inaccessible"
            entry["error_category"] = _error_category(result.status_code, result.response_class.value)
            entry["error"] = f"HTTP {result.status_code} access denied by the target"
            inaccessible.append(path)
        elif result.status_code == 404:
            entry["outcome"] = "missing"
            entry["error_category"] = "not_found"
            entry["error"] = "HTTP 404 not found"
            missing.append(path)
        else:
            entry["outcome"] = "http_error"
            entry["error_category"] = _error_category(result.status_code, result.response_class.value)
            entry["error"] = f"HTTP {result.status_code}"
        resources[path] = entry

    tested = len(paths)
    if network_failures == tested:
        status = "failed"
        summary = f"All {tested} well-known requests failed at the network layer."
    elif found and not errors and not parse_errors:
        status = "ok"
        summary = f"{len(found)} well-known resource(s) retrieved."
    else:
        status = "partial"
        summary = (
            f"{len(found)}/{tested} retrieved, {len(missing)} missing, "
            f"{len(inaccessible)} inaccessible, {len(parse_errors)} parse failure(s), "
            f"{network_failures} network error(s)."
        )

    error_categories: dict[str, int] = {}
    for entry in resources.values():
        category = entry.get("error_category")
        if category:
            error_categories[category] = error_categories.get(category, 0) + 1

    evidence_items = [
        evidence(
            "web_content",
            f"{path}: HTTP {entry.get('status')} ({entry.get('size', 0)} bytes, {entry.get('outcome')})"
            + (f" [{entry.get('error_category')}]" if entry.get("error_category") else ""),
            url=entry.get("url"),
            status=entry.get("status"),
            outcome=entry.get("outcome"),
            error_category=entry.get("error_category"),
            diagnostic=entry.get("diagnostic"),
        )
        for path, entry in resources.items()
    ]

    return ToolResult(
        tool="web_content",
        status=status,
        summary=summary,
        data={
            "found": found,
            "resources": resources,
            "missing": missing,
            "inaccessible": inaccessible,
            "parse_errors": parse_errors,
            "errors": errors,
            "error_categories": error_categories,
            "tested": tested,
            "retrieved": len(found),
        },
        evidence=evidence_items,
        note=(
            "Absence of these files is not evidence that the site has no other content; "
            "a missing, inaccessible and unparsable resource are reported separately."
        ),
        command=f"GET {base}{{robots.txt,sitemap.xml,security.txt}}",
    )
