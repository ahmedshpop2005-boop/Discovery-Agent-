"""Projection from workflow state to the Web surface contract.

The Web extension (WEB EXTENSION 02) turns the raw HTTP/TLS/fingerprint
observations into a sourced :class:`WebAssetInventory`: observed applications,
routes/endpoints, web observations, relationship proposals, provenance,
evidence, coverage summaries, uncertainties and unassessed targets.

Design rules:

* A route is only ``observed`` when it was actually requested and answered.
  Routes declared by robots.txt/sitemap/OpenAPI or read from client scripts are
  recorded as ``observed=False`` (spec-only) - never as a vulnerability.
* Technology versions are fingerprinted/claimed, never package-verified, and
  the normaliser rejects IPs, country names, MIME types and header directives.
* A 401/403/429 or CDN response is classified as *limited*; the origin
  application is unconfirmed and is never called secure.
* Route coverage is ``limited``/``partial`` whenever access controls, missing
  authentication or tool failures prevent confirmation - never ``full`` just
  because every candidate was attempted.
* No authenticated surface or role boundary is claimed when no authorized
  access profile was actually exercised.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.agents.technologies import normalize_technologies
from app.contracts.discovery import (
    AuthenticationCoverage,
    DiscoveryInput,
    EndpointRecord,
    EvidenceRecord,
    FormRecord,
    RelationshipProposal,
    RouteCoverage,
    TechnologyRecord,
    Uncertainty,
    UnassessedTarget,
    WebApplication,
    WebAssetInventory,
    WebContext,
    WebObservationProvenance,
    WebObservationRecord,
)
from app.contracts.enums import (
    ConfidenceLevel,
    CoverageStatus,
    ObservationBasis,
    RelationshipKind,
    VerificationStatus,
)
from app.net.http import classify_response
from app.tools.registry import get as get_spec

_WEB_TOOLS = (
    "http_posture",
    "http_curl",
    "whatweb",
    "web_content",
    "gobuster_scan",
    "wafw00f",
    "http_waf_detect",
    "http_favicon",
    "tls_posture",
    "tls_openssl",
)

_TECH_PREFIXES = {
    "server",
    "x-powered-by",
    "meta generator",
    "x-generator",
    "x-aspnet-version",
    "x-drupal-cache",
    "x-shopify-stage",
}

_ASSET_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
)

_INACCESSIBLE_STATUSES = {401, 403, 429}
_FAILED_STATUSES = {404, 500, 502, 503, 504}

_MAX_ENDPOINTS = 200
_MAX_EVIDENCE = 200


def _prov_ref(tool: str) -> str:
    return f"prov:{tool}"


def _app_id(origin: str) -> str:
    return f"app:{origin}"


def _endpoint_id(origin: str, method: str, path: str) -> str:
    return f"endpoint:{origin}:{method.upper()} {path}"


def _split_name_version(value: str) -> tuple[str, str | None]:
    value = (value or "").strip()
    if not value:
        return "unknown", None
    if "/" in value:
        name, _, version = value.partition("/")
        if name.strip() and any(ch.isdigit() for ch in version):
            return name.strip(), version.strip() or None
    match = re.match(r"^([A-Za-z][\w .\-]*?)[ /]v?(\d[\w.\-]*)$", value)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return value, None


def _parse_tech_hint(hint: str) -> tuple[str, str | None]:
    text = hint.strip()
    lowered = text.lower()
    for prefix in _TECH_PREFIXES:
        if lowered.startswith(prefix + ":"):
            text = text[len(prefix) + 1 :].strip()
            break
    return _split_name_version(text)


def _base_origin(state: dict, inp: DiscoveryInput) -> str:
    base = state.get("base_url")
    if not base:
        seed = inp.target_seeds[0] if inp.target_seeds else ""
        base = seed or "unknown"
    return base.rstrip("/")


def _evidence_id(tool: str, index: int) -> str:
    return f"ev:{tool}:{index}"


# ---------------------------------------------------------------------------
# Applications / technology normalisation
# ---------------------------------------------------------------------------


def _waf_label(results: dict[str, Any]) -> str | None:
    waf = results.get("wafw00f", {}).get("data", {}) or {}
    if waf.get("detected"):
        return str(waf.get("firewall") or "detected")
    passive = results.get("http_waf_detect", {}).get("data", {}) or {}
    indicators = [item for item in (passive.get("indicators") or []) if item != "Server header"]
    return ", ".join(indicators) if indicators else None


def _raw_technologies(
    http: dict[str, Any],
    whatweb: dict[str, Any],
    *,
    origin: str,
    observed_at: datetime,
) -> list[dict]:
    observations: list[dict] = []
    for hint in http.get("technology") or []:
        name, version = _parse_tech_hint(str(hint))
        method = "header" if ":" in str(hint) else "html"
        observations.append(
            {
                "name": name,
                "version": version,
                "source": "http_posture",
                "tool": "http_posture",
                "method": method,
                "evidence": [f"HTTP hint: {hint}"],
                "source_url": origin,
                "observed_at": observed_at,
            }
        )
    for name, detail in (whatweb.get("plugins") or {}).items():
        version = None
        evidence = [f"WhatWeb plugin: {name}"]
        if isinstance(detail, dict):
            version = detail.get("version") or detail.get("string")
            if version:
                evidence.append(f"WhatWeb {name} value: {version}")
        observations.append(
            {
                "name": str(name),
                "version": str(version) if version else None,
                "source": "whatweb",
                "tool": "whatweb",
                "method": "whatweb",
                "evidence": evidence,
                "source_url": origin,
                "observed_at": observed_at,
            }
        )
    return observations


def build_applications(
    state: dict,
    inp: DiscoveryInput,
    origin: str,
    observed_at: datetime | None = None,
) -> tuple[list[WebApplication], list[Uncertainty]]:
    results = state.get("results", {})
    http = results.get("http_posture", {}).get("data", {}) or {}
    headers = http.get("headers") or {}
    application_id = _app_id(origin)
    observed_at = observed_at or datetime.now().astimezone()

    if state.get("technologies") is not None:
        technologies = [TechnologyRecord.model_validate(item) for item in state["technologies"]]
        uncertainties = [
            Uncertainty.model_validate(item) for item in (state.get("technology_uncertainties") or [])
        ]
    else:
        raw = _raw_technologies(
            http,
            results.get("whatweb", {}).get("data", {}) or {},
            origin=origin,
            observed_at=observed_at,
        )
        technologies, uncertainties = normalize_technologies(
            raw, observed_at=observed_at, source_url=origin
        )

    context = inp.web_context or WebContext()
    application = WebApplication(
        application_id=application_id,
        origin=origin,
        identity=http.get("title") or origin,
        title=http.get("title"),
        base_paths=[context.base_path or "/"],
        technologies=sorted(technologies, key=lambda t: t.name.lower()),
        server=headers.get("server"),
        waf=_waf_label(results),
        evidence_refs=[_prov_ref("http_posture")] if http else [],
    )
    return [application], uncertainties


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _query_parameters(path: str) -> list[str]:
    try:
        return sorted(parse_qs(urlparse(path).query).keys())
    except ValueError:
        return []


def _clean_path(value: str) -> str:
    path = (value or "").strip()
    if not path:
        return "/"
    if "://" in path:
        parsed = urlparse(path)
        path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _classification(status: int | None) -> str:
    return classify_response(status).value if isinstance(status, int) else "unknown"


def build_endpoints(state: dict, inp: DiscoveryInput, origin: str) -> list[EndpointRecord]:
    results = state.get("results", {})
    application_id = _app_id(origin)
    endpoints: list[EndpointRecord] = []
    seen: set[tuple[str, str]] = set()

    def add(
        path: str,
        method: str = "GET",
        *,
        status: int | None = None,
        parameters: list[str] | None = None,
        forms: list[FormRecord] | None = None,
        source: str,
        observed: bool = True,
        api_operation: str | None = None,
        snippet: str | None = None,
        collection_method: str | None = None,
        limitations: list[str] | None = None,
    ) -> None:
        if len(endpoints) >= _MAX_ENDPOINTS:
            return
        cleaned = _clean_path(path)
        if cleaned.lower().endswith(_ASSET_SUFFIXES):
            return
        method = (method or "GET").upper()
        key = (method, cleaned)
        if key in seen:
            return
        seen.add(key)
        evidence_items = []
        if status is not None:
            evidence_items.append(f"{source}: {method} {origin}{cleaned} -> HTTP {status}")
        if snippet:
            evidence_items.append(f"{source}: {snippet}")
        endpoints.append(
            EndpointRecord(
                endpoint_id=_endpoint_id(origin, method, cleaned),
                application_id=application_id,
                path=cleaned,
                method=method,
                parameters=sorted(set(parameters or _query_parameters(cleaned))),
                forms=forms or [],
                api_operation=api_operation,
                observed=observed,
                status=status,
                classification=_classification(status) if observed else "declared",
                collection_method=collection_method or source.split(":")[0],
                source=source,
                evidence=evidence_items,
                limitations=limitations or [],
                evidence_refs=[_prov_ref(source.split(":")[0])],
            )
        )

    http = results.get("http_posture", {})
    if http.get("status") == "ok":
        data = http.get("data", {}) or {}
        add(
            "/",
            "GET",
            status=data.get("http_status"),
            source="http_posture",
            snippet=data.get("body_snippet"),
            collection_method="http",
            limitations=(
                [f"base response classified as {data.get('response_class')}"]
                if data.get("response_class") not in {"success", "redirect"}
                else []
            ),
        )
        for form in data.get("forms") or []:
            action = form.get("action") or "/"
            add(
                action,
                form.get("method") or "GET",
                parameters=form.get("parameters") or [],
                forms=[
                    FormRecord(
                        action=action,
                        method=(form.get("method") or "GET").upper(),
                        parameters=form.get("parameters") or [],
                    )
                ],
                source="http_posture:form",
                collection_method="html-form",
                observed=False if action == "/" else False,
                api_operation="form-declared",
            )
        for link in data.get("links") or []:
            add(link, "GET", source="http_posture:link", observed=False, collection_method="html-link", api_operation="link-declared")
        for hint in data.get("api_hints") or []:
            add(hint, "GET", source="http_posture:client-script", observed=False, collection_method="client-script", api_operation="client-script-hint")

    gobuster = results.get("gobuster_scan", {}).get("data", {}) or {}
    uniform = bool(gobuster.get("suspicious_uniform"))
    for item in gobuster.get("paths") or []:
        status = item.get("status")
        add(
            item.get("path") or "/",
            "GET",
            status=status,
            source="gobuster_scan",
            collection_method="content-discovery",
            limitations=(
                ["uniform access-control/CDN response; route not confirmed"] if uniform else []
            ),
        )

    content_result = results.get("web_content", {})
    content_data = content_result.get("data", {}) or {}
    resources = content_data.get("resources") or {}
    found = content_data.get("found", {}) or {}
    if resources:
        for path, entry in resources.items():
            outcome = entry.get("outcome")
            add(
                path,
                "GET",
                status=entry.get("status"),
                source="web_content",
                observed=entry.get("status") is not None,
                collection_method="well-known",
                limitations=(
                    [f"resource outcome: {outcome}"]
                    if outcome in {"inaccessible", "network_error", "missing"}
                    else []
                ),
            )
    else:
        for path, entry in found.items():
            add(path, "GET", status=entry.get("status"), source="web_content", collection_method="well-known")

    for path, entry in found.items():
        if path == "/robots.txt":
            for declared in entry.get("disallow") or []:
                add(declared, "GET", source="web_content:robots", observed=False, api_operation="robots-declared")
        if path == "/sitemap.xml":
            for declared in entry.get("urls") or []:
                add(declared, "GET", source="web_content:sitemap", observed=False, api_operation="sitemap-declared")

    favicon = results.get("http_favicon", {})
    if favicon.get("status") == "ok":
        add("/favicon.ico", "GET", source="http_favicon", collection_method="favicon", observed=False)

    context = inp.web_context or WebContext()
    for spec in context.api_specs:
        add(spec, "GET", source="web_context", observed=False, api_operation="spec-only", collection_method="spec")

    return endpoints


# ---------------------------------------------------------------------------
# Route coverage / authentication coverage
# ---------------------------------------------------------------------------


def build_route_coverage(
    state: dict,
    inp: DiscoveryInput,
    endpoints: list[EndpointRecord],
) -> RouteCoverage:
    results = state.get("results", {})
    http = results.get("http_posture", {}).get("data", {}) or {}
    web_content = results.get("web_content", {}).get("data", {}) or {}
    gobuster = results.get("gobuster_scan", {}).get("data", {}) or {}

    attempted = 0
    confirmed = 0
    inaccessible = 0
    failed = 0
    untested = len([endpoint for endpoint in endpoints if not endpoint.observed])
    limitations: list[str] = []

    base_status = http.get("http_status")
    if isinstance(base_status, int):
        attempted += 1
        if 200 <= base_status < 400:
            confirmed += 1
        elif base_status in _INACCESSIBLE_STATUSES:
            inaccessible += 1
        else:
            failed += 1
    elif results.get("http_posture", {}).get("status") in {"failed", "unavailable"}:
        failed += 1

    resources = web_content.get("resources") or {}
    if resources:
        for entry in resources.values():
            attempted += 1
            status = entry.get("status")
            if entry.get("outcome") == "retrieved" or (isinstance(status, int) and 200 <= status < 400):
                confirmed += 1
            elif status in _INACCESSIBLE_STATUSES:
                inaccessible += 1
            else:
                failed += 1
        if web_content.get("parse_errors"):
            limitations.append(
                f"{len(web_content['parse_errors'])} well-known resource(s) could not be parsed"
            )
    elif web_content.get("found"):
        attempted += len(web_content["found"])
        confirmed += len(web_content["found"])

    if gobuster:
        candidates = int(gobuster.get("attempted") or gobuster.get("tested") or 0)
        attempted += candidates
        valid = int(gobuster.get("valid_responses") or 0)
        if gobuster.get("suspicious_uniform"):
            valid = 0
            limitations.append(
                "Gobuster responses were a uniform access-control/CDN page; treated as "
                "inaccessible, not discovered"
            )
        confirmed += valid
        inaccessible += int(gobuster.get("rejected_responses") or 0)
        failed += int(gobuster.get("server_error_responses") or 0)
        remaining = int(gobuster.get("untested") or 0)
        if remaining:
            failed += remaining
            limitations.append(f"{remaining} Gobuster candidate(s) were not tested")
        if gobuster.get("timed_out"):
            limitations.append("Gobuster timed out; only partial results were preserved")
        elif gobuster.get("zero_result_success"):
            limitations.append(
                "Gobuster completed with zero responses; zero does not prove that no "
                "paths exist"
            )

    base_class = http.get("response_class")
    if base_class in {"auth_required", "forbidden", "rate_limited"}:
        limitations.append(
            f"base URL returned {base_class.replace('_', ' ')} (HTTP {base_status}); the "
            "underlying application response is unconfirmed"
        )
    if http.get("edge_likely"):
        indicators = ", ".join(http.get("edge_indicators") or [])
        limitations.append(
            f"CDN/WAF indicators present ({indicators}); responses may reflect an edge page"
        )

    if not any(profile.authenticated for profile in inp.access_profiles):
        limitations.append(
            "no authenticated access profile was supplied; authenticated/role-protected "
            "routes could not be assessed"
        )

    for tool in ("web_content", "gobuster_scan"):
        payload = results.get(tool, {})
        if payload.get("status") in {"failed", "unavailable"}:
            limitations.append(f"{tool} did not complete: {payload.get('summary') or payload.get('error')}")
    if results.get("gobuster_scan", {}).get("status") == "partial":
        limitations.append("Gobuster completed partially; coverage is incomplete")

    methods_executed = [
        tool for tool in state.get("executed", []) if tool in {"http_posture", "web_content", "gobuster_scan"}
    ]
    methods_skipped = [
        tool
        for tool in state.get("tool_plan", [])
        if tool in {"http_posture", "web_content", "gobuster_scan"} and tool not in state.get("executed", [])
    ]

    hard_block = (
        base_class in {"auth_required", "forbidden", "rate_limited"}
        or bool(http.get("edge_likely"))
        or bool(gobuster.get("suspicious_uniform"))
        or results.get("web_content", {}).get("status") == "failed"
        or results.get("gobuster_scan", {}).get("status") in {"failed", "unavailable"}
    )

    if attempted == 0 and not methods_executed:
        coverage_status = CoverageStatus.UNKNOWN
    elif hard_block:
        coverage_status = CoverageStatus.LIMITED
        limitations.append("coverage is limited by an access-control/tool failure")
    elif limitations:
        coverage_status = CoverageStatus.PARTIAL
    else:
        coverage_status = CoverageStatus.FULL

    return RouteCoverage(
        routes_attempted=attempted,
        routes_confirmed=confirmed,
        routes_inaccessible=inaccessible,
        routes_failed=failed,
        routes_untested=untested,
        coverage_status=coverage_status,
        coverage_limitations=_dedupe(limitations),
        methods_executed=methods_executed,
        methods_skipped=methods_skipped,
    )


def build_authentication_coverage(state: dict, inp: DiscoveryInput) -> AuthenticationCoverage:
    profiles = inp.access_profiles or []
    authenticated = [profile for profile in profiles if profile.authenticated]
    http = state.get("results", {}).get("http_posture", {}).get("data", {}) or {}

    checks_completed: list[str] = []
    if http.get("http_status") is not None:
        checks_completed.append("unauthenticated external HTTP probes")
    if any(profile.kind == "external-probe" for profile in profiles):
        checks_completed.append("external probe identity recording")

    checks_unverified = [
        "authenticated routes",
        "role-based authorization boundaries",
        "post-login data flows",
    ]

    notes: list[str] = []
    if not authenticated:
        status = "not_assessed"
        notes.append(
            "No authenticated access profile was supplied; authenticated routes and role "
            "boundaries were not assessed."
        )
    else:
        status = "profiles_supplied_not_exercised"
        notes.append(
            "Access-profile metadata was supplied, but this non-destructive run does not "
            "log in, replay secrets or guess credentials; authenticated checks remain unverified."
        )
    if profiles:
        notes.append(
            f"{len(profiles)} access profile(s) recorded, {len(authenticated)} marked authenticated; "
            "secrets are never read from source or logged."
        )
    return AuthenticationCoverage(
        status=status,
        profiles_supplied=len(profiles),
        authenticated_profiles=len(authenticated),
        checks_completed=checks_completed,
        checks_unverified=checks_unverified,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Web observations
# ---------------------------------------------------------------------------


def build_observations(state: dict, origin: str) -> list[WebObservationRecord]:
    results = state.get("results", {})
    application_id = _app_id(origin)
    observations: list[WebObservationRecord] = []

    def obs(
        category: str,
        key: str,
        value: Any,
        tool: str,
        basis: ObservationBasis = ObservationBasis.CONFIGURATION,
        evidence_text: str | None = None,
    ) -> None:
        if value in (None, "", [], {}):
            return
        observations.append(
            WebObservationRecord(
                application_id=application_id,
                category=category,
                key=key,
                value=str(value),
                basis=basis,
                source_url=origin,
                collection_method=tool,
                evidence=[evidence_text] if evidence_text else [f"{tool}: {category}/{key}"],
                evidence_refs=[_prov_ref(tool)],
            )
        )

    http = results.get("http_posture", {}).get("data", {}) or {}
    if http:
        obs("http", "status", http.get("http_status"), "http_posture")
        obs("http", "response_class", http.get("response_class"), "http_posture")
        obs("http", "title", http.get("title"), "http_posture")
        obs("http", "redirect", http.get("redirect"), "http_posture")
        obs("http", "methods", http.get("methods"), "http_posture")
        obs("http", "server", (http.get("headers") or {}).get("server"), "http_posture")
        obs("http", "www_authenticate", http.get("www_authenticate"), "http_posture")
        if http.get("edge_indicators"):
            obs("edge", "indicators", ", ".join(http["edge_indicators"]), "http_posture")
        if http.get("body_snippet"):
            obs("http", "body_snippet", http["body_snippet"], "http_posture")
        status = http.get("http_status")
        if status in {401, 403}:
            obs("auth-boundary", "unauthenticated_access", f"restricted (HTTP {status})", "http_posture")
        elif status == 429:
            obs("auth-boundary", "unauthenticated_access", "rate limited (HTTP 429)", "http_posture")
        elif status:
            obs("auth-boundary", "unauthenticated_access", f"responded (HTTP {status})", "http_posture")
        for header in http.get("missing_headers") or []:
            obs("http-headers", f"missing:{header}", "absent", "http_posture")
        for header in http.get("present_headers") or []:
            obs("http-headers", f"present:{header}", "set", "http_posture")
        for cookie in http.get("cookies") or []:
            obs(
                "cookie",
                str(cookie.get("name") or "cookie"),
                f"secure={cookie.get('secure')} httponly={cookie.get('httponly')} samesite={cookie.get('samesite')}",
                "http_posture",
            )
        cors = http.get("cors") or {}
        if cors:
            obs("cors", "allow_origin", cors.get("allow_origin"), "http_posture")
            obs("cors", "credentials", cors.get("credentials"), "http_posture")
        for script in http.get("scripts") or []:
            obs("client-script", "src", script, "http_posture")
        if http.get("api_hints"):
            obs("client-script", "api_hints", ", ".join(http["api_hints"][:12]), "http_posture")
        if http.get("external_links"):
            obs("content", "external_links", http["external_links"], "http_posture")

    for tool in ("tls_posture", "tls_openssl"):
        data = results.get(tool, {}).get("data", {}) or {}
        if not data:
            continue
        obs("tls", "protocol", data.get("protocol"), tool)
        obs("tls", "cipher", data.get("cipher"), tool)
        obs("tls", "legacy_versions", data.get("legacy_versions"), tool)
        cert = data.get("certificate") or {}
        obs("tls", "certificate_subject", cert.get("subject_common_name"), tool)
        obs("tls", "certificate_issuer", cert.get("issuer_common_name"), tool)
        obs("tls", "certificate_not_after", cert.get("not_after"), tool)
        obs("tls", "certificate_self_signed", cert.get("self_signed"), tool)

    wafw = results.get("wafw00f", {}).get("data", {}) or {}
    if wafw:
        obs("waf", "firewall", wafw.get("firewall"), "wafw00f")
        obs("waf", "detected", wafw.get("detected"), "wafw00f")
    passive_waf = results.get("http_waf_detect", {}).get("data", {}) or {}
    if passive_waf.get("indicators"):
        obs("waf", "indicators", ", ".join(passive_waf["indicators"]), "http_waf_detect")

    content_result = results.get("web_content", {})
    content_data = content_result.get("data", {}) or {}
    content = content_data.get("found", {}) or {}
    if content_result.get("status") in {"ok", "partial"}:
        robots = content.get("/robots.txt") or {}
        if robots:
            obs("content", "robots_disallowed", len(robots.get("disallow") or []), "web_content")
            obs("content", "robots_sitemaps", len(robots.get("sitemaps") or []), "web_content")
        sitemap = content.get("/sitemap.xml") or {}
        if sitemap:
            obs("content", "sitemap_urls", len(sitemap.get("urls") or []), "web_content")
        obs("content", "security_txt_present", "/.well-known/security.txt" in content, "web_content")
        for path in content_data.get("missing") or []:
            obs("content", "missing_resource", path, "web_content")
        for path in content_data.get("inaccessible") or []:
            obs("content", "inaccessible_resource", path, "web_content")

    gobuster = results.get("gobuster_scan", {}).get("data", {}) or {}
    if gobuster:
        obs("content", "gobuster_attempted", gobuster.get("attempted"), "gobuster_scan")
        obs("content", "gobuster_untested", gobuster.get("untested"), "gobuster_scan")
        obs("content", "gobuster_zero_result_success", gobuster.get("zero_result_success"), "gobuster_scan")

    favicon = results.get("http_favicon", {}).get("data", {}) or {}
    if favicon.get("md5"):
        obs("content", "favicon_md5", favicon["md5"], "http_favicon")

    return observations


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def build_evidence(
    state: dict,
    inp: DiscoveryInput,
    origin: str,
    observed_at: datetime,
    endpoints: list[EndpointRecord],
) -> list[EvidenceRecord]:
    results = state.get("results", {})
    evidence_records: list[EvidenceRecord] = []

    for tool in state.get("executed", []):
        if tool not in _WEB_TOOLS:
            continue
        payload = results.get(tool, {})
        data = payload.get("data", {}) or {}
        status = data.get("http_status") or data.get("base_status")
        for index, item in enumerate(payload.get("evidence") or []):
            if len(evidence_records) >= _MAX_EVIDENCE:
                return evidence_records
            detail = str(item.get("detail") or "")
            raw = item.get("raw") or {}
            evidence_records.append(
                EvidenceRecord(
                    evidence_id=_evidence_id(tool, index),
                    type="tool-observation",
                    source_tool=tool,
                    target=str(raw.get("url") or data.get("url") or data.get("final_url") or origin),
                    status=str(raw.get("status") or status) if (raw.get("status") or status) else None,
                    snippet=detail[:400],
                    observed_at=observed_at,
                    confidence=(
                        ConfidenceLevel.MEDIUM
                        if isinstance(status, int) and 200 <= status < 400
                        else ConfidenceLevel.LOW
                    ),
                    verification_status=VerificationStatus.UNVERIFIED,
                    limitations=(
                        ["access-control/CDN response; origin application unconfirmed"]
                        if data.get("response_class") in {"auth_required", "forbidden", "rate_limited"}
                        or data.get("edge_likely")
                        else []
                    ),
                    evidence_refs=[_prov_ref(tool)],
                )
            )

    for endpoint in endpoints:
        if not endpoint.observed:
            continue
        if len(evidence_records) >= _MAX_EVIDENCE:
            break
        evidence_records.append(
            EvidenceRecord(
                evidence_id=f"ev:route:{len(evidence_records)}",
                type="route-observation",
                source_tool=endpoint.collection_method or "route",
                target=f"{origin}{endpoint.path}",
                status=str(endpoint.status) if endpoint.status is not None else None,
                snippet=f"{endpoint.method} {endpoint.path} classified as {endpoint.classification}",
                observed_at=observed_at,
                confidence=(
                    ConfidenceLevel.MEDIUM
                    if endpoint.classification in {"success", "redirect"}
                    else ConfidenceLevel.LOW
                ),
                verification_status=VerificationStatus.UNVERIFIED,
                limitations=endpoint.limitations,
                evidence_refs=endpoint.evidence_refs,
            )
        )
    return evidence_records


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def build_provenance(state: dict, inp: DiscoveryInput, origin: str, observed_at: datetime) -> list[WebObservationProvenance]:
    results = state.get("results", {})
    provenance: list[WebObservationProvenance] = []
    for name in state.get("executed", []):
        if name not in _WEB_TOOLS:
            continue
        result = results.get(name, {})
        if result.get("status") in {"skipped"}:
            continue
        try:
            version = get_spec(name).version
        except KeyError:  # pragma: no cover - defensive
            version = "unknown"
        provenance.append(
            WebObservationProvenance(
                observation_id=_prov_ref(name),
                source_tool=name,
                tool_version=version,
                runner_id=inp.network_context.runner_id,
                identity="external-probe",
                environment=inp.common.environment_kind,
                observed_at=observed_at,
                command=result.get("command"),
                evidence_refs=[f"ev:{name}:{i}" for i, _ in enumerate(result.get("evidence") or [])],
                source_url=origin,
            )
        )
    return provenance


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


def build_relationships(
    inp: DiscoveryInput,
    origin: str,
    endpoints: list[EndpointRecord],
) -> list[RelationshipProposal]:
    application_id = _app_id(origin)
    proposals: list[RelationshipProposal] = [
        RelationshipProposal(
            kind=RelationshipKind.OBSERVED,
            from_ref=application_id,
            to_ref=f"origin:{origin}",
            relation="app-on-origin",
            evidence_refs=[_prov_ref("http_posture")],
        )
    ]
    for endpoint in endpoints:
        proposals.append(
            RelationshipProposal(
                kind=RelationshipKind.OBSERVED if endpoint.observed else RelationshipKind.INFERRED,
                from_ref=endpoint.endpoint_id,
                to_ref=application_id,
                relation="route-in-app",
                evidence_refs=endpoint.evidence_refs,
            )
        )
        for form in endpoint.forms:
            proposals.append(
                RelationshipProposal(
                    kind=RelationshipKind.INFERRED,
                    from_ref=endpoint.endpoint_id,
                    to_ref=f"dataflow:{origin}{_clean_path(form.action)}",
                    relation="submits-data",
                    evidence_refs=endpoint.evidence_refs,
                )
            )
    for profile in inp.access_profiles:
        proposals.append(
            RelationshipProposal(
                kind=RelationshipKind.INFERRED,
                from_ref=application_id,
                to_ref=f"role:{profile.id}",
                relation="role-access",
                evidence_refs=[_prov_ref("http_posture")],
            )
        )
    return proposals


# ---------------------------------------------------------------------------
# Uncertainties / gaps
# ---------------------------------------------------------------------------


def _field(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def build_uncertainties(
    state: dict,
    inp: DiscoveryInput,
    origin: str,
    endpoints: list[EndpointRecord],
    tech_uncertainties: list[Uncertainty],
    route_coverage: RouteCoverage | None = None,
) -> list[Uncertainty]:
    results = state.get("results", {})
    application_id = _app_id(origin)
    uncertainties = list(tech_uncertainties)

    technologies = state.get("technologies")
    if technologies is None:
        raw = _raw_technologies(
            results.get("http_posture", {}).get("data", {}) or {},
            results.get("whatweb", {}).get("data", {}) or {},
            origin=origin,
            observed_at=datetime.now().astimezone(),
        )
        technologies, extra = normalize_technologies(raw, source_url=origin)
        uncertainties.extend(extra)
    versions = [item for item in technologies or [] if _field(item, "version")]
    if versions:
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=(
                    f"{len(versions)} technology version(s) are fingerprint/banner observations, "
                    "not authenticated package evidence"
                ),
                evidence_refs=[_prov_ref("http_posture")],
            )
        )

    declared = [e for e in endpoints if not e.observed]
    if declared:
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=(
                    f"{len(declared)} route(s) are declared (robots/sitemap/spec/client-script) but were "
                    "not requested; they are not confirmed to exist or be reachable"
                ),
                evidence_refs=[_prov_ref("web_content")],
            )
        )

    http = results.get("http_posture", {}).get("data", {}) or {}
    response_class = http.get("response_class")
    status = http.get("http_status")
    if response_class in {"auth_required", "forbidden", "rate_limited"}:
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=(
                    f"base URL returned HTTP {status} ({response_class}); the underlying application "
                    "response is unconfirmed and is not assumed to be a specific CDN/WAF vendor"
                ),
                evidence_refs=[_prov_ref("http_posture")],
            )
        )
    if http.get("edge_likely"):
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=(
                    "CDN/WAF indicators observed: "
                    + ", ".join(http.get("edge_indicators") or [])
                    + "; responses may reflect an edge page rather than the application"
                ),
                evidence_refs=[_prov_ref("http_posture")],
            )
        )
    if isinstance(status, int) and status >= 500:
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=f"base URL returned HTTP {status} (server/intermediary error); application behaviour is unconfirmed",
                evidence_refs=[_prov_ref("http_posture")],
            )
        )

    if not any(p.authenticated for p in inp.access_profiles):
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail=(
                    "no authenticated access profile was supplied; authenticated routes, role boundaries "
                    "and post-login data flows were not observed"
                ),
            )
        )

    for tool in ("whatweb", "web_content", "gobuster_scan", "wafw00f"):
        payload = results.get(tool, {})
        if payload.get("status") in {"unavailable", "failed", "partial"}:
            uncertainties.append(
                Uncertainty(
                    subject=application_id,
                    detail=f"{tool} did not complete cleanly: {payload.get('summary') or payload.get('error') or 'no data'}",
                    evidence_refs=[_prov_ref(tool)],
                )
            )

    if route_coverage is not None:
        auth_missing = not any(p.authenticated for p in inp.access_profiles)
        for limitation in route_coverage.coverage_limitations:
            # Those categories are already recorded above with their own
            # structured evidence; keep them in route_coverage but do not repeat
            # them as separate report limitations.
            if limitation.startswith("base URL returned") and response_class in {
                "auth_required",
                "forbidden",
                "rate_limited",
            }:
                continue
            if limitation.startswith("CDN/WAF indicators") and http.get("edge_likely"):
                continue
            if "no authenticated access profile" in limitation and auth_missing:
                continue
            uncertainties.append(
                Uncertainty(
                    subject=application_id,
                    detail=f"route coverage {route_coverage.coverage_status.value}: {limitation}",
                    evidence_refs=[_prov_ref("gobuster_scan")],
                )
            )

    observed = [e for e in endpoints if e.observed and e.path not in {"/", "/robots.txt", "/sitemap.xml"}]
    if not observed:
        uncertainties.append(
            Uncertainty(
                subject=application_id,
                detail="only the base/well-known paths were observed; route coverage is limited",
                evidence_refs=[_prov_ref("http_posture")],
            )
        )
    return uncertainties


def build_unassessed(
    state: dict,
    inp: DiscoveryInput,
    origin: str,
    endpoints: list[EndpointRecord],
) -> list[UnassessedTarget]:
    unassessed: list[UnassessedTarget] = []
    for endpoint in endpoints:
        if endpoint.observed:
            continue
        reason = (
            "declared in robots.txt but not fetched (non-destructive crawl limit)"
            if endpoint.api_operation == "robots-declared"
            else "declared but not requested; existence unconfirmed"
        )
        unassessed.append(
            UnassessedTarget(
                target=f"{origin}{endpoint.path}",
                reason=reason,
                category="unassessed-route",
            )
        )
    if not any(p.authenticated for p in inp.access_profiles):
        unassessed.append(
            UnassessedTarget(
                target=origin,
                reason="authenticated/role-protected surface not assessed (no access profile)",
                category="access",
            )
        )
    for tool in ("whatweb", "web_content", "gobuster_scan", "tls_posture"):
        payload = state.get("results", {}).get(tool, {})
        if payload.get("status") in {"unavailable", "failed"}:
            unassessed.append(
                UnassessedTarget(
                    target=origin,
                    reason=f"{tool}: {payload.get('summary') or 'did not complete'}",
                    category="tooling",
                )
            )
    for gap in state.get("coverage_gaps", []):
        unassessed.append(UnassessedTarget(target=origin, reason=gap, category="coverage"))
    return unassessed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_web_inventory(state: dict, inp: DiscoveryInput, observed_at: datetime) -> WebAssetInventory:
    origin = _base_origin(state, inp)
    applications, tech_uncertainties = build_applications(state, inp, origin, observed_at)
    endpoints = build_endpoints(state, inp, origin)
    route_coverage = build_route_coverage(state, inp, endpoints)
    return WebAssetInventory(
        applications=applications,
        endpoints=endpoints,
        web_observations=build_observations(state, origin),
        evidence=build_evidence(state, inp, origin, observed_at, endpoints),
        route_coverage=route_coverage,
        authentication_coverage=build_authentication_coverage(state, inp),
        relationship_proposals=build_relationships(inp, origin, endpoints),
        observation_provenance=build_provenance(state, inp, origin, observed_at),
        uncertainties=build_uncertainties(
            state, inp, origin, endpoints, tech_uncertainties, route_coverage
        ),
        unassessed_targets=build_unassessed(state, inp, origin, endpoints),
    )
