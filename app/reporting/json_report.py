"""Machine-readable final report.

The JSON report is the primary downloadable artifact. It carries the
standardised Discovery sections (metadata, scope, assets, services,
technologies, observations, routes, evidence, tool results, authentication and
route coverage, uncertainties, errors, overall status) plus the legacy
``findings``/``web_inventory`` keys so existing consumers keep working.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.config import settings

_SUCCESS = {"ok"}
_NEUTRAL = {"skipped"}

_STATUS_MAP = {
    "ok": "success",
    "partial": "partial",
    "failed": "failed",
    "unavailable": "unavailable",
    "skipped": "skipped",
}


def build_json_report(result: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-serialisable report from a completed assessment state."""
    generated_at = datetime.now(timezone.utc)
    web = result.get("web_inventory") or {}
    inventory = result.get("inventory") or {}
    inp = result.get("discovery_input") or {}
    common = inp.get("common") or {}
    scope_ref = common.get("scope_ref") or {}
    network_context = inp.get("network_context") or {}

    applications = web.get("applications") or []
    endpoints = web.get("endpoints") or []
    observations = web.get("web_observations") or []
    evidence = web.get("evidence") or []
    route_coverage = web.get("route_coverage") or {}
    authentication_coverage = web.get("authentication_coverage") or {}
    uncertainties = list(inventory.get("uncertainties") or []) + list(web.get("uncertainties") or [])
    technologies = _technologies(applications)
    tool_results = _tool_results(result)
    overall_status = _overall_status(result, web, tool_results)
    findings = result.get("findings") or []
    services = inventory.get("services") or result.get("services") or []

    target = result.get("base_url") or result.get("target")
    payload = {
        "report": {
            "tool": settings.app_name,
            "version": settings.version,
            "generated_at": generated_at.isoformat(timespec="seconds"),
            "target": target,
            "scan_id": result.get("scan_id"),
            "profile": result.get("profile", "safe"),
            "status": result.get("status"),
            "kind": "json",
        },
        "summary": {
            "findings": len(findings),
            "open_services": len(services),
            "web_applications": len(applications),
            "web_endpoints": len(endpoints),
            "web_observations": len(observations),
            "evidence_records": len(evidence),
            "coverage_gaps": len(result.get("coverage_gaps") or []),
            "overall_status": overall_status,
        },
        "scan_metadata": {
            "tool": settings.app_name,
            "version": settings.version,
            "generated_at": generated_at.isoformat(timespec="seconds"),
            "scan_id": result.get("scan_id"),
            "target": target,
            "profile": result.get("profile", "safe"),
            "objective": common.get("objective"),
            "environment_kind": common.get("environment_kind"),
            "runner_id": network_context.get("runner_id"),
            "status": result.get("status"),
            "overall_status": overall_status,
        },
        "scope_validation": {
            "authorized": bool(result.get("consent")) and "read-only" in (scope_ref.get("permitted_effects") or []),
            "consent": bool(result.get("consent")),
            "targets": scope_ref.get("targets") or result.get("target_seeds") or [],
            "permitted_effects": scope_ref.get("permitted_effects") or [],
            "discovery_limits": inp.get("discovery_limits") or {},
            "block_gate": result.get("block_gate"),
        },
        "assets": inventory.get("assets") or [],
        "services": services,
        "technologies": technologies,
        "web_observations": observations,
        "routes": endpoints,
        "evidence": evidence,
        "tool_results": tool_results,
        "authentication_coverage": authentication_coverage,
        "route_coverage": route_coverage,
        "uncertainties": uncertainties,
        "errors": list(result.get("errors") or []),
        "overall_status": overall_status,
        # --- backward-compatible keys (existing UI/consumers) -----------------
        "findings": findings,
        "web_inventory": result.get("web_inventory"),
        "inventory": result.get("inventory"),
        "coverage_gaps": result.get("coverage_gaps") or [],
        "events": result.get("events") or [],
        "agent_result": result.get("agent_result"),
    }
    return payload


def _technologies(applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str | None]] = set()
    records: list[dict[str, Any]] = []
    for application in applications:
        for technology in application.get("technologies") or []:
            key = (str(technology.get("name", "")).lower(), technology.get("version"))
            if key in seen:
                continue
            seen.add(key)
            records.append(technology)
    return records


def _tool_results(result: dict[str, Any]) -> list[dict[str, Any]]:
    results = result.get("results") or {}
    executed = list(result.get("executed") or [])
    planned = list(result.get("tool_plan") or [])
    entries: list[dict[str, Any]] = []
    for tool in executed:
        payload = results.get(tool) or {}
        data = payload.get("data") or {}
        raw_status = payload.get("status") or "unknown"
        entries.append(
            {
                "tool": tool,
                "status": _STATUS_MAP.get(raw_status, "unknown"),
                "raw_status": raw_status,
                "summary": payload.get("summary") or "",
                "error": payload.get("error"),
                "command": payload.get("command"),
                "duration_ms": payload.get("duration_ms"),
                "attempts": data.get("attempts"),
                "retries": data.get("retries"),
                "retry_reasons": data.get("retry_reasons") or [],
                "response_class": data.get("response_class") or data.get("base_response_class"),
                "status_code": data.get("http_status") or data.get("base_status"),
                "timed_out": data.get("timed_out", False),
                "returncode": data.get("returncode"),
                "limitations": _tool_limitations(payload),
            }
        )
    for tool in planned:
        if tool in executed:
            continue
        entries.append(
            {
                "tool": tool,
                "status": "not_run",
                "raw_status": "not_run",
                "summary": "Planned but not executed (limit reached or prerequisites changed).",
                "error": None,
                "command": None,
                "duration_ms": None,
                "attempts": None,
                "retries": None,
                "retry_reasons": [],
                "response_class": None,
                "status_code": None,
                "timed_out": False,
                "returncode": None,
                "limitations": [],
            }
        )
    return entries


def _tool_limitations(payload: dict[str, Any]) -> list[str]:
    data = payload.get("data") or {}
    limitations: list[str] = []
    if data.get("response_class") in {"auth_required", "forbidden", "rate_limited"}:
        limitations.append("access-control/rate-limit response; origin application unconfirmed")
    if data.get("edge_likely"):
        limitations.append("CDN/WAF indicators observed")
    if data.get("timed_out"):
        limitations.append("tool timed out; partial results only")
    if data.get("suspicious_uniform"):
        limitations.append("uniform access-control/CDN responses; not confirmed as routes")
    if data.get("zero_result_success"):
        limitations.append("zero results do not prove absence of content")
    if payload.get("status") == "partial":
        limitations.append(payload.get("summary") or "partial result")
    return limitations


def _overall_status(
    result: dict[str, Any],
    web: dict[str, Any],
    tool_results: list[dict[str, Any]],
) -> str:
    if result.get("status") == "blocked":
        return "blocked"
    agent_status = ((result.get("agent_result") or {}).get("output") or {}).get("status")
    if agent_status == "BLOCKED":
        return "blocked"
    if not tool_results:
        return "failed"

    statuses = {entry["status"] for entry in tool_results}
    if statuses <= {"failed", "unavailable", "skipped", "not_run"}:
        return "failed"

    http = (result.get("results") or {}).get("http_posture", {}).get("data") or {}
    response_class = http.get("response_class")
    coverage_status = (web.get("route_coverage") or {}).get("coverage_status")

    if response_class in {"auth_required", "forbidden", "rate_limited"}:
        return "inconclusive"
    if http.get("edge_likely") and response_class not in {"success", "redirect"}:
        return "inconclusive"
    if coverage_status == "unknown" and web:
        return "inconclusive"
    if statuses & {"failed", "unavailable", "partial"} or coverage_status in {"limited", "partial"}:
        return "partial"
    if result.get("errors") or result.get("coverage_gaps"):
        return "partial"
    return "success"
