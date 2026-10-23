"""Workflow nodes: guard -> plan -> collect -> adapt -> validate.

The agent plans a tool set, executes it, then *adapts* based on what it
observed (e.g. discovering port 443 triggers a TLS probe; discovered services
trigger banner grabs) before validating the evidence into findings.
"""

from __future__ import annotations

from typing import Any

from app.agents.state import AssessmentState, new_state
from app.knowledge import retrieve
from app.llm import reasoning
from app.models.schemas import Confidence, EvidenceItem, Finding, Severity, ToolStatus
from app.safety.authorization import authorize
from app.tools.base import ToolContext, ToolResult
from app.tools.registry import alternatives, capabilities, get as get_spec, is_available, specs_for_profile

MAX_ADAPT_ITERATIONS = 3
MAX_TOOLS_PER_RUN = 40

_ADMIN_PORTS = {22, 23, 3389, 5900, 512, 513, 514}
_DATASTORE_PORTS = {3306, 5432, 6379, 27017, 11211, 9200, 9300, 9042, 1433, 1521}


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


def guard_node(state: AssessmentState) -> dict:
    consent = bool(state.get("consent", False))
    seeds = state.get("target_seeds") or ([state["target"]] if state.get("target") else [])

    if not seeds:
        return {
            "status": "blocked",
            "block_gate": "INPUT",
            "errors": ["No target seed supplied; a target seed is required to run Discovery."],
            "events": ["Guard blocked: missing required input (target_seeds)."],
        }

    decision = authorize(seeds[0], consent)
    if not decision.ok or decision.target is None:
        return {
            "status": "blocked",
            "block_gate": "AUTHORIZATION",
            "errors": [decision.error or "Authorization blocked."],
            "events": ["Authorization guard blocked the assessment."],
        }
    target = decision.target
    return {
        "host": target.host,
        "base_url": target.base_url,
        "scheme": target.scheme,
        "status": "running",
        "events": [f"Authorization acknowledged. Target accepted: {target.base_url}"],
    }


def route_after_guard(state: AssessmentState) -> str:
    return "end" if state.get("status") == "blocked" else "plan"


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def _context(state: AssessmentState, profile: str) -> ToolContext:
    from app.safety.authorization import normalize_target

    target = normalize_target(state.get("target", ""))
    options: dict[str, Any] = {
        "profile": profile,
        "services": state.get("services", []),
        "aggressive": profile in {"network", "full"},
    }
    return ToolContext(target=target, scan_id=state.get("scan_id", ""), options=options)


def _best_per_capability(specs: list) -> list[str]:
    """Highest-priority tool of each capability, in registry order.

    Non-chosen tools of a capability remain as automatic fallbacks at execution
    time (see :func:`collect_node`).
    """
    best: dict[str, Any] = {}
    for spec in specs:
        current = best.get(spec.capability)
        if current is None or (spec.priority, spec.order, spec.name) < (
            current.priority,
            current.order,
            current.name,
        ):
            best[spec.capability] = spec
    return [spec.name for spec in sorted(best.values(), key=lambda s: (s.order, s.name))]


def plan_node(state: AssessmentState) -> dict:
    """Select the tools to run for the profile.

    An optional LLM planner may choose among the eligible (registered, profile
    appropriate, currently-available) tools; its proposal is validated against
    that allow-list. Without an LLM the deterministic best-per-capability plan
    is used, so behaviour is unchanged when the API is not configured.
    """
    profile = state.get("profile", "safe")
    ctx = _context(state, profile)
    eligible = [spec for spec in specs_for_profile(profile) if is_available(spec, ctx)]
    allowed = [spec.name for spec in sorted(eligible, key=lambda s: (s.order, s.name))]
    deterministic = _best_per_capability(eligible)

    discovery_input = state.get("discovery_input") or {}
    objective = (discovery_input.get("common") or {}).get(
        "objective", "Build a sourced inventory of the authorized target."
    )
    questions = discovery_input.get("discovery_questions") or []

    planned_llm, source = reasoning.propose_tool_plan(
        objective=objective,
        target=state.get("target", ""),
        profile=profile,
        allowed=allowed,
        deterministic=deterministic,
        discovery_questions=questions,
    )

    if source == "llm":
        # The LLM may add tools, but it can never drop the deterministic baseline
        # (the best tool per capability), so no capability is silently lost.
        keep = set(planned_llm) | set(deterministic)
        planned = [name for name in allowed if name in keep]
    else:
        planned = planned_llm

    author = "LLM planner" if source == "llm" else "Deterministic planner"
    return {
        "tool_plan": planned,
        "executed": [],
        "iterations": 0,
        "events": [f"{author} selected the '{profile}' profile: {', '.join(planned) or 'no tools'}."],
    }


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------


def _merge_services(existing: list[dict], new_ports: list[dict], source: str) -> list[dict]:
    merged = {f"{s.get('port')}/{s.get('protocol', 'tcp')}": dict(s) for s in existing}
    for port in new_ports:
        try:
            key = f"{int(port.get('port'))}/{port.get('protocol', 'tcp')}"
        except (TypeError, ValueError):
            continue
        record = merged.get(key, {})
        # Prefer records that carry product/version detail.
        for field in ("service", "product", "version"):
            if port.get(field) and not record.get(field):
                record[field] = port[field]
        record.setdefault("port", port.get("port"))
        record.setdefault("protocol", port.get("protocol", "tcp"))
        record.setdefault("service", port.get("service", "unknown"))
        record["source"] = record.get("source") or source
        merged[key] = record
    return sorted(merged.values(), key=lambda r: int(r.get("port", 0)))


def _merge_banner_versions(services: list[dict], banners: dict[str, str]) -> list[dict]:
    """Fill missing product/version on services from advertised banners."""
    from app.agents.inventory import _parse_banner

    updated: list[dict] = []
    for service in services:
        record = dict(service)
        if not record.get("product") or not record.get("version"):
            key = f"{record.get('port')}/{record.get('protocol', 'tcp')}"
            banner = banners.get(str(record.get("port"))) or banners.get(key)
            product, version = _parse_banner(banner)
            record["product"] = record.get("product") or product
            record["version"] = record.get("version") or version
        updated.append(record)
    return updated


_FALLBACK_TRIGGERS = {ToolStatus.FAILED.value, ToolStatus.UNAVAILABLE.value}


def collect_node(state: AssessmentState) -> dict:
    profile = state.get("profile", "safe")
    executed = list(state.get("executed", []))
    executed_set = set(executed)
    results = dict(state.get("results", {}))
    services = list(state.get("services", []))
    errors: list[str] = []
    events: list[str] = []
    queue = [name for name in state.get("tool_plan", []) if name not in executed_set]

    while queue:
        name = queue.pop(0)
        if name in executed_set or len(results) >= MAX_TOOLS_PER_RUN:
            continue
        ctx = _context({**state, "services": services}, profile)
        try:
            spec = get_spec(name)
        except KeyError:
            events.append(f"Unknown tool {name}; skipped.")
            executed.append(name)
            executed_set.add(name)
            continue
        try:
            if not is_available(spec, ctx):
                events.append(f"Skipped {name}: prerequisites not met.")
                results[name] = ToolResult(
                    tool=name, status=ToolStatus.SKIPPED.value, summary="Prerequisites not met."
                ).to_dict()
                executed.append(name)
                executed_set.add(name)
                continue
            result = spec.function(ctx)
            payload = result.to_dict()
        except Exception as exc:  # a tool error must never abort the run
            payload = ToolResult(
                tool=name, status=ToolStatus.FAILED.value, summary="Tool raised an exception.",
                error=f"{type(exc).__name__}: {exc}",
            ).to_dict()

        results[name] = payload
        executed.append(name)
        executed_set.add(name)
        events.append(f"{name}: {payload['status']} · {payload.get('summary', '')}")
        if payload.get("error"):
            errors.append(f"{name}: {payload['error']}")
        if payload.get("data", {}).get("ports"):
            services = _merge_services(services, payload["data"]["ports"], name)
        if payload.get("data", {}).get("banners"):
            services = _merge_banner_versions(services, payload["data"]["banners"])

        # Redundancy: if this tool failed or is unavailable, try an alternative
        # tool that performs the same capability (or an explicit fallback).
        if payload.get("status") in _FALLBACK_TRIGGERS:
            alt_ctx = _context({**state, "services": services}, profile)
            for alt in alternatives(spec, alt_ctx, exclude=executed_set | set(queue)):
                queue.append(alt.name)
                events.append(
                    f"Fallback: {name} was {payload['status']}; trying {alt.name} instead."
                )
                break

    return {"results": results, "executed": executed, "services": services, "events": events, "errors": errors}


# ---------------------------------------------------------------------------
# Adapt
# ---------------------------------------------------------------------------


def adapt_node(state: AssessmentState) -> dict:
    """Add follow-up tools justified by the observations collected so far.

    Follow-ups are requested by *capability* so the best available tool for the
    job is chosen (with the other same-capability tools kept as automatic
    fallbacks at execution time).
    """
    profile = state.get("profile", "safe")
    executed = set(state.get("executed", []))
    plan = list(state.get("tool_plan", []))
    iterations = state.get("iterations", 0) + 1
    results = state.get("results", {})
    services = state.get("services", [])
    events: list[str] = []
    ctx = _context({**state, "services": services}, profile)
    allowed = {spec.name for spec in specs_for_profile(profile)}

    def add(tool_name: str, reason: str) -> None:
        if tool_name not in plan and tool_name not in executed:
            plan.append(tool_name)
            events.append(f"Adaptive step: {tool_name} ({reason}).")

    def add_capability(capability: str, reason: str) -> None:
        for spec in capabilities().get(capability, []):
            if spec.name in executed or spec.name in plan or spec.name not in allowed:
                continue
            if not is_available(spec, ctx):
                continue
            add(spec.name, reason)
            return

    ports = {int(s.get("port", 0)) for s in services}
    http = results.get("http_posture", {})
    http_ok = http.get("status") == ToolStatus.OK.value
    hostname = not ctx.target.is_ip

    if iterations <= MAX_ADAPT_ITERATIONS:
        if services:
            add_capability("service_banner", "open services discovered")
            add_capability("advisory", "map discovered products/versions to advisories")
        if (443 in ports or state.get("scheme") == "https") and "tls_posture" not in executed:
            add_capability("tls_info", "a TLS endpoint is present")
        if hostname and profile in {"web", "network", "full"}:
            add_capability("dns_enum", "domain target present")
        if hostname and profile in {"web", "full"}:
            add_capability("osint", "domain target present")
        if hostname and profile in {"network", "full"}:
            add_capability("subdomain", "domain target present")
        if http_ok and profile in {"web", "full"}:
            add_capability("web_content", "HTTP service responded")
            add_capability("http_fingerprint", "HTTP service responded")
            add_capability("http_waf_detect", "HTTP service responded")
        if profile in {"network", "full"}:
            for capability, trigger in (
                ("ssh_info", 22),
                ("smtp_info", 25),
                ("ftp_info", 21),
                ("smb_info", 445),
                ("redis_info", 6379),
                ("mysql_info", 3306),
            ):
                if trigger in ports:
                    add_capability(capability, f"service on port {trigger} discovered")

    plan = [name for name in plan if name in allowed and is_available(get_spec(name), ctx)]

    if not events:
        events.append("Adaptive review complete: no further tools were required.")
    return {"tool_plan": plan, "iterations": iterations, "events": events}


def route_after_adapt(state: AssessmentState) -> str:
    pending = set(state.get("tool_plan", [])) - set(state.get("executed", []))
    return "collect" if pending else "validate"


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


def _finding(
    idx: int,
    *,
    title: str,
    category: str,
    severity: Severity,
    confidence: Confidence,
    source_tool: str,
    source: str,
    detail: str,
    asset: str | None,
    remediation: str,
    query: str,
    raw: dict | None = None,
) -> Finding:
    return Finding(
        id=f"F-{idx:02d}",
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        asset=asset,
        evidence=EvidenceItem(source=source, detail=detail, raw=raw or {}),
        remediation=remediation,
        query=query,
        references=retrieve(query),
        source_tool=source_tool,
    )


def validate_node(state: AssessmentState) -> dict:
    results = state.get("results", {})
    asset = state.get("base_url") or state.get("host") or state.get("target")
    findings: list[Finding] = []
    gaps: list[str] = []

    def add(**kwargs) -> None:
        findings.append(_finding(len(findings) + 1, asset=asset, **kwargs))

    # -- HTTP posture ------------------------------------------------------
    http = results.get("http_posture", {})
    if http.get("status") == ToolStatus.OK.value:
        data = http.get("data", {})
        status = data.get("http_status", 0)
        response_class = data.get("response_class") or "unknown"
        limited = response_class not in {"success", "redirect"}
        for header in data.get("missing_headers", []):
            add(
                title=(f"Header posture observation: {header} absent" if limited else f"Missing security header: {header}"),
                category="Security misconfiguration",
                severity=Severity.INFORMATIONAL if limited else Severity.LOW,
                confidence=Confidence.NEEDS_VALIDATION if limited else Confidence.CONFIRMED,
                source_tool="http_posture",
                source="http_posture",
                detail=(
                    f"HTTP {status} ({response_class}) response from {data.get('url')} did not include {header}."
                    + (
                        " The response is classified as limited (access-control/CDN or error); the origin "
                        "application response is unconfirmed, so validate on an application response."
                        if limited
                        else ""
                    )
                ),
                remediation=f"Configure {header} per the application security policy (CWE-693 / OWASP A05:2021).",
                query=f"missing {header} security header",
                raw={"http_status": status, "response_class": response_class},
            )
        for cookie in data.get("cookies", []):
            problems = []
            if not cookie.get("secure"):
                problems.append("Secure")
            if not cookie.get("httponly"):
                problems.append("HttpOnly")
            if problems:
                add(
                    title=f"Cookie '{cookie.get('name')}' missing flags: {', '.join(problems)}",
                    category="Session management",
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    source_tool="http_posture",
                    source="http_posture",
                    detail=f"Set-Cookie for '{cookie.get('name')}' lacks {', '.join(problems)} (SameSite={cookie.get('samesite')}).",
                    remediation="Set Secure, HttpOnly and an appropriate SameSite attribute on sensitive cookies.",
                    query="cookie missing secure httponly flags",
                    raw=cookie,
                )
        cors = data.get("cors")
        if cors and cors.get("allow_origin") in {"*", "https://sentinel.invalid"}:
            add(
                title="Permissive CORS policy observed",
                category="Access control",
                severity=Severity.MEDIUM if cors.get("credentials") else Severity.LOW,
                confidence=Confidence.POTENTIAL,
                source_tool="http_posture",
                source="http_posture",
                detail=f"Access-Control-Allow-Origin reflected: {cors.get('allow_origin')} (credentials: {cors.get('credentials')}).",
                remediation="Restrict CORS to trusted origins; never combine a wildcard origin with credentials.",
                query="permissive CORS access-control-allow-origin",
                raw=cors,
            )
        methods = (data.get("methods") or "").upper()
        risky = [m for m in ("TRACE", "PUT", "DELETE") if m in methods]
        if risky:
            add(
                title=f"Potentially risky HTTP method(s) advertised: {', '.join(risky)}",
                category="Security misconfiguration",
                severity=Severity.LOW,
                confidence=Confidence.OBSERVED,
                source_tool="http_posture",
                source="http_posture",
                detail=f"OPTIONS advertised: {methods}",
                remediation="Disable unnecessary HTTP methods at the server/proxy layer.",
                query="risky HTTP methods OPTIONS",
                raw={"methods": methods},
            )
        for hint in data.get("technology", []):
            add(
                title="Technology fingerprint disclosed",
                category="Information disclosure",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.OBSERVED,
                source_tool="http_posture",
                source="http_posture",
                detail=f"Observed: {hint}",
                remediation="Remove unnecessary version/product disclosure where feasible (CWE-200).",
                query="exposed server information header",
                raw={"hint": hint},
            )
    elif http.get("status") in {ToolStatus.FAILED.value, ToolStatus.UNAVAILABLE.value}:
        gaps.append("HTTP posture was unavailable; no application-layer conclusion is made.")

    # -- TLS posture -------------------------------------------------------
    tls = results.get("tls_posture", {})
    if tls.get("status") == ToolStatus.OK.value:
        data = tls.get("data", {})
        for version in data.get("legacy_versions", []):
            add(
                title=f"Legacy TLS protocol enabled ({version})",
                category="Transport security",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                source_tool="tls_posture",
                source="tls_posture",
                detail=f"Handshake negotiated {version} on port {data.get('port')}.",
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2+ with modern ciphers (CWE-326).",
                query="TLS configuration legacy protocol",
                raw={"version": version},
            )
        cert = data.get("certificate") or {}
        if cert.get("self_signed"):
            add(
                title="Self-signed certificate presented",
                category="Transport security",
                severity=Severity.MEDIUM,
                confidence=Confidence.OBSERVED,
                source_tool="tls_posture",
                source="tls_posture",
                detail=f"Subject equals issuer ({cert.get('subject_common_name')}).",
                remediation="Use a certificate from a trusted CA for public endpoints.",
                query="self signed certificate TLS",
                raw={"cn": cert.get("subject_common_name")},
            )
        days = cert.get("days_until_expiry")
        if isinstance(days, int) and days < 0:
            add(
                title="TLS certificate is expired",
                category="Transport security",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                source_tool="tls_posture",
                source="tls_posture",
                detail=f"Certificate expired {abs(days)} day(s) ago (notAfter={cert.get('not_after')}).",
                remediation="Renew and deploy a valid certificate; automate renewal and monitoring.",
                query="expired TLS certificate",
            )
        elif isinstance(days, int) and days <= 30:
            add(
                title=f"TLS certificate expires soon ({days} day(s))",
                category="Transport security",
                severity=Severity.LOW,
                confidence=Confidence.OBSERVED,
                source_tool="tls_posture",
                source="tls_posture",
                detail=f"notAfter={cert.get('not_after')}",
                remediation="Renew the certificate before expiry and verify automated renewal.",
                query="TLS certificate expiry",
            )
    elif tls.get("status") == ToolStatus.UNAVAILABLE.value:
        gaps.append("No TLS endpoint was reachable; no TLS conclusion is made.")

    # -- Open services -----------------------------------------------------
    for service in state.get("services", []):
        port = int(service.get("port", 0))
        name = service.get("service", "unknown")
        if port in _ADMIN_PORTS:
            add(
                title=f"Remote administration service exposed ({name}/{port})",
                category="Exposure",
                severity=Severity.MEDIUM,
                confidence=Confidence.POTENTIAL,
                source_tool="network",
                source="service discovery",
                detail=f"Open TCP/{port} ({name}); product: {service.get('product') or 'not identified'}.",
                remediation="Confirm business need; restrict by network policy, require MFA and monitor access.",
                query="exposed remote administration service ssh rdp",
                raw=service,
            )
        if port in _DATASTORE_PORTS:
            add(
                title=f"Data store port reachable ({name}/{port})",
                category="Exposure",
                severity=Severity.HIGH,
                confidence=Confidence.POTENTIAL,
                source_tool="network",
                source="service discovery",
                detail=f"Open TCP/{port} ({name}) observed from the assessment runner.",
                remediation="Confirm reachability is intentional; bind data stores to private interfaces and require authentication.",
                query="exposed database redis mongodb elasticsearch",
                raw=service,
            )

    # -- DNS ---------------------------------------------------------------
    dns = results.get("dns_recon", {})
    if dns.get("status") == ToolStatus.OK.value:
        txt = " ".join((dns.get("data", {}).get("records", {}).get("TXT") or []))
        if txt and "v=spf1" not in txt.lower():
            add(
                title="No SPF record observed in DNS TXT data",
                category="Email security",
                severity=Severity.LOW,
                confidence=Confidence.POTENTIAL,
                source_tool="dns_recon",
                source="dns_recon",
                detail=f"TXT records observed: {txt[:160]}",
                remediation="Publish an SPF record limiting authorized senders; add DKIM and DMARC.",
                query="missing SPF email authentication DNS",
            )
    if dns.get("status") == ToolStatus.PARTIAL.value:
        gaps.append("DNS enumeration returned no records; email/DNS coverage is unconfirmed.")

    # -- Web content -------------------------------------------------------
    content = results.get("web_content", {})
    if content.get("status") == ToolStatus.OK.value:
        found = content.get("data", {}).get("found", {})
        disallow = found.get("/robots.txt", {}).get("disallow", [])
        if disallow:
            add(
                title="robots.txt discloses interesting paths",
                category="Information disclosure",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.OBSERVED,
                source_tool="web_content",
                source="web_content",
                detail=f"Disallowed paths include: {', '.join(disallow[:12])}",
                remediation="Ensure robots.txt does not reveal sensitive areas; protect them with authorization, not obscurity.",
                query="robots.txt sensitive paths disclosure",
                raw={"disallow": disallow[:12]},
            )
        if "/.well-known/security.txt" not in found:
            add(
                title="No security.txt published",
                category="Governance",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.OBSERVED,
                source_tool="web_content",
                source="web_content",
                detail="/.well-known/security.txt was not retrievable.",
                remediation="Publish a security.txt describing how to report vulnerabilities.",
                query="publish security.txt vulnerability disclosure",
            )

    gaps.extend(
        f"{name}: {results[name].get('summary')}"
        for name in _incomplete_tools(results)
    )

    view = [f.to_view() for f in findings]
    return {
        "findings": view,
        "status": "completed",
        "coverage_gaps": gaps,
        "events": [f"Evidence validator retained {len(findings)} finding(s) and {len(gaps)} coverage gap(s)."],
    }


def _incomplete_tools(results: dict[str, dict]) -> list[str]:
    """Names of core tools that did not produce a clean, complete observation."""
    bad = {ToolStatus.FAILED.value, ToolStatus.UNAVAILABLE.value, ToolStatus.PARTIAL.value}
    core = {"nmap_discovery", "tcp_scan", "http_posture", "tls_posture", "dns_recon"}
    return [name for name, payload in results.items() if payload.get("status") in bad and name in core]


# ---------------------------------------------------------------------------
# Normalize: raw fingerprints -> validated technology/evidence observations
# ---------------------------------------------------------------------------


def normalize_node(state: AssessmentState) -> dict:
    """Normalise raw fingerprints and classify the transport outcome.

    This node never upgrades an HTML/JS/banner/header value to a verified
    version: rejected candidates (IPs, country names, MIME types, header
    directives) are retained as evidence plus an explicit uncertainty.
    """
    from datetime import datetime, timezone

    from app.agents.technologies import normalize_technologies
    from app.agents.web_inventory import _raw_technologies

    results = state.get("results", {})
    origin = state.get("base_url") or state.get("target") or ""
    observed_at = datetime.now(timezone.utc)
    raw = _raw_technologies(
        results.get("http_posture", {}).get("data", {}) or {},
        results.get("whatweb", {}).get("data", {}) or {},
        origin=origin,
        observed_at=observed_at,
    )
    technologies, uncertainties = normalize_technologies(
        raw, observed_at=observed_at, source_url=origin
    )

    response_classes = sorted(
        {
            payload.get("data", {}).get("response_class")
            for payload in results.values()
            if payload.get("data", {}).get("response_class")
        }
    )
    return {
        "technologies": [item.model_dump(mode="json") for item in technologies],
        "technology_uncertainties": [item.model_dump(mode="json") for item in uncertainties],
        "events": [
            f"Normalized {len(technologies)} technology observation(s); "
            f"{len(uncertainties)} uncertainty note(s). "
            f"HTTP classes: {', '.join(response_classes) or 'none'}."
        ],
    }


# ---------------------------------------------------------------------------
# Project: state -> SentinelX Discovery contract result
# ---------------------------------------------------------------------------


def project_node(state: AssessmentState) -> dict:
    """Convert the collected observations into the contract-shaped result.

    Runs after ``validate`` so coverage gaps are known. The internal ``status``
    (``completed``/``blocked``) is preserved for the dashboard; the contract
    status lives in ``agent_result.output.status``.
    """
    from datetime import datetime, timezone

    from app.agents.inventory import build_common_output, build_inventory
    from app.agents.web_inventory import build_web_inventory
    from app.contracts.common import RuntimeBinding
    from app.contracts.discovery import DiscoveryInput, DiscoveryResult

    raw_input = state.get("discovery_input") or {}
    if raw_input:
        inp = DiscoveryInput.model_validate(raw_input)
    else:  # pragma: no cover - only when called without a contract input
        from app.contracts import default_discovery_input

        inp = default_discovery_input(state.get("target", ""), consent=bool(state.get("consent")))

    observed_at = datetime.now(timezone.utc)
    inventory = build_inventory(state, inp, observed_at)
    # Network-only scans do not produce a Web inventory (surface separation).
    web_inventory = None
    if state.get("profile", "safe") != "network":
        web_inventory = build_web_inventory(state, inp, observed_at)
    web_uncertainties = web_inventory.uncertainties if web_inventory else []
    web_unassessed = web_inventory.unassessed_targets if web_inventory else []
    output = build_common_output(
        state,
        inp,
        services=inventory.services,
        uncertainties=inventory.uncertainties + web_uncertainties,
        unassessed=inventory.unassessed_targets + web_unassessed,
        provenance=inventory.observation_provenance,
    )
    runtime = RuntimeBinding(
        workspace_id=inp.common.workspace_id,
        run_id=inp.common.run_id,
        environment_id=inp.common.environment_id,
    )
    result = DiscoveryResult(runtime=runtime, output=output, inventory=inventory, web_inventory=web_inventory)
    events = [f"Discovery contract result: {output.status.value}."]
    if web_inventory is not None:
        events.append(
            f"Web inventory: {len(web_inventory.applications)} application(s), "
            f"{len(web_inventory.endpoints)} route(s), "
            f"{len(web_inventory.web_observations)} observation(s)."
        )
    return {
        "inventory": inventory.model_dump(mode="json"),
        "web_inventory": web_inventory.model_dump(mode="json") if web_inventory else None,
        "agent_result": result.model_dump(mode="json"),
        "events": events,
    }


__all__ = [
    "guard_node",
    "route_after_guard",
    "plan_node",
    "collect_node",
    "adapt_node",
    "route_after_adapt",
    "validate_node",
    "normalize_node",
    "project_node",
    "new_state",
]
