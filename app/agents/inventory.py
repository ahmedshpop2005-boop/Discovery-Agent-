"""Projection from internal workflow state to the Discovery contract.

The tools produce raw observation dicts; this module turns them into the
strict ``AssetInventory`` plus the common output, so the result conforms to the
SentinelX shared agent contract (owner: Shaaban).

Design rules honoured here:

* Every observation links to its source tool, runner, tool version and time.
* A version string is recorded as a ``banner`` observation, never as
  authenticated package evidence.
* Authenticated and unauthenticated observations are kept separate.
* Failures and unsupported checks become explicit gaps; an unreachable host is
  never reported as clean.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.contracts.discovery import (
    Asset,
    AssetInventory,
    HostObservation,
    ObservationProvenance,
    RelationshipProposal,
    ServiceRecord,
    Uncertainty,
    UnassessedTarget,
)
from app.contracts.enums import (
    AgentStatus,
    ObservationBasis,
    Reachability,
    RelationshipKind,
    RequiredGate,
)
from app.contracts.common import CommonOutput, ProposedAction
from app.contracts.discovery import DiscoveryInput
from app.tools.registry import get as get_spec

# Tools whose output is a raw key=value observation rather than an asset/service.
_OBSERVATION_TOOLS = {
    "tls_posture",
    "tls_openssl",
    "http_posture",
    "http_curl",
    "ssh_algorithms",
    "service_banner",
}

_ADDRESS_KEYS = {"A", "AAAA"}

_BANNER_PATTERNS = (
    re.compile(r"SSH-\d+\.\d+-(?P<product>[A-Za-z]+)[-_](?P<version>[\w.\-]+)"),
    re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9._\-]*)/(?P<version>\d[\w.\-]*)"),
    re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9._\-]*)[ /](?P<version>\d+\.\d+(?:[\w.\-]*))"),
)


def _parse_banner(banner: str | None) -> tuple[str | None, str | None]:
    """Best-effort product/version from an advertised service banner."""
    if not banner:
        return None, None
    for pattern in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            return match.group("product"), match.group("version")
    return None, None


def _prov_ref(tool: str) -> str:
    return f"prov:{tool}"


def _evidence_refs(tool: str, result: dict[str, Any]) -> list[str]:
    return [f"ev:{tool}:{i}" for i, _ in enumerate(result.get("evidence") or [])]


def _observed_at() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def build_provenance(state: dict, inp: DiscoveryInput, observed_at: datetime) -> list[ObservationProvenance]:
    results = state.get("results", {})
    provenance: list[ObservationProvenance] = []
    for name in state.get("executed", []):
        result = results.get(name, {})
        if result.get("status") in {"skipped"}:
            continue
        try:
            spec = get_spec(name)
            version = spec.version
        except KeyError:  # pragma: no cover - defensive
            version = "unknown"
        provenance.append(
            ObservationProvenance(
                observation_id=_prov_ref(name),
                source_tool=name,
                tool_version=version,
                runner_id=inp.network_context.runner_id,
                identity="external-probe",
                environment=inp.common.environment_kind,
                observed_at=observed_at,
                command=result.get("command"),
                evidence_refs=_evidence_refs(name, result),
            )
        )
    return provenance


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def _asset_id(host: str) -> str:
    return f"asset:{host}"


def build_assets(state: dict, inp: DiscoveryInput) -> list[Asset]:
    host = state.get("host") or (inp.target_seeds[0] if inp.target_seeds else "unknown")
    addresses: list[str] = [host]
    dns = state.get("results", {}).get("dns_recon", {})
    for record_type, values in (dns.get("data", {}).get("records") or {}).items():
        if record_type in _ADDRESS_KEYS:
            addresses.extend(str(v) for v in values)
    reverse = state.get("results", {}).get("reverse_dns", {})
    for name in reverse.get("data", {}).get("names", []) or []:
        addresses.append(str(name))
    seen: list[str] = []
    for value in addresses:
        if value not in seen:
            seen.append(value)
    os_name = None
    results = state.get("results", {})
    guess = results.get("nmap_discovery", {}).get("data", {})
    if guess.get("os"):
        os_name = str(guess["os"])

    evidence_snippets: list[str] = []
    host_alive = results.get("host_alive", {}).get("data", {}) or {}
    if host_alive:
        evidence_snippets.append(
            f"host_alive: icmp={host_alive.get('icmp')} tcp={host_alive.get('tcp')}"
        )
    if dns.get("data", {}).get("records"):
        evidence_snippets.append(
            "dns_recon: " + ", ".join(sorted(str(key) for key in dns["data"]["records"]))
        )
    if guess:
        evidence_snippets.append(f"nmap_discovery: {guess.get('summary') or 'host observed'}")
    if reverse.get("data", {}).get("names"):
        evidence_snippets.append("reverse_dns: " + ", ".join(str(n) for n in reverse["data"]["names"][:5]))

    return [
        Asset(
            asset_id=_asset_id(host),
            identity=state.get("host") or host,
            addresses=seen,
            os=os_name,
            os_basis=ObservationBasis.INFERRED if os_name else None,
            evidence=evidence_snippets,
            evidence_refs=[],
        )
    ]


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def build_services(state: dict, inp: DiscoveryInput) -> tuple[list[ServiceRecord], list[Uncertainty]]:
    host = state.get("host") or (inp.target_seeds[0] if inp.target_seeds else "unknown")
    asset_id = _asset_id(host)
    uncertainties: list[Uncertainty] = []
    services: list[ServiceRecord] = []

    # Detect conflicting names for the same port across tools.
    by_key: dict[str, set[str]] = {}
    for entry in state.get("services", []):
        key = f"{entry.get('port')}/{entry.get('protocol', 'tcp')}"
        name = str(entry.get("service") or "unknown").lower()
        by_key.setdefault(key, set()).add(name)

    banners = state.get("results", {}).get("service_banner", {}).get("data", {}).get("banners", {}) or {}

    for entry in state.get("services", []):
        port = int(entry.get("port", 0))
        protocol = entry.get("protocol", "tcp")
        key = f"{port}/{protocol}"
        product = entry.get("product") or None
        version = entry.get("version") or None
        source = entry.get("source") or "unknown"
        if not product or not version:
            banner = banners.get(str(port)) or banners.get(key)
            banner_product, banner_version = _parse_banner(banner)
            product = product or banner_product
            version = version or banner_version
            if (banner_product or banner_version) and source == "unknown":
                source = "service_banner"
        local_uncertainty: list[str] = []
        if version:
            note = f"version '{version}' is a banner observation, not authenticated package evidence"
            local_uncertainty.append(note)
            uncertainties.append(
                Uncertainty(subject=f"svc:{host}:{key}", detail=note, evidence_refs=[_prov_ref(source)])
            )
        if len(by_key.get(key, set())) > 1:
            names = sorted(by_key[key])
            note = f"conflicting service names reported for {key}: {', '.join(names)}"
            local_uncertainty.append(note)
            uncertainties.append(
                Uncertainty(subject=f"svc:{host}:{key}", detail=note, evidence_refs=[_prov_ref(source)])
            )
        service_evidence = [f"{source}: TCP/{port} open"]
        banner = banners.get(str(port)) or banners.get(key)
        if banner:
            service_evidence.append(f"banner: {str(banner)[:200]}")
        if product or version:
            service_evidence.append(
                f"{source}: product={product or 'unknown'} version={version or 'unknown'} (unverified)"
            )
        services.append(
            ServiceRecord(
                service_id=f"svc:{host}:{key}",
                asset_id=asset_id,
                port=port,
                transport=protocol,
                name=str(entry.get("service") or "unknown"),
                product=product,
                version=version,
                version_basis=ObservationBasis.BANNER,
                authenticated=False,
                reachability=Reachability.REACHABLE,
                uncertainty=local_uncertainty,
                evidence=service_evidence,
                evidence_refs=[_prov_ref(source)],
            )
        )
    return services, uncertainties


# ---------------------------------------------------------------------------
# Host observations
# ---------------------------------------------------------------------------


def _obs(asset_id: str, category: str, key: str, value: Any, tool: str) -> HostObservation:
    return HostObservation(
        asset_id=asset_id,
        category=category,
        key=key,
        value=str(value),
        basis=ObservationBasis.CONFIGURATION,
        evidence_refs=[_prov_ref(tool)],
    )


def build_host_observations(state: dict, inp: DiscoveryInput) -> list[HostObservation]:
    host = state.get("host") or (inp.target_seeds[0] if inp.target_seeds else "unknown")
    asset_id = _asset_id(host)
    results = state.get("results", {})
    observations: list[HostObservation] = []

    for tool in ("tls_posture", "tls_openssl"):
        data = results.get(tool, {}).get("data", {}) or {}
        if data.get("protocol"):
            observations.append(_obs(asset_id, "tls", "negotiated_protocol", data["protocol"], tool))
        if data.get("cipher"):
            observations.append(_obs(asset_id, "tls", "cipher", data["cipher"], tool))
        cert = data.get("certificate") or {}
        for cert_key in ("subject", "issuer", "not_after", "verify_message"):
            if cert.get(cert_key):
                observations.append(_obs(asset_id, "tls", f"certificate_{cert_key}", cert[cert_key], tool))
        if cert.get("self_signed") is not None:
            observations.append(_obs(asset_id, "tls", "certificate_self_signed", cert["self_signed"], tool))

    for tool in ("http_posture", "http_curl"):
        data = results.get(tool, {}).get("data", {}) or {}
        status = data.get("http_status") or data.get("status_line")
        if status:
            observations.append(_obs(asset_id, "http", "status", status, tool))
        for header in data.get("missing_headers", []) or []:
            observations.append(_obs(asset_id, "http-headers", f"missing:{header}", "absent", tool))
        for header in data.get("present_headers", []) or []:
            observations.append(_obs(asset_id, "http-headers", f"present:{header}", "set", tool))

    ssh = results.get("ssh_algorithms", {}).get("data", {}) or {}
    if ssh.get("banner"):
        observations.append(_obs(asset_id, "service-banner", "ssh", ssh["banner"], "ssh_algorithms"))
    for weak in ssh.get("weak_kex", []) or []:
        observations.append(_obs(asset_id, "service-config", f"weak-kex:{weak}", weak, "ssh_algorithms"))
    for weak in ssh.get("weak_host_keys", []) or []:
        observations.append(_obs(asset_id, "service-config", f"weak-hostkey:{weak}", weak, "ssh_algorithms"))

    banners = results.get("service_banner", {}).get("data", {}).get("banners", {}) or {}
    for port, banner in banners.items():
        observations.append(_obs(asset_id, "service-banner", f"port:{port}", banner, "service_banner"))

    return observations


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


def build_relationships(state: dict, services: list[ServiceRecord]) -> list[RelationshipProposal]:
    host = state.get("host") or "unknown"
    asset_id = _asset_id(host)
    proposals: list[RelationshipProposal] = []
    for service in services:
        proposals.append(
            RelationshipProposal(
                kind=RelationshipKind.OBSERVED,
                from_ref=service.service_id,
                to_ref=asset_id,
                relation="service-on-host",
                evidence_refs=service.evidence_refs,
            )
        )
    dns = state.get("results", {}).get("dns_recon", {}).get("data", {}).get("records", {}) or {}
    for record_type in _ADDRESS_KEYS:
        for value in dns.get(record_type, []) or []:
            proposals.append(
                RelationshipProposal(
                    kind=RelationshipKind.OBSERVED,
                    from_ref=asset_id,
                    to_ref=f"addr:{value}",
                    relation="resolves-to",
                    evidence_refs=[_prov_ref("dns_recon")],
                )
            )
    return proposals


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


def build_unassessed(
    state: dict,
    inp: DiscoveryInput,
    coverage_gaps: list[str],
) -> list[UnassessedTarget]:
    host = state.get("host") or (inp.target_seeds[0] if inp.target_seeds else "unknown")
    unassessed = [
        UnassessedTarget(target=host, reason=gap, category="coverage") for gap in coverage_gaps
    ]
    # Additional seeds are not expanded in this build; record them honestly.
    for seed in inp.target_seeds[1:]:
        unassessed.append(
            UnassessedTarget(
                target=seed,
                reason="multi-seed expansion is limited to the first seed in this build",
                category="scope",
            )
        )
    for question in inp.discovery_questions:
        unassessed.append(
            UnassessedTarget(
                target=host,
                reason=f"discovery question not yet answered: {question}",
                category="unanswered-question",
            )
        )
    if not state.get("services"):
        host_alive = state.get("results", {}).get("host_alive", {}).get("data", {})
        if host_alive and not host_alive.get("icmp") and not host_alive.get("tcp"):
            unassessed.append(
                UnassessedTarget(
                    target=host,
                    reason="host did not respond to liveness probes; not declared secure",
                    category="unreachable",
                )
            )
    return unassessed


# ---------------------------------------------------------------------------
# Common output + result envelope
# ---------------------------------------------------------------------------


def _infer_gate(state: dict) -> RequiredGate:
    gate = state.get("block_gate")
    if gate:
        try:
            return RequiredGate(gate)
        except ValueError:
            pass
    for error in state.get("errors", []):
        if "uthoriz" in error:
            return RequiredGate.AUTHORIZATION
    return RequiredGate.INPUT


def build_common_output(
    state: dict,
    inp: DiscoveryInput,
    *,
    services: list[ServiceRecord],
    uncertainties: list[Uncertainty],
    unassessed: list[UnassessedTarget],
    provenance: list[ObservationProvenance],
) -> CommonOutput:
    coverage_gaps = list(state.get("coverage_gaps", []))
    conflicts = [u for u in uncertainties if "conflicting" in u.detail]
    artifact = [f"artifact:asset_inventory:{inp.common.run_id}"]
    evidence_refs = [p.observation_id for p in provenance]

    assumptions = [
        "All observations are external/unauthenticated unless an access profile states otherwise.",
        "Service version strings are banner observations and are not authenticated package evidence.",
        "Empty lists mean no records were collected, not that none exist.",
    ]

    proposed_actions: list[ProposedAction] = []
    authenticating = [p for p in inp.access_profiles if p.authenticated]
    if services and authenticating:
        proposed_actions.append(
            ProposedAction(
                capability="authenticated-package-read",
                capability_version="1.0",
                stage="Enumeration",
                asset_ids=[s.asset_id for s in services],
                environment=inp.common.environment_kind,
                evidence_refs=evidence_refs,
            )
        )
    if unassessed:
        proposed_actions.append(
            ProposedAction(
                capability="tcp_scan",
                capability_version="1.0",
                stage="Scanning",
                asset_ids=[a.asset_id for a in services] or [f"asset:{state.get('host', 'unknown')}"],
                environment=inp.common.environment_kind,
                dependency_ids=[u.reason for u in unassessed],
            )
        )

    if state.get("status") == "blocked":
        gate = _infer_gate(state)
        return CommonOutput(
            status=AgentStatus.BLOCKED,
            concise_rationale="; ".join(state.get("errors", [])) or "Blocked before collection.",
            required_gate=gate,
            assumptions=assumptions,
            coverage_gaps=coverage_gaps or ["Assessment did not run; no coverage established."],
            artifact_refs=artifact,
            evidence_refs=evidence_refs,
        )

    if conflicts:
        status = AgentStatus.NEEDS_REVIEW
        next_objective = "Resolve conflicting observations before downstream testing."
        gate: RequiredGate | None = RequiredGate.REVIEW
    elif unassessed or coverage_gaps or not services:
        status = AgentStatus.MORE_WORK
        next_objective = "Close coverage gaps and confirm service versions."
        gate = None
    else:
        status = AgentStatus.DONE
        next_objective = None
        gate = None

    rationale = (
        f"Collected {len(services)} service record(s), {len(provenance)} sourced observation set(s) "
        f"across {len(inp.target_seeds) or 1} seed(s); {len(coverage_gaps)} coverage gap(s)."
    )
    return CommonOutput(
        status=status,
        concise_rationale=rationale,
        next_objective=next_objective,
        required_gate=gate,
        assumptions=assumptions,
        coverage_gaps=coverage_gaps,
        proposed_actions=proposed_actions,
        artifact_refs=artifact,
        evidence_refs=evidence_refs,
    )


def build_inventory(state: dict, inp: DiscoveryInput, observed_at: datetime) -> AssetInventory:
    provenance = build_provenance(state, inp, observed_at)
    services, uncertainties = build_services(state, inp)
    coverage_gaps = list(state.get("coverage_gaps", []))
    return AssetInventory(
        assets=build_assets(state, inp),
        services=services,
        host_observations=build_host_observations(state, inp),
        relationship_proposals=build_relationships(state, services),
        observation_provenance=provenance,
        uncertainties=uncertainties,
        unassessed_targets=build_unassessed(state, inp, coverage_gaps),
    )
