"""Discovery role contract (input + ``AssetInventory`` output).

Owner: Shaaban. The Discovery agent builds a sourced inventory of assets,
services and available context and hands it to Pentesting. Every observation
carries provenance (source, time, runner, tool version and evidence references)
and the difference between an observed fact and an assumption is explicit.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.contracts.common import CommonInput, CommonOutput, RuntimeBinding
from app.contracts.enums import (
    ConfidenceLevel,
    CoverageStatus,
    EnvironmentKind,
    ObservationBasis,
    Reachability,
    RelationshipKind,
    TechnologyObservationType,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Role-specific input
# ---------------------------------------------------------------------------


class AccessProfile(BaseModel):
    """An available identity / privilege set.

    Secret material stays outside the model: only a protected ``secret_ref``
    may be carried (contract: "Secret material stays outside model context").
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str = "external-probe"
    authenticated: bool = False
    privileges: list[str] = Field(default_factory=list)
    secret_ref: str | None = None


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runner_id: str
    source_network: str | None = None
    known_topology: list[str] = Field(default_factory=list)


class WebContext(BaseModel):
    """Runner/proxy/API context needed to interpret Web responses.

    Kept separate from :class:`NetworkContext` so the Web surface can be
    described without leaking session secrets (only protected references).
    """

    model_config = ConfigDict(extra="forbid")

    runner_origin: str | None = None
    base_path: str = "/"
    reverse_proxy: bool | None = None
    api_specs: list[str] = Field(default_factory=list)
    auth_flows: list[str] = Field(default_factory=list)


class DiscoveryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ports: list[int] | None = None
    protocols: list[str] = Field(default_factory=lambda: ["tcp"])
    methods: list[str] = Field(default_factory=list)
    scan_rate: float | None = None
    concurrency: int | None = None
    duration_seconds: float | None = None


class DiscoveryInput(BaseModel):
    """Discover from authorized seeds within declared limits."""

    model_config = ConfigDict(extra="forbid")

    common: CommonInput
    target_seeds: list[str] = Field(default_factory=list)
    discovery_limits: DiscoveryLimits = Field(default_factory=DiscoveryLimits)
    known_inventory_refs: list[str] = Field(default_factory=list)
    access_profiles: list[AccessProfile] = Field(default_factory=list)
    network_context: NetworkContext
    web_context: WebContext | None = None
    discovery_questions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Role-specific output: AssetInventory
# ---------------------------------------------------------------------------


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    identity: str
    addresses: list[str] = Field(default_factory=list)
    os: str | None = None
    os_basis: ObservationBasis | None = None
    evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ServiceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str
    asset_id: str
    port: int
    transport: str = "tcp"
    name: str = "unknown"
    product: str | None = None
    version: str | None = None
    version_basis: ObservationBasis = ObservationBasis.BANNER
    authenticated: bool = False
    reachability: Reachability = Reachability.REACHABLE
    uncertainty: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class HostObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    category: str
    key: str
    value: str
    basis: ObservationBasis = ObservationBasis.CONFIGURATION
    evidence_refs: list[str] = Field(default_factory=list)


class RelationshipProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: RelationshipKind = RelationshipKind.OBSERVED
    from_ref: str
    to_ref: str
    relation: str
    evidence_refs: list[str] = Field(default_factory=list)


class ObservationProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: str
    source_tool: str
    tool_version: str = "1.0"
    runner_id: str
    identity: str = "external-probe"
    environment: EnvironmentKind
    observed_at: datetime
    command: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class Uncertainty(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    detail: str
    evidence_refs: list[str] = Field(default_factory=list)


class UnassessedTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    reason: str
    category: str = "unsupported"


class AssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[Asset] = Field(default_factory=list)
    services: list[ServiceRecord] = Field(default_factory=list)
    host_observations: list[HostObservation] = Field(default_factory=list)
    relationship_proposals: list[RelationshipProposal] = Field(default_factory=list)
    observation_provenance: list[ObservationProvenance] = Field(default_factory=list)
    uncertainties: list[Uncertainty] = Field(default_factory=list)
    unassessed_targets: list[UnassessedTarget] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Web surface extension (WEB EXTENSION 02)
# ---------------------------------------------------------------------------


class TechnologyRecord(BaseModel):
    """Normalised technology observation.

    The normaliser never promotes arbitrary metadata (country names, IPs,
    header directives, MIME types) to a version. HTML/JS/banner/header values
    are ``version_claimed``/``banner_observed`` and remain ``unverified``
    unless an independent check validated them.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str | None = None
    observation_type: TechnologyObservationType = TechnologyObservationType.FINGERPRINT_OBSERVED
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    basis: ObservationBasis = ObservationBasis.BANNER
    evidence: list[str] = Field(default_factory=list)
    source_url: str | None = None
    collection_method: str | None = None
    observed_at: datetime | None = None
    conflicting_versions: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class FormRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = ""
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)


class EndpointRecord(BaseModel):
    """A route/template observed on the wire or declared by a spec.

    ``observed`` is ``True`` only when the endpoint was actually requested and
    answered. Routes declared by robots.txt/sitemap/OpenAPI but not requested
    are ``observed=False`` (spec-only) and are never inferred to be vulnerable.
    """

    model_config = ConfigDict(extra="forbid")

    endpoint_id: str
    application_id: str
    path: str
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    forms: list[FormRecord] = Field(default_factory=list)
    api_operation: str | None = None
    observed: bool = True
    status: int | None = None
    classification: str = "unknown"
    collection_method: str | None = None
    source: str = "unknown"
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class WebApplication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str
    origin: str
    identity: str | None = None
    title: str | None = None
    base_paths: list[str] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)
    server: str | None = None
    waf: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class WebObservationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str
    category: str
    key: str
    value: str
    basis: ObservationBasis = ObservationBasis.CONFIGURATION
    source_url: str | None = None
    collection_method: str | None = None
    evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class WebObservationProvenance(ObservationProvenance):
    """Provenance that also names the URL/path the observation came from."""

    source_url: str | None = None


class EvidenceRecord(BaseModel):
    """A traceable piece of evidence behind an asset/service/route observation."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    type: str
    source_tool: str
    target: str
    status: str | None = None
    snippet: str = ""
    observed_at: datetime | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    limitations: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class RouteCoverage(BaseModel):
    """Honest route-discovery coverage summary.

    ``coverage_status`` is never ``full`` merely because every configured
    candidate was attempted: access-control responses, CDN pages, missing
    authentication and tool failures force ``limited``/``partial``.
    """

    model_config = ConfigDict(extra="forbid")

    routes_attempted: int = 0
    routes_confirmed: int = 0
    routes_inaccessible: int = 0
    routes_failed: int = 0
    routes_untested: int = 0
    coverage_status: CoverageStatus = CoverageStatus.UNKNOWN
    coverage_limitations: list[str] = Field(default_factory=list)
    methods_executed: list[str] = Field(default_factory=list)
    methods_skipped: list[str] = Field(default_factory=list)


class AuthenticationCoverage(BaseModel):
    """What was and was not assessed regarding authenticated/role surfaces."""

    model_config = ConfigDict(extra="forbid")

    status: str = "not_assessed"
    profiles_supplied: int = 0
    authenticated_profiles: int = 0
    checks_completed: list[str] = Field(default_factory=list)
    checks_unverified: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WebAssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    applications: list[WebApplication] = Field(default_factory=list)
    endpoints: list[EndpointRecord] = Field(default_factory=list)
    web_observations: list[WebObservationRecord] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    route_coverage: RouteCoverage = Field(default_factory=RouteCoverage)
    authentication_coverage: AuthenticationCoverage = Field(default_factory=AuthenticationCoverage)
    relationship_proposals: list[RelationshipProposal] = Field(default_factory=list)
    observation_provenance: list[WebObservationProvenance] = Field(default_factory=list)
    uncertainties: list[Uncertainty] = Field(default_factory=list)
    unassessed_targets: list[UnassessedTarget] = Field(default_factory=list)


class DiscoveryResult(BaseModel):
    """Stored discovery result = runtime binding + common output + inventory."""

    model_config = ConfigDict(extra="forbid")

    runtime: RuntimeBinding
    output: CommonOutput
    inventory: AssetInventory
    web_inventory: WebAssetInventory | None = None
