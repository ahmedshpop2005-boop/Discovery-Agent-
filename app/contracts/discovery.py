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
    EnvironmentKind,
    ObservationBasis,
    Reachability,
    RelationshipKind,
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


class DiscoveryResult(BaseModel):
    """Stored discovery result = runtime binding + common output + inventory."""

    model_config = ConfigDict(extra="forbid")

    runtime: RuntimeBinding
    output: CommonOutput
    inventory: AssetInventory
