"""Common agent contract (shared input and output).

Every role receives the common input plus its role-specific input, and returns
the common output plus its role-specific artifact. These models are strict
(``extra="forbid"``) so an unexpected field is a rejection, matching the
contract rule: *do not add arbitrary fields to the strict envelope*.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.contracts.enums import AgentStatus, EnvironmentKind, RequiredGate


class ScopeRef(BaseModel):
    """Reference to the current versioned authorization and scope."""

    model_config = ConfigDict(extra="forbid")

    scope_id: str
    version: int = 1
    targets: list[str] = Field(default_factory=list)
    permitted_effects: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class RuntimeBinding(BaseModel):
    """Trusted-runtime identifiers that accompany every stored result.

    The model cannot change these; the runtime assigns or verifies them.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    workspace_id: str
    run_id: str
    environment_id: str
    agent_id: str = "discovery"
    model_call_id: str | None = None


class ProposedAction(BaseModel):
    """A typed proposal naming a registered capability and its inputs."""

    model_config = ConfigDict(extra="forbid")

    capability: str
    capability_version: str = "1.0"
    stage: str
    asset_ids: list[str] = Field(default_factory=list)
    environment: EnvironmentKind
    parameter_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    cleanup_plan_ref: str | None = None


class CommonInput(BaseModel):
    """Fields present in the input of every role."""

    model_config = ConfigDict(extra="forbid")

    workspace_id: str
    run_id: str
    task_id: str
    environment_id: str
    environment_kind: EnvironmentKind
    objective: str
    selected_stages: list[str] = Field(default_factory=list)
    scope_ref: ScopeRef
    context_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    available_capabilities: list[str] = Field(default_factory=list)
    remaining_budget: dict[str, float] = Field(default_factory=dict)


class CommonOutput(BaseModel):
    """Fields present in the output of every role."""

    model_config = ConfigDict(extra="forbid")

    status: AgentStatus
    artifact_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    required_gate: RequiredGate | None = None
    concise_rationale: str
    next_objective: str | None = None
