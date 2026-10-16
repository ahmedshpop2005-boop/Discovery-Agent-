"""SentinelX shared agent contracts.

Only the Discovery role contract is implemented here (owner: Shaaban). The
common input/output and the ``AssetInventory`` output are the interface other
roles consume, so they are strict, versioned Pydantic models with a JSON Schema
export.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.contracts.common import (
    CommonInput,
    CommonOutput,
    ProposedAction,
    RuntimeBinding,
    ScopeRef,
)
from app.contracts.discovery import (
    AccessProfile,
    Asset,
    AssetInventory,
    DiscoveryInput,
    DiscoveryLimits,
    DiscoveryResult,
    HostObservation,
    NetworkContext,
    ObservationProvenance,
    RelationshipProposal,
    ServiceRecord,
    Uncertainty,
    UnassessedTarget,
)
from app.contracts.enums import (
    AgentStatus,
    EnvironmentKind,
    ObservationBasis,
    Reachability,
    RelationshipKind,
    RequiredGate,
)

__all__ = [
    "AgentStatus",
    "EnvironmentKind",
    "ObservationBasis",
    "Reachability",
    "RelationshipKind",
    "RequiredGate",
    "CommonInput",
    "CommonOutput",
    "ProposedAction",
    "RuntimeBinding",
    "ScopeRef",
    "AccessProfile",
    "Asset",
    "AssetInventory",
    "DiscoveryInput",
    "DiscoveryLimits",
    "DiscoveryResult",
    "HostObservation",
    "NetworkContext",
    "ObservationProvenance",
    "RelationshipProposal",
    "ServiceRecord",
    "Uncertainty",
    "UnassessedTarget",
    "default_discovery_input",
    "export_schemas",
    "SCHEMA_MODELS",
]

SCHEMA_MODELS = {
    "common_input": CommonInput,
    "common_output": CommonOutput,
    "discovery_input": DiscoveryInput,
    "discovery_result": DiscoveryResult,
    "asset_inventory": AssetInventory,
}


def export_schemas(directory: Path) -> list[Path]:
    """Write each contract model's JSON Schema to ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema()
        path = directory / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
        written.append(path)
    return written


def default_discovery_input(
    target: str,
    *,
    consent: bool = False,
    profile: str = "safe",
    environment_kind: EnvironmentKind = EnvironmentKind.REAL,
    workspace_id: str = "ws-demo",
    run_id: str | None = None,
    objective: str = "Build a sourced inventory of the authorized target.",
) -> DiscoveryInput:
    """Convenience builder for simple/CLI use and backward compatibility."""
    import app.tools  # noqa: F401  (ensure tools are registered)
    from app.tools.registry import all_specs

    run_id = run_id or uuid4().hex[:12]
    capabilities = [f"{spec.name}@{spec.version}" for spec in all_specs()]
    return DiscoveryInput(
        common=CommonInput(
            workspace_id=workspace_id,
            run_id=run_id,
            task_id=f"disc-{run_id}",
            environment_id=f"env-{run_id}",
            environment_kind=environment_kind,
            objective=objective,
            selected_stages=["Discovery"],
            scope_ref=ScopeRef(
                scope_id=f"scope-{run_id}",
                targets=[target] if target else [],
                permitted_effects=["read-only"] if consent else [],
            ),
            available_capabilities=capabilities,
        ),
        target_seeds=[target] if target else [],
        discovery_limits=DiscoveryLimits(),
        access_profiles=[AccessProfile(id="external", kind="external-probe", authenticated=False)],
        network_context=NetworkContext(runner_id="runner-local"),
    )
