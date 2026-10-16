"""LangGraph assembly for the Discovery workflow.

    guard ──▶ plan ──▶ collect ──▶ adapt ──┐
      │                         ▲          │
      └─(blocked)─▶ END         └──(more)──┘
                                └─(done)──▶ validate ──▶ project ──▶ END

The final ``project`` node converts the collected observations into the
SentinelX Discovery contract result (``AssetInventory`` + common output), so the
workflow is directly consumable by the Pentesting agent.
"""

from __future__ import annotations

from uuid import uuid4

from langgraph.graph import END, StateGraph

from app.agents.nodes import (
    adapt_node,
    collect_node,
    guard_node,
    plan_node,
    project_node,
    route_after_adapt,
    route_after_guard,
    validate_node,
)
from app.agents.state import AssessmentState, new_state
from app.contracts import DiscoveryInput, DiscoveryResult, default_discovery_input


def build_graph():
    graph = StateGraph(AssessmentState)
    graph.add_node("guard", guard_node)
    graph.add_node("plan", plan_node)
    graph.add_node("collect", collect_node)
    graph.add_node("adapt", adapt_node)
    graph.add_node("validate", validate_node)
    graph.add_node("project", project_node)

    graph.set_entry_point("guard")
    graph.add_conditional_edges("guard", route_after_guard, {"plan": "plan", "end": END})
    graph.add_edge("plan", "collect")
    graph.add_edge("collect", "adapt")
    graph.add_conditional_edges("adapt", route_after_adapt, {"collect": "collect", "validate": "validate"})
    graph.add_edge("validate", "project")
    graph.add_edge("project", END)
    return graph.compile()


def run_assessment(
    target: str,
    consent: bool,
    profile: str = "safe",
    scan_id: str | None = None,
) -> AssessmentState:
    """Execute the full workflow and return the final state.

    Kept for the dashboard/PDF/CLI; also emits ``inventory`` and
    ``agent_result`` (the Discovery contract result) in the state.
    """
    scan_id = scan_id or uuid4().hex[:12]
    inp = default_discovery_input(target, consent=consent, profile=profile, run_id=scan_id)
    initial = new_state(
        target=target,
        consent=consent,
        profile=profile,
        scan_id=scan_id,
        target_seeds=inp.target_seeds,
        discovery_input=inp.model_dump(mode="json"),
    )
    return build_graph().invoke(initial)


def run_discovery(inp: DiscoveryInput) -> DiscoveryResult:
    """Run Discovery against a validated contract input and return the contract result."""
    seeds = list(inp.target_seeds)
    initial = new_state(
        target=seeds[0] if seeds else "",
        consent="read-only" in inp.common.scope_ref.permitted_effects,
        profile="safe",
        scan_id=inp.common.run_id,
        target_seeds=seeds,
        discovery_input=inp.model_dump(mode="json"),
    )
    final = build_graph().invoke(initial)
    result = final.get("agent_result")
    if result is None:  # blocked before the projection node
        result = _project_blocked(final, inp)
    return DiscoveryResult.model_validate(result)


def _project_blocked(state: AssessmentState, inp: DiscoveryInput) -> dict:
    from datetime import datetime, timezone

    from app.agents.inventory import build_common_output, build_inventory
    from app.contracts.common import RuntimeBinding

    observed_at = datetime.now(timezone.utc)
    inventory = build_inventory(state, inp, observed_at)
    output = build_common_output(
        state,
        inp,
        services=inventory.services,
        uncertainties=inventory.uncertainties,
        unassessed=inventory.unassessed_targets,
        provenance=inventory.observation_provenance,
    )
    runtime = RuntimeBinding(
        workspace_id=inp.common.workspace_id,
        run_id=inp.common.run_id,
        environment_id=inp.common.environment_id,
    )
    return DiscoveryResult(runtime=runtime, output=output, inventory=inventory).model_dump(mode="json")
