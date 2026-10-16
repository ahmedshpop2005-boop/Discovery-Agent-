"""Typed state for the assessment workflow.

List fields that accumulate across nodes use LangGraph's ``add`` reducer so
their contents merge instead of being overwritten.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict


class AssessmentState(TypedDict, total=False):
    # Input
    target: str
    consent: bool
    profile: str
    scan_id: str
    target_seeds: list[str]
    discovery_input: dict[str, Any]

    # Resolved after the authorization guard
    host: str
    base_url: str
    scheme: str
    block_gate: str

    # Planning / execution bookkeeping
    tool_plan: list[str]
    executed: list[str]
    iterations: int

    # Collected observations keyed by tool name
    results: dict[str, dict[str, Any]]
    services: list[dict[str, Any]]

    # Outputs
    findings: list[dict[str, Any]]
    status: str

    # SentinelX Discovery contract output
    inventory: dict[str, Any]
    agent_result: dict[str, Any]

    # Traces (merge-friendly)
    events: Annotated[list[str], add]
    errors: Annotated[list[str], add]
    coverage_gaps: Annotated[list[str], add]


def new_state(
    target: str,
    consent: bool,
    profile: str = "safe",
    scan_id: str = "",
    *,
    target_seeds: list[str] | None = None,
    discovery_input: dict[str, Any] | None = None,
) -> AssessmentState:
    return {
        "target": target,
        "consent": consent,
        "profile": profile,
        "scan_id": scan_id,
        "target_seeds": target_seeds if target_seeds is not None else ([target] if target else []),
        "discovery_input": discovery_input or {},
        "events": [],
        "errors": [],
        "coverage_gaps": [],
        "results": {},
        "services": [],
        "tool_plan": [],
        "executed": [],
        "iterations": 0,
    }
