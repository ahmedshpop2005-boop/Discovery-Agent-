"""Tests for the SentinelX Discovery contract (input/output schemas)."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.tools  # noqa: F401  (register tools)
from app.agents.graph import run_discovery
from app.contracts import (
    CommonOutput,
    DiscoveryInput,
    DiscoveryResult,
    default_discovery_input,
)
from app.contracts.enums import AgentStatus, RequiredGate

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "contracts"


# ---------------------------------------------------------------------------
# Schema / validation (success cases)
# ---------------------------------------------------------------------------


def test_default_input_is_valid_and_round_trips():
    inp = default_discovery_input("https://demo.example.com", consent=True)
    again = DiscoveryInput.model_validate(inp.model_dump(mode="json"))
    assert again == inp
    assert "read-only" in again.common.scope_ref.permitted_effects


def test_exported_examples_validate_against_models():
    example_input = json.loads((CONTRACTS / "example_input.json").read_text(encoding="utf-8"))
    example_output = json.loads((CONTRACTS / "example_output.json").read_text(encoding="utf-8"))
    DiscoveryInput.model_validate(example_input)
    result = DiscoveryResult.model_validate(example_output)
    assert result.output.status is AgentStatus.DONE
    assert result.inventory.services[0].version_basis.value == "banner"


def test_json_schemas_are_exported():
    for name in ("common_input", "common_output", "discovery_input", "discovery_result", "asset_inventory"):
        assert (CONTRACTS / f"{name}.schema.json").exists()


# ---------------------------------------------------------------------------
# Rejection rules
# ---------------------------------------------------------------------------


def test_unknown_field_is_rejected():
    data = default_discovery_input("https://demo.example.com", consent=True).model_dump(mode="json")
    data["unexpected_extra"] = "nope"
    with pytest.raises(ValidationError):
        DiscoveryInput.model_validate(data)


def test_missing_scope_ref_is_rejected():
    data = default_discovery_input("https://demo.example.com", consent=True).model_dump(mode="json")
    del data["common"]["scope_ref"]
    with pytest.raises(ValidationError):
        DiscoveryInput.model_validate(data)


def test_invalid_status_value_is_rejected():
    with pytest.raises(ValidationError):
        CommonOutput(status="OK", concise_rationale="not a valid status")


def test_invalid_environment_kind_is_rejected():
    data = default_discovery_input("https://demo.example.com", consent=True).model_dump(mode="json")
    data["common"]["environment_kind"] = "PRODUCTION"
    with pytest.raises(ValidationError):
        DiscoveryInput.model_validate(data)


# ---------------------------------------------------------------------------
# Missing-input / authorization cases (gates, not crashes)
# ---------------------------------------------------------------------------


def test_missing_target_seed_blocks_with_input_gate():
    result = run_discovery(default_discovery_input("", consent=True))
    assert result.output.status is AgentStatus.BLOCKED
    assert result.output.required_gate is RequiredGate.INPUT
    assert result.inventory.services == []


def test_without_consent_blocks_with_authorization_gate():
    result = run_discovery(default_discovery_input("http://127.0.0.1:9/", consent=False))
    assert result.output.status is AgentStatus.BLOCKED
    assert result.output.required_gate is RequiredGate.AUTHORIZATION


# ---------------------------------------------------------------------------
# Successful run produces a contract-shaped AssetInventory
# ---------------------------------------------------------------------------


def test_successful_run_produces_contract_result(local_http_server):
    base_url, host, _port = local_http_server
    result = run_discovery(default_discovery_input(base_url, consent=True))

    assert isinstance(result, DiscoveryResult)
    assert result.output.status in {AgentStatus.DONE, AgentStatus.MORE_WORK, AgentStatus.NEEDS_REVIEW}

    # Assets, services and provenance are populated.
    assert result.inventory.assets
    assert result.inventory.services
    assert result.inventory.observation_provenance

    # Provenance carries source, tool version, runner and time.
    first = result.inventory.observation_provenance[0]
    assert first.source_tool and first.tool_version == "1.0"
    assert first.runner_id == "runner-local"
    assert first.observed_at is not None

    # Every service is unauthenticated and versioned as a banner observation.
    for service in result.inventory.services:
        assert service.authenticated is False
        assert service.version_basis.value == "banner"

    # relationships link each service to its host asset.
    relations = {r.relation for r in result.inventory.relationship_proposals}
    assert "service-on-host" in relations
