"""Tests for the optional LLM reasoning layer.

Hermetic: no network is ever hit. The provider's ``chat`` is monkeypatched and
``is_enabled`` is forced, so behaviour is verified without an API key.
"""

from __future__ import annotations

import pytest

from app.agents import nodes
from app.agents.state import new_state
from app.llm import provider, reasoning
from app.llm.provider import LLMUnavailable


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: False)
    assert provider.is_enabled() is False
    with pytest.raises(LLMUnavailable):
        provider.chat([{"role": "user", "content": "hi"}])


def test_describe_never_leaks_key():
    info = provider.describe()
    assert "api_key" not in info
    assert set(info) == {"enabled", "models", "base_url", "timeout", "retries"}


def test_models_splits_chain():
    assert provider.models("a,b , c") == ["a", "b", "c"]
    assert provider.models("") == ["gpt-4o-mini"]


def test_chat_retries_then_falls_through_model_chain(monkeypatch):
    import httpx

    monkeypatch.setattr(provider, "is_enabled", lambda: True)
    monkeypatch.setattr(provider, "models", lambda raw=None: ["busy", "works"])
    monkeypatch.setattr(provider.time, "sleep", lambda _seconds: None)
    seen: list[str] = []

    def fake_post(url, headers, payload, timeout):
        seen.append(payload["model"])
        request = httpx.Request("POST", url)
        if payload["model"] == "busy":
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}, request=request)

    monkeypatch.setattr(provider, "_post", fake_post)
    assert provider.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert seen[0] == "busy" and seen[-1] == "works"
    assert seen.count("busy") == provider.settings.llm_retries + 1


def test_extract_json_handles_code_fence():
    payload = reasoning.provider.extract_json('```json\n{"tools": ["a"], "reason": "x"}\n```')
    assert payload["tools"] == ["a"]


def test_plan_falls_back_when_disabled(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: False)
    tools, source = reasoning.propose_tool_plan(
        objective="o", target="127.0.0.1", profile="safe",
        allowed=["http_probe", "tcp_scan"], deterministic=["http_probe"],
    )
    assert source == "deterministic"
    assert tools == ["http_probe"]


def test_plan_uses_model_subset_and_drops_hallucinations(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: True)
    monkeypatch.setattr(
        provider, "chat",
        lambda messages, **kw: '{"tools": ["tcp_scan", "ghost_tool"], "reason": "r"}',
    )
    tools, source = reasoning.propose_tool_plan(
        objective="o", target="127.0.0.1", profile="safe",
        allowed=["http_probe", "tcp_scan"], deterministic=["http_probe"],
    )
    assert source == "llm"
    assert tools == ["tcp_scan"]  # hallucinated name dropped, registry order kept


def test_plan_empty_selection_falls_back(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: True)
    monkeypatch.setattr(provider, "chat", lambda messages, **kw: '{"tools": ["ghost"]}')
    tools, source = reasoning.propose_tool_plan(
        objective="o", target="127.0.0.1", profile="safe",
        allowed=["http_probe"], deterministic=["http_probe"],
    )
    assert source == "deterministic"
    assert tools == ["http_probe"]


def test_plan_survives_model_error(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: True)

    def boom(messages, **kw):
        raise LLMUnavailable("network down")

    monkeypatch.setattr(provider, "chat", boom)
    tools, source = reasoning.propose_tool_plan(
        objective="o", target="127.0.0.1", profile="safe",
        allowed=["http_probe"], deterministic=["http_probe"],
    )
    assert (tools, source) == (["http_probe"], "deterministic")


def test_plan_node_uses_llm_when_enabled(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: True)

    def fake_chat(messages, **kw):
        allowed = messages[-1]["content"].split("ALLOWED: ", 1)[1].split("\n", 1)[0]
        first = eval(allowed)[0]  # the request carries a python list literal
        return '{"tools": ["%s"]}' % first

    monkeypatch.setattr(provider, "chat", fake_chat)
    state = new_state("127.0.0.1", True, profile="safe")
    update = nodes.plan_node(state)
    assert update["tool_plan"], "LLM plan should not be empty"
    assert any("LLM planner" in e for e in update["events"])


def test_plan_node_deterministic_without_llm(monkeypatch):
    monkeypatch.setattr(provider, "is_enabled", lambda: False)
    state = new_state("127.0.0.1", True, profile="safe")
    update = nodes.plan_node(state)
    assert update["tool_plan"]
    assert any("Deterministic planner" in e for e in update["events"])


def test_plan_node_always_keeps_port_discovery(monkeypatch):
    """A model that omits port discovery must not remove it from the plan."""
    from app.tools.registry import get as get_spec

    monkeypatch.setattr(provider, "is_enabled", lambda: True)
    monkeypatch.setattr(provider, "chat", lambda messages, **kw: '{"tools": ["host_alive"]}')
    update = nodes.plan_node(new_state("127.0.0.1", True, profile="safe"))
    caps = {get_spec(name).capability for name in update["tool_plan"]}
    assert "port_discovery" in caps
    assert "host_discovery" in caps


def test_llm_and_health_endpoints():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    health = client.get("/healthz").json()
    assert health["status"] == "ok"
    assert "llm" in health
    status = client.get("/api/llm").json()
    assert "enabled" in status and "api_key" not in status
