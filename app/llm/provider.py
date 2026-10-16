"""Optional LLM provider (OpenAI-compatible chat completions).

The provider is intentionally optional and dependency-light: it talks to any
OpenAI-compatible ``/chat/completions`` endpoint over ``httpx`` (already a
dependency). When no API key is configured it reports unavailable and the agent
falls back to deterministic reasoning, so the system still runs offline and the
test suite stays hermetic.

Security: only non-sensitive task context (objective, target host, capability
names) is ever sent. Credentials, raw evidence bodies and secrets are never
included, and the model's output is treated as an untrusted *proposal* that the
registry validates before use.
"""

from __future__ import annotations

import json

import httpx

from app.config import settings


class LLMUnavailable(RuntimeError):
    """Raised when the LLM is disabled or a call fails."""


def is_enabled() -> bool:
    return settings.llm_enabled


def describe() -> dict:
    """Non-sensitive status (never returns the key)."""
    base = settings.llm_base_url
    return {
        "enabled": is_enabled(),
        "model": settings.llm_model,
        "base_url": base,
        "timeout": settings.llm_timeout,
    }


def chat(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.0,
    max_tokens: int = 600,
    timeout: float | None = None,
) -> str:
    """Send a chat-completions request and return the assistant text."""
    if not is_enabled():
        raise LLMUnavailable("no LLM API key configured")
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.llm_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.llm_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=timeout or settings.llm_timeout)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError, IndexError) as exc:
        raise LLMUnavailable(f"LLM request failed: {type(exc).__name__}") from exc


def extract_json(text: str) -> dict:
    """Best-effort JSON extraction from a model reply (handles code fences)."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model reply")
    return json.loads(cleaned[start : end + 1])
