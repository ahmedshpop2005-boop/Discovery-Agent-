"""Optional LLM provider (OpenAI-compatible chat completions).

The provider is intentionally optional and dependency-light: it talks to any
OpenAI-compatible ``/chat/completions`` endpoint over ``httpx`` (already a
dependency). When no API key is configured it reports unavailable and the agent
falls back to deterministic reasoning, so the system still runs offline and the
test suite stays hermetic.

``APS_LLM_MODEL`` may list several comma-separated models; they are tried in
order so a busy/failed model (e.g. a transient HTTP 503) falls through to the
next one. Transient statuses and network errors are retried per model.

Security: only non-sensitive task context (objective, target host, capability
names) is ever sent. Credentials, raw evidence bodies and secrets are never
included, and the model's output is treated as an untrusted *proposal* that the
registry validates before use.
"""

from __future__ import annotations

import json
import time

import httpx

from app.config import settings

_RETRY_STATUS = {429, 500, 502, 503, 504}


class LLMUnavailable(RuntimeError):
    """Raised when the LLM is disabled or a call fails."""


def is_enabled() -> bool:
    return settings.llm_enabled


def models(raw: str | None = None) -> list[str]:
    """The configured model chain (``APS_LLM_MODEL`` may be comma-separated)."""
    value = settings.llm_model if raw is None else raw
    chain = [part.strip() for part in (value or "").split(",") if part.strip()]
    return chain or ["gpt-4o-mini"]


def describe() -> dict:
    """Non-sensitive status (never returns the key)."""
    return {
        "enabled": is_enabled(),
        "models": models(),
        "base_url": settings.llm_base_url,
        "timeout": settings.llm_timeout,
        "retries": settings.llm_retries,
    }


def _post(url: str, headers: dict, payload: dict, timeout: float) -> httpx.Response:
    return httpx.post(url, json=payload, headers=headers, timeout=timeout)


def chat(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.0,
    max_tokens: int = 600,
    timeout: float | None = None,
) -> str:
    """Send a chat-completions request and return the assistant text.

    Tries each configured model in order, retrying transient failures with a
    small backoff before moving on to the next model.
    """
    if not is_enabled():
        raise LLMUnavailable("no LLM API key configured")
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.llm_api_key}",
        "Content-Type": "application/json",
    }
    deadline = timeout or settings.llm_timeout
    last: object = "no attempt made"

    for model in models():
        for attempt in range(settings.llm_retries + 1):
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            try:
                response = _post(url, headers, payload, deadline)
            except httpx.HTTPError as exc:
                last = type(exc).__name__
                if attempt < settings.llm_retries:
                    time.sleep(0.8 * (attempt + 1))
                    continue
                break
            if response.status_code in _RETRY_STATUS:
                last = f"HTTP {response.status_code}"
                if attempt < settings.llm_retries:
                    time.sleep(0.8 * (attempt + 1))
                    continue
                break
            try:
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]
            except (httpx.HTTPError, KeyError, ValueError, IndexError) as exc:
                last = type(exc).__name__
                break

    raise LLMUnavailable(f"LLM request failed: {last}")


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
