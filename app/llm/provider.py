"""Optional LLM provider (OpenAI-compatible chat completions).

The provider is intentionally optional and dependency-light: it talks to any
OpenAI-compatible ``/chat/completions`` endpoint over ``httpx`` (already a
dependency). When no provider is configured it reports unavailable and the agent
falls back to deterministic reasoning, so the system still runs offline and the
test suite stays hermetic.

Two layers of redundancy:

* **Model chain** - ``APS_LLM_MODEL`` (and the fallback model) may list several
  comma-separated models; they are tried in order.
* **Provider chain** - a primary provider (``APS_LLM_*``) is tried first, then an
  optional fallback provider (``APS_LLM_FALLBACK_*``, e.g. a local Ollama). So a
  cloud outage or rate limit automatically drops to the local model.

Transient statuses and network errors are retried per model before moving on.

Security: only non-sensitive task context (objective, target host, capability
names) is ever sent. Credentials, raw evidence bodies and secrets are never
included, and the model's output is treated as an untrusted *proposal* that the
registry validates before use.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import httpx

from app.config import settings

_RETRY_STATUS = {429, 500, 502, 503, 504}


class LLMUnavailable(RuntimeError):
    """Raised when no provider is configured or every provider/model failed."""


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key: str = ""
    models: tuple[str, ...] = field(default_factory=tuple)

    @property
    def chat_url(self) -> str:
        return self.base_url.rstrip("/") + "/chat/completions"


def _split(raw: str | None, default: str) -> list[str]:
    value = default if raw is None or raw == "" else raw
    chain = [part.strip() for part in (value or "").split(",") if part.strip()]
    return chain or [default]


def models(raw: str | None = None) -> list[str]:
    """The primary model chain (``APS_LLM_MODEL`` may be comma-separated)."""
    value = settings.llm_model if raw is None else raw
    return _split(value, "gpt-4o-mini")


def providers() -> list[Provider]:
    """Configured providers in priority order (primary, then fallback)."""
    chain: list[Provider] = []
    if settings.llm_api_key:
        chain.append(
            Provider(
                name="primary",
                base_url=settings.llm_base_url,
                api_key=settings.llm_api_key,
                models=tuple(models()),
            )
        )
    if settings.llm_fallback_base_url:
        chain.append(
            Provider(
                name="fallback",
                base_url=settings.llm_fallback_base_url,
                api_key=settings.llm_fallback_api_key,
                models=tuple(_split(settings.llm_fallback_model, "llama3.2")),
            )
        )
    return chain


def is_enabled() -> bool:
    return bool(providers())


def describe() -> dict:
    """Non-sensitive status (never returns keys)."""
    return {
        "enabled": is_enabled(),
        "providers": [
            {"name": provider.name, "base_url": provider.base_url, "models": list(provider.models)}
            for provider in providers()
        ],
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
    """Return assistant text, trying each provider, then each model, in order."""
    chain = providers()
    if not chain:
        raise LLMUnavailable("no LLM provider configured")
    deadline = timeout or settings.llm_timeout
    last: object = "no attempt made"

    for provider in chain:
        headers = {"Content-Type": "application/json"}
        if provider.api_key:
            headers["Authorization"] = f"Bearer {provider.api_key}"
        for model in provider.models:
            for attempt in range(settings.llm_retries + 1):
                payload = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                try:
                    response = _post(provider.chat_url, headers, payload, deadline)
                except httpx.HTTPError as exc:
                    last = f"{provider.name}:{type(exc).__name__}"
                    if attempt < settings.llm_retries:
                        time.sleep(0.8 * (attempt + 1))
                        continue
                    break
                if response.status_code in _RETRY_STATUS:
                    last = f"{provider.name}:{model}:HTTP {response.status_code}"
                    if attempt < settings.llm_retries:
                        time.sleep(0.8 * (attempt + 1))
                        continue
                    break
                try:
                    response.raise_for_status()
                    return response.json()["choices"][0]["message"]["content"]
                except (httpx.HTTPError, KeyError, ValueError, IndexError) as exc:
                    last = f"{provider.name}:{model}:{type(exc).__name__}"
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
