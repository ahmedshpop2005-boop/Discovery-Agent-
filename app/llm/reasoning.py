"""LLM-assisted planning for the Discovery agent.

The model only *proposes* which registered capabilities to run. Every proposal
is validated against the allow-list of eligible tools for the active profile
before use, so the model can never introduce an unregistered or unauthorized
capability. When the LLM is disabled or returns something unusable, the
deterministic plan is used instead.
"""

from __future__ import annotations

from app.llm import provider

_SYSTEM_PROMPT = (
    "You are the Discovery planner for an authorized, non-destructive security "
    "assessment. Choose which of the ALLOWED tools to run for the objective. "
    "You may only use tool names from ALLOWED; never invent tools. Prefer a small, "
    "relevant set. Reply with strict JSON: {\"tools\": [\"name\", ...], \"reason\": \"...\"}."
)


def propose_tool_plan(
    *,
    objective: str,
    target: str,
    profile: str,
    allowed: list[str],
    deterministic: list[str],
    discovery_questions: list[str] | None = None,
) -> tuple[list[str], str]:
    """Return ``(tool_names, source)`` where source is ``"llm"`` or ``"deterministic"``."""
    if not allowed:
        return deterministic, "deterministic"
    if not provider.is_enabled():
        return deterministic, "deterministic"

    request = (
        f"objective: {objective}\n"
        f"target: {target}\n"
        f"profile: {profile}\n"
        f"discovery_questions: {discovery_questions or []}\n"
        f"ALLOWED: {allowed}\n"
        "Choose the tools to run. JSON only."
    )
    try:
        content = provider.chat(
            [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": request},
            ]
        )
        parsed = provider.extract_json(content)
        chosen = parsed.get("tools")
        if not isinstance(chosen, list):
            return deterministic, "deterministic"
        allowed_set = set(allowed)
        # Keep registry order and drop anything the model hallucinated.
        ordered = [name for name in allowed if name in chosen and name in allowed_set]
        return (ordered, "llm") if ordered else (deterministic, "deterministic")
    except Exception:
        return deterministic, "deterministic"
