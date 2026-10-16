"""Tool registry.

A single place where every collection tool registers its metadata. The agent
planner chooses tools from here; it never calls a subprocess directly.

Capabilities & redundancy
-------------------------
Every tool declares a ``capability`` - the *logical job* it performs (e.g.
``port_discovery``, ``http_headers``, ``tls_info``). Multiple tools can share
a capability, which gives the agent redundancy: if the primary tool fails or
is unavailable, the executor automatically tries another tool with the same
capability. This is what keeps the assessment useful when one tool or one
external binary is not working.

Profiles
--------
``safe``    - default, network + DNS + HTTP + TLS posture only.
``web``     - safe plus deeper HTTP/content analysis and OSINT.
``network`` - safe plus broader scanning and service probes.
``full``    - every registered tool that is applicable to the target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.tools.base import EffectClass, ToolContext, ToolResult

TOOL_FN = Callable[[ToolContext], ToolResult]

VALID_PROFILES = ("safe", "web", "network", "full")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    category: str
    effect_class: str
    function: TOOL_FN
    capability: str = "misc"
    requires: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ("safe",)
    order: int = 100
    # Fallback priority within a capability: lower runs first.
    priority: int = 50
    # Capability/tool version recorded in observation provenance.
    version: str = "1.0"


_REGISTRY: dict[str, ToolSpec] = {}


def register(spec: ToolSpec) -> ToolSpec:
    if spec.name in _REGISTRY:
        raise ValueError(f"duplicate tool name: {spec.name}")
    _REGISTRY[spec.name] = spec
    return spec


def tool(
    *,
    name: str,
    description: str,
    category: str,
    effect_class: str = EffectClass.READ_ONLY,
    capability: str = "misc",
    requires: tuple[str, ...] = (),
    profiles: tuple[str, ...] = ("safe",),
    order: int = 100,
    priority: int = 50,
    version: str = "1.0",
) -> Callable[[TOOL_FN], TOOL_FN]:
    """Decorator that registers a tool function."""

    def wrapper(fn: TOOL_FN) -> TOOL_FN:
        register(
            ToolSpec(
                name=name,
                description=description,
                category=category,
                effect_class=effect_class,
                function=fn,
                capability=capability,
                requires=requires,
                profiles=profiles,
                order=order,
                priority=priority,
                version=version,
            )
        )
        return fn

    return wrapper


def get(name: str) -> ToolSpec:
    try:
        return _REGISTRY[name]
    except KeyError as exc:  # pragma: no cover - defensive
        raise KeyError(f"unknown tool: {name}") from exc


def all_specs() -> list[ToolSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.order, s.name))


def specs_for_profile(profile: str) -> list[ToolSpec]:
    profile = (profile or "safe").lower()
    if profile not in VALID_PROFILES:
        profile = "safe"
    if profile == "full":
        return all_specs()
    return [s for s in all_specs() if profile in s.profiles]


def capabilities() -> dict[str, list[ToolSpec]]:
    """Group every tool by its logical capability."""
    grouped: dict[str, list[ToolSpec]] = {}
    for spec in _REGISTRY.values():
        grouped.setdefault(spec.capability, []).append(spec)
    for specs in grouped.values():
        specs.sort(key=lambda s: (s.priority, s.order, s.name))
    return grouped


def is_available(spec: ToolSpec, ctx: ToolContext) -> bool:
    """Whether a tool's declared requirements are met for this target."""
    for requirement in spec.requires:
        if requirement == "base_url" and not ctx.target.base_url:
            return False
        if requirement == "host" and not ctx.target.host:
            return False
        if requirement == "hostname" and ctx.target.is_ip:
            return False
        if requirement == "services" and not ctx.option("services"):
            return False
        if requirement == "domain" and ctx.target.is_ip:
            return False
    return True


def alternatives(
    spec: ToolSpec,
    ctx: ToolContext,
    exclude: set[str] | None = None,
) -> list[ToolSpec]:
    """Other available tools that perform the same logical capability.

    Ordered by priority so the executor can try the next-best tool when the
    primary one failed or was unavailable. Tools outside the active profile are
    never offered, so redundancy never widens the scan envelope by itself.
    """
    exclude = set(exclude or set()) | {spec.name}
    profile = str(ctx.option("profile") or "safe").lower()
    allowed = {s.name for s in specs_for_profile(profile)}
    same = [s for s in capabilities().get(spec.capability, []) if s.name not in exclude]
    return [s for s in same if s.name in allowed and is_available(s, ctx)]
