"""Tool base types.

A tool is a *real, non-destructive* collection action. Every tool returns a
:class:`ToolResult` with a status that distinguishes success, partial data,
unavailable tooling and failure. A failure is never reported as "secure".
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from app.config import settings
from app.models.schemas import ToolStatus
from app.safety.authorization import Target
from app.safety.redaction import redact, redact_mapping


@dataclass
class EffectClass:
    READ_ONLY = "READ_ONLY"
    PASSIVE = "PASSIVE"
    ACTIVE_PROBE = "ACTIVE_PROBE"


@dataclass
class ToolContext:
    """Everything a tool needs, assembled by the executor.

    ``options`` carries per-run knobs (ports, limits) so tools stay pure.
    """

    target: Target
    scan_id: str
    options: dict[str, Any] = field(default_factory=dict)

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)


@dataclass
class ToolResult:
    tool: str
    status: str  # ToolStatus value
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    command: str | None = None
    note: str | None = None
    error: str | None = None
    duration_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["data"] = redact_mapping(payload.get("data") or {})
        payload["summary"] = redact(payload.get("summary") or "")
        if payload.get("error"):
            payload["error"] = redact(payload["error"])
        return payload

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.OK.value


def which(binary: str) -> str | None:
    return shutil.which(binary)


def run_command(
    args: list[str],
    *,
    timeout: float,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a native binary without a shell (no injection surface)."""
    return subprocess.run(  # noqa: S603 - list args, no shell
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
        encoding="utf-8",
        errors="replace",
    )


def unavailable(tool: str, summary: str, *, command: str | None = None) -> ToolResult:
    return ToolResult(tool=tool, status=ToolStatus.UNAVAILABLE.value, summary=summary, command=command)


def failure(tool: str, error: str, *, command: str | None = None) -> ToolResult:
    return ToolResult(
        tool=tool,
        status=ToolStatus.FAILED.value,
        summary="Collection did not complete.",
        error=redact(error),
        command=command,
    )


def evidence(source: str, detail: str, **raw: Any) -> dict[str, Any]:
    return {"source": source, "detail": redact(detail), "raw": redact_mapping(raw)}


DEFAULT_TIMEOUT = settings.socket_timeout
