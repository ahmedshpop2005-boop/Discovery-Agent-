"""Pydantic record types used across tools, the agent and reporting.

Typed models are the contract between layers. Tool functions return dicts for
easy serialisation through LangGraph state, but every finding is validated
through :class:`Finding` before it is shown or exported.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    OBSERVED = "Observed"
    POTENTIAL = "Potential"
    NEEDS_VALIDATION = "Needs validation"


class ToolStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class EvidenceItem(BaseModel):
    """A single sourced observation supporting a finding."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="Tool or file the observation came from.")
    detail: str = Field(description="Concrete observed value, no interpretation.")
    raw: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """An evidence-backed security observation.

    The reference rule stands: a finding is only ``Confirmed`` when a concrete
    observation exists; otherwise it is ``Potential`` / ``Needs validation``.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    category: str = "General"
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.OBSERVED
    asset: str | None = None
    evidence: EvidenceItem
    remediation: str = ""
    query: str = ""
    references: list[dict[str, str]] = Field(default_factory=list)
    source_tool: str = ""

    def to_view(self) -> dict[str, Any]:
        """Serialise for the template/report (enums to plain strings)."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "asset": self.asset,
            "evidence": self.evidence.model_dump(),
            "remediation": self.remediation,
            "query": self.query,
            "references": self.references,
            "source_tool": self.source_tool,
        }
