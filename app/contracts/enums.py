"""Enumerations for the SentinelX agent contracts.

These mirror the vocabulary in *SentinelX AI — Shared Agent Contracts v1.0*
(status values, environment kinds, gates, observation basis). Keeping them as
enums means invalid values are rejected at validation time.
"""

from __future__ import annotations

from enum import Enum


class AgentStatus(str, Enum):
    """Lifecycle status of a role task (common output ``status``)."""

    DONE = "DONE"
    MORE_WORK = "MORE_WORK"
    BLOCKED = "BLOCKED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"


class EnvironmentKind(str, Enum):
    REAL = "REAL"
    TWIN = "TWIN"


class RequiredGate(str, Enum):
    """External gate a result is waiting on, or ``None`` when none is needed."""

    INPUT = "INPUT"
    AUTHORIZATION = "AUTHORIZATION"
    APPROVAL = "APPROVAL"
    REVIEW = "REVIEW"


class Reachability(str, Enum):
    REACHABLE = "REACHABLE"
    FILTERED = "FILTERED"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class ObservationBasis(str, Enum):
    """How an observation was obtained.

    ``BANNER`` means an advertised/unauthenticated string. It must not be
    treated as authenticated package evidence (see the Networking example:
    "Label the version as a banner observation until authenticated package
    evidence supports it").
    """

    BANNER = "banner"
    AUTHENTICATED_PACKAGE = "authenticated-package"
    CONFIGURATION = "configuration"
    INFERRED = "inferred"


class RelationshipKind(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
