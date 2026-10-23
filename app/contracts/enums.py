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


class TechnologyObservationType(str, Enum):
    """How a technology/version was obtained.

    Only ``VERSION_VERIFIED`` (independent validation) and
    ``PACKAGE_VERIFIED`` (authenticated package inventory) may ever be
    presented as verified; everything derived from HTML, JavaScript, banners
    or HTTP headers stays a claim/fingerprint.
    """

    FINGERPRINT_OBSERVED = "fingerprint_observed"
    BANNER_OBSERVED = "banner_observed"
    VERSION_CLAIMED = "version_claimed"
    VERSION_VERIFIED = "version_verified"
    PACKAGE_VERIFIED = "package_verified"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    PACKAGE_VERIFIED = "package_verified"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ResponseClass(str, Enum):
    """Deterministic classification of an HTTP exchange."""

    SUCCESS = "success"
    REDIRECT = "redirect"
    AUTH_REQUIRED = "auth_required"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    TIMEOUT = "timeout"
    DNS_FAILURE = "dns_failure"
    TLS_ERROR = "tls_error"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN = "unknown"


class CoverageStatus(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    LIMITED = "limited"
    UNKNOWN = "unknown"


class OverallStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
