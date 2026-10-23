"""Normalise technology fingerprints into honest observations.

Fingerprints come from untrusted, unauthenticated sources (HTTP headers, HTML,
JavaScript, banners, WhatWeb). This module:

* validates that a candidate really looks like a software version;
* rejects IPs, country names, MIME types and header directives;
* keeps the rejected candidate in the evidence instead of dropping it;
* marks every HTML/JS/banner/header version as ``version_claimed`` and
  ``unverified`` - package verification requires authenticated evidence;
* merges duplicate technologies and records conflicting versions explicitly.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from app.contracts.discovery import TechnologyRecord, Uncertainty
from app.contracts.enums import (
    ConfidenceLevel,
    ObservationBasis,
    TechnologyObservationType,
    VerificationStatus,
)

_COUNTRY_NAMES = {
    "united states",
    "united kingdom",
    "netherlands",
    "germany",
    "france",
    "ireland",
    "singapore",
    "japan",
    "china",
    "india",
    "canada",
    "australia",
    "brazil",
    "russia",
}

_NON_TECHNOLOGY_NAMES = {
    "country",
    "ip",
    "script",
    "title",
    "email",
    "phone",
    "cookie",
    "robots.txt",
    "redirect",
    "httpvhost",
    "meta-author",
}

_NON_VERSION_TOKENS = {
    "none",
    "null",
    "true",
    "false",
    "unknown",
    "detected",
    "enabled",
    "disabled",
    "cloudflare",
    "akamai",
    "cloudfront",
    "fastly",
    "imperva",
    "sucuri",
}

_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-_.+~]?[A-Za-z][A-Za-z0-9]*)?$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_CANONICAL_NAMES = {
    "jquery": "jQuery",
    "wordpress": "WordPress",
    "php": "PHP",
    "apache": "Apache",
    "nginx": "nginx",
    "openssl": "OpenSSL",
    "iis": "IIS",
    "microsoft-iis": "IIS",
    "asp.net": "ASP.NET",
    "bootstrap": "Bootstrap",
    "react": "React",
    "vue": "Vue.js",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "cloudflare": "Cloudflare",
}

_STRIP_PREFIXES = (
    "server:",
    "x-powered-by:",
    "meta generator:",
    "x-generator:",
    "x-aspnet-version:",
    "x-drupal-cache:",
    "x-shopify-stage:",
)


def _canonical_name(value: str) -> str:
    name = (value or "").strip().strip("\"'")
    lowered = name.lower()
    for prefix in _STRIP_PREFIXES:
        if lowered.startswith(prefix):
            name = name[len(prefix) :].strip()
            lowered = name.lower()
            break
    return _CANONICAL_NAMES.get(lowered, name)


def is_plausible_version(value: str | None, *, name: str = "") -> bool:
    """Return ``True`` only for values that can reasonably be a version."""
    if value is None:
        return False
    candidate = str(value).strip().strip("\"'")
    if not candidate or len(candidate) > 48:
        return False
    lowered = candidate.lower()
    if lowered in _NON_VERSION_TOKENS or lowered in _COUNTRY_NAMES:
        return False
    if name and lowered == name.strip().lower():
        return False
    if not any(char.isdigit() for char in candidate):
        return False
    if any(char.isspace() for char in candidate):
        return False
    if any(token in candidate for token in ("=", ";", ",", "/", "\\", "://")):
        return False
    if candidate.startswith(("http", "www.")):
        return False
    if _IPV4_RE.match(candidate):
        return False
    try:
        ipaddress.ip_address(candidate)
        return False
    except ValueError:
        pass
    return bool(_VERSION_RE.match(candidate))


def _observation_type(method: str, has_version: bool) -> TechnologyObservationType:
    method = (method or "").lower()
    if not has_version:
        return TechnologyObservationType.FINGERPRINT_OBSERVED
    if method in {"header", "headers", "banner", "server"}:
        return TechnologyObservationType.BANNER_OBSERVED
    return TechnologyObservationType.VERSION_CLAIMED


def _confidence(method: str, has_version: bool) -> ConfidenceLevel:
    method = (method or "").lower()
    if has_version:
        return ConfidenceLevel.LOW
    if method in {"header", "headers", "banner", "server"}:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def normalize_technologies(
    observations: list[dict],
    *,
    observed_at: datetime | None = None,
    source_url: str | None = None,
) -> tuple[list[TechnologyRecord], list[Uncertainty]]:
    """Normalise raw ``{name, version, source, method}`` observations.

    Returns the deduplicated records plus explicit uncertainties for every
    rejected candidate version and every version conflict.
    """
    grouped: dict[str, list[TechnologyRecord]] = {}
    uncertainties: list[Uncertainty] = []

    for raw in observations or []:
        name = _canonical_name(str(raw.get("name") or ""))
        if not name or name.lower() in {"unknown", "server", "http server"}:
            continue
        if name.lower() in _NON_TECHNOLOGY_NAMES:
            continue
        candidate = raw.get("version")
        candidate_text = str(candidate).strip() if candidate not in (None, "") else None
        method = str(raw.get("method") or raw.get("source") or "fingerprint")
        source = str(raw.get("source") or method)
        tool = str(raw.get("tool") or source).split(":")[0]
        evidence = [str(item) for item in (raw.get("evidence") or [])]
        record_source_url = raw.get("source_url") or source_url
        basis = raw.get("basis") or (
            ObservationBasis.BANNER if method in {"header", "headers", "banner", "server"} else ObservationBasis.INFERRED
        )

        accepted = is_plausible_version(candidate_text, name=name)
        if candidate_text and not accepted:
            evidence.append(
                f"{source}: candidate version '{candidate_text}' rejected as non-version metadata"
            )
            uncertainties.append(
                Uncertainty(
                    subject=f"tech:{name}",
                    detail=(
                        f"value '{candidate_text}' from {source} is not a plausible software version; "
                        "it was retained as evidence but not reported as a version"
                    ),
                    evidence_refs=[f"prov:{tool}"],
                )
            )

        version = candidate_text if accepted else None
        evidence.append(f"{source}: {name}" + (f" {version}" if version else " (no verified version)"))
        record = TechnologyRecord(
            name=name,
            version=version,
            observation_type=_observation_type(method, bool(version)),
            verification_status=VerificationStatus.UNVERIFIED,
            confidence=_confidence(method, bool(version)),
            basis=basis,
            evidence=evidence,
            source_url=record_source_url,
            collection_method=method,
            observed_at=raw.get("observed_at") or observed_at,
            evidence_refs=[f"prov:{tool}"],
        )
        grouped.setdefault(name.lower(), []).append(record)

    records: list[TechnologyRecord] = []
    for _key, group in sorted(grouped.items()):
        versions = sorted({rec.version for rec in group if rec.version})
        chosen = max(
            group,
            key=lambda rec: (
                _confidence_rank(rec.confidence),
                bool(rec.version),
                len(rec.evidence),
            ),
        )
        if len(versions) > 1:
            chosen = chosen.model_copy(
                update={
                    "conflicting_versions": [value for value in versions if value != chosen.version],
                    "confidence": ConfidenceLevel.LOW,
                    "verification_status": VerificationStatus.UNVERIFIED,
                    "evidence": chosen.evidence
                    + [f"conflicting versions observed: {', '.join(versions)}"],
                }
            )
            uncertainties.append(
                Uncertainty(
                    subject=f"tech:{chosen.name}",
                    detail=(
                        f"conflicting versions observed for {chosen.name}: {', '.join(versions)}; "
                        "none is verified, the highest-confidence observation is shown"
                    ),
                    evidence_refs=chosen.evidence_refs,
                )
            )
        # Merge evidence from duplicate observations of the same technology.
        merged_evidence: list[str] = []
        for rec in group:
            for item in rec.evidence:
                if item not in merged_evidence:
                    merged_evidence.append(item)
        chosen = chosen.model_copy(update={"evidence": merged_evidence})
        records.append(chosen)

    return records, uncertainties


def _confidence_rank(value: ConfidenceLevel) -> int:
    return {
        ConfidenceLevel.HIGH: 3,
        ConfidenceLevel.MEDIUM: 2,
        ConfidenceLevel.LOW: 1,
        ConfidenceLevel.UNKNOWN: 0,
    }.get(value, 0)
