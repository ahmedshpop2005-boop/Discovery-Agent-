"""Authorization guard and target normalization.

The first workflow node. It enforces the human authorization acknowledgement
and validates/normalizes the target before any network activity. Untrusted
text (including injection-style input) can never become a target.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import re

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_ALLOWED_SCHEMES = {"http", "https"}


class AuthorizationError(ValueError):
    """Raised when a target is missing, malformed or not authorized."""


@dataclass(frozen=True)
class Target:
    """A validated, normalized assessment target."""

    raw: str
    scheme: str
    host: str
    port: int | None
    base_url: str

    @property
    def is_ip(self) -> bool:
        return bool(_IPV4_RE.match(self.host))

    @property
    def default_tls_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if any(part == "" for part in host.split(".")):
        return False
    if "_" in host:  # underscores are not valid in public DNS hostnames
        return False
    return bool(_HOSTNAME_RE.match(host))


def normalize_target(value: str) -> Target:
    """Validate and normalize a user-supplied target.

    Accepts an ``http(s)://`` URL, a bare hostname/IP, or ``host:port``.
    Raises :class:`AuthorizationError` for anything else.
    """
    raw = (value or "").strip()
    if not raw:
        raise AuthorizationError("A target is required.")
    if any(ch.isspace() for ch in raw):
        raise AuthorizationError("The target must not contain whitespace.")

    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise AuthorizationError("Only http and https targets are supported.")
    if parsed.username or parsed.password:
        raise AuthorizationError("Credentials must not be embedded in the target URL.")

    host = (parsed.hostname or "").lower()
    if not host:
        raise AuthorizationError("Enter a valid HTTP(S) URL, hostname or IP address.")
    if not (_is_valid_hostname(host) or _IPV4_RE.match(host)):
        raise AuthorizationError("The target hostname contains unsupported characters.")

    try:
        port = parsed.port
    except ValueError as exc:  # invalid port in URL
        raise AuthorizationError(f"Invalid port in target: {exc}") from exc

    netloc = host if port is None else f"{host}:{port}"
    base_url = f"{parsed.scheme}://{netloc}"
    return Target(raw=raw, scheme=parsed.scheme, host=host, port=port, base_url=base_url)


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    target: Target | None = None
    error: str | None = None


def authorize(target_value: str, consent: bool) -> GuardResult:
    """Full authorization decision.

    ``consent`` is the explicit human acknowledgement that they are authorized
    to assess the target. No consent means the run is blocked before any tool
    is dispatched.
    """
    if not consent:
        return GuardResult(
            ok=False,
            error="Authorization acknowledgement is required before any assessment.",
        )
    try:
        return GuardResult(ok=True, target=normalize_target(target_value))
    except AuthorizationError as exc:
        return GuardResult(ok=False, error=str(exc))
