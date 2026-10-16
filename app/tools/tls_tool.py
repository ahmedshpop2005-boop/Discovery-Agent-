"""TLS posture tool.

Collects certificate and protocol observations for an authorized host:

* negotiated protocol + cipher on the target port;
* which TLS versions the endpoint still accepts (best-effort);
* certificate subject/issuer/validity/SANs and self-signed heuristic.

Everything is an observation. A certificate detail or an accepted legacy
protocol is recorded with evidence and mapped to guidance downstream.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

_LEGACY = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _ssl_context(minimum: int | None = None, maximum: int | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if minimum is not None or maximum is not None:
        context.minimum_version = minimum if minimum is not None else ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = maximum if maximum is not None else ssl.TLSVersion.MAXIMUM_SUPPORTED
    return context


def _handshake(host: str, port: int, sni: str | None) -> dict:
    with socket.create_connection((host, port), timeout=settings.socket_timeout) as raw:
        with _ssl_context().wrap_socket(raw, server_hostname=sni) as tls:
            cipher = tls.cipher()
            return {
                "protocol": tls.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
            }


def _supported_versions(host: str, port: int, sni: str | None) -> dict[str, bool]:
    versions = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    supported: dict[str, bool] = {}
    for label, version in versions.items():
        try:
            context = _ssl_context(minimum=version, maximum=version)
            with socket.create_connection((host, port), timeout=settings.socket_timeout) as raw:
                with context.wrap_socket(raw, server_hostname=sni):
                    supported[label] = True
        except (ssl.SSLError, ValueError, OSError):
            supported[label] = False
    return supported


def _certificate(host: str, port: int) -> dict | None:
    try:
        pem = ssl.get_server_certificate((host, port), timeout=settings.socket_timeout)
    except (ssl.SSLError, OSError):
        return None
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            tmp_path = Path(handle.name)
        decoded = ssl._ssl._test_decode_cert(str(tmp_path))  # type: ignore[attr-defined]
    except Exception:
        return {"parsed": False}
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    subject = dict(decoded.get("subject", ()))
    issuer = dict(decoded.get("issuer", ()))
    not_after = decoded.get("notAfter")
    return {
        "parsed": True,
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "subject": subject,
        "issuer": issuer,
        "serial_number": decoded.get("serialNumber"),
        "not_before": decoded.get("notBefore"),
        "not_after": not_after,
        "days_until_expiry": _days_until(not_after),
        "subject_alt_names": [value for _, value in decoded.get("subjectAltName", ())],
        "self_signed": subject == issuer,
    }


def _days_until(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expiry - datetime.now(timezone.utc)).days


@tool(
    name="tls_posture",
    description="TLS certificate, supported-version and cipher posture.",
    category="TLS",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="tls_info",
    priority=10,
    requires=("host",),
    profiles=("safe", "web", "network", "full"),
    order=40,
)
def tls_posture(ctx: ToolContext) -> ToolResult:
    host = ctx.target.host
    port = int(ctx.option("tls_port", ctx.target.port or 443))
    sni = None if ctx.target.is_ip else host
    started = time.perf_counter()

    try:
        negotiated = _handshake(host, port, sni)
    except (ssl.SSLError, OSError) as exc:
        return ToolResult(
            tool="tls_posture",
            status="unavailable",
            summary=f"No TLS endpoint on {host}:{port}.",
            error=type(exc).__name__,
            command=f"TLS handshake {host}:{port}",
        )

    supported = _supported_versions(host, port, sni)
    cert = _certificate(host, port)
    legacy = sorted(v for v, is_on in supported.items() if is_on and v in _LEGACY)

    duration = int((time.perf_counter() - started) * 1000)
    data = {
        "protocol": negotiated["protocol"],
        "cipher": negotiated["cipher"],
        "cipher_bits": negotiated["cipher_bits"],
        "supported_versions": supported,
        "legacy_versions": legacy,
        "certificate": cert,
        "port": port,
    }
    return ToolResult(
        tool="tls_posture",
        status="ok",
        summary=f"TLS {negotiated['protocol']} on :{port}" + (f"; legacy: {legacy}" if legacy else ""),
        data=data,
        evidence=[
            evidence("tls_posture", f"negotiated {negotiated['protocol']} / {negotiated['cipher']}"),
            evidence("tls_posture", f"supported versions: {supported}"),
        ],
        command=f"TLS handshake + version probe {host}:{port}",
        duration_ms=duration,
    )
