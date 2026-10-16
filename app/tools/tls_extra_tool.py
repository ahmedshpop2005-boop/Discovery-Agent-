"""Extra TLS tool: OpenSSL fallback for certificate/protocol posture.

Used when the Python ``ssl`` based :mod:`app.tools.tls_tool` cannot complete a
handshake (for example, exotic protocols or ciphers it will not negotiate). It
shares the ``tls_info`` capability so the executor can fall back to it.
"""

from __future__ import annotations

import re

from app.tools.base import (
    EffectClass,
    ToolContext,
    ToolResult,
    evidence,
    run_command,
    unavailable,
    which,
)
from app.tools.registry import tool

_PROTOCOL_RE = re.compile(r"Protocol\s*:\s*(\S+)")
_CIPHER_RE = re.compile(r"Cipher\s*:\s*(\S+)")
_FIELD_RE = {
    "subject": re.compile(r"subject=(.+)"),
    "issuer": re.compile(r"issuer=(.+)"),
    "not_before": re.compile(r"notBefore=(.+)"),
    "not_after": re.compile(r"notAfter=(.+)"),
}
_VERIFY_RE = re.compile(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)")
_SAN_RE = re.compile(r"DNS:([A-Za-z0-9.*-]+)")


@tool(
    name="tls_openssl",
    description="TLS certificate/protocol posture via the openssl binary (fallback).",
    category="TLS",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="tls_info",
    priority=20,
    requires=("host",),
    profiles=("safe", "web", "network", "full"),
    order=41,
)
def tls_openssl(ctx: ToolContext) -> ToolResult:
    binary = which("openssl")
    if binary is None:
        return unavailable("openssl", "openssl is not installed.", command="openssl s_client")
    host = ctx.target.host
    port = int(ctx.option("tls_port", ctx.target.port or 443))
    sni = "" if ctx.target.is_ip else host
    command = [binary, "s_client", "-connect", f"{host}:{port}", "-servername", sni or host, "-showcerts"]
    read_text = f"openssl s_client -connect {host}:{port} -servername {sni or host}"
    try:
        proc = run_command(command, timeout=20, input_text="")
    except Exception as exc:
        return ToolResult(tool="tls_openssl", status="failed", summary="openssl handshake did not complete.", error=type(exc).__name__, command=read_text)

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    protocol = _match(_PROTOCOL_RE, output)
    cipher = _match(_CIPHER_RE, output)
    if not protocol and not cipher:
        return ToolResult(tool="tls_openssl", status="unavailable", summary=f"No TLS endpoint on {host}:{port}.", command=read_text)

    cert = {name: _match(regex, output) for name, regex in _FIELD_RE.items()}
    verify = _VERIFY_RE.search(output)
    sans = sorted(set(_SAN_RE.findall(output)))
    cert["subject_alt_names"] = sans
    cert["verify_code"] = verify.group(1) if verify else None
    cert["verify_message"] = verify.group(2) if verify else None

    return ToolResult(
        tool="tls_openssl",
        status="ok",
        summary=f"TLS {protocol or '?'} / {cipher or '?'} on :{port}",
        data={"protocol": protocol, "cipher": cipher, "certificate": cert, "port": port},
        evidence=[evidence("tls_openssl", f"{protocol} / {cipher}"), evidence("tls_openssl", f"verify={cert.get('verify_message')}")],
        command=read_text,
    )


def _match(regex: re.Pattern, text: str) -> str | None:
    match = regex.search(text)
    return match.group(1).strip() if match else None
