"""Service-specific probes (read-only).

Each probe targets one protocol on a discovered port and records an
observation. No authentication is attempted against remote accounts and no
state is modified (Redis uses ``INFO``, MySQL/SSH/SMB only read the greeting /
negotiation, SNMP performs a single community ``GET`` for sysDescr).
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

WEAK_SSH_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_SSH_HOSTKEY = {"ssh-dss", "ssh-rsa"}


def _port_for(services: list[dict], default: int, names: set[str]) -> int | None:
    for service in services:
        label = str(service.get("service", "")).lower()
        if label in names:
            return int(service.get("port", default))
    for service in services:
        if int(service.get("port", 0)) == default:
            return default
    return None


def _read_some(sock: socket.socket, limit: int = 4096) -> bytes:
    chunks = []
    total = 0
    while total < limit:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, count: int) -> bytes | None:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_namelist(payload: bytes, offset: int) -> tuple[list[str], int]:
    (length,) = struct.unpack(">I", payload[offset : offset + 4])
    offset += 4
    raw = payload[offset : offset + length]
    offset += length
    return (raw.decode("ascii", "replace").split(",") if raw else []), offset


@tool(
    name="ssh_algorithms",
    description="SSH banner + KEX/host-key/cipher algorithms; flags weak options.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="ssh_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=52,
)
def ssh_algorithms(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 22, {"ssh"})
    if port is None:
        return ToolResult(tool="ssh_algorithms", status="skipped", summary="no SSH service found.")
    banner = ""
    body = None
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            banner = _read_some(sock, 256).decode("utf-8", "replace").strip()
            sock.sendall(b"SSH-2.0-SentinelProbe_1.0\r\n")
            header = _recv_exact(sock, 4)
            if header is not None:
                (packet_length,) = struct.unpack(">I", header)
                body = _recv_exact(sock, packet_length) if 0 < packet_length <= 35000 else None
    except OSError as exc:
        if not banner:
            return ToolResult(tool="ssh_algorithms", status="failed", summary="SSH probe did not complete.", error=type(exc).__name__)

    data: dict[str, Any] = {"banner": banner, "port": port}
    if body and body[0] not in (0,) and len(body) > 1:
        padding = body[0]
        payload = body[1 : len(body) - padding]
        if payload and payload[0] == 20:
            offset = 17
            try:
                for label in ("kex_algorithms", "server_host_key_algorithms", "encryption_c2s", "encryption_s2c", "mac_c2s", "mac_s2c"):
                    values, offset = _read_namelist(payload, offset)
                    data[label] = values
            except (IndexError, struct.error):
                pass
    weak_kex = sorted(set(data.get("kex_algorithms", [])) & WEAK_SSH_KEX)
    weak_key = sorted(set(data.get("server_host_key_algorithms", [])) & WEAK_SSH_HOSTKEY)
    data["weak_kex"] = weak_kex
    data["weak_host_keys"] = weak_key
    has_algorithms = bool(data.get("kex_algorithms") or data.get("encryption_c2s"))
    return ToolResult(
        tool="ssh_algorithms",
        status="ok" if has_algorithms else "partial",
        summary=f"SSH {banner[:40]}" + (f"; weak: {weak_kex + weak_key}" if (weak_kex or weak_key) else ""),
        data=data,
        evidence=[evidence("ssh_algorithms", f"banner={banner}"), evidence("ssh_algorithms", f"weak={weak_kex + weak_key}")],
        command=f"SSH KEXINIT {ctx.target.host}:{port}",
        note="Banner/algorithm strings are observations, not authenticated versions.",
    )


# ---------------------------------------------------------------------------
# SMTP / FTP
# ---------------------------------------------------------------------------


@tool(
    name="smtp_probe",
    description="SMTP banner and EHLO capability probe.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="smtp_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=53,
)
def smtp_probe(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 25, {"smtp", "submission"})
    if port is None:
        return ToolResult(tool="smtp_probe", status="skipped", summary="no SMTP service found.")
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            banner = _read_some(sock, 1024).decode("utf-8", "replace").strip()
            sock.sendall(b"EHLO sentinel.invalid\r\n")
            ehlo = _read_some(sock, 2048).decode("utf-8", "replace").strip()
    except OSError as exc:
        return ToolResult(tool="smtp_probe", status="failed", summary="SMTP probe did not complete.", error=type(exc).__name__)
    return ToolResult(
        tool="smtp_probe",
        status="ok",
        summary=f"SMTP banner: {banner.splitlines()[0][:60] if banner else 'none'}",
        data={"banner": banner, "ehlo": ehlo, "port": port},
        evidence=[evidence("smtp_probe", banner[:200]), evidence("smtp_probe", ehlo[:200])],
        command=f"SMTP EHLO {ctx.target.host}:{port}",
    )


@tool(
    name="ftp_probe",
    description="FTP banner and FEAT feature list.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="ftp_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=54,
)
def ftp_probe(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 21, {"ftp"})
    if port is None:
        return ToolResult(tool="ftp_probe", status="skipped", summary="no FTP service found.")
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            banner = _read_some(sock, 1024).decode("utf-8", "replace").strip()
            sock.sendall(b"FEAT\r\n")
            feat = _read_some(sock, 2048).decode("utf-8", "replace").strip()
            sock.sendall(b"QUIT\r\n")
    except OSError as exc:
        return ToolResult(tool="ftp_probe", status="failed", summary="FTP probe did not complete.", error=type(exc).__name__)
    return ToolResult(
        tool="ftp_probe",
        status="ok",
        summary=f"FTP banner: {banner.splitlines()[0][:60] if banner else 'none'}",
        data={"banner": banner, "feat": feat, "port": port},
        evidence=[evidence("ftp_probe", banner[:200]), evidence("ftp_probe", feat[:200])],
        command=f"FTP FEAT {ctx.target.host}:{port}",
        note="Cleartext protocol; no login attempted.",
    )


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------

_SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00"
    b"\x00\x62\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00"
    b"\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00"
)


@tool(
    name="smb_probe",
    description="SMB negotiation probe (dialect + signing).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="smb_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=55,
)
def smb_probe(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 445, {"microsoft-ds", "netbios-ssn", "smb"})
    if port is None:
        return ToolResult(tool="smb_probe", status="skipped", summary="no SMB service found.")
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            sock.sendall(_SMB1_NEGOTIATE)
            response = sock.recv(1024)
    except OSError as exc:
        return ToolResult(tool="smb_probe", status="failed", summary="SMB probe did not complete.", error=type(exc).__name__)

    if len(response) < 5:
        return ToolResult(tool="smb_probe", status="partial", summary="no SMB response.", data={"raw_len": len(response)})

    dialect_marker = response[4:8]
    dialect = "SMB2/3" if dialect_marker[:1] == b"\xfe" else ("SMB1" if dialect_marker[:1] == b"\xff" else "unknown")
    signing_required = False
    if dialect == "SMB1" and len(response) >= 4 + 32 + 4:
        security_mode = response[4 + 32 + 3]
        signing_required = bool(security_mode & 0x08)
    return ToolResult(
        tool="smb_probe",
        status="ok",
        summary=f"SMB responded ({dialect})" + ("; signing REQUIRED" if signing_required else ""),
        data={"dialect": dialect, "signing_required": signing_required, "port": port},
        evidence=[evidence("smb_probe", f"dialect={dialect} signing_required={signing_required}")],
        command=f"SMB negotiate {ctx.target.host}:{port}",
        note="Signing not required is a relay-risk observation, not proof of exploitability.",
    )


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


@tool(
    name="snmp_probe",
    description="SNMP v2c sysDescr probe using the 'public' community.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="snmp_info",
    requires=("host",),
    profiles=("network", "full"),
    order=56,
)
def snmp_probe(ctx: ToolContext) -> ToolResult:
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))
    varbindlist = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00") + varbindlist)
    message = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, b"public") + pdu)

    port = int(ctx.option("snmp_port", 161))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(settings.socket_timeout)
    try:
        sock.sendto(message, (ctx.target.host, port))
        response, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        response = b""
    finally:
        sock.close()

    if not response:
        return ToolResult(tool="snmp_probe", status="partial", summary="no SNMP response to community 'public'.", data={"responsive": False}, command=f"SNMP GET sysDescr {ctx.target.host}")
    printable = "".join(chr(b) if 32 <= b < 127 else " " for b in response)
    return ToolResult(
        tool="snmp_probe",
        status="ok",
        summary="SNMP agent responded to community 'public'.",
        data={"responsive": True, "response_bytes": len(response), "text": printable[:300]},
        evidence=[evidence("snmp_probe", f"responded to 'public' ({len(response)} bytes)")],
        command=f"SNMP GET sysDescr {ctx.target.host}",
        note="Default community strings are a common misconfiguration; validate manually.",
    )


# ---------------------------------------------------------------------------
# Redis / MySQL
# ---------------------------------------------------------------------------


@tool(
    name="redis_probe",
    description="Redis INFO probe for version/metadata (read-only).",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="redis_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=57,
)
def redis_probe(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 6379, {"redis"})
    if port is None:
        return ToolResult(tool="redis_probe", status="skipped", summary="no Redis service found.")
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            sock.sendall(b"INFO\r\n")
            response = _read_some(sock, 8192).decode("utf-8", "replace")
    except OSError as exc:
        return ToolResult(tool="redis_probe", status="failed", summary="Redis probe did not complete.", error=type(exc).__name__)
    if response.startswith("-NOAUTH") or response.startswith("-ERR"):
        return ToolResult(tool="redis_probe", status="ok", summary="Redis requires authentication.", data={"protected": True, "reply": response[:120]}, command=f"Redis INFO {ctx.target.host}:{port}")
    fields = {}
    for line in response.splitlines():
        if ":" in line and not line.startswith("#"):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    version = fields.get("redis_version")
    return ToolResult(
        tool="redis_probe",
        status="ok",
        summary=f"Redis {version or 'responded'} (unauthenticated INFO)",
        data={"protected": False, "version": version, "mode": fields.get("redis_mode"), "os": fields.get("os")},
        evidence=[evidence("redis_probe", f"redis_version={version}")],
        command=f"Redis INFO {ctx.target.host}:{port}",
        note="Unauthenticated INFO indicates a missing-requirepass exposure lead.",
    )


@tool(
    name="mysql_probe",
    description="MySQL/MariaDB server greeting probe.",
    category="NETWORK",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="mysql_info",
    requires=("host", "services"),
    profiles=("network", "full"),
    order=58,
)
def mysql_probe(ctx: ToolContext) -> ToolResult:
    port = _port_for(ctx.option("services") or [], 3306, {"mysql", "ms-sql"})
    if port is None:
        return ToolResult(tool="mysql_probe", status="skipped", summary="no MySQL service found.")
    try:
        with socket.create_connection((ctx.target.host, port), timeout=settings.socket_timeout) as sock:
            sock.settimeout(settings.socket_timeout)
            header = sock.recv(4)
            if len(header) < 4:
                raise OSError("short greeting")
            length = header[0] | (header[1] << 8) | (header[2] << 16)
            packet = b""
            while len(packet) < length:
                chunk = sock.recv(length - len(packet))
                if not chunk:
                    break
                packet += chunk
    except OSError as exc:
        return ToolResult(tool="mysql_probe", status="failed", summary="MySQL probe did not complete.", error=type(exc).__name__)
    if not packet or packet[0] != 0x0A:
        return ToolResult(tool="mysql_probe", status="partial", summary="unexpected greeting format.", data={"raw": packet[:40].hex()})
    end = packet.find(b"\x00", 1)
    version = packet[1:end].decode("utf-8", "replace") if end > 1 else "unknown"
    return ToolResult(
        tool="mysql_probe",
        status="ok",
        summary=f"MySQL/MariaDB greeting: {version}",
        data={"version": version, "port": port},
        evidence=[evidence("mysql_probe", f"server_version={version}")],
        command=f"MySQL greeting {ctx.target.host}:{port}",
        note="Greeting version is banner data; confirm before mapping to advisories.",
    )
