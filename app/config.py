"""Runtime configuration for AutoPentest Sentinel.

Values are intentionally conservative. Every network-facing default is chosen
to keep the safe profile non-destructive and rate-conscious.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_name: str = "AutoPentest Sentinel"
    version: str = "2.0.0"

    # Filesystem
    reports_dir: Path = ROOT / "reports"
    knowledge_dir: Path = ROOT / "data" / "knowledge"
    wordlist_dir: Path = ROOT / "data" / "wordlists"

    # Network behaviour
    http_timeout: float = _env_float("APS_HTTP_TIMEOUT", 12.0)
    socket_timeout: float = _env_float("APS_SOCKET_TIMEOUT", 6.0)
    nmap_timeout: float = _env_float("APS_NMAP_TIMEOUT", 120.0)

    # Scan envelopes (safe defaults)
    tcp_scan_max_ports: int = _env_int("APS_TCP_SCAN_MAX_PORTS", 1024)
    tcp_scan_concurrency: int = _env_int("APS_TCP_SCAN_CONCURRENCY", 200)
    subdomain_limit: int = _env_int("APS_SUBDOMAIN_LIMIT", 60)
    aggressive_ports: int = _env_int("APS_AGGRESSIVE_TOP_PORTS", 1000)

    # Filesystem-managed options
    write_evidence: bool = os.getenv("APS_WRITE_EVIDENCE", "0") == "1"

    @property
    def user_agent(self) -> str:
        return f"AutoPentestSentinel/{self.version} (+authorized-assessment; non-destructive)"


settings = Settings()
