"""Runtime configuration for AutoPentest Sentinel.

Values are intentionally conservative. Every network-facing default is chosen
to keep the safe profile non-destructive and rate-conscious.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    """Load ``ROOT/.env`` into the environment without overwriting real vars.

    Dependency-free helper so an optional ``.env`` file can carry the LLM API
    key during local development. Absent file is a no-op.
    """
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


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


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


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

    # Bounded HTTP retries (transient failures only; 401/403/404 never retried)
    http_retries: int = _env_int("APS_HTTP_RETRIES", 2)
    http_retry_backoff: float = _env_float("APS_HTTP_RETRY_BACKOFF", 0.3)
    http_retry_max_backoff: float = _env_float("APS_HTTP_RETRY_MAX_BACKOFF", 4.0)
    http_retry_jitter: float = _env_float("APS_HTTP_RETRY_JITTER", 0.2)

    # Scan envelopes (safe defaults)
    tcp_scan_max_ports: int = _env_int("APS_TCP_SCAN_MAX_PORTS", 1024)
    tcp_scan_concurrency: int = _env_int("APS_TCP_SCAN_CONCURRENCY", 200)
    subdomain_limit: int = _env_int("APS_SUBDOMAIN_LIMIT", 60)
    aggressive_ports: int = _env_int("APS_AGGRESSIVE_TOP_PORTS", 1000)

    # Filesystem-managed options
    write_evidence: bool = os.getenv("APS_WRITE_EVIDENCE", "0") == "1"

    # Optional LLM reasoning (OpenAI-compatible). Disabled when no key is set,
    # so the agent runs fully deterministically/offline by default.
    llm_api_key: str = _env_str("APS_LLM_API_KEY") or _env_str("OPENAI_API_KEY")
    llm_base_url: str = os.getenv("APS_LLM_BASE_URL", "https://api.openai.com/v1")
    llm_model: str = os.getenv("APS_LLM_MODEL", "gpt-4o-mini")
    llm_timeout: float = _env_float("APS_LLM_TIMEOUT", 30.0)
    llm_retries: int = _env_int("APS_LLM_RETRIES", 2)

    # Optional secondary provider (e.g. a local Ollama) used when the primary
    # provider is unreachable or overloaded. Enabled when its base URL is set.
    llm_fallback_api_key: str = _env_str("APS_LLM_FALLBACK_API_KEY")
    llm_fallback_base_url: str = _env_str("APS_LLM_FALLBACK_BASE_URL")
    llm_fallback_model: str = _env_str("APS_LLM_FALLBACK_MODEL", "llama3.2")

    @property
    def user_agent(self) -> str:
        return f"AutoPentestSentinel/{self.version} (+authorized-assessment; non-destructive)"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)


settings = Settings()
