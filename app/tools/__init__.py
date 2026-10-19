"""Collection tools.

Importing this package registers every tool. Keep the imports explicit so the
registry is deterministic.
"""

from app.tools import (  # noqa: F401  (import for registration side effect)
    advisory_tool,
    banner_tool,
    dns_extra_tool,
    dns_tool,
    http_extra_tool,
    http_tool,
    network_extra_tool,
    nmap_tool,
    osint_extra_tool,
    paths_tool,
    service_probes_tool,
    smb_extra_tool,
    subdomain_tool,
    tcp_scan_tool,
    tls_extra_tool,
    tls_tool,
    webscan_extra_tool,
    whois_tool,
)
from app.tools.registry import (
    ToolSpec,
    all_specs,
    alternatives,
    capabilities,
    get,
    is_available,
    specs_for_profile,
)

__all__ = [
    "ToolSpec",
    "all_specs",
    "alternatives",
    "capabilities",
    "get",
    "is_available",
    "specs_for_profile",
]
