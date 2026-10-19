import app.tools  # noqa: F401  (register tools)
from app.safety.authorization import normalize_target
from app.tools.base import ToolContext
from app.tools.registry import (
    all_specs,
    alternatives,
    capabilities,
    get,
    is_available,
    specs_for_profile,
)


def test_expected_tools_registered():
    names = {spec.name for spec in all_specs()}
    assert {
        "nmap_discovery",
        "tcp_scan",
        "masscan_scan",
        "host_alive",
        "udp_scan",
        "traceroute",
        "dns_recon",
        "dns_nslookup",
        "reverse_dns",
        "dns_zone_transfer",
        "http_posture",
        "http_curl",
        "http_favicon",
        "http_waf_detect",
        "tls_posture",
        "tls_openssl",
        "service_banner",
        "ssh_algorithms",
        "smtp_probe",
        "ftp_probe",
        "smb_probe",
        "snmp_probe",
        "redis_probe",
        "mysql_probe",
        "advisory_match",
        "web_content",
        "whois_lookup",
        "subdomain_enum",
        # external recon tools
        "amass_enum",
        "theharvester",
        "dnsrecon",
        "netdiscover",
        "whatweb",
        "gobuster_scan",
        "wafw00f",
        "enum4linux_ng",
    } <= names


def test_redundant_capabilities_have_multiple_tools():
    caps = capabilities()
    assert {"http_posture", "http_curl"} <= {s.name for s in caps["http_headers"]}
    assert {"tls_posture", "tls_openssl"} <= {s.name for s in caps["tls_info"]}
    assert {"dns_recon", "dns_nslookup"} <= {s.name for s in caps["dns_resolve"]}
    assert {"nmap_discovery", "tcp_scan"} <= {s.name for s in caps["port_discovery"]}
    # external tools share a capability with a pure-Python fallback
    assert {"subdomain_enum", "amass_enum"} <= {s.name for s in caps["subdomain"]}
    assert {"host_alive", "netdiscover"} <= {s.name for s in caps["host_discovery"]}
    assert {"web_content", "gobuster_scan"} <= {s.name for s in caps["web_content"]}
    assert {"smb_probe", "enum4linux_ng"} <= {s.name for s in caps["smb_info"]}
    assert {"http_waf_detect", "wafw00f"} <= {s.name for s in caps["http_waf_detect"]}


def test_external_primary_tools_rank_before_fallbacks():
    caps = capabilities()
    assert caps["subdomain"][0].name == "amass_enum"
    assert caps["smb_info"][0].name == "enum4linux_ng"
    assert caps["http_waf_detect"][0].name == "wafw00f"


def test_alternatives_respect_profile_boundaries():
    spec = get("nmap_discovery")
    target = normalize_target("https://example.com")
    safe_ctx = ToolContext(target=target, scan_id="t", options={"profile": "safe"})
    safe_names = {s.name for s in alternatives(spec, safe_ctx)}
    assert "tcp_scan" in safe_names
    assert "masscan_scan" not in safe_names  # network/full only

    full_ctx = ToolContext(target=target, scan_id="t", options={"profile": "full"})
    assert "masscan_scan" in {s.name for s in alternatives(spec, full_ctx)}


def test_safe_profile_selection():
    names = {spec.name for spec in specs_for_profile("safe")}
    assert {"nmap_discovery", "tcp_scan", "http_posture", "tls_posture", "dns_recon"} <= names
    # web_content is a web/full tool and must not appear in the safe profile
    assert "web_content" not in names


def test_full_profile_includes_all():
    assert len(specs_for_profile("full")) == len(all_specs())


def test_unknown_tool_raises():
    try:
        get("does_not_exist")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_availability_requirements():
    target = normalize_target("https://example.com")
    ctx = ToolContext(target=target, scan_id="t", options={})
    # dns/whois require a hostname and are available for a domain
    assert is_available(get("dns_recon"), ctx) is True
    # service_banner requires discovered services
    assert is_available(get("service_banner"), ctx) is False
    ctx.options["services"] = [{"port": 22}]
    assert is_available(get("service_banner"), ctx) is True


def test_ip_target_skips_hostname_tools():
    target = normalize_target("10.0.0.1")
    ctx = ToolContext(target=target, scan_id="t", options={})
    assert is_available(get("dns_recon"), ctx) is False
    assert is_available(get("whois_lookup"), ctx) is False
