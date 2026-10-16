import app.tools  # noqa: F401
from app.safety.authorization import normalize_target
from app.tools.base import ToolContext
from app.tools.registry import get


def _ctx(target, **options):
    return ToolContext(target=normalize_target(target), scan_id="test", options=options)


def test_tcp_scan_finds_open_local_port(open_tcp_port):
    ctx = _ctx("127.0.0.1", tcp_ports=[open_tcp_port], tcp_concurrency=10)
    result = get("tcp_scan").function(ctx)
    assert result.status == "ok"
    ports = {p["port"] for p in result.data["ports"]}
    assert open_tcp_port in ports


def test_tcp_scan_reports_no_open_port_when_closed():
    # 1 is a reserved port; connection should be refused quickly.
    ctx = _ctx("127.0.0.1", tcp_ports=[1], tcp_timeout=1)
    result = get("tcp_scan").function(ctx)
    assert result.status == "ok"
    assert result.data["ports"] == []


def test_tls_unavailable_on_plain_http(local_http_server):
    base_url, _host, _port = local_http_server
    result = get("tls_posture").function(_ctx(base_url))
    assert result.status == "unavailable"


def test_http_posture_collects_headers_and_cookies(local_http_server):
    base_url, _host, _port = local_http_server
    result = get("http_posture").function(_ctx(base_url))
    assert result.status == "ok"
    data = result.data
    assert data["http_status"] == 200
    assert "content-security-policy" in data["missing_headers"]
    assert any(c["name"] == "session" and not c["secure"] for c in data["cookies"])
    assert "TRACE" in (data["methods"] or "")


def test_web_content_retrieves_robots(local_http_server):
    base_url, _host, _port = local_http_server
    result = get("web_content").function(_ctx(base_url))
    assert result.status == "ok"
    robots = result.data["found"].get("/robots.txt")
    assert robots is not None
    assert "/admin" in robots["disallow"]


def test_nmap_reports_unavailable_without_binary():
    result = get("nmap_discovery").function(_ctx("127.0.0.1"))
    assert result.status == "unavailable"


def test_service_banner_reads_local_banner(banner_server):
    ctx = _ctx("127.0.0.1", services=[{"port": banner_server}])
    result = get("service_banner").function(ctx)
    assert result.status == "ok"
    assert "OpenSSH" in result.data["banners"][str(banner_server)]


def test_http_curl_alternative_returns_status(local_http_server):
    base_url, _host, _port = local_http_server
    result = get("http_curl").function(_ctx(base_url))
    assert result.status == "ok"
    assert "200" in result.data["status_line"]


def test_ssh_algorithms_reads_banner(banner_server):
    ctx = _ctx("127.0.0.1", services=[{"port": banner_server, "service": "ssh"}])
    result = get("ssh_algorithms").function(ctx)
    assert result.status in {"ok", "partial"}
    assert "OpenSSH" in result.data.get("banner", "")


def test_advisory_match_flags_known_vulnerable_version():
    ctx = _ctx(
        "127.0.0.1",
        services=[{"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"}],
    )
    result = get("advisory_match").function(ctx)
    assert result.status == "ok"
    assert "CVE-2021-41773" in {match["cve"] for match in result.data["matches"]}


def test_advisory_match_no_match_for_patched_version():
    ctx = _ctx(
        "127.0.0.1",
        services=[{"port": 80, "product": "Apache httpd", "version": "2.4.60"}],
    )
    result = get("advisory_match").function(ctx)
    assert result.data["matches"] == []


def test_tls_name_dict_handles_flat_and_nested_layouts():
    from app.tools.tls_tool import _name_dict

    flat = (("commonName", "example.com"), ("countryName", "US"))
    nested = ((("commonName", "example.com"),), (("countryName", "US"),))
    expected = {"commonName": "example.com", "countryName": "US"}
    assert _name_dict(flat) == expected
    assert _name_dict(nested) == expected
    assert _name_dict(()) == {}

