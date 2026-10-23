"""Web surface (WEB EXTENSION 02) inventory and profile separation tests."""

from __future__ import annotations

from datetime import datetime, timezone

import app.tools  # noqa: F401  (register tools)
from app.agents.graph import run_assessment
from app.agents.web_inventory import build_web_inventory
from app.contracts import default_discovery_input
from app.tools.http_tool import _extract_forms, _extract_links
from app.tools.registry import specs_for_profile


def _state() -> dict:
    return {
        "host": "app.example.com",
        "base_url": "https://app.example.com",
        "executed": [
            "http_posture",
            "whatweb",
            "web_content",
            "gobuster_scan",
            "wafw00f",
            "tls_posture",
        ],
        "results": {
            "http_posture": {
                "status": "ok",
                "command": "GET https://app.example.com",
                "evidence": [{"source": "http_posture", "detail": "HTTP 200"}],
                "data": {
                    "http_status": 200,
                    "title": "Acme Portal",
                    "headers": {"server": "nginx/1.25.3"},
                    "technology": [
                        "Server: nginx/1.25.3",
                        "X-Powered-By: Express",
                        "meta generator: WordPress 6.4",
                    ],
                    "missing_headers": ["content-security-policy"],
                    "present_headers": ["strict-transport-security"],
                    "cookies": [
                        {"name": "sid", "secure": False, "httponly": True, "samesite": "Lax"}
                    ],
                    "methods": "GET, POST",
                    "cors": {"allow_origin": "https://sentinel.invalid", "credentials": None},
                    "forms": [
                        {
                            "action": "/session",
                            "method": "POST",
                            "parameters": ["username", "password"],
                        }
                    ],
                    "links": ["/account/1", "/api/users"],
                    "scripts": ["/static/app.js"],
                    "api_hints": ["/api/v1/users"],
                    "external_links": 2,
                    "www_authenticate": None,
                },
            },
            "whatweb": {
                "status": "ok",
                "command": "whatweb",
                "evidence": [],
                "data": {
                    "plugins": {
                        "nginx": {"version": "1.25.3"},
                        "Express": {},
                        "WordPress": {"version": "6.4"},
                    },
                    "targets": ["https://app.example.com"],
                },
            },
            "web_content": {
                "status": "ok",
                "command": "GET robots",
                "evidence": [],
                "data": {
                    "found": {
                        "/robots.txt": {
                            "status": 200,
                            "size": 41,
                            "disallow": ["/admin"],
                            "sitemaps": [],
                        },
                        "/.well-known/security.txt": {"status": 200, "size": 10, "fields": []},
                    }
                },
            },
            "gobuster_scan": {
                "status": "ok",
                "command": "gobuster",
                "evidence": [],
                "data": {"paths": [{"path": "/login", "status": 200, "size": 1}], "tested": 42},
            },
            "wafw00f": {
                "status": "ok",
                "command": "wafw00f",
                "evidence": [],
                "data": {"detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare"},
            },
            "tls_posture": {
                "status": "ok",
                "command": "tls",
                "evidence": [],
                "data": {
                    "protocol": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "legacy_versions": [],
                    "port": 443,
                    "certificate": {
                        "subject_common_name": "app.example.com",
                        "issuer_common_name": "R3",
                        "not_after": "Dec 31 23:59:59 2027 GMT",
                        "self_signed": False,
                    },
                },
            },
        },
    }


def test_web_inventory_applications_and_versions():
    inp = default_discovery_input("https://app.example.com", consent=True)
    inventory = build_web_inventory(_state(), inp, datetime.now(timezone.utc))

    assert len(inventory.applications) == 1
    app = inventory.applications[0]
    assert app.origin == "https://app.example.com"
    assert app.title == "Acme Portal"
    assert app.server == "nginx/1.25.3"
    assert app.waf == "Cloudflare"
    tech = {t.name: t.version for t in app.technologies}
    assert tech["nginx"] == "1.25.3"
    assert tech["WordPress"] == "6.4"
    assert "Express" in tech


def test_web_inventory_endpoints_observed_vs_declared():
    inp = default_discovery_input("https://app.example.com", consent=True)
    inventory = build_web_inventory(_state(), inp, datetime.now(timezone.utc))
    routes = {(e.method, e.path): e for e in inventory.endpoints}

    assert ("GET", "/") in routes and routes[("GET", "/")].observed
    assert ("POST", "/session") in routes
    assert routes[("POST", "/session")].parameters == ["password", "username"]
    assert routes[("POST", "/session")].forms
    assert ("GET", "/login") in routes and routes[("GET", "/login")].observed
    admin = routes[("GET", "/admin")]
    assert admin.observed is False  # declared in robots.txt, not fetched
    assert routes[("GET", "/api/v1/users")].observed is False


def test_web_inventory_observations_and_provenance():
    inp = default_discovery_input("https://app.example.com", consent=True)
    inventory = build_web_inventory(_state(), inp, datetime.now(timezone.utc))
    observations = {(o.category, o.key): o for o in inventory.web_observations}

    assert observations[("http", "title")].value == "Acme Portal"
    assert observations[("tls", "protocol")].value == "TLSv1.3"
    assert observations[("cookie", "sid")].value.startswith("secure=False")
    assert observations[("waf", "firewall")].value == "Cloudflare"
    assert observations[("auth-boundary", "unauthenticated_access")]

    provenance = {p.source_tool: p for p in inventory.observation_provenance}
    assert set(provenance) >= {"http_posture", "whatweb", "tls_posture"}
    assert provenance["http_posture"].source_url == "https://app.example.com"
    assert provenance["http_posture"].tool_version


def test_web_inventory_records_uncertainties_and_gaps():
    inp = default_discovery_input("https://app.example.com", consent=True)
    inventory = build_web_inventory(_state(), inp, datetime.now(timezone.utc))
    details = " ".join(u.detail for u in inventory.uncertainties)

    assert "not authenticated package evidence" in details
    assert "no authenticated access profile" in details
    assert "declared" in details or "not requested" in details

    unassessed = {u.target for u in inventory.unassessed_targets}
    assert "https://app.example.com/admin" in unassessed
    assert "https://app.example.com" in unassessed


def test_http_extraction_forms_and_links():
    html = """
    <a href="/account/1">Account</a>
    <img src="/logo.png">
    <a href="https://other.example/x">External</a>
    <form action="/login" method="post">
      <input name="user"><input name="pass">
    </form>
    """
    forms = _extract_forms(html)
    assert forms == [{"action": "/login", "method": "POST", "parameters": ["pass", "user"]}]
    links, external = _extract_links(html, "https://app.example.com")
    assert "/account/1" in links
    assert "/logo.png" not in links  # static asset filtered
    assert external == 1


def test_banner_version_parser():
    from app.agents.inventory import _parse_banner

    assert _parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu") == ("OpenSSH", "8.9p1")
    assert _parse_banner("Server: nginx/1.25.3") == ("nginx", "1.25.3")
    assert _parse_banner("MySQL 8.0.36") == ("MySQL", "8.0.36")
    assert _parse_banner("") == (None, None)


def test_network_and_web_profiles_are_separated():
    network = {spec.name for spec in specs_for_profile("network")}
    web = {spec.name for spec in specs_for_profile("web")}
    full = {spec.name for spec in specs_for_profile("full")}

    assert {"nmap_discovery", "tcp_scan", "service_banner", "masscan_scan"} <= network
    assert "http_posture" not in network
    assert "whatweb" not in network

    assert {"http_posture", "web_content", "whatweb", "gobuster_scan"} <= web
    assert "nmap_discovery" not in web
    assert "service_banner" not in web

    assert {"nmap_discovery", "http_posture", "web_content"} <= full


def test_network_profile_projects_no_web_inventory():
    from app.agents.nodes import project_node

    state = {
        "target": "https://demo.example.com",
        "host": "demo.example.com",
        "base_url": "https://demo.example.com",
        "profile": "network",
        "consent": True,
        "status": "completed",
        "results": {},
        "services": [],
        "executed": [],
    }
    update = project_node(state)
    assert update["web_inventory"] is None
    assert update["agent_result"]["web_inventory"] is None


def test_web_profile_run_emits_web_inventory(local_http_server):
    base_url, _host, _port = local_http_server
    state = run_assessment(base_url, consent=True, profile="web")

    assert state["status"] == "completed"
    web = state["web_inventory"]
    assert web["applications"][0]["origin"] == base_url
    paths = {endpoint["path"] for endpoint in web["endpoints"]}
    assert "/" in paths
    assert "/robots.txt" in paths
    assert any(endpoint["observed"] is False for endpoint in web["endpoints"])
    # Web profile must not dispatch network-only scanners.
    assert "nmap_discovery" not in state["executed"]
    assert "tcp_scan" not in state["executed"]
