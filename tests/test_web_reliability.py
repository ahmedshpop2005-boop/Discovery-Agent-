"""Evidence, verification and failure-handling tests (Web reliability upgrade).

Hermetic: every network interaction is mocked with httpx.MockTransport or a
fake response object. No third-party site is contacted.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import httpx

from app.agents.technologies import is_plausible_version, normalize_technologies
from app.agents.web_inventory import (
    build_authentication_coverage,
    build_route_coverage,
    build_web_inventory,
)
from app.contracts import default_discovery_input
from app.contracts.enums import (
    ConfidenceLevel,
    CoverageStatus,
    ResponseClass,
    TechnologyObservationType,
    VerificationStatus,
)
from app.net.http import HttpResult, classify_response, detect_edge, request_with_retries
from app.reporting import build_json_report
from app.safety.authorization import normalize_target
from app.tools import paths_tool, webscan_extra_tool
from app.tools.base import ToolContext


def _ctx(url: str = "http://app.example.test", options: dict | None = None) -> ToolContext:
    return ToolContext(target=normalize_target(url), scan_id="test", options=options or {})


# 1. Valid fingerprint with an unverified version ---------------------------


def test_valid_fingerprint_is_claimed_not_verified():
    records, uncertainties = normalize_technologies(
        [
            {
                "name": "jQuery",
                "version": "3.7.1",
                "source": "whatweb",
                "method": "whatweb",
            }
        ]
    )

    assert len(records) == 1
    record = records[0]
    assert record.version == "3.7.1"
    assert record.observation_type == TechnologyObservationType.VERSION_CLAIMED
    assert record.verification_status == VerificationStatus.UNVERIFIED
    assert record.confidence == ConfidenceLevel.LOW
    assert record.evidence
    assert uncertainties == []


# 2. Malformed observation: metadata is never promoted to a version --------


def test_metadata_is_not_treated_as_a_version():
    candidates = [
        ("HTTPServer", "cloudflare"),
        ("Country", "UNITED STATES"),
        ("IP", "104.26.4.84"),
        ("Script", "application/json"),
        ("Strict-Transport-Security", "max-age=2592000"),
        ("JQuery", "3.7.1"),
    ]
    records, uncertainties = normalize_technologies(
        [
            {"name": name, "version": version, "source": "http_posture", "method": "header"}
            for name, version in candidates
        ]
    )

    versions = {record.name: record.version for record in records}
    assert versions["HTTPServer"] is None
    assert versions["Strict-Transport-Security"] is None
    assert versions["jQuery"] == "3.7.1"
    # Pure metadata plugins are not technologies at all.
    assert {"Country", "IP", "Script"} & set(versions) == set()
    assert len(uncertainties) == 2
    assert all(
        "rejected as non-version metadata" in note
        for record in records
        for note in record.evidence
        if "candidate version" in note
    )
    assert not is_plausible_version("104.26.4.84")
    assert not is_plausible_version("max-age=2592000")


# 3. HTTP 200 classification -------------------------------------------------


def test_http_200_is_success():
    assert classify_response(200) == ResponseClass.SUCCESS
    assert classify_response(204) == ResponseClass.SUCCESS


# 4. HTTP 403 access-control classification ---------------------------------


def test_http_403_is_forbidden_without_vendor_assumption():
    assert classify_response(403) == ResponseClass.FORBIDDEN
    # A bare 403 must not be attributed to Cloudflare.
    assert detect_edge({}, b"Access denied") == []
    assert detect_edge({"cf-ray": "abc123"}, b"") == ["cloudflare"]


# 5. HTTP 429 with bounded retry behaviour ----------------------------------


def test_429_is_retried_with_a_bound():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(429, headers={"retry-after": "0"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = request_with_retries(
        "http://app.example.test",
        retries=2,
        backoff=0,
        jitter=0,
        client=client,
    )

    assert result.response_class == ResponseClass.RATE_LIMITED
    assert result.attempts == 3
    assert result.retries == 2
    assert len(calls) == 3


# 6. Transient timeout followed by a successful retry -----------------------


def test_timeout_then_success():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, text="recovered")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = request_with_retries(
        "http://app.example.test",
        retries=2,
        backoff=0,
        jitter=0,
        client=client,
    )

    assert result.status_code == 200
    assert result.response_class == ResponseClass.SUCCESS
    assert result.attempts == 2
    assert result.retries == 1
    assert calls["count"] == 2


# 7. Well-known resource returning 404 --------------------------------------


def test_well_known_404_is_missing_not_secure(monkeypatch):
    def fake_request(url: str, **_kwargs) -> HttpResult:
        return HttpResult(url=url, status_code=404, response_class=ResponseClass.NOT_FOUND)

    monkeypatch.setattr(paths_tool, "request_with_retries", fake_request)
    result = paths_tool.web_content(_ctx())

    assert result.status == "partial"
    assert result.data["found"] == {}
    assert set(result.data["missing"]) == set(paths_tool.WELL_KNOWN)
    assert result.data["resources"]["/robots.txt"]["outcome"] == "missing"
    assert "not evidence" in (result.note or "").lower() or "not evidence" in result.summary.lower()


# 8. Web-content parser failure is isolated ---------------------------------


def test_web_content_parser_failure_is_reported(monkeypatch):
    def fake_request(url: str, **_kwargs) -> HttpResult:
        return HttpResult(
            url=url,
            status_code=200,
            response_class=ResponseClass.SUCCESS,
            body=b"User-agent: *\nDisallow: /admin\n",
        )

    def broken_parser(_text: str):
        raise ValueError("malformed robots")

    monkeypatch.setattr(paths_tool, "request_with_retries", fake_request)
    monkeypatch.setattr(paths_tool, "_parse_robots", broken_parser)
    result = paths_tool.web_content(_ctx())

    assert result.status == "partial"
    assert result.data["parse_errors"]
    assert "/robots.txt" in result.data["parse_errors"][0]
    assert result.data["found"]["/robots.txt"]["parse_status"] == "failed"


# 9. Gobuster completes successfully with zero results ----------------------


def test_gobuster_zero_results_is_a_clean_success(monkeypatch):
    monkeypatch.setattr(webscan_extra_tool, "which", lambda _name: "gobuster")
    monkeypatch.setattr(
        webscan_extra_tool,
        "request_with_retries",
        lambda *_args, **_kwargs: HttpResult(
            url="http://app.example.test",
            status_code=200,
            response_class=ResponseClass.SUCCESS,
        ),
    )
    monkeypatch.setattr(
        webscan_extra_tool,
        "run_command",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )

    result = webscan_extra_tool.gobuster_scan(_ctx())

    assert result.status == "ok"
    assert result.data["zero_result_success"] is True
    assert result.data["paths"] == []
    assert result.data["tested"] > 0
    assert "do not mean no paths exist" in (result.note or "")


# 10. Gobuster process failure / timeout ------------------------------------


def test_gobuster_timeout_preserves_partial_results(monkeypatch):
    monkeypatch.setattr(webscan_extra_tool, "which", lambda _name: "gobuster")
    monkeypatch.setattr(
        webscan_extra_tool,
        "request_with_retries",
        lambda *_args, **_kwargs: HttpResult(
            url="http://app.example.test",
            status_code=200,
            response_class=ResponseClass.SUCCESS,
        ),
    )

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["gobuster"], timeout=1, output="/admin (Status: 200)\n"
        )

    monkeypatch.setattr(webscan_extra_tool, "run_command", timeout)
    result = webscan_extra_tool.gobuster_scan(_ctx())

    assert result.status == "partial"
    assert result.data["timed_out"] is True
    assert [item["path"] for item in result.data["paths"]] == ["/admin"]


def test_gobuster_process_failure_is_failed(monkeypatch):
    monkeypatch.setattr(webscan_extra_tool, "which", lambda _name: "gobuster")
    monkeypatch.setattr(
        webscan_extra_tool,
        "request_with_retries",
        lambda *_args, **_kwargs: HttpResult(
            url="http://app.example.test",
            status_code=200,
            response_class=ResponseClass.SUCCESS,
        ),
    )
    monkeypatch.setattr(
        webscan_extra_tool,
        "run_command",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "boom"),
    )
    result = webscan_extra_tool.gobuster_scan(_ctx())

    assert result.status == "failed"
    assert result.data["returncode"] == 1
    assert result.data["paths"] == []


# 11. Missing authenticated access profile ----------------------------------


def test_missing_authenticated_profile_is_explicit():
    inp = default_discovery_input("https://app.example.com", consent=True)
    coverage = build_authentication_coverage({"results": {}}, inp)

    assert coverage.status == "not_assessed"
    assert coverage.authenticated_profiles == 0
    assert "authenticated routes" in coverage.checks_unverified
    assert any("No authenticated access profile" in note for note in coverage.notes)


# 12. Partial discovery preserves successful findings -----------------------


def test_partial_web_content_preserves_successes(monkeypatch):
    def fake_request(url: str, **_kwargs) -> HttpResult:
        if url.endswith("/robots.txt"):
            return HttpResult(
                url=url,
                status_code=200,
                response_class=ResponseClass.SUCCESS,
                body=b"User-agent: *\nDisallow: /admin\n",
            )
        if url.endswith("/sitemap.xml"):
            return HttpResult(url=url, response_class=ResponseClass.TIMEOUT, error="ReadTimeout")
        return HttpResult(url=url, status_code=404, response_class=ResponseClass.NOT_FOUND)

    monkeypatch.setattr(paths_tool, "request_with_retries", fake_request)
    result = paths_tool.web_content(_ctx())

    assert result.status == "partial"
    assert "/robots.txt" in result.data["found"]
    assert result.data["found"]["/robots.txt"]["disallow"] == ["/admin"]
    assert result.data["errors"]
    assert "/.well-known/security.txt" in result.data["missing"]


# 13. Route coverage stays limited after access-control failures -------------


def test_route_coverage_is_limited_by_access_control():
    inp = default_discovery_input("https://app.example.com", consent=True)
    state = {
        "base_url": "https://app.example.com",
        "executed": ["http_posture", "web_content", "gobuster_scan"],
        "tool_plan": ["http_posture", "web_content", "gobuster_scan"],
        "results": {
            "http_posture": {
                "status": "ok",
                "data": {
                    "http_status": 403,
                    "response_class": "forbidden",
                    "edge_indicators": [],
                },
            },
            "web_content": {
                "status": "partial",
                "data": {
                    "resources": {
                        "/robots.txt": {"status": 403, "outcome": "inaccessible"},
                    }
                },
            },
            "gobuster_scan": {
                "status": "partial",
                "data": {
                    "attempted": 42,
                    "tested": 42,
                    "paths": [{"path": "/admin", "status": 403}],
                    "valid_responses": 0,
                    "rejected_responses": 1,
                    "suspicious_uniform": True,
                    "untested": 0,
                },
            },
        },
    }

    coverage = build_route_coverage(state, inp, [])
    assert coverage.coverage_status == CoverageStatus.LIMITED
    assert coverage.routes_inaccessible >= 2
    assert any("access-control" in limitation or "forbidden" in limitation for limitation in coverage.coverage_limitations)


# 14. Final report serialisation --------------------------------------------


def test_dashboard_renders_coverage_and_report_buttons(local_http_server):
    from fastapi.testclient import TestClient

    from app.main import app

    base_url, _host, _port = local_http_server
    client = TestClient(app)
    response = client.post(
        "/scan",
        data={"target": base_url, "consent": "true", "profile": "web"},
    )

    assert response.status_code == 200
    assert "ROUTE COVERAGE" in response.text
    assert "AUTHENTICATION COVERAGE" in response.text
    assert 'action="/report.json"' in response.text
    assert "Download JSON report" in response.text


def test_final_report_is_serialisable(local_http_server):
    from app.agents.graph import run_assessment

    base_url, _host, _port = local_http_server
    state = run_assessment(base_url, consent=True, profile="web")
    payload = build_json_report(state)

    json.dumps(payload, default=str)
    required = {
        "scan_metadata",
        "scope_validation",
        "assets",
        "services",
        "technologies",
        "web_observations",
        "routes",
        "evidence",
        "tool_results",
        "authentication_coverage",
        "route_coverage",
        "uncertainties",
        "errors",
        "overall_status",
    }
    assert required <= set(payload)
    assert payload["overall_status"] in {"success", "partial", "blocked", "inconclusive", "failed"}
    assert payload["tool_results"]
    assert payload["report"]["profile"] == "web"
    assert payload["web_inventory"]["route_coverage"]["coverage_status"] in {
        "full",
        "partial",
        "limited",
        "unknown",
    }
def _forbidden(url: str, body: bytes = b"denied", **_kwargs) -> HttpResult:
    return HttpResult(
        url=url,
        status_code=403,
        response_class=ResponseClass.FORBIDDEN,
        body=body,
        body_length=len(body),
        attempts=1,
    )


def test_gobuster_parses_bare_and_full_url_paths():
    stdout = "\n".join(
        [
            "admin                (Status: 200) [Size: 35]",
            "https://app.example.test/api (Status: 301) [Size: 0]",
            "/private (Status: 403)",
            "not a result line",
        ]
    )
    parsed = webscan_extra_tool._parse_gobuster(stdout)
    assert [item["path"] for item in parsed] == ["/admin", "/api", "/private"]
    assert [item["status"] for item in parsed] == [200, 301, 403]


def test_gobuster_wildcard_preflight_failure_is_reported(monkeypatch):
    monkeypatch.setattr(webscan_extra_tool, "which", lambda _name: "gobuster")
    monkeypatch.setattr(webscan_extra_tool, "request_with_retries", _forbidden)
    message = (
        "the server returns a status code that matches the provided options for non "
        "existing urls. http://app.example.test/abc => 403 (Length: 48). "
        "Please exclude the response length or the status code or set the wildcard option."
    )
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, "gobuster version 3.8.2\n", "")
        return subprocess.CompletedProcess(args, 1, "", message)

    monkeypatch.setattr(webscan_extra_tool, "run_command", fake_run)
    result = webscan_extra_tool.gobuster_scan(_ctx())

    assert result.status == "failed"
    assert result.data["returncode"] == 1
    assert result.data["paths"] == []
    assert result.data["zero_result_success"] is False
    assert result.data["failure_stage"] == "preflight"
    assert result.data["failure_reason"] == "wildcard_or_uniform_response"
    assert result.data["attempted"] == 0
    assert result.data["untested"] > 0
    assert result.data["executable"] == "gobuster"
    assert result.data["version"] == "3.8.2"
    assert result.data["exclude_length"] == 6
    assert result.data["stderr_tail"]
    assert any("--exclude-length" in command for command in calls)


def test_gobuster_discovers_paths_behind_uniform_deny_page(monkeypatch):
    monkeypatch.setattr(webscan_extra_tool, "which", lambda _name: "gobuster")
    monkeypatch.setattr(webscan_extra_tool, "request_with_retries", _forbidden)
    captured = {}

    def fake_run(args, **_kwargs):
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, "gobuster version 3.8.2", "")
        captured["args"] = list(args)
        return subprocess.CompletedProcess(
            args, 0, "admin (Status: 200) [Size: 35]\n", ""
        )

    monkeypatch.setattr(webscan_extra_tool, "run_command", fake_run)
    result = webscan_extra_tool.gobuster_scan(_ctx())

    assert result.status == "ok"
    assert [item["path"] for item in result.data["paths"]] == ["/admin"]
    assert [item["path"] for item in result.data["confirmed_paths"]] == ["/admin"]
    assert result.data["exclude_length"] == 6
    assert captured["args"][captured["args"].index("--exclude-length") + 1] == "6"
    assert result.data["zero_result_success"] is False


def test_web_content_403_is_access_denied_not_missing(monkeypatch):
    def fake_request(url: str, **_kwargs) -> HttpResult:
        result = _forbidden(url)
        result.headers = {"cf-ray": "8a1b2c3d4e5f-SIN", "server": "cloudflare"}
        result.edge_indicators = ["cloudflare"]
        return result

    monkeypatch.setattr(paths_tool, "request_with_retries", fake_request)
    result = paths_tool.web_content(_ctx())

    assert result.status == "partial"
    assert result.data["tested"] == len(paths_tool.WELL_KNOWN)
    assert result.data["retrieved"] == 0
    assert result.data["missing"] == []
    assert set(result.data["inaccessible"]) == set(paths_tool.WELL_KNOWN)
    assert result.data["error_categories"] == {"access_denied": 3}
    entry = result.data["resources"]["/robots.txt"]
    assert entry["url"] == "http://app.example.test/robots.txt"
    assert entry["status"] == 403
    assert entry["outcome"] == "inaccessible"
    assert entry["error_category"] == "access_denied"
    assert entry["attempts"] == 1
    assert entry["diagnostic"] == "denied"
    assert entry["edge_indicators"] == ["cloudflare"]


def test_web_content_uses_configured_paths(monkeypatch):
    monkeypatch.setattr(
        paths_tool,
        "request_with_retries",
        lambda url, **_kwargs: HttpResult(
            url=url, status_code=404, response_class=ResponseClass.NOT_FOUND
        ),
    )
    result = paths_tool.web_content(_ctx(options={"well_known_paths": ["/a.txt", "/b.txt"]}))

    assert result.data["tested"] == 2
    assert set(result.data["missing"]) == {"/a.txt", "/b.txt"}
    assert result.status == "partial"


def test_json_report_dedupes_limitations_and_merges_evidence():
    duplicate = "Gobuster did not complete cleanly: uniform access-control page"
    payload = build_json_report(
        {
            "status": "completed",
            "executed": ["gobuster_scan"],
            "tool_plan": [],
            "results": {
                "gobuster_scan": {
                    "status": "partial",
                    "summary": "partial",
                    "data": {"suspicious_uniform": True, "response_class": "forbidden"},
                }
            },
            "inventory": {
                "uncertainties": [
                    {"subject": "app", "detail": duplicate, "evidence_refs": ["prov:a"]}
                ]
            },
            "web_inventory": {
                "uncertainties": [
                    {"subject": "app", "detail": duplicate, "evidence_refs": ["prov:b"]}
                ],
                "route_coverage": {
                    "coverage_status": "limited",
                    "coverage_limitations": ["auth unavailable", "auth unavailable"],
                },
                "authentication_coverage": {
                    "status": "not_assessed",
                    "checks_unverified": ["authenticated routes", "authenticated routes"],
                },
            },
        }
    )

    assert len(payload["uncertainties"]) == 1
    assert set(payload["uncertainties"][0]["evidence_refs"]) == {"prov:a", "prov:b"}
    assert payload["route_coverage"]["coverage_limitations"] == ["auth unavailable"]
    assert payload["authentication_coverage"]["checks_unverified"] == ["authenticated routes"]
    assert len(payload["tool_results"][0]["limitations"]) == len(
        set(payload["tool_results"][0]["limitations"])
    )

