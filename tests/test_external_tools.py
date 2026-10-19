"""Hermetic tests for the external recon tool wrappers.

Binaries are disabled by the autouse fixture in ``conftest`` so every wrapper
must degrade to ``unavailable``. Parsers are exercised directly on captured
sample output (no process is spawned).
"""

import app.tools  # noqa: F401  (register tools)
from app.safety.authorization import normalize_target
from app.tools.base import ToolContext
from app.tools.registry import get


def _ctx(target, **options):
    return ToolContext(target=normalize_target(target), scan_id="test", options=options)


UNAVAILABLE = [
    ("amass_enum", "example.com"),
    ("theharvester", "example.com"),
    ("dnsrecon", "example.com"),
    ("netdiscover", "127.0.0.1"),
    ("whatweb", "http://127.0.0.1:8080"),
    ("gobuster_scan", "http://127.0.0.1:8080"),
    ("wafw00f", "http://127.0.0.1:8080"),
    ("enum4linux_ng", "127.0.0.1"),
]


def test_external_tools_report_unavailable_without_binary():
    for name, target in UNAVAILABLE:
        options = {"services": [{"port": 445}]} if name == "enum4linux_ng" else {}
        result = get(name).function(_ctx(target, **options))
        assert result.status == "unavailable", name


def test_parse_amass_filters_to_domain():
    from app.tools.osint_extra_tool import _parse_amass

    out = "api.example.com\nmail.example.com\nevil.com\napi.example.com\n"
    assert _parse_amass(out, "example.com") == ["api.example.com", "mail.example.com"]


def test_parse_harvester_extracts_emails_hosts_ips():
    from app.tools.osint_extra_tool import _parse_harvester

    out = "admin@example.com\nwww.example.com 1.2.3.4\nother@test.org"
    parsed = _parse_harvester(out, "example.com")
    assert "admin@example.com" in parsed["emails"]
    assert "www.example.com" in parsed["hosts"]
    assert "1.2.3.4" in parsed["ips"]


def test_parse_dnsrecon_json_normalises_records():
    from app.tools.osint_extra_tool import _parse_dnsrecon_json

    text = '[{"type": "A", "name": "example.com", "address": "1.2.3.4"}, {"type": "MX", "exchange": "mail.example.com"}]'
    records = _parse_dnsrecon_json(text)
    assert records[0] == {"type": "A", "name": "example.com", "address": "1.2.3.4", "raw": ""}
    assert records[1]["raw"] == "mail.example.com"


def test_parse_netdiscover_rows():
    from app.tools.osint_extra_tool import _parse_netdiscover

    out = " 1.2.3.4   00:11:22:33:44:55   Acme Corp\n not-an-ip x\n"
    hosts = _parse_netdiscover(out)
    assert hosts == [{"ip": "1.2.3.4", "mac": "00:11:22:33:44:55", "vendor": "Acme Corp"}]


def test_parse_whatweb_json_lines():
    from app.tools.webscan_extra_tool import _parse_whatweb_json

    text = (
        '{"target": "http://x", "plugins": {"Apache": {"version": ["2.4.49"]}, '
        '"PHP": {"string": ["7.4"]}}}'
    )
    parsed = _parse_whatweb_json(text)
    assert parsed["technologies"] == ["Apache", "PHP"]
    assert parsed["plugins"]["Apache"]["version"] == "2.4.49"
    assert parsed["plugins"]["PHP"]["string"] == "7.4"


def test_parse_gobuster_lines():
    from app.tools.webscan_extra_tool import _parse_gobuster

    out = "/admin (Status: 200) [Size: 1234]\n/login (Status: 302) [Size: 0]\nrandom noise\n"
    found = _parse_gobuster(out)
    assert found[0] == {"path": "/admin", "status": 200, "size": 1234}
    assert found[1]["status"] == 302


def test_parse_wafw00f_json_and_text():
    from app.tools.webscan_extra_tool import _parse_wafw00f

    json_out = '[{"detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]'
    assert _parse_wafw00f(json_out)["firewall"] == "Cloudflare"
    text_out = "The site http://x is behind Cloudflare (Cloudflare Inc.)"
    parsed = _parse_wafw00f(text_out)
    assert parsed["detected"] is True
    assert parsed["firewall"] == "Cloudflare"
    assert _parse_wafw00f("No WAF detected")["detected"] is False


def test_parse_enum4linux_summarises():
    from app.tools.smb_extra_tool import _parse_enum4linux

    text = '{"users": {"admin": {}}, "shares": {"public": {}}, "os_info": {"OS": "Windows 10"}}'
    parsed = _parse_enum4linux(text)
    assert parsed["users"] == ["admin"]
    assert parsed["shares"] == ["public"]
    assert parsed["os"] == "Windows 10"
    assert _parse_enum4linux("not json") == {}


def test_gobuster_wordlist_is_bounded():
    from app.tools.webscan_extra_tool import _load_wordlist

    words = _load_wordlist()
    assert words and "admin" in words
