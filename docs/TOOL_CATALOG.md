# Tool Catalog

Every tool is registered in `app/tools/registry.py` and implemented in its own module. Tools
return a `ToolResult` and never call each other or the HTTP layer directly.

Common `ToolResult` shape:

```json
{
  "tool": "tls_posture",
  "status": "ok",              // ok | partial | unavailable | failed | blocked | skipped
  "summary": "human-readable, redacted",
  "data": { "...": "structured observations" },
  "evidence": [{ "source": "...", "detail": "...", "raw": {} }],
  "command": "what was executed (no secrets)",
  "note": "caveats",
  "error": "redacted error, if any",
  "duration_ms": 123
}
```

## Profiles

`safe` (default) · `web` · `network` · `full`. A tool runs only if its `profiles` include the
selected profile **and** its `requires` are satisfied.

## Capabilities & redundancy

Every tool declares a `capability` (the logical job it does) and a `priority` (lower runs first).
The planner selects only the best tool per capability, and the executor automatically falls back
to another tool of the same capability when the primary one reports `failed` or `unavailable`.
This is what keeps a scan useful when a binary is missing or a probe is blocked.

| Capability | Primary | Fallbacks |
| --- | --- | --- |
| `port_discovery` | `nmap_discovery` | `masscan_scan`, `tcp_scan` |
| `dns_resolve` | `dns_recon` | `dns_nslookup` |
| `http_headers` | `http_posture` | `http_curl` |
| `tls_info` | `tls_posture` | `tls_openssl` |

Fallbacks only offer tools inside the active profile, so redundancy never widens the scan envelope
on its own.

---

## NETWORK

### `nmap_discovery` — Nmap service/version discovery
* **Command:** `nmap -sV --version-light --top-ports <n> -T3 -oX - <host>`
* **Options:** `top_ports` (default 100), `aggressive` (default 1000 for network/full)
* **Output:** `data.ports[]` = `{host, port, protocol, service, product, version, cpe}`
* **Degrades:** returns `status=unavailable` when Nmap is not installed.

### `masscan_scan` — Masscan port discovery *(fallback)*
* **Capability:** `port_discovery` (priority 15) · **Requires:** the `masscan` binary
* **Degrades:** `unavailable` when masscan is absent.

### `tcp_scan` — Built-in asynchronous TCP connect scan
* **Options:** `tcp_preset` (`common` | `web` | `top100`), `tcp_ports` (explicit list),
  `tcp_timeout`, `tcp_concurrency`
* **Output:** `data.ports[]` = `{port, protocol, service, product, version}` plus `scanned`, `preset`
* **Why:** dependency-free discovery that works when Nmap is absent.

### `host_alive` — Host liveness check
* **Capability:** `host_discovery`
* **Behaviour:** ICMP ping (when available) plus a quick TCP-connect check on common ports.
* **Output:** `data.icmp`, `data.tcp[]`.

### `udp_scan` — Bounded UDP probe
* **Profiles:** `network`, `full` · **Options:** `udp_ports`
* **Behaviour:** sends a small datagram and records any response (no amplification).

### `traceroute` — Network path
* **Profiles:** `network`, `full` · **Backend:** `tracert`/`traceroute` when available.
* **Output:** `data.hops[]`.

### `service_banner` — Service banner grabber
* **Requires:** discovered `services`
* **Behaviour:** passive read for line protocols (SSH/FTP/SMTP/…); a single read-only request
  for HTTP (`HEAD`) and Redis (`INFO`).
* **Output:** `data.banners` = `{ "<port>": "<banner>" }`
* **Note:** banners are advertised strings, not authenticated versions.

### Service probes *(network/full, `requires` discovered services)*
Each probe targets the matching port and only reads the greeting/negotiation — no authentication
is attempted and no remote state is changed.

| Tool | Capability | Port | Collects |
| --- | --- | --- | --- |
| `ssh_algorithms` | `ssh_info` | 22 | banner + KEX/host-key/cipher/MAC lists; flags weak options |
| `smtp_probe` | `smtp_info` | 25 | banner + `EHLO` capabilities |
| `ftp_probe` | `ftp_info` | 21 | banner + `FEAT` (cleartext warning) |
| `smb_probe` | `smb_info` | 445 | SMB dialect + signing-required flag |
| `snmp_probe` | `snmp_info` | 161/udp | single community-`public` `sysDescr` `GET` |
| `redis_probe` | `redis_info` | 6379 | read-only `INFO` (auth state, version) |
| `mysql_probe` | `mysql_info` | 3306 | server greeting/version banner |

---

## DNS / OSINT

### `dns_recon` — Public DNS enumeration
* **Requires:** hostname
* **Records:** A, AAAA, NS, MX, TXT, CNAME, SOA, CAA
* **Backend:** `dnspython` when installed, else `nslookup`
* **Output:** `data.records` = `{ "A": [...], "MX": [...], ... }`
* **Note:** an empty result means nothing was collected, not that none exist.

### `dns_nslookup` — nslookup-based DNS records *(fallback)*
* **Capability:** `dns_resolve` (priority 20) · **Backend:** the `nslookup` binary
* **Records:** A, AAAA, MX, NS, TXT · **Degrades:** `unavailable` when nslookup is absent.

### `reverse_dns` — PTR lookup
* **Profiles:** `web`, `network`, `full` · **Backend:** dnspython, else `socket.gethostbyaddr`
* **Output:** `data.names[]`.

### `dns_zone_transfer` — AXFR attempt
* **Profiles:** `network`, `full` · **Behaviour:** tries AXFR against the domain's name servers.
* **Note:** success is a finding (full zone disclosure); refusal is the normal/expected result.

### `subdomain_enum` — DNS-only subdomain enumeration
* **Profiles:** `full` only (opt-in)
* **Options:** `subdomain_words`
* **Wordlist:** `data/wordlists/subdomains.txt` (bounded by `APS_SUBDOMAIN_LIMIT`, default 60)
* **Output:** `data.subdomains` = `{ "<fqdn>": ["<ip>", ...] }`

### `whois_lookup` — Registration lookup
* **Requires:** hostname · **Transport:** TCP/43 with IANA referral
* **Output:** `data.fields` = registrar, creation/expiry dates, name servers, status

---

## WEB / TLS

### `http_posture` — HTTP security posture
* **Requests:** base `GET`, one `OPTIONS`, one `Origin` probe (rate-conscious)
* **Output:** `http_status`, redacted `headers`, `missing_headers`, `present_headers`,
  `cookies[]` (`secure`/`httponly`/`samesite`), `methods`, `cors`, `technology`, `title`,
  `redirect`
* **Note:** a 4xx/CDN response is recorded and downgraded in the validator — never treated as an
  application observation.

### `tls_posture` — TLS certificate & protocol posture
* **Options:** `tls_port` (default 443)
* **Output:** `protocol`, `cipher`, `supported_versions`, `legacy_versions`,
  `certificate{ subject, issuer, not_after, days_until_expiry, subject_alt_names, self_signed }`

### `http_curl` — HTTP headers via curl *(fallback)*
* **Capability:** `http_headers` (priority 20) · **Backend:** the `curl` binary
* **Output:** `status_line`, redacted `headers`, `security_headers_present`
* **Degrades:** `unavailable` when curl is absent.

### `tls_openssl` — TLS/certificate via OpenSSL *(fallback)*
* **Capability:** `tls_info` (priority 20) · **Backend:** the `openssl` binary
* **Output:** `protocol`, `cipher`, `certificate{ subject, issuer, not_before, not_after,
  subject_alt_names, verify_* }`
* **Degrades:** `unavailable` when openssl is absent.

### `http_favicon` — Favicon fingerprint
* **Profiles:** `web`, `full` · **Output:** `md5`, `sha256`, `size` (for hash-based product
  lookups).

### `http_waf_detect` — WAF/CDN/edge detection
* **Profiles:** `web`, `full` · **Output:** `data.detected[]` from header signatures.

### `web_content` — Well-known content discovery
* **Profiles:** `web`, `full`
* **Fetches:** `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`
* **Output:** `data.found` = per-path `{status, size, disallow[], sitemaps[], urls[], fields[]}`

---

## ADVISORY

### `advisory_match` — Local advisory matching
* **Requires:** discovered `services` (product/version)
* **Index:** `data/knowledge/advisories.json` (illustrative; extend with NVD/OSV in production)
* **Output:** `data.matches[]` = `{port, product, version, cve, severity, title, affected,
  remediation, reference}`
* **Note:** a version match is a *candidate lead*, never proof — it needs target-specific
  confirmation before being reported as `Confirmed`.

---

## Extending

1. Create `app/tools/<name>_tool.py`.
2. Decorate the function with `@tool(...)` (name, category, effect_class, capability, priority,
   requires, profiles, order).
3. Import it in `app/tools/__init__.py`.

The planner, executor, validator, UI and PDF pick it up automatically. If the tool produces
`data.ports`, those merge into the shared attack-surface inventory used by the banner grabber
and the report appendix. Naming a `capability` that another tool already uses makes the new tool
an automatic fallback for it — no executor change required.
