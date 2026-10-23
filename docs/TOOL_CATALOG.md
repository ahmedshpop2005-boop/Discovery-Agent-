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

## Profiles (scan surfaces)

| Profile | Tools | Surface |
| --- | --- | --- |
| `safe` (default) | 11 | conservative network + HTTP + TLS baseline |
| `network` | 27 | host/port/service/DNS/TLS — **no HTTP/Web tools** |
| `web` | 17 | HTTP/TLS/fingerprint/content/routes/OSINT — **no port scanners** |
| `full` | 36 | network + web together |

A tool runs only if its `profiles` include the selected profile **and** its `requires` are
satisfied. `full` bypasses the per-tool `profiles` list and includes every registered tool.

## Capabilities & redundancy

Every tool declares a `capability` (the logical job it does) and a `priority` (lower runs first).
The planner selects only the best tool per capability, and the executor automatically falls back
to another tool of the same capability when the primary one reports `failed` or `unavailable`.
This is what keeps a scan useful when a binary is missing or a probe is blocked.

| Capability | Primary | Fallbacks |
| --- | --- | --- |
| `port_discovery` | `nmap_discovery` | `masscan_scan`, `tcp_scan` |
| `host_discovery` | `host_alive` | `netdiscover` |
| `dns_resolve` | `dns_recon` | `dns_nslookup` |
| `subdomain` | `amass_enum` | `subdomain_enum` |
| `http_headers` | `http_posture` | `http_curl` |
| `http_waf_detect` | `wafw00f` | `http_waf_detect` |
| `web_content` | `gobuster_scan` | `web_content` |
| `smb_info` | `enum4linux_ng` | `smb_probe` |
| `tls_info` | `tls_posture` | `tls_openssl` |

Fallbacks only offer tools inside the active profile, so redundancy never widens the scan envelope
on its own.

### External recon wrappers

`amass_enum`, `theharvester`, `dnsrecon`, `netdiscover`, `whatweb`, `gobuster_scan`, `wafw00f` and
`enum4linux_ng` shell out to their upstream binaries with fixed, injection-safe argument lists.
None is required: when the binary is missing the tool returns `status=unavailable` and the executor
falls back to the built-in tool that shares its capability (see the table above).

---

## NETWORK

### `nmap_discovery` — Nmap service/version discovery
* **Profiles:** `safe`, `network`, `full` · **Requires:** `host`
* **Command:** `nmap -sV --version-light --top-ports <n> -T3 -oX - <host>`
* **Options:** `top_ports` (default 100), `aggressive` (default 1000 for network/full)
* **Output:** `data.ports[]` = `{host, port, protocol, service, product, version, cpe}`
* **Degrades:** returns `status=unavailable` when Nmap is not installed.

### `masscan_scan` — Masscan port discovery *(fallback)*
* **Capability:** `port_discovery` (priority 15) · **Requires:** the `masscan` binary
* **Degrades:** `unavailable` when masscan is absent.

### `tcp_scan` — Built-in asynchronous TCP connect scan
* **Profiles:** `safe`, `network`, `full` · **Requires:** `host`
* **Options:** `tcp_preset` (`common` | `web` | `top100`), `tcp_ports` (explicit list),
  `tcp_timeout`, `tcp_concurrency`
* **Output:** `data.ports[]` = `{port, protocol, service, product, version}` plus `scanned`, `preset`
* **Why:** dependency-free discovery that works when Nmap is absent.

### `host_alive` — Host liveness check
* **Capability:** `host_discovery` · **Profiles:** `safe`, `network`, `full`
* **Behaviour:** ICMP ping (when available) plus a quick TCP-connect check on common ports.
* **Output:** `data.icmp`, `data.tcp[]`.

### `netdiscover` — ARP host discovery *(fallback)*
* **Capability:** `host_discovery` (priority 60) · **Profiles:** `network`, `full`
* **Requires:** the `netdiscover` binary (Linux/ARP only)
* **Behaviour:** `netdiscover -r <host>/32 -N`; parsed into `data.hosts[]` = `{ip, mac, vendor}`
* **Degrades:** `unavailable` off-segment or when the binary is absent.

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
| `enum4linux_ng` | `smb_info` (prio 40) | 445 | shares, users, groups, OS info (`enum4linux-ng -A`) |
| `snmp_probe` | `snmp_info` | 161/udp | single community-`public` `sysDescr` `GET` |
| `redis_probe` | `redis_info` | 6379 | read-only `INFO` (auth state, version) |
| `mysql_probe` | `mysql_info` | 3306 | server greeting/version banner |

`enum4linux_ng` is an external read-only wrapper: it runs `enum4linux-ng -A <host>` and parses the
JSON report. No credential attacks are performed; when the binary is absent the built-in
`smb_probe` remains the `smb_info` fallback.

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
* **Profiles:** `network`, `full`
* **Options:** `subdomain_words`
* **Wordlist:** `data/wordlists/subdomains.txt` (bounded by `APS_SUBDOMAIN_LIMIT`, default 60)
* **Output:** `data.subdomains` = `{ "<fqdn>": ["<ip>", ...] }`

### `amass_enum` — OWASP Amass passive enumeration *(primary)*
* **Capability:** `subdomain` (priority 40) · **Profiles:** `network`, `full`
* **Command:** `amass enum -passive -d <domain> -timeout <n>`
* **Output:** `data.subdomains[]` · **Degrades:** `unavailable` when Amass is absent
* **Note:** passive OSINT sources only — no active DNS brute force.

### `dnsrecon` — Standard DNS enumeration
* **Capability:** `dns_enum` (priority 40) · **Profiles:** `web`, `network`, `full`
* **Command:** `dnsrecon -d <domain> -t std -j <report.json>`
* **Output:** `data.records[]` = `{type, name, address, raw}`
* **Degrades:** `unavailable` when dnsrecon is absent; the standard enumeration never brute-forces.

### `theharvester` — Public-source OSINT
* **Capability:** `osint` (priority 50) · **Profiles:** `web`, `full`
* **Command:** `theHarvester -d <domain> -b duckduckgo,bing -l <n>`
* **Output:** `data.emails[]`, `data.hosts[]`, `data.ips[]`
* **Note:** public sources only; an empty result is not proof of absence.

### `whois_lookup` — Registration lookup
* **Profiles:** `web`, `network`, `full` · **Requires:** hostname · **Transport:** TCP/43 with IANA referral
* **Output:** `data.fields` = registrar, creation/expiry dates, name servers, status

---

## WEB / TLS

### `http_posture` — HTTP security posture
* **Profiles:** `safe`, `web`, `full` · **Requires:** `base_url`
* **Requests:** base `GET`, one `OPTIONS`, one `Origin` probe (rate-conscious)
* **Output:** `http_status`, `response_class`, `limited`, `edge_indicators`, `attempts`,
  `retries`, `retry_reasons`, redacted `headers`, `missing_headers`, `present_headers`,
  `cookies[]` (`secure`/`httponly`/`samesite`), `methods`, `cors`, `technology`, `title`,
  `redirect`, `forms[]`, `links[]`, `scripts[]`, `api_hints[]`, `external_links`,
  `www_authenticate`, `body_snippet`
* **Retries:** 429/5xx/timeouts/connection errors only, bounded exponential backoff + jitter;
  401/403/404 are never retried.
* **Note:** a 4xx/CDN response is classified as limited and downgraded in the validator — never
  treated as an application observation. A 403 is not attributed to a vendor without specific
  CDN/WAF indicators.

### `tls_posture` — TLS certificate & protocol posture
* **Options:** `tls_port` (default 443)
* **Output:** `protocol`, `cipher`, `supported_versions`, `legacy_versions`,
  `certificate{ subject, issuer, not_after, days_until_expiry, subject_alt_names, self_signed }`

### `http_curl` — HTTP headers via curl *(fallback)*
* **Capability:** `http_headers` (priority 20) · **Profiles:** `safe`, `web`, `full`
* **Backend:** the `curl` binary
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

### `whatweb` — Web technology fingerprinting
* **Capability:** `http_fingerprint` (priority 40) · **Profiles:** `web`, `full`
* **Command:** `whatweb --color=never --log-json <report> <url>`
* **Output:** `data.technologies[]`, `data.plugins{ name: {version, string} }`
* **Degrades:** `unavailable` when WhatWeb is absent · **Note:** fingerprinting only.

### `wafw00f` — WAF fingerprinting *(primary)*
* **Capability:** `http_waf_detect` (priority 40) · **Profiles:** `web`, `full`
* **Command:** `wafw00f <url> -f json`
* **Output:** `data.detected`, `data.firewall`, `data.manufacturer`
* **Degrades:** `unavailable` when wafw00f is absent (falls back to `http_waf_detect` headers).

### `gobuster_scan` — Directory/content discovery *(primary)*
* **Capability:** `web_content` (priority 40) · **Profiles:** `web`, `full`
* **Command:** `gobuster dir -u <url> -w <wordlist> -q -t 20 --timeout 5s --no-progress`
* **Wordlist:** `data/wordlists/common.txt` (bounded; override with option `content_words`)
* **Output:** `data.paths[]`, `confirmed_paths[]`, `tested`, `attempted`, `untested`,
  `valid_responses`, `rejected_responses`, `server_error_responses`, `returncode`, `timed_out`,
  `completed`, `process_started`, `duration_ms`, `executable`, `version`, `arguments`,
  `failure_stage` (`preflight`/`execution`/`completed`), `failure_reason`, `exclude_length`,
  `random_probe_url`, `random_probe_status`, `random_probe_length`, `base_status`,
  `base_response_class`, `suspicious_uniform`, `zero_result_success`, `stdout_tail`, `stderr_tail`
* **Wildcard guard:** Gobuster aborts when a random path returns the deny page. The adapter
  probes one random path and passes its body length as `--exclude-length`, so the scan can run
  without bypassing access controls; excluded responses are never reported as routes.
* **Degrades:** `unavailable` when Gobuster is absent. A completed zero-result scan is `ok`;
  a timeout with output is `partial` and preserves output. Uniform 401/403/429 responses are
  inaccessible, not discovered routes. **Note:** bounded discovery, not brute force.

### `web_content` — Well-known content discovery *(fallback)*
* **Profiles:** `web`, `full`
* **Fetches:** `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`
* **Output:** `data.found`, `data.resources` (per path: `url`, `status`, `response_class`,
  `outcome`, `error_category`, `attempts`, `retries`, `diagnostic`, `retrieved`, `parse_status`,
  `parse_error`), `data.missing`, `data.inaccessible`, `data.parse_errors`, `data.errors`,
  `data.error_categories`, `data.tested`, `data.retrieved`
* **Note:** HTTP 403 is `access_denied`, never `missing`; DNS, connection, timeout and parser
  failures carry distinct categories. A missing resource is not proof of no content.

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
