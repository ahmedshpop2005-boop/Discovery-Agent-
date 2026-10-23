# AutoPentest Sentinel

An **evidence-first, agentic security-assessment platform** for **authorized**, non-destructive
web and network testing. A LangGraph workflow plans real collection tools, adapts to what it
observes, validates every result into evidence-backed findings, retrieves remediation guidance
locally, and produces an analyst report.

> **Ethical use.** Assess only assets you are explicitly authorized to test. The platform
> intentionally excludes exploitation, credential attacks, denial-of-service, persistence and
> destructive actions.

This repository implements the **Discovery agent** of the *SentinelX AI* shared-agent contracts
(owner: Shaaban). It discovers hosts, ports, services, versions and available configuration, and
produces a sourced `AssetInventory` for the Pentesting agent.

On top of that it has a modular, registry-based tool layer with **36 real, non-destructive
collection tools** (Nmap plus 35 built-ins, including optional wrappers for Amass, theHarvester,
DNSRecon, WhatWeb, Gobuster, enum4linux-ng, Wafw00f and Netdiscover) and automatic
**redundancy/fallback**: if a tool or its external binary is missing, the agent transparently
switches to another tool that performs the same job.

---

## What's new in this version

| Area | Before | Now |
| --- | --- | --- |
| Tools | Nmap + 1 HTTP + 1 TLS check | 36 registered tools (see catalog) |
| Tool layer | functions in `scanners.py` | `app/tools/` registry, metadata, capabilities |
| Redundancy | none | capability + priority with automatic fallback |
| Workflow | fixed 3 nodes | adaptive planner → executor → **re-planner** → validator |
| Records | plain dicts | typed Pydantic `Finding` / `EvidenceItem` |
| Safety | inline | `app/safety/` authorization + redaction layer |
| Scanning | Nmap only | Nmap **plus** a dependency-free async TCP scanner |

### New tools (beyond Nmap)

* **Discovery:** `masscan_scan`, `host_alive`, `udp_scan`, `traceroute`, `netdiscover`.
* **DNS:** `dns_nslookup`, `reverse_dns`, `dns_zone_transfer`, `dnsrecon`, `amass_enum`.
* **HTTP/Web:** `http_curl`, `http_favicon`, `http_waf_detect`, `whatweb`, `gobuster_scan`, `wafw00f`.
* **TLS:** `tls_openssl`.
* **Service probes:** `ssh_algorithms`, `smtp_probe`, `ftp_probe`, `smb_probe`, `enum4linux_ng`,
  `snmp_probe`, `redis_probe`, `mysql_probe`.
* **OSINT:** `theharvester` (emails/hosts/subdomains from public sources).
* **Advisory:** `advisory_match` (local advisory index).

### Redundancy model

Every tool declares a `capability` and a `priority`. The planner picks the best tool per
capability; the executor automatically falls back to another tool of the same capability when the
primary one reports `failed` or `unavailable` (and only within the active profile):

| Capability | Primary | Fallback(s) |
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

External wrappers (`amass_enum`, `gobuster_scan`, `wafw00f`, `enum4linux_ng`) lead their capability
when installed and silently defer to the built-in fallback when the binary is absent.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   authorized    │                app.agents (LangGraph)         │
   target  ─────▶│  guard ─▶ plan ─▶ collect ─▶ adapt ─┐          │
                 │    │                        ▲       │          │
                 │    └─(blocked)─▶ END        └─(more)┘          │
                 │                              └─(done)─▶ validate ─▶ findings
                 └───────────────┬──────────────────────────────┘
                                 │ dispatch by name
                                 ▼
                 ┌──────────────────────────────────────────────┐
                 │            app.tools (registry)               │
                 │  36 tools grouped by capability; the executor │
                 │  falls back to an alternative tool of the same │
                 │  capability when one fails or is unavailable   │
                 └───────────────┬──────────────────────────────┘
                                 │ returns typed ToolResult (+redaction)
        ┌────────────────────────┼──────────────────────────────┐
        ▼                        ▼                              ▼
  app.safety               app.models                     app.knowledge
  (authz, redaction)       (Finding, Evidence)            (local retrieval)
                                 │
                                 ▼
                          app.reporting (PDF) · app.api (FastAPI)
```

Layer rule: **tools never call each other and never touch HTTP**; the agent dispatches one
registered tool at a time through the registry, and safety boundaries are enforced outside the
model.

---

## Tool catalog

| Tool | Capability (prio) | Category | Effect | Profiles | Requires |
| --- | --- | --- | --- | --- | --- |
| `nmap_discovery` | port_discovery (10) | NETWORK | passive | safe, network, full | host |
| `masscan_scan` | port_discovery (15) | NETWORK | active | network, full | host |
| `tcp_scan` | port_discovery (20) | NETWORK | active | safe, network, full | host |
| `host_alive` | host_discovery (50) | NETWORK | active | safe, network, full | host |
| `netdiscover` | host_discovery (60) | NETWORK | active | network, full | host |
| `udp_scan` | udp_scan (50) | NETWORK | active | network, full | host |
| `traceroute` | network_path (50) | NETWORK | active | network, full | host |
| `service_banner` | service_banner (50) | NETWORK | active | safe, network, full | host + services |
| `ssh_algorithms` | ssh_info (50) | NETWORK | active | network, full | host + services |
| `smtp_probe` | smtp_info (50) | NETWORK | active | network, full | host + services |
| `ftp_probe` | ftp_info (50) | NETWORK | active | network, full | host + services |
| `smb_probe` | smb_info (50) | NETWORK | active | network, full | host + services |
| `enum4linux_ng` | smb_info (40) | NETWORK | active | network, full | host + services |
| `snmp_probe` | snmp_info (50) | NETWORK | active | network, full | host |
| `redis_probe` | redis_info (50) | NETWORK | active | network, full | host + services |
| `mysql_probe` | mysql_info (50) | NETWORK | active | network, full | host + services |
| `dns_recon` | dns_resolve (10) | DNS | read-only | all | hostname |
| `dns_nslookup` | dns_resolve (20) | DNS | read-only | all | hostname |
| `reverse_dns` | reverse_dns (50) | DNS | read-only | web, network, full | host |
| `dns_zone_transfer` | zone_transfer (50) | DNS | read-only | network, full | hostname |
| `subdomain_enum` | subdomain (50) | DNS | read-only | network, full | hostname |
| `amass_enum` | subdomain (40) | DNS | passive | network, full | hostname |
| `dnsrecon` | dns_enum (40) | DNS | active | web, network, full | hostname |
| `http_posture` | http_headers (10) | WEB | passive | safe, web, full | base_url |
| `http_curl` | http_headers (20) | WEB | passive | safe, web, full | base_url |
| `http_favicon` | http_favicon (50) | WEB | active | web, full | base_url |
| `http_waf_detect` | http_waf_detect (50) | WEB | passive | web, full | base_url |
| `whatweb` | http_fingerprint (40) | WEB | passive | web, full | base_url |
| `wafw00f` | http_waf_detect (40) | WEB | passive | web, full | base_url |
| `web_content` | web_content (50) | CONTENT | passive | web, full | base_url |
| `gobuster_scan` | web_content (40) | CONTENT | active | web, full | base_url |
| `tls_posture` | tls_info (10) | TLS | active | all | host |
| `tls_openssl` | tls_info (20) | TLS | active | all | host |
| `whois_lookup` | whois (50) | OSINT | read-only | web, network, full | hostname |
| `theharvester` | osint (50) | OSINT | passive | web, full | hostname |
| `advisory_match` | advisory (50) | ADVISORY | read-only | all | services |

See [`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md) for parameters and outputs.

---

## SentinelX Discovery contract

The agent consumes the shared-agent **input** and returns the **`AssetInventory`** output defined
in the SentinelX contracts. Models live in [`app/contracts/`](app/contracts) (strict Pydantic,
`extra="forbid"`), with JSON Schemas and example JSON in [`docs/contracts/`](docs/contracts).

* **Input:** common input (`workspace_id/run_id/task_id`, `environment_kind`, `scope_ref`,
  `available_capabilities`, `remaining_budget`, …) + Discovery input (`target_seeds`,
  `discovery_limits`, `access_profiles`, `network_context`, `web_context`,
  `discovery_questions`).
* **Output:** common output (`status`, `artifact_refs`, `proposed_actions`, `assumptions`,
  `coverage_gaps`, `required_gate`, `concise_rationale`, `next_objective`) + `AssetInventory`
  (`assets`, `services`, `host_observations`, `relationship_proposals`,
  `observation_provenance`, `uncertainties`, `unassessed_targets`) + the Web extension
  `WebAssetInventory` (`applications`, `endpoints`, `web_observations`, `evidence`,
  `route_coverage`, `authentication_coverage`, `relationship_proposals`,
  `observation_provenance`, `uncertainties`, `unassessed_targets`).
* **Status:** `DONE · MORE_WORK · BLOCKED · NEEDS_REVIEW · FAILED`; missing input ⇒ `BLOCKED`
  with gate `INPUT`; no consent ⇒ `BLOCKED` with gate `AUTHORIZATION`.
* **Honesty:** a version string is a `banner`/`version_claimed` observation (never
  `package_verified` without authenticated package evidence) with an `uncertainty`; every
  observation carries provenance (source tool, version, runner, time); an unreachable host
  is never reported as `DONE`.

```bash
python scripts/export_contracts.py     # regenerate schemas + example JSON
```

Full field tables, rejection rules and cases: [`docs/contracts/CONTRACT.md`](docs/contracts/CONTRACT.md).

### Scan surfaces (profiles)

The same input is assessed as two separate surfaces; pick one or both.

* **network** (27 tools) — host/port/service discovery, version/banner detection,
  DNS/zone-transfer, subdomain enumeration, service probes (SSH, SMTP, FTP, SMB,
  SNMP, Redis, MySQL), TLS and routing. **No HTTP/Web tools run.**
* **web** (17 tools) — HTTP posture/headers/cookies, TLS, technology+version
  fingerprinting, content/route discovery, WAF/edge detection and domain OSINT.
  **No port scanners run** (the URL already names the origin and port).
* **full** (36 tools) — both surfaces in one run.
* **safe** (11 tools, default) — conservative baseline of network + HTTP + TLS with
  polite limits: `nmap_discovery`, `tcp_scan`, `host_alive`, `service_banner`,
  `dns_recon`, `dns_nslookup`, `http_posture`, `http_curl`, `tls_posture`,
  `tls_openssl`, `advisory_match`.

Every Web run also emits a `WebAssetInventory`: observed applications and
technologies (with claimed versions and verification status), routes/endpoints
(observed vs declared/spec-only), headers/cookies/TLS/auth-boundary
observations, traceable evidence records, route/authentication coverage,
provenance (source URL, tool version, time), uncertainties and explicitly
unassessed routes. A declared route (robots/sitemap/API spec) is never treated
as a vulnerability, and a 404/blocked crawl is a recorded gap, not a clean
result.

---

## Evidence, verification and coverage

The upgrade distinguishes an *observation* from a *verified fact*:

| Field | Meaning |
| --- | --- |
| `observation_type` | `fingerprint_observed`, `banner_observed`, `version_claimed`, `version_verified`, `package_verified`, `unknown` |
| `verification_status` | `unverified` (default), `verified`, `package_verified`, `rejected`, `unknown` |
| `confidence` | `low`, `medium`, `high`, `unknown` |
| `evidence` | Sanitised snippets plus the source tool/method/URL/time |

* **Version validation:** `app/agents/technologies.py` accepts a candidate only
  when it looks like a software version (digits plus optional dotted/suffix
  parts). IP addresses, country names, MIME types (`application/json`) and
  header directives (`max-age=2592000`) are rejected and retained as evidence
  with an explicit uncertainty — they are never printed as versions.
* **No silent promotion:** HTML/JS/WhatWeb/banner/header versions stay
  `version_claimed`/`banner_observed` and `unverified`. `package_verified`
  requires authenticated package inventory, which this non-destructive
  external-probe agent does not collect.
* **Duplicates and conflicts:** observations are merged by canonical technology
  name; conflicting versions are preserved in `conflicting_versions` with a
  `low` confidence uncertainty instead of being silently dropped.
* **HTTP classification:** 2xx `success`, 3xx `redirect`, 401
  `auth_required`, 403 `forbidden`, 404 `not_found`, 429 `rate_limited`,
  5xx `server_error`, plus `timeout`, `dns_failure`, `tls_error` and
  `connection_error`. A 403 is **not** attributed to Cloudflare; a vendor is
  recorded only when specific CDN/WAF headers/cookies are present.
* **Bounded retries:** only 429/5xx/timeouts/connection errors are retried, with
  exponential backoff + jitter (`APS_HTTP_RETRIES`, `APS_HTTP_RETRY_BACKOFF`,
  `APS_HTTP_RETRY_MAX_BACKOFF`, `APS_HTTP_RETRY_JITTER`). 401/403/404 are never
  retried.
* **Partial results:** `web_content` reports each well-known resource as
  `retrieved`, `missing`, `inaccessible`, `network_error` or `parse failed`;
  Gobuster records exit code, timeout, duration, attempted/untested counts and
  preserves output on timeout. A zero-result Gobuster run is a clean `ok`, not
  a failure, and never proves absence.
* **Route coverage:** `RouteCoverage` reports attempted/confirmed/inaccessible/
  failed/untested routes, executed/skipped methods and limitations. It stays
  `limited`/`partial`/`unknown` when access controls, missing authentication or
  tool failures prevent confirmation — never `full` just because every
  configured candidate was attempted.
* **Authentication coverage:** without an authorized profile the report says
  `not_assessed`; supplied profiles are recorded but **not exercised** and are
  marked `profiles_supplied_not_exercised`. The agent never guesses credentials,
  sprays passwords or logs in.
* **Final JSON report:** `POST /report.json` returns the standardised sections
  `scan_metadata`, `scope_validation`, `assets`, `services`, `technologies`,
  `web_observations`, `routes`, `evidence`, `tool_results` (success/partial/
  failed/unavailable/skipped/not_run), `authentication_coverage`,
  `route_coverage`, `uncertainties`, `errors` and `overall_status`, plus the
  legacy `findings`/`web_inventory` keys.

Details and test cases: [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md).

---

## Optional LLM reasoning

The agent runs **fully offline by default**. Set an OpenAI-compatible API key and the
Discovery planner will ask a model to choose among the registered, profile-eligible tools
(the result is validated against that allow-list, so the model can never introduce an
unregistered capability). Without a key, or on any error, the deterministic best-per-capability
plan is used instead — behaviour and the test suite stay unchanged.

```bash
# PowerShell
$env:APS_LLM_API_KEY="sk-..."          # or OPENAI_API_KEY
$env:APS_LLM_MODEL="gpt-4o-mini"       # optional
$env:APS_LLM_BASE_URL="https://api.openai.com/v1"   # optional, any OpenAI-compatible gateway
```

Copy `.env.example` to `.env` for a drop-in template. `GET /api/llm` reports whether LLM
reasoning is active (it never returns the key). Only non-sensitive context (objective, target
host, capability names) is sent — never credentials or raw evidence.

---

## Install and run

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

.venv\Scripts\python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>, enter a target you are authorized to assess, tick the
acknowledgement, and run a profile. **Install [Nmap](https://nmap.org/download) to enable
`nmap_discovery`** — every other tool works without it, so the platform still discovers
services via the built-in TCP scanner.

### API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Web interface |
| GET | `/healthz` | Liveness probe (includes `llm` flag) |
| GET | `/api/tools` | Tool catalog as JSON |
| GET | `/api/llm` | Whether LLM reasoning is enabled (no key exposed) |
| GET | `/api/contracts` | SentinelX Discovery contract JSON Schemas |
| POST | `/api/discovery` | Run Discovery against a contract input, return the contract result |
| POST | `/api/scan` | Run an assessment, return the full state as JSON |
| POST | `/scan` | Run and render the HTML dashboard |
| POST | `/report.json` | Run and download the **JSON report** (primary: findings, services, Web inventory, contract result) |
| POST | `/report` | Run and download the optional PDF report |

---

## Safety and honesty model

* **Authorization gate first** — no consent, no scan. Injection-style or malformed input can
  never become a target.
* **Non-destructive only** — read-only probes; the "aggressive" options are still bounded and
  payload-free.
* **Redaction at every boundary** — `Set-Cookie`, `Authorization`, API keys and tokens are
  masked before display/export.
* **Evidence thresholds** — a finding is `Confirmed` only with a concrete observation;
  otherwise it is `Potential` / `Needs validation`.
* **Failures are visible** — an unavailable tool or empty result becomes an explicit
  *coverage gap*, never a "secure" conclusion.

---

## Testing

```bash
.venv\Scripts\python -m pytest -q
```

Tests are hermetic (local HTTP server + local sockets, Nmap disabled) and cover the guardrails,
tool registry, each new tool, the adaptive workflow and report generation.

---

## Project layout

```
autopentest-sentinel/
├─ app/
│  ├─ main.py                 FastAPI app
│  ├─ config.py               settings and safe defaults
│  ├─ api/routes.py           HTTP + JSON endpoints
│  ├─ agents/                 state · nodes · graph · inventory · technologies · web_inventory
│  ├─ contracts/              SentinelX common + Discovery contract models
│  ├─ net/http.py             classified HTTP client (retries, edge detection)
│  ├─ tools/                  base · registry · one module per tool
│  ├─ safety/                 authorization.py · redaction.py
│  ├─ models/schemas.py       Finding / EvidenceItem (Pydantic)
│  ├─ knowledge/retrieval.py  local remediation retrieval
│  ├─ llm/                    optional OpenAI-compatible planner (provider · reasoning)
│  └─ reporting/              json_report.py (primary) · pdf.py (optional)
├─ data/knowledge/            remediation knowledge base + advisories.json
├─ data/wordlists/            subdomain wordlist
├─ docs/                      TOOL_CATALOG, PRESENTATION_OUTLINE, contracts/
├─ scripts/export_contracts.py JSON Schema + example JSON exporter
├─ tests/                     pytest suite
└─ requirements.txt
```

---

## Adding a tool

```python
# app/tools/my_tool.py
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

@tool(
    name="my_check",
    description="One-line description.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_headers",   # same capability => automatic fallback peer
    priority=30,                 # lower runs first within the capability
    requires=("base_url",),
    profiles=("web", "full"),
    order=65,
)
def my_check(ctx: ToolContext) -> ToolResult:
    ...
    return ToolResult(
        tool="my_check", status="ok", summary="...",
        data={"...": "..."},
        evidence=[evidence("my_check", "concrete observation")],
    )
```

Import it in `app/tools/__init__.py` and it is automatically planned, executed, validated and
reported.

---

## Requirements mapping (course rubric)

| Requirement | Implementation |
| --- | --- |
| SentinelX Discovery contract | `app/contracts/` — strict `DiscoveryInput` → `AssetInventory` + `CommonOutput`; schemas/examples in `docs/contracts/` |
| Agentic workflow | `app/agents/graph.py` plans, executes, **adapts**, validates and **projects** the contract result |
| Design pattern | Supervisor-style planner–executor with authorization router and evidence validator |
| LangGraph | typed state, nodes, conditional edges (`agents/state.py`, `agents/graph.py`) |
| Modular tools | registry-driven `app/tools/` with 36 real tools and capability-based redundancy |
| LlamaIndex | `app/knowledge/retrieval.py` local remediation retrieval |
| Guardrails | `app/safety/` authorization, validation, redaction, honest failure states |
| Edge cases | missing authorization, malformed/injection input, tool failures, limited responses, no TLS |
| Reporting | `app/reporting/pdf.py` evidence-based PDF |
