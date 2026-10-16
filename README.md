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

On top of that it has a modular, registry-based tool layer with **28 real, non-destructive
collection tools** (Nmap plus 27 built-ins) and automatic **redundancy/fallback**: if a tool or
its external binary is missing, the agent transparently switches to another tool that performs
the same job.

---

## What's new in this version

| Area | Before | Now |
| --- | --- | --- |
| Tools | Nmap + 1 HTTP + 1 TLS check | 28 registered tools (see catalog) |
| Tool layer | functions in `scanners.py` | `app/tools/` registry, metadata, capabilities |
| Redundancy | none | capability + priority with automatic fallback |
| Workflow | fixed 3 nodes | adaptive planner → executor → **re-planner** → validator |
| Records | plain dicts | typed Pydantic `Finding` / `EvidenceItem` |
| Safety | inline | `app/safety/` authorization + redaction layer |
| Scanning | Nmap only | Nmap **plus** a dependency-free async TCP scanner |

### New tools (beyond Nmap)

* **Discovery:** `masscan_scan`, `host_alive`, `udp_scan`, `traceroute`.
* **DNS:** `dns_nslookup`, `reverse_dns`, `dns_zone_transfer`.
* **HTTP/Web:** `http_curl`, `http_favicon`, `http_waf_detect`.
* **TLS:** `tls_openssl`.
* **Service probes:** `ssh_algorithms`, `smtp_probe`, `ftp_probe`, `smb_probe`, `snmp_probe`,
  `redis_probe`, `mysql_probe`.
* **Advisory:** `advisory_match` (local advisory index).

### Redundancy model

Every tool declares a `capability` and a `priority`. The planner picks the best tool per
capability; the executor automatically falls back to another tool of the same capability when the
primary one reports `failed` or `unavailable` (and only within the active profile):

| Capability | Primary | Fallback(s) |
| --- | --- | --- |
| `port_discovery` | `nmap_discovery` | `masscan_scan`, `tcp_scan` |
| `dns_resolve` | `dns_recon` | `dns_nslookup` |
| `http_headers` | `http_posture` | `http_curl` |
| `tls_info` | `tls_posture` | `tls_openssl` |

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
                 │  28 tools grouped by capability; the executor │
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
| `nmap_discovery` | port_discovery (10) | NETWORK | passive | all | host |
| `masscan_scan` | port_discovery (15) | NETWORK | active | network, full | host |
| `tcp_scan` | port_discovery (20) | NETWORK | active | all | host |
| `host_alive` | host_discovery (50) | NETWORK | active | all | host |
| `udp_scan` | udp_scan (50) | NETWORK | active | network, full | host |
| `traceroute` | network_path (50) | NETWORK | active | network, full | host |
| `service_banner` | service_banner (50) | NETWORK | active | safe, network, full | host + services |
| `ssh_algorithms` | ssh_info (50) | NETWORK | active | network, full | host + services |
| `smtp_probe` | smtp_info (50) | NETWORK | active | network, full | host + services |
| `ftp_probe` | ftp_info (50) | NETWORK | active | network, full | host + services |
| `smb_probe` | smb_info (50) | NETWORK | active | network, full | host + services |
| `snmp_probe` | snmp_info (50) | NETWORK | active | network, full | host |
| `redis_probe` | redis_info (50) | NETWORK | active | network, full | host + services |
| `mysql_probe` | mysql_info (50) | NETWORK | active | network, full | host + services |
| `dns_recon` | dns_resolve (10) | DNS | read-only | all | hostname |
| `dns_nslookup` | dns_resolve (20) | DNS | read-only | all | hostname |
| `reverse_dns` | reverse_dns (50) | DNS | read-only | web, network, full | host |
| `dns_zone_transfer` | zone_transfer (50) | DNS | read-only | network, full | hostname |
| `subdomain_enum` | subdomain (50) | DNS | read-only | full | hostname |
| `http_posture` | http_headers (10) | WEB | passive | all | base_url |
| `http_curl` | http_headers (20) | WEB | passive | all | base_url |
| `http_favicon` | http_favicon (50) | WEB | active | web, full | base_url |
| `http_waf_detect` | http_waf_detect (50) | WEB | passive | web, full | base_url |
| `web_content` | web_content (50) | CONTENT | passive | web, full | base_url |
| `tls_posture` | tls_info (10) | TLS | active | all | host |
| `tls_openssl` | tls_info (20) | TLS | active | all | host |
| `whois_lookup` | whois (50) | OSINT | read-only | web, full | hostname |
| `advisory_match` | advisory (50) | ADVISORY | read-only | all | services |

See [`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md) for parameters and outputs.

---

## SentinelX Discovery contract

The agent consumes the shared-agent **input** and returns the **`AssetInventory`** output defined
in the SentinelX contracts. Models live in [`app/contracts/`](app/contracts) (strict Pydantic,
`extra="forbid"`), with JSON Schemas and example JSON in [`docs/contracts/`](docs/contracts).

* **Input:** common input (`workspace_id/run_id/task_id`, `environment_kind`, `scope_ref`,
  `available_capabilities`, `remaining_budget`, …) + Discovery input (`target_seeds`,
  `discovery_limits`, `access_profiles`, `network_context`, `discovery_questions`).
* **Output:** common output (`status`, `artifact_refs`, `proposed_actions`, `assumptions`,
  `coverage_gaps`, `required_gate`, `concise_rationale`, `next_objective`) + `AssetInventory`
  (`assets`, `services`, `host_observations`, `relationship_proposals`,
  `observation_provenance`, `uncertainties`, `unassessed_targets`).
* **Status:** `DONE · MORE_WORK · BLOCKED · NEEDS_REVIEW · FAILED`; missing input ⇒ `BLOCKED`
  with gate `INPUT`; no consent ⇒ `BLOCKED` with gate `AUTHORIZATION`.
* **Honesty:** a version string is a `banner` observation (`authenticated=false`) with an
  `uncertainty`; every observation carries provenance (source tool, version, runner, time);
  an unreachable host is never reported as `DONE`.

```bash
python scripts/export_contracts.py     # regenerate schemas + example JSON
```

Full field tables, rejection rules and cases: [`docs/contracts/CONTRACT.md`](docs/contracts/CONTRACT.md).

### Profiles

* **safe** (default) — discovery + DNS + HTTP + TLS posture with polite limits.
* **web** — adds content discovery, favicon/WAF fingerprint and WHOIS.
* **network** — adds broader scanning, service probes and zone-transfer attempts.
* **full** — every applicable tool, including subdomain enumeration.

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
| POST | `/report` | Run and download a PDF report |

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
│  ├─ agents/                 state · nodes · graph · inventory (LangGraph + projection)
│  ├─ contracts/              SentinelX common + Discovery contract models
│  ├─ tools/                  base · registry · one module per tool
│  ├─ safety/                 authorization.py · redaction.py
│  ├─ models/schemas.py       Finding / EvidenceItem (Pydantic)
│  ├─ knowledge/retrieval.py  local remediation retrieval
│  ├─ llm/                    optional OpenAI-compatible planner (provider · reasoning)
│  └─ reporting/pdf.py        PDF report builder
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
| Modular tools | registry-driven `app/tools/` with 28 real tools and capability-based redundancy |
| LlamaIndex | `app/knowledge/retrieval.py` local remediation retrieval |
| Guardrails | `app/safety/` authorization, validation, redaction, honest failure states |
| Edge cases | missing authorization, malformed/injection input, tool failures, limited responses, no TLS |
| Reporting | `app/reporting/pdf.py` evidence-based PDF |
