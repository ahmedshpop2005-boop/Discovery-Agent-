# AutoPentest Sentinel — Presentation Outline

## 1. Problem
Security-assessment overload: engineers juggle service discovery, DNS, HTTP/TLS posture and
advisories across disconnected tools, then reconstruct context for every finding. Tool warnings
are noisy and rarely tied to evidence.

## 2. Solution
An evidence-first **agentic** platform: a LangGraph agent plans real tools, **adapts** to what it
observes, validates every result into an evidence-backed finding, and produces a report —
non-destructive and authorization-gated.

## 3. Live architecture
```
guard ▸ plan ▸ collect ▸ adapt ↺ ▸ validate ▸ report
```
* **guard** — authorization + target validation (injection-safe).
* **plan** — selects the best tool per capability from the registry by profile.
* **collect** — dispatches one tool at a time; tool errors never abort the run, and a failed/
  unavailable tool triggers an automatic fallback to another tool of the same capability.
* **adapt** — new observations trigger follow-ups (e.g. port 443 ⇒ TLS probe).
* **validate** — evidence thresholds; failures become coverage gaps.

## 4. Tool stack (28 tools, all real, all non-destructive)
Nmap · masscan · built-in async TCP scan · host-alive · UDP · traceroute · banner grab ·
SSH/SMTP/FTP/SMB/SNMP/Redis/MySQL probes · DNS (A/AAAA/MX/NS/TXT) · nslookup · reverse DNS ·
zone-transfer attempt · subdomains · HTTP posture · curl · favicon · WAF detection ·
TLS posture · OpenSSL · robots/sitemap/security.txt · WHOIS · local advisory matching.

Redundancy: tools sharing a **capability** act as fallbacks (nmap↔tcp_scan, http_posture↔http_curl,
tls_posture↔tls_openssl, dns_recon↔dns_nslookup), so a missing binary never stops the assessment.

## 4b. Contract (what Pentesting consumes)
The Discovery agent consumes the SentinelX shared **input** and returns the **`AssetInventory`**
(+ common output): assets, services, host_observations, relationship_proposals,
observation_provenance, uncertainties, unassessed_targets, with status
`DONE/MORE_WORK/BLOCKED/NEEDS_REVIEW/FAILED`. Strict Pydantic + JSON Schema; a banner version is
labelled and an unreachable host is never "DONE". See `docs/contracts/CONTRACT.md`.

## 5. Live demo (3 minutes)
1. Start the app, scan an authorized target.
2. Show the agent console: guard → plan → collect → fallback/adaptive step → validate.
3. Open a finding: evidence, confidence, remediation, knowledge source.
4. Download the PDF report.
5. Run without consent → blocked. Run against an unreachable host → coverage gap, not "secure".
6. Delete Nmap from PATH and re-run: the console shows the automatic fallback to the built-in
   TCP scanner, and discovery still succeeds.

## 6. Guardrails & honest results
Authorization first · read-only probes · secret redaction · confirmed vs potential · failures are
visible, never reported as security.

## 7. Business value
Less repetitive triage, reproducible evidence, a report an analyst can defend, and a modular tool
layer that grows without rewriting the workflow.

## 8. Roadmap
Authenticated read-only checks · improved service→advisory matching · scheduled re-assessment ·
lightweight knowledge graph of assets.
