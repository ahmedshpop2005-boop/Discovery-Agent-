# Discovery Agent — Contract (SentinelX AI, role: Shaaban)

Implements the **Discovery** role of the SentinelX shared agent contracts v1.0.
Discovery builds a sourced inventory of assets, services and available context
and hands it to the Pentesting agent. Everything here is enforced by strict
Pydantic models (`extra="forbid"`); unknown fields and invalid enum values are
**rejected at validation time**.

Source of truth: [`app/contracts/`](../../app/contracts). Generated schemas and
examples live in this directory (`*.schema.json`, `example_input.json`,
`example_output.json`) and are regenerated with:

```bash
python scripts/export_contracts.py
```

## 1. Common input (every role)

| Field | Required | Notes |
| --- | --- | --- |
| `workspace_id` | yes | UUID identifying the workspace |
| `run_id` | yes | UUID identifying the run |
| `task_id` | yes | UUID identifying the assigned task |
| `environment_id` | yes | Exact environment identity |
| `environment_kind` | yes | `REAL` or `TWIN` |
| `objective` | yes | Task objective |
| `selected_stages` | no (default `[]`) | A stage does not itself grant authorization |
| `scope_ref` | yes | `{scope_id, version, targets, permitted_effects, expires_at}` |
| `context_refs` / `evidence_refs` | no (default `[]`) | Resolved by the context builder |
| `available_capabilities` | no (default `[]`) | Registered capability IDs + versions |
| `remaining_budget` | no (default `{}`) | time / ops / token-cost limits |

## 2. Discovery role-specific input

| Field | Required | Notes |
| --- | --- | --- |
| `common` | yes | The common input above |
| `target_seeds` | yes (may be empty, see gates) | Authorized IPs/hostnames/CIDR |
| `discovery_limits` | no | `{ports, protocols, methods, scan_rate, concurrency, duration_seconds}` |
| `known_inventory_refs` | no (default `[]`) | Prior observations (may be empty) |
| `access_profiles` | no (default `[]`) | Identities/privileges; **secret material stays out** (only `secret_ref`) |
| `network_context` | yes | `{runner_id, source_network, known_topology}` |
| `web_context` | no | `{runner_origin, base_path, reverse_proxy, api_specs[], auth_flows[]}` |
| `discovery_questions` | no (default `[]`) | Specific unanswered questions |

## 3. Discovery role-specific output: `AssetInventory`

| Field | Content |
| --- | --- |
| `assets` | `{asset_id, identity, addresses[], os, os_basis, evidence[], evidence_refs[]}` |
| `services` | `{service_id, asset_id, port, transport, name, product, version, version_basis, authenticated, reachability, uncertainty[], evidence[], evidence_refs[]}` |
| `host_observations` | `{asset_id, category, key, value, basis, evidence_refs[]}` |
| `relationship_proposals` | `{kind (observed\|inferred), from_ref, to_ref, relation, evidence_refs[]}` |
| `observation_provenance` | `{observation_id, source_tool, tool_version, runner_id, identity, environment, observed_at, command, evidence_refs[]}` |
| `uncertainties` | `{subject, detail, evidence_refs[]}` |
| `unassessed_targets` | `{target, reason, category}` |

## 3b. Web extension output: `WebAssetInventory`

| Field | Content |
| --- | --- |
| `applications` | `{application_id, origin, identity, title, base_paths[], technologies[], server, waf, evidence_refs[]}` |
| `technologies[]` | `{name, version, observation_type, verification_status, confidence, basis, evidence[], source_url, collection_method, observed_at, conflicting_versions[], evidence_refs[]}` |
| `endpoints` | `{endpoint_id, application_id, path, method, parameters[], forms[], api_operation, observed, status, classification, collection_method, source, evidence[], limitations[], evidence_refs[]}` |
| `forms[]` | `{action, method, parameters[]}` |
| `web_observations` | `{application_id, category, key, value, basis, source_url, collection_method, evidence[], evidence_refs[]}` |
| `evidence` | `{evidence_id, type, source_tool, target, status, snippet, observed_at, confidence, verification_status, limitations[], evidence_refs[]}` |
| `route_coverage` | `{routes_attempted, routes_confirmed, routes_inaccessible, routes_failed, routes_untested, coverage_status, coverage_limitations[], methods_executed[], methods_skipped[]}` |
| `authentication_coverage` | `{status, profiles_supplied, authenticated_profiles, checks_completed[], checks_unverified[], notes[]}` |
| `relationship_proposals` | `{kind, from_ref, to_ref, relation, evidence_refs[]}` (app-on-origin, route-in-app, role-access, submits-data) |
| `observation_provenance` | provenance **plus** `source_url` |
| `uncertainties` | rejected versions, conflicting versions, declared-but-unrequested routes, blocked/4xx crawl, missing auth, coverage limitations |
| `unassessed_targets` | declared routes, authenticated surface, unavailable tools (`category="unassessed-route"\|"access"\|"tooling"`) |

`observed=true` means the route was requested and answered. Routes declared by
robots.txt/sitemap/API spec/client-script are `observed=false` (spec-only) and are never
treated as vulnerabilities. A 404 or blocked crawl is a recorded gap, not a clean result.

A 401/403/429 base response is classified (`auth_required`/`forbidden`/`rate_limited`), is
never attributed to a vendor without specific CDN/WAF headers, and forces
`route_coverage.coverage_status` to `limited`. `versions` from HTML/JS/WhatWeb/banners/
headers are `unverified` and must not be read as package versions. `evidence` is redacted
and traceable; see [`../EVIDENCE_MODEL.md`](../EVIDENCE_MODEL.md).

## 4. Common output (every role)

| Field | Content |
| --- | --- |
| `status` | `DONE` · `MORE_WORK` · `BLOCKED` · `NEEDS_REVIEW` · `FAILED` |
| `artifact_refs` / `evidence_refs` | References that must resolve in the workspace |
| `proposed_actions` | Typed `{capability, capability_version, stage, asset_ids, environment, parameter_ref, evidence_refs, dependency_ids, cleanup_plan_ref}` |
| `assumptions` | Explicit assumptions |
| `coverage_gaps` | Unsupported checks, missing access, untested/inconclusive areas |
| `required_gate` | `INPUT` · `AUTHORIZATION` · `APPROVAL` · `REVIEW` · `null` |
| `concise_rationale` | Brief evidence-based explanation |
| `next_objective` | Next objective, or `null` |

The stored result is `DiscoveryResult = { runtime, output, inventory, web_inventory? }`, where
`runtime` holds `schema_version, workspace_id, run_id, environment_id, agent_id,
model_call_id` — assigned by the trusted runtime, not the model.

## 5. Status semantics

| Status | When |
| --- | --- |
| `BLOCKED` (gate `INPUT`) | Required input missing (e.g. no `target_seeds`) |
| `BLOCKED` (gate `AUTHORIZATION`) | Consent / authorization not granted |
| `NEEDS_REVIEW` (gate `REVIEW`) | Conflicting observations need human review |
| `MORE_WORK` | Coverage gaps, unassessed targets or no services; `next_objective` set |
| `DONE` | Services collected and no gaps/conflicts |
| `FAILED` | Reserved for unrecoverable internal error |

**An unreachable host is never reported as `DONE`** — it becomes `MORE_WORK`
with an `unassessed_targets` entry (`category="unreachable"`).

## 6. Rejection rules

* Any **unknown field** in any model → `ValidationError` (`extra="forbid"`).
* Missing **required** fields (`common`, `scope_ref`, `network_context`,
  `workspace_id`, …) → `ValidationError`.
* Invalid **enum** values (`environment_kind`, `status`, `reachability`,
  `version_basis`, `required_gate`) → `ValidationError`.
* Credentials must not appear: only a protected `secret_ref` is allowed.

## 7. Cases (all covered by `tests/test_contracts.py`)

| Case | Expected |
| --- | --- |
| Valid input, reachable target | `DONE`/`MORE_WORK`; populated `assets`, `services`, `observation_provenance` |
| Missing `target_seeds` | `BLOCKED`, gate `INPUT`, empty inventory |
| No consent / authorization | `BLOCKED`, gate `AUTHORIZATION` |
| Unknown field / bad enum | `ValidationError` (rejection) |
| Tool fails or is unavailable | recorded in `coverage_gaps` + `unassessed_targets`, status not `DONE` |

## 8. Honesty rules encoded

* A version string is `version_basis="banner"`, `authenticated=false`, and adds
  an `uncertainty` — banner evidence is not authenticated package evidence.
* Every observation links to `observation_provenance` (source tool, version,
  runner, environment, time).
* Empty lists mean *no records collected*, never "no vulnerability exists".
* Authenticated and unauthenticated observations are stored separately.
