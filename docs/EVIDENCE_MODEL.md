# Evidence, verification and coverage model

This document describes how the Discovery Agent separates observations from
verified facts, how it classifies failures, and how coverage is reported. It is
the reference for the Web reliability upgrade.

## 1. Technology observations

`TechnologyRecord` (in `app/contracts/discovery.py`) has:

| Field | Values |
| --- | --- |
| `name` | canonical technology name (`jQuery`, `WordPress`, `nginx`, ...) |
| `version` | accepted version or `null` |
| `observation_type` | `fingerprint_observed`, `banner_observed`, `version_claimed`, `version_verified`, `package_verified`, `unknown` |
| `verification_status` | `unverified`, `verified`, `package_verified`, `rejected`, `unknown` |
| `confidence` | `low`, `medium`, `high`, `unknown` |
| `basis` | contract `ObservationBasis` (`banner`, `authenticated-package`, `configuration`, `inferred`) |
| `evidence` | sanitised evidence snippets (including rejected candidates) |
| `source_url`, `collection_method`, `observed_at` | traceability |
| `conflicting_versions` | other versions seen for the same technology |

Normalisation lives in `app/agents/technologies.py`:

* A version is accepted only if it looks like a software version: it starts
  with a digit (optional `v`), has no whitespace/header separators, is not an
  IP address, and is not a country name/MIME type/keyword.
* HTML, JavaScript, WhatWeb, banner and header values become
  `version_claimed`/`banner_observed` with `verification_status=unverified`
  and `confidence=low|medium`.
* `version_verified` and `package_verified` are reserved for independent or
  authenticated package evidence; the external-probe agent does not set them.
* Rejected values are kept in `evidence` and reported as an `Uncertainty`.
* Duplicate names are merged; conflicting versions are preserved in
  `conflicting_versions` and reported as an uncertainty.

## 2. Confidence

* `high` — reserved for independently verified versions (not produced by
  external fingerprinting).
* `medium` — a technology was observed directly (e.g. a specific server header)
  but the version is absent/unverified.
* `low` — a version is claimed by HTML/JS/WhatWeb/banner/header, or conflicting
  versions exist.
* `unknown` — not enough evidence to classify.

Multiple tools returning the same unverified banner does **not** raise
confidence; the observations are merged as evidence, not as verification.

## 3. Evidence records

`WebAssetInventory.evidence` contains `EvidenceRecord` entries:

```
evidence_id, type, source_tool, target, status, snippet,
observed_at, confidence, verification_status, limitations, evidence_refs
```

Endpoints, applications, services and assets also carry `evidence` (snippets)
and `evidence_refs` (provenance ids). Snippets are redacted before export
(`Set-Cookie`, `Authorization`, tokens and secrets are masked).

## 4. HTTP response classification and retries

`app/net/http.py`:

| Class | Status / cause |
| --- | --- |
| `success` | 2xx |
| `redirect` | 3xx |
| `auth_required` | 401 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `rate_limited` | 429 |
| `client_error` | other 4xx |
| `server_error` | 5xx |
| `timeout` | connect/read/write/pool timeout |
| `dns_failure` | name resolution failure |
| `tls_error` | certificate/TLS failure |
| `connection_error` | reset/refused/network error |

* Retries: only 429, 5xx, timeout and connection errors. Bounded by
  `APS_HTTP_RETRIES` (default 2), with exponential backoff and jitter.
  `Retry-After` is honoured (capped).
* Deterministic responses (401/403/404/400/405/...) are **never** retried.
* CDN/WAF detection uses specific headers/cookies (`cf-ray`, `x-amz-cf-id`,
  `x-akamai-*`, `x-iinfo`, ...). A bare 403 is never labelled Cloudflare.
* A limited response is marked `limited=true` and is not graded as secure.

## 5. Web content (`web_content`)

Each configured well-known path (`/robots.txt`, `/sitemap.xml`,
`/.well-known/security.txt`) has its own result:

```
status, response_class, content_type, size, retrieved, redirected,
attempts, retries, outcome, parse_status, parse_error
```

`outcome` is one of `retrieved`, `missing`, `inaccessible`, `network_error`,
`http_error`. A parser failure is isolated per resource and does not discard
other resources. Missing files are never treated as proof of no content.

## 6. Gobuster (`gobuster_scan`)

The result records:

* `returncode`, `timed_out`, `completed`, `duration_ms`
* `tested`, `attempted`, `untested`
* `valid_responses`, `rejected_responses`, `server_error_responses`
* `paths`, `confirmed_paths` (empty when responses are a uniform access-control
  page)
* `base_status`, `base_response_class`, `base_edge_indicators`
* `uniform_response`, `suspicious_uniform`
* `zero_result_success`

A completed scan with zero results is `status=ok`, not `partial`. A timeout with
partial output is `partial`; a timeout/process failure without output is
`failed`. Zero results never prove that no paths exist.

## 7. Route coverage

`RouteCoverage`:

```
routes_attempted, routes_confirmed, routes_inaccessible,
routes_failed, routes_untested, coverage_status,
coverage_limitations, methods_executed, methods_skipped
```

`coverage_status` rules:

* `unknown` — no Web discovery method ran.
* `limited` — the base URL returned 401/403/429, CDN/WAF indicators are
  present, Gobuster/`web_content` failed or was unavailable, or Gobuster
  returned a uniform access-control page.
* `partial` — some routes were unconfirmed, untested, unparsable or
  authentication was unavailable.
* `full` — every configured method completed and every attempted route was
  confirmed.

Attempting every configured candidate does not make coverage `full`.

## 8. Authentication coverage

`AuthenticationCoverage` records `profiles_supplied`,
`authenticated_profiles`, completed checks, unverified checks and notes.

* No profile ⇒ `status=not_assessed`; the report explicitly says authenticated
  routes, role boundaries and post-login flows were not assessed.
* Profiles supplied ⇒ `status=profiles_supplied_not_exercised`; the agent does
  not log in, replay secrets, guess credentials or spray passwords. Secrets are
  never read from source or written to logs/reports.
* Role-based coverage metadata is recorded, but authorization boundaries are
  not claimed as tested unless a check was actually performed.

## 9. Final report

`POST /report.json` returns:

`report` (legacy), `summary`, `scan_metadata`, `scope_validation`, `assets`,
`services`, `technologies`, `web_observations`, `routes`, `evidence`,
`tool_results`, `authentication_coverage`, `route_coverage`, `uncertainties`,
`errors`, `overall_status`, plus `findings`, `web_inventory`, `inventory`,
`coverage_gaps`, `events` and `agent_result` for backward compatibility.

`overall_status` is `success`, `partial`, `blocked`, `inconclusive` or `failed`.
An access-control base response makes it `inconclusive`; any failed/partial
tool or limited route coverage makes it `partial`.

## 10. Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `APS_HTTP_TIMEOUT` | `12` | per-request timeout (s) |
| `APS_HTTP_RETRIES` | `2` | transient retry count |
| `APS_HTTP_RETRY_BACKOFF` | `0.3` | base backoff (s) |
| `APS_HTTP_RETRY_MAX_BACKOFF` | `4` | backoff cap (s) |
| `APS_HTTP_RETRY_JITTER` | `0.2` | random jitter (s) |
| `APS_NMAP_TIMEOUT` | `120` | Gobuster/subprocess timeout (s) |

Authorized access profiles are supplied through the Discovery contract input
(`access_profiles`: `id`, `kind`, `authenticated`, `privileges`, `secret_ref`).
`secret_ref` is a protected reference; secret material is never placed in the
contract.

## 11. Tests

```bash
python -m pytest -q
```

`tests/test_web_reliability.py` covers the 14 required cases: unverified
version, malformed metadata, 200/403/429, timeout-then-success, 404 well-known,
parser failure, Gobuster zero/failure/timeout, missing auth profile, partial
result preservation, limited route coverage after access-control, and final
report serialisation. All tests are hermetic (mocked transport, local fixtures).
