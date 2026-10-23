"""Export the SentinelX Discovery contract: JSON Schemas + example JSON.

Run:  python scripts/export_contracts.py
Writes to docs/contracts/ and validates the example output against the model.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.contracts import (  # noqa: E402
    DiscoveryInput,
    DiscoveryResult,
    SCHEMA_MODELS,
    default_discovery_input,
    export_schemas,
)

OUT_DIR = ROOT / "docs" / "contracts"

EXAMPLE_OUTPUT = {
    "runtime": {
        "schema_version": "1.0",
        "workspace_id": "ws-demo",
        "run_id": "run-0001",
        "environment_id": "env-0001",
        "agent_id": "discovery",
        "model_call_id": None,
    },
    "output": {
        "status": "DONE",
        "artifact_refs": ["artifact:asset_inventory:run-0001"],
        "evidence_refs": ["prov:nmap_discovery", "prov:service_banner"],
        "proposed_actions": [],
        "assumptions": [
            "All observations are external/unauthenticated unless an access profile states otherwise.",
            "Service version strings are banner observations and are not authenticated package evidence.",
        ],
        "coverage_gaps": [],
        "required_gate": None,
        "concise_rationale": "Collected 1 service record and 2 sourced observation sets on 1 seed.",
        "next_objective": None,
    },
    "inventory": {
        "assets": [
            {
                "asset_id": "asset:10.0.0.5",
                "identity": "10.0.0.5",
                "addresses": ["10.0.0.5"],
                "os": None,
                "os_basis": None,
                "evidence_refs": [],
            }
        ],
        "services": [
            {
                "service_id": "svc:10.0.0.5:22/tcp",
                "asset_id": "asset:10.0.0.5",
                "port": 22,
                "transport": "tcp",
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.9p1",
                "version_basis": "banner",
                "authenticated": False,
                "reachability": "REACHABLE",
                "uncertainty": [
                    "version '8.9p1' is a banner observation, not authenticated package evidence"
                ],
                "evidence_refs": ["prov:service_banner"],
            }
        ],
        "host_observations": [
            {
                "asset_id": "asset:10.0.0.5",
                "category": "service-banner",
                "key": "ssh",
                "value": "SSH-2.0-OpenSSH_8.9p1",
                "basis": "configuration",
                "evidence_refs": ["prov:service_banner"],
            }
        ],
        "relationship_proposals": [
            {
                "kind": "observed",
                "from_ref": "svc:10.0.0.5:22/tcp",
                "to_ref": "asset:10.0.0.5",
                "relation": "service-on-host",
                "evidence_refs": ["prov:service_banner"],
            }
        ],
        "observation_provenance": [
            {
                "observation_id": "prov:nmap_discovery",
                "source_tool": "nmap_discovery",
                "tool_version": "1.0",
                "runner_id": "runner-local",
                "identity": "external-probe",
                "environment": "REAL",
                "observed_at": "2026-10-16T10:00:00Z",
                "command": "nmap -sV --version-light --top-ports 100 -T3 -oX - 10.0.0.5",
                "evidence_refs": ["ev:nmap_discovery:0"],
            },
            {
                "observation_id": "prov:service_banner",
                "source_tool": "service_banner",
                "tool_version": "1.0",
                "runner_id": "runner-local",
                "identity": "external-probe",
                "environment": "REAL",
                "observed_at": "2026-10-16T10:00:05Z",
                "command": "read banner 10.0.0.5:22",
                "evidence_refs": ["ev:service_banner:0"],
            },
        ],
        "uncertainties": [
            {
                "subject": "svc:10.0.0.5:22/tcp",
                "detail": "version '8.9p1' is a banner observation, not authenticated package evidence",
                "evidence_refs": ["prov:service_banner"],
            }
        ],
        "unassessed_targets": [],
    },
    "web_inventory": {
        "applications": [
            {
                "application_id": "app:https://demo.example.com",
                "origin": "https://demo.example.com",
                "identity": "Demo Portal",
                "title": "Demo Portal",
                "base_paths": ["/"],
                "technologies": [
                    {
                        "name": "nginx",
                        "version": "1.25.3",
                        "basis": "banner",
                        "evidence_refs": ["prov:whatweb"],
                    }
                ],
                "server": "nginx/1.25.3",
                "waf": "Cloudflare",
                "evidence_refs": ["prov:http_posture"],
            }
        ],
        "endpoints": [
            {
                "endpoint_id": "endpoint:https://demo.example.com:GET /",
                "application_id": "app:https://demo.example.com",
                "path": "/",
                "method": "GET",
                "parameters": [],
                "forms": [],
                "api_operation": None,
                "observed": True,
                "status": 200,
                "source": "http_posture",
                "evidence_refs": ["prov:http_posture"],
            },
            {
                "endpoint_id": "endpoint:https://demo.example.com:GET /admin",
                "application_id": "app:https://demo.example.com",
                "path": "/admin",
                "method": "GET",
                "parameters": [],
                "forms": [],
                "api_operation": "robots-declared",
                "observed": False,
                "status": None,
                "source": "web_content:robots",
                "evidence_refs": ["prov:web_content"],
            },
        ],
        "web_observations": [
            {
                "application_id": "app:https://demo.example.com",
                "category": "http",
                "key": "title",
                "value": "Demo Portal",
                "basis": "configuration",
                "evidence_refs": ["prov:http_posture"],
            }
        ],
        "relationship_proposals": [
            {
                "kind": "observed",
                "from_ref": "app:https://demo.example.com",
                "to_ref": "origin:https://demo.example.com",
                "relation": "app-on-origin",
                "evidence_refs": ["prov:http_posture"],
            },
            {
                "kind": "inferred",
                "from_ref": "endpoint:https://demo.example.com:GET /admin",
                "to_ref": "app:https://demo.example.com",
                "relation": "route-in-app",
                "evidence_refs": ["prov:web_content"],
            },
        ],
        "observation_provenance": [
            {
                "observation_id": "prov:http_posture",
                "source_tool": "http_posture",
                "tool_version": "1.0",
                "runner_id": "runner-local",
                "identity": "external-probe",
                "environment": "REAL",
                "observed_at": "2026-10-16T10:00:00Z",
                "command": "GET https://demo.example.com",
                "evidence_refs": [],
                "source_url": "https://demo.example.com",
            }
        ],
        "uncertainties": [
            {
                "subject": "app:https://demo.example.com",
                "detail": (
                    "no authenticated access profile was supplied; authenticated routes "
                    "and role boundaries were not observed"
                ),
                "evidence_refs": [],
            }
        ],
        "unassessed_targets": [
            {
                "target": "https://demo.example.com/admin",
                "reason": "declared in robots.txt but not fetched (non-destructive crawl limit)",
                "category": "unassessed-route",
            }
        ],
    },
}


def main() -> None:
    written = export_schemas(OUT_DIR)

    example_input = default_discovery_input(
        "https://demo.example.com", consent=True, run_id="run-0001"
    )
    (OUT_DIR / "example_input.json").write_text(
        json.dumps(example_input.model_dump(mode="json"), indent=2), encoding="utf-8"
    )

    validated = DiscoveryResult.model_validate(EXAMPLE_OUTPUT)
    (OUT_DIR / "example_output.json").write_text(
        json.dumps(validated.model_dump(mode="json"), indent=2), encoding="utf-8"
    )

    # Round-trip the example input through the model as a self-check.
    DiscoveryInput.model_validate(example_input.model_dump(mode="json"))

    for path in written:
        print("wrote", path.relative_to(ROOT))
    print("wrote", (OUT_DIR / "example_input.json").relative_to(ROOT))
    print("wrote", (OUT_DIR / "example_output.json").relative_to(ROOT))
    print(f"validated {len(SCHEMA_MODELS)} schemas + example input/output")


if __name__ == "__main__":
    main()
