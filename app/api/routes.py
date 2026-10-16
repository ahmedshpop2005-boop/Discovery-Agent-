"""HTTP routes for the assessment interface and JSON API."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.agents.graph import run_assessment, run_discovery
from app.config import ROOT, settings
from app.contracts import DiscoveryInput, SCHEMA_MODELS
from app.reporting import build_report
from app.tools.registry import all_specs, specs_for_profile

router = APIRouter()
templates = Jinja2Templates(directory=str(ROOT / "app" / "templates"))

_PROFILES = ["safe", "web", "network", "full"]


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": settings.app_name, "version": settings.version}


@router.get("/api/tools")
def list_tools() -> dict:
    return {
        "tools": [
            {
                "name": spec.name,
                "description": spec.description,
                "category": spec.category,
                "effect_class": spec.effect_class,
                "capability": spec.capability,
                "priority": spec.priority,
                "version": spec.version,
                "profiles": list(spec.profiles),
                "requires": list(spec.requires),
            }
            for spec in all_specs()
        ]
    }


@router.get("/api/contracts")
def contracts() -> dict:
    """The SentinelX shared-agent JSON Schemas (Discovery role)."""
    return {name: model.model_json_schema() for name, model in SCHEMA_MODELS.items()}


@router.post("/api/discovery")
def api_discovery(inp: DiscoveryInput) -> JSONResponse:
    """Run Discovery against a validated contract input and return the contract result."""
    result = run_discovery(inp)
    return JSONResponse(result.model_dump(mode="json"))


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"result": None, "profiles": _PROFILES, "tool_count": len(all_specs())},
    )


@router.post("/scan", response_class=HTMLResponse)
def scan(
    request: Request,
    target: str = Form(""),
    consent: bool = Form(False),
    profile: str = Form("safe"),
):
    result = run_assessment(target=target, consent=consent, profile=profile)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "result": result,
            "target": target,
            "profile": profile,
            "profiles": _PROFILES,
            "tool_count": len(all_specs()),
            "generated": datetime.now().isoformat(timespec="seconds"),
        },
    )


@router.post("/api/scan")
def api_scan(
    target: str = Form(""),
    consent: bool = Form(False),
    profile: str = Form("safe"),
) -> JSONResponse:
    result = run_assessment(target=target, consent=consent, profile=profile)
    return JSONResponse(result)


@router.post("/report")
def report(
    target: str = Form(""),
    consent: bool = Form(True),
    profile: str = Form("safe"),
):
    result = run_assessment(target=target, consent=consent, profile=profile)
    path: Path = build_report(result)
    return FileResponse(path, media_type="application/pdf", filename=path.name)
