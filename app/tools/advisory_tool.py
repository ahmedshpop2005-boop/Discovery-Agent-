"""Local advisory matching.

Matches discovered product/version observations against a small local advisory
index (``data/knowledge/advisories.json``). Results are *candidate leads*: a
version match is a lead, not proof, and is labelled accordingly.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from app.config import settings
from app.tools.base import EffectClass, ToolContext, ToolResult, evidence
from app.tools.registry import tool

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(text: str) -> tuple[int, ...]:
    match = _VERSION_RE.search(text or "")
    if not match:
        return ()
    groups = [int(g) for g in match.groups() if g is not None]
    return tuple(groups)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def _matches(affected: str, version: tuple[int, ...]) -> bool:
    if not version:
        return False
    affected = affected.strip()
    if affected == "*":
        return True
    for clause in affected.split(","):
        clause = clause.strip()
        if clause.startswith("<="):
            if _cmp(version, _parse_version(clause[2:])) > 0:
                return False
        elif clause.startswith(">="):
            if _cmp(version, _parse_version(clause[2:])) < 0:
                return False
        elif clause.startswith("<"):
            if _cmp(version, _parse_version(clause[1:])) >= 0:
                return False
        elif clause.startswith(">"):
            if _cmp(version, _parse_version(clause[1:])) <= 0:
                return False
        elif clause.startswith("=="):
            if _cmp(version, _parse_version(clause[2:])) != 0:
                return False
    return True


@lru_cache(maxsize=1)
def _load_index() -> dict:
    path = settings.knowledge_dir / "advisories.json"
    if not path.exists():
        return {"products": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"products": {}}


@tool(
    name="advisory_match",
    description="Match discovered product/version observations to a local advisory index.",
    category="ADVISORY",
    effect_class=EffectClass.READ_ONLY,
    capability="advisory",
    requires=("services",),
    profiles=("safe", "web", "network", "full"),
    order=110,
)
def advisory_match(ctx: ToolContext) -> ToolResult:
    index = _load_index().get("products", {})
    matches: list[dict] = []
    for service in ctx.option("services") or []:
        product = (service.get("product") or service.get("service") or "").lower()
        version = service.get("version") or ""
        if not product:
            continue
        key = None
        for name, entry in index.items():
            aliases = [name] + [a.lower() for a in entry.get("aliases", [])]
            if any(alias and alias in product for alias in aliases):
                key = name
                break
        if key is None:
            continue
        parsed = _parse_version(version)
        for rule in index[key].get("rules", []):
            if _matches(rule["affected"], parsed):
                matches.append(
                    {
                        "port": service.get("port"),
                        "product": service.get("product") or key,
                        "version": version or None,
                        "cve": rule.get("cve"),
                        "severity": rule.get("severity"),
                        "title": rule.get("title"),
                        "affected": rule.get("affected"),
                        "remediation": rule.get("remediation"),
                        "reference": rule.get("reference"),
                    }
                )
    return ToolResult(
        tool="advisory_match",
        status="ok" if matches else "partial",
        summary=f"{len(matches)} candidate advisory lead(s) matched.",
        data={"matches": matches},
        evidence=[evidence("advisory_match", f"{m['product']} {m['version']} -> {m['cve'] or m['title']}") for m in matches[:10]],
        command="local advisory index match",
        note="A version match is a candidate lead and needs target-specific confirmation.",
    )
