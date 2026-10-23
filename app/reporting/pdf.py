"""PDF report builder.

Produces an analyst-readable report from a completed assessment state. The
report preserves the platform's honesty rules: it separates observations from
confirmations and always states coverage limitations.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import settings

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#b91c1c"),
    "High": colors.HexColor("#dc2626"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#475569"),
}


def build_report(result: dict[str, Any], destination: Path | None = None) -> Path:
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = destination or settings.reports_dir / f"pentest-report-{timestamp}.pdf"

    styles = getSampleStyleSheet()
    story: list[Any] = []
    target = result.get("base_url") or result.get("target") or "n/a"

    story.append(Paragraph("AutoPentest Sentinel", styles["Title"]))
    story.append(Paragraph("Authorized Security Assessment", styles["Heading2"]))
    story.append(Spacer(1, 6))
    meta = [
        ["Target", str(target)],
        ["Scan ID", str(result.get("scan_id", "n/a"))],
        ["Profile", str(result.get("profile", "safe"))],
        ["Generated", datetime.now().isoformat(timespec="seconds")],
        ["Status", str(result.get("status", "n/a"))],
    ]
    story.append(_kv_table(meta))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Scope and safety", styles["Heading2"]))
    story.append(
        Paragraph(
            "This is a non-destructive, evidence-first assessment. No exploitation, "
            "brute force, denial-of-service or destructive action was performed. "
            "Every observation is tied to collected evidence and requires analyst review. "
            "An unavailable tool, a limited response, or a missing observation is not proof "
            "that the target is secure.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 8))

    _section_limitations(story, styles, result)
    _section_tools(story, styles, result)
    _section_findings(story, styles, result)
    _section_web(story, styles, result)
    _section_appendix(story, styles, result)

    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        title="AutoPentest Sentinel Report",
        author="AutoPentest Sentinel",
        leftMargin=18 * mm,
        rightMargin=18 * mm,
    ).build(story)
    return path


def _kv_table(rows: list[list[str]]) -> Table:
    table = Table(rows, colWidths=[38 * mm, 120 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ]
        )
    )
    return table


def _section_limitations(story, styles, result) -> None:
    gaps = list(result.get("coverage_gaps", [])) + list(result.get("errors", []))
    if not gaps:
        return
    story.append(Paragraph("Coverage limitations", styles["Heading2"]))
    for gap in gaps:
        story.append(Paragraph(f"• {gap}", styles["Normal"]))
    story.append(Spacer(1, 8))


def _section_tools(story, styles, result) -> None:
    results = result.get("results", {})
    if not results:
        return
    story.append(Paragraph("Collection summary", styles["Heading2"]))
    rows = [["Tool", "Status", "Summary"]]
    for name, payload in results.items():
        rows.append([name, str(payload.get("status", "")), str(payload.get("summary", ""))[:90]])
    table = Table(rows, colWidths=[38 * mm, 20 * mm, 100 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5f5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 10))


def _section_findings(story, styles, result) -> None:
    findings = result.get("findings", [])
    story.append(Paragraph("Security observations", styles["Heading2"]))
    if not findings:
        story.append(
            Paragraph(
                "No observations were retained. This is not evidence that the target is secure; "
                "review the coverage limitations above and assess manually.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 8))
        return
    for item in findings:
        severity = item.get("severity", "Informational")
        color = _SEVERITY_COLORS.get(severity, colors.black)
        title = Paragraph(f"<b>{item.get('id')}</b> · {item.get('title')}", styles["Heading3"])
        tags = Paragraph(
            f"<font color='{color.hexval()}'><b>{severity}</b></font> · "
            f"{item.get('confidence')} · {item.get('category')}",
            styles["Normal"],
        )
        evidence = item.get("evidence", {})
        story.append(title)
        story.append(tags)
        story.append(Paragraph(f"<b>Evidence:</b> {evidence.get('detail', '')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Recommended next step:</b> {item.get('remediation', '')}", styles["Normal"]))
        refs = item.get("references", [])
        if refs:
            sources = ", ".join(sorted({r.get("source", "") for r in refs}))
            story.append(Paragraph(f"<i>Knowledge references: {sources}</i>", styles["Normal"]))
        story.append(Spacer(1, 8))


def _section_web(story, styles, result) -> None:
    web = result.get("web_inventory") or {}
    applications = web.get("applications") or []
    endpoints = web.get("endpoints") or []
    if not applications and not endpoints:
        return
    story.append(Paragraph("Web application surface", styles["Heading2"]))
    if applications:
        rows = [["Origin", "Title", "Technologies (version)", "Server", "WAF"]]
        for app in applications:
            technologies = ", ".join(
                f"{tech.get('name', '')}"
                + (f" {tech.get('version')}" if tech.get("version") else "")
                + (f" ({tech.get('verification_status')})" if tech.get("version") else "")
                for tech in app.get("technologies") or []
            )
            rows.append(
                [
                    str(app.get("origin", ""))[:40],
                    str(app.get("title") or app.get("identity") or "")[:40],
                    technologies[:80],
                    str(app.get("server") or "")[:30],
                    str(app.get("waf") or "")[:30],
                ]
            )
        table = Table(rows, colWidths=[38 * mm, 34 * mm, 45 * mm, 20 * mm, 21 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5f5")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 8))
    if endpoints:
        story.append(Paragraph("Observed routes / endpoints", styles["Heading3"]))
        rows = [["Method", "Path", "Status", "Observed", "Source"]]
        for endpoint in endpoints[:80]:
            rows.append(
                [
                    str(endpoint.get("method", "GET")),
                    str(endpoint.get("path", ""))[:60],
                    str(endpoint.get("status") if endpoint.get("status") is not None else ""),
                    "yes" if endpoint.get("observed", True) else "declared",
                    str(endpoint.get("source", ""))[:30],
                ]
            )
        table = Table(rows, colWidths=[16 * mm, 60 * mm, 18 * mm, 24 * mm, 40 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5f5")),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 8))

    coverage = web.get("route_coverage") or {}
    if coverage:
        story.append(Paragraph("Route coverage", styles["Heading3"]))
        story.append(
            Paragraph(
                f"Status: <b>{coverage.get('coverage_status', 'unknown')}</b> · "
                f"attempted {coverage.get('routes_attempted', 0)}, "
                f"confirmed {coverage.get('routes_confirmed', 0)}, "
                f"inaccessible {coverage.get('routes_inaccessible', 0)}, "
                f"failed {coverage.get('routes_failed', 0)}, "
                f"untested {coverage.get('routes_untested', 0)}",
                styles["Normal"],
            )
        )
        for limitation in coverage.get("coverage_limitations") or []:
            story.append(Paragraph(f"• {limitation}", styles["Normal"]))
        story.append(Spacer(1, 8))

    auth = web.get("authentication_coverage") or {}
    if auth:
        story.append(Paragraph("Authentication coverage", styles["Heading3"]))
        story.append(
            Paragraph(
                f"Status: <b>{auth.get('status', 'not_assessed')}</b> · "
                f"{auth.get('profiles_supplied', 0)} profile(s), "
                f"{auth.get('authenticated_profiles', 0)} authenticated. "
                + " ".join(auth.get("notes") or []),
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 10))


def _section_appendix(story, styles, result) -> None:
    services = result.get("services", [])
    if not services:
        return
    story.append(Paragraph("Appendix A - Discovered services", styles["Heading2"]))
    rows = [["Port", "Proto", "Service", "Product", "Version"]]
    for service in services:
        rows.append(
            [
                str(service.get("port", "")),
                str(service.get("protocol", "tcp")),
                str(service.get("service", "")),
                str(service.get("product", "") or ""),
                str(service.get("version", "") or ""),
            ]
        )
    table = Table(rows, colWidths=[18 * mm, 18 * mm, 40 * mm, 45 * mm, 37 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5f5")),
            ]
        )
    )
    story.append(table)
