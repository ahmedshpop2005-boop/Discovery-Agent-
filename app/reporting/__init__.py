"""Report generation."""

from app.reporting.json_report import build_json_report
from app.reporting.pdf import build_report

__all__ = ["build_report", "build_json_report"]
