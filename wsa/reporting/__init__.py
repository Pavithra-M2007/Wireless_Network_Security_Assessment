"""
wsa.reporting — Stage 4 report generation.

Public API
----------
Assessment          — full assessment data model
NetworkAssessment   — per-BSSID findings + risk score
build_assessment    — construct Assessment from ScanFeatures + engine results
assess_pcap         — full pipeline: PCAP → Assessment in one call
to_json             — JSON report generator
to_markdown         — Markdown report generator
to_html             — self-contained HTML report generator
to_pdf              — audit-grade PDF report generator
"""
from wsa.reporting.assessment import (
    Assessment,
    NetworkAssessment,
    RISK_SCORES,
    SEVERITIES,
    build_assessment,
    assess_pcap,
    data_source_note,
)
from wsa.reporting.json_reporter import to_json
from wsa.reporting.markdown_reporter import to_markdown
from wsa.reporting.html_reporter import to_html
from wsa.reporting.pdf_reporter import to_pdf

__all__ = [
    "Assessment",
    "NetworkAssessment",
    "RISK_SCORES",
    "SEVERITIES",
    "build_assessment",
    "assess_pcap",
    "data_source_note",
    "to_json",
    "to_markdown",
    "to_html",
    "to_pdf",
]
