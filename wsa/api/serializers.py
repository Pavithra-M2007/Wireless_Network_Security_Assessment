"""JSON safe representations used by the application API."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from wsa.reporting.assessment import Assessment
from wsa.reporting.json_reporter import to_json


def assessment_dict(assessment: Assessment) -> dict[str, Any]:
    """Return the engine's canonical JSON report as a Python dictionary."""
    import json

    return json.loads(to_json(assessment))


def public_assessment(assessment_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Wrap a report with a stable application id and UI metadata."""
    summary = data.get("summary", {})
    return {
        "id": assessment_id,
        "filename": data.get("source_filename") or data.get("filename") or Path(data.get("source_file", "")).name,
        "data_source": data.get("data_source"),
        "data_source_note": data.get("data_source_note"),
        "analysis_timestamp": data.get("analysis_timestamp"),
        "summary": summary,
        "parse_errors": data.get("parse_errors", []),
        "networks": data.get("networks", []),
        "devices": data.get("devices", []),
        "protocol_analysis": data.get("protocol_analysis", {}),
    }


def assessment_summary(assessment_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Return the compact shape used by list and dashboard endpoints."""
    summary = data.get("summary", {})
    networks = data.get("networks", [])
    devices = data.get("devices", [])
    return {
        "id": assessment_id,
        "filename": data.get("source_filename") or data.get("filename") or Path(data.get("source_file", "")).name,
        "data_source": data.get("data_source"),
        "analysis_timestamp": data.get("analysis_timestamp"),
        "total_networks": summary.get("total_networks", len(networks)),
        "total_findings": summary.get("total_findings", 0),
        "total_risk_score": summary.get("total_risk_score", 0),
        "total_devices": len(devices),
        "severity_counts": summary.get("severity_counts", {}),
    }
