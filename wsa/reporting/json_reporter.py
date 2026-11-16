"""
JSON report generator.

Produces a structured, schema-versioned JSON document from an ``Assessment``.

Design notes
------------
* Explicit dict construction (not ``dataclasses.asdict()``) so that computed
  properties (``avg_rssi``, ``hidden_ssid``, ``risk_score``, ``highest_severity``,
  ``severity_counts``) are included alongside raw dataclass fields.
* ``None`` values serialise to JSON ``null`` automatically via ``json.dumps``.
* All string values are taken as-is; no HTML escaping is applied (JSON is
  a data format, not a rendered document).
* The ``schema_version`` key allows consumers to detect format changes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from wsa.reporting.assessment import (
    Assessment,
    NetworkAssessment,
    SEVERITIES,
    data_source_note,
)
from wsa.rules.finding import Finding

_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_json(assessment: Assessment, indent: int = 2) -> str:
    """
    Serialise *assessment* to a JSON string.

    Parameters
    ----------
    assessment : Assessment
    indent : int
        JSON indentation width.  ``0`` produces compact single-line output.

    Returns
    -------
    str
        Valid, UTF-8 safe JSON.
    """
    doc = _assessment_to_dict(assessment)
    return json.dumps(doc, indent=indent if indent > 0 else None, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Conversion helpers  (private)
# ---------------------------------------------------------------------------

def _assessment_to_dict(a: Assessment) -> Dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "source_file": a.source_file,
        "source_filename": Path(a.source_file).name,
        "data_source": a.data_source,
        "data_source_note": data_source_note(a.data_source),
        "analysis_timestamp": a.analysis_timestamp,
        "summary": {
            "total_frames":         a.total_frames,
            "total_networks":       a.total_networks,
            "total_probe_requests": a.total_probe_requests,
            "total_deauth_frames":  a.total_deauth_frames,
            "total_eapol_frames":   a.total_eapol_frames,
            "total_findings":       a.finding_count,
            "total_risk_score":     a.total_risk_score,
            "severity_counts":      a.severity_counts,
        },
        "parse_errors": a.parse_errors,
        "networks": [_na_to_dict(na) for na in a.network_assessments],
    }


def _na_to_dict(na: NetworkAssessment) -> Dict[str, Any]:
    net = na.network
    return {
        # Identity
        "bssid":  net.bssid,
        "ssid":   net.ssid,        # None when SSID IE was absent
        # RF
        "channel":     net.channel,       # None when DS-set IE absent
        "avg_rssi_dbm": net.avg_rssi,     # None when no RadioTap signal data
        # Encryption
        "cipher":          net.cipher,
        "group_cipher":    net.group_cipher,   # None when no RSN IE
        "pairwise_ciphers": net.pairwise_ciphers,
        "privacy_bit":     net.privacy_bit,
        # Authentication / key management
        "auth_type":   net.auth_type,
        "akm_suites":  net.akm_suites,
        "wpa_versions": net.wpa_versions,
        # Management frame protection
        "mfp_capable":  net.mfp_capable,  # None when no RSN IE
        "mfp_required": net.mfp_required, # None when no RSN IE
        # Wi-Fi Protected Setup
        "wps_present": net.wps_present,
        # Counts
        "beacon_count":      net.beacon_count,
        "deauth_count":      net.deauth_count,
        "eapol_frame_count": net.eapol_frame_count,
        # Derived / convenience
        "hidden_ssid": net.hidden_ssid,
        # Parser observations
        "parser_notes": net.parser_notes,
        # Assessment results
        "risk_score":       na.risk_score,
        "highest_severity": na.highest_severity,  # None when no findings
        "severity_counts":  na.severity_counts,
        "findings": [_finding_to_dict(f) for f in na.findings],
    }


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "rule_id":     f.rule_id,
        "category":    f.category,
        "severity":    f.severity,
        "title":       f.title,
        "explanation": f.explanation,
        "impact":      f.impact,
        "remediation": f.remediation,
        "evidence":    f.evidence,
        "bssid":       f.bssid,
        "ssid":        f.ssid,
    }
