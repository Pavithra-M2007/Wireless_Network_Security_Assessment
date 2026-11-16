"""
Markdown report generator.

Produces a GitHub-Flavoured Markdown document from an ``Assessment``.
The output is suitable for display in any GFM-compatible renderer (GitHub,
GitLab, VS Code, Obsidian, etc.) as well as for conversion to other formats
via Pandoc.

Escaping policy for Markdown tables
-------------------------------------
``|`` characters in SSID, evidence, or other PCAP-derived strings would break
GFM table cells.  These are replaced with the HTML entity ``&#124;`` which
renders correctly in all GFM renderers.  Backtick characters in code spans
are doubled (`` `` `` `` ``).  Other Markdown metacharacters are left as-is
because they are not harmful outside of specific structural contexts.

Absent-value convention
-----------------------
``None`` values are displayed as ``—`` (em-dash) rather than as blank
or as the string ``"None"``, so readers can distinguish absent evidence
from a value of zero or false.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from wsa.reporting.assessment import (
    Assessment,
    NetworkAssessment,
    SEVERITIES,
    data_source_note,
)
from wsa.rules.finding import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cell(value: object) -> str:
    """
    Format *value* as a safe GFM table cell string.

    * Replaces ``|`` with ``&#124;`` to prevent table breakage.
    * Replaces bare backticks with escaped backticks.
    * Converts ``None`` to ``—``.
    * Converts booleans before the string conversion so they read as
      ``True``/``False``, not ``1``/``0``.
    """
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    text = text.replace("|", "&#124;")
    text = text.replace("`", "\\`")
    return text


def _opt_bool(val: Optional[bool], absent_label: str = "— (RSN IE absent)") -> str:
    if val is None:
        return absent_label
    return "Yes" if val else "No"


def _opt_int(val: Optional[int]) -> str:
    return "Unknown" if val is None else str(val)


def _opt_float(val: Optional[float]) -> str:
    return "Unknown" if val is None else f"{val:.1f} dBm"


def _display_ssid(ssid: Optional[str]) -> str:
    if ssid is None:
        return "(SSID IE absent)"
    if ssid == "":
        return "(Hidden SSID)"
    return ssid


def _severity_row(severity: str, count: int) -> str:
    return f"| {severity:<8} | {count} |"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_markdown(assessment: Assessment) -> str:
    """
    Generate a Markdown report from *assessment*.

    Returns
    -------
    str
        A complete GFM Markdown document.
    """
    parts: list[str] = []

    _header(parts, assessment)
    _provenance_banner(parts, assessment)
    _scan_meta_table(parts, assessment)
    _executive_summary(parts, assessment)
    _networks_section(parts, assessment)
    if assessment.parse_errors:
        _parse_errors_section(parts, assessment)
    _footer(parts, assessment)

    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Section builders  (private)
# ---------------------------------------------------------------------------

def _header(parts: list, a: Assessment) -> None:
    parts.append("# Wireless Network Security Assessment Report")
    parts.append("")


def _provenance_banner(parts: list, a: Assessment) -> None:
    note = data_source_note(a.data_source)
    parts.append(f"> **DATA SOURCE: {a.data_source.upper()}** — {note}")
    parts.append("")


def _scan_meta_table(parts: list, a: Assessment) -> None:
    filename = Path(a.source_file).name
    parts.append("| Field | Value |")
    parts.append("|---|---|")
    parts.append(f"| Source file | `{_cell(filename)}` |")
    parts.append(f"| Data source | {_cell(a.data_source)} |")
    parts.append(f"| Analysis timestamp | {_cell(a.analysis_timestamp)} |")
    parts.append("")
    parts.append("---")
    parts.append("")


def _executive_summary(parts: list, a: Assessment) -> None:
    parts.append("## Executive Summary")
    parts.append("")
    parts.append("| Metric | Value |")
    parts.append("|---|---|")
    parts.append(f"| Total frames analysed | {a.total_frames} |")
    parts.append(f"| Networks discovered | {a.total_networks} |")
    parts.append(f"| Probe request frames | {a.total_probe_requests} |")
    parts.append(f"| Deauth / disassoc frames | {a.total_deauth_frames} |")
    parts.append(f"| EAPOL frames | {a.total_eapol_frames} |")
    parts.append(f"| Total findings | {a.finding_count} |")
    parts.append(f"| Total risk score | {a.total_risk_score} |")
    parts.append("")
    parts.append("### Findings by Severity")
    parts.append("")
    parts.append("| Severity | Count |")
    parts.append("|---|---|")
    for sev in SEVERITIES:
        parts.append(_severity_row(sev, a.severity_counts[sev]))
    parts.append("")
    parts.append("---")
    parts.append("")


def _networks_section(parts: list, a: Assessment) -> None:
    parts.append(f"## Networks ({a.total_networks})")
    parts.append("")
    if not a.network_assessments:
        parts.append("*No networks were discovered in this capture.*")
        parts.append("")
        return
    for na in a.network_assessments:
        _network_block(parts, na)


def _network_block(parts: list, na: NetworkAssessment) -> None:
    net = na.network
    ssid_label = _display_ssid(net.ssid)
    parts.append(f"### {_cell(ssid_label)} — `{net.bssid}`")
    parts.append("")

    # Properties table
    parts.append("| Property | Value |")
    parts.append("|---|---|")
    parts.append(f"| Channel | {_opt_int(net.channel)} |")
    parts.append(f"| Cipher | {_cell(net.cipher)} |")
    parts.append(f"| Auth type | {_cell(net.auth_type)} |")
    parts.append(f"| WPA versions | {_cell(', '.join(net.wpa_versions) or '—')} |")
    parts.append(f"| Group cipher | {_cell(net.group_cipher)} |")
    parts.append(f"| Pairwise ciphers | {_cell(', '.join(net.pairwise_ciphers) or '—')} |")
    parts.append(f"| MFP capable | {_opt_bool(net.mfp_capable)} |")
    parts.append(f"| MFP required | {_opt_bool(net.mfp_required)} |")
    parts.append(f"| WPS advertised | {_opt_bool(net.wps_present, '—')} |")
    parts.append(f"| Average RSSI | {_opt_float(net.avg_rssi)} |")
    parts.append(f"| Beacon count | {net.beacon_count} |")
    parts.append(f"| Deauth count | {net.deauth_count} |")
    parts.append(f"| EAPOL frames | {net.eapol_frame_count} |")
    parts.append("")

    # Risk line
    hs = na.highest_severity or "—"
    parts.append(f"**Risk score:** {na.risk_score} &nbsp;·&nbsp; **Highest severity:** {hs}")
    parts.append("")

    # Findings
    parts.append(f"#### Security Findings ({len(na.findings)})")
    parts.append("")
    if not na.findings:
        parts.append(
            "> ✅ No security findings for this network. "
            "Configuration appears satisfactory based on available evidence."
        )
        parts.append("")
    else:
        sorted_findings = sorted(na.findings, key=lambda f: f.severity_order)
        for finding in sorted_findings:
            _finding_block(parts, finding)

    # Parser notes (optional)
    if net.parser_notes:
        parts.append("<details>")
        parts.append(f"<summary>Parser notes ({len(net.parser_notes)})</summary>")
        parts.append("")
        for note in net.parser_notes:
            parts.append(f"- {_cell(note)}")
        parts.append("")
        parts.append("</details>")
        parts.append("")

    parts.append("---")
    parts.append("")


def _finding_block(parts: list, f: Finding) -> None:
    parts.append(f"##### [{f.severity}] {f.rule_id} — {_cell(f.title)}")
    parts.append("")
    parts.append(f"**Evidence:** `{_cell(f.evidence)}`")
    parts.append("")
    parts.append(f"**Explanation:** {_cell(f.explanation)}")
    parts.append("")
    parts.append(f"**Impact:** {_cell(f.impact)}")
    parts.append("")
    parts.append(f"**Remediation:** {_cell(f.remediation)}")
    parts.append("")


def _parse_errors_section(parts: list, a: Assessment) -> None:
    parts.append("## Parse Errors")
    parts.append("")
    parts.append(
        "> The following non-fatal errors were recorded during PCAP loading "
        "or frame parsing. Other fields may still be valid."
    )
    parts.append("")
    for err in a.parse_errors:
        parts.append(f"- {_cell(err)}")
    parts.append("")
    parts.append("---")
    parts.append("")


def _footer(parts: list, a: Assessment) -> None:
    parts.append(
        f"*Generated by Wireless Security Assessment (WSA) · "
        f"{a.analysis_timestamp}*"
    )
