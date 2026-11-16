"""
Assessment comparison and differential security engine — Stage 5.

Performs before-and-after wireless security assessment comparison,
quantifying risk delta, identifying resolved vs newly introduced vulnerabilities,
and tracking access point security configuration changes over time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple


def _finding_key(finding: Dict[str, Any]) -> str:
    """Unique key identifying a finding by rule and target."""
    rule_id = finding.get("rule_id", "")
    bssid = finding.get("bssid", "") or finding.get("network_bssid", "")
    return f"{rule_id}:{bssid.lower()}"


def compare_assessments(
    baseline: Dict[str, Any],
    target: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare two assessments (baseline vs current/target).

    Parameters
    ----------
    baseline : dict
        Earlier or baseline assessment record.
    target : dict
        Later or current assessment record to compare against.

    Returns
    -------
    dict
        Structured differential analysis with risk delta, posture verdict,
        resolved vs new findings, and per-network configuration changes.
    """
    baseline_id = baseline.get("id", "baseline")
    target_id = target.get("id", "target")

    b_summary = baseline.get("summary", {})
    t_summary = target.get("summary", {})

    b_risk = int(b_summary.get("total_risk_score", baseline.get("total_risk_score", 0)))
    t_risk = int(t_summary.get("total_risk_score", target.get("total_risk_score", 0)))

    risk_delta = t_risk - b_risk
    if b_risk > 0:
        pct_change = round(((t_risk - b_risk) / b_risk) * 100, 1)
    elif t_risk > 0:
        pct_change = 100.0
    else:
        pct_change = 0.0

    if t_risk < b_risk:
        posture = "IMPROVED"
    elif t_risk > b_risk:
        posture = "REGRESSED"
    else:
        posture = "UNCHANGED"

    # Extract all findings
    def get_findings(record: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        for net in record.get("networks", []):
            for f in net.get("findings", []):
                item = dict(f)
                item["network_ssid"] = net.get("ssid")
                item["network_bssid"] = net.get("bssid")
                results.append(item)
        return results

    b_findings = get_findings(baseline)
    t_findings = get_findings(target)

    b_map = {_finding_key(f): f for f in b_findings}
    t_map = {_finding_key(f): f for f in t_findings}

    b_keys = set(b_map.keys())
    t_keys = set(t_map.keys())

    resolved_keys = b_keys - t_keys
    new_keys = t_keys - b_keys
    persistent_keys = b_keys & t_keys

    resolved_findings = [b_map[k] for k in resolved_keys]
    new_findings = [t_map[k] for k in new_keys]
    persistent_findings = [t_map[k] for k in persistent_keys]

    # Compare networks
    b_nets = {net.get("bssid", "").lower(): net for net in baseline.get("networks", []) if net.get("bssid")}
    t_nets = {net.get("bssid", "").lower(): net for net in target.get("networks", []) if net.get("bssid")}

    added_bssids = set(t_nets.keys()) - set(b_nets.keys())
    removed_bssids = set(b_nets.keys()) - set(t_nets.keys())
    common_bssids = set(b_nets.keys()) & set(t_nets.keys())

    network_diffs: List[Dict[str, Any]] = []
    for bssid in sorted(list(common_bssids)):
        bn = b_nets[bssid]
        tn = t_nets[bssid]
        changes = []

        if bn.get("cipher") != tn.get("cipher"):
            changes.append({
                "field": "cipher",
                "label": "Encryption Cipher",
                "before": bn.get("cipher"),
                "after": tn.get("cipher"),
                "improved": (bn.get("cipher") in ("WEP", "NONE") and tn.get("cipher") in ("CCMP", "GCMP")),
            })
        if bn.get("auth_type") != tn.get("auth_type"):
            changes.append({
                "field": "auth_type",
                "label": "Authentication Protocol",
                "before": bn.get("auth_type"),
                "after": tn.get("auth_type"),
                "improved": (bn.get("auth_type") in ("OPEN", "UNKNOWN") and tn.get("auth_type") in ("PSK", "SAE")),
            })
        if bn.get("wps_present") != tn.get("wps_present"):
            changes.append({
                "field": "wps_present",
                "label": "WPS Broadcast",
                "before": "Enabled" if bn.get("wps_present") else "Disabled",
                "after": "Enabled" if tn.get("wps_present") else "Disabled",
                "improved": (bool(bn.get("wps_present")) and not bool(tn.get("wps_present"))),
            })
        if bn.get("mfp_required") != tn.get("mfp_required"):
            changes.append({
                "field": "mfp_required",
                "label": "802.11w MFP Enforcement",
                "before": "Required" if bn.get("mfp_required") else "Optional/None",
                "after": "Required" if tn.get("mfp_required") else "Optional/None",
                "improved": bool(tn.get("mfp_required")),
            })

        b_score = bn.get("risk_score", 0)
        t_score = tn.get("risk_score", 0)

        network_diffs.append({
            "bssid": bssid,
            "ssid": tn.get("ssid") or bn.get("ssid"),
            "risk_before": b_score,
            "risk_after": t_score,
            "risk_delta": t_score - b_score,
            "changes": changes,
        })

    # Generate executive narrative
    narratives = []
    if posture == "IMPROVED":
        narratives.append(
            f"Security posture improved. Overall risk score decreased by {abs(risk_delta)} points "
            f"({abs(pct_change)}% reduction). {len(resolved_findings)} vulnerability finding(s) remediated."
        )
    elif posture == "REGRESSED":
        narratives.append(
            f"Security posture regressed. Overall risk score increased by {risk_delta} points "
            f"(+{pct_change}% increase). {len(new_findings)} new vulnerability finding(s) detected."
        )
    else:
        narratives.append("Security posture remained unchanged between assessments.")

    if resolved_findings:
        remediated_titles = [f.get("title", "") for f in resolved_findings[:3]]
        narratives.append(f"Key remediations: {', '.join(remediated_titles)}.")

    if new_findings:
        new_titles = [f.get("title", "") for f in new_findings[:3]]
        narratives.append(f"Attention needed: newly observed risks include {', '.join(new_titles)}.")

    return {
        "baseline_id": baseline_id,
        "baseline_filename": baseline.get("filename", baseline.get("source_filename", "Baseline")),
        "baseline_timestamp": baseline.get("analysis_timestamp", ""),
        "baseline_risk": b_risk,
        "target_id": target_id,
        "target_filename": target.get("filename", target.get("source_filename", "Target")),
        "target_timestamp": target.get("analysis_timestamp", ""),
        "target_risk": t_risk,
        "risk_delta": risk_delta,
        "percentage_change": pct_change,
        "posture": posture,
        "narrative": " ".join(narratives),
        "summary": {
            "resolved_count": len(resolved_findings),
            "new_count": len(new_findings),
            "persistent_count": len(persistent_findings),
            "networks_added": len(added_bssids),
            "networks_removed": len(removed_bssids),
            "networks_common": len(common_bssids),
        },
        "resolved_findings": resolved_findings,
        "new_findings": new_findings,
        "persistent_findings": persistent_findings,
        "network_diffs": network_diffs,
    }
