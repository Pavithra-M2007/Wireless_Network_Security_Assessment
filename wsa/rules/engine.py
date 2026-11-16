"""
Rule engine — orchestrates loading, evaluation, and Finding creation.

Usage
-----
::

    from wsa.rules.engine import RuleEngine

    engine = RuleEngine()                       # loads rules from rules/
    findings = engine.evaluate_network(network) # List[Finding]
    results  = engine.evaluate_scan(scan)       # Dict[bssid, List[Finding]]
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from wsa.analysis.feature_set import NetworkFeatures, ScanFeatures
from wsa.rules.evaluator import ConditionError, evaluate_condition
from wsa.rules.finding import Finding
from wsa.rules.loader import RuleLoadError, load_rules_from_dir


def _default_rules_dir() -> Path:
    """
    Locate the project-level ``rules/`` directory relative to this file.

    File layout:
        <project_root>/wsa/rules/engine.py   → this file
        <project_root>/rules/                → rule YAML files
    """
    return Path(__file__).resolve().parent.parent.parent / "rules"


class RuleEngine:
    """
    Loads YAML rule definitions and evaluates them against NetworkFeatures.

    Parameters
    ----------
    rules_dir : str | Path | None
        Directory containing rule YAML files.
        Defaults to the project-level ``rules/`` directory.

    Attributes
    ----------
    rules : list[dict]
        All validated rule dicts loaded from YAML.
    rules_dir : Path
        Directory from which rules were loaded.
    """

    def __init__(self, rules_dir: Union[str, Path, None] = None) -> None:
        self.rules_dir: Path = (
            Path(rules_dir) if rules_dir is not None else _default_rules_dir()
        )
        self.rules: List[Dict[str, Any]] = load_rules_from_dir(self.rules_dir)

    # ------------------------------------------------------------------
    # Public evaluation API
    # ------------------------------------------------------------------

    def evaluate_network(self, network: NetworkFeatures) -> List[Finding]:
        """
        Evaluate all loaded rules against a single network.

        Parameters
        ----------
        network : NetworkFeatures
            Extracted features for one AP (one BSSID).

        Returns
        -------
        list[Finding]
            Zero or more findings, in the order rules were loaded.
            Each finding corresponds to one triggered rule.

        Notes
        -----
        ConditionError from a single rule is caught and logged to
        ``network.parser_notes`` rather than aborting the evaluation loop.
        This ensures a broken rule file does not suppress all other findings.
        """
        findings: List[Finding] = []
        for rule in self.rules:
            finding = self._try_rule(rule, network)
            if finding is not None:
                findings.append(finding)
        return findings

    def evaluate_scan(
        self, scan: ScanFeatures
    ) -> List[Tuple[NetworkFeatures, List[Finding]]]:
        """
        Evaluate all rules against every network in a scan.

        Parameters
        ----------
        scan : ScanFeatures
            Aggregate output from a PCAP parse session.

        Returns
        -------
        list[tuple[NetworkFeatures, list[Finding]]]
            One entry per network.  The NetworkFeatures and its Finding
            list are paired so Stage 4 can produce reports without a
            separate lookup.
        """
        return [
            (net, self.evaluate_network(net))
            for net in scan.networks
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_rule(
        self, rule: Dict[str, Any], network: NetworkFeatures
    ) -> Optional[Finding]:
        """
        Evaluate one rule against one network.

        Returns a Finding if the condition matches, None otherwise.
        ConditionError is caught; the error text is appended to
        ``network.parser_notes`` and None is returned.
        """
        try:
            matched = evaluate_condition(rule["condition"], network)
        except ConditionError as exc:
            # Non-fatal: record the issue and continue with other rules.
            note = f"Rule {rule.get('id', '?')!r} condition error: {exc}"
            if hasattr(network, "parser_notes") and isinstance(
                network.parser_notes, list
            ):
                network.parser_notes.append(note)
            return None
        except Exception as exc:
            note = f"Rule {rule.get('id', '?')!r} unexpected error: {exc}"
            if hasattr(network, "parser_notes") and isinstance(
                network.parser_notes, list
            ):
                network.parser_notes.append(note)
            return None

        if not matched:
            return None

        return _make_finding(rule, network)


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _make_finding(rule: Dict[str, Any], network: NetworkFeatures) -> Finding:
    """
    Construct a Finding from a triggered rule and the matching network.

    The evidence string is formatted as ``field_name = repr(value)`` so
    that the exact observed value is preserved unambiguously.
    """
    evidence_field: str = rule["evidence_field"]
    try:
        evidence_val = getattr(network, evidence_field)
        evidence = f"{evidence_field} = {evidence_val!r}"
    except AttributeError:
        evidence = f"{evidence_field} = <field not found on NetworkFeatures>"

    return Finding(
        rule_id     = rule["id"],
        category    = rule["category"],
        severity    = rule["severity"],
        title       = rule["title"],
        explanation = str(rule.get("explanation", "")).strip(),
        impact      = str(rule.get("impact", "")).strip(),
        remediation = str(rule.get("remediation", "")).strip(),
        evidence    = evidence,
        bssid       = network.bssid,
        ssid        = network.ssid,
    )
