"""
Finding dataclass — the output unit of the rule engine.

One Finding is produced per (rule, network) pair where the rule condition
evaluates to True.  Findings carry only factual observations and
structured remediation guidance; they make no claim that a network is
"compromised" or that an attacker has been identified.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Severity constants  (ordered most-severe → least-severe for sorting)
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

VALID_SEVERITIES: frozenset[str] = frozenset(
    {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}
)

# Maps severity label → sort key (lower = more severe)
SEVERITY_ORDER: dict[str, int] = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH:     1,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      3,
    SEVERITY_INFO:     4,
}


@dataclass(frozen=True)
class Finding:
    """
    A single security observation produced by the rule engine.

    Frozen to prevent accidental mutation after creation.

    Fields
    ------
    rule_id      : Stable identifier from the YAML rule file (e.g. ``ENC-001``).
    category     : Broad category string (e.g. ``Encryption``).
    severity     : One of CRITICAL, HIGH, MEDIUM, LOW, INFO.
    title        : Short human-readable finding title.
    explanation  : What was observed and what it means.  Factual; no attribution.
    impact       : Possible security consequences.  Uses "may", "can", not "will".
    remediation  : Actionable steps to address the finding.
    evidence     : The specific field value that triggered the rule,
                   formatted as ``field_name = repr(value)``.
    bssid        : AP MAC address (lower-case colon-separated).
    ssid         : Network name, or ``None`` if the SSID IE was absent.
    """

    rule_id:     str
    category:    str
    severity:    str
    title:       str
    explanation: str
    impact:      str
    remediation: str
    evidence:    str
    bssid:       str
    ssid:        Optional[str]

    @property
    def severity_order(self) -> int:
        """Integer sort key; lower value = higher severity."""
        return SEVERITY_ORDER.get(self.severity, 99)
