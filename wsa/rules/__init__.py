"""
wsa.rules — YAML rule engine for wireless security assessment.

Public API
----------
Finding          — structured security observation dataclass
RuleEngine       — loads YAML rules and evaluates them against NetworkFeatures
RuleLoadError    — raised when a YAML rule file is invalid
ConditionError   — raised when a rule condition cannot be evaluated
evaluate_condition — low-level condition evaluator (for testing)
"""
from wsa.rules.finding import (
    Finding,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    VALID_SEVERITIES,
    SEVERITY_ORDER,
)
from wsa.rules.loader import RuleLoadError, load_rules_from_dir, load_rules_from_file
from wsa.rules.evaluator import ConditionError, evaluate_condition
from wsa.rules.engine import RuleEngine

__all__ = [
    "Finding",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
    "SEVERITY_INFO",
    "VALID_SEVERITIES",
    "SEVERITY_ORDER",
    "RuleLoadError",
    "load_rules_from_dir",
    "load_rules_from_file",
    "ConditionError",
    "evaluate_condition",
    "RuleEngine",
]
