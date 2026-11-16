"""
YAML rule file loader.

Loads and validates rule definitions from YAML files in a rules directory.
All parsing uses ``yaml.safe_load`` (never ``yaml.load`` with a full Loader)
to prevent arbitrary code execution from untrusted YAML content.

A ``RuleLoadError`` is raised for:
- Files that cannot be parsed as valid YAML.
- Files missing required top-level or rule-level keys.
- Rules whose ``severity`` is not in the approved set.
- Conditions referencing unknown operators (deferred to the evaluator).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml

from wsa.rules.finding import VALID_SEVERITIES

# ---------------------------------------------------------------------------
# Required keys at every level of a rule definition.
# ---------------------------------------------------------------------------

_REQUIRED_RULE_KEYS: frozenset[str] = frozenset(
    {
        "id",
        "category",
        "severity",
        "title",
        "evidence_field",
        "condition",
        "explanation",
        "impact",
        "remediation",
    }
)

_REQUIRED_SIMPLE_CONDITION_KEYS: frozenset[str] = frozenset({"op"})

# Operators that require a companion ``conditions`` list (compound ops)
_COMPOUND_OPS: frozenset[str] = frozenset({"all_of", "any_of", "none_of"})

# Operators that work on a single field (simple ops)
_SIMPLE_OPS: frozenset[str] = frozenset(
    {
        "eq", "ne",
        "gte", "gt", "lte", "lt",
        "is_true", "is_false", "is_none", "is_not_none",
        "in", "not_in",
        "contains", "not_contains",
    }
)


class RuleLoadError(ValueError):
    """
    Raised when a YAML rule file cannot be loaded or fails validation.

    Inherits from ``ValueError`` so callers can catch it narrowly.
    """


def load_rules_from_dir(rules_dir: Path) -> List[Dict[str, Any]]:
    """
    Load and validate all YAML files in *rules_dir*.

    Files are processed in sorted order for reproducibility.
    Files whose names begin with ``_`` or ``.`` are skipped.

    Parameters
    ----------
    rules_dir : Path
        Directory containing rule YAML files.

    Returns
    -------
    list[dict]
        Flat list of validated rule dicts from all files.

    Raises
    ------
    RuleLoadError
        If *rules_dir* does not exist or if any YAML file fails validation.
    """
    if not rules_dir.exists():
        raise RuleLoadError(
            f"Rules directory does not exist: {rules_dir!r}"
        )
    if not rules_dir.is_dir():
        raise RuleLoadError(
            f"Rules path is not a directory: {rules_dir!r}"
        )

    yaml_files = sorted(
        p for p in rules_dir.glob("*.yaml")
        if not p.name.startswith(("_", "."))
    )

    all_rules: List[Dict[str, Any]] = []
    for yaml_path in yaml_files:
        file_rules = load_rules_from_file(yaml_path)
        all_rules.extend(file_rules)

    return all_rules


def load_rules_from_file(path: Path) -> List[Dict[str, Any]]:
    """
    Load and validate rules from a single YAML file.

    Parameters
    ----------
    path : Path
        YAML file to load.

    Returns
    -------
    list[dict]
        Validated rule dicts from this file.

    Raises
    ------
    RuleLoadError
        For any YAML parse error or schema violation.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(f"Cannot read {path!r}: {exc}") from exc

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RuleLoadError(
            f"YAML parse error in {path.name!r}: {exc}"
        ) from exc

    if doc is None:
        # Empty file — silently return no rules.
        return []

    if not isinstance(doc, dict):
        raise RuleLoadError(
            f"{path.name!r}: top-level document must be a YAML mapping "
            f"(got {type(doc).__name__!r})."
        )

    raw_rules = doc.get("rules")
    if raw_rules is None:
        raise RuleLoadError(
            f"{path.name!r}: missing required top-level key 'rules'."
        )
    if not isinstance(raw_rules, list):
        raise RuleLoadError(
            f"{path.name!r}: 'rules' must be a YAML sequence "
            f"(got {type(raw_rules).__name__!r})."
        )

    validated: List[Dict[str, Any]] = []
    for idx, rule in enumerate(raw_rules):
        _validate_rule(rule, path.name, idx)
        validated.append(rule)

    return validated


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_rule(rule: Any, source: str, idx: int) -> None:
    """
    Validate one rule dict.  Raises RuleLoadError with a descriptive message.
    """
    if not isinstance(rule, dict):
        raise RuleLoadError(
            f"{source!r} rule[{idx}]: expected a mapping, "
            f"got {type(rule).__name__!r}."
        )

    missing = _REQUIRED_RULE_KEYS - rule.keys()
    if missing:
        rule_id = rule.get("id", f"<rule[{idx}]>")
        raise RuleLoadError(
            f"{source!r} rule {rule_id!r}: missing required key(s): "
            f"{sorted(missing)}."
        )

    severity = rule.get("severity", "")
    if severity not in VALID_SEVERITIES:
        raise RuleLoadError(
            f"{source!r} rule {rule['id']!r}: invalid severity {severity!r}. "
            f"Must be one of {sorted(VALID_SEVERITIES)}."
        )

    # Validate condition structure (surface-level only; operators are checked
    # by the evaluator at runtime so that condition nesting can be arbitrary).
    _validate_condition(rule["condition"], source, rule["id"])


def _validate_condition(cond: Any, source: str, rule_id: str) -> None:
    """Recursively validate condition structure."""
    if not isinstance(cond, dict):
        raise RuleLoadError(
            f"{source!r} rule {rule_id!r}: condition must be a mapping, "
            f"got {type(cond).__name__!r}."
        )

    op = cond.get("op")
    if not op:
        raise RuleLoadError(
            f"{source!r} rule {rule_id!r}: condition missing 'op' key."
        )
    if not isinstance(op, str):
        raise RuleLoadError(
            f"{source!r} rule {rule_id!r}: 'op' must be a string, "
            f"got {type(op).__name__!r}."
        )

    known = _COMPOUND_OPS | _SIMPLE_OPS
    if op not in known:
        raise RuleLoadError(
            f"{source!r} rule {rule_id!r}: unknown operator {op!r}. "
            f"Allowed: {sorted(known)}."
        )

    if op in _COMPOUND_OPS:
        sub = cond.get("conditions")
        if not isinstance(sub, list) or not sub:
            raise RuleLoadError(
                f"{source!r} rule {rule_id!r}: compound op {op!r} requires "
                f"a non-empty 'conditions' list."
            )
        for child in sub:
            _validate_condition(child, source, rule_id)
    else:
        if "field" not in cond:
            raise RuleLoadError(
                f"{source!r} rule {rule_id!r}: simple op {op!r} requires "
                f"a 'field' key."
            )
