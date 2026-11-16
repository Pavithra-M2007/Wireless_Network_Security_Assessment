"""
Rule condition evaluator.

Evaluates structured condition dicts against a NetworkFeatures object.

Design guarantee: this module never calls eval(), exec(), or any
dynamic code-execution mechanism. Every operator is implemented
as an explicit Python comparison or membership test.

Supported operators
-------------------
Simple (require ``field`` key; optionally ``value``):
  eq, ne              — equality / inequality (any type)
  gte, gt, lte, lt    — numeric comparison; returns False if field is None
  is_true             — field is the boolean True (not truthy — identity)
  is_false            — field is the boolean False (not falsy — identity)
  is_none             — field is None
  is_not_none         — field is not None
  in                  — field in value  (value must be a list)
  not_in              — field not in value
  contains            — value in field  (field must be list/set)
  not_contains        — value not in field

Compound (require ``conditions`` list; no ``field`` key):
  all_of              — all sub-conditions must be True (logical AND)
  any_of              — at least one sub-condition must be True (logical OR)
  none_of             — all sub-conditions must be False (logical NOR)
"""
from __future__ import annotations

from typing import Any, Dict

from wsa.analysis.feature_set import NetworkFeatures


class ConditionError(ValueError):
    """
    Raised when a condition cannot be evaluated due to a structural error
    (unknown operator, missing field, wrong value type).

    Inherits from ``ValueError`` so callers can catch it narrowly.
    """


def evaluate_condition(condition: Dict[str, Any], network: NetworkFeatures) -> bool:
    """
    Evaluate a structured condition dict against *network*.

    Parameters
    ----------
    condition : dict
        A condition as loaded from a YAML rule file.
    network : NetworkFeatures
        The network to evaluate against.

    Returns
    -------
    bool
        True if the condition matches; False otherwise.

    Raises
    ------
    ConditionError
        For unknown operators, missing fields, or wrong value types.
        Individual condition errors propagate upward; the engine decides
        whether to skip the rule or abort.
    """
    op = condition.get("op")
    if not op:
        raise ConditionError("Condition is missing the 'op' key.")

    # ------------------------------------------------------------------
    # Compound operators — recurse into sub-conditions
    # ------------------------------------------------------------------

    if op == "all_of":
        return _all_of(condition, network)
    if op == "any_of":
        return _any_of(condition, network)
    if op == "none_of":
        return _none_of(condition, network)

    # ------------------------------------------------------------------
    # Simple operators — read field value once, then compare
    # ------------------------------------------------------------------

    field_name = condition.get("field")
    if not field_name:
        raise ConditionError(
            f"Simple operator {op!r} requires a 'field' key."
        )

    try:
        field_val = getattr(network, field_name)
    except AttributeError:
        raise ConditionError(
            f"NetworkFeatures has no field {field_name!r}."
        )

    return _apply_simple_op(op, field_val, condition, field_name)


# ---------------------------------------------------------------------------
# Compound operator implementations
# ---------------------------------------------------------------------------

def _all_of(condition: Dict[str, Any], network: NetworkFeatures) -> bool:
    sub = _require_conditions_list(condition, "all_of")
    return all(evaluate_condition(c, network) for c in sub)


def _any_of(condition: Dict[str, Any], network: NetworkFeatures) -> bool:
    sub = _require_conditions_list(condition, "any_of")
    return any(evaluate_condition(c, network) for c in sub)


def _none_of(condition: Dict[str, Any], network: NetworkFeatures) -> bool:
    sub = _require_conditions_list(condition, "none_of")
    return not any(evaluate_condition(c, network) for c in sub)


def _require_conditions_list(
    condition: Dict[str, Any], op: str
) -> list:
    sub = condition.get("conditions")
    if not isinstance(sub, list) or not sub:
        raise ConditionError(
            f"Compound operator {op!r} requires a non-empty 'conditions' list."
        )
    return sub


# ---------------------------------------------------------------------------
# Simple operator dispatcher
# ---------------------------------------------------------------------------

def _apply_simple_op(
    op: str,
    field_val: Any,
    condition: Dict[str, Any],
    field_name: str,
) -> bool:
    """Dispatch to the correct comparison based on *op*."""

    # --- Equality -----------------------------------------------------------
    if op == "eq":
        return field_val == condition.get("value")

    if op == "ne":
        return field_val != condition.get("value")

    # --- Identity / presence checks -----------------------------------------
    # NOTE: ``is True`` and ``is False`` use object identity, NOT ``==``.
    # This correctly distinguishes False from None and 0.

    if op == "is_true":
        return field_val is True

    if op == "is_false":
        return field_val is False

    if op == "is_none":
        return field_val is None

    if op == "is_not_none":
        return field_val is not None

    # --- Numeric comparisons ------------------------------------------------
    # All numeric ops return False when the field value is None rather than
    # raising an exception, so rules never fire on absent evidence.

    if op in ("gte", "gt", "lte", "lt"):
        if field_val is None:
            return False
        value = condition.get("value")
        if value is None:
            raise ConditionError(
                f"Numeric operator {op!r} on field {field_name!r} "
                f"requires a 'value' key."
            )
        try:
            if op == "gte":
                return field_val >= value
            if op == "gt":
                return field_val > value
            if op == "lte":
                return field_val <= value
            if op == "lt":
                return field_val < value
        except TypeError as exc:
            raise ConditionError(
                f"Type error in numeric comparison on field {field_name!r}: {exc}"
            ) from exc

    # --- Membership (field value IN a list) ---------------------------------
    if op == "in":
        value_list = condition.get("value")
        if not isinstance(value_list, list):
            raise ConditionError(
                f"Operator 'in' on field {field_name!r} requires "
                f"'value' to be a list."
            )
        return field_val in value_list

    if op == "not_in":
        value_list = condition.get("value")
        if not isinstance(value_list, list):
            raise ConditionError(
                f"Operator 'not_in' on field {field_name!r} requires "
                f"'value' to be a list."
            )
        return field_val not in value_list

    # --- Membership (a value IN the field's list) ---------------------------
    if op == "contains":
        if not isinstance(field_val, (list, set, frozenset)):
            # Treat non-list fields as an empty collection — no match.
            return False
        return condition.get("value") in field_val

    if op == "not_contains":
        if not isinstance(field_val, (list, set, frozenset)):
            return True  # Value absent from a non-list field
        return condition.get("value") not in field_val

    # --- Unknown operator ---------------------------------------------------
    raise ConditionError(f"Unknown operator: {op!r}.")
