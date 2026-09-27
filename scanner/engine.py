"""
engine.py — The compliance rule evaluation engine.

Responsibilities:
  1. Index policies by (resource_type, environment) for O(1) lookup
  2. For each service, find all applicable policies
  3. Evaluate each policy's conditions against the service config
  4. Collect and return all violations

Design principles:
  - Evaluation is pure and stateless — no side effects, easy to test
  - Field resolution uses safe dot-notation traversal (never throws on missing keys)
  - Each condition produces a detailed ConditionResult explaining the outcome
"""

import logging
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.models import (
    Condition,
    ConditionResult,
    LogicMode,
    Operator,
    Policy,
    ScanResult,
    Service,
    Violation,
)

logger = logging.getLogger(__name__)

# Sentinel used to distinguish "field is absent" from "field has value None"
_MISSING = object()


def _values_equal(actual: Any, expected: Any) -> bool:
    """Keep booleans distinct from numbers in policy comparisons."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    return actual == expected


# ---------------------------------------------------------------------------
# Field Resolution
# ---------------------------------------------------------------------------

def resolve_field(obj: Any, path: str) -> Any:
    """
    Safely resolve a dot-notation field path into a nested dict.

    Returns _MISSING if any segment of the path does not exist.
    Returns None if a segment exists but its value is None.

    Examples:
      resolve_field({"config": {"backup_enabled": True}}, "config.backup_enabled")
      → True

      resolve_field({"config": {}}, "config.backup_enabled")
      → _MISSING

      resolve_field({"config": {"replicas": 0}}, "config.replicas")
      → 0  (falsy but NOT missing)
    """
    parts = path.split(".")
    current = obj

    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        else:
            return _MISSING

    return current


def field_exists(obj: Any, path: str) -> bool:
    """Return True if the field path exists in the object (even if value is None)."""
    return resolve_field(obj, path) is not _MISSING


# ---------------------------------------------------------------------------
# Condition Evaluator
# ---------------------------------------------------------------------------

def evaluate_condition(condition: Condition, service: Service) -> ConditionResult:
    """
    Evaluate a single condition against a service's configuration.

    Returns a ConditionResult with passed=True/False and a human-readable
    explanation of the actual vs. expected state.
    """
    # Resolve the field from the service's full attribute dict (not just config)
    # This allows policies to reference top-level service attributes too,
    # e.g., "region", "owner", as well as "config.backup_enabled"
    service_dict = {
        "name": service.name,
        "type": service.type,
        "environment": service.environment,
        "region": service.region,
        "owner": service.owner,
        "tags": service.tags,
        "config": service.config,
    }

    raw_value = resolve_field(service_dict, condition.field)
    is_missing = raw_value is _MISSING
    actual_value = None if is_missing else raw_value

    op = condition.operator
    expected = condition.value

    def _fail(msg: str) -> ConditionResult:
        return ConditionResult(
            condition=condition,
            passed=False,
            actual_value=actual_value,
            message=msg,
        )

    def _pass(msg: str = "") -> ConditionResult:
        return ConditionResult(
            condition=condition,
            passed=True,
            actual_value=actual_value,
            message=msg,
        )

    # --- Existence checks ---
    if op == Operator.EXISTS:
        if is_missing:
            return _fail(f"Field '{condition.field}' does not exist.")
        return _pass()

    if op == Operator.NOT_EXISTS:
        if not is_missing:
            return _fail(f"Field '{condition.field}' exists with value '{actual_value}' but should not.")
        return _pass()

    # For all remaining operators, a missing field is an automatic failure
    if is_missing:
        return _fail(
            f"Field '{condition.field}' is not present in service config. "
            f"Expected it to exist with operator '{op.value}'."
        )

    # --- Equality ---
    if op == Operator.EQUALS:
        if _values_equal(actual_value, expected):
            return _pass()
        return _fail(
            f"'{condition.field}' is '{actual_value}', expected '{expected}'."
        )

    if op == Operator.NOT_EQUALS:
        if not _values_equal(actual_value, expected):
            return _pass()
        return _fail(
            f"'{condition.field}' is '{actual_value}', which is not allowed."
        )

    # --- Numeric comparisons (with type safety) ---
    numeric_ops = {Operator.GREATER_THAN, Operator.LESS_THAN, Operator.GTE, Operator.LTE}
    if op in numeric_ops:
        if isinstance(actual_value, bool) or isinstance(expected, bool):
            return _fail(f"Cannot compare '{condition.field}' numerically with a boolean value.")
        try:
            actual_num = float(actual_value)
            expected_num = float(expected)
        except (TypeError, ValueError):
            return _fail(
                f"Cannot compare '{condition.field}' (value='{actual_value}', "
                f"type={type(actual_value).__name__}) numerically with '{expected}'."
            )
        if not math.isfinite(actual_num) or not math.isfinite(expected_num):
            return _fail(f"Cannot compare '{condition.field}' with a non-finite number.")

        op_map = {
            Operator.GREATER_THAN: (actual_num > expected_num,  ">"),
            Operator.LESS_THAN:    (actual_num < expected_num,  "<"),
            Operator.GTE:          (actual_num >= expected_num, ">="),
            Operator.LTE:          (actual_num <= expected_num, "<="),
        }
        passed, symbol = op_map[op]
        if passed:
            return _pass()
        return _fail(
            f"'{condition.field}' is {actual_num}, must be {symbol} {expected_num}."
        )

    # --- Membership ---
    if op == Operator.IN:
        if not isinstance(expected, list):
            return _fail(f"Operator 'in' requires 'value' to be a list, got {type(expected).__name__}.")
        if any(_values_equal(actual_value, candidate) for candidate in expected):
            return _pass()
        return _fail(
            f"'{condition.field}' is '{actual_value}', must be one of: {expected}."
        )

    if op == Operator.NOT_IN:
        if not isinstance(expected, list):
            return _fail(f"Operator 'not_in' requires 'value' to be a list.")
        if not any(_values_equal(actual_value, candidate) for candidate in expected):
            return _pass()
        return _fail(
            f"'{condition.field}' is '{actual_value}', which is not allowed. "
            f"Disallowed values: {expected}."
        )

    # --- String containment ---
    if op == Operator.CONTAINS:
        try:
            if str(expected) in str(actual_value):
                return _pass()
            return _fail(
                f"'{condition.field}' ('{actual_value}') does not contain '{expected}'."
            )
        except TypeError:
            return _fail(f"Cannot check containment for field '{condition.field}'.")

    if op == Operator.NOT_CONTAINS:
        try:
            if str(expected) not in str(actual_value):
                return _pass()
            return _fail(
                f"'{condition.field}' ('{actual_value}') contains disallowed value '{expected}'."
            )
        except TypeError:
            return _fail(f"Cannot check containment for field '{condition.field}'.")

    # Fallback — should never reach here if operator enum is complete
    return _fail(f"Unknown operator '{op.value}'.")


# ---------------------------------------------------------------------------
# Policy Applicability
# ---------------------------------------------------------------------------

def policy_applies_to(policy: Policy, service: Service) -> bool:
    """
    Determine whether a policy should be evaluated against a given service.

    A policy applies when:
      1. resource_type matches the service type (exact match, case-insensitive)
      2. environment is None (applies everywhere) OR matches the service environment
    """
    type_match = policy.resource_type.lower() == service.type.lower()
    env_match = (
        policy.environment is None
        or policy.environment.lower() == service.environment.lower()
    )
    return type_match and env_match


# ---------------------------------------------------------------------------
# Policy Evaluation
# ---------------------------------------------------------------------------

def evaluate_policy(policy: Policy, service: Service) -> Optional[Violation]:
    """
    Evaluate all conditions in a policy against a service.

    Returns a Violation if the policy fails, or None if it passes.
    Respects the policy's AND/OR logic mode.
    """
    results: List[ConditionResult] = [
        evaluate_condition(cond, service) for cond in policy.conditions
    ]

    if policy.logic == LogicMode.AND:
        # All conditions must pass — collect every failure
        failures = [r for r in results if not r.passed]
        if failures:
            return Violation(policy=policy, service=service, failed_conditions=failures)
        return None

    elif policy.logic == LogicMode.OR:
        # At least one condition must pass
        if any(r.passed for r in results):
            return None
        # All failed — report all of them
        return Violation(policy=policy, service=service, failed_conditions=results)

    return None  # Should not happen


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class ComplianceEngine:
    """
    The main compliance evaluation engine.

    At initialization, policies are indexed by (resource_type, environment)
    for efficient lookup — this scales to thousands of services without
    re-scanning the policy list for every service.
    """

    def __init__(self, policies: List[Policy]):
        self.policies = policies
        # Index: (resource_type, env_or_None) → list of policies
        # We store None separately to represent "applies to all envs"
        self._index: Dict[Tuple[str, Optional[str]], List[Policy]] = defaultdict(list)
        self._build_index()

    def _build_index(self) -> None:
        """Pre-index policies by (resource_type, environment) for O(1) lookup."""
        for policy in self.policies:
            key = (
                policy.resource_type.lower(),
                policy.environment.lower() if policy.environment is not None else None,
            )
            self._index[key].append(policy)
        logger.debug(
            "Policy index built: %d buckets for %d policies.",
            len(self._index), len(self.policies)
        )

    def _get_applicable_policies(self, service: Service) -> List[Policy]:
        """
        Return all policies that apply to a given service.

        Looks up both environment-specific and environment-agnostic policies.
        """
        svc_type = service.type.lower()
        svc_env = service.environment.lower()

        # Environment-specific policies
        specific = self._index.get((svc_type, svc_env), [])
        # Environment-agnostic policies (environment=None in policy)
        global_scope = self._index.get((svc_type, None), [])

        return specific + global_scope

    def scan(self, services: List[Service]) -> ScanResult:
        """
        Scan all services against all applicable policies.

        Returns a ScanResult with the full violation list and summary statistics.
        """
        all_violations: List[Violation] = []
        unscanned_services: List[Service] = []

        for service in services:
            applicable = self._get_applicable_policies(service)
            if not applicable:
                unscanned_services.append(service)
                logger.debug(
                    "No policies apply to service '%s' (%s/%s).",
                    service.name, service.type, service.environment,
                )
                continue
            logger.debug(
                "Service '%s' (%s/%s): checking against %d policies.",
                service.name, service.type, service.environment, len(applicable)
            )

            for policy in applicable:
                violation = evaluate_policy(policy, service)
                if violation:
                    all_violations.append(violation)
                    logger.debug(
                        "VIOLATION: service='%s' policy='%s'",
                        service.name, policy.id
                    )

        # Sort violations: severity first, then service name, then policy ID
        all_violations.sort(
            key=lambda v: (v.severity.sort_key, v.service.name, v.policy.id)
        )

        return ScanResult(
            violations=all_violations,
            total_services=len(services),
            total_policies=len(self.policies),
            unscanned_services=unscanned_services,
        )
