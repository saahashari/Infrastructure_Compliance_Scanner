"""
models.py — Core data models for the compliance scanner.

These dataclasses represent the three central entities:
  - Service: a piece of infrastructure with a type, environment, and config
  - Policy: a compliance rule with conditions, severity, and remediation advice
  - Violation: the result of a policy failing against a specific service
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Violation severity levels, ordered from most to least critical."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def sort_key(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}[self.value]


class Operator(str, Enum):
    """
    Supported condition operators.

    Comparison:   equals, not_equals, greater_than, less_than, gte, lte
    Membership:   in, not_in, contains, not_contains
    Existence:    exists, not_exists
    """
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GTE = "gte"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"


class LogicMode(str, Enum):
    """How multiple conditions in a policy are combined."""
    AND = "AND"  # All conditions must pass (default — conservative)
    OR = "OR"   # At least one condition must pass


# ---------------------------------------------------------------------------
# Condition
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """
    A single field check within a policy.

    `field` uses dot-notation to traverse into nested config dicts.
    e.g., "config.storage.encryption_enabled"
    """
    field: str
    operator: Operator
    value: Any = None
    message: str = ""  # Optional human-readable description of what this checks


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """
    A compliance policy/rule consisting of one or more conditions.

    Policies are scoped by resource_type and optionally by environment.
    A policy with environment=None applies to all environments.
    """
    id: str
    name: str
    description: str
    severity: Severity
    resource_type: str          # e.g. "database", "compute", "storage"
    conditions: List[Condition]
    environment: Optional[str] = None   # None → applies to all envs
    logic: LogicMode = LogicMode.AND
    remediation: str = ""
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service (Infrastructure Resource)
# ---------------------------------------------------------------------------

@dataclass
class Service:
    """
    Represents a single infrastructure resource (a service/database/instance).

    `config` is a free-form dict that mirrors cloud provider API output.
    Field paths in conditions are resolved against this dict using dot-notation.
    """
    name: str
    type: str               # Must match policy resource_type
    environment: str        # e.g. "production", "staging", "dev"
    config: Dict[str, Any]
    region: str = "us-east-1"
    owner: str = "unknown"
    tags: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Condition & Violation Results
# ---------------------------------------------------------------------------

@dataclass
class ConditionResult:
    """The outcome of evaluating a single condition against a service."""
    condition: Condition
    passed: bool
    actual_value: Any           # What the service config actually has
    message: str = ""           # Human-readable explanation of the failure


@dataclass
class Violation:
    """
    A policy violation: a specific policy failed against a specific service.
    Contains the full context needed to understand and fix the issue.
    """
    policy: Policy
    service: Service
    failed_conditions: List[ConditionResult]

    @property
    def severity(self) -> Severity:
        return self.policy.severity

    @property
    def service_name(self) -> str:
        return self.service.name

    @property
    def policy_id(self) -> str:
        return self.policy.id

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "policy_id": self.policy.id,
            "policy_name": self.policy.name,
            "severity": self.policy.severity.value,
            "service": self.service.name,
            "environment": self.service.environment,
            "resource_type": self.service.type,
            "region": self.service.region,
            "owner": self.service.owner,
            "description": self.policy.description,
            "remediation": self.policy.remediation,
            "failed_conditions": [
                {
                    "field": r.condition.field,
                    "operator": r.condition.operator.value,
                    "expected": r.condition.value,
                    "actual": r.actual_value,
                    "message": r.message,
                }
                for r in self.failed_conditions
            ],
        }


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    The complete output of a single compliance scan run.
    Holds all violations and aggregate statistics.
    """
    violations: List[Violation]
    total_services: int
    total_policies: int
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    @property
    def total_violations(self) -> int:
        return len(self.violations)

    @property
    def compliant_services(self) -> int:
        violating = {v.service.name for v in self.violations}
        return self.total_services - len(violating)

    @property
    def violations_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for v in self.violations:
            counts[v.severity.value] += 1
        return counts

    def is_compliant(self) -> bool:
        return len(self.violations) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total_services": self.total_services,
                "total_policies": self.total_policies,
                "total_violations": self.total_violations,
                "compliant_services": self.compliant_services,
                "violations_by_severity": self.violations_by_severity,
            },
            "violations": [v.to_dict() for v in self.violations],
        }
