"""
tests/test_engine.py — Unit tests for the compliance rule evaluation engine.

Uses Python's built-in unittest module only — no external dependencies.

Run:
  python -m unittest discover tests/ -v
  python tests/test_engine.py
"""

import json
import unittest

from scanner.engine import (
    ComplianceEngine,
    _MISSING,
    evaluate_condition,
    evaluate_policy,
    field_exists,
    policy_applies_to,
    resolve_field,
)
from scanner.models import (
    Condition,
    LogicMode,
    Operator,
    Policy,
    Service,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_service(name="test-db", svc_type="database", environment="production",
                 owner="platform-team", config=None) -> Service:
    return Service(name=name, type=svc_type, environment=environment,
                   region="us-east-1", owner=owner, config=config or {})


def make_policy(policy_id="TEST-001", resource_type="database",
                environment="production", severity=Severity.HIGH,
                conditions=None, logic=LogicMode.AND) -> Policy:
    return Policy(id=policy_id, name="Test Policy", description="A test.",
                  severity=severity, resource_type=resource_type,
                  environment=environment, conditions=conditions or [],
                  logic=logic, remediation="Fix it.")


def make_condition(field, operator, value=None, message="") -> Condition:
    return Condition(field=field, operator=operator, value=value, message=message)


# ---------------------------------------------------------------------------
# 1. Field Resolution
# ---------------------------------------------------------------------------

class TestFieldResolution(unittest.TestCase):

    def test_top_level_field(self):
        self.assertEqual(resolve_field({"owner": "data-team"}, "owner"), "data-team")

    def test_nested_config_field(self):
        obj = {"config": {"backup_enabled": True}}
        self.assertTrue(resolve_field(obj, "config.backup_enabled"))

    def test_deeply_nested_field(self):
        obj = {"config": {"storage": {"encryption": True}}}
        self.assertTrue(resolve_field(obj, "config.storage.encryption"))

    def test_missing_top_level_field_returns_sentinel(self):
        self.assertIs(resolve_field({"config": {}}, "nonexistent"), _MISSING)

    def test_missing_nested_field_returns_sentinel(self):
        obj = {"config": {"backup_enabled": True}}
        self.assertIs(resolve_field(obj, "config.encryption_at_rest"), _MISSING)

    def test_missing_intermediate_key_returns_sentinel(self):
        self.assertIs(resolve_field({"config": {}}, "config.storage.encryption"), _MISSING)

    def test_zero_is_not_missing(self):
        obj = {"config": {"replicas": 0}}
        result = resolve_field(obj, "config.replicas")
        self.assertEqual(result, 0)
        self.assertIsNot(result, _MISSING)

    def test_false_boolean_is_not_missing(self):
        obj = {"config": {"backup_enabled": False}}
        result = resolve_field(obj, "config.backup_enabled")
        self.assertIs(result, False)
        self.assertIsNot(result, _MISSING)

    def test_none_value_is_not_missing(self):
        obj = {"config": {"field": None}}
        result = resolve_field(obj, "config.field")
        self.assertIsNone(result)
        self.assertIsNot(result, _MISSING)

    def test_field_exists_when_present(self):
        obj = {"config": {"backup_enabled": False}}
        self.assertTrue(field_exists(obj, "config.backup_enabled"))

    def test_field_not_exists_when_absent(self):
        self.assertFalse(field_exists({"config": {}}, "config.backup_enabled"))


# ---------------------------------------------------------------------------
# 2. Condition Evaluation — All Operators
# ---------------------------------------------------------------------------

class TestEqualsOperator(unittest.TestCase):

    def test_passes_when_equal(self):
        svc = make_service(config={"backup_enabled": True})
        cond = make_condition("config.backup_enabled", Operator.EQUALS, True)
        self.assertTrue(evaluate_condition(cond, svc).passed)

    def test_fails_when_not_equal(self):
        svc = make_service(config={"backup_enabled": False})
        cond = make_condition("config.backup_enabled", Operator.EQUALS, True)
        result = evaluate_condition(cond, svc)
        self.assertFalse(result.passed)
        self.assertIs(result.actual_value, False)

    def test_missing_field_fails(self):
        svc = make_service(config={})
        cond = make_condition("config.backup_enabled", Operator.EQUALS, True)
        result = evaluate_condition(cond, svc)
        self.assertFalse(result.passed)
        self.assertIsNone(result.actual_value)

    def test_string_equality(self):
        svc = make_service(config={"engine": "postgres"})
        cond = make_condition("config.engine", Operator.EQUALS, "postgres")
        self.assertTrue(evaluate_condition(cond, svc).passed)


class TestNotEqualsOperator(unittest.TestCase):

    def test_passes_for_different_value(self):
        svc = make_service(owner="platform-team")
        self.assertTrue(evaluate_condition(make_condition("owner", Operator.NOT_EQUALS, "unknown"), svc).passed)

    def test_fails_for_same_value(self):
        svc = make_service(owner="unknown")
        self.assertFalse(evaluate_condition(make_condition("owner", Operator.NOT_EQUALS, "unknown"), svc).passed)


class TestNumericOperators(unittest.TestCase):

    def test_gte_passes_equal(self):
        svc = make_service(config={"replicas": 2})
        self.assertTrue(evaluate_condition(make_condition("config.replicas", Operator.GTE, 2), svc).passed)

    def test_gte_passes_greater(self):
        svc = make_service(config={"replicas": 5})
        self.assertTrue(evaluate_condition(make_condition("config.replicas", Operator.GTE, 2), svc).passed)

    def test_gte_fails_less(self):
        svc = make_service(config={"replicas": 1})
        result = evaluate_condition(make_condition("config.replicas", Operator.GTE, 2), svc)
        self.assertFalse(result.passed)
        self.assertEqual(result.actual_value, 1)

    def test_lte_passes(self):
        svc = make_service(config={"replicas": 2})
        self.assertTrue(evaluate_condition(make_condition("config.replicas", Operator.LTE, 5), svc).passed)

    def test_greater_than_strict_boundary(self):
        # 2 > 2 is False
        svc = make_service(config={"replicas": 2})
        self.assertFalse(evaluate_condition(make_condition("config.replicas", Operator.GREATER_THAN, 2), svc).passed)

    def test_less_than_strict(self):
        svc = make_service(config={"replicas": 1})
        self.assertTrue(evaluate_condition(make_condition("config.replicas", Operator.LESS_THAN, 2), svc).passed)

    def test_non_numeric_fails_gracefully(self):
        svc = make_service(config={"replicas": "many"})
        result = evaluate_condition(make_condition("config.replicas", Operator.GTE, 2), svc)
        self.assertFalse(result.passed)
        self.assertIn("Cannot compare", result.message)


class TestInOperator(unittest.TestCase):

    def test_value_in_list_passes(self):
        svc = make_service(config={"instance_type": "db.t3.micro"})
        cond = make_condition("config.instance_type", Operator.IN, ["db.t3.micro", "db.t3.small"])
        self.assertTrue(evaluate_condition(cond, svc).passed)

    def test_value_not_in_list_fails(self):
        svc = make_service(config={"instance_type": "db.r5.2xlarge"})
        cond = make_condition("config.instance_type", Operator.IN, ["db.t3.micro", "db.t3.small"])
        self.assertFalse(evaluate_condition(cond, svc).passed)

    def test_not_in_blocks_disallowed(self):
        svc = make_service(config={"instance_type": "m5.8xlarge"})
        cond = make_condition("config.instance_type", Operator.NOT_IN, ["m5.8xlarge", "r5.8xlarge"])
        self.assertFalse(evaluate_condition(cond, svc).passed)

    def test_not_in_allows_permitted(self):
        svc = make_service(config={"instance_type": "t3.small"})
        cond = make_condition("config.instance_type", Operator.NOT_IN, ["m5.8xlarge", "r5.8xlarge"])
        self.assertTrue(evaluate_condition(cond, svc).passed)


class TestExistenceOperators(unittest.TestCase):

    def test_exists_passes_for_false_value(self):
        # False is present — exists should pass
        svc = make_service(config={"backup_enabled": False})
        self.assertTrue(evaluate_condition(make_condition("config.backup_enabled", Operator.EXISTS), svc).passed)

    def test_exists_fails_for_absent_field(self):
        svc = make_service(config={})
        self.assertFalse(evaluate_condition(make_condition("config.backup_enabled", Operator.EXISTS), svc).passed)

    def test_not_exists_passes_for_absent(self):
        svc = make_service(config={})
        self.assertTrue(evaluate_condition(make_condition("config.deprecated_field", Operator.NOT_EXISTS), svc).passed)

    def test_not_exists_fails_for_present(self):
        svc = make_service(config={"deprecated_field": "value"})
        self.assertFalse(evaluate_condition(make_condition("config.deprecated_field", Operator.NOT_EXISTS), svc).passed)


class TestContainsOperator(unittest.TestCase):

    def test_contains_substring(self):
        svc = make_service(config={"engine": "postgres-14"})
        self.assertTrue(evaluate_condition(make_condition("config.engine", Operator.CONTAINS, "postgres"), svc).passed)

    def test_contains_missing_substring_fails(self):
        svc = make_service(config={"engine": "mysql-8"})
        self.assertFalse(evaluate_condition(make_condition("config.engine", Operator.CONTAINS, "postgres"), svc).passed)

    def test_not_contains_passes(self):
        svc = make_service(config={"engine": "mysql-8"})
        self.assertTrue(evaluate_condition(make_condition("config.engine", Operator.NOT_CONTAINS, "postgres"), svc).passed)

    def test_not_contains_fails_when_present(self):
        svc = make_service(config={"engine": "postgres-14"})
        self.assertFalse(evaluate_condition(make_condition("config.engine", Operator.NOT_CONTAINS, "postgres"), svc).passed)


# ---------------------------------------------------------------------------
# 3. Policy Scoping
# ---------------------------------------------------------------------------

class TestPolicyScoping(unittest.TestCase):

    def test_matches_type_and_env(self):
        policy = make_policy(resource_type="database", environment="production")
        svc = make_service(svc_type="database", environment="production")
        self.assertTrue(policy_applies_to(policy, svc))

    def test_skips_wrong_type(self):
        policy = make_policy(resource_type="compute", environment="production")
        svc = make_service(svc_type="database", environment="production")
        self.assertFalse(policy_applies_to(policy, svc))

    def test_skips_wrong_environment(self):
        policy = make_policy(resource_type="database", environment="production")
        svc = make_service(svc_type="database", environment="dev")
        self.assertFalse(policy_applies_to(policy, svc))

    def test_global_policy_applies_to_all_envs(self):
        policy = make_policy(resource_type="database", environment=None)
        for env in ["production", "staging", "dev"]:
            svc = make_service(svc_type="database", environment=env)
            self.assertTrue(policy_applies_to(policy, svc), f"Should apply to {env}")

    def test_case_insensitive_matching(self):
        policy = make_policy(resource_type="Database", environment="Production")
        svc = make_service(svc_type="database", environment="production")
        self.assertTrue(policy_applies_to(policy, svc))


# ---------------------------------------------------------------------------
# 4. AND / OR Logic
# ---------------------------------------------------------------------------

class TestAndLogic(unittest.TestCase):

    def test_all_pass_no_violation(self):
        svc = make_service(config={"backup_enabled": True, "replicas": 3})
        policy = make_policy(logic=LogicMode.AND, conditions=[
            make_condition("config.backup_enabled", Operator.EQUALS, True),
            make_condition("config.replicas", Operator.GTE, 2),
        ])
        self.assertIsNone(evaluate_policy(policy, svc))

    def test_one_failure_creates_violation(self):
        svc = make_service(config={"backup_enabled": True, "replicas": 1})
        policy = make_policy(logic=LogicMode.AND, conditions=[
            make_condition("config.backup_enabled", Operator.EQUALS, True),
            make_condition("config.replicas", Operator.GTE, 2),
        ])
        result = evaluate_policy(policy, svc)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.failed_conditions), 1)
        self.assertEqual(result.failed_conditions[0].condition.field, "config.replicas")

    def test_all_fail_reports_every_failure(self):
        svc = make_service(config={"backup_enabled": False, "replicas": 0})
        policy = make_policy(logic=LogicMode.AND, conditions=[
            make_condition("config.backup_enabled", Operator.EQUALS, True),
            make_condition("config.replicas", Operator.GTE, 2),
        ])
        result = evaluate_policy(policy, svc)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.failed_conditions), 2)


class TestOrLogic(unittest.TestCase):

    def test_one_pass_no_violation(self):
        svc = make_service(config={"tls": "TLSv1.2"})
        policy = make_policy(logic=LogicMode.OR, conditions=[
            make_condition("config.tls", Operator.EQUALS, "TLSv1.2"),
            make_condition("config.tls", Operator.EQUALS, "TLSv1.3"),
        ])
        self.assertIsNone(evaluate_policy(policy, svc))

    def test_all_fail_creates_violation(self):
        svc = make_service(config={"tls": "TLSv1.0"})
        policy = make_policy(logic=LogicMode.OR, conditions=[
            make_condition("config.tls", Operator.EQUALS, "TLSv1.2"),
            make_condition("config.tls", Operator.EQUALS, "TLSv1.3"),
        ])
        result = evaluate_policy(policy, svc)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.failed_conditions), 2)


# ---------------------------------------------------------------------------
# 5. Engine Integration
# ---------------------------------------------------------------------------

class TestComplianceEngine(unittest.TestCase):

    def test_compliant_service_is_clean(self):
        policy = make_policy(conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        result = engine.scan([make_service(config={"backup_enabled": True})])
        self.assertEqual(result.total_violations, 0)
        self.assertTrue(result.is_compliant())

    def test_non_compliant_service_produces_violation(self):
        policy = make_policy(conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        result = engine.scan([make_service(config={"backup_enabled": False})])
        self.assertEqual(result.total_violations, 1)
        self.assertEqual(result.violations[0].policy.id, "TEST-001")
        self.assertEqual(result.violations[0].service.name, "test-db")

    def test_prod_policy_does_not_apply_to_dev(self):
        policy = make_policy(resource_type="database", environment="production",
                             conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        dev_svc = make_service(environment="dev", config={"backup_enabled": False})
        self.assertEqual(engine.scan([dev_svc]).total_violations, 0)

    def test_global_policy_fires_in_all_envs(self):
        policy = make_policy(resource_type="database", environment=None,
                             conditions=[make_condition("config.encryption_at_rest", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        services = [
            make_service("prod-db", environment="production", config={"encryption_at_rest": False}),
            make_service("dev-db",  environment="dev",        config={"encryption_at_rest": False}),
            make_service("stg-db",  environment="staging",    config={"encryption_at_rest": True}),
        ]
        result = engine.scan(services)
        self.assertEqual(result.total_violations, 2)
        self.assertNotIn("stg-db", {v.service.name for v in result.violations})

    def test_violations_sorted_by_severity(self):
        policies = [
            make_policy("LOW-001",  severity=Severity.LOW,      conditions=[make_condition("config.a", Operator.EQUALS, True)]),
            make_policy("CRIT-001", severity=Severity.CRITICAL, conditions=[make_condition("config.b", Operator.EQUALS, True)]),
            make_policy("HIGH-001", severity=Severity.HIGH,     conditions=[make_condition("config.c", Operator.EQUALS, True)]),
        ]
        engine = ComplianceEngine(policies)
        result = engine.scan([make_service(config={"a": False, "b": False, "c": False})])
        self.assertEqual(
            [v.severity for v in result.violations],
            [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
        )

    def test_scan_summary_statistics(self):
        policy = make_policy(severity=Severity.CRITICAL,
                             conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        services = [
            make_service("svc-1", config={"backup_enabled": False}),
            make_service("svc-2", config={"backup_enabled": True}),
        ]
        result = engine.scan(services)
        self.assertEqual(result.total_services, 2)
        self.assertEqual(result.total_violations, 1)
        self.assertEqual(result.compliant_services, 1)
        self.assertEqual(result.violations_by_severity["critical"], 1)
        self.assertEqual(result.violations_by_severity["high"], 0)

    def test_violation_is_json_serializable(self):
        policy = make_policy(conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        result = engine.scan([make_service(config={"backup_enabled": False})])
        d = result.to_dict()
        json_str = json.dumps(d)  # Must not raise
        self.assertIn("violations", d)
        v = d["violations"][0]
        for key in ["policy_id", "service", "failed_conditions", "remediation"]:
            self.assertIn(key, v)

    def test_empty_services_returns_compliant(self):
        policy = make_policy(conditions=[make_condition("config.backup_enabled", Operator.EQUALS, True)])
        engine = ComplianceEngine([policy])
        result = engine.scan([])
        self.assertTrue(result.is_compliant())
        self.assertEqual(result.total_services, 0)

    def test_no_policies_leave_service_unscanned(self):
        engine = ComplianceEngine([])
        result = engine.scan([make_service(config={"backup_enabled": False})])
        self.assertFalse(result.is_compliant())
        self.assertEqual(result.scanned_services, 0)
        self.assertEqual(result.compliant_services, 0)
        self.assertEqual(len(result.unscanned_services), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
