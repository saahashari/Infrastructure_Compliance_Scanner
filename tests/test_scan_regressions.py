"""Regression tests for behavior across policy matching and scanning."""

import unittest

from scanner.engine import ComplianceEngine, evaluate_condition, policy_applies_to
from scanner.models import Condition, Operator, Policy, Service, Severity


class TestScanRegressions(unittest.TestCase):
    def test_scan_matches_environment_and_resource_type_without_case(self):
        policy = Policy(
            id="CASE-001",
            name="Require encryption",
            description="Databases must be encrypted.",
            severity=Severity.HIGH,
            resource_type="DATABASE",
            environment="Production",
            conditions=[Condition("config.encrypted", Operator.EQUALS, True)],
        )
        service = Service(
            name="customer-db",
            type="database",
            environment="production",
            config={"encrypted": False},
        )

        self.assertTrue(policy_applies_to(policy, service))
        result = ComplianceEngine([policy]).scan([service])

        self.assertEqual(["CASE-001"], [v.policy_id for v in result.violations])
        self.assertEqual(0, result.compliant_services)

    def test_boolean_policy_rejects_numeric_one(self):
        policy = Policy(
            id="SEC-BOOL",
            name="Require encryption",
            description="Encryption must be enabled.",
            severity=Severity.CRITICAL,
            resource_type="database",
            conditions=[Condition("config.encrypted", Operator.EQUALS, True)],
        )
        service = Service(
            name="customer-db",
            type="database",
            environment="production",
            config={"encrypted": 1},
        )

        result = ComplianceEngine([policy]).scan([service])

        self.assertEqual(1, result.total_violations)
        self.assertEqual(1, result.violations[0].failed_conditions[0].actual_value)

    def test_numeric_comparison_rejects_boolean_and_infinity(self):
        for value in (True, float("inf")):
            with self.subTest(value=value):
                service = Service(
                    name="customer-db",
                    type="database",
                    environment="production",
                    config={"replicas": value},
                )
                condition = Condition("config.replicas", Operator.GTE, 1)
                self.assertFalse(evaluate_condition(condition, service).passed)

    def test_membership_keeps_booleans_distinct_from_numbers(self):
        service = Service(
            name="customer-db",
            type="database",
            environment="production",
            config={"value": True},
        )

        self.assertFalse(
            evaluate_condition(Condition("config.value", Operator.IN, [1]), service).passed
        )
        self.assertTrue(
            evaluate_condition(Condition("config.value", Operator.NOT_IN, [1]), service).passed
        )


if __name__ == "__main__":
    unittest.main()
