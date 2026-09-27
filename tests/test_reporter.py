"""JSON output contract tests."""

import io
import json
import unittest

from scanner.engine import ComplianceEngine
from scanner.models import Condition, Operator, Policy, Service, Severity
from scanner.reporter import print_json_report, print_terminal_report


class TestJSONReport(unittest.TestCase):
    def test_terminal_report_identifies_unscanned_service(self):
        service = Service(
            name="customer-db",
            type="database",
            environment="production",
            config={},
        )
        result = ComplianceEngine([]).scan([service])
        output = io.StringIO()

        print_terminal_report(result, output)

        report = output.getvalue()
        self.assertIn("UNSCANNED SERVICES", report)
        self.assertIn("customer-db (database/production)", report)
        self.assertIn("0 violation(s) and 1 unscanned service(s)", report)
        self.assertNotIn("ALL SERVICES COMPLIANT", report)

    def test_non_finite_actual_values_remain_valid_json(self):
        policy = Policy(
            id="OPS-NUMERIC",
            name="Minimum replicas",
            description="Require at least two replicas.",
            severity=Severity.HIGH,
            resource_type="database",
            conditions=[Condition("config.replicas", Operator.GTE, 2)],
        )

        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=str(value)):
                service = Service(
                    name="customer-db",
                    type="database",
                    environment="production",
                    config={"replicas": value},
                )
                result = ComplianceEngine([policy]).scan([service])
                output = io.StringIO()

                print_json_report(result, output)
                report = json.loads(
                    output.getvalue(),
                    parse_constant=lambda constant: self.fail(
                        f"Non-standard JSON number: {constant}"
                    ),
                )

                self.assertEqual(1, report["summary"]["total_violations"])
                self.assertEqual(
                    str(value),
                    report["violations"][0]["failed_conditions"][0]["actual"],
                )


if __name__ == "__main__":
    unittest.main()
