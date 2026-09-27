"""Integration tests for complete input loading and CLI exit behavior."""

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from scanner.loader import load_configs, load_policies


PROJECT_ROOT = Path(__file__).resolve().parents[1]

GOOD_POLICY = """
policies:
  - id: SEC-001
    name: Require encryption
    severity: high
    resource_type: database
    conditions:
      - field: config.encrypted
        operator: equals
        value: true
"""

GOOD_CONFIG = """
services:
  - name: customer-db
    type: database
    environment: production
    config:
      encrypted: true
"""


class TestInputAndCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policies_dir = self.root / "policies"
        self.configs_dir = self.root / "configs"
        self._write("policies/valid.yaml", GOOD_POLICY)
        self._write("configs/valid.yaml", GOOD_CONFIG)

    def _write(self, relative_path, contents):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(contents).lstrip(), encoding="utf-8")

    def _run_cli(self, *args):
        return subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "main.py"),
                "--policies", str(self.policies_dir),
                "--configs", str(self.configs_dir),
                "--output", "json",
                *args,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_valid_scan_reports_complete_input(self):
        result = self._run_cli()
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)["summary"]
        self.assertEqual(1, summary["total_policies"])
        self.assertEqual(1, summary["total_services"])
        self.assertEqual(0, summary["total_violations"])

    def test_invalid_policy_cannot_be_skipped_even_with_no_fail(self):
        self._write("policies/invalid.yaml", """
            policies:
              - id: SEC-002
                name: Bad operator
                severity: high
                resource_type: database
                conditions:
                  - field: config.encrypted
                    operator: unknown
                    value: true
        """)
        result = self._run_cli("--no-fail")
        self.assertEqual(2, result.returncode)
        self.assertIn("Unknown operator", result.stderr)
        self.assertEqual("", result.stdout)

    def test_malformed_policy_item_raises_clear_error(self):
        self._write("policies/invalid.yaml", "policies: [null]\n")
        with self.assertRaisesRegex(ValueError, "Policy must be a mapping"):
            load_policies(str(self.policies_dir))

    def test_duplicate_policy_ids_are_rejected(self):
        self._write("policies/duplicate.yaml", GOOD_POLICY)
        with self.assertRaisesRegex(ValueError, "Duplicate policy ID"):
            load_policies(str(self.policies_dir))

    def test_invalid_config_cannot_be_skipped(self):
        self._write("configs/invalid.yaml", """
            services:
              - name: broken-db
                type: database
                environment: production
                config: []
        """)
        with self.assertRaisesRegex(ValueError, "'config' must be a dict"):
            load_configs(str(self.configs_dir))

    def test_duplicate_service_names_are_rejected(self):
        self._write("configs/duplicate.yaml", GOOD_CONFIG)
        with self.assertRaisesRegex(ValueError, "Duplicate service"):
            load_configs(str(self.configs_dir))

    def test_unmatched_filter_is_configuration_error_even_with_no_fail(self):
        for option in ("--env", "--service"):
            with self.subTest(option=option):
                result = self._run_cli(option, "missing", "--no-fail")
                self.assertEqual(2, result.returncode)
                self.assertIn("No service", result.stderr)
                self.assertEqual("", result.stdout)

    def test_uncovered_service_is_reported_and_fails_even_with_no_fail(self):
        self._write("configs/uncovered.yaml", """
            services:
              - name: analytics-worker
                type: compute
                environment: production
                config: {}
        """)

        result = self._run_cli("--no-fail")

        self.assertEqual(2, result.returncode)
        self.assertIn("no applicable policies", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(2, report["summary"]["total_services"])
        self.assertEqual(1, report["summary"]["scanned_services"])
        self.assertEqual(1, report["summary"]["unscanned_services"])
        self.assertEqual(1, report["summary"]["compliant_services"])
        self.assertEqual("analytics-worker", report["unscanned_services"][0]["name"])


if __name__ == "__main__":
    unittest.main()
