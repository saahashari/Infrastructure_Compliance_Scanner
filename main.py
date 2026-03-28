#!/usr/bin/env python3
"""
main.py — CLI entrypoint for the Infrastructure Compliance Scanner.

Usage examples:
  python main.py
  python main.py --policies policies/ --configs configs/
  python main.py --output json > report.json
  python main.py --severity critical high
  python main.py --env production
  python main.py --verbose

Exit codes:
  0  — All services are compliant (or --dry-run)
  1  — One or more violations found
  2  — Configuration or runtime error
"""

import argparse
import logging
import sys
from typing import List, Optional

from scanner.engine import ComplianceEngine
from scanner.loader import load_configs, load_policies
from scanner.models import Severity, Violation
from scanner.reporter import print_json_report, print_terminal_report


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compliance-scanner",
        description="Scan infrastructure configurations against compliance policies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                  Run with default dirs
  python main.py --env production                 Scan only production services
  python main.py --severity critical high         Show only critical/high violations
  python main.py --output json > report.json      Export JSON report
  python main.py --verbose                        Enable debug logging
        """,
    )

    parser.add_argument(
        "--policies",
        default="policies/",
        metavar="DIR",
        help="Directory containing YAML policy files (default: policies/)",
    )
    parser.add_argument(
        "--configs",
        default="configs/",
        metavar="DIR",
        help="Directory containing YAML infrastructure config files (default: configs/)",
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format: 'terminal' (default) or 'json'",
    )
    parser.add_argument(
        "--env",
        metavar="ENV",
        help="Filter: only scan services in this environment (e.g., production)",
    )
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=[s.value for s in Severity],
        metavar="SEV",
        help="Filter: only show violations at these severity levels",
    )
    parser.add_argument(
        "--service",
        metavar="NAME",
        help="Filter: only scan a specific service by name",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0 even if violations are found (useful in reporting-only mode)",
    )

    return parser


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def filter_violations(
    violations: List[Violation],
    severities: Optional[List[str]],
) -> List[Violation]:
    """Apply post-scan filters to the violation list."""
    if severities:
        severity_set = {Severity(s) for s in severities}
        violations = [v for v in violations if v.severity in severity_set]
    return violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s  %(name)s: %(message)s",
        stream=sys.stderr,  # Logging to stderr keeps stdout clean for JSON output
    )

    # --- Load policies ---
    try:
        policies = load_policies(args.policies)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not policies:
        print("ERROR: No policies were loaded. Check your policies directory.", file=sys.stderr)
        return 2

    # --- Load infrastructure configs ---
    try:
        services = load_configs(args.configs)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not services:
        print("ERROR: No services were loaded. Check your configs directory.", file=sys.stderr)
        return 2

    # --- Apply pre-scan filters ---
    if args.env:
        services = [s for s in services if s.environment.lower() == args.env.lower()]
        if not services:
            print(
                f"WARNING: No services found for environment '{args.env}'.",
                file=sys.stderr
            )
            return 0

    if args.service:
        services = [s for s in services if s.name.lower() == args.service.lower()]
        if not services:
            print(
                f"WARNING: No service named '{args.service}' found.",
                file=sys.stderr
            )
            return 0

    # --- Run the engine ---
    engine = ComplianceEngine(policies)
    result = engine.scan(services)

    # --- Apply post-scan filters (severity filter affects display only) ---
    if args.severity:
        result.violations = filter_violations(result.violations, args.severity)

    # --- Output ---
    if args.output == "json":
        print_json_report(result, sys.stdout)
    else:
        print_terminal_report(result, sys.stdout)

    # --- Exit code ---
    if args.no_fail:
        return 0

    return 1 if result.total_violations > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
